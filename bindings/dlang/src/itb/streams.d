/// File-like streaming wrappers over the one-shot ITB encrypt /
/// decrypt API.
///
/// ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
/// container size limit). Streaming larger payloads simply means
/// slicing the input into chunks at the binding layer, encrypting
/// each chunk through the regular FFI path, and concatenating the
/// results. The reverse operation walks a concatenated chunk stream
/// by reading the chunk header, calling [`itb.registry.parseChunkLen`]
/// to learn the chunk's body length, reading that many bytes, and
/// decrypting the single chunk.
///
/// Both struct-based wrappers ([`StreamEncryptor`], [`StreamDecryptor`]
/// and their Triple counterparts) and free-function convenience
/// wrappers ([`encryptStream`], [`decryptStream`], plus Triple
/// variants) are provided. Memory peak is bounded by `chunkSize`
/// (default 16 MB), regardless of the total payload length.
///
/// The Triple-Ouroboros (7-seed) variants share the same I/O contract
/// and only differ in the seed list passed to the constructor.
///
/// Output sink. The struct constructors accept a `void delegate(const
/// (ubyte)[])` writer delegate that receives each emitted chunk;
/// the free functions additionally take a `size_t delegate(ubyte[])`
/// reader delegate that fills its buffer argument with the next slice
/// of input bytes and returns the number of bytes read (zero on EOF).
/// The delegate-based shape lets callers route bytes through any
/// source / sink — sockets, files, in-memory buffers — without
/// committing the streaming wrappers to a specific I/O abstraction.
///
/// Warning. Do not call [`itb.registry.setNonceBits`] between writes
/// on the same stream. The chunks are encrypted under the active
/// nonce-size at the moment each chunk is flushed; switching
/// nonce-bits mid-stream produces a chunk header layout the paired
/// decryptor (which snapshots [`itb.registry.headerSize`] at
/// construction) cannot parse.
module itb.streams;

import itb.cipher : decrypt, decryptTriple, encrypt, encryptTriple;
import itb.errors : check, ITBError, raiseFor;
import itb.registry : headerSize, parseChunkLen;
import itb.seed : Seed;
import itb.status : Status;
import itb.sys;

/// Default chunk size — matches `itb.DefaultChunkSize` on the Go side
/// (16 MB), the size at which ITB's barrier-encoded container layout
/// stays well within the per-chunk pixel cap.
enum size_t DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024;

// --------------------------------------------------------------------
// Single Ouroboros — chunked writer.
// --------------------------------------------------------------------

/// Chunked encrypt writer: buffers plaintext until at least
/// `chunkSize` bytes are available, then encrypts and emits one chunk
/// to the output writer delegate. The trailing partial buffer is
/// flushed as a final chunk on [`StreamEncryptor.close`] (so the
/// on-the-wire chunk count is `ceil(total / chunkSize)`).
///
/// Usage:
///
/// ---
/// import itb;
///
/// auto n = Seed("blake3", 1024);
/// auto d = Seed("blake3", 1024);
/// auto s = Seed("blake3", 1024);
/// ubyte[] sink;
/// auto enc = StreamEncryptor(n, d, s,
///     (const(ubyte)[] chunk) { sink ~= chunk; },
///     1 << 16);
/// enc.write(cast(const(ubyte)[]) "chunk one");
/// enc.write(cast(const(ubyte)[]) "chunk two");
/// enc.close();
/// ---
struct StreamEncryptor
{
    private void delegate(const(ubyte)[]) @trusted _writer;
    private size_t _chunkSize;
    private ubyte[] _buf;
    private bool _closed;
    // Raw pointers to caller-supplied Seed values, dereferenced on
    // every chunk's encrypt() call. D does not statically enforce
    // borrow lifetimes, so the **caller MUST keep the original Seed
    // values alive for the entire StreamEncryptor lifetime** — letting
    // a Seed go out of scope before close() finishes triggers
    // use-after-free in the FFI call. These pointers are load-bearing,
    // not diagnostic.
    private const(Seed)* _noiseRef;
    private const(Seed)* _dataRef;
    private const(Seed)* _startRef;

    @disable this(this);

    /// Constructs a fresh stream encryptor wrapping the given output
    /// writer delegate. `chunkSize` must be positive.
    ///
    /// Lifetime contract. The constructor stores raw pointers to the
    /// supplied `noise` / `data` / `start` Seed values. The caller
    /// MUST keep all three Seeds alive for the entire stream
    /// lifetime — until the destructor or `close()` returns. Letting
    /// any Seed go out of scope before then is undefined behaviour
    /// (use-after-free in the FFI call).
    this(ref const Seed noise, ref const Seed data, ref const Seed start,
         void delegate(const(ubyte)[]) @trusted writer,
         size_t chunkSize = DEFAULT_CHUNK_SIZE) @trusted
    {
        if (chunkSize == 0)
            throw new ITBError(Status.BadInput, "chunkSize must be positive");
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");
        this._noiseRef = &noise;
        this._dataRef = &data;
        this._startRef = &start;
        this._writer = writer;
        this._chunkSize = chunkSize;
        this._buf = [];
        this._closed = false;
    }

    /// Destructor — best-effort flush. Errors during destruction are
    /// swallowed because there is no path to surface them. Callers
    /// that need to see close-time errors must call `close()`
    /// explicitly.
    ~this() @trusted
    {
        try
        {
            if (!_closed)
                close();
        }
        catch (Exception)
        {
            // Swallow — destructor cannot raise.
        }
    }

    /// Appends `data` to the internal buffer, encrypting and emitting
    /// every full `chunkSize`-sized slice that becomes available.
    void write(const(ubyte)[] data) @trusted
    {
        if (_closed)
            throw new ITBError(Status.BadInput, "write on closed StreamEncryptor");
        _buf ~= data;
        while (_buf.length >= _chunkSize)
        {
            ubyte[] chunk = _buf[0 .. _chunkSize].dup;
            _buf = _buf[_chunkSize .. $];
            ubyte[] ct = encrypt(*_noiseRef, *_dataRef, *_startRef, chunk);
            _writer(ct);
        }
    }

    /// Encrypts and emits any remaining buffered bytes as the final
    /// chunk. Idempotent — a second call is a no-op.
    void close() @trusted
    {
        if (_closed)
            return;
        if (_buf.length > 0)
        {
            ubyte[] chunk = _buf;
            _buf = [];
            ubyte[] ct = encrypt(*_noiseRef, *_dataRef, *_startRef, chunk);
            _writer(ct);
        }
        _closed = true;
    }
}

// --------------------------------------------------------------------
// Single Ouroboros — chunked reader.
// --------------------------------------------------------------------

/// Chunked decrypt reader: accumulates ciphertext bytes via
/// [`StreamDecryptor.feed`] until a full chunk (header + body) is
/// available, then decrypts the chunk and writes the plaintext to the
/// output writer delegate. Multiple full chunks in one feed call are
/// processed sequentially.
///
/// Usage:
///
/// ---
/// import itb;
///
/// auto n = Seed("blake3", 1024);
/// auto d = Seed("blake3", 1024);
/// auto s = Seed("blake3", 1024);
/// ubyte[] sink;
/// auto dec = StreamDecryptor(n, d, s,
///     (const(ubyte)[] pt) { sink ~= pt; });
/// dec.feed(ciphertext);
/// dec.close();
/// ---
struct StreamDecryptor
{
    private void delegate(const(ubyte)[]) @trusted _writer;
    private ubyte[] _buf;
    private bool _closed;
    private size_t _headerSize;
    // Raw pointers to caller-supplied Seed values, dereferenced on
    // every chunk's decrypt() call. D does not statically enforce
    // borrow lifetimes, so the **caller MUST keep the original Seed
    // values alive for the entire StreamDecryptor lifetime** — until
    // the destructor or `close()` returns. Letting any Seed go out of
    // scope before then triggers use-after-free in the FFI call.
    private const(Seed)* _noiseRef;
    private const(Seed)* _dataRef;
    private const(Seed)* _startRef;

    @disable this(this);

    /// Constructs a fresh stream decryptor wrapping the given output
    /// writer delegate. The chunk-header size is snapshotted at
    /// construction so the decryptor uses the same header layout the
    /// matching encryptor saw — changing
    /// [`itb.registry.setNonceBits`] mid-stream would break decoding
    /// anyway.
    ///
    /// Lifetime contract. The constructor stores raw pointers to the
    /// supplied `noise` / `data` / `start` Seed values. The caller
    /// MUST keep all three Seeds alive for the entire stream
    /// lifetime — until the destructor or `close()` returns. Letting
    /// any Seed go out of scope before then is undefined behaviour
    /// (use-after-free in the FFI call).
    this(ref const Seed noise, ref const Seed data, ref const Seed start,
         void delegate(const(ubyte)[]) @trusted writer) @trusted
    {
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");
        this._noiseRef = &noise;
        this._dataRef = &data;
        this._startRef = &start;
        this._writer = writer;
        this._buf = [];
        this._closed = false;
        this._headerSize = cast(size_t) headerSize();
    }

    /// Destructor — marks the decryptor closed without raising on
    /// partial input. Callers who need to detect a half-chunk tail
    /// must call `close()` explicitly.
    ~this() @safe
    {
        _closed = true;
    }

    /// Appends `data` to the internal buffer and drains every complete
    /// chunk that has become available, calling the writer delegate
    /// with the decrypted plaintext.
    void feed(const(ubyte)[] data) @trusted
    {
        if (_closed)
            throw new ITBError(Status.BadInput, "feed on closed StreamDecryptor");
        _buf ~= data;
        drain();
    }

    /// Finalises the decryptor. Throws `ITBError` with `Status.BadInput`
    /// when leftover bytes do not form a complete chunk — streaming
    /// ITB ciphertext cannot have a half-chunk tail.
    void close() @trusted
    {
        if (_closed)
            return;
        if (_buf.length > 0)
        {
            import std.conv : to;
            throw new ITBError(Status.BadInput,
                "StreamDecryptor: trailing " ~ _buf.length.to!string
                ~ " bytes do not form a complete chunk");
        }
        _closed = true;
    }

    private void drain() @trusted
    {
        while (true)
        {
            if (_buf.length < _headerSize)
                return;
            size_t chunkLen = parseChunkLen(_buf[0 .. _headerSize]);
            if (_buf.length < chunkLen)
                return;
            ubyte[] chunk = _buf[0 .. chunkLen].dup;
            _buf = _buf[chunkLen .. $];
            ubyte[] pt = decrypt(*_noiseRef, *_dataRef, *_startRef, chunk);
            _writer(pt);
        }
    }
}

// --------------------------------------------------------------------
// Triple Ouroboros — chunked writer.
// --------------------------------------------------------------------

/// Triple-Ouroboros (7-seed) counterpart of [`StreamEncryptor`].
struct StreamEncryptor3
{
    private void delegate(const(ubyte)[]) @trusted _writer;
    private size_t _chunkSize;
    private ubyte[] _buf;
    private bool _closed;
    // Raw pointers to caller-supplied Seed values, dereferenced on
    // every chunk's encryptTriple() call. D does not statically
    // enforce borrow lifetimes, so the **caller MUST keep all seven
    // original Seed values alive for the entire StreamEncryptor3
    // lifetime** — until the destructor or `close()` returns. Letting
    // any Seed go out of scope before then triggers use-after-free in
    // the FFI call.
    private const(Seed)* _noiseRef;
    private const(Seed)* _data1Ref;
    private const(Seed)* _data2Ref;
    private const(Seed)* _data3Ref;
    private const(Seed)* _start1Ref;
    private const(Seed)* _start2Ref;
    private const(Seed)* _start3Ref;

    @disable this(this);

    /// Constructs a fresh Triple-Ouroboros stream encryptor.
    /// `chunkSize` must be positive.
    ///
    /// Lifetime contract. The constructor stores raw pointers to the
    /// supplied seven Seed values. The caller MUST keep all seven
    /// Seeds alive for the entire stream lifetime — until the
    /// destructor or `close()` returns. Letting any Seed go out of
    /// scope before then is undefined behaviour (use-after-free in
    /// the FFI call).
    this(ref const Seed noise,
         ref const Seed data1, ref const Seed data2, ref const Seed data3,
         ref const Seed start1, ref const Seed start2, ref const Seed start3,
         void delegate(const(ubyte)[]) @trusted writer,
         size_t chunkSize = DEFAULT_CHUNK_SIZE) @trusted
    {
        if (chunkSize == 0)
            throw new ITBError(Status.BadInput, "chunkSize must be positive");
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");
        this._noiseRef = &noise;
        this._data1Ref = &data1;
        this._data2Ref = &data2;
        this._data3Ref = &data3;
        this._start1Ref = &start1;
        this._start2Ref = &start2;
        this._start3Ref = &start3;
        this._writer = writer;
        this._chunkSize = chunkSize;
        this._buf = [];
        this._closed = false;
    }

    /// Destructor — best-effort flush; errors swallowed.
    ~this() @trusted
    {
        try
        {
            if (!_closed)
                close();
        }
        catch (Exception)
        {
            // Swallow — destructor cannot raise.
        }
    }

    /// Appends `data` to the internal buffer, encrypting and emitting
    /// every full `chunkSize`-sized slice that becomes available.
    void write(const(ubyte)[] data) @trusted
    {
        if (_closed)
            throw new ITBError(Status.BadInput, "write on closed StreamEncryptor3");
        _buf ~= data;
        while (_buf.length >= _chunkSize)
        {
            ubyte[] chunk = _buf[0 .. _chunkSize].dup;
            _buf = _buf[_chunkSize .. $];
            ubyte[] ct = encryptTriple(
                *_noiseRef,
                *_data1Ref, *_data2Ref, *_data3Ref,
                *_start1Ref, *_start2Ref, *_start3Ref,
                chunk);
            _writer(ct);
        }
    }

    /// Encrypts and emits any remaining buffered bytes as the final
    /// chunk. Idempotent.
    void close() @trusted
    {
        if (_closed)
            return;
        if (_buf.length > 0)
        {
            ubyte[] chunk = _buf;
            _buf = [];
            ubyte[] ct = encryptTriple(
                *_noiseRef,
                *_data1Ref, *_data2Ref, *_data3Ref,
                *_start1Ref, *_start2Ref, *_start3Ref,
                chunk);
            _writer(ct);
        }
        _closed = true;
    }
}

// --------------------------------------------------------------------
// Triple Ouroboros — chunked reader.
// --------------------------------------------------------------------

/// Triple-Ouroboros (7-seed) counterpart of [`StreamDecryptor`].
struct StreamDecryptor3
{
    private void delegate(const(ubyte)[]) @trusted _writer;
    private ubyte[] _buf;
    private bool _closed;
    private size_t _headerSize;
    // Raw pointers to caller-supplied Seed values, dereferenced on
    // every chunk's decryptTriple() call. D does not statically
    // enforce borrow lifetimes, so the **caller MUST keep all seven
    // original Seed values alive for the entire StreamDecryptor3
    // lifetime** — until the destructor or `close()` returns. Letting
    // any Seed go out of scope before then triggers use-after-free in
    // the FFI call.
    private const(Seed)* _noiseRef;
    private const(Seed)* _data1Ref;
    private const(Seed)* _data2Ref;
    private const(Seed)* _data3Ref;
    private const(Seed)* _start1Ref;
    private const(Seed)* _start2Ref;
    private const(Seed)* _start3Ref;

    @disable this(this);

    /// Constructs a fresh Triple-Ouroboros stream decryptor.
    ///
    /// Lifetime contract. The constructor stores raw pointers to the
    /// supplied seven Seed values. The caller MUST keep all seven
    /// Seeds alive for the entire stream lifetime — until the
    /// destructor or `close()` returns. Letting any Seed go out of
    /// scope before then is undefined behaviour (use-after-free in
    /// the FFI call).
    this(ref const Seed noise,
         ref const Seed data1, ref const Seed data2, ref const Seed data3,
         ref const Seed start1, ref const Seed start2, ref const Seed start3,
         void delegate(const(ubyte)[]) @trusted writer) @trusted
    {
        if (writer is null)
            throw new ITBError(Status.BadInput, "writer delegate must be non-null");
        this._noiseRef = &noise;
        this._data1Ref = &data1;
        this._data2Ref = &data2;
        this._data3Ref = &data3;
        this._start1Ref = &start1;
        this._start2Ref = &start2;
        this._start3Ref = &start3;
        this._writer = writer;
        this._buf = [];
        this._closed = false;
        this._headerSize = cast(size_t) headerSize();
    }

    /// Destructor — marks the decryptor closed without raising on
    /// partial input.
    ~this() @safe
    {
        _closed = true;
    }

    /// Appends `data` to the internal buffer and drains every complete
    /// chunk that has become available.
    void feed(const(ubyte)[] data) @trusted
    {
        if (_closed)
            throw new ITBError(Status.BadInput, "feed on closed StreamDecryptor3");
        _buf ~= data;
        drain();
    }

    /// Finalises the decryptor. Throws `ITBError` with `Status.BadInput`
    /// when leftover bytes do not form a complete chunk.
    void close() @trusted
    {
        if (_closed)
            return;
        if (_buf.length > 0)
        {
            import std.conv : to;
            throw new ITBError(Status.BadInput,
                "StreamDecryptor3: trailing " ~ _buf.length.to!string
                ~ " bytes do not form a complete chunk");
        }
        _closed = true;
    }

    private void drain() @trusted
    {
        while (true)
        {
            if (_buf.length < _headerSize)
                return;
            size_t chunkLen = parseChunkLen(_buf[0 .. _headerSize]);
            if (_buf.length < chunkLen)
                return;
            ubyte[] chunk = _buf[0 .. chunkLen].dup;
            _buf = _buf[chunkLen .. $];
            ubyte[] pt = decryptTriple(
                *_noiseRef,
                *_data1Ref, *_data2Ref, *_data3Ref,
                *_start1Ref, *_start2Ref, *_start3Ref,
                chunk);
            _writer(pt);
        }
    }
}

// --------------------------------------------------------------------
// Functional convenience wrappers.
// --------------------------------------------------------------------

/// Reads plaintext from `reader` until EOF, encrypts in chunks of
/// `chunkSize`, and writes concatenated ITB chunks to `writer`.
///
/// `reader` is a delegate that fills its buffer argument with the
/// next slice of input bytes and returns the number of bytes read
/// (zero on EOF). `writer` is a delegate that consumes each emitted
/// ciphertext chunk.
void encryptStream(
    ref const Seed noise, ref const Seed data, ref const Seed start,
    scope size_t delegate(ubyte[]) @trusted reader,
    scope void delegate(const(ubyte)[]) @trusted writer,
    size_t chunkSize = DEFAULT_CHUNK_SIZE) @trusted
{
    if (chunkSize == 0)
        throw new ITBError(Status.BadInput, "chunkSize must be positive");
    if (reader is null)
        throw new ITBError(Status.BadInput, "reader delegate must be non-null");
    if (writer is null)
        throw new ITBError(Status.BadInput, "writer delegate must be non-null");

    auto enc = StreamEncryptor(noise, data, start, writer, chunkSize);
    ubyte[] buf = new ubyte[chunkSize];
    while (true)
    {
        size_t n = reader(buf);
        if (n == 0)
            break;
        enc.write(buf[0 .. n]);
    }
    enc.close();
}

/// Reads concatenated ITB chunks from `reader` until EOF and writes
/// the recovered plaintext to `writer`.
///
/// `readSize` controls the size of the staging buffer used to pull
/// ciphertext bytes from `reader`; it must be positive but does not
/// have to match the encrypter's chunk size. The decryptor
/// re-assembles full chunks internally by inspecting each chunk's
/// header.
void decryptStream(
    ref const Seed noise, ref const Seed data, ref const Seed start,
    scope size_t delegate(ubyte[]) @trusted reader,
    scope void delegate(const(ubyte)[]) @trusted writer,
    size_t readSize = DEFAULT_CHUNK_SIZE) @trusted
{
    if (readSize == 0)
        throw new ITBError(Status.BadInput, "readSize must be positive");
    if (reader is null)
        throw new ITBError(Status.BadInput, "reader delegate must be non-null");
    if (writer is null)
        throw new ITBError(Status.BadInput, "writer delegate must be non-null");

    auto dec = StreamDecryptor(noise, data, start, writer);
    ubyte[] buf = new ubyte[readSize];
    while (true)
    {
        size_t n = reader(buf);
        if (n == 0)
            break;
        dec.feed(buf[0 .. n]);
    }
    dec.close();
}

/// Triple-Ouroboros (7-seed) counterpart of [`encryptStream`].
void encryptStreamTriple(
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    scope size_t delegate(ubyte[]) @trusted reader,
    scope void delegate(const(ubyte)[]) @trusted writer,
    size_t chunkSize = DEFAULT_CHUNK_SIZE) @trusted
{
    if (chunkSize == 0)
        throw new ITBError(Status.BadInput, "chunkSize must be positive");
    if (reader is null)
        throw new ITBError(Status.BadInput, "reader delegate must be non-null");
    if (writer is null)
        throw new ITBError(Status.BadInput, "writer delegate must be non-null");

    auto enc = StreamEncryptor3(
        noise, data1, data2, data3, start1, start2, start3,
        writer, chunkSize);
    ubyte[] buf = new ubyte[chunkSize];
    while (true)
    {
        size_t n = reader(buf);
        if (n == 0)
            break;
        enc.write(buf[0 .. n]);
    }
    enc.close();
}

/// Triple-Ouroboros (7-seed) counterpart of [`decryptStream`].
void decryptStreamTriple(
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    scope size_t delegate(ubyte[]) @trusted reader,
    scope void delegate(const(ubyte)[]) @trusted writer,
    size_t readSize = DEFAULT_CHUNK_SIZE) @trusted
{
    if (readSize == 0)
        throw new ITBError(Status.BadInput, "readSize must be positive");
    if (reader is null)
        throw new ITBError(Status.BadInput, "reader delegate must be non-null");
    if (writer is null)
        throw new ITBError(Status.BadInput, "writer delegate must be non-null");

    auto dec = StreamDecryptor3(
        noise, data1, data2, data3, start1, start2, start3, writer);
    ubyte[] buf = new ubyte[readSize];
    while (true)
    {
        size_t n = reader(buf);
        if (n == 0)
            break;
        dec.feed(buf[0 .. n]);
    }
    dec.close();
}
