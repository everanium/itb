// File-like streaming wrappers over the one-shot ITB encrypt / decrypt
// API.
//
// ITB ciphertexts cap at ~64 MB plaintext per chunk (the underlying
// container size limit). Streaming larger payloads simply means slicing
// the input into chunks at the binding layer, encrypting each chunk
// through the regular FFI path, and concatenating the results. The
// reverse operation walks a concatenated chunk stream by reading the
// chunk header, calling <see cref="Library.ParseChunkLen"/> to learn
// the chunk's body length, reading that many bytes, and decrypting the
// single chunk.
//
// Both class-based wrappers (<see cref="StreamEncryptor"/> /
// <see cref="StreamDecryptor"/> and their Triple Ouroboros counterparts
// <see cref="StreamEncryptorTriple"/> / <see cref="StreamDecryptorTriple"/>)
// and the convenience helpers (<see cref="EncryptStream"/> /
// <see cref="DecryptStream"/> plus the Triple variants) are provided.
// Memory peak per call is bounded by <c>chunkSize</c> (default 16 MiB
// — see <see cref="DefaultChunkSize"/>), regardless of the total
// payload length.
//
// The Triple Ouroboros (7-seed) variants share the same I/O contract
// and only differ in the seed list passed to the constructor.
//
// Threading caveat. Do not change <see cref="Library.NonceBits"/>
// between writes on the same stream. The chunks are encrypted under
// the active nonce-size at the moment each chunk is flushed; switching
// nonce-bits mid-stream produces a chunk header layout the paired
// decryptor (which snapshots <see cref="Library.HeaderSize"/> at
// construction) cannot parse.
//
// Lifecycle. Stream wrappers do NOT take ownership of the underlying
// <see cref="System.IO.Stream"/>. The caller retains responsibility for
// closing / disposing the wrapped stream after the wrapper is itself
// disposed.

using System.IO;
using Itb.Native;

namespace Itb;

/// <summary>
/// Streaming-related defaults and convenience helpers.
/// </summary>
public static class StreamDefaults
{
    /// <summary>
    /// Default chunk size — matches <c>itb.DefaultChunkSize</c> on the
    /// Go side (16 MiB), the size at which ITB's barrier-encoded
    /// container layout stays well within the per-chunk pixel cap.
    /// </summary>
    public const int DefaultChunkSize = 16 * 1024 * 1024;
}

/// <summary>
/// Chunked encrypt writer over a Single Ouroboros seed trio. Buffers
/// plaintext until at least <c>chunkSize</c> bytes are available, then
/// encrypts and emits one chunk to the wrapped output stream. The
/// trailing partial buffer is flushed as a final chunk on
/// <see cref="Close"/> / <see cref="Dispose"/>, so the on-the-wire
/// chunk count is <c>ceil(total / chunkSize)</c>.
/// </summary>
/// <remarks>
/// <para>The wrapped <see cref="Stream"/> is NOT disposed when this
/// writer is disposed; the caller retains ownership of the underlying
/// stream's lifecycle.</para>
/// <para><b>Thread-safety contract.</b> The buffer-and-emit state
/// machine is not safe to invoke concurrently from multiple threads.
/// Sharing one <see cref="StreamEncryptor"/> across threads requires
/// external synchronisation.</para>
/// </remarks>
public sealed class StreamEncryptor : IDisposable
{
    private readonly Seed _noise;
    private readonly Seed _data;
    private readonly Seed _start;
    private readonly Stream _output;
    private readonly int _chunkSize;
    private readonly List<byte> _buf = new();
    private bool _closed;

    /// <summary>
    /// Constructs a fresh stream encryptor wrapping the given output
    /// stream. <paramref name="chunkSize"/> must be positive.
    /// </summary>
    public StreamEncryptor(Seed noise, Seed data, Seed start, Stream output,
        int chunkSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(output);
        if (chunkSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkSize),
                "chunkSize must be positive");
        }
        _noise = noise;
        _data = data;
        _start = start;
        _output = output;
        _chunkSize = chunkSize;
    }

    /// <summary>
    /// Appends <paramref name="data"/> to the internal buffer,
    /// encrypting and emitting every full <c>chunkSize</c>-sized slice
    /// that becomes available. Returns the number of bytes consumed
    /// (always equal to <c>data.Length</c> on success).
    /// </summary>
    public int Write(ReadOnlySpan<byte> data)
    {
        if (_closed)
        {
            throw new InvalidOperationException("write on closed StreamEncryptor");
        }
        for (var i = 0; i < data.Length; i++)
        {
            _buf.Add(data[i]);
        }
        while (_buf.Count >= _chunkSize)
        {
            var chunk = new byte[_chunkSize];
            _buf.CopyTo(0, chunk, 0, _chunkSize);
            _buf.RemoveRange(0, _chunkSize);
            var ct = Cipher.Encrypt(_noise, _data, _start, chunk);
            _output.Write(ct, 0, ct.Length);
        }
        return data.Length;
    }

    /// <summary>
    /// Encrypts and emits any remaining buffered bytes as the final
    /// chunk. Idempotent — a second call is a no-op.
    /// </summary>
    public void Close()
    {
        if (_closed)
        {
            return;
        }
        if (_buf.Count > 0)
        {
            var chunk = _buf.ToArray();
            _buf.Clear();
            var ct = Cipher.Encrypt(_noise, _data, _start, chunk);
            _output.Write(ct, 0, ct.Length);
        }
        _closed = true;
    }

    /// <summary>
    /// Calls <see cref="Close"/> if it has not been called yet.
    /// Releases nothing else — the wrapped output stream remains the
    /// caller's responsibility.
    /// </summary>
    public void Dispose()
    {
        Close();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Chunked decrypt writer over a Single Ouroboros seed trio.
/// Accumulates ciphertext bytes via <see cref="Feed"/> until a full
/// chunk (header plus body) is available, then decrypts the chunk and
/// writes the plaintext to the wrapped output stream. Multiple full
/// chunks in one feed call are processed sequentially.
/// </summary>
/// <remarks>
/// <para>The wrapped <see cref="Stream"/> is NOT disposed when this
/// writer is disposed.</para>
/// <para><b>Thread-safety contract.</b> The buffer-and-emit state
/// machine is not safe to invoke concurrently from multiple threads.
/// Sharing one <see cref="StreamDecryptor"/> across threads requires
/// external synchronisation.</para>
/// </remarks>
public sealed class StreamDecryptor : IDisposable
{
    private readonly Seed _noise;
    private readonly Seed _data;
    private readonly Seed _start;
    private readonly Stream _output;
    private readonly List<byte> _buf = new();
    private readonly int _headerSize;
    private bool _closed;

    /// <summary>
    /// Constructs a fresh stream decryptor wrapping the given output
    /// stream. The chunk-header size is snapshotted at construction so
    /// the decryptor uses the same header layout the matching encryptor
    /// saw — changing <see cref="Library.NonceBits"/> mid-stream would
    /// break decoding anyway.
    /// </summary>
    public StreamDecryptor(Seed noise, Seed data, Seed start, Stream output)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(output);
        _noise = noise;
        _data = data;
        _start = start;
        _output = output;
        _headerSize = Library.HeaderSize;
    }

    /// <summary>
    /// Appends <paramref name="data"/> to the internal buffer and
    /// drains every complete chunk that has become available, writing
    /// decrypted plaintext to the output stream. Returns the number of
    /// bytes consumed (always equal to <c>data.Length</c> on success).
    /// </summary>
    public int Feed(ReadOnlySpan<byte> data)
    {
        if (_closed)
        {
            throw new InvalidOperationException("feed on closed StreamDecryptor");
        }
        for (var i = 0; i < data.Length; i++)
        {
            _buf.Add(data[i]);
        }
        Drain();
        return data.Length;
    }

    private void Drain()
    {
        // Header buffer is allocated once on the heap to keep the
        // stack-frame footprint independent of how many chunks are
        // drained per call (analyser CA2014 — no stackalloc in a loop).
        var header = new byte[_headerSize];
        while (true)
        {
            if (_buf.Count < _headerSize)
            {
                return;
            }
            for (var i = 0; i < _headerSize; i++)
            {
                header[i] = _buf[i];
            }
            var chunkLen = Library.ParseChunkLen(header);
            if (_buf.Count < chunkLen)
            {
                return;
            }
            var chunk = new byte[chunkLen];
            _buf.CopyTo(0, chunk, 0, chunkLen);
            _buf.RemoveRange(0, chunkLen);
            var pt = Cipher.Decrypt(_noise, _data, _start, chunk);
            _output.Write(pt, 0, pt.Length);
        }
    }

    /// <summary>
    /// Finalises the decryptor. Throws when leftover bytes do not form
    /// a complete chunk — streaming ITB ciphertext cannot have a
    /// half-chunk tail.
    /// </summary>
    public void Close()
    {
        if (_closed)
        {
            return;
        }
        if (_buf.Count > 0)
        {
            throw new InvalidOperationException(
                $"StreamDecryptor: trailing {_buf.Count} bytes do not form a complete chunk");
        }
        _closed = true;
    }

    /// <summary>
    /// Marks the decryptor closed. Suppresses the half-chunk-tail check
    /// performed by <see cref="Close"/> because <see cref="IDisposable"/>
    /// has no path to surface errors; callers who need to detect a
    /// half-chunk tail must call <see cref="Close"/> explicitly.
    /// </summary>
    public void Dispose()
    {
        _closed = true;
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Triple Ouroboros (7-seed) counterpart of
/// <see cref="StreamEncryptor"/>.
/// </summary>
/// <remarks>
/// <para>The wrapped <see cref="Stream"/> is NOT disposed when this
/// writer is disposed.</para>
/// <para><b>Thread-safety contract.</b> The buffer-and-emit state
/// machine is not safe to invoke concurrently from multiple threads.
/// Sharing one <see cref="StreamEncryptorTriple"/> across threads
/// requires external synchronisation.</para>
/// </remarks>
public sealed class StreamEncryptorTriple : IDisposable
{
    private readonly Seed _noise;
    private readonly Seed _data1;
    private readonly Seed _data2;
    private readonly Seed _data3;
    private readonly Seed _start1;
    private readonly Seed _start2;
    private readonly Seed _start3;
    private readonly Stream _output;
    private readonly int _chunkSize;
    private readonly List<byte> _buf = new();
    private bool _closed;

    /// <summary>Constructs a fresh Triple Ouroboros stream encryptor.
    /// <paramref name="chunkSize"/> must be positive.</summary>
    public StreamEncryptorTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Stream output,
        int chunkSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data1);
        ArgumentNullException.ThrowIfNull(data2);
        ArgumentNullException.ThrowIfNull(data3);
        ArgumentNullException.ThrowIfNull(start1);
        ArgumentNullException.ThrowIfNull(start2);
        ArgumentNullException.ThrowIfNull(start3);
        ArgumentNullException.ThrowIfNull(output);
        if (chunkSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkSize),
                "chunkSize must be positive");
        }
        _noise = noise;
        _data1 = data1;
        _data2 = data2;
        _data3 = data3;
        _start1 = start1;
        _start2 = start2;
        _start3 = start3;
        _output = output;
        _chunkSize = chunkSize;
    }

    /// <summary>Appends <paramref name="data"/> to the internal buffer,
    /// encrypting and emitting every full <c>chunkSize</c>-sized slice
    /// that becomes available.</summary>
    public int Write(ReadOnlySpan<byte> data)
    {
        if (_closed)
        {
            throw new InvalidOperationException("write on closed StreamEncryptorTriple");
        }
        for (var i = 0; i < data.Length; i++)
        {
            _buf.Add(data[i]);
        }
        while (_buf.Count >= _chunkSize)
        {
            var chunk = new byte[_chunkSize];
            _buf.CopyTo(0, chunk, 0, _chunkSize);
            _buf.RemoveRange(0, _chunkSize);
            var ct = Cipher.EncryptTriple(_noise, _data1, _data2, _data3,
                _start1, _start2, _start3, chunk);
            _output.Write(ct, 0, ct.Length);
        }
        return data.Length;
    }

    /// <summary>Encrypts and emits any remaining buffered bytes as the
    /// final chunk. Idempotent.</summary>
    public void Close()
    {
        if (_closed)
        {
            return;
        }
        if (_buf.Count > 0)
        {
            var chunk = _buf.ToArray();
            _buf.Clear();
            var ct = Cipher.EncryptTriple(_noise, _data1, _data2, _data3,
                _start1, _start2, _start3, chunk);
            _output.Write(ct, 0, ct.Length);
        }
        _closed = true;
    }

    /// <summary>Calls <see cref="Close"/> if not already called.</summary>
    public void Dispose()
    {
        Close();
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Triple Ouroboros (7-seed) counterpart of
/// <see cref="StreamDecryptor"/>.
/// </summary>
/// <remarks>
/// <para>The wrapped <see cref="Stream"/> is NOT disposed when this
/// writer is disposed.</para>
/// <para><b>Thread-safety contract.</b> The buffer-and-emit state
/// machine is not safe to invoke concurrently from multiple threads.
/// Sharing one <see cref="StreamDecryptorTriple"/> across threads
/// requires external synchronisation.</para>
/// </remarks>
public sealed class StreamDecryptorTriple : IDisposable
{
    private readonly Seed _noise;
    private readonly Seed _data1;
    private readonly Seed _data2;
    private readonly Seed _data3;
    private readonly Seed _start1;
    private readonly Seed _start2;
    private readonly Seed _start3;
    private readonly Stream _output;
    private readonly List<byte> _buf = new();
    private readonly int _headerSize;
    private bool _closed;

    /// <summary>Constructs a fresh Triple Ouroboros stream
    /// decryptor.</summary>
    public StreamDecryptorTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Stream output)
    {
        ArgumentNullException.ThrowIfNull(noise);
        ArgumentNullException.ThrowIfNull(data1);
        ArgumentNullException.ThrowIfNull(data2);
        ArgumentNullException.ThrowIfNull(data3);
        ArgumentNullException.ThrowIfNull(start1);
        ArgumentNullException.ThrowIfNull(start2);
        ArgumentNullException.ThrowIfNull(start3);
        ArgumentNullException.ThrowIfNull(output);
        _noise = noise;
        _data1 = data1;
        _data2 = data2;
        _data3 = data3;
        _start1 = start1;
        _start2 = start2;
        _start3 = start3;
        _output = output;
        _headerSize = Library.HeaderSize;
    }

    /// <summary>Appends <paramref name="data"/> to the internal buffer
    /// and drains every complete chunk that has become available.</summary>
    public int Feed(ReadOnlySpan<byte> data)
    {
        if (_closed)
        {
            throw new InvalidOperationException("feed on closed StreamDecryptorTriple");
        }
        for (var i = 0; i < data.Length; i++)
        {
            _buf.Add(data[i]);
        }
        Drain();
        return data.Length;
    }

    private void Drain()
    {
        // Header buffer is allocated once on the heap to keep the
        // stack-frame footprint independent of how many chunks are
        // drained per call (analyser CA2014 — no stackalloc in a loop).
        var header = new byte[_headerSize];
        while (true)
        {
            if (_buf.Count < _headerSize)
            {
                return;
            }
            for (var i = 0; i < _headerSize; i++)
            {
                header[i] = _buf[i];
            }
            var chunkLen = Library.ParseChunkLen(header);
            if (_buf.Count < chunkLen)
            {
                return;
            }
            var chunk = new byte[chunkLen];
            _buf.CopyTo(0, chunk, 0, chunkLen);
            _buf.RemoveRange(0, chunkLen);
            var pt = Cipher.DecryptTriple(_noise, _data1, _data2, _data3,
                _start1, _start2, _start3, chunk);
            _output.Write(pt, 0, pt.Length);
        }
    }

    /// <summary>Finalises the decryptor. Throws when leftover bytes do
    /// not form a complete chunk.</summary>
    public void Close()
    {
        if (_closed)
        {
            return;
        }
        if (_buf.Count > 0)
        {
            throw new InvalidOperationException(
                $"StreamDecryptorTriple: trailing {_buf.Count} bytes do not form a complete chunk");
        }
        _closed = true;
    }

    /// <summary>Marks the decryptor closed without raising on partial
    /// input.</summary>
    public void Dispose()
    {
        _closed = true;
        GC.SuppressFinalize(this);
    }
}

/// <summary>
/// Convenience helpers wrapping the streaming class APIs as one-shot
/// read-encrypt-write / read-decrypt-write pipelines.
/// </summary>
public static class StreamPipeline
{
    /// <summary>
    /// Reads plaintext from <paramref name="input"/> until end of
    /// stream, encrypts in chunks of <paramref name="chunkSize"/>, and
    /// writes concatenated ITB chunks to <paramref name="output"/>.
    /// Neither stream is disposed by this method.
    /// </summary>
    public static void EncryptStream(
        Seed noise, Seed data, Seed start,
        Stream input, Stream output,
        int chunkSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (chunkSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkSize),
                "chunkSize must be positive");
        }
        using var enc = new StreamEncryptor(noise, data, start, output, chunkSize);
        var buf = new byte[chunkSize];
        while (true)
        {
            var n = input.Read(buf, 0, buf.Length);
            if (n == 0)
            {
                break;
            }
            enc.Write(buf.AsSpan(0, n));
        }
        enc.Close();
    }

    /// <summary>
    /// Reads concatenated ITB chunks from <paramref name="input"/>
    /// until end of stream and writes the recovered plaintext to
    /// <paramref name="output"/>. Neither stream is disposed by this
    /// method.
    /// </summary>
    public static void DecryptStream(
        Seed noise, Seed data, Seed start,
        Stream input, Stream output,
        int readSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (readSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(readSize),
                "readSize must be positive");
        }
        using var dec = new StreamDecryptor(noise, data, start, output);
        var buf = new byte[readSize];
        while (true)
        {
            var n = input.Read(buf, 0, buf.Length);
            if (n == 0)
            {
                break;
            }
            dec.Feed(buf.AsSpan(0, n));
        }
        dec.Close();
    }

    /// <summary>Triple Ouroboros (7-seed) counterpart of
    /// <see cref="EncryptStream"/>.</summary>
    public static void EncryptStreamTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Stream input, Stream output,
        int chunkSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (chunkSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(chunkSize),
                "chunkSize must be positive");
        }
        using var enc = new StreamEncryptorTriple(noise, data1, data2, data3,
            start1, start2, start3, output, chunkSize);
        var buf = new byte[chunkSize];
        while (true)
        {
            var n = input.Read(buf, 0, buf.Length);
            if (n == 0)
            {
                break;
            }
            enc.Write(buf.AsSpan(0, n));
        }
        enc.Close();
    }

    /// <summary>Triple Ouroboros (7-seed) counterpart of
    /// <see cref="DecryptStream"/>.</summary>
    public static void DecryptStreamTriple(
        Seed noise,
        Seed data1, Seed data2, Seed data3,
        Seed start1, Seed start2, Seed start3,
        Stream input, Stream output,
        int readSize = StreamDefaults.DefaultChunkSize)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        if (readSize <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(readSize),
                "readSize must be positive");
        }
        using var dec = new StreamDecryptorTriple(noise, data1, data2, data3,
            start1, start2, start3, output);
        var buf = new byte[readSize];
        while (true)
        {
            var n = input.Read(buf, 0, buf.Length);
            if (n == 0)
            {
                break;
            }
            dec.Feed(buf.AsSpan(0, n));
        }
        dec.Close();
    }
}
