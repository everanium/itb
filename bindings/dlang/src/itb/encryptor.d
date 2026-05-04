/// High-level Encryptor wrapper over the libitb C ABI.
///
/// Mirrors the `github.com/everanium/itb/easy` Go sub-package: one
/// constructor call replaces the lower-level seven-line setup ceremony
/// (hash factory, three or seven seeds, MAC closure, container-config
/// wiring) and returns an `Encryptor` value that owns its own
/// per-instance configuration. Two encryptors with different settings
/// can be used in parallel without cross-contamination of the
/// process-wide ITB configuration.
///
/// Quick start (Single Ouroboros + HMAC-BLAKE3):
///
/// ---
/// import itb;
///
/// auto enc = Encryptor("blake3", 1024);
/// auto ct = enc.encryptAuth(cast(const(ubyte)[]) "hello world");
/// auto pt = enc.decryptAuth(ct);
/// assert(pt == cast(const(ubyte)[]) "hello world");
/// ---
///
/// Triple Ouroboros (7 seeds, mode = 3):
///
/// ---
/// auto enc = Encryptor("areion512", 2048, "kmac256", 3);
/// auto ct = enc.encrypt(big);
/// auto pt = enc.decrypt(ct);
/// ---
///
/// Cross-process persistence (encrypt today / decrypt tomorrow):
///
/// ---
/// auto blob = enc.exportState();
/// // ... save blob to disk / KMS / wire ...
/// auto cfg = peekConfig(blob);
/// auto dec = Encryptor(cfg.primitive, cfg.keyBits, cfg.macName, cfg.mode);
/// dec.importState(blob);
/// ---
///
/// Streaming. Chunking lives on the binding side (same pattern as the
/// lower-level API): slice the plaintext into chunks of `chunk_size`
/// bytes and call `encrypt` per chunk; on the decrypt side walk the
/// concatenated stream by reading the chunk header, calling
/// `parseChunkLen`, and feeding the chunk to `decrypt`. The
/// encryptor's chunk-size knob (set via `setChunkSize`) is consumed
/// only by the Go-side `EncryptStream` entry point; one-shot
/// `encrypt` honours the container-cap heuristic in `itb.ChunkSize`.
///
/// Output-buffer cache. The cipher methods reuse a per-encryptor
/// `ubyte[]` slice to avoid the per-call allocation cost; the buffer
/// grows on demand and survives between calls. Each cipher call
/// returns a slice over the cache covering the current result, so the
/// cache IS exposed to the caller — call `.dup` to detach the bytes
/// when their lifetime needs to outlast the next cipher call. The
/// cached bytes (the most recent ciphertext or plaintext) sit in heap
/// memory until the next cipher call overwrites them or `close` /
/// `~this` zeroes them. Callers handling sensitive plaintext under a
/// heap-scan threat model should call `close` immediately after the
/// last decrypt rather than relying on destruction-time zeroisation
/// at the end of scope.
///
/// Lifecycle. `Encryptor` is a non-copyable struct; the destructor
/// calls `ITB_Easy_Free` and wipes the output cache best-effort.
/// `close` is the explicit zeroing path (wipes PRF / MAC / seed
/// material on the Go side and wipes the per-instance output cache on
/// the D side); the destructor's `Free` call subsumes `close` on the
/// Go side, so manual `close` is only needed when the working set
/// must be zeroed earlier than scope exit.
module itb.encryptor;

import std.conv : to;
import std.string : toStringz;

import itb.errors : check, ITBError, raiseFor,
    readBytes, readLastMismatchField, readString;
import itb.status : Status;
import itb.sys;

/// Parsed metadata returned by `peekConfig`. Carries the
/// `(primitive, keyBits, mode, macName)` quadruple as named fields for
/// readable call sites.
struct EasyConfig
{
    string primitive;
    int keyBits;
    int mode;
    string macName;
}

/// Reads the offending JSON field name from the most recent
/// `ITB_Easy_Import` call that returned `Status.EasyMismatch` on this
/// thread. Empty string when the most recent failure was not a
/// mismatch.
///
/// The `Encryptor.importState` method already attaches this name to
/// the thrown `ITBEasyMismatchError.field`; this free function is
/// exposed for callers that need to read the field independently of
/// the exception path. Module-level alias for
/// `itb.errors.readLastMismatchField`.
string lastMismatchField() @trusted nothrow
{
    return readLastMismatchField();
}

/// Parses a state blob's metadata `(primitive, keyBits, mode,
/// macName)` without performing full validation, allowing a caller to
/// inspect a saved blob before constructing a matching encryptor.
///
/// Returns the four-field `EasyConfig` on success; throws
/// `ITBError(Status.EasyMalformed)` on JSON parse failure / kind
/// mismatch / too-new version / unknown mode value.
EasyConfig peekConfig(const(ubyte)[] blob) @trusted
{
    void* blobPtr = blob.length == 0 ? null : cast(void*) blob.ptr;

    // Probe both string sizes first.
    size_t primLen = 0;
    size_t macLen = 0;
    int kbOut = 0;
    int modeOut = 0;
    int rc = ITB_Easy_PeekConfig(
        blobPtr, blob.length,
        null, 0, &primLen,
        &kbOut, &modeOut,
        null, 0, &macLen);
    if (rc != Status.OK && rc != Status.BufferTooSmall)
        raiseFor(rc);

    char[] primBuf = primLen == 0 ? null : new char[primLen];
    char[] macBuf = macLen == 0 ? null : new char[macLen];
    rc = ITB_Easy_PeekConfig(
        blobPtr, blob.length,
        primBuf.ptr, primLen, &primLen,
        &kbOut, &modeOut,
        macBuf.ptr, macLen, &macLen);
    check(rc);

    EasyConfig cfg;
    cfg.keyBits = kbOut;
    cfg.mode = modeOut;
    // Strip the trailing NUL libitb counts in the *Len out-params.
    cfg.primitive = primLen <= 1 ? "" : (cast(string) primBuf[0 .. primLen - 1]).idup;
    cfg.macName = macLen <= 1 ? "" : (cast(string) macBuf[0 .. macLen - 1]).idup;
    return cfg;
}

/// High-level Encryptor over the libitb C ABI.
///
/// Construction is the heavy step — generates fresh PRF keys, fresh
/// seed components, and a fresh MAC key from `/dev/urandom`. Reusing
/// one `Encryptor` value across many encrypt / decrypt calls
/// amortises the cost across the lifetime of a session.
///
/// Lifecycle is RAII: the destructor calls `ITB_Easy_Free`
/// best-effort. `close` is the explicit zeroing path that wipes PRF /
/// MAC / seed material on the Go side and wipes the per-instance
/// output cache on the D side.
///
/// Concurrency. Cipher methods (`encrypt` / `decrypt` / `encryptAuth`
/// / `decryptAuth`) write into the per-instance output-buffer cache
/// and are **not safe** to invoke concurrently against the same
/// encryptor. Sharing one `Encryptor` value across threads requires
/// external synchronisation. Per-instance configuration setters
/// (`setNonceBits` / `setBarrierFill` / `setBitSoup` / `setLockSoup`
/// / `setLockSeed` / `setChunkSize`) and persistence (`exportState`
/// / `importState`) likewise require external synchronisation when
/// invoked against the same encryptor from multiple threads.
/// Distinct `Encryptor` values, each owned by one thread, run
/// independently against the libitb worker pool.
struct Encryptor
{
    private size_t _handle;
    /// Per-encryptor output buffer cache. Grows on demand;
    /// `close` / destructor wipe it before drop.
    private ubyte[] _outCache;

    @disable this(this);

    /// Constructs a fresh encryptor.
    ///
    /// `primitive` is a canonical hash name from `listHashes` —
    /// `"areion256"`, `"areion512"`, `"siphash24"`, `"aescmac"`,
    /// `"blake2b256"`, `"blake2b512"`, `"blake2s"`, `"blake3"`,
    /// `"chacha20"`. Empty / `null` selects the libitb default
    /// (`"areion512"`).
    ///
    /// `keyBits` is the ITB key width in bits (512, 1024, 2048;
    /// multiple of the primitive's native hash width). Pass `0` to
    /// select the libitb default (1024).
    ///
    /// `macName` is a canonical MAC name from `listMACs` —
    /// `"kmac256"`, `"hmac-sha256"`, or `"hmac-blake3"`. Both `null`
    /// and the empty string `""` trigger a binding-side override to
    /// `"hmac-blake3"` rather than forwarding NULL through to libitb's
    /// own default (`"kmac256"`); HMAC-BLAKE3 measures the lightest
    /// MAC overhead in the Easy-Mode bench surface, so the
    /// constructor-without-MAC path picks the lowest-cost
    /// authenticated MAC by default.
    ///
    /// `mode` is 1 (Single Ouroboros, 3 seeds — noise / data / start)
    /// or 3 (Triple Ouroboros, 7 seeds — noise + 3 pairs of data /
    /// start). Other values throw `ITBError(Status.BadInput)`.
    this(string primitive, int keyBits, string macName = null, int mode = 1) @trusted
    {
        if (mode != 1 && mode != 3)
            throw new ITBError(Status.BadInput,
                "mode must be 1 (Single) or 3 (Triple), got " ~ mode.to!string);

        // Binding-side default override: when the caller passes
        // `macName=null` the binding picks `hmac-blake3` rather than
        // forwarding NULL through to libitb's own default.
        string effectiveMac = (macName is null || macName.length == 0) ? "hmac-blake3" : macName;

        const(char)* primPtr = (primitive is null) ? null : toStringz(primitive);
        const(char)* macPtr = toStringz(effectiveMac);

        size_t handle = 0;
        int rc = ITB_Easy_New(
            cast(char*) primPtr, keyBits, cast(char*) macPtr, mode, &handle);
        check(rc);
        this._handle = handle;
    }

    // ─── Mixed-mode constructors ──────────────────────────────────────

    /// Constructs a Single-Ouroboros encryptor with per-slot PRF
    /// primitive selection.
    ///
    /// `primN` / `primD` / `primS` cover the noise / data / start
    /// slots; `primL` (default `null`) is the optional dedicated
    /// lockSeed primitive — when provided non-null and non-empty, a
    /// 4th seed slot is allocated under that primitive and BitSoup +
    /// LockSoup are auto-coupled on the on-direction.
    ///
    /// All four primitive names must resolve to the same native hash
    /// width via the libitb registry; mixed widths throw `ITBError`
    /// with the panic message captured in `readLastError`.
    static Encryptor newMixed(
        string primN,
        string primD,
        string primS,
        int keyBits,
        string macName = null,
        string primL = null) @trusted
    {
        string effectiveMac = (macName is null || macName.length == 0) ? "hmac-blake3" : macName;

        const(char)* nPtr = toStringz(primN);
        const(char)* dPtr = toStringz(primD);
        const(char)* sPtr = toStringz(primS);
        const(char)* macPtr = toStringz(effectiveMac);
        const(char)* lPtr = (primL is null || primL.length == 0)
            ? null : toStringz(primL);

        size_t handle = 0;
        int rc = ITB_Easy_NewMixed(
            cast(char*) nPtr,
            cast(char*) dPtr,
            cast(char*) sPtr,
            cast(char*) lPtr,
            keyBits,
            cast(char*) macPtr,
            &handle);
        check(rc);

        Encryptor e;
        e._handle = handle;
        return e;
    }

    /// Triple-Ouroboros counterpart of `Encryptor.newMixed`. Accepts
    /// seven per-slot primitive names (noise + 3 data + 3 start) plus
    /// the optional `primL` lockSeed primitive. See
    /// `Encryptor.newMixed` for the construction contract.
    static Encryptor newMixed3(
        string primN,
        string primD1,
        string primD2,
        string primD3,
        string primS1,
        string primS2,
        string primS3,
        int keyBits,
        string macName = null,
        string primL = null) @trusted
    {
        string effectiveMac = (macName is null || macName.length == 0) ? "hmac-blake3" : macName;

        const(char)* nPtr = toStringz(primN);
        const(char)* d1Ptr = toStringz(primD1);
        const(char)* d2Ptr = toStringz(primD2);
        const(char)* d3Ptr = toStringz(primD3);
        const(char)* s1Ptr = toStringz(primS1);
        const(char)* s2Ptr = toStringz(primS2);
        const(char)* s3Ptr = toStringz(primS3);
        const(char)* macPtr = toStringz(effectiveMac);
        const(char)* lPtr = (primL is null || primL.length == 0)
            ? null : toStringz(primL);

        size_t handle = 0;
        int rc = ITB_Easy_NewMixed3(
            cast(char*) nPtr,
            cast(char*) d1Ptr,
            cast(char*) d2Ptr,
            cast(char*) d3Ptr,
            cast(char*) s1Ptr,
            cast(char*) s2Ptr,
            cast(char*) s3Ptr,
            cast(char*) lPtr,
            keyBits,
            cast(char*) macPtr,
            &handle);
        check(rc);

        Encryptor e;
        e._handle = handle;
        return e;
    }

    /// Destructor — wipes the output cache, then releases the
    /// underlying libitb handle if held. Idempotent; errors are
    /// swallowed (no path to surface them from a destructor).
    ~this() @trusted
    {
        _wipeCache();
        if (_handle != 0)
        {
            cast(void) ITB_Easy_Free(_handle);
            _handle = 0;
        }
    }

    // ─── Read-only field accessors ────────────────────────────────────

    /// Opaque libitb handle id (uintptr). Useful for diagnostics and
    /// FFI-level interop; bindings should not rely on its numerical
    /// value.
    size_t handle() const @safe @nogc nothrow pure
    {
        return _handle;
    }

    /// Returns the canonical primitive name bound at construction.
    string primitive() @trusted
    {
        size_t h = _handle;
        return readString((char* buf, size_t cap, size_t* outLen) =>
            ITB_Easy_Primitive(h, buf, cap, outLen));
    }

    /// Returns the canonical hash primitive name bound to the given
    /// seed slot index.
    ///
    /// Slot ordering is canonical — 0 = noiseSeed, then
    /// dataSeed{,1..3}, then startSeed{,1..3}, with the optional
    /// dedicated lockSeed at the trailing slot. For single-primitive
    /// encryptors every slot returns the same `primitive` value; for
    /// encryptors built via `newMixed` / `newMixed3` each slot
    /// returns its independently-chosen primitive name.
    string primitiveAt(int slot) @trusted
    {
        size_t h = _handle;
        return readString((char* buf, size_t cap, size_t* outLen) =>
            ITB_Easy_PrimitiveAt(h, slot, buf, cap, outLen));
    }

    /// Returns the ITB key width in bits.
    int keyBits() @trusted
    {
        int st = 0;
        int v = ITB_Easy_KeyBits(_handle, &st);
        check(st);
        return v;
    }

    /// Returns 1 (Single Ouroboros) or 3 (Triple Ouroboros).
    int mode() @trusted
    {
        int st = 0;
        int v = ITB_Easy_Mode(_handle, &st);
        check(st);
        return v;
    }

    /// Returns `true` when the encryptor was constructed via
    /// `newMixed` / `newMixed3` (per-slot primitive selection);
    /// `false` for single-primitive encryptors built via the regular
    /// constructor.
    bool isMixed() @trusted
    {
        int st = 0;
        int v = ITB_Easy_IsMixed(_handle, &st);
        check(st);
        return v != 0;
    }

    /// Returns the canonical MAC name bound at construction.
    string macName() @trusted
    {
        size_t h = _handle;
        return readString((char* buf, size_t cap, size_t* outLen) =>
            ITB_Easy_MACName(h, buf, cap, outLen));
    }

    /// Number of seed slots: 3 (Single without LockSeed),
    /// 4 (Single with LockSeed), 7 (Triple without LockSeed),
    /// 8 (Triple with LockSeed).
    int seedCount() @trusted
    {
        int st = 0;
        int v = ITB_Easy_SeedCount(_handle, &st);
        check(st);
        return v;
    }

    /// Returns the nonce size in bits configured for this encryptor —
    /// either the value from the most recent `setNonceBits` call, or
    /// the process-wide `getNonceBits` reading at construction time
    /// when no per-instance override has been issued. Reads the live
    /// `cfg.NonceBits` via `ITB_Easy_NonceBits` so a setter call on
    /// the Go side is reflected immediately.
    int nonceBits() @trusted
    {
        int st = 0;
        int v = ITB_Easy_NonceBits(_handle, &st);
        check(st);
        return v;
    }

    /// Returns the per-instance ciphertext-chunk header size in bytes
    /// (nonce + 2-byte width + 2-byte height).
    ///
    /// Tracks this encryptor's own `nonceBits`, NOT the process-wide
    /// `headerSize` reading — important when the encryptor has called
    /// `setNonceBits` to override the default. Use this when slicing
    /// a chunk header off the front of a ciphertext stream produced
    /// by this encryptor or when sizing a tamper region for an
    /// authenticated-decrypt test.
    int easyHeaderSize() @trusted
    {
        int st = 0;
        int v = ITB_Easy_HeaderSize(_handle, &st);
        check(st);
        return v;
    }

    /// `true` when the encryptor's primitive uses fixed PRF keys per
    /// seed slot (every shipped primitive except `siphash24`).
    bool hasPRFKeys() @trusted
    {
        int st = 0;
        int v = ITB_Easy_HasPRFKeys(_handle, &st);
        check(st);
        return v != 0;
    }

    /// Per-instance counterpart of `itb.registry.parseChunkLen`.
    /// Inspects a chunk header (the fixed-size
    /// `[nonce(N) || width(2) || height(2)]` prefix where `N` comes
    /// from this encryptor's `nonceBits`) and returns the total chunk
    /// length on the wire.
    ///
    /// Use this when walking a concatenated chunk stream produced by
    /// this encryptor: read `easyHeaderSize` bytes from the wire,
    /// call `enc.parseChunkLen(buf[0 .. enc.easyHeaderSize()])`, read
    /// the remaining `chunkLen - easyHeaderSize` bytes, and feed the
    /// full chunk to `decrypt` / `decryptAuth`.
    ///
    /// The buffer must contain at least `easyHeaderSize` bytes; only
    /// the header is consulted, the body bytes do not need to be
    /// present. Throws `ITBError(Status.BadInput)` on too-short
    /// buffer, zero dimensions, or width × height overflow against
    /// the container pixel cap.
    size_t parseChunkLen(const(ubyte)[] header) @trusted
    {
        void* hdrPtr = header.length == 0 ? null : cast(void*) header.ptr;
        size_t out_ = 0;
        int rc = ITB_Easy_ParseChunkLen(_handle, hdrPtr, header.length, &out_);
        check(rc);
        return out_;
    }

    // ─── Material getters (defensive copies) ──────────────────────────

    /// Returns the uint64 components of one seed slot (defensive
    /// copy).
    ///
    /// Slot index follows the canonical ordering: Single =
    /// `[noise, data, start]`; Triple = `[noise, data1, data2,
    /// data3, start1, start2, start3]`; the dedicated lockSeed slot,
    /// when present, is appended at the trailing index (index 3 for
    /// Single, index 7 for Triple). Bindings can consult `seedCount`
    /// to determine the valid slot range for the active mode +
    /// lockSeed configuration.
    ulong[] seedComponents(int slot) @trusted
    {
        int outLen = 0;
        // Probe call — out=NULL / capCount=0 returns
        // BufferTooSmall with the required size in *outLen.
        // BadInput here would signal an out-of-range slot.
        int rc = ITB_Easy_SeedComponents(_handle, slot, null, 0, &outLen);
        if (rc == Status.OK)
            return [];
        if (rc != Status.BufferTooSmall)
            raiseFor(rc);
        auto buf = new ulong[outLen];
        rc = ITB_Easy_SeedComponents(_handle, slot, buf.ptr, outLen, &outLen);
        check(rc);
        return buf[0 .. outLen];
    }

    /// Returns the fixed PRF key bytes for one seed slot (defensive
    /// copy). Throws `ITBError(Status.BadInput)` when the primitive
    /// has no fixed PRF keys (`siphash24` — caller should consult
    /// `hasPRFKeys` first) or when `slot` is out of range.
    ubyte[] prfKey(int slot) @trusted
    {
        size_t h = _handle;
        return readBytes((ubyte* buf, size_t cap, size_t* outLen) =>
            ITB_Easy_PRFKey(h, slot, buf, cap, outLen));
    }

    /// Returns a defensive copy of the encryptor's bound MAC fixed
    /// key. Save these bytes alongside the seed material for
    /// cross-process restore via `exportState` / `importState`.
    ubyte[] macKey() @trusted
    {
        size_t h = _handle;
        return readBytes((ubyte* buf, size_t cap, size_t* outLen) =>
            ITB_Easy_MACKey(h, buf, cap, outLen));
    }

    // ─── Cipher entry points ─────────────────────────────────────────

    /// Encrypts `plaintext` using the encryptor's configured primitive
    /// / keyBits / mode and per-instance Config snapshot.
    ///
    /// Plain mode — does not attach a MAC tag; for authenticated
    /// encryption use `encryptAuth`.
    ///
    /// Returns a slice over the per-encryptor output cache; the bytes
    /// remain valid until the next cipher call on this encryptor or
    /// until `close` / destruction. Call `.dup` to detach an owned
    /// copy.
    ubyte[] encrypt(const(ubyte)[] plaintext) @trusted
    {
        return _cipherCall(&ITB_Easy_Encrypt, plaintext);
    }

    /// Decrypts ciphertext produced by `encrypt` under the same
    /// encryptor.
    ///
    /// Returns a slice over the per-encryptor output cache; the bytes
    /// remain valid until the next cipher call on this encryptor or
    /// until `close` / destruction. Call `.dup` to detach an owned
    /// copy.
    ubyte[] decrypt(const(ubyte)[] ciphertext) @trusted
    {
        return _cipherCall(&ITB_Easy_Decrypt, ciphertext);
    }

    /// Encrypts `plaintext` and attaches a MAC tag using the
    /// encryptor's bound MAC closure.
    ///
    /// Returns a slice over the per-encryptor output cache; the bytes
    /// remain valid until the next cipher call on this encryptor or
    /// until `close` / destruction. Call `.dup` to detach an owned
    /// copy.
    ubyte[] encryptAuth(const(ubyte)[] plaintext) @trusted
    {
        return _cipherCall(&ITB_Easy_EncryptAuth, plaintext);
    }

    /// Verifies and decrypts ciphertext produced by `encryptAuth`.
    /// Throws `ITBError(Status.MACFailure)` on tampered ciphertext or
    /// wrong MAC key.
    ///
    /// Returns a slice over the per-encryptor output cache; the bytes
    /// remain valid until the next cipher call on this encryptor or
    /// until `close` / destruction. Call `.dup` to detach an owned
    /// copy.
    ubyte[] decryptAuth(const(ubyte)[] ciphertext) @trusted
    {
        return _cipherCall(&ITB_Easy_DecryptAuth, ciphertext);
    }

    // ─── Per-instance configuration setters ──────────────────────────

    /// Override the nonce size for this encryptor's subsequent
    /// encrypt / decrypt calls. Valid values: 128, 256, 512.
    ///
    /// Mutates only this encryptor's Config copy; process-wide
    /// `setNonceBits` is unaffected. The `nonceBits` /
    /// `easyHeaderSize` accessors read through to the live Go-side
    /// `cfg.NonceBits`, so they reflect the new value automatically
    /// on the next access.
    void setNonceBits(int n) @trusted
    {
        check(ITB_Easy_SetNonceBits(_handle, n));
    }

    /// Override the CSPRNG barrier-fill margin for this encryptor.
    /// Valid values: 1, 2, 4, 8, 16, 32. Asymmetric — receiver does
    /// not need the same value as sender.
    void setBarrierFill(int n) @trusted
    {
        check(ITB_Easy_SetBarrierFill(_handle, n));
    }

    /// 0 = byte-level split (default); non-zero = bit-level Bit Soup
    /// split.
    void setBitSoup(int mode) @trusted
    {
        check(ITB_Easy_SetBitSoup(_handle, mode));
    }

    /// 0 = off (default); non-zero = on. Auto-couples `BitSoup=1` on
    /// this encryptor.
    void setLockSoup(int mode) @trusted
    {
        check(ITB_Easy_SetLockSoup(_handle, mode));
    }

    /// 0 = off; 1 = on (allocates a dedicated lockSeed and routes the
    /// bit-permutation overlay through it; auto-couples
    /// `LockSoup=1 + BitSoup=1` on this encryptor). Calling after the
    /// first encrypt throws
    /// `ITBError(Status.EasyLockSeedAfterEncrypt)`.
    void setLockSeed(int mode) @trusted
    {
        check(ITB_Easy_SetLockSeed(_handle, mode));
    }

    /// Per-instance streaming chunk-size override (0 = auto-detect
    /// via `itb.ChunkSize` on the Go side).
    void setChunkSize(int n) @trusted
    {
        check(ITB_Easy_SetChunkSize(_handle, n));
    }

    // ─── State serialization ─────────────────────────────────────────

    /// Serialises the encryptor's full state (PRF keys, seed
    /// components, MAC key, dedicated lockSeed material when active)
    /// as a JSON blob. The caller saves the bytes as it sees fit
    /// (disk, KMS, wire) and later passes them back to `importState`
    /// on a fresh encryptor to reconstruct the exact state.
    ///
    /// Per-instance configuration knobs (NonceBits, BarrierFill,
    /// BitSoup, LockSoup, ChunkSize) are NOT carried in the v1 blob
    /// — both sides communicate them via deployment config.
    /// LockSeed is carried because activating it changes the
    /// structural seed count.
    ubyte[] exportState() @trusted
    {
        size_t outLen = 0;
        int rc = ITB_Easy_Export(_handle, null, 0, &outLen);
        if (rc == Status.OK)
            return [];
        if (rc != Status.BufferTooSmall)
            raiseFor(rc);
        auto buf = new ubyte[outLen];
        rc = ITB_Easy_Export(_handle, cast(void*) buf.ptr, outLen, &outLen);
        check(rc);
        return buf[0 .. outLen];
    }

    /// Replaces the encryptor's PRF keys, seed components, MAC key,
    /// and (optionally) dedicated lockSeed material with the values
    /// carried in a JSON blob produced by a prior `exportState` call.
    ///
    /// On any failure the encryptor's pre-import state is unchanged
    /// (the underlying Go-side `Encryptor.Import` is transactional).
    /// Mismatch on primitive / keyBits / mode / mac throws
    /// `ITBEasyMismatchError`; the offending JSON field name is
    /// available on the exception's `.field` member and is also
    /// retrievable via `lastMismatchField`.
    void importState(const(ubyte)[] blob) @trusted
    {
        void* blobPtr = blob.length == 0 ? null : cast(void*) blob.ptr;
        int rc = ITB_Easy_Import(_handle, blobPtr, blob.length);
        check(rc);
    }

    // ─── Lifecycle ───────────────────────────────────────────────────

    /// Zeroes the encryptor's PRF keys, MAC key, and seed components
    /// on the Go side, and marks the encryptor as closed. Idempotent
    /// — multiple `close` calls return without error. Also wipes the
    /// per-encryptor output cache so the last ciphertext / plaintext
    /// does not linger in heap memory after the encryptor's working
    /// set has been zeroed on the Go side.
    void close() @trusted
    {
        _wipeCache();
        if (_handle == 0)
            return;
        check(ITB_Easy_Close(_handle));
    }

    // ─── Internals ───────────────────────────────────────────────────

    private alias FnEasyCipher = extern (C) int function(
        size_t, void*, size_t, void*, size_t, size_t*) @system @nogc nothrow;

    /// Direct-call buffer-convention dispatcher with a per-encryptor
    /// output cache. Skips the size-probe round-trip the lower-level
    /// FFI helpers use: pre-allocates output capacity from a 1.25×
    /// upper bound (the empirical ITB ciphertext-expansion factor
    /// measured at ≤ 1.155 across every primitive / mode / nonce /
    /// payload-size combination) and falls through to an explicit
    /// grow-and-retry only on the rare under-shoot. Reuses the buffer
    /// across calls; `close` / destructor wipe it before drop.
    ///
    /// The current `Easy_Encrypt` / `Easy_Decrypt` C ABI does the
    /// full crypto on every call regardless of out-buffer capacity
    /// (it computes the result internally, then returns
    /// `BufferTooSmall` without exposing the work) — so the
    /// pre-allocation here avoids paying for a duplicate encrypt /
    /// decrypt on each D call.
    private ubyte[] _cipherCall(FnEasyCipher fn, const(ubyte)[] payload) @trusted
    {
        // 1.25× + 4 KiB headroom comfortably exceeds the 1.155 max
        // expansion factor observed across the primitive / mode /
        // nonce-bits matrix; floor at 4 KiB so the very-small payload
        // case still gets a usable buffer. Saturating arithmetic
        // protects against `size_t` wrap on 32-bit targets at very
        // large payload sizes — under wrap the grow-and-retry path
        // would still recover, but only at the cost of an extra
        // round-trip; saturating to `size_t.max` keeps the first call
        // big enough on any host.
        size_t cap = _saturatingExpansion(payload.length);
        _ensureCache(cap);

        void* inPtr = payload.length == 0 ? null : cast(void*) payload.ptr;

        size_t outLen = 0;
        int rc = fn(
            _handle,
            inPtr, payload.length,
            cast(void*) _outCache.ptr, _outCache.length,
            &outLen);
        if (rc == Status.BufferTooSmall)
        {
            // Pre-allocation was too tight (extremely rare given the
            // 1.25× safety margin) — grow exactly to the required
            // size and retry. The first call already paid for the
            // underlying crypto via the current C ABI's
            // full-encrypt-on-every-call contract, so the retry runs
            // the work again; this is strictly the fallback path and
            // not the hot loop.
            _ensureCache(outLen);
            rc = fn(
                _handle,
                inPtr, payload.length,
                cast(void*) _outCache.ptr, _outCache.length,
                &outLen);
        }
        check(rc);
        return _outCache[0 .. outLen];
    }

    /// Computes the saturating output-cache capacity estimate for a
    /// payload of size `n`. Caps at `size_t.max` on overflow rather
    /// than wrapping, so the first cipher call never under-allocates
    /// silently on pathologically large payloads.
    private static size_t _saturatingExpansion(size_t n) @safe @nogc nothrow pure
    {
        // n * 5 / 4 with overflow-safe arithmetic.
        size_t mul;
        if (n > size_t.max / 5)
            mul = size_t.max;
        else
            mul = (n * 5) / 4;
        size_t add;
        if (mul > size_t.max - 4096)
            add = size_t.max;
        else
            add = mul + 4096;
        return add < 4096 ? 4096 : add;
    }

    /// Ensures the output cache has at least `need` bytes of
    /// capacity. Wipe-on-grow: zeroes the OLD slice before discarding
    /// the reference, so the previous-call ciphertext does not linger
    /// in heap garbage waiting for GC.
    private void _ensureCache(size_t need) @trusted
    {
        if (_outCache.length >= need)
            return;
        if (_outCache.length > 0)
            _outCache[] = 0;
        size_t cap = need < 4096 ? 4096 : need;
        _outCache = new ubyte[cap];
    }

    /// Zeroes and drops the output cache. Used by `close` and the
    /// destructor.
    private void _wipeCache() @trusted
    {
        if (_outCache.length > 0)
            _outCache[] = 0;
        _outCache = null;
    }
}
