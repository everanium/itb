/// Low-level encrypt / decrypt entry points.
///
/// Mirrors the free functions exposed by Rust's `encrypt` module:
/// `encrypt` / `decrypt` over a `(noise, data, start)` Single Ouroboros
/// seed trio, `encryptTriple` / `decryptTriple` over a seven-seed
/// Triple Ouroboros configuration, and the four authenticated `*Auth`
/// variants that take an additional `MAC` handle.
///
/// Every entry point follows the libitb probe-then-allocate idiom:
/// the first FFI call passes `cap = 0` to discover the required
/// output size via `Status.BufferTooSmall`, then a second call
/// writes the produced bytes into a freshly-allocated buffer. The
/// allocation is GC-managed; for the throughput-sensitive Easy Mode
/// surface, the per-encryptor output buffer cache (in
/// `itb.encryptor`) skips the second-call round-trip.
module itb.cipher;

import itb.errors : check, ITBError, raiseFor;
import itb.mac : MAC;
import itb.seed : Seed;
import itb.status : Status;
import itb.sys;

// --------------------------------------------------------------------
// Single Ouroboros — three seeds.
// --------------------------------------------------------------------

/// Encrypts `plaintext` under the (noise, data, start) seed trio.
///
/// All three seeds must share the same native hash width.
ubyte[] encrypt(ref const Seed noise, ref const Seed data, ref const Seed start,
                const(ubyte)[] plaintext) @trusted
{
    return dispatchSingle(&ITB_Encrypt, noise, data, start, plaintext);
}

/// Decrypts ciphertext produced by `encrypt` under the same seed trio.
ubyte[] decrypt(ref const Seed noise, ref const Seed data, ref const Seed start,
                const(ubyte)[] ciphertext) @trusted
{
    return dispatchSingle(&ITB_Decrypt, noise, data, start, ciphertext);
}

// --------------------------------------------------------------------
// Triple Ouroboros — seven seeds.
// --------------------------------------------------------------------

/// Triple Ouroboros encrypt over seven seeds.
///
/// Splits plaintext across three interleaved snake payloads. The
/// on-wire ciphertext format is the same shape as `encrypt` — only
/// the internal split / interleave differs. All seven seeds must
/// share the same native hash width and be pairwise distinct handles.
ubyte[] encryptTriple(
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    const(ubyte)[] plaintext) @trusted
{
    return dispatchTriple(&ITB_Encrypt3,
        noise, data1, data2, data3, start1, start2, start3, plaintext);
}

/// Inverse of `encryptTriple`.
ubyte[] decryptTriple(
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    const(ubyte)[] ciphertext) @trusted
{
    return dispatchTriple(&ITB_Decrypt3,
        noise, data1, data2, data3, start1, start2, start3, ciphertext);
}

// --------------------------------------------------------------------
// Authenticated Single — three seeds + MAC.
// --------------------------------------------------------------------

/// Authenticated single-Ouroboros encrypt with MAC-Inside-Encrypt.
ubyte[] encryptAuth(
    ref const Seed noise, ref const Seed data, ref const Seed start,
    ref const MAC mac, const(ubyte)[] plaintext) @trusted
{
    return dispatchAuth(&ITB_EncryptAuth, noise, data, start, mac, plaintext);
}

/// Authenticated single-Ouroboros decrypt. Throws `ITBError` with
/// `Status.MACFailure` on tampered ciphertext or wrong MAC key.
ubyte[] decryptAuth(
    ref const Seed noise, ref const Seed data, ref const Seed start,
    ref const MAC mac, const(ubyte)[] ciphertext) @trusted
{
    return dispatchAuth(&ITB_DecryptAuth, noise, data, start, mac, ciphertext);
}

// --------------------------------------------------------------------
// Authenticated Triple — seven seeds + MAC.
// --------------------------------------------------------------------

/// Authenticated Triple Ouroboros encrypt (7 seeds + MAC).
ubyte[] encryptAuthTriple(
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    ref const MAC mac, const(ubyte)[] plaintext) @trusted
{
    return dispatchAuthTriple(&ITB_EncryptAuth3,
        noise, data1, data2, data3, start1, start2, start3, mac, plaintext);
}

/// Authenticated Triple Ouroboros decrypt.
ubyte[] decryptAuthTriple(
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    ref const MAC mac, const(ubyte)[] ciphertext) @trusted
{
    return dispatchAuthTriple(&ITB_DecryptAuth3,
        noise, data1, data2, data3, start1, start2, start3, mac, ciphertext);
}

// --------------------------------------------------------------------
// Internal dispatch helpers — probe / allocate / write idiom.
// --------------------------------------------------------------------

private alias FnSingle = extern (C) int function(
    size_t, size_t, size_t,
    void*, size_t, void*, size_t, size_t*) @system @nogc nothrow;

private alias FnTriple = extern (C) int function(
    size_t, size_t, size_t, size_t, size_t, size_t, size_t,
    void*, size_t, void*, size_t, size_t*) @system @nogc nothrow;

private alias FnAuthSingle = extern (C) int function(
    size_t, size_t, size_t, size_t,
    void*, size_t, void*, size_t, size_t*) @system @nogc nothrow;

private alias FnAuthTriple = extern (C) int function(
    size_t, size_t, size_t, size_t, size_t, size_t, size_t, size_t,
    void*, size_t, void*, size_t, size_t*) @system @nogc nothrow;

private ubyte[] dispatchSingle(
    FnSingle fn,
    ref const Seed noise, ref const Seed data, ref const Seed start,
    const(ubyte)[] payload) @trusted
{
    void* inPtr = payload.length == 0 ? null : cast(void*) payload.ptr;
    size_t outLen = 0;
    int rc = fn(noise.handle, data.handle, start.handle,
        inPtr, payload.length, null, 0, &outLen);
    if (rc == Status.OK)
        return [];
    if (rc != Status.BufferTooSmall)
        raiseFor(rc);
    auto buf = new ubyte[outLen];
    rc = fn(noise.handle, data.handle, start.handle,
        inPtr, payload.length, cast(void*) buf.ptr, outLen, &outLen);
    check(rc);
    return buf[0 .. outLen];
}

private ubyte[] dispatchTriple(
    FnTriple fn,
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    const(ubyte)[] payload) @trusted
{
    void* inPtr = payload.length == 0 ? null : cast(void*) payload.ptr;
    size_t outLen = 0;
    int rc = fn(
        noise.handle,
        data1.handle, data2.handle, data3.handle,
        start1.handle, start2.handle, start3.handle,
        inPtr, payload.length, null, 0, &outLen);
    if (rc == Status.OK)
        return [];
    if (rc != Status.BufferTooSmall)
        raiseFor(rc);
    auto buf = new ubyte[outLen];
    rc = fn(
        noise.handle,
        data1.handle, data2.handle, data3.handle,
        start1.handle, start2.handle, start3.handle,
        inPtr, payload.length, cast(void*) buf.ptr, outLen, &outLen);
    check(rc);
    return buf[0 .. outLen];
}

private ubyte[] dispatchAuth(
    FnAuthSingle fn,
    ref const Seed noise, ref const Seed data, ref const Seed start,
    ref const MAC mac, const(ubyte)[] payload) @trusted
{
    void* inPtr = payload.length == 0 ? null : cast(void*) payload.ptr;
    size_t outLen = 0;
    int rc = fn(noise.handle, data.handle, start.handle, mac.handle,
        inPtr, payload.length, null, 0, &outLen);
    if (rc == Status.OK)
        return [];
    if (rc != Status.BufferTooSmall)
        raiseFor(rc);
    auto buf = new ubyte[outLen];
    rc = fn(noise.handle, data.handle, start.handle, mac.handle,
        inPtr, payload.length, cast(void*) buf.ptr, outLen, &outLen);
    check(rc);
    return buf[0 .. outLen];
}

private ubyte[] dispatchAuthTriple(
    FnAuthTriple fn,
    ref const Seed noise,
    ref const Seed data1, ref const Seed data2, ref const Seed data3,
    ref const Seed start1, ref const Seed start2, ref const Seed start3,
    ref const MAC mac, const(ubyte)[] payload) @trusted
{
    void* inPtr = payload.length == 0 ? null : cast(void*) payload.ptr;
    size_t outLen = 0;
    int rc = fn(
        noise.handle,
        data1.handle, data2.handle, data3.handle,
        start1.handle, start2.handle, start3.handle,
        mac.handle,
        inPtr, payload.length, null, 0, &outLen);
    if (rc == Status.OK)
        return [];
    if (rc != Status.BufferTooSmall)
        raiseFor(rc);
    auto buf = new ubyte[outLen];
    rc = fn(
        noise.handle,
        data1.handle, data2.handle, data3.handle,
        start1.handle, start2.handle, start3.handle,
        mac.handle,
        inPtr, payload.length, cast(void*) buf.ptr, outLen, &outLen);
    check(rc);
    return buf[0 .. outLen];
}
