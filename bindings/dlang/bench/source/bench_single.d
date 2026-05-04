/// Easy-Mode Single-Ouroboros benchmarks for the D binding.
///
/// Mirrors the BenchmarkSingle* cohort from itb_ext_test.go for the
/// nine PRF-grade primitives, locked at 1024-bit ITB key width and
/// 16 MiB CSPRNG-filled payload. One mixed-primitive variant
/// (`Encryptor.newMixed` with BLAKE3 / BLAKE2s / BLAKE2b-256 +
/// Areion-SoEM-256 dedicated lockSeed) covers the Easy-Mode Mixed
/// surface alongside the single-primitive grid.
///
/// Run with:
///
/// ---
/// dub build :single --compiler=ldc2
/// ./bench/bin/itb-bench-single
///
/// ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ./bench/bin/itb-bench-single
///
/// ITB_BENCH_FILTER=blake3_encrypt ./bench/bin/itb-bench-single
/// ---
///
/// The harness emits one Go-bench-style line per case (name, iters,
/// ns/op, MB/s). See `bench.common` for the supported environment
/// variables and the convergence policy.
module bench.bench_single;

import std.format : format;
import std.stdio : writeln;

import itb : Encryptor, setMaxWorkers, setNonceBits;

import bench.common :
    BenchCase,
    BenchFn,
    PAYLOAD_16MB,
    PRIMITIVES_CANONICAL,
    envLockSeed,
    envNonceBits,
    randomBytes,
    runAll;

// Mixed-primitive composition used by the Mixed Single bench cases.
// noise / data / start cycle through the BLAKE family while
// Areion-SoEM-256 takes the dedicated lockSeed slot - every name
// resolves to a 256-bit native hash width so the Encryptor.newMixed
// width-check passes.
private enum string MIXED_NOISE = "blake3";
private enum string MIXED_DATA = "blake2s";
private enum string MIXED_START = "blake2b256";
private enum string MIXED_LOCK = "areion256";

private enum int KEY_BITS = 1024;
private enum string MAC_NAME = "hmac-blake3";
private enum size_t PAYLOAD_BYTES = PAYLOAD_16MB;

// Heap-resident registry of bench encryptors so each closure can
// reach its Encryptor through a stable pointer. Encryptors are
// non-copyable in D (`@disable this(this)`) so the closure must
// reference them rather than capture by value.
private struct EncBox { Encryptor enc; }

private EncBox*[] _encryptorRegistry;

/// Apply the dedicated lockSeed slot when `ITB_LOCKSEED` is set. Easy
/// Mode auto-couples BitSoup + LockSoup as a side effect, so no
/// separate calls are issued.
private void applyLockSeedIfRequested(Encryptor* enc) @trusted
{
    if (envLockSeed())
        enc.setLockSeed(1);
}

/// Construct a single-primitive 1024-bit Single-Ouroboros encryptor
/// with HMAC-BLAKE3 authentication. Stored on the heap-resident
/// registry so the closure can reach it through a stable pointer.
private EncBox* buildSingle(string primitive) @trusted
{
    auto box = new EncBox;
    box.enc = Encryptor(primitive, KEY_BITS, MAC_NAME, 1);
    applyLockSeedIfRequested(&box.enc);
    _encryptorRegistry ~= box;
    return box;
}

/// Construct a mixed-primitive Single-Ouroboros encryptor matching
/// the README Quick Start composition (BLAKE3 noise / BLAKE2s data /
/// BLAKE2b-256 start). The dedicated Areion-SoEM-256 lockSeed slot
/// is allocated only when `ITB_LOCKSEED` is set, so the no-LockSeed
/// bench arm measures the plain mixed-primitive cost without the
/// BitSoup + LockSoup auto-couple. The four primitive names share
/// the 256-bit native hash width.
private EncBox* buildMixedSingle() @trusted
{
    // When `primL` is set, newMixed auto-couples BitSoup + LockSoup
    // on construction; an extra setLockSeed call would be a
    // redundant no-op against the already-active lockSeed slot.
    // When `primL` is null the encryptor stays in plain mixed mode.
    string primL = envLockSeed() ? MIXED_LOCK : null;
    auto box = new EncBox;
    box.enc = Encryptor.newMixed(
        MIXED_NOISE, MIXED_DATA, MIXED_START,
        KEY_BITS, MAC_NAME, primL);
    _encryptorRegistry ~= box;
    return box;
}

/// Build a plain-Encrypt bench case. Encryptor + payload are
/// constructed once outside the measured loop; only the encrypt call
/// is timed.
private BenchCase makeEncryptCase(string name, EncBox* box) @trusted
{
    auto payload = randomBytes(PAYLOAD_BYTES);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
            cast(void) box.enc.encrypt(payload);
    };
    return BenchCase(name, run, PAYLOAD_BYTES);
}

/// Build a plain-Decrypt bench case. Pre-encrypts a single
/// ciphertext outside the measured loop; only the decrypt call is
/// timed.
private BenchCase makeDecryptCase(string name, EncBox* box) @trusted
{
    auto payload = randomBytes(PAYLOAD_BYTES);
    auto ciphertext = box.enc.encrypt(payload).dup;
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
            cast(void) box.enc.decrypt(ciphertext);
    };
    return BenchCase(name, run, PAYLOAD_BYTES);
}

/// Build an authenticated-Encrypt bench case (MAC tag attached).
private BenchCase makeEncryptAuthCase(string name, EncBox* box) @trusted
{
    auto payload = randomBytes(PAYLOAD_BYTES);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
            cast(void) box.enc.encryptAuth(payload);
    };
    return BenchCase(name, run, PAYLOAD_BYTES);
}

/// Build an authenticated-Decrypt bench case (MAC tag verified on
/// the way back).
private BenchCase makeDecryptAuthCase(string name, EncBox* box) @trusted
{
    auto payload = randomBytes(PAYLOAD_BYTES);
    auto ciphertext = box.enc.encryptAuth(payload).dup;
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
            cast(void) box.enc.decryptAuth(ciphertext);
    };
    return BenchCase(name, run, PAYLOAD_BYTES);
}

/// Assemble the full case list: 9 single-primitive entries x 4 ops
/// plus 1 mixed entry x 4 ops = 40 cases. Order is primitive-major /
/// op-minor so a filter on a primitive name keeps all four ops
/// grouped together in the output.
private BenchCase[] buildCases() @trusted
{
    BenchCase[] cases;
    cases.reserve(40);
    foreach (prim; PRIMITIVES_CANONICAL)
    {
        string base = format("bench_single_%s_%dbit", prim, KEY_BITS);
        cases ~= makeEncryptCase(
            format("%s_encrypt_16mb", base), buildSingle(prim));
        cases ~= makeDecryptCase(
            format("%s_decrypt_16mb", base), buildSingle(prim));
        cases ~= makeEncryptAuthCase(
            format("%s_encrypt_auth_16mb", base), buildSingle(prim));
        cases ~= makeDecryptAuthCase(
            format("%s_decrypt_auth_16mb", base), buildSingle(prim));
    }
    string base = format("bench_single_mixed_%dbit", KEY_BITS);
    cases ~= makeEncryptCase(
        format("%s_encrypt_16mb", base), buildMixedSingle());
    cases ~= makeDecryptCase(
        format("%s_decrypt_16mb", base), buildMixedSingle());
    cases ~= makeEncryptAuthCase(
        format("%s_encrypt_auth_16mb", base), buildMixedSingle());
    cases ~= makeDecryptAuthCase(
        format("%s_decrypt_auth_16mb", base), buildMixedSingle());
    return cases;
}

void main() @trusted
{
    int nonceBits = envNonceBits(128);
    setMaxWorkers(0);
    setNonceBits(nonceBits);

    writeln(format(
        "# easy_single primitives=%d key_bits=%d mac=%s nonce_bits=%d lockseed=%s workers=auto",
        PRIMITIVES_CANONICAL.length,
        KEY_BITS,
        MAC_NAME,
        nonceBits,
        envLockSeed() ? "on" : "off"));

    auto cases = buildCases();
    runAll(cases);
}
