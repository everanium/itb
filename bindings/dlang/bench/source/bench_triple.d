/// Easy-Mode Triple-Ouroboros benchmarks for the D binding.
///
/// Mirrors the BenchmarkTriple* cohort from itb3_ext_test.go for the
/// nine PRF-grade primitives, locked at 1024-bit ITB key width and
/// 16 MiB CSPRNG-filled payload. One mixed-primitive variant
/// (`Encryptor.newMixed3` cycling the same BLAKE family +
/// Areion-SoEM-256 dedicated lockSeed used by bench_single's mixed
/// case) covers the Easy-Mode Mixed surface alongside the
/// single-primitive grid.
///
/// Run with:
///
/// ---
/// dub build :triple --compiler=ldc2
/// ./bench/bin/itb-bench-triple
///
/// ITB_NONCE_BITS=512 ITB_LOCKSEED=1 ./bench/bin/itb-bench-triple
///
/// ITB_BENCH_FILTER=blake3_encrypt ./bench/bin/itb-bench-triple
/// ---
///
/// The harness emits one Go-bench-style line per case (name, iters,
/// ns/op, MB/s). See `bench.common` for the supported environment
/// variables and the convergence policy. The pure bit-soup
/// configuration is intentionally not exercised on the Triple side -
/// the BitSoup/LockSoup overlay routes through the auto-coupled path
/// when `ITB_LOCKSEED=1`, which already covers the Triple bit-level
/// split surface end-to-end.
module bench.bench_triple;

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

// Mixed-primitive composition for Triple Ouroboros - the same four
// 256-bit-wide names used by bench_single's Mixed case are cycled
// across the seven seed slots (noise + 3 data + 3 start) plus
// Areion-SoEM-256 on the dedicated lockSeed slot.
private enum string MIXED_NOISE = "blake3";
private enum string MIXED_DATA1 = "blake2s";
private enum string MIXED_DATA2 = "blake2b256";
private enum string MIXED_DATA3 = "blake3";
private enum string MIXED_START1 = "blake2s";
private enum string MIXED_START2 = "blake2b256";
private enum string MIXED_START3 = "blake3";
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

/// Apply the dedicated lockSeed slot when `ITB_LOCKSEED` is set.
/// Easy Mode auto-couples BitSoup + LockSoup as a side effect.
private void applyLockSeedIfRequested(Encryptor* enc) @trusted
{
    if (envLockSeed())
        enc.setLockSeed(1);
}

/// Construct a single-primitive 1024-bit Triple-Ouroboros encryptor
/// with HMAC-BLAKE3 authentication. Triple = mode=3, 7-seed layout.
private EncBox* buildTriple(string primitive) @trusted
{
    auto box = new EncBox;
    box.enc = Encryptor(primitive, KEY_BITS, MAC_NAME, 3);
    applyLockSeedIfRequested(&box.enc);
    _encryptorRegistry ~= box;
    return box;
}

/// Construct a mixed-primitive Triple-Ouroboros encryptor with the
/// four-name BLAKE family across the seven middle slots. The
/// dedicated Areion-SoEM-256 lockSeed slot is allocated only when
/// `ITB_LOCKSEED` is set, so the no-LockSeed bench arm measures the
/// plain mixed-primitive cost without the BitSoup + LockSoup
/// auto-couple. The four primitive names share the same native hash
/// width so the `Encryptor.newMixed3` width-check passes.
private EncBox* buildMixedTriple() @trusted
{
    string primL = envLockSeed() ? MIXED_LOCK : null;
    auto box = new EncBox;
    box.enc = Encryptor.newMixed3(
        MIXED_NOISE,
        MIXED_DATA1, MIXED_DATA2, MIXED_DATA3,
        MIXED_START1, MIXED_START2, MIXED_START3,
        KEY_BITS, MAC_NAME, primL);
    _encryptorRegistry ~= box;
    return box;
}

private BenchCase makeEncryptCase(string name, EncBox* box) @trusted
{
    auto payload = randomBytes(PAYLOAD_BYTES);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
            cast(void) box.enc.encrypt(payload);
    };
    return BenchCase(name, run, PAYLOAD_BYTES);
}

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

private BenchCase makeEncryptAuthCase(string name, EncBox* box) @trusted
{
    auto payload = randomBytes(PAYLOAD_BYTES);
    BenchFn run = (ulong iters) {
        foreach (_; 0 .. iters)
            cast(void) box.enc.encryptAuth(payload);
    };
    return BenchCase(name, run, PAYLOAD_BYTES);
}

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
        string base = format("bench_triple_%s_%dbit", prim, KEY_BITS);
        cases ~= makeEncryptCase(
            format("%s_encrypt_16mb", base), buildTriple(prim));
        cases ~= makeDecryptCase(
            format("%s_decrypt_16mb", base), buildTriple(prim));
        cases ~= makeEncryptAuthCase(
            format("%s_encrypt_auth_16mb", base), buildTriple(prim));
        cases ~= makeDecryptAuthCase(
            format("%s_decrypt_auth_16mb", base), buildTriple(prim));
    }
    string base = format("bench_triple_mixed_%dbit", KEY_BITS);
    cases ~= makeEncryptCase(
        format("%s_encrypt_16mb", base), buildMixedTriple());
    cases ~= makeDecryptCase(
        format("%s_decrypt_16mb", base), buildMixedTriple());
    cases ~= makeEncryptAuthCase(
        format("%s_encrypt_auth_16mb", base), buildMixedTriple());
    cases ~= makeDecryptAuthCase(
        format("%s_decrypt_auth_16mb", base), buildMixedTriple());
    return cases;
}

void main() @trusted
{
    int nonceBits = envNonceBits(128);
    setMaxWorkers(0);
    setNonceBits(nonceBits);

    writeln(format(
        "# easy_triple primitives=%d key_bits=%d mac=%s nonce_bits=%d lockseed=%s workers=auto",
        PRIMITIVES_CANONICAL.length,
        KEY_BITS,
        MAC_NAME,
        nonceBits,
        envLockSeed() ? "on" : "off"));

    auto cases = buildCases();
    runAll(cases);
}
