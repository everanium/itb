//! Easy-Mode Single-Ouroboros benchmarks for the Rust binding.
//!
//! Mirrors the BenchmarkSingle* cohort from itb_ext_test.go for the
//! nine PRF-grade primitives, locked at 1024-bit ITB key width and 16
//! MiB CSPRNG-filled payload. One mixed-primitive variant
//! ([`itb::Encryptor::mixed_single`] with BLAKE3 / BLAKE2s /
//! BLAKE2b-256 + Areion-SoEM-256 dedicated lockSeed) covers the
//! Easy-Mode Mixed surface alongside the single-primitive grid.
//!
//! Run with::
//!
//!     cargo bench --bench bench_single
//!
//!     ITB_NONCE_BITS=512 ITB_LOCKSEED=1 \
//!         cargo bench --bench bench_single
//!
//!     ITB_BENCH_FILTER=blake3_encrypt \
//!         cargo bench --bench bench_single
//!
//! The harness emits one Go-bench-style line per case (name, iters,
//! ns/op, MB/s). See `common.rs` for the supported environment
//! variables and the convergence policy.

#[path = "common.rs"]
mod common;

use itb::Encryptor;

use crate::common::{BenchCase, BenchFn, PAYLOAD_16MB};

// Canonical 9-primitive PRF-grade order, mirroring bench_single.py.
// The three below-spec lab primitives (CRC128, FNV-1a, MD5) are not
// exposed through the libitb registry and are therefore absent here
// by construction.
const PRIMITIVES_CANONICAL: &[&str] = &[
    "areion256",
    "areion512",
    "blake2b256",
    "blake2b512",
    "blake2s",
    "blake3",
    "aescmac",
    "siphash24",
    "chacha20",
];

// Mixed-primitive composition used by the bench_single_mixed_*
// cases. noise / data / start cycle through the BLAKE family while
// Areion-SoEM-256 takes the dedicated lockSeed slot — every name
// resolves to a 256-bit native hash width so the
// Encryptor::mixed_single width-check passes.
const MIXED_NOISE: &str = "blake3";
const MIXED_DATA: &str = "blake2s";
const MIXED_START: &str = "blake2b256";
const MIXED_LOCK: &str = "areion256";

const KEY_BITS: i32 = 1024;
const MAC_NAME: &str = "hmac-blake3";
const PAYLOAD_BYTES: usize = PAYLOAD_16MB;

/// When `ITB_LOCKSEED` is set the harness flips the dedicated
/// lockSeed channel on every encryptor. Easy Mode auto-couples
/// BitSoup + LockSoup as a side effect, so no separate calls are
/// issued.
fn apply_lockseed_if_requested(enc: &Encryptor) {
    if common::env_lock_seed() {
        enc.set_lock_seed(1).expect("set_lock_seed(1)");
    }
}

/// Construct a single-primitive 1024-bit Single-Ouroboros encryptor
/// with KMAC256 authentication, mirroring the shape used by every
/// benchmark in this module.
fn build_single(primitive: &str) -> Encryptor {
    let enc = Encryptor::new(Some(primitive), Some(KEY_BITS), Some(MAC_NAME), 1)
        .unwrap_or_else(|e| panic!("Encryptor::new({primitive}): {e:?}"));
    apply_lockseed_if_requested(&enc);
    enc
}

/// Construct a mixed-primitive Single-Ouroboros encryptor matching
/// the README Quick Start composition (BLAKE3 noise / BLAKE2s data /
/// BLAKE2b-256 start). The dedicated Areion-SoEM-256 lockSeed slot
/// is allocated only when `ITB_LOCKSEED` is set, so the no-LockSeed
/// bench arm measures the plain mixed-primitive cost without the
/// BitSoup + LockSoup auto-couple. The four primitive names share
/// the 256-bit native hash width.
fn build_mixed_single() -> Encryptor {
    // When `primitive_l` is set, mixed_single auto-couples BitSoup +
    // LockSoup on construction; an extra set_lock_seed call would be
    // a redundant no-op against the already-active lockSeed slot.
    // When `primitive_l` is None the encryptor stays in plain mixed
    // mode.
    let prim_l = if common::env_lock_seed() { Some(MIXED_LOCK) } else { None };
    Encryptor::mixed_single(
        MIXED_NOISE,
        MIXED_DATA,
        MIXED_START,
        KEY_BITS,
        MAC_NAME,
        prim_l,
    )
    .expect("mixed_single")
}

/// Build a plain-Encrypt bench case. Encryptor + payload are
/// constructed once outside the measured loop; only the encrypt call
/// is timed.
fn make_encrypt_case(name: String, mut enc: Encryptor) -> BenchCase {
    let payload = common::random_bytes(PAYLOAD_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = enc.encrypt(&payload).expect("encrypt");
        }
    });
    BenchCase {
        name,
        run,
        payload_bytes: PAYLOAD_BYTES,
    }
}

/// Build a plain-Decrypt bench case. Pre-encrypts a single
/// ciphertext outside the measured loop; only the decrypt call is
/// timed.
fn make_decrypt_case(name: String, mut enc: Encryptor) -> BenchCase {
    let payload = common::random_bytes(PAYLOAD_BYTES);
    let ciphertext = enc.encrypt(&payload).expect("encrypt for decrypt-case");
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = enc.decrypt(&ciphertext).expect("decrypt");
        }
    });
    BenchCase {
        name,
        run,
        payload_bytes: PAYLOAD_BYTES,
    }
}

/// Build an authenticated-Encrypt bench case (MAC tag attached).
fn make_encrypt_auth_case(name: String, mut enc: Encryptor) -> BenchCase {
    let payload = common::random_bytes(PAYLOAD_BYTES);
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = enc.encrypt_auth(&payload).expect("encrypt_auth");
        }
    });
    BenchCase {
        name,
        run,
        payload_bytes: PAYLOAD_BYTES,
    }
}

/// Build an authenticated-Decrypt bench case (MAC tag verified on
/// the way back).
fn make_decrypt_auth_case(name: String, mut enc: Encryptor) -> BenchCase {
    let payload = common::random_bytes(PAYLOAD_BYTES);
    let ciphertext = enc
        .encrypt_auth(&payload)
        .expect("encrypt_auth for decrypt-case");
    let run: BenchFn = Box::new(move |iters: u64| {
        for _ in 0..iters {
            let _ = enc.decrypt_auth(&ciphertext).expect("decrypt_auth");
        }
    });
    BenchCase {
        name,
        run,
        payload_bytes: PAYLOAD_BYTES,
    }
}

/// Assemble the full case list: 9 single-primitive entries × 4 ops
/// plus 1 mixed entry × 4 ops = 40 cases. Order is primitive-major /
/// op-minor so a filter on a primitive name keeps all four ops
/// grouped together in the output.
fn build_cases() -> Vec<BenchCase> {
    let mut cases: Vec<BenchCase> = Vec::with_capacity(40);
    for prim in PRIMITIVES_CANONICAL {
        let base = format!("bench_single_{prim}_{KEY_BITS}bit");
        cases.push(make_encrypt_case(
            format!("{base}_encrypt_16mb"),
            build_single(prim),
        ));
        cases.push(make_decrypt_case(
            format!("{base}_decrypt_16mb"),
            build_single(prim),
        ));
        cases.push(make_encrypt_auth_case(
            format!("{base}_encrypt_auth_16mb"),
            build_single(prim),
        ));
        cases.push(make_decrypt_auth_case(
            format!("{base}_decrypt_auth_16mb"),
            build_single(prim),
        ));
    }
    let base = format!("bench_single_mixed_{KEY_BITS}bit");
    cases.push(make_encrypt_case(
        format!("{base}_encrypt_16mb"),
        build_mixed_single(),
    ));
    cases.push(make_decrypt_case(
        format!("{base}_decrypt_16mb"),
        build_mixed_single(),
    ));
    cases.push(make_encrypt_auth_case(
        format!("{base}_encrypt_auth_16mb"),
        build_mixed_single(),
    ));
    cases.push(make_decrypt_auth_case(
        format!("{base}_decrypt_auth_16mb"),
        build_mixed_single(),
    ));
    cases
}

fn main() {
    let nonce_bits = common::env_nonce_bits(128);
    itb::set_max_workers(0).expect("set_max_workers(0)");
    itb::set_nonce_bits(nonce_bits).expect("set_nonce_bits");

    println!(
        "# easy_single primitives={} key_bits={} mac={} nonce_bits={} lockseed={} workers=auto",
        PRIMITIVES_CANONICAL.len(),
        KEY_BITS,
        MAC_NAME,
        nonce_bits,
        if common::env_lock_seed() { "on" } else { "off" },
    );

    let cases = build_cases();
    common::run_all(cases);
}
