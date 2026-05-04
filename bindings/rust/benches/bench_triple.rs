//! Easy-Mode Triple-Ouroboros benchmarks for the Rust binding.
//!
//! Mirrors the BenchmarkTriple* cohort from itb3_ext_test.go for the
//! nine PRF-grade primitives, locked at 1024-bit ITB key width and 16
//! MiB CSPRNG-filled payload. One mixed-primitive variant
//! ([`itb::Encryptor::mixed_triple`] cycling the same BLAKE family +
//! Areion-SoEM-256 dedicated lockSeed used by bench_single_mixed)
//! covers the Easy-Mode Mixed surface alongside the single-primitive
//! grid.
//!
//! Run with::
//!
//!     cargo bench --bench bench_triple
//!
//!     ITB_NONCE_BITS=512 ITB_LOCKSEED=1 \
//!         cargo bench --bench bench_triple
//!
//!     ITB_BENCH_FILTER=blake3_encrypt \
//!         cargo bench --bench bench_triple
//!
//! The harness emits one Go-bench-style line per case (name, iters,
//! ns/op, MB/s). See `common.rs` for the supported environment
//! variables and the convergence policy. The pure bit-soup
//! configuration is intentionally not exercised on the Triple side —
//! the BitSoup/LockSoup overlay routes through the auto-coupled path
//! when ITB_LOCKSEED=1, which already covers the Triple bit-level
//! split surface end-to-end.

#[path = "common.rs"]
mod common;

use itb::Encryptor;

use crate::common::{BenchCase, BenchFn, PAYLOAD_16MB};

// Canonical 9-primitive PRF-grade order, mirroring bench_triple.py.
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

// Mixed-primitive composition for Triple Ouroboros — the same four
// 256-bit-wide names used by bench_single_mixed are cycled across
// the seven seed slots (noise + 3 data + 3 start) plus
// Areion-SoEM-256 on the dedicated lockSeed slot.
const MIXED_NOISE: &str = "blake3";
const MIXED_DATA1: &str = "blake2s";
const MIXED_DATA2: &str = "blake2b256";
const MIXED_DATA3: &str = "blake3";
const MIXED_START1: &str = "blake2s";
const MIXED_START2: &str = "blake2b256";
const MIXED_START3: &str = "blake3";
const MIXED_LOCK: &str = "areion256";

const KEY_BITS: i32 = 1024;
const MAC_NAME: &str = "hmac-blake3";
const PAYLOAD_BYTES: usize = PAYLOAD_16MB;

/// When `ITB_LOCKSEED` is set the harness flips the dedicated
/// lockSeed channel on every encryptor. Easy Mode auto-couples
/// BitSoup + LockSoup as a side effect.
fn apply_lockseed_if_requested(enc: &Encryptor) {
    if common::env_lock_seed() {
        enc.set_lock_seed(1).expect("set_lock_seed(1)");
    }
}

/// Construct a single-primitive 1024-bit Triple-Ouroboros encryptor
/// with KMAC256 authentication. Triple = mode=3, 7-seed layout.
fn build_triple(primitive: &str) -> Encryptor {
    let enc = Encryptor::new(Some(primitive), Some(KEY_BITS), Some(MAC_NAME), 3)
        .unwrap_or_else(|e| panic!("Encryptor::new({primitive}, mode=3): {e:?}"));
    apply_lockseed_if_requested(&enc);
    enc
}

/// Construct a mixed-primitive Triple-Ouroboros encryptor with the
/// four-name BLAKE family across the seven middle slots. The
/// dedicated Areion-SoEM-256 lockSeed slot is allocated only when
/// `ITB_LOCKSEED` is set, so the no-LockSeed bench arm measures the
/// plain mixed-primitive cost without the BitSoup + LockSoup
/// auto-couple. The four primitive names share the same native hash
/// width so the `Encryptor::mixed_triple` width-check passes.
fn build_mixed_triple() -> Encryptor {
    let prim_l = if common::env_lock_seed() { Some(MIXED_LOCK) } else { None };
    Encryptor::mixed_triple(
        MIXED_NOISE,
        MIXED_DATA1,
        MIXED_DATA2,
        MIXED_DATA3,
        MIXED_START1,
        MIXED_START2,
        MIXED_START3,
        prim_l,
        KEY_BITS,
        MAC_NAME,
    )
    .expect("mixed_triple")
}

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
        let base = format!("bench_triple_{prim}_{KEY_BITS}bit");
        cases.push(make_encrypt_case(
            format!("{base}_encrypt_16mb"),
            build_triple(prim),
        ));
        cases.push(make_decrypt_case(
            format!("{base}_decrypt_16mb"),
            build_triple(prim),
        ));
        cases.push(make_encrypt_auth_case(
            format!("{base}_encrypt_auth_16mb"),
            build_triple(prim),
        ));
        cases.push(make_decrypt_auth_case(
            format!("{base}_decrypt_auth_16mb"),
            build_triple(prim),
        ));
    }
    let base = format!("bench_triple_mixed_{KEY_BITS}bit");
    cases.push(make_encrypt_case(
        format!("{base}_encrypt_16mb"),
        build_mixed_triple(),
    ));
    cases.push(make_decrypt_case(
        format!("{base}_decrypt_16mb"),
        build_mixed_triple(),
    ));
    cases.push(make_encrypt_auth_case(
        format!("{base}_encrypt_auth_16mb"),
        build_mixed_triple(),
    ));
    cases.push(make_decrypt_auth_case(
        format!("{base}_decrypt_auth_16mb"),
        build_mixed_triple(),
    ));
    cases
}

fn main() {
    let nonce_bits = common::env_nonce_bits(128);
    itb::set_max_workers(0).expect("set_max_workers(0)");
    itb::set_nonce_bits(nonce_bits).expect("set_nonce_bits");

    println!(
        "# easy_triple primitives={} key_bits={} mac={} nonce_bits={} lockseed={} workers=auto",
        PRIMITIVES_CANONICAL.len(),
        KEY_BITS,
        MAC_NAME,
        nonce_bits,
        if common::env_lock_seed() { "on" } else { "off" },
    );

    let cases = build_cases();
    common::run_all(cases);
}
