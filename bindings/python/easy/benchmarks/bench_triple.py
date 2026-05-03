"""Easy-Mode Triple-Ouroboros benchmarks for the Python binding.

Mirrors the BenchmarkTriple* cohort from itb3_ext_test.go for the
nine PRF-grade primitives, locked at 1024-bit ITB key width and 16
MiB CSPRNG-filled payload. One mixed-primitive variant
(:meth:`itb.Encryptor.mixed_triple` cycling the same BLAKE family +
Areion-SoEM-256 dedicated lockSeed used by bench_single_mixed)
covers the Easy-Mode Mixed surface alongside the single-primitive
grid.

Run with::

    python -m bindings.python.easy.benchmarks.bench_triple

    ITB_NONCE_BITS=512 \
    ITB_LOCKSEED=1 \
        python -m bindings.python.easy.benchmarks.bench_triple

    ITB_BENCH_FILTER=blake3_encrypt \
        python -m bindings.python.easy.benchmarks.bench_triple

The harness emits one Go-bench-style line per case (name, iters,
ns/op, MB/s). See ``_common.py`` for the supported environment
variables and the convergence policy. The pure Bit-Soup
configuration is intentionally not exercised on the Triple side —
the BitSoup/LockSoup overlay routes through the auto-coupled path
when ITB_LOCKSEED=1, which already covers the Triple bit-level
split surface end-to-end.
"""

from __future__ import annotations

import sys
from typing import Callable, List, Tuple

import itb

from . import _common


# Canonical 9-primitive PRF-grade order from CLAUDE.md (positions
# 4 through 12).
PRIMITIVES_CANONICAL: List[str] = [
    "areion256",
    "areion512",
    "blake2b256",
    "blake2b512",
    "blake2s",
    "blake3",
    "aescmac",
    "siphash24",
    "chacha20",
]

# Mixed-primitive composition for Triple Ouroboros — the same four
# 256-bit-wide names used by bench_single_mixed are cycled across
# the seven seed slots (noise + 3 data + 3 start) plus
# Areion-SoEM-256 on the dedicated lockSeed slot.
MIXED_NOISE = "blake3"
MIXED_DATA1 = "blake2s"
MIXED_DATA2 = "blake2b256"
MIXED_DATA3 = "blake3"
MIXED_START1 = "blake2s"
MIXED_START2 = "blake2b256"
MIXED_START3 = "blake3"
MIXED_LOCK = "areion256"

KEY_BITS = 1024
MAC_NAME = "hmac-blake3"
PAYLOAD_BYTES = _common.PAYLOAD_16MB


def _apply_lockseed_if_requested(enc: itb.Encryptor) -> None:
    """When ``ITB_LOCKSEED`` is set the harness flips the dedicated
    lockSeed channel on every encryptor. Easy Mode auto-couples
    BitSoup + LockSoup as a side effect."""
    if _common.env_lock_seed():
        enc.set_lock_seed(1)


def _build_triple(primitive: str) -> itb.Encryptor:
    """Construct a single-primitive 1024-bit Triple-Ouroboros
    encryptor with HMAC-BLAKE3 authentication. Triple = mode=3, 7-seed
    layout."""
    enc = itb.Encryptor(primitive, KEY_BITS, MAC_NAME, mode=3)
    _apply_lockseed_if_requested(enc)
    return enc


def _build_mixed_triple() -> itb.Encryptor:
    """Construct a mixed-primitive Triple-Ouroboros encryptor with
    the four-name BLAKE family across the seven middle slots. The
    dedicated Areion-SoEM-256 lockSeed slot is allocated only when
    ``ITB_LOCKSEED`` is set, so the no-LockSeed bench arm measures
    the plain mixed-primitive cost without the BitSoup + LockSoup
    auto-couple. The four primitive names share the same native hash
    width so the Encryptor.mixed_triple width-check passes."""
    primL = MIXED_LOCK if _common.env_lock_seed() else None
    enc = itb.Encryptor.mixed_triple(
        primitive_n=MIXED_NOISE,
        primitive_d1=MIXED_DATA1,
        primitive_d2=MIXED_DATA2,
        primitive_d3=MIXED_DATA3,
        primitive_s1=MIXED_START1,
        primitive_s2=MIXED_START2,
        primitive_s3=MIXED_START3,
        primitive_l=primL,
        key_bits=KEY_BITS,
        mac=MAC_NAME,
    )
    return enc


def _make_encrypt_case(name: str, builder: Callable[[], itb.Encryptor]) -> _common.BenchCase:
    enc = builder()
    payload = _common.random_bytes(PAYLOAD_BYTES)

    def fn(iters: int) -> None:
        for _ in range(iters):
            enc.encrypt(payload)

    return (name, fn, PAYLOAD_BYTES)


def _make_decrypt_case(name: str, builder: Callable[[], itb.Encryptor]) -> _common.BenchCase:
    enc = builder()
    payload = _common.random_bytes(PAYLOAD_BYTES)
    ciphertext = enc.encrypt(payload)

    def fn(iters: int) -> None:
        for _ in range(iters):
            enc.decrypt(ciphertext)

    return (name, fn, PAYLOAD_BYTES)


def _make_encrypt_auth_case(name: str, builder: Callable[[], itb.Encryptor]) -> _common.BenchCase:
    enc = builder()
    payload = _common.random_bytes(PAYLOAD_BYTES)

    def fn(iters: int) -> None:
        for _ in range(iters):
            enc.encrypt_auth(payload)

    return (name, fn, PAYLOAD_BYTES)


def _make_decrypt_auth_case(name: str, builder: Callable[[], itb.Encryptor]) -> _common.BenchCase:
    enc = builder()
    payload = _common.random_bytes(PAYLOAD_BYTES)
    ciphertext = enc.encrypt_auth(payload)

    def fn(iters: int) -> None:
        for _ in range(iters):
            enc.decrypt_auth(ciphertext)

    return (name, fn, PAYLOAD_BYTES)


def _build_cases() -> List[_common.BenchCase]:
    """Assemble the full case list: 9 single-primitive entries
    × 4 ops + 1 mixed entry × 4 ops = 40 cases. Order is
    primitive-major / op-minor so a filter on a primitive name
    keeps all four ops grouped together in the output."""
    cases: List[_common.BenchCase] = []
    for prim in PRIMITIVES_CANONICAL:
        builder = (lambda p=prim: _build_triple(p))
        base = f"bench_triple_{prim}_{KEY_BITS}bit"
        cases.append(_make_encrypt_case(f"{base}_encrypt_16mb", builder))
        cases.append(_make_decrypt_case(f"{base}_decrypt_16mb", builder))
        cases.append(_make_encrypt_auth_case(f"{base}_encrypt_auth_16mb", builder))
        cases.append(_make_decrypt_auth_case(f"{base}_decrypt_auth_16mb", builder))

    base = f"bench_triple_mixed_{KEY_BITS}bit"
    cases.append(_make_encrypt_case(f"{base}_encrypt_16mb", _build_mixed_triple))
    cases.append(_make_decrypt_case(f"{base}_decrypt_16mb", _build_mixed_triple))
    cases.append(_make_encrypt_auth_case(f"{base}_encrypt_auth_16mb", _build_mixed_triple))
    cases.append(_make_decrypt_auth_case(f"{base}_decrypt_auth_16mb", _build_mixed_triple))

    return cases


def main() -> None:
    nonce_bits = _common.env_nonce_bits()
    itb.set_max_workers(0)
    itb.set_nonce_bits(nonce_bits)

    print(
        f"# easy_triple primitives={len(PRIMITIVES_CANONICAL)} "
        f"key_bits={KEY_BITS} mac={MAC_NAME} "
        f"nonce_bits={nonce_bits} "
        f"lockseed={'on' if _common.env_lock_seed() else 'off'} "
        f"workers=auto",
        flush=True,
    )

    cases = _build_cases()
    _common.run_all(cases)


if __name__ == "__main__":
    main()
