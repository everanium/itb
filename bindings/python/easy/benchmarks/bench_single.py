"""Easy-Mode Single-Ouroboros benchmarks for the Python binding.

Mirrors the BenchmarkSingle* cohort from itb_ext_test.go for the
nine PRF-grade primitives, locked at 1024-bit ITB key width and 16
MiB CSPRNG-filled payload. One mixed-primitive variant
(:meth:`itb.Encryptor.mixed_single` with BLAKE3 / BLAKE2s /
BLAKE2b-256 + Areion-SoEM-256 dedicated lockSeed) covers the
Easy-Mode Mixed surface alongside the single-primitive grid.

Run with::

    python -m bindings.python.easy.benchmarks.bench_single

    ITB_NONCE_BITS=512 \
    ITB_LOCKSEED=1 \
        python -m bindings.python.easy.benchmarks.bench_single

    ITB_BENCH_FILTER=blake3_encrypt \
        python -m bindings.python.easy.benchmarks.bench_single

The harness emits one Go-bench-style line per case (name, iters,
ns/op, MB/s). See ``_common.py`` for the supported environment
variables and the convergence policy.
"""

from __future__ import annotations

import sys
from typing import Callable, List, Tuple

import itb

from . import _common


# Canonical 9-primitive PRF-grade order from CLAUDE.md (positions
# 4 through 12). The three below-spec lab primitives (CRC128,
# FNV-1a, MD5) are not exposed through the libitb registry and are
# therefore absent here by construction.
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

# Mixed-primitive composition used by the bench_single_mixed_*
# cases. noise / data / start cycle through the BLAKE family while
# Areion-SoEM-256 takes the dedicated lockSeed slot — every name
# resolves to a 256-bit native hash width so the
# Encryptor.mixed_single width-check passes.
MIXED_NOISE = "blake3"
MIXED_DATA = "blake2s"
MIXED_START = "blake2b256"
MIXED_LOCK = "areion256"

KEY_BITS = 1024
MAC_NAME = "kmac256"
PAYLOAD_BYTES = _common.PAYLOAD_16MB


def _apply_lockseed_if_requested(enc: itb.Encryptor) -> None:
    """When ``ITB_LOCKSEED`` is set the harness flips the dedicated
    lockSeed channel on every encryptor. Easy Mode auto-couples
    BitSoup + LockSoup as a side effect, so no separate calls are
    issued."""
    if _common.env_lock_seed():
        enc.set_lock_seed(1)


def _build_single(primitive: str) -> itb.Encryptor:
    """Construct a single-primitive 1024-bit Single-Ouroboros
    encryptor with KMAC256 authentication, mirroring the shape used
    by every benchmark in this module."""
    enc = itb.Encryptor(primitive, KEY_BITS, MAC_NAME, mode=1)
    _apply_lockseed_if_requested(enc)
    return enc


def _build_mixed_single() -> itb.Encryptor:
    """Construct a mixed-primitive Single-Ouroboros encryptor
    matching the README Quick Start composition (BLAKE3 noise /
    BLAKE2s data / BLAKE2b-256 start + Areion-SoEM-256 dedicated
    lockSeed). The four primitive names share the 256-bit native
    hash width."""
    enc = itb.Encryptor.mixed_single(
        primitive_n=MIXED_NOISE,
        primitive_d=MIXED_DATA,
        primitive_s=MIXED_START,
        primitive_l=MIXED_LOCK,
        key_bits=KEY_BITS,
        mac=MAC_NAME,
    )
    # mixed_single with primitive_l set already auto-couples
    # BitSoup + LockSoup; calling set_lock_seed here would be a
    # redundant no-op against the already-active lockSeed slot.
    return enc


def _make_encrypt_case(name: str, builder: Callable[[], itb.Encryptor]) -> _common.BenchCase:
    """Build a plain-Encrypt bench case bound to ``builder``. The
    encryptor + payload are constructed once outside the measured
    loop; only the encrypt call is timed."""
    enc = builder()
    payload = _common.random_bytes(PAYLOAD_BYTES)

    def fn(iters: int) -> None:
        for _ in range(iters):
            enc.encrypt(payload)

    return (name, fn, PAYLOAD_BYTES)


def _make_decrypt_case(name: str, builder: Callable[[], itb.Encryptor]) -> _common.BenchCase:
    """Build a plain-Decrypt bench case. Pre-encrypts a single
    ciphertext outside the measured loop; only the decrypt call is
    timed."""
    enc = builder()
    payload = _common.random_bytes(PAYLOAD_BYTES)
    ciphertext = enc.encrypt(payload)

    def fn(iters: int) -> None:
        for _ in range(iters):
            enc.decrypt(ciphertext)

    return (name, fn, PAYLOAD_BYTES)


def _make_encrypt_auth_case(name: str, builder: Callable[[], itb.Encryptor]) -> _common.BenchCase:
    """Build an authenticated-Encrypt bench case (MAC tag attached)."""
    enc = builder()
    payload = _common.random_bytes(PAYLOAD_BYTES)

    def fn(iters: int) -> None:
        for _ in range(iters):
            enc.encrypt_auth(payload)

    return (name, fn, PAYLOAD_BYTES)


def _make_decrypt_auth_case(name: str, builder: Callable[[], itb.Encryptor]) -> _common.BenchCase:
    """Build an authenticated-Decrypt bench case (MAC tag verified
    on the way back)."""
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
        builder = (lambda p=prim: _build_single(p))
        base = f"bench_single_{prim}_{KEY_BITS}bit"
        cases.append(_make_encrypt_case(f"{base}_encrypt_16mb", builder))
        cases.append(_make_decrypt_case(f"{base}_decrypt_16mb", builder))
        cases.append(_make_encrypt_auth_case(f"{base}_encrypt_auth_16mb", builder))
        cases.append(_make_decrypt_auth_case(f"{base}_decrypt_auth_16mb", builder))

    base = f"bench_single_mixed_{KEY_BITS}bit"
    cases.append(_make_encrypt_case(f"{base}_encrypt_16mb", _build_mixed_single))
    cases.append(_make_decrypt_case(f"{base}_decrypt_16mb", _build_mixed_single))
    cases.append(_make_encrypt_auth_case(f"{base}_encrypt_auth_16mb", _build_mixed_single))
    cases.append(_make_decrypt_auth_case(f"{base}_decrypt_auth_16mb", _build_mixed_single))

    return cases


def main() -> None:
    nonce_bits = _common.env_nonce_bits()
    itb.set_max_workers(0)
    itb.set_nonce_bits(nonce_bits)

    print(
        f"# easy_single primitives={len(PRIMITIVES_CANONICAL)} "
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
