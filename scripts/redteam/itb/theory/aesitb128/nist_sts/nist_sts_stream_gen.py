#!/usr/bin/env python3
"""ChainHash<AES-ITB-128> output-stream generator for NIST STS 2.1.2.

Reuses the bit-exact reference ChainHash implementation from
`chainhashes.aesitb128` (validated on import against the shipped
`aesitb/aesitb_test.go` KAT vectors) and emits a concatenated binary
stream of lo-lane bytes suitable for `/usr/bin/nist-sts` (`Input File`
generator, binary data format).

The lo lane is the observable the shipped Pixel Barrier consumes, so NIST
STS is measuring exactly the wire byte stream ITB emits at each cascade
depth.

Per call: draws random `data` of length `--data-len` bytes, computes
ChainHash<aesitb128>(seed, data) at cascade depth `--rounds`, appends
the 8-byte lo lane to the output file. Total stream = `--samples` * 8
bytes. For a NIST STS run with `--samples 156250`, the file is
10^7 bits = 1.25 MB, matching the NIST STS default `n = 1_000_000` bits
per substream x 10 substreams.

Seed reproducibility: `--seed-hex` pins the 16 seed uint64 components
via SHA-256 expansion of the hex string; `--random-seed` picks a fresh
one from `os.urandom` and prints it to stderr for the runner log.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path

import numpy as np

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "_common"))

from chainhashes import aesitb128 as prim  # noqa: E402

N_SEED_COMPONENTS_MAX = 32  # 16 rounds x 2 uint64 lanes


def seed_from_hex(hex_str: str, n_components: int) -> list[int]:
    """Deterministically expand a hex string into `n_components` uint64
    seed components via SHA-256(hex_str || "seed" || counter)."""
    comps = []
    raw = bytes.fromhex(hex_str)
    counter = 0
    while len(comps) < n_components:
        h = hashlib.sha256(raw + b"seed" + counter.to_bytes(4, "little")).digest()
        for j in range(0, 32, 8):
            comps.append(int.from_bytes(h[j:j + 8], "little"))
            if len(comps) >= n_components:
                break
        counter += 1
    return comps


def data_stream(hex_str: str, total_bytes: int) -> bytes:
    """Deterministic DRBG (CSPRNG-seeded SHAKE-256) that produces the
    concatenated random-data bytes fed into each ChainHash call. Same
    seed_hex -> identical data_arr sequence, so a report is regenerable
    exactly from the seed_log line.

    SHAKE-256 is used for its arbitrary-length output; the pinned prefix
    b"data" separates this stream from the seed-component DRBG (seed"),
    so the two derivations never collide."""
    xof = hashlib.shake_256(bytes.fromhex(hex_str) + b"data")
    return xof.digest(total_bytes)


def random_seed_hex() -> str:
    return os.urandom(32).hex()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--rounds", type=int, required=True,
                    help="ChainHash cascade depth r (1 = raw primitive)")
    ap.add_argument("--data-len", type=int, required=True,
                    help="Data byte length per call (shipped shapes: 13/20/36/68)")
    ap.add_argument("--samples", type=int, default=156_250,
                    help="Number of ChainHash calls (default 156250 = 10^7 bits)")
    ap.add_argument("--seed-hex", type=str, default=None,
                    help="Deterministic hex seed material (else random from urandom)")
    ap.add_argument("--out", type=str, required=True,
                    help="Output binary file path")
    ap.add_argument("--batch", type=int, default=8192,
                    help="Batch size for the numpy evaluator (default 8192)")
    args = ap.parse_args()

    r = args.rounds
    if r < 1 or r > 16:
        print(f"error: --rounds must be in [1,16], got {r}", file=sys.stderr)
        return 2
    n_comps = 2 * r
    if args.seed_hex is None:
        seed_hex = random_seed_hex()
        print(f"[gen] fresh random seed_hex={seed_hex}", file=sys.stderr)
    else:
        seed_hex = args.seed_hex
        print(f"[gen] pinned seed_hex={seed_hex}", file=sys.stderr)
    comps = seed_from_hex(seed_hex, n_comps)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    total = args.samples
    L = args.data_len
    # Produce the entire deterministic data stream once via SHAKE-256(seed).
    # 156_250 * 68 = 10.6 MB worst case — well within memory.
    data_bytes = data_stream(seed_hex, total * L)
    written = 0
    with open(out_path, "wb") as f:
        while written < total:
            n = min(args.batch, total - written)
            off = written * L
            data_arr = np.frombuffer(data_bytes[off:off + n * L],
                                     dtype=np.uint8).reshape(n, L)
            lo = prim.chainhash_batch(data_arr, comps, rounds=r, discard=True)
            f.write(lo.tobytes())
            written += n

    size_bytes = out_path.stat().st_size
    print(f"[gen] wrote {size_bytes} bytes ({size_bytes*8} bits) "
          f"to {out_path} (r={r} shape={L} samples={total})",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
