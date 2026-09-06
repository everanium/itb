#!/usr/bin/env python3
"""4th-order integral: a 2^32-text Λ-set (four active data bytes) through
ChainHash<AES-ITB-128> — the cost step above order3_chainhash.py, used to
ask whether a larger structured sample finds an integral where orders 1-3
read at the floor. The active positions matter:

  * `--active 3,4,9,14` (default) — a DIAGONAL of the column-major state
    (rows 0..3 in columns 1, 2, 3, 0). ShiftRows moves all four into one
    column, MixColumns makes that column a 32-bit permutation, and the set
    splits into 2^24 one-byte Λ-sets after the first round: the classic
    4-round Square set. Valid at every data length >= 15 (byte 15 is the
    PKCS#7 pad at the one-block shape, so the 0,5,10,15 diagonal is not).
  * `--active 0,1,2,3` — a COLUMN. After ShiftRows the four bytes sit in
    four different columns; the set reaches only the 3-round property.

Cells of interest: shipped 20-byte shape at r = 1 (4 rounds per call —
the diagonal set is predicted balanced with probability 1, the column set
not: positive / negative control), and the one-block lab shape at r = 2,
where the value entering the second call is pad(data) XOR seed_2 XOR
h_1(data) and the order-4 test asks whether the top monomial of a 32-bit
data sub-cube vanishes for any output byte.

The XOR-sum over 2^32 texts is split across worker processes (2^20 texts
per task); the four active bytes carry the LE32 text index, the remaining
data bytes a random constant. Only the XOR-sums are combined, so the
result is exact. Cost ~3.7 CPU-s per 2^20 chunk -> ~4 CPU-hours per cell
(~15 min on 16 cores).
"""
import argparse
import multiprocessing as mp
import os
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from screens_common import OBSERVABLES, depth_label, observables, random_comps  # noqa: E402

_CFG = {}


def _init(cfg):
    _CFG.update(cfg)


def _worker(start):
    n = _CFG["chunk"]
    L = _CFG["data_len"]
    idx = np.arange(start, start + n, dtype=np.uint64)
    arr = np.broadcast_to(_CFG["fixed"], (n, L)).copy()
    for k, pos in enumerate(_CFG["active"]):
        arr[:, pos] = ((idx >> np.uint64(8 * k)) & np.uint64(0xFF)).astype(np.uint8)
    obs = observables(arr, _CFG["comps"], _CFG["rounds"])
    out = {}
    for k, v in obs.items():
        out[k] = (np.bitwise_xor.reduce(v, axis=0), v[0].copy(), np.any(v != v[0], axis=0))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-len", type=int, default=15)
    ap.add_argument("--rounds", type=int, default=1)
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--log2-texts", type=int, default=32)
    ap.add_argument("--active", default="3,4,9,14",
                    help="four active data byte positions (default: a diagonal; "
                         "0,1,2,3 = a column)")
    args = ap.parse_args()

    active = [int(p) for p in args.active.split(",")]
    assert len(active) == 4 and max(active) < min(args.data_len, 16)
    n_total = 1 << args.log2_texts
    chunk = 1 << 20
    fixed = np.frombuffer(os.urandom(args.data_len), dtype=np.uint8).copy()
    cfg = dict(chunk=chunk, data_len=args.data_len, fixed=fixed, active=active,
               comps=random_comps(args.rounds), rounds=args.rounds)
    print(f"4th-order integral through ChainHash<AES-ITB-128>: 2^{args.log2_texts} texts, "
          f"active bytes {active}, data_len={args.data_len}, rounds={args.rounds} "
          f"({depth_label(args.rounds) or 'cascade'}), {args.workers} workers", flush=True)
    t0 = time.time()
    acc = {k: None for k in OBSERVABLES}
    first = {}
    active = {}
    with mp.Pool(args.workers, initializer=_init, initargs=(cfg,)) as pool:
        for i, res in enumerate(pool.imap_unordered(_worker, range(0, n_total, chunk))):
            for k, (x, f0, act) in res.items():
                acc[k] = x if acc[k] is None else acc[k] ^ x
                if k not in first:
                    first[k] = f0
                    active[k] = np.zeros(act.shape, dtype=bool)
                active[k] |= act | (f0 != first[k])
            if (i + 1) % 512 == 0:
                print(f"  ... {i + 1}/{n_total // chunk} chunks, {time.time() - t0:.0f} s", flush=True)
    print(f"{'observable':>20} {'#active':>8} {'#balanced':>10} {'rand_exp':>9}  verdict", flush=True)
    for k in OBSERVABLES:
        nb = acc[k].shape[0]
        bal = int(np.count_nonzero(acc[k] == 0))
        act = int(np.count_nonzero(active[k]))
        rexp = nb / 256.0
        tag = "HIGHER-ORDER LEAK" if bal > rexp + 1 else "random (no 4th-order leak)"
        print(f"{k:>20} {act:>8} {bal:>10} {rexp:>9.3f}  {tag}", flush=True)
    print(f"DONE ({time.time() - t0:.0f} s)", flush=True)


if __name__ == "__main__":
    main()
