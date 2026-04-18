#!/usr/bin/env python3
"""Prepare binary streams per hash variant for dieharder / NIST STS.

Reads all ciphertexts in tmp/encrypted/<hash>/*.bin, strips the 20-byte
header (16 nonce + 2W + 2H), concatenates the pixel bytes, writes to
tmp/streams/<hash>.bin.

Output size: ~40 MB per hash from 387 samples (mostly huge kinds).
"""

import sys
import glob
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import HASH_DIRNAMES, HEADER_SIZE

PROJ = Path(__file__).resolve().parents[3]
ROOT = PROJ / "tmp"
ENCRYPTED = ROOT / "encrypted"
STREAMS = ROOT / "streams"

def prepare(hash_name: str):
    bins = sorted(glob.glob(str(ENCRYPTED / hash_name / "*.bin")))
    out_path = STREAMS / f"{hash_name}.bin"
    STREAMS.mkdir(exist_ok=True, parents=True)
    total_bytes = 0
    with open(out_path, "wb") as out:
        for b in bins:
            data = open(b, "rb").read()
            out.write(data[HEADER_SIZE:])
            total_bytes += len(data) - HEADER_SIZE
    print(f"  {hash_name}: {len(bins):3d} samples -> {out_path}  ({total_bytes} bytes = {total_bytes*8} bits)")
    return out_path, total_bytes

if __name__ == "__main__":
    print("Preparing ciphertext streams (pixel bytes only, headers stripped)")
    for h in HASH_DIRNAMES:
        prepare(h)
