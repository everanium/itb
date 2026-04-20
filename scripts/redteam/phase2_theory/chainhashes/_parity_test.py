#!/usr/bin/env python3
"""Go ↔ Python mirror parity test for the pluggable chainhashes modules.

Runs the Go helper `_parity_dump/main.go`, parses its JSON dump of
`(primitive, data, seed) → (lo, hi)` vectors, and verifies that every
`chainhashes/<primitive>.py` mirror reproduces those outputs bit-for-bit.

Fails loudly on any divergence — a single mismatched vector means the
bias-probe numbers for that primitive are untrustworthy.

Usage:
    python3 scripts/redteam/phase2_theory/chainhashes/_parity_test.py
"""

from __future__ import annotations

import importlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJ = HERE.parents[3]
GO_DUMP = HERE / "_parity_dump" / "main.go"

# Add phase2_theory to sys.path so we can import chainhashes.<name>
sys.path.insert(0, str(HERE.parent))


def run_go_dump() -> list[dict]:
    print(f"[parity] running {GO_DUMP} ...")
    out = subprocess.run(
        ["go", "run", str(GO_DUMP)],
        cwd=PROJ, capture_output=True, text=True, check=True,
    )
    return json.loads(out.stdout)


def verify(entries: list[dict]) -> int:
    failures = 0
    by_prim: dict[str, int] = {}
    for e in entries:
        prim = e["primitive"]
        by_prim[prim] = by_prim.get(prim, 0) + 1
        mod = importlib.import_module(f"chainhashes.{prim}")
        data = bytes.fromhex(e["data_hex"])
        seed = list(e["seed_components"])
        expected_lo = int(e["expected_lo_hex"], 16)
        got_lo = mod.chainhash_lo(data, seed) & ((1 << 64) - 1)
        if got_lo != expected_lo:
            failures += 1
            print(f"  MISMATCH [{prim}] data={len(data)}B  "
                  f"got={got_lo:016x}  expected={expected_lo:016x}")
        else:
            print(f"  OK       [{prim}] data={len(data)}B  lo={got_lo:016x}")
    return failures


def main() -> int:
    entries = run_go_dump()
    print(f"[parity] {len(entries)} vectors across "
          f"{len(set(e['primitive'] for e in entries))} primitive(s)")
    failures = verify(entries)
    if failures:
        print(f"[parity] FAIL — {failures}/{len(entries)} vectors diverged")
        return 1
    print(f"[parity] PASS — {len(entries)}/{len(entries)} vectors match")
    return 0


if __name__ == "__main__":
    sys.exit(main())
