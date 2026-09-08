#!/usr/bin/env python3
"""Tabulate tools/loop JSON summaries produced by loop_policy_sweep.sh.

Reads every *.json in the given directory (each holding one --json-output
summary line), and prints a Markdown table ordered by cell label with the
policy knobs the run executed under (microbatch_tiers / hashpool_starters
/ gogc) next to the throughput, allocation, GC and pool-miss figures.

Usage:
    python3 scripts/bench/loop_policy_aggregate.py OUT_DIR [--sort payload]
"""
import glob
import json
import os
import sys

MiB = 1024 * 1024

COLUMNS = (
    "cell", "hash", "gogc", "tiers", "pools", "payload",
    "enc MB/s", "dec MB/s", "alloc MiB/iter", "gc/s", "gc cpu %",
    "hash miss %", "buf miss %", "chunk miss %", "peak heap MiB", "verdict",
)


def human_size(n):
    for unit, div in (("MB", MiB), ("KB", 1024)):
        if n % div == 0 and n >= div:
            return f"{n // div}{unit}"
    return str(n)


def load(path):
    with open(path) as f:
        lines = [ln for ln in f.read().splitlines() if ln.strip()]
    if not lines:
        return None
    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError:
        return None


def hash_miss(d):
    tiers = d.get("hash_pool_tiers") or []
    get = sum(t["get"] for t in tiers)
    miss = sum(t["new"] + t["regrow"] for t in tiers)
    return 100.0 * miss / get if get else 0.0


def row(stem, d):
    return (
        stem,
        d.get("hash", ""),
        d.get("gogc", ""),
        d.get("microbatch_tiers", "?"),
        d.get("hashpool_starters", "?"),
        human_size(int(d.get("payload_bytes", 0))),
        f"{d['encrypt_mb_per_sec']:.1f}",
        f"{d['decrypt_mb_per_sec']:.1f}",
        f"{d['alloc_bytes_per_iteration'] / MiB:.2f}",
        f"{d['gc_per_sec']:.1f}",
        f"{d['gc_cpu_fraction'] * 100:.2f}",
        f"{hash_miss(d):.1f}",
        f"{d['buf_pool']['miss_percent']:.1f}",
        f"{d['parallax_chunk_pool']['miss_percent']:.1f}",
        f"{d['heap_peak_bytes'] / MiB:.0f}",
        d.get("verdict", ""),
    )


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    out = argv[1]
    sort_payload = "--sort" in argv and "payload" in argv
    rows = []
    for path in sorted(glob.glob(os.path.join(out, "*.json"))):
        d = load(path)
        if d is None:
            print(f"skip (no summary): {path}", file=sys.stderr)
            continue
        rows.append((int(d.get("payload_bytes", 0)), row(os.path.basename(path)[:-5], d)))
    if sort_payload:
        rows.sort(key=lambda r: (r[0], r[1][0]))
    print("| " + " | ".join(COLUMNS) + " |")
    print("|" + "---|" * len(COLUMNS))
    for _, r in rows:
        print("| " + " | ".join(r) + " |")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
