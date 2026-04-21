#!/usr/bin/env python3
"""Matrix cell emitter — one-shot helper invoked per cell by the parallel
driver. Reads the cell's summary.jsonl, stamps matrix_{size,coverage,
kind,exit_code} fields onto each entry, and appends to the aggregate
matrix_summary.jsonl + human-readable progress log under flock so
parallel workers don't interleave output."""
import fcntl
import json
import sys
from pathlib import Path


def main() -> int:
    (src, size, cov, kind, rc, matrix_summary, progress_log) = sys.argv[1:]
    src_path = Path(src)
    entries = []
    with open(src_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            entry["matrix_size"] = int(size)
            entry["matrix_coverage"] = int(cov)
            entry["matrix_kind"] = kind
            entry["matrix_exit_code"] = int(rc)
            entries.append(entry)
    # Compact one-liner for the progress log (uses first entry).
    first = entries[0] if entries else {}
    demask = "OK" if first.get("demask_ok") else "FAIL"
    si_ok = first.get("compound_key_ok")
    si = "OK" if si_ok is True else ("FAIL" if si_ok is False else "—")
    cand = first.get("compound_key_brute_candidates", "—")
    cor = first.get("compound_key_n_correct", "—")
    sha = first.get("compound_key_n_shadow", "—")
    chm = first.get("compound_key_channels_matched", "—")
    cht = first.get("compound_key_channels_total", "—")
    shift = first.get("compound_key_chosen_shift", "—")
    wall = first.get("compound_key_elapsed_s", "—")
    human = (f"size={size:>7} cov={cov}% kind={kind:<16} demask={demask:<4} "
             f"si={si:<4} cands={cand:>3} correct={cor} shadow={sha:>3} "
             f"shift={shift} pred={chm}/{cht} wall={wall}s")

    with open(matrix_summary, "a") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    with open(progress_log, "a") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        f.write(human + "\n")
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    print(human, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
