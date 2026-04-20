#!/usr/bin/env python3
"""Matrix cell emitter for bias_audit_matrix.sh.

Parses the per-cell probe log, extracts key statistics, appends one
JSON line to matrix_summary.jsonl under flock so parallel workers
never interleave mid-record. Also appends a short human-readable
line to matrix_progress.log and emits it to stdout for live feedback.
"""
import fcntl
import json
import re
import sys
from pathlib import Path


def main() -> int:
    (
        meta_path, probe_log, primitive, size, fmt, rc,
        matrix_summary, progress_log,
    ) = sys.argv[1:]
    meta = json.loads(Path(meta_path).read_text())
    log_text = Path(probe_log).read_text() if Path(probe_log).exists() else ""

    def grab_num(pattern, default=None, cast=float):
        m = re.search(pattern, log_text, flags=re.DOTALL)
        if m is None:
            return default
        try:
            return cast(m.group(1))
        except Exception:
            return default

    entry = {
        "primitive": primitive,
        "hash_display": meta.get("hash_display"),
        "hash_width": meta.get("hash_width"),
        "size_bytes": int(size),
        "format": fmt,
        "total_pixels": meta.get("total_pixels"),
        "probe_exit_code": int(rc),
        "min_conflict_pct":    grab_num(r"min:\s+([\d.]+)%"),
        "p01_conflict_pct":    grab_num(r"p01:\s+([\d.]+)%"),
        "p05_conflict_pct":    grab_num(r"p05:\s+([\d.]+)%"),
        "median_conflict_pct": grab_num(r"median:\s+([\d.]+)%"),
        "p95_conflict_pct":    grab_num(r"p95:\s+([\d.]+)%"),
        "p99_conflict_pct":    grab_num(r"p99:\s+([\d.]+)%"),
        "max_conflict_pct":    grab_num(r"max:\s+([\d.]+)%"),
        "true_shift_rank":     grab_num(r"rank (\d+)/\d+", cast=int),
        "total_shifts":        grab_num(r"rank \d+/(\d+)", cast=int),
        "plateau_size":        grab_num(r"plateau .*= (\d+) shift", cast=int),
        "true_shift_conflict_pct": grab_num(r"= ([\d.]+)%\s+\|\s+plateau"),
        "scan_elapsed_s":      grab_num(r"scan elapsed:\s+([\d.]+)s"),
        # Axis-2 prediction — bit-accuracy is the PRIMARY signal under
        # raw-mode masking (5-12 p.p. gap between GF(2)-linear primitives
        # and PRFs). Channel-accuracy is ~0 for all primitives under
        # rotate7 + noise injection and kept only for diagnostics.
        "pred_min_bits_pct": grab_num(
            r"Axis-2 prediction at min-conflict shift.*?bits matched\s*:\s*\d+/\d+ = ([\d.]+)%",
        ),
        "pred_min_channels_pct": grab_num(
            r"Axis-2 prediction at min-conflict shift.*?channels matched\s*:\s*\d+/\d+ = ([\d.]+)%",
        ),
        "pred_true_bits_pct": grab_num(
            r"Axis-2 prediction at TRUE shift.*?bits matched\s*:\s*\d+/\d+ = ([\d.]+)%",
        ),
        "pred_true_channels_pct": grab_num(
            r"Axis-2 prediction at TRUE shift.*?channels matched\s*:\s*\d+/\d+ = ([\d.]+)%",
        ),
    }

    with open(matrix_summary, "a") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    human = (
        f"{primitive:<8}  size={size:>8}  fmt={fmt:<6}  "
        f"min={entry['min_conflict_pct']}%  "
        f"med={entry['median_conflict_pct']}%  "
        f"max={entry['max_conflict_pct']}%  "
        f"TRUE_rank={entry['true_shift_rank']}/{entry['total_shifts']}  "
        f"plateau={entry['plateau_size']}  wall={entry['scan_elapsed_s']}s"
    )
    with open(progress_log, "a") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        f.write(human + "\n")
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    print(human, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
