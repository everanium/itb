# scripts/bench — reproducible bench methodology

Cross-host bench experiments for tuning constants in the pixel encoder hot
path. Each script backs up the source file it mutates, applies the const
change via `sed`, runs the bench, restores the original file via `trap EXIT`.
No git operations, no persistent code changes — clean tree after run.

## `prefetch_sweep.sh` — `PrefetchDistance` const sweep

Sweeps `PrefetchDistance ∈ {8, 16, 32, 64, 128}` through
`BenchmarkExtProductionMessage_(Encrypt|Decrypt)_(1|16|64)MB` at the
canonical bench config (`areion512` / 512-bit key / no MAC / no overlays).

Wall-time budget: `5s × 3 counts × 6 sub-benches × 5 configs` ≈ 10-15 min on
a warm cgo cache. Cold-start builds add ~30-60 s per config.

**Usage** (run from anywhere; the script self-locates the repo root):

```sh
cd path/to/itb
bash scripts/bench/prefetch_sweep.sh
```

Results land in `~/scratch/prefetch-sweep/<UTC-stamp>/`:

- `process_pixels.c.original` — verbatim backup of the pre-run source
- `prefetch_<N>.log` — full `go test -bench` output for each config
- The last summary at end of the script's stdout prints the median MB/s
  per config

## Env overrides

| Var | Default | Notes |
|---|---|---|
| `ITB_REPO` | script's `../..` | repo root path |
| `ITB_SWEEP_RESULT_ROOT` | `~/scratch/prefetch-sweep` | result parent dir |
| `BENCH_TIME` | `5s` | `go test -benchtime` value |
| `BENCH_COUNT` | `3` | `go test -count` value (median of N) |
| `SWEEP_VALUES` | `"8 16 32 64 128"` | space-separated PrefetchDistance values |
| `ITB_INNER_HASH` | `areion512` | inner primitive |
| `ITB_KEY_BITS` | `512` | key width |
| `ITB_NONCE_BITS` | `512` | nonce width |
| `ITB_WITH_MAC` | `false` | canonical no-MAC |
| `ITB_WITH_PARALLAX` | `false` | canonical no-parallax |
| `ITB_WITH_WRAPPER` | `false` | canonical no-wrapper |
| `ITB_GOMEMLIMIT` | `1GiB` | Go heap cap |
| `ITB_GOGC` | `20` | GC trigger |

## Safety

- `set -uo pipefail` — no `-e`, continues past a single-config failure
- `trap ... EXIT` restores `process_pixels.c` even on Ctrl+C or crash
- All state under the result dir; nothing writes into the repo working tree
- No git operations — user reruns as needed via `git pull` between iterations
