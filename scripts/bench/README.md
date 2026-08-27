# scripts/bench — reproducible bench methodology

Cross-host bench experiments for tuning constants in the pixel encoder hot
path. Each script backs up the source file it mutates, applies the const
change via `sed`, runs the bench, restores the original file via `trap EXIT`.
No git operations, no persistent code changes — clean tree after run.

## `prefetch_sweep.sh` — `PrefetchDistance` const sweep

Sweeps `PrefetchDistance ∈ {8, 16, 32, 64, 128}` in `process_pixels.c`
through `BenchmarkExtProductionMessage_(Encrypt|Decrypt)_(1|16|64)MB`
at the canonical bench config (`areion512` / 512-bit key / no MAC /
no overlays). Measures whether the software prefetch distance covers
what the hardware prefetcher does not.

Wall-time budget: `5s × 3 counts × 6 sub-benches × 5 configs` ≈ 10-15 min on
a warm cgo cache. Cold-start builds add ~30-60 s per config.

## `microbatch_sweep.sh` — `microBatchSize` const sweep

Sweeps `microBatchSize ∈ {512, 1024, 2048, 4096, 8192}` in
`process_cgo.go` through the same canonical bench. Measures the
trade-off between CGO crossing count (fewer at larger batch) and L1
cache pressure (hash arrays sized `batch × 2 × 8 bytes`).

Memory footprint per config:

| microBatchSize | Hash arrays | Cache tier |
|---|---:|---|
| 512  |   8 KiB | L1 |
| 1024 |  16 KiB | L1 |
| 2048 |  32 KiB | L1 edge |
| 4096 |  64 KiB | L1 miss → L2 |
| 8192 | 128 KiB | L2 hit |

Wall-time budget: ~10-15 min on a warm cgo cache.

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
