# scripts/bench — reproducible bench methodology

Cross-host bench experiments for tuning constants in the pixel encoder hot
path. Backs up the source files it mutates, applies const changes via
`sed`, runs the bench, restores the originals via `trap EXIT`. No git
operations, no persistent code changes — clean tree after each run.

## `sweep.sh` — unified const sweep (PrefetchDistance + microBatchSize)

Sweeps either or both hot-path knobs — `PrefetchDistance` (const in
`process_pixels.c`, controls software prefetch look-ahead in the pixel
encoder) and `microBatchSize` (const in `process_cgo.go`, controls the
Go → C handoff granularity per iteration). Both are const at compile
time, so each sweep step edits the source, forces a `go clean -testcache`,
and reruns the canonical bench.

Cartesian product runs when both env vars carry multi-valued lists —
useful for measuring interaction (e.g. does a larger prefetch compensate
the L1 pressure of a larger batch).

### Bench shape (canonical)

`BenchmarkExtProductionMessage_(Encrypt|Decrypt)_(1|16|64)MB` at
`areion512` / 512-bit key / no MAC / no parallax / no wrapper — the
narrowest configuration that isolates the pixel encoder hot path from
composition overhead.

### Memory footprint per `microBatchSize`

Hash arrays sized `batch × 2 × 8 bytes` (noise + data channels, `uint64`):

| `microBatchSize` | Hash arrays | Cache tier |
|---:|---:|---|
|    512 |   8 KiB | L1 |
|   1024 |  16 KiB | L1 |
|   2048 |  32 KiB | L1 edge |
|   4096 |  64 KiB | L1 miss → L2 |
|   8192 | 128 KiB | L2 hit |
|  16384 | 256 KiB | L2 |
|  32768 | 512 KiB | L2 (Intel L2=512K) / L2 (Zen 5 L2=1M) |
|  65536 |   1 MiB | L2 edge / L3 |

### Usage

Run from anywhere; the script self-locates the repo root.

Baseline single point (no sweep, just measure the shipped constants):

```sh
cd path/to/itb
bash scripts/bench/sweep.sh
```

PrefetchDistance sweep only:

```sh
SWEEP_PREFETCH="32 64 128 256 512 1024" bash scripts/bench/sweep.sh
```

microBatchSize sweep only:

```sh
SWEEP_MICROBATCH="4096 8192 16384 32768 65536" bash scripts/bench/sweep.sh
```

Cartesian product (interaction study — total configs = product of list lengths):

```sh
SWEEP_PREFETCH="32 128 512" \
SWEEP_MICROBATCH="1024 4096 16384" \
  bash scripts/bench/sweep.sh
```

### Env overrides

| Var | Default | Notes |
|---|---|---|
| `ITB_REPO` | script's `../..` | repo root path |
| `ITB_SWEEP_RESULT_ROOT` | `~/scratch/sweep` | result parent dir |
| `BENCH_TIME` | `5s` | `go test -benchtime` |
| `BENCH_COUNT` | `3` | `go test -count` (median of N) |
| `SWEEP_PREFETCH` | `"8"` | space-separated PrefetchDistance values |
| `SWEEP_MICROBATCH` | `"512"` | space-separated microBatchSize values |
| `ITB_INNER_HASH` | `areion512` | inner primitive |
| `ITB_KEY_BITS` | `512` | key width |
| `ITB_NONCE_BITS` | `512` | nonce width |
| `ITB_WITH_MAC` | `false` | canonical no-MAC |
| `ITB_WITH_PARALLAX` | `false` | canonical no-parallax |
| `ITB_WITH_WRAPPER` | `false` | canonical no-wrapper |
| `ITB_GOMEMLIMIT` | `1GiB` | Go heap cap |
| `ITB_GOGC` | `20` | GC trigger |

### Wall-time budget

Per-config ≈ 2 min on a warm cgo cache (`5s × 3 counts × 6 sub-benches`
plus cgo rebuild). Cartesian 6 × 5 = 30 configs ≈ 60 min. Cold-start
adds first-config rebuild time (~30-60 s).

### Result layout

```
~/scratch/sweep/<UTC-stamp>/
├── process_pixels.c.original      # verbatim pre-run backup
├── process_cgo.go.original        # verbatim pre-run backup
└── pd<N>_mb<N>.log                # per-config bench output
```

The script prints median MB/s per sub-bench per config to stdout as it
runs; the `.log` files carry the raw `go test -bench` output for
independent analysis.

### Safety

- `set -uo pipefail` — no `-e`, continues past a single-config failure
- `trap ... EXIT` restores both source files even on Ctrl+C or crash
- All state under the result dir; nothing writes into the repo tree
  outside the temporary sed mutations that get restored
- No git operations — rerun via `git pull` between iterations as needed
