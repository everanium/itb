# scripts/bench — microBatch policy sweep

Single-file sweep runner for the CGO pixel encoder's adaptive microBatch
switch and its two sync.Pool tiers. The shipped binary reads the policy
from two env vars at package init(), so no source edits are needed
between runs.

## Env vars

| Var                     | Format                          | Default (unset)              |
|-------------------------|---------------------------------|------------------------------|
| `ITB_MICROBATCH_TIERS`  | `"upper:batch,…,-1:batch"`      | `16384:512,8388608:262144,-1:512` |
| `ITB_HASHPOOL_STARTERS` | `"s1,s2,…"` (ints, uniq+sorted) | `512,262144`                 |

### `ITB_MICROBATCH_TIERS`

A comma-separated list of `upper:batch` pairs read left to right. The
first tier whose `upper` matches (or the `-1` fallback) picks the batch
stride. `upper` is compared against the **per-snake** payload length —
under Triple Ouroboros the low-level entry receives one third of the
user-visible plaintext.

Examples:

- Shipped 3-tier:            `16384:512,8388608:262144,-1:512`
- 4-tier with mid stride:    `16384:512,131072:65536,8388608:262144,-1:512`
- 2-tier always adaptive:    `16384:512,-1:262144`
- Baseline everywhere:       `-1:512`

### `ITB_HASHPOOL_STARTERS`

A comma-separated list of `sync.Pool` starter capacities (in `uint64`
elements). Each entry becomes an independent pool tier; every fresh
`pool.New` call allocates two arrays of that size.

`getHashArraysFor(microBatch, n)` picks the smallest tier whose starter
`>= microBatch`; falls back to the largest tier when `microBatch`
exceeds every configured starter.

Examples:

- Shipped 2-pool:            `512,262144`
- 3-pool with mid tier:      `512,65536,262144`
- Single pool baseline:      `512`
- Single pool always wide:   `262144`

## Compact output format

```
CPU: <model> <cores>c/<threads>t
Policy: <name>
  tiers=<active tiers or "default">
  pools=<active pools or "default">
E   4KB   <allocs/op>   <ns/op>   <MB/s>
E  64KB   <allocs/op>   <ns/op>   <MB/s>
…
D   4KB   <allocs/op>   <ns/op>   <MB/s>
…
```

`E` = Encrypt, `D` = Decrypt. Rows in ladder order across
`4KB / 64KB / 512KB / 1MB / 4MB / 8MB / 16MB / 32MB / 48MB / 64MB`.

## Usage

Baseline (shipped defaults):

```sh
bash scripts/bench/sweep.sh
```

Mid-tier stride + mid-tier pool:

```sh
POLICY_NAME="3tier-mid65536" \
ITB_MICROBATCH_TIERS="16384:512,131072:65536,8388608:262144,-1:512" \
ITB_HASHPOOL_STARTERS="512,65536,262144" \
    bash scripts/bench/sweep.sh
```

Baseline switch but with the extra mid-tier pool (test whether pool
starter alone moves anything):

```sh
POLICY_NAME="default+pool65536" \
ITB_HASHPOOL_STARTERS="512,65536,262144" \
    bash scripts/bench/sweep.sh
```

Adaptive always-on:

```sh
POLICY_NAME="always-wide" \
ITB_MICROBATCH_TIERS="16384:512,-1:262144" \
    bash scripts/bench/sweep.sh
```

## Env overrides

| Var                     | Default | Notes                                  |
|-------------------------|---------|----------------------------------------|
| `POLICY_NAME`           | `default` | Human label printed in the header      |
| `BENCH_TIME`            | `1s`    | `go test -benchtime` value             |
| `BENCH_COUNT`           | `1`     | `go test -count` value (median of N)   |
| `ITB_REPO`              | `$PWD/../..` | Repo root path                     |
| `ITB_INNER_HASH`        | `areion512` | Canonical bench profile knobs      |
| `ITB_KEY_BITS`          | `512`   |                                        |
| `ITB_NONCE_BITS`        | `512`   |                                        |
| `ITB_WITH_MAC`          | `false` |                                        |
| `ITB_WITH_PARALLAX`     | `false` |                                        |
| `ITB_WITH_WRAPPER`      | `false` |                                        |
| `ITB_GOMEMLIMIT`        | `1GiB`  |                                        |
| `ITB_GOGC`              | `20`    |                                        |

## Wall-time budget

`1s × count=1 × 20 sub-benches` ≈ 20 s per policy on a warm cgo cache
plus ~5 s of pre-run cgo build. Cold cache adds ~30–60 s to the first
policy of a session.

If a policy shows visibly noisy numbers, bump `BENCH_TIME=2s`; if still
noisy on the very small end of the ladder, bump `BENCH_COUNT=3` and read
the median across runs.
