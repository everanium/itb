## ITB CPU Dispatch Diagnostics

Bash utilities for investigating per-CPU throughput
anomalies in the ITB dispatch matrix. The scripts build a Go test
binary at `/tmp/itb.test` (via `go test -c`) on first run, then reuse
it across configurations to avoid Go-compile-time noise in the
per-cell numbers.

The diagnostic scripts write nothing to the repository or to any persistent
storage; they are read-only benches suitable for running on a fresh
target CPU without side effects.

## tier_diag.sh

Runs a short message bench at natural dispatch and then under
every documented forced-tier value, one axis at a time:

- `ITB_FORCE_INTERLOCK_TIER` ∈ {`avx512`, `avx512x8`, `avx2`, `sve2`, `sve`, `neon`, `scalar`}
- `ITB_FORCE_HASH_TIER` ∈ {`avx512`, `vaesavx2`, `avx2`, `vex`, `aesni`, `gpr`, `sve2`, `sve`, `neon`, `scalar`}
- `ITB_FORCE_INTERLOCK_PRF_FILL_TIER` ∈ {`avx512`, `vaesavx2`, `avx2`, `vex`, `aesni`, `gpr`, `neon`, `scalar`}
- `ITB_FORCE_PIXEL_TIER` ∈ {`A`, `A_NOGFNI`, `B`, `B_NOGFNI`, `C`}

`tier_matrix_bench.sh` (the AES-ITB-128 hash-tier × batch-16 fill-tier
matrix) additionally carries the `avx512x4` row — `ITB_FORCE_HASH_TIER=avx512`
with `ITB_FORCE_CHAINHASH_X4=1`, the ZMM tier with the eight-lane fused
ChainHash kernels disarmed — so the `avx512` / `avx512x4` pair isolates the
eight-lane arm on hosts that select it.

The purpose is to identify a slow tier by comparison. When natural
dispatch throughput is significantly below one of the forced arms,
the auto-selected tier on this silicon underperforms and warrants a
kernel investigation. Prefer fixing the offending kernel so every
affected silicon runs the same shipped code with bit-exact parity.

```sh
bash scripts/diag/tier_diag.sh                       # defaults
PAYLOAD=1MB BENCH_TIME=1s bash scripts/diag/tier_diag.sh
```

## hash_diag.sh

Renders a per-registry-primitive × three-nonce-width throughput matrix at
a fixed tier configuration. The canonical primitive set and three nonce
widths cover every shipped fused-cascade kernel width (13 / 20 / 36 /
68) across every registered inner primitive.

A uniform host-vs-host ratio across all cells signals general
silicon performance difference; an outlier cell signals a
primitive-specific dispatch bug or a kernel regression on that CPU. Tier
overrides let the same matrix run against different arm choices, so
comparing e.g. `HASH_TIER=avx512` vs `HASH_TIER=avx2` on the same
host quantifies the AVX-512 vs AVX2 hash kernel spread.

```sh
bash scripts/diag/hash_diag.sh                             # defaults (INTERLOCK=avx2)
INTERLOCK_TIER=avx512 bash scripts/diag/hash_diag.sh       # compare interlock arms
HASH_TIER=avx2 bash scripts/diag/hash_diag.sh              # narrow to AVX2 hash kernels
INTERLOCK_TIER=natural bash scripts/diag/hash_diag.sh      # observe natural dispatch on this host
```

## Env inputs shared by the scripts

| Var                 | Default        | Purpose                                            |
|---------------------|----------------|----------------------------------------------------|
| `ITB_REPO`          | script-relative| Repo root; overridden for out-of-tree runs         |
| `ITB_TEST_BINARY`   | `/tmp/itb.test`| Path to (or destination for) the built bench binary|
| `PAYLOAD`           | `4MB`          | ExtProductionMessage ladder rung (`4KB`..`64MB`)   |
| `BENCH_TIME`        | `300ms`        | Go `-benchtime` per sample                         |
| `BENCH_COUNT`       | `3`            | Go `-count`; samples averaged in the printed value |
| `ITB_KEY_BITS`      | `512`          | Key width                                          |
| `ITB_INTERLOCK`     | `""` (48)      | Interlock chunk width (`48` or `168`; `hash_diag.sh` narrows to 512-bit primitives under `168`) |

The bench profile is fixed: `singlemsg-triple-nomac-v1` with
`GOMEMLIMIT=4GiB GOGC=100` so the numbers stay comparable across
runs. Altering the profile invalidates cross-run comparisons.

## Typical investigation flow

1. When a CPU-specific regression is suspected, running `tier_diag.sh` on
   the host compares `natural` against each forced arm — a large gap
   (`natural` much slower than one of the forced tiers) localises the
   problem to that axis.
2. Once localised, running `hash_diag.sh` under the identified healthy
   arm (e.g. `INTERLOCK_TIER=avx2`) checks whether the other axes
   have any secondary regressions across the per-hash × per-nonce-width
   surface, or whether they are uniformly healthy on that silicon.
3. When confirmed narrow (one tier axis, one CPU family), the offending
   kernel is rewritten or adjusted so the affected silicon runs the
   standard path with bit-exact parity.

