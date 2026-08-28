# scripts/diag — CPU dispatch diagnostics

Two short bash utilities for investigating per-CPU throughput
anomalies in the ITB dispatch matrix. Both scripts build a Go test
binary at `/tmp/itb.test` (via `go test -c`) on first run, then reuse
it across configurations to avoid Go-compile-time noise in the
per-cell numbers.

Neither script writes anything to the repository or to any persistent
storage; both are read-only benches suitable for running on a fresh
target CPU without side effects.

## tier_diag.sh

Runs a short single-thread bench at natural dispatch and then under
every documented forced-tier value, one axis at a time:

- `ITB_FORCE_INTERLOCK_TIER` ∈ {`avx512`, `avx2`, `scalar`}
- `ITB_FORCE_HASH_TIER` ∈ {`avx512`, `vaesavx2`, `avx2`, `aesni`, `scalar`}
- `ITB_FORCE_PIXEL_TIER` ∈ {`A`, `A_NOGFNI`, `B`, `B_NOGFNI`, `C`}

The purpose is to identify a slow tier by comparison. When natural
dispatch throughput is significantly below one of the forced arms,
the auto-selected tier on this silicon underperforms and warrants a
kernel investigation. Prefer fixing the offending kernel so every
affected silicon runs the same shipped code; an SKU-scoped dispatch
adjustment is a last-resort fallback.

```sh
bash scripts/diag/tier_diag.sh                       # defaults
PAYLOAD=1MB BENCH_TIME=1s bash scripts/diag/tier_diag.sh
```

## hash_diag.sh

Renders a 9-hash x 3-nonce-width throughput matrix (27 cells for
encrypt, 27 for decrypt) at a fixed tier configuration. The nine
canonical hashes and three nonce widths cover every shipped
chain-absorb kernel width (13 / 20 / 36 / 68) across every registered
inner primitive.

A uniform host-vs-host ratio across all 27 cells signals general
silicon performance difference; an outlier cell signals a
hash-specific dispatch bug or a kernel regression on that CPU. Tier
overrides let the same matrix run against different arm choices, so
comparing e.g. `HASH_TIER=avx512` vs `HASH_TIER=avx2` on the same
host quantifies the AVX-512 vs AVX2 hash kernel spread.

```sh
bash scripts/diag/hash_diag.sh                             # defaults (INTERLOCK=avx2)
INTERLOCK_TIER=avx512 bash scripts/diag/hash_diag.sh       # compare interlock arms
HASH_TIER=avx2 bash scripts/diag/hash_diag.sh              # narrow to AVX2 hash kernels
INTERLOCK_TIER=natural bash scripts/diag/hash_diag.sh      # observe natural dispatch on this host
```

## Env inputs shared by both scripts

| Var                 | Default        | Purpose                                            |
|---------------------|----------------|----------------------------------------------------|
| `ITB_REPO`          | script-relative| Repo root; overridden for out-of-tree runs         |
| `ITB_TEST_BINARY`   | `/tmp/itb.test`| Path to (or destination for) the built bench binary|
| `PAYLOAD`           | `4MB`          | ExtProductionMessage ladder rung (`4KB`..`64MB`)   |
| `BENCH_TIME`        | `300ms`        | Go `-benchtime` per sample                         |
| `BENCH_COUNT`       | `3`            | Go `-count`; samples averaged in the printed value |
| `ITB_KEY_BITS`      | `512`          | Key width                                          |

The bench profile is fixed: `singlemsg-triple-nomac-v1` with
`GOMEMLIMIT=1GiB GOGC=20` so the numbers stay comparable across
runs. Change these only if you understand the profile matters.

## Typical investigation flow

1. Suspect a CPU-specific regression? Run `tier_diag.sh` on the
   host. Compare `natural` vs each forced arm — a large gap
   (natural much slower than one of the forced tiers) localises the
   problem to that axis.
2. Once localised, run `hash_diag.sh` under the identified healthy
   arm (e.g. `INTERLOCK_TIER=avx2`) to check whether the other axes
   have any secondary regressions across the 9-hash × 3-nonce
   surface, or whether they are uniformly healthy on this silicon.
3. If confirmed narrow (one tier axis, one CPU family), first attempt
   to fix the offending kernel — rewrite so the affected silicon runs
   the same shipped code as everyone else. The interlock rank-mask
   kernel is the canonical example: an SKU blacklist against
   Sapphire Rapids shipped briefly (commit `30c4ddd`) and was retired
   once the underlying legacy-SSE-bridge issue was fixed at the
   kernel level. An SKU-scoped runtime dispatch adjustment is a
   last-resort fallback when kernel-level fixing is not tractable.
