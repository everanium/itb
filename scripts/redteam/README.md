# scripts/redteam — Python attack tooling status

Every script in this directory is functional. What differs between
scripts is the range of ITB versions each is compatible with, because
the v0.3.0 wire hard-fork (Triple-only, 48-bit Interlocked Barrier
non-disableable, 8-seed API) changes what the attack surface looks
like from Python's side.

Nothing is moved. The scripts split into two compatibility bands:

- **Compatible with v0.3.0+ (and also with ≤ v0.2.1)** — cited by
  [HARNESS.md](../../HARNESS.md) as a reproduction path a reader can
  invoke today against the shipped construction. These are the
  primitive-shelf validation surface (Axes A / A′ / B / C on
  non-cryptographic and reduced-round primitives) plus the SAT-free
  pre-screen. They characterise **individual hash primitives** and
  their `ChainHash128`-wrapped variants — the barrier layer is not in
  scope for the measurement, so the wire hard-fork at v0.3.0 does not
  invalidate them.
- **Compatible with ≤ v0.2.1 only** — attacks that assumed **Single
  Ouroboros** or ran with the **overlay disengaged**. Both conditions
  are permanently gone in v0.3.0 (Triple is the only construction, the
  48-bit Interlocked Barrier is non-disableable), so these scripts
  require a pre-v0.3.0 tree to run. Check out the last v0.2 commit
  (the parent of the first v0.3.0 commit `2133136`, i.e. `git checkout
  2133136^`) into a work tree and the scripts execute exactly as they
  did on that release. Their historical results are also preserved
  verbatim in [archive/REDTEAM-v0.2.md](../../archive/REDTEAM-v0.2.md)
  and [archive/HARNESS-v0.2.md](../../archive/HARNESS-v0.2.md). The
  scripts remain in tree as templates for future Python probe
  sequences and as the attribution source `redteam_broken_test.go`
  cites when it ports logic.

The v0.3.0 empirical validation itself is delivered as shipped Go
tests, not Python. See the [Go test surface](#where-the-v030-empirical-validation-lives)
section at the bottom.

## Compatible with v0.3.0+ (and ≤ v0.2.1)

Cited by HARNESS.md and reproducible against the shipped tree.

### Axis A / A′ / B / C — primitive shelf (4 primitives)

| Primitive | Live scripts |
|---|---|
| **t1ha1_64le** | `harness_bias_audit_t1ha1.sh` · `phase2_theory_t1ha1/{lab_bias_t1ha1,lab_struct_t1ha1,sat_calibration_raw_t1ha1,t1ha1_chain_lo_concrete}.py` |
| **SeaHash** | `harness_bias_audit_seahash.sh` · `phase2_theory_seahash/{lab_bias_seahash,lab_struct_seahash,sat_calibration_raw_seahash,seahash_chain_lo_concrete}.py` |
| **mx3** | `harness_bias_audit_mx3.sh` · `phase2_theory_mx3/{lab_bias_mx3,lab_struct_mx3,sat_calibration_raw_mx3,mx3_chain_lo_concrete}.py` |
| **SipHash-1-3** | `harness_bias_audit_siphash13.sh` · `phase2_theory_siphash13/{lab_bias_siphash13,lab_struct_siphash13,sat_calibration_raw_siphash13,siphash13_chain_lo_concrete}.py` |

### §3.7 reduced-round-primitive control

- `phase2_theory_aes2r/{integral_aes2r,keyrecover_r2,sat_calibration_aes2r,differential_chainhash,distinguisher_chainhash,higher_order_chainhash,order3_chainhash,cms_xor_aes2r,gd_chainhash_aes2r}.py`
  — 2-round AES integral break characterisation, deferred SAT / differential
  / higher-order calibration. Cited from HARNESS.md §3.7 and §3.4/§3.5 tables.

### §3.5 SAT-free pre-screen (Axis 4)

- `phase2_theory/chainhashes/avalanche_screen.py`
- `phase2_theory/chainhashes/differential_screen.py`

### Shared probe modules

- `phase2_theory/raw_mode_bias_probe.py` — attacker-realistic raw-mode
  bias probe (attacker-visible input; codified capability, cf.
  [CLAUDE.md](../../CLAUDE.md) attacker-realism section).
- `phase2_theory/raw_mode_common.py` — common raw-mode helpers.
- `attack_common.py` — shared attacker-side helpers imported by shelf scripts.
- `common.py`, `_bias_cell_emit.py`, `_matrix_cell_emit.py` — shelf-shared
  cell emit / config plumbing.

## Compatible with ≤ v0.2.1 only

Cited from [archive/REDTEAM-v0.2.md](../../archive/REDTEAM-v0.2.md).
Reproducible against a checked-out pre-v0.3.0 tree (`git checkout 2133136^`);
not against the shipped v0.3.0+ tree, where Single Ouroboros and the
overlay-disengaged mode the attacks target no longer exist. Kept in
tree as templates for future Python probe sequences and as attribution
sources for the ported Go tests.

### Broken-primitive attack scripts

- `phase2_theory/{crib_crc128_kpa,crib_crc128_kpa_full,crib_crc128_decrypt,crib_crc128_decrypt_full,compound_key_crc128}.py`
- `phase2_theory_fnv1a/{decrypt_full_fnv1a,fnv_chain_lo_concrete,itb_channel_mirror,sat_calibration_raw_fnv,sat_harness_4round,t_solver_fnv,tsolver_harness_4round,tsolver_z3_propagator}.py`
- `phase2_theory_md5/`
- `phase2_theory_bea1/` — BEA-1 trapdoor primitive control (HARNESS.md §3.6
  cites the trapdoor result; the actual break scripts targeted Single).
- `phase2_theory/nonce_reuse_demask.py`
- `phase2_theory/{classical_decrypt,distinguisher,distinguisher_full}.py`
- `phase2_theory/kl_{massive_single,massive_single_full,matrix,urandom}.py`
- `phase2_theory/{startpixel_enum,startpixel_multisample}.py`
- `phase2_theory/{related_seed_diff_analyze,aggregate_related_seed_diff,sat_solver_bitwuzla}.py`

### Pre-screen-only primitives (mentioned in HARNESS.md but not wired)

- `phase2_theory_murmur3/` — murmur3 pre-screen only per HARNESS.md §3.5;
  reference primitive not taken through Axes A–C.
- `phase2_theory_splitmix64/` — splitmix64 pre-screen only; invertible-mixer
  control, reference primitive not wired into the shelf.

### Aggregation and matrix orchestrators

- `aggregate_bias_audit.py` — Axis-B result aggregation across the
  4-primitive matrix; still callable from the v0.3.0+ `harness_bias_audit_*.sh`
  and lands here in the ≤ v0.2.1-only band because the 4-primitive
  matrix (crc128 / fnv1a / blake3 / md5) it aggregates is a pre-v0.3.0
  artefact.
- `aggregate_crc128_matrix.py`, `aggregate_partial_kpa_matrix.py`
- `bias_audit_matrix.sh`, `bias_audit_matrix_triple.sh`
- `crc128_compound_key_matrix.sh`, `partial_kpa_matrix.sh`
- `phase2e_related_seed_matrix.sh`
- `phase1_sanity/` — pre-v0.3.0 baseline sanity probes.

## The `phase2_theory/chainhashes/` primitive mirrors

`phase2_theory/chainhashes/` holds Python parity mirrors of the per-primitive
inner hash: `aes2r.py`, `blake3.py`, `crc128.py`, `fnv1a.py`, `md5.py`,
`murmur3.py`, `mx3.py`, `seahash.py`, `siphash13.py`, `splitmix64.py`,
`t1ha1.py`, `xxhash64.py`, plus the `avalanche_screen.py` /
`differential_screen.py` pre-screen batteries. Each mirror is
bit-for-bit parity-checked against its Go reference (see
`_parity_test.py` and `_parity_dump/`). This subdirectory serves both
bands — it is the source of truth for the Python side of every
primitive in scope, live or archived. Do not delete individual mirrors
even when the parent attack script is archived; the pre-screen and the
live shelf scripts both import from here.

## Where the v0.3.0 empirical validation lives

The v0.3.0 REDTEAM re-verification is delivered as **shipped Go tests**,
not Python scripts. They compile with the release, run through
`go test -count=1 ./...`, and require no external Python environment:

- `redteam_broken_test.go` — FNV-1a and CRC128 broken-primitive
  re-verification (Full KPA / Partial KPA / Nonce-Reuse / mixed-algebra
  / related-seed differential) under Triple + Interlocked Barrier.
  Some logic is ported from `scripts/redteam/attack_common.py` and
  `scripts/redteam/phase2_theory/crib_crc128_kpa.py`; the port
  attribution lives at the top of the Go file.
- `redteam_prf_blake3_test.go` — PRF-grade primitive re-verification
  (BLAKE3 as the representative), 4-probe minimum + CPA + equivalence
  claim against the broken-primitive verdict.
- `harness_test.go` (root package) — Phase 4 construction-level creative
  probes: C2 mask-space uniformity, C4b lane decorrelation, C5-core
  cumulative-bias floor.
- `triple/harness_wire_test.go` — Phase 4 wire-shaped probes: C1 mode
  ambiguity, C3 tail-fill positional χ², C4a cross-snake wire
  correlation, C5 cumulative-bias wire floor, C6 nonce-freshness
  smoke test.

The narrative record of these Go probes is in
[REDTEAM.md](../../REDTEAM.md) (Phase 4 §4.0 through §4.6 covers the
creative-probe track; the broken-primitive and PRF-grade tracks each
carry their own section above it).
