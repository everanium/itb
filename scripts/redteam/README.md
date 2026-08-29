# scripts/redteam — Python attack tooling status

Every Python script that ships with the repository lives under
`scripts/redteam/itb/`. The four shell drivers under
`scripts/redteam/itb/theory/<primitive>/harness_bias_audit.sh` invoke
the shipped Go harness together with the sibling Python bias probe.

The tree splits into two compatibility bands, matching the split in the
paper-facing documentation:

- **Compatible with the shipped tree** — cited by
  [HARNESS.md](../../HARNESS.md) as a reproduction path a reader can
  invoke today against the shipped construction. These are the
  primitive-shelf validation surface (Axes A / A′ / B / C on
  non-cryptographic and reduced-round primitives) plus the SAT-free
  pre-screen. They characterise **individual hash primitives** and
  their `ChainHash128`-wrapped variants — the barrier layer is not in
  scope for the measurement, so the shipped dual-nonce wire does not
  invalidate them.
- **Compatible with the archived tree only** — attacks that assumed
  the retired construction (single-nonce wire, opt-in barrier, 3-seed
  layout). Both conditions are permanently gone in the shipped tree
  (Triple is the only construction, the 48-bit Interlocked Barrier is
  non-disableable), so these scripts require an archived tree to run.
  Check out the commit immediately before the first shipped commit
  `2133136` (i.e. `git checkout 2133136^`) into a work tree and the
  scripts execute exactly as they did on that release. Their
  historical results are also preserved verbatim in
  [archive/REDTEAM.md](../../archive/REDTEAM.md) and
  [archive/HARNESS.md](../../archive/HARNESS.md). The scripts remain
  in tree as templates for future Python probe sequences and as the
  attribution source `redteam_broken_test.go` cites when it ports
  logic.

The empirical validation for the shipped construction itself is
delivered as shipped Go tests, not Python. See the
[Go test surface](#where-the-empirical-validation-lives) section at
the bottom.

## Compatible with the shipped tree

Cited by HARNESS.md and reproducible against the shipped tree.

### Axes A / A′ / B / C — primitive shelf (4 primitives)

| Primitive | Live scripts |
|---|---|
| **t1ha1_64le** | `itb/theory/t1ha1/harness_bias_audit.sh` · `itb/theory/t1ha1/{lab_bias_t1ha1,lab_struct_t1ha1,sat_calibration_raw_t1ha1,t1ha1_chain_lo_concrete}.py` |
| **SeaHash** | `itb/theory/seahash/harness_bias_audit.sh` · `itb/theory/seahash/{lab_bias_seahash,lab_struct_seahash,sat_calibration_raw_seahash,seahash_chain_lo_concrete}.py` |
| **mx3** | `itb/theory/mx3/harness_bias_audit.sh` · `itb/theory/mx3/{lab_bias_mx3,lab_struct_mx3,sat_calibration_raw_mx3,mx3_chain_lo_concrete}.py` |
| **SipHash-1-3** | `itb/theory/siphash13/harness_bias_audit.sh` · `itb/theory/siphash13/{lab_bias_siphash13,lab_struct_siphash13,sat_calibration_raw_siphash13,siphash13_chain_lo_concrete}.py` |

### §5.7 reduced-round-primitive control

- `itb/theory/aes2r/{integral_aes2r,keyrecover_r2,sat_calibration_aes2r,differential_chainhash,distinguisher_chainhash,higher_order_chainhash,order3_chainhash,cms_xor_aes2r,gd_chainhash_aes2r}.py`
  — 2-round AES integral break characterisation, deferred SAT / differential
  / higher-order calibration. Cited from HARNESS.md §5.7 and §3.4 / §3.5 tables.

### §5.6 SAT-free pre-screen (Axis 4)

- `itb/theory/_common/chainhashes/avalanche_screen.py`
- `itb/theory/_common/chainhashes/differential_screen.py`

### Shared probe modules under `itb/theory/_common/`

- `raw_mode_bias_probe.py` — attacker-realistic raw-mode bias probe
  (attacker-visible input; codified capability).
- `raw_mode_common.py` — common raw-mode helpers.
- `attack_common.py` — shared attacker-side helpers imported by shelf scripts.

## Compatible with the archived tree only

Cited from [archive/REDTEAM.md](../../archive/REDTEAM.md).
Reproducible against a checked-out archived tree (`git checkout
2133136^`); not against the shipped tree, where the archived
construction and the overlay-disengaged mode the attacks target no
longer exist. Kept in tree as templates for future Python probe
sequences and as attribution sources for the ported Go tests.

### Broken-primitive attack scripts

- `itb/theory/crc128/{crib_crc128_kpa,crib_crc128_kpa_full,crib_crc128_decrypt,crib_crc128_decrypt_full,compound_key_crc128}.py`
- `itb/theory/fnv1a/{decrypt_full_fnv1a,fnv_chain_lo_concrete,itb_channel_mirror,sat_calibration_raw_fnv,sat_harness_4round,t_solver_fnv,tsolver_harness_4round,tsolver_z3_propagator}.py`
- `itb/theory/bea1/` — BEA-1 trapdoor primitive control (HARNESS.md §3.6
  cites the trapdoor result; the actual break scripts targeted the
  archived construction).
- `itb/theory/_common/nonce_reuse_demask.py`
- `itb/theory/_common/{classical_decrypt,distinguisher,distinguisher_full}.py`
- `itb/theory/_common/kl/{kl_massive,kl_massive_full,kl_matrix,kl_urandom}.py`
- `itb/theory/_common/{startpixel_enum,startpixel_multisample}.py`
- `itb/theory/_common/{related_seed_diff_analyze,aggregate_related_seed_diff,sat_solver_bitwuzla}.py`

### Pre-screen-only primitives (mentioned in HARNESS.md but not wired)

- `itb/theory/murmur3/` — murmur3 pre-screen only per HARNESS.md §3.5;
  reference primitive not taken through Axes A–C.
- `itb/theory/splitmix64/` — splitmix64 pre-screen only; invertible-mixer
  control, reference primitive not wired into the shelf.

## The `itb/theory/_common/chainhashes/` primitive mirrors

`itb/theory/_common/chainhashes/` holds Python parity mirrors of the
per-primitive inner hash: `aes2r.py`, `blake3.py`, `crc128.py`,
`fnv1a.py`, `murmur3.py`, `mx3.py`, `seahash.py`, `siphash13.py`,
`splitmix64.py`, `t1ha1.py`, `xxhash64.py`, plus the
`avalanche_screen.py` / `differential_screen.py` pre-screen batteries.
Each mirror is bit-for-bit parity-checked against its Go reference (see
`_parity_test.py` and `_parity_dump/`). This subdirectory serves both
bands — it is the source of truth for the Python side of every
primitive in scope. Do not delete individual mirrors even when the
parent attack script is archived; the pre-screen and the live shelf
scripts both import from here.

## Where the empirical validation lives

The REDTEAM re-verification for the shipped construction is delivered
as **shipped Go tests**, not Python scripts. They compile with the
release, run through `go test -count=1 ./...`, and require no external
Python environment:

- `redteam_broken_test.go` — FNV-1a and CRC128 broken-primitive
  re-verification (Full KPA / Partial KPA / Nonce-Reuse / mixed-algebra
  / related-seed differential) under Triple + Interlocked Barrier.
  Some logic is ported from `scripts/redteam/itb/theory/_common/attack_common.py`
  and `scripts/redteam/itb/theory/crc128/crib_crc128_kpa.py`; the port
  attribution lives at the top of the Go file.
- `redteam_prf_blake3_test.go` — PRF-grade primitive re-verification
  (BLAKE3 as the representative), 4-probe minimum + CPA + equivalence
  claim against the broken-primitive verdict.
- `harness_test.go` (root package) — construction-level creative probes:
  mask-space uniformity, lane decorrelation, cumulative-bias floor.
- `triple/harness_wire_test.go` — wire-shaped probes: mode ambiguity,
  tail-fill positional χ², cross-snake wire correlation, cumulative-bias
  wire floor, nonce-freshness smoke test.

The narrative record of these Go probes is in
[REDTEAM.md](../../REDTEAM.md); the broken-primitive and PRF-grade
tracks each carry their own section.
