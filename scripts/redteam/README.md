## ITB Python Attack Tools

Every Python script that ships with the repository lives under
`scripts/redteam/itb/`. Shell drivers accompany them in three places:
the per-track `run.sh` orchestrators directly under `itb/`, the
per-primitive `itb/theory/<primitive>/harness_bias_audit.sh` bias
audits, and the NIST STS sweep under
`itb/theory/aesitb128/nist_sts/`.

The tree splits into two compatibility bands, matching the split in the
paper-facing documentation:

- **Compatible with the shipped tree** — runnable against the shipped
  tree today; most are cited from [REDTEAM.md](../../REDTEAM.md) or
  [HARNESS.md](../../HARNESS.md) as reproduction paths, and the rest
  are dependencies, corpus consumers or one-off comparisons those
  reproduction paths rest on. Two kinds sit here: the
  shipped-construction re-verification tracks, which drive the shipped
  Go harness and aggregate its records, and the primitive-shelf
  validation surface, which characterises **individual hash
  primitives** and their `ChainHash128`-wrapped variants with the
  barrier layer out of scope for the measurement.
- **Compatible with the archived tree only** — attacks that assumed the
  retired construction: a single region under an opt-in overlay, a
  3-seed layout, and a per-pixel configuration map recoverable without
  a barrier in the path. The shipped tree has none of those — Triple is
  the only construction, the 8-seed constellation is mandatory, and the
  48-bit Interlocked Barrier is non-disableable — so these scripts
  require an archived tree to run. Check out the commit immediately
  before the first shipped commit `2133136` (i.e. `git checkout
  2133136^`) into a work tree and the scripts execute exactly as they
  did on that release. Their historical results are also preserved
  verbatim in [archive/REDTEAM.md](../../archive/REDTEAM.md) and
  [archive/HARNESS.md](../../archive/HARNESS.md). The scripts remain in
  tree as templates for future Python probe sequences and as the
  attribution source `redteam_broken_test.go` cites when it ports
  logic.

The wire header shape is not a band discriminator. The always-on
Interlocked Barrier and the 8-seed constellation are.

The empirical validation for the shipped construction itself is
delivered as shipped Go tests, not Python; the Python tracks below
aggregate those tests' records. See the
[Go test surface](#where-the-empirical-validation-lives) section at
the bottom.

## Compatible with the shipped tree

### Shipped-construction re-verification tracks

Each directory holds a `run.sh` that invokes the shipped Go harness
under `-tags redteam`, an `aggregate.py` that rolls the emitted records
into a Markdown summary, and a `README.md` stating the track's threat
model. Reproduction commands are cited from REDTEAM.md.

| Track | Scope |
|---|---|
| `itb/nonce_reuse/` | Full KPA under forced nonce collision (`setBrokenTestNonce`) |
| `itb/related_nonce/` | Lab-forced 1-bit nonce Δ, diffusion check across the compared pair |
| `itb/related_seed/` | Lab-forced seed Δ against the archived Phase 2e axis-hit finding |
| `itb/cpa_broken/` | Fresh-nonce chosen-plaintext posture, below-spec primitive on all 8 seed roles |
| `itb/near_identical_fresh/` | Cross-message near-identical distinguisher under fresh nonces |
| `itb/fnv1a_sat/` | FNV-1a lo-lane Full KPA SAT re-verification; `sat_probe.py` drives Bitwuzla |

### Axes A / A′ / B / C — primitive shelf

| Primitive | Live scripts |
|---|---|
| **t1ha1_64le** | `itb/theory/t1ha1/harness_bias_audit.sh` · `itb/theory/t1ha1/{lab_bias_t1ha1,lab_struct_t1ha1,sat_calibration_raw_t1ha1,t1ha1_chain_lo_concrete}.py` |
| **SeaHash** | `itb/theory/seahash/harness_bias_audit.sh` · `itb/theory/seahash/{lab_bias_seahash,lab_struct_seahash,sat_calibration_raw_seahash,seahash_chain_lo_concrete}.py` |
| **mx3** | `itb/theory/mx3/harness_bias_audit.sh` · `itb/theory/mx3/{lab_bias_mx3,lab_struct_mx3,sat_calibration_raw_mx3,mx3_chain_lo_concrete}.py` |
| **SipHash-1-3** | `itb/theory/siphash13/harness_bias_audit.sh` · `itb/theory/siphash13/{lab_bias_siphash13,lab_struct_siphash13,sat_calibration_raw_siphash13,siphash13_chain_lo_concrete}.py` |

### §3.7 / §3.10 reduced-round-primitive controls

- `itb/theory/aes2r/{integral_aes2r,keyrecover_r2,sat_calibration_aes2r,differential_chainhash,distinguisher_chainhash,higher_order_chainhash,order3_chainhash,cms_xor_aes2r,gd_chainhash_aes2r}.py`
  — 2-round AES integral break characterisation, deferred SAT / differential
  / higher-order calibration. Result in HARNESS.md §3.7, reproduction block
  §5.8; also carried in the §3.4 / §3.5 tables.
- `itb/theory/aesitb128/{integral_aesitb128,keyrecover_r2,keyrecover_r1_2p20,keyrecover_r1_lo,distinguisher_chainhash,higher_order_chainhash,order3_chainhash,order4_chainhash,differential_chainhash,uniformity_chainhash,screens_common}.py`
  — the same treatment on the shipped AES-ITB-128 sponge: standalone Square
  integral + one-pair inversion, the lo-lane last-round peel on the encoder's
  own observable, then the cascade sweep r ∈ {1 … 16} with the lo-lane /
  full-state / peeled observables, up to 2^32-text Λ-sets.
  Cited from HARNESS.md §3.10 / §5.10 and the §3.5 tables.
- `itb/theory/aes2r/fullkey_aes2r.py` — the aes2r engine extended to the
  full master key (15 Λ-sets + 2^8), cited from the §3.7 r = 1 row.
- `itb/theory/aesitb128/keyrecover_r2_20byte.py` — discard-off classical
  4-round Square κ-byte recovery at the shipped 20-byte shape (r = 2
  recovers); `--model realistic` runs the same shape on the shipped
  observable (lo lane only, Λ-sets confined to the `LE32(idx)` bytes, a
  random nonce per set) with the lab cell as the in-run positive control.
- `itb/theory/aesitb128/keyrecover_kbyte_go/` — Go κ-byte / pair-constancy /
  global-parity Square engines driven through the shipped 4-lane batched
  arm, order-N Λ-sets, attacker-model flags `--observable {full,lo}` ×
  `--nonce {chosen,idx-only}` (`--model realistic`), lab control in the
  same invocation.
- `itb/theory/aesitb128/order5_chainhash_go/` — 2^40 order-5 Λ-set integral
  through the cascade, every depth from one sweep.
- `itb/theory/aesitb128/order4_unrank_go/` — order-4 Λ-set integral scored on
  the mask triple the Interlocked Barrier fill actually consumes downstream,
  rather than on the encoder's lo-lane observable.
- `itb/theory/aesitb128/nist_sts/` — NIST STS 2.1.2 sweep over
  r ∈ {1 … 16} × the shipped inner-Barrier data shapes:
  `nist_sts_stream_gen.py` emits the lo-lane stream, `nist_sts_run.sh`
  drives one cell, `nist_sts_sweep.sh` walks the grid and
  `nist_sts_aggregate.py` rolls the results up.
- `itb/theory/aes2r/higher_round_square_aes2r.py`,
  `itb/theory/aes2r/square5_go/` — the aes2r NR ladder mirror and the 2^32
  5-round Square (same attacker-model flags; AES-NI rounds via `--hw`).
- `itb/theory/aes2r/order5_aes2r_go/` — the aes2r order-5 Λ-set probe
  (resumable across bounded runs; every complete 2^32 group reported as an
  order-4 verdict).

### §3.6 / §3.8 trapdoor and chosen-constants primitive controls

- `itb/theory/bea1/` — BEA-1 trapdoor primitive control. `bea1.py` /
  `bea1_tables.py` are the clean-room transcription, `bea1_validate.py`
  self-checks it, `bea1_trapdoor.py` re-derives the published partition,
  and `exp1_pure_bea1.py` / `exp2_chainhash_r1.py` /
  `exp3_chainhash_feedforward.py` / `exp3_structure_solver.py` measure
  whether the trapdoor survives the `ChainHash128` wrap.
  `exp3_structure_solver.py` is the only consumer of
  `_common/sat_solver_bitwuzla.py` here, and only on its `--solver
  bitwuzla` default — `--solver z3` runs the same formula in process.
  Result in HARNESS.md §3.6, reproduction block §5.7.
- `itb/theory/msha1/` — Malicious-SHA-1 collision-absorption control.
  `sha1_malicious.py` is the RFC 3174 core with the round constants
  exposed, `sha1_collide.py` carries the published colliding pair,
  `sha1_chainhash.py` is the feedforward wrap, and `exp1_snap.py` runs
  the raw / seed-invariant / snap / depth-plateau sub-probes.
  Result in HARNESS.md §3.8, reproduction block §5.9.

### §5.6 SAT-free pre-screen (Axis 4)

- `itb/theory/_common/chainhashes/avalanche_screen.py`
- `itb/theory/_common/chainhashes/differential_screen.py`

### KL floor probes under `itb/theory/_common/kl/`

These consume the shipped wire directly — the corpus generator is
`TestRedTeamGenerateTripleMassive` in `redteam_kl_test.go`, which emits
on the shipped Triple + always-on Interlocked Barrier container.

- `kl_massive.py` — KL floor on one large encryption, idealised
  alignment (startPixel read from the `.pixel` sidecar, plaintext XOR).
- `kl_massive_full.py` — the realistic-attacker variant: no startPixel,
  no plaintext XOR, every container pixel treated as one flat stream.
- `kl_urandom.py` — the matched-size `/dev/urandom` control for
  `kl_massive_full.py`. Takes the container **body** size, i.e.
  `ciphertext_bytes − (NonceSize + 4)`.
- `kl_matrix.py` — the `BarrierFill` × plaintext-size auto-selection
  driver over both of the above.

### Shared probe modules under `itb/theory/_common/`

- `raw_mode_bias_probe.py` — attacker-realistic raw-mode bias probe
  (attacker-visible input; codified capability).
- `raw_mode_common.py` — common raw-mode helpers.
- `attack_common.py` — shared attacker-side helpers imported by shelf scripts.
- `sat_solver_bitwuzla.py` — Bitwuzla-via-subprocess SMT-LIB2 helper,
  imported by every `sat_calibration_raw_*.py` in the tree — across both
  bands and both pre-screen-only primitives — and by
  `bea1/exp3_structure_solver.py`. Construction-independent: it takes a
  Z3-built QF_BV formula and enforces a wall-clock budget at the OS
  level, which is why it belongs to neither band on its own.
- `stats_comparison_a2r_a128.py` — head-to-head raw uniformity / bias
  comparison of the two reduced-round AES primitives on the shelf under
  one harness, one sample size and one seed stream.

## Compatible with the archived tree only

Cited from [archive/REDTEAM.md](../../archive/REDTEAM.md).
Reproducible against a checked-out archived tree (`git checkout
2133136^`); not against the shipped tree, where the single-region
overlay-disengaged construction these attacks target no longer exists.
Kept in tree as templates for future Python probe sequences and as
attribution sources for the ported Go tests.

### Broken-primitive attack scripts

- `itb/theory/crc128/{crib_crc128_kpa,crib_crc128_kpa_full,crib_crc128_decrypt,crib_crc128_decrypt_full,compound_key_crc128}.py`
- `itb/theory/fnv1a/{decrypt_full_fnv1a,fnv_chain_lo_concrete,itb_channel_mirror,sat_calibration_raw_fnv,sat_harness_4round,t_solver_fnv,tsolver_harness_4round,tsolver_z3_propagator}.py`
- `itb/theory/_common/nonce_reuse_demask.py` — the Layer 1 / Layer 2
  per-pixel configuration demasker the decrypt scripts above build on.
- `itb/theory/_common/classical_decrypt.py` — keystream-equivalence
  experiment on the demasker's output.
- `itb/theory/_common/{related_seed_diff_analyze,aggregate_related_seed_diff}.py`
  — the 3-seed related-seed differential analyser and its roll-up. The
  shipped-tree equivalent is `itb/related_seed/`.

### Pre-screen-only primitives (mentioned in HARNESS.md but not wired)

- `itb/theory/murmur3/` — murmur3 pre-screen only per HARNESS.md §3.5;
  reference primitive not taken through Axes A–C.
- `itb/theory/splitmix64/` — splitmix64 pre-screen only; invertible-mixer
  control, reference primitive not wired into the shelf.

## The `itb/theory/_common/chainhashes/` primitive mirrors

`itb/theory/_common/chainhashes/` holds Python parity mirrors of the
per-primitive inner hash: `aes2r.py`, `aesitb128.py`, `blake3.py`,
`crc128.py`, `fnv1a.py`, `murmur3.py`, `mx3.py`, `seahash.py`,
`siphash13.py`, `splitmix64.py`, `t1ha1.py`, `xxhash64.py`, plus the
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
Python environment; the re-verification tracks above consume their
emitted records:

- `redteam_broken_test.go` — FNV-1a and CRC128 broken-primitive
  re-verification (Full KPA / Partial KPA / Nonce-Reuse / mixed-algebra
  / related-seed differential) under Triple + Interlocked Barrier.
  Some logic is ported from `scripts/redteam/itb/theory/_common/attack_common.py`
  and `scripts/redteam/itb/theory/crc128/crib_crc128_kpa.py`; the port
  attribution lives at the top of the Go file.
- `redteam_broken_fnv1a_sat_test.go` — FNV-1a probes F1..F6, including
  the corpus emitter `itb/fnv1a_sat/sat_probe.py` consumes.
- `redteam_cpa_broken_test.go` — fresh-nonce CPA matrix.
- `redteam_near_identical_fresh_test.go` — fresh-nonce cross-message
  near-identical pair matrix.
- `redteam_kl_test.go` — the large-container corpus emitter the
  `itb/theory/_common/kl/` probes consume.
- `redteam_prf_blake3_test.go` — PRF-grade primitive re-verification
  (BLAKE3 as the representative), 4-probe minimum + CPA + equivalence
  claim against the broken-primitive verdict.
- `harness_test.go` (root package) — construction-level creative probes:
  mask-space uniformity, lane decorrelation, cumulative-bias floor.
- `triple/harness_wire_test.go` — wire-shaped probes: mode ambiguity,
  tail-fill positional χ², cross-region wire correlation, cumulative-bias
  wire floor, nonce-freshness smoke test.

The narrative record of these Go probes is in
[REDTEAM.md](../../REDTEAM.md); the broken-primitive and PRF-grade
tracks each carry their own section.
