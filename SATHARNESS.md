# SATHARNESS.md — SAT-based Empirical KPA Cryptanalysis Shelf

*(local planning document — gitignored; will graduate to a public sibling of
REDTEAM.md / ITB.md / SCIENCE.md once the first empirical rows are in)*

## 0. Status

Skeleton only. Populated as primitives are measured. Each row is a reproducible
wall-clock measurement, not a theoretical claim.

---

## 1. Scope

Primitive-focused SAT-based Known-Plaintext-Attack (KPA) calibration for the
middle-zone of the hash spectrum: **non-cryptographic hashes that are neither
trivially invertible nor publicly broken under KPA**. The question answered
per primitive:

> Given polynomially-many `(m_i, h(m_i, k))` pairs, can a commodity SAT solver
> recover `k` on commodity hardware, and within what wall-clock budget?

Two columns per primitive:

- **Raw KPA** — primitive called directly from seed: `h(m, k)`. No ChainHash,
  no ITB envelope. Primitive-level resistance only.
- **ChainHash-1** — one round of ITB-style ChainHash128 wrapping (hLo-only
  extraction: `ChainHash(data, k).lo & MASK64`). Tests whether the hLo-only
  projection helps or hurts attacker (for some primitives lo-lane isolation
  kicks in; for others the full state mixes into hLo).

### 1.1. What IS in scope

Primitives with all three properties:

1. **Non-cryptographic** — designed for distribution quality / speed /
   hash-table load factor, not for cryptographic security. Typically has no
   formal PRF proof and no published KPA security argument.
2. **Not publicly broken under KPA** — no existing academic or industry
   paper demonstrating seed recovery from polynomially-many known-plaintext
   pairs in practical wall-clock.
3. **Not trivially invertible** — no closed-form algebraic inverse (rules
   out FNV-1, FNV-1a, DJB2, SDBM, Adler32, every CRC variant, Jenkins OAAT,
   PJW, Pearson, and similar per-byte-carry-only / linear constructions).

### 1.2. What IS NOT in scope (and why)

- **Invertible non-crypto hashes** (FNV-1/FNV-1a, DJB2, SDBM, Adler32,
  CRC 8/16/32/64/128, Jenkins OAAT, PJW, ElfHash, Pearson, Lookup3 core,
  FNV-64 variants, MurmurHash2 lo-round form, …). ITB Phase 2g already
  establishes the empirical pattern for the FNV-1a family (SAT-breakable at
  ITB minimum config in ~8 h commodity), and the pattern generalises to every
  primitive in this class — the same carry-chain / XOR-linear structure
  admits SAT recovery with trivial adaptation. Adding more rows would be
  pure redundancy: the answer is already known.
- **Publicly broken hashes** (MD5 collisions, SHA-1 collisions, RIPEMD-128
  preimage-reduced, Tiger preimage-reduced, GOST pre-2015). Public attack
  literature already answers the resistance question; this shelf documents
  where empirical answers are missing, not where they exist.
- **Formally-PRF hashes** (SipHash family, AES-CMAC, BLAKE2 / BLAKE3 family,
  ChaCha20 keyed, HMAC-SHA-256 / SHA-512, KMAC, Areion, …). Under the PRF
  assumption, successful SAT recovery would constitute a PRF distinguisher
  and is therefore ruled out by definition — the PRF assumption does the
  work, no calibration needed.
- **Full-round current SHA-family** (SHA-256, SHA-512, SHA-3 / Keccak).
  No published SAT attacks at full rounds; PRF-grade by consensus; out of
  scope for the same reason as the SipHash row.

### 1.3. Contingency note

If any primitive placed in "Not scope — invertible / broken" turns out to
resist this shelf's generic SAT approach, that itself becomes an in-scope
row (unexpected empirical robustness of a presumed-trivial primitive is a
research finding). Conversely, if a primitive in the shelf turns out to
admit a previously-unknown closed-form inverse during harness development,
the inverse itself is the publication — not the SAT measurement.

---

## 2. Relationship to ITB (clarifying note)

This document lives in the ITB repository for infrastructure reuse
(Z3 / Bitwuzla harness scaffolding from `scripts/redteam/phase2_theory_*`,
parity-gadget patterns, synthetic-corpus generation conventions). It is
**NOT ITB-specific**:

- Every measurement here is on the primitive **standalone** (raw KPA column)
  or wrapped in a **minimal 1-round ChainHash** (ChainHash-1 column). No ITB
  per-pixel envelope, no noise_pos ambiguity, no `startPixel` enumeration.
- ITB's full ChainHash wrap + per-pixel envelope adds a primitive-dependent
  multiplier on top of the measurements here. Empirically measured on
  FNV-1a (see REDTEAM.md Phase 2g): ~20-100× from ChainHash round count,
  further ×289 from `startPixel` brute force for 4 KB ciphertext.
- SAT parallelism under the full ITB wrap scales **only** through disjoint
  `startPixel` instance enumeration (one candidate per worker). In-instance
  parallelism (cube-and-conquer, `smt.threads=N`) is empirically
  counterproductive under the densely-coupled carry-chain + mod-7 rotation
  constraint graph (Phase 2g finding). This shelf measures primitive-level
  raw resistance and does NOT inherit that serialisation constraint.

If the reader's security argument rests on the primitive standing alone,
the numbers here apply directly. If the argument rests on ITB composition,
the shelf numbers are a lower bound; use REDTEAM.md Phase 2g methodology
with the primitive swap for the composed-system measurement.

---

## 3. Methodology

### 3.1. Harness structure

Per primitive `<p>`:

```
scripts/redteam/phase2_theory_<p>/
├── <p>_chain_lo_concrete.py    # parity gadget: pure Python + Z3 symbolic
├── sat_calibration_raw_<p>.py  # raw-KPA calibration harness (no ChainHash)
└── sat_calibration_chain_<p>.py # ChainHash-1 variant (for column 2)
```

Pattern templates from `scripts/redteam/phase2_theory_fnv1a/` and
`scripts/redteam/phase2_theory_md5/`. Single-file parity gadget validates
concrete-vs-symbolic on random vectors before SAT run. Calibration harness
emits incremental JSON with per-cell wall-clock / RSS / holdout / status.

### 3.2. Grid

Default measurement grid per primitive:

- **Observations:** `{1, 2, 4, 8, 16, 32, 64}` known `(m, h(m, k))` pairs.
- **Timeout per cell:** 24 h single-core baseline; extended to 1 week or
  3 months for primitives expected in the "timeout" regime.
- **Solvers:** Z3 4.14+ for small instances, Bitwuzla 0.9+ for large or
  multiplication-heavy instances (same rationale as FNV-1a calibration —
  Bitwuzla's subprocess timeout is enforced across parse / bit-blast /
  CDCL uniformly, Z3's applies only to CDCL loop).
- **Hardware:** commodity 16-core Linux host, 48 GB RAM. Larger budgets
  (1-week, 3-month) delegated to secondary machines.

### 3.3. Verdict categories and REDTEAM.md Hash matrix labels

Each primitive × measurement cell gets one of the per-cell status codes:

- ✗ **SAT-broken** — seed recovered with `holdout_functionally_equivalent`
  in the cell's wall-clock budget. Report recovered bit-count vs seed size,
  wall-clock, peak RSS.
- ⏱ **Timeout at budget** — SAT did not terminate within the largest
  attempted budget (1 day / 1 week / 3 months). Report the budget and
  peak RSS at termination.
- ⚠ **Resistant but unproven** — timeout at largest budget tried AND the
  primitive has no known structural weakness that suggests a tighter
  analysis would succeed. Weakest positive claim allowed here.
- ✓ **PRF-assumption-blocked** — only used for primitives that somehow
  migrate into scope from the formal-PRF category (shouldn't happen by
  design of § 1.1).

Beyond the per-cell status, each primitive receives a **shelf-level
verdict label** mirroring the [REDTEAM.md Hash matrix](REDTEAM.md#hash-matrix)
convention so a reader can scan this document for the same class of
decision they use when picking a primitive for production:

- **Fully broken** — the Raw-KPA OR ChainHash-1 column empirically produced
  `SAT-broken` with functionally-equivalent K in a reasonable commodity
  budget (days-to-weeks single-core, not analytical extrapolation). The
  primitive is empirically invertible through generic SAT on ITB-style
  seed-to-output observations. Reference datum: FNV-1a in REDTEAM.md
  Phase 2g — ~8 h single-core at ITB keyBits=512 for a functionally-
  equivalent K, leading to its `Fully broken` marking in the REDTEAM.md
  Hash matrix.
- **Dangerous** — raw / ChainHash-1 SAT timed out at the shelf budget,
  BUT analytical extrapolation from the measured per-round scaling AND
  the measured primitive-level bit-blast cost puts the full ITB-wrapped
  decrypt (keyBits = 512 minimum, 1024 shipped, or 2048 paranoid) inside
  the attacker-reachable envelope — cluster-week to cluster-year budgets
  that a well-funded adversary can allocate. Reference datum: MD5 in
  REDTEAM.md Phase 2a extrapolation (reduced-round preimage via SAT
  known, full-round extrapolated to cluster-days at keyBits=512 under
  the measured raw-MD5 SAT cost curve), leading to its `Dangerous`
  marking in the REDTEAM.md Hash matrix.
- **Resistant (at tested budget)** — raw / ChainHash-1 SAT timed out at
  the shelf budget AND analytical extrapolation to ITB-wrapped ranges
  lands beyond any plausible attacker budget (decades to cosmological
  timescales). No empirical break, no feasible extrapolation. This is
  the weakest positive claim this shelf ever emits — always qualified
  with the measured budget that produced the timeout.

A primitive may hold different labels at different ITB-wrapping levels:
e.g. `Fully broken at keyBits = 512 / 4 rounds` but `Resistant at
keyBits = 1024 / 8 rounds`. The shelf records the worst-case level at
which the break is feasible, with a concrete analytical extrapolation
footnote for the levels where it is not.

---

## 4. Primitive shelf

Empty scaffold. Each row populated as measurements complete. Rows ordered
by expected SAT-hardness (weakest first).

### 4.1. xxh family

| Primitive | Raw KPA | ChainHash-1 | Verdict label | Impl | Notes |
|:----------|:-------:|:-----------:|:-------------:|:----:|:------|
| **xxh3-64 withSeed** (Collet, 2019+) | — | — | — | TODO | 64-bit seed, 64-bit output. Novel target: no published SAT KPA. Reference: `cespare/xxhash/v2`. |
| **xxh3-128 withSeed** (Collet, 2019+) | — | — | — | TODO | 64-bit seed, 128-bit output. More observable per query than 64-bit variant. |
| **xxh3-64 withSecret** (192 B secret) | — | — | — | TODO | 1 536-bit secret; expanded-seed form. |
| **xxh3-128 withSecret** | — | — | — | TODO | Same as above, 128-bit output. |
| **xxh64** (Collet, 2012) | — | — | — | TODO | Predecessor to xxh3; still widely deployed (LZ4 framing). |

### 4.2. MurmurHash family

| Primitive | Raw KPA | ChainHash-1 | Verdict label | Impl | Notes |
|:----------|:-------:|:-----------:|:-------------:|:----:|:------|
| **MurmurHash3 x64_128** (Appleby, 2011) | — | — | — | TODO | Used in Cassandra, Kafka, Elasticsearch. 32-bit seed expanded to 128-bit output. |
| **MurmurHash3 x86_128** | — | — | — | TODO | 32-bit platform variant. |
| **MurmurHash3 x86_32** | — | — | — | TODO | Simpler structure; may fall to raw KPA quickly. |

### 4.3. Google hash family

| Primitive | Raw KPA | ChainHash-1 | Verdict label | Impl | Notes |
|:----------|:-------:|:-----------:|:-------------:|:----:|:------|
| **CityHash64** (Google, 2011) | — | — | — | TODO | Originally optimised for Intel Sandy Bridge. Uses `PRIME × MUL` accumulator pattern. |
| **CityHash128** | — | — | — | TODO | 128-bit output variant. |
| **FarmHash64** (Google, 2014) | — | — | — | TODO | CityHash successor; internal algorithm selection based on input size. |
| **FarmHash128** | — | — | — | TODO | |
| **FarmHashFingerprint64** | — | — | — | TODO | Finalised fingerprint variant (deterministic across versions). |

### 4.4. Metro / Wy family

| Primitive | Raw KPA | ChainHash-1 | Verdict label | Impl | Notes |
|:----------|:-------:|:-----------:|:-------------:|:----:|:------|
| **MetroHash64** (Rogers, 2015) | — | — | — | TODO | |
| **MetroHash128** | — | — | — | TODO | |
| **wyhash-final4** (Wang Yi, 2021+) | — | — | — | TODO | Used in Zig stdlib; inspired wyhash-derivative rapidhash. Two 64-bit multiplications per block. |
| **wyhash-final3** | — | — | — | TODO | Previous generation; different accumulator structure. |
| **rapidhash** (De Carli, 2024+) | — | — | — | TODO | wyhash-derivative; used in newer Rust crates as SwissTable hasher. |
| **komihash** (Vaneev, 2021+) | — | — | — | TODO | Alternative wyhash-style fast 64-bit hash. |

### 4.5. Rust ecosystem defaults

| Primitive | Raw KPA | ChainHash-1 | Verdict label | Impl | Notes |
|:----------|:-------:|:-----------:|:-------------:|:----:|:------|
| **FxHash** (Firefox / rustc) | — | — | — | TODO | Simple `state = (state.rotate_left(5) ^ byte) * PRIME`. Likely trivially invertible — pending check; may migrate to "out of scope" if so. |
| **AHash** (Kaitchuck) | — | — | — | TODO | Uses AES-NI when available → migrates to formal-PRF category. Pure-fallback path (no AES-NI) uses non-AES ARX mixing — that fallback IS in scope. |
| **fnv-rs** default (FNV-1a 64) | — | — | — | TODO | Trivially invertible; already covered by ITB Phase 2g analogy — NOT in shelf scope. Listed here only for disambiguation against above. |
| **foldhash** (Mara Bos, 2024+) | — | — | — | TODO | New Rust stdlib candidate; ARX-based. Relatively unstudied. |
| **gxhash** (2024+) | — | — | — | TODO | AES-NI / VAES-based; migrates to formal-PRF when hw available, ARX fallback in scope. |

### 4.6. Zig / Go / other ecosystem

| Primitive | Raw KPA | ChainHash-1 | Verdict label | Impl | Notes |
|:----------|:-------:|:-----------:|:-------------:|:----:|:------|
| **Zig stdlib Wyhash** | — | — | — | TODO | Ports upstream wyhash-final4. Covered above; this row just points to Zig-specific wrapper testing. |
| **Go `hash/maphash`** | — | — | — | TODO | Runtime implementation uses AES-NI when available (→ formal-PRF); fallback variant uses wyhash-style ARX (→ in scope). |
| **Rust `HashMap` pre-1.37** (SipHash-1-3) | — | — | — | TODO | Reduced-round SipHash variant. Whether the reduction moves it out of formal PRF bounds is an open question; measure. |

### 4.7. Other categories to consider later

- **Universal hashing families** (UMAC, Polynomial over large prime fields with keyed coefficient). These often have provable weak-KPA bounds but are interesting empirical targets when the base field / prime is small.
- **SpookyHash V2** (Jenkins).
- **HighwayHash** (Google) — SIMD-heavy; AES-NI dependencies push it toward formal-PRF regime, pure-SW path worth measuring.
- **t1ha family** (Leonid Yuriev).
- **NMHash / NMHash-X** (James Z. M. Gao).

---

## 5. Expected results matrix (prior to measurement)

Prior beliefs, updated as empirical rows land:

| Primitive class | Expected raw-KPA verdict | Expected ChainHash-1 verdict | Expected shelf verdict label |
|:----------------|:------------------------:|:----------------------------:|:-----------------------------:|
| xxh3 / xxh64 family | ⏱ timeout at 1 week+ | ⏱ timeout, higher budget | **Dangerous** (analytical ITB extrapolation within cluster-year) |
| MurmurHash3 x64_128 | ⏱ timeout at 1 week | ⏱ timeout | **Dangerous** |
| CityHash / FarmHash | ⏱ timeout at 1 week | ⏱ timeout | **Dangerous** |
| wyhash / rapidhash / komihash | ⏱ timeout, unknown budget | ⏱ timeout | **Dangerous** |
| MurmurHash3 x86_32 (short accum) | ✗ recoverable, hours-days | ✗ recoverable, extended | **Fully broken** (expected sub-day at ITB keyBits=512) |
| FxHash (if non-trivial) | ✗ likely trivial at raw | — | **Fully broken** or migrates to "invertible — out of scope" |
| AHash ARX-fallback | ⏱ timeout 1 week | ⏱ timeout | **Dangerous** |

Priors held with wide error bars. Any inversion at significantly tighter
wall-clock than predicted is itself a publication.

---

## 6. Reproducibility

Same template as REDTEAM.md Phase 2g reproduction block — install Bitwuzla,
run calibration script, collect JSON + log, summarise.

Template command:

```bash
# Raw-KPA calibration: N rounds × M observations grid.
python3 scripts/redteam/phase2_theory_<p>/sat_calibration_raw_<p>.py \
    --rounds 1 --obs 16,32,64 --timeout-sec 86400 \
    --json-report tmp/attack/<p>stress/phase0_raw_24h.json

# ChainHash-1 variant.
python3 scripts/redteam/phase2_theory_<p>/sat_calibration_chain_<p>.py \
    --rounds 1 --obs 16,32,64 --timeout-sec 86400 \
    --json-report tmp/attack/<p>stress/phase0_chain_24h.json
```

---

## 7. Publication strategy

Each primitive × column pair that produces a concrete verdict is a candidate
for a short standalone writeup (blog post / arXiv note): "Empirical SAT
KPA resistance of `<primitive>`, wall-clock `<N> h` at `<M>` observations
on commodity hardware". The full shelf is a second-paper target once 3+
primitives are measured: *"SAT Cryptanalysis Shelf: Empirical KPA
Resistance of Widely-Deployed Non-Cryptographic Hash Functions"*.

xxh3-128 is the headline case (most deployed, most ambiguous PRF status,
zero published cryptanalysis). Subsequent primitives add breadth to the
"practically-behaves-like-PRF but no proof" empirical map.

A separate orthogonal research thread, deferred: **ML-enhanced beam-search
discrimination** under non-linear wrapping constructions. The current shelf
harness ranks per-pixel `noise_pos` candidates using format-aware heuristics
(printable-ASCII ratio, format-signature counts) — the same discriminators
used in [REDTEAM.md Phase 2g](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) decrypt. Replacing those heuristics with a CNN /
transformer / LLM-API scorer trained on self-generated corpora follows the
established ML-cryptanalysis pattern (Gohr, CRYPTO 2019; subsequent follow-
up literature); the trained model deploys on target ciphertext using only
beam-search-visible partial reconstructions — attacker-realistic train /
deploy separation preserved. Binary-format recovery rates under the current
heuristic are known to sit at the random-byte collision floor ([REDTEAM.md
Phase 2g architectural finding 6](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based)); ML-enhanced discrimination is expected to
raise them substantially on formats that carry structural entropy margin
(ZIP, PDF, MP4, DEFLATE). Quantifying this improvement is a distinct
empirical study. Appropriate title for the follow-up paper: *"ML-enhanced
beam-search disambiguation of noise-encoded ciphertexts under non-linear
wrapping constructions"*. Out of scope for this shelf's primitive-resistance
measurements; complements them by clarifying the decrypt-side boundary.

---

## 8. Running log

(Append one dated line per concrete milestone. Do not rewrite history.)

- 2026-04-23 — File created as planning skeleton; gitignored. Structure
  follows FNV-1a / MD5 working-plan pattern. Primitive shelf seeded with
  ~20 candidate primitives across xxh / Murmur / Google / Metro / Wy /
  Rust-ecosystem / Zig-Go-ecosystem families. No measurements yet — awaiting
  MD5 calibration outcome (PID 115102, 24 h budget) before committing to
  first shelf measurement. xxh3-128 withSeed identified as headline
  primary target per `.MD5STRESS.md` § 11 follow-up pointer.
- 2026-04-23 — Moved out of `.gitignore`; SATHARNESS.md becomes a public
  sibling of REDTEAM.md / ITB.md / SCIENCE.md / PROOFS.md as a statement
  of intent — the non-crypto-hash empirical-cryptanalysis project is an
  active, publicly-declared direction, not an internal planning document.
- 2026-04-23 — Shelf verdict scheme aligned with
  [REDTEAM.md Hash matrix](REDTEAM.md#hash-matrix) labels: per-primitive
  **Verdict label** column added to every shelf table (xxh / Murmur /
  Google / Metro-Wy / Rust / Zig-Go) with the same `Fully broken` /
  `Dangerous` / `Resistant` vocabulary used for the ITB Hash matrix.
  `Fully broken` = Raw-KPA or ChainHash-1 empirically produced functional
  K in commodity budget (FNV-1a reference at ~8 h); `Dangerous` = shelf
  measurement timed out, but analytical extrapolation under ChainHash +
  ITB places full decrypt inside well-funded-attacker reach (cluster-
  weeks to cluster-years — MD5 reference from REDTEAM.md Phase 2a);
  `Resistant` = timeout at the shelf budget AND extrapolation to ITB-
  wrapped levels lands beyond any plausible attacker budget. Expected
  results matrix (§ 5) updated with prior-belief verdict labels for
  each primitive family — to be replaced by empirical labels as shelf
  measurements land. A primitive may hold different labels at different
  ITB-wrapping levels (e.g. Fully broken at keyBits=512 / 4 rounds but
  Resistant at keyBits=1024 / 8 rounds), recorded as worst-case with
  analytical footnotes for the higher levels.
- 2026-04-23 — ML-enhanced beam-search discrimination recorded in § 7 as
  an orthogonal research thread (deferred). Current shelf harness ranks
  per-pixel `noise_pos` candidates via format-aware heuristics; replacing
  those with CNN / transformer / LLM-API scorers (Gohr CRYPTO 2019-style
  methodology) is attacker-realistic and expected to lift binary-format
  recovery rates above the random floor observed in REDTEAM.md Phase 2g
  finding 6. Quantification deferred to a separate empirical paper.
