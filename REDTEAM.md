# ITB Red-Team Empirical Validation

This document records the **v0.3.0** adversarial re-verification of ITB. The shipped construction under test is **Triple Ouroboros** — the byte-level 3-snake split — over the **8-seed** constellation, with the **always-on 48-bit Interlocked Barrier** as its non-disableable core. There is no Single Ouroboros, no overlay toggle, and no Bit Soup mode; every pre-v0.3.0 measurement conditioned on "Single" or "overlay disengaged" describes a construction that no longer ships.

The complete pre-v0.3.0 empirical record is preserved verbatim in **[REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md)** and is cross-referenced by phase throughout — the archived detail is not re-inlined here.

The re-verification is organised as three tracks, each a self-contained adversarial pass:

- **[Broken-primitive re-verification](#broken-primitive-re-verification--fnv-1a-and-crc128)** — FNV-1a and CRC128 as the hardest-case algebraic controls.
- **[PRF-grade primitive re-verification](#prf-grade-primitive-re-verification)** — BLAKE3 as the representative primitive, generalised through the PRF assumption.
- **[Phase 4 — construction-level creative probes](#phase-4--construction-level-creative-probes-triple--interlocked-barrier)** — properties that do not depend on which hash keys the barrier.

The highest-insight architectural outcome is the **layer-attribution** finding in [Phase 4 §4.0](#40-the-single-most-important-finding--layer-attribution): the Triple + Interlocked Barrier layer produces a COBS-framed container whose byte histogram carries a fixed `0x00`-terminator signature, and the **outer-cipher wrapper**, not the barrier, is the layer that whitens the wire to the uniform floor and delivers wire-level format deniability.

## Construction under test and shared conventions

Every track drives the shipped core Triple entrypoints (`Encrypt3x128Cfg` / `Encrypt3x256Cfg` and their decrypt duals) over the 8 mandatory distinct seeds (noiseSeed, lockSeed, dataSeed1..3, startSeed1..3). The 48-bit Interlocked Barrier permutes the plaintext into the three snakes through a per-chunk mask triple — three balanced 16-of-48 partitions drawn PRF-keyed from the lockSeed and the nonce — **before** COBS framing and pixel encoding. Parallax and the outer-cipher wrapper are independent layers above this; except where a probe explicitly toggles the wrapper, the measured surface is the barrier layer alone.

**Discipline carried on every claim.** Every empirical verdict is **sample-bounded**: a null result means no measurable signal above the finite-sample floor at the stated sample size N under the stated threat model, never that no signal exists. PRF-grade closure claims are **PRF-conditional**. The independent-stream reference throughout is the byte-equal rate of two uniform random streams, **1/256 ≈ 0.00391**.

**Nonce-Reuse is a lab-only assumption.** A caller cannot force nonce reuse — the nonce is drawn from `crypto/rand` on every call — but it is the only condition under which the pre-v0.3.0 suite ever measured signal, so several probes below adopt it to give the attacker its best case.

**Barrier constants** (architectural, from the mask-space counting argument; the single canonical numeric reference for the tracks below):

| Constant | Value |
|---|---|
| Chunk width | 48 bits / 6 bytes |
| Mask triple | three balanced 16-of-48 partitions |
| Mask-space cardinality per chunk (A · B) | ≈ **2^70.20** |
| Partition constants A = C(48,16), B = C(32,16) | 2,254,848,913,647 · 601,080,390 |
| gcd(A, B) anti-collapse trap | **66,861** = 3² · 17 · 19 · 23 |
| Preimage count per chunk (fresh-nonce under-determination) | ≈ **2^57.80** |
| Per-chunk bias | ≈ **2^-57.8** |
| Per-message accumulated bias | ≈ **2^-34.4** |
| Distinguisher sample budget | ≈ **2^115.6** chunks (beyond attainable) |

## Broken-primitive re-verification — FNV-1a and CRC128

This track stresses the shipped v0.3.0 construction — Triple Ouroboros
with the always-on 48-bit Interlocked Barrier over the 8-seed
constellation — with two deliberately below-spec lab-control primitives
plugged in as the ITB ChainHash. The controls are the hardest algebraic
stress cases available: a fully **GF(2)-linear** primitive and an
**invertible non-linear** one. Both sit far below the shipped registry's
PRF-grade floor; neither is a production hash and neither appears in the
shipped registry. They are used here precisely because they leak
maximally in isolation, so the barrier's absorption is measured against
the strongest possible primitive weakness rather than against easy PRF
wins.

- **CRC128** — two keyed CRC64 lanes (ECMA + ISO polynomials). Every
  operation is GF(2)-linear, so the ITB ChainHash over it stays affine
  end-to-end: the per-pixel data hash factors as
  `dataHash(pixel) = K ⊕ const(pixel, nonce)` with `K` a
  pixel-independent compound key and `const` a public, seed-independent
  per-pixel value. This end-to-end linearity is the property that a
  direct algebraic crib attack exploits.
- **FNV-1a** — the classic FNV-1a multiply over Z/2^128. Invertible
  (the multiply is a bijection modulo 2^128) but not GF(2)-linear; the
  low lane is a triangular T-function of the low input bits, which a SAT
  solver can invert given a fixed known-plaintext anchor.

The pre-v0.3.0 empirical record broke both controls, but only under a
construction that no longer ships: **Single Ouroboros with the overlay
disengaged**. That evidence is preserved verbatim in **[REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md)**
(CRC128: `## Phase 2f — Direct Crib KPA against GF(2)-linear primitives`;
FNV-1a: `## Phase 2g — Multi Crib KPA against FNV-1a + ITB (SAT-based)`;
mixed-algebra nonce-reuse stress: `### Phase 2a extension — empirical
mixed-algebra stress test via CRC128 (Nonce-Reuse)`; related-seed:
`## Phase 2e — Related-seed differential`). It is cited by section
throughout this track and not re-inlined. The v0.3.0 line removes Single
Ouroboros, removes the ability to disengage the overlay, and widens the
per-chunk mask space from ≈ 2^33.14 (24-bit Triple) to ≈ 2^70.20 (48-bit
Triple). The pre-v0.3.0 break preconditions no longer exist.

All verdicts here are **PRF-conditional and/or architectural** and, where
they rest on measurement, **sample-bounded**. Nonce-Reuse is a lab-only
assumption on ciphertext generation — a real caller cannot force it,
because the nonce is drawn from `crypto/rand` on every call — and it is
the only condition under which the pre-v0.3.0 suite ever measured signal;
every probe below adopts it to give the attacker its best case. The
attacker-realism discipline holds throughout: every recovery decision
uses only attacker-visible inputs (ciphertext bytes, the public crib, the
public nonce from the header, the seed-independent public per-pixel
`const`); ground-truth seed values appear only in terminal-stage audit
printouts, never in a decision.

### Why the barrier closes the algebraic crib attacks

The architectural reason is adopted from the pre-flight cryptographer
verdict (threat-model §2.1 / §3.1) and corroborated empirically below; it
is not re-derived here. The 48-bit Interlocked Barrier permutes the
plaintext into the three snakes through a per-chunk mask triple drawn
from a space of ≈ 2^70.20 balanced 16-of-48 partitions, keyed by the
lockSeed and the nonce, **before** COBS framing and pixel encoding. A
known crib therefore never reaches a fixed, solver-anchorable pixel
position: the mapping from a plaintext bit to the observed lane is itself
a hidden per-chunk secret. The GF(2)-linear pixel-independent collapse
that recovered the CRC128 compound key against Single/overlay-off has no
analogue against the keyed 48-bit permutation, and the FNV-1a lo-lane SAT
instance cannot even be formulated because the attacker cannot say which
observed byte carries which plaintext bit.

The ≈ 2^70.20 mask-space cardinality and the 3-snake independence this
argument rests on are primitive-agnostic and are measured once, at the
barrier core, in [Phase 4 Probe C2](#42-probe-c2--mask-space-structural-uniformity-and-the-gcd-anti-collapse-trap)
(full balanced mask space, gcd anti-collapse trap avoided) and
[Probe C4b](#44-probe-c4--cross-snake-independence) (cross-lane
decorrelation at the sampling floor); this track cites that shared core
rather than re-running it.

### Threat-model summary

| Attack | Threat model | Budget | Verdict |
|---|---|---|---|
| **CRC128 Crib KPA** | Crib / Full KPA + Nonce-Reuse (lab) | 0.09 s Go harness, 625-shift scan | null — 0 anchoring shifts, 0 shadow-K survivors |
| **FNV-1a lo-lane SAT** | Full KPA + Nonce-Reuse (lab) | closed, not run (v0.2 ≈ 8 h precedent) | architecturally foreclosed at instance formulation |
| **Barrier crib displacement** | structural invariant (both controls) | 0.07 s Go harness | crib fully displaced for linear and non-linear controls |
| **CRC128 Nonce-Reuse (two ciphertexts)** | Nonce-Reuse (lab) | 0.01 s Go harness | null — Crib KPA still recovers no key from either ciphertext |
| **CRC128 mixed-algebra nonce-reuse** | Nonce-Reuse (lab) | see v0.2 `Phase 2a extension` | signal is nonce-reuse-scoped; not a fresh-nonce channel |
| **Related-seed differential** | Related-Seed (lab, upstream-key) | see v0.2 `Phase 2e` | outside the shipped API; 8-seed isolation + barrier diffusion |

The below-spec controls lead this table because the methodology seeks the
hardest algebraic stress cases, not the easiest PRF wins; the shipped
PRF-grade primitives are covered in the PRF-grade track.

### CRC128 Crib KPA

**Threat model.** Crib / Full KPA with the Nonce-Reuse lab assumption
(fixed 64-byte nonce). The attacker holds the ciphertext, a public-schema
JSON crib, the public nonce, and the public seed-independent per-pixel
`const`. **Budget.** A single Go harness run — `go test -run
TestRedTeamBrokenCRC128CribKPA ./` — completes in ≈ 0.09 s: a
625-candidate startPixel scan against a four-pixel (28-byte) crib.

**Attack.** The recovery is ported from the pre-v0.3.0 CRC128 Crib KPA
(`scripts/redteam/phase2_theory/crib_crc128_kpa.py` derive-K + cross-pixel
verify, and `crib_crc128_kpa_full.py` survivor enumeration). For each
candidate startPixel and each crib pixel it recovers the observable
56-bit compound key from the container byte and the known crib byte, over
all noise-position (8-way) and rotation (7-way) guesses — a strictly
**stronger** attacker than the pre-v0.3.0 filter, which recovers both
algebraically rather than by brute force. The **shadow-K survivor count**
is the number of observable keys consistent with every crib pixel at the
best-anchoring shift.

**Verdict — null.** Against a Single, overlay-off control encode (reached
only through the low-level in-package path, which the shipped v0.3.0 API
does not expose), the ported filter anchors exactly one shift and returns
exactly one survivor — the true compound key. That control confirms the
filter is sensitive. Against the shipped `Encrypt3x128Cfg` ciphertext of
the same plaintext, the filter anchors **zero** shifts and returns
**zero** survivors across all 625 candidate startPixels; the ciphertext
round-trips, so it is a genuine encryption under attack. The observable
2^56 key space is not reduced at any shift.

**Rationale.** The barrier permutes the plaintext into the snakes before
it is pixel-encoded, so the crib bytes the attacker substitutes as
"pixel p's plaintext" are the wrong bytes. The GF(2)-linear
pixel-independent collapse that recovered CRC128 pre-v0.3.0 (v0.2
`Phase 2f`, ≈ 1 s at 4 KB, 100 % second-message decryption) has no
analogue: there is no fixed bit-position-to-lane anchor for the linear
system to hang on. The closure is at the instance-formulation layer under
the PRF assumption; it is sample-bounded by the 625-shift scan and the
four-pixel crib, and no absolute claim is made beyond the tested surface.

**Partial KPA.** No dedicated Partial KPA probe is run: the result
follows a fortiori from the Full / Crib KPA null. A Partial KPA attacker
holds strictly less known plaintext than the full crib used above, so its
achievable-key sets per pixel are a superset of the full-crib sets and
its cross-pixel intersection can only be larger, never smaller — it
recovers no key where the stronger full-crib attacker recovers none.
Threat-model §2.3 states the same: Partial KPA is closed at the
instance-formulation layer strictly more than Full KPA, with the
byte-splitting obstacle (v0.2 `Phase 2d`, gcd(7,8)=1 forcing every
plaintext byte across two channels) as an additional independent factor.

### FNV-1a lo-lane SAT

**Threat model.** Full KPA with the Nonce-Reuse lab assumption,
SAT-based. **Budget — mathematically closed, not run.** The pre-v0.3.0
FNV-1a lo-lane SAT break (v0.2 `Phase 2g`) needed ≈ 8 h single-core
against Single/overlay-off to recover a functionally equivalent dataSeed
lo lane from four public-schema cribs plus a disclosed startPixel,
decrypting future messages at ≈ 83–85 % byte accuracy on structured text.
Re-running that solver against the v0.3.0 barrier falls outside the
coordinator's 30-minute-per-probe budget, and the architectural argument
forecloses it upstream of solver speed, so it is documented rather than
executed.

**Rationale.** The FNV-1a lo lane is a triangular T-function, invertible
by a solver **only when the crib anchors a fixed bit-to-lane mapping** so
the instance can be written down. The barrier removes that anchor. The
primitive-agnostic displacement probe below shows the FNV-1a crib is
displaced exactly as the CRC128 crib is — so the SAT instance cannot be
formulated at all. This is an instance-formulation closure, not a
solver-throughput one: no amount of SAT horsepower converts an
unformulable instance into a solvable one. Consistent with the
coordinator budget decision, the closure is recorded as architecturally
foreclosed rather than brute-forced in vain.

### Barrier crib-anchor displacement

**Threat model.** Structural invariant of the construction, measured for
both controls. This probe holds the true seeds to observe **what the
barrier did** — it is not an attack decision path. **Budget.** A single
Go harness run — `go test -run TestRedTeamBrokenBarrierDisplacement ./` —
≈ 0.07 s.

**Measurement.** A fully attacker-known structured crib is encrypted, and
the barrier-permuted snake payloads are recovered and compared against
the raw-order positions the pre-v0.3.0 attacker would assume. The
fraction of the leading crib bytes still sitting at their assumed
post-split position is the displacement metric.

**Verdict.** For both controls the fraction sits at ≈ 0.0056 (1 in 180),
below the ≈ 0.0385 same-symbol coincidence rate of the 26-symbol
structured crib. The crib is displaced for the **GF(2)-linear (CRC128)**
and the **non-linear invertible (FNV-1a)** control alike. Anchor
destruction is therefore primitive-agnostic — it does not depend on any
algebraic property the primitive happens to lack, which is why it closes
both the CRC128 linear collapse and the FNV-1a lo-lane SAT by the same
mechanism.

### CRC128 Nonce-Reuse (two ciphertexts)

**Threat model.** Nonce-Reuse, lab-only. **Budget.** A single Go harness
run — `go test -run TestRedTeamBrokenCRC128NonceReuse ./` — ≈ 0.01 s.

**Setup and verdict.** Two different plaintexts are encrypted under an
identical 64-byte nonce and an identical 8-seed bundle; the collision is
realised and asserted on the wire. The Crib KPA is then run against each
ciphertext. Both return **zero anchoring shifts and zero shadow-K
survivors** over 625 candidate startPixels. Nonce reuse alone does not
hand the attacker the barrier permutation, because the mask triple is
keyed by the lockSeed as well as the nonce; the masks repeat across the
colliding pair, but the crib remains unanchored, so no key is recovered
from either ciphertext.

**Rationale.** This matches threat-model §2.4: nonce reuse is a usage
precondition, not something the barrier architecturally closes. The
container structure aligns across the pair (the PRF-grade track's
nonce-reuse probe measures the resulting ciphertext-level correlation at
≈ 5.4× the independent-stream floor), but full demask of the colliding
pair additionally requires Full KPA (v0.2 `Phase 2d`) and, even then,
yields only the barrier-permuted snake images rather than plaintext — the
plaintext order stays behind the ≈ 2^70.20-per-chunk mask space. The two
findings are the two halves of one result: nonce reuse re-exposes
nonce-deterministic container structure but not a plaintext-recovery
channel.

### CRC128 mixed-algebra nonce-reuse stress

**Threat model.** Nonce-Reuse, lab-only, mixed-algebra stress. The
pre-v0.3.0 measurement is in v0.2 `### Phase 2a extension — empirical
mixed-algebra stress test via CRC128 (Nonce-Reuse)`. Its finding — that
ITB's mixed-algebra defense (GF(2) XOR interleaved with the primitive's
own algebra) is load-bearing, and that a same-algebra primitive such as
CRC128 collapses the ChainHash where a mixed-algebra one does not —
carries forward unchanged as the motivation for CRC128 as a control. The
v0.3.0 barrier adds the per-chunk mask permutation on top, so even the
same-algebra collapse no longer anchors (this track's CRC128 Crib KPA and
Nonce-Reuse probes). The mixed-algebra property is a property of the
ChainHash layer; the barrier is an independent, always-on layer above it.

### Related-seed differential

**Threat model.** Related-Seed differential, lab-only. No public API
exposes the ability to induce a controlled seed differential; the 8-seed
intake draws independent CSPRNG components and rejects pointer-identical
seeds. The pre-v0.3.0 CRC128 measurement is in v0.2 `## Phase 2e —
Related-seed differential`, where CRC128 leaked on every axis under its
end-to-end GF(2)-linearity and FNV-1a leaked on one narrow delta visible
to the differential probe but discarded by the hLo extraction on the
encryption path.

**Verdict.** Under the v0.3.0 8-seed constellation the related-seed setup
remains outside the shipped API, and the barrier diffuses rather than
localizes any induced seed delta. The PRF-grade track's related-seed
probe measures the two representative channels directly (a one-bit
dataSeed delta diffused to ≈ 0.24 bit-difference fraction, snake-scoped;
a one-bit lockSeed delta re-drawing every mask to ≈ 0.48, approaching full
avalanche), confirming that neither channel leaves a low-weight,
position-predictable differential. Any residual related-seed exposure
would be an **upstream key-management** defect (correlated seeds supplied
by a defective KDF), not a barrier property; the construction cannot
repair correlated inputs and does not claim to.

### Closure and boundaries

Under the PRF assumption and with fresh per-message nonces, this track's
measurements corroborate the architectural closure of the Crib / Full KPA
family against the two hardest algebraic control primitives at 48-bit
chunk width: the crib does not anchor, so the shadow-K survivor set stays
at the full observable key space and no key is recovered. The closure is
an architectural claim (mask-space cardinality, per-chunk PRF
independence, 3-snake enumeration, 8-seed isolation) corroborated by these
sample-bounded null measurements, not an independent proof. The
[PRF-grade-versus-broken-primitive equivalence claim](#prf-grade-versus-broken-primitive-equivalence)
places this result in its architectural context: the barrier's
mask-formulation under-determination is the dominant term regardless of
the primitive's own strength, so a would-be-broken primitive is masked to
null by the same mechanism that leaves a PRF-grade primitive null. It is
explicitly conditional on the PRF assumption and fresh nonces: total
inversion of the primitive circumvents the barrier, and nonce reuse
re-exposes container structure the barrier does not remove. These
boundaries — nonce reuse, total or systematic PRF inversion, upstream
key-management, side channels, key compromise, implementation defects,
and CCA via a deployment decryption oracle — sit outside what the barrier
itself closes and are addressed at the construction level in SECURITY.md
and PROOFS.md.

### Reproduction

```
# All broken-primitive probes (CRC128 + FNV-1a), package itb.
go test -run TestRedTeamBroken -v ./

# Individually:
go test -run TestRedTeamBrokenCRC128CribKPA -v ./
go test -run TestRedTeamBrokenBarrierDisplacement -v ./
go test -run TestRedTeamBrokenCRC128NonceReuse -v ./
```

The harness is `redteam_broken_test.go` (package `itb`). The CRC128 /
FNV-1a adapters and the ported Crib KPA filter carry inline provenance
comments pointing at the retired lab test scaffolds
(`redteam_lab_test.go` / `redteam_test.go` at the pre-rewrite commit) and
the Python arsenal routines they adapt.

## PRF-grade primitive re-verification

### Scope and stance

This section records the v0.3.0 adversarial re-verification against a
**PRF-grade** primitive. BLAKE3 is the representative primitive; the
verdicts generalise across the PRF-grade registry subset through the PRF
assumption, which is what makes a single representative sufficient: each
member is
configured as a secure PRF, and the barrier's closure argument consumes
only that property, not any BLAKE3-specific structure.

The v0.3.0 construction under test is the shipped default: **Triple
Ouroboros** (byte-level 3-snake split), the **always-on 48-bit
Interlocked Barrier**, and the **8-seed** constellation (noiseSeed,
lockSeed, dataSeed1..3, startSeed1..3), driven through the core
`Encrypt3x256Cfg` / `Decrypt3x256Cfg` entrypoints. There is no Single
Ouroboros fallback and no overlay toggle; every pre-v0.3.0 measurement
conditioned on "overlay disengaged" or "Single" describes a
construction that no longer ships and is retained only in
[REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md).

The honest headline, stated once and carried as a qualification on every
claim below: **under the PRF assumption and with fresh per-message
nonces, the barrier is designed to close the Crib / Partial / Full KPA
and fresh-nonce CPA families at the instance-formulation layer.** The
closure of the barrier layer is architectural — it rests on the
per-chunk mask-space cardinality, per-chunk PRF independence, the
3-snake enumeration dimension, and the 8-seed isolation — corroborated
by the empirical probes recorded here and by the pre-v0.3.0 evidence for
the shared pixel construction, and it is not an independently certified
result. Total inversion of the primitive, or a reused nonce, is outside
what the barrier is designed to close.

### Why one representative primitive is sufficient

The pre-v0.3.0 suite measured a spectrum spanning deliberately broken
lab controls (CRC128, FNV-1a, MD5) through paper-grade PRFs, and the
recurring structural fact was that **no PRF-grade primitive was broken
at any phase, under any threat model, and no break survived engagement
of the opt-in overlay** (see [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md), Phase 2 result tables).
The plaintext-recovery breaks were obtained only against below-spec
primitives, only against Single Ouroboros, and only with the overlay
disengaged.

For a PRF-grade primitive the null result is a **definitional
consequence of the PRF assumption**, not an accident of the tested
sample: a secure PRF's ChainHash output is computationally
indistinguishable from random before the barrier is ever applied, so the
attack surface reduces to statistical ciphertext properties already at
the finite-sample floor. Expanding the empirical breadth across every
PRF-grade member would multiply runs without changing the argument —
each member enters the construction through the same ChainHash interface
and is consumed by the same barrier. The representative-primitive
approach documents the null rigorously on BLAKE3 and generalises through
the shared assumption, rather than re-deriving the same null per member.

### 4-probe minimum — BLAKE3, v0.3.0

The mandatory 4-probe minimum drives the shipped core Triple entrypoint
(BLAKE3-256, width 256, 512-bit key width, 8 distinct seeds, always-on
barrier). The probes are landed as `redteam_prf_blake3_test.go`
(package `itb`); reproduce with `go test -run TestRedteamPRF -v ./`.
Combined wall-clock is under one second. Every verdict is
**sample-bounded**: a null result means no measurable signal above the
finite-sample floor at the stated sample size N under the stated threat
model, never that no signal exists.

The independent-stream reference throughout is the byte-equal rate of
two uniform random streams, **1/256 ≈ 0.00391**: two ciphertexts whose
byte-equal rate sits at this floor carry no cross-message correlation an
attacker could aggregate.

| Probe | Threat model | Sample | Observable | Floor / target | Verdict |
|---|---|---|---|---|---|
| 1 — Crib KPA, fresh nonce | Crib KPA, PRF-conditional, fresh-nonce | N = 200, 4 KB body, shared public-schema crib | crib-region ct byte-equal **0.00465**; mean \|Pearson\| **0.01020** | 0.00391 (1/256) | **null** — crib anchors nothing at N = 200 |
| 2 — Nonce-reuse | Nonce-Reuse, **lab-only** | N = 200, forced fixed nonce | reused-nonce ct byte-equal **0.02126**; mean \|Pearson\| **0.01739** | 0.00391 | **small structural correlation** (~5.4× floor); lab-only, no fresh-nonce analogue |
| 3 — Related-seed differential | Related-Seed, **lab-only** | N = 128, 1-bit seed Δ, fixed nonce | dataSeed1 Δ ct bit-diff **0.24029**; lockSeed Δ ct bit-diff **0.47753** | diffused, no low-weight trace | **null for exploitability** — no followable differential |
| 4 — Full KPA, shared state | Full KPA, PRF-conditional, fresh-nonce | N = 64 pairs, shared 8-seed bundle | pairwise ct byte-equal **0.00464**; all round-trips exact | 0.00391 | **null** — shared state yields no aggregable correlation |

#### Probe 1 — Crib KPA under fresh nonces

**Attack.** Two plaintexts share a public-schema JSON header crib and
differ in the body; both are encrypted under one fixed 8-seed bundle
with fresh per-message nonces — the shipped condition, since the nonce
is drawn from `crypto/rand` on every call. A crib that anchored any
bit-position-to-lane mapping would surface as correlation in the
crib-region ciphertext bytes of the two messages.

**Budget.** N = 200 message pairs, ≈ 0.2 s wall-clock.

**Verdict.** The crib-region byte-equal rate (**0.00465**) sits at the
independent-stream floor (0.00391) within finite-sample tolerance; the
distinguisher signal |rate − floor| is **0.00074** and the mean
absolute Pearson correlation is **0.01020**. No measurable crib-anchor
signal at N = 200 under the PRF assumption and fresh nonces. The
architectural reason is that each 48-bit chunk draws its mask triple
PRF-keyed from a space of roughly **2^70.20** balanced partitions, and a
fresh nonce re-draws every mask, noise position, and startPixel — so the
shared crib fixes no mapping a solver could anchor on. Pre-v0.3.0 Crib
KPA detail against below-spec primitives is preserved in
[REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md) (Phase 2f CRC128, Phase 2g FNV-1a); neither analogue
applies to a PRF-grade primitive under the keyed 48-bit permutation.

#### Probe 2 — Nonce-reuse correlation (lab-only assumption)

**Attack.** Nonce reuse is **not reachable through the shipped API** —
the nonce is internally generated per call. Forced here via the
test-only nonce override, this probe measures the one condition under
which the pre-v0.3.0 suite saw any signal ([REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md), Phase 2d).
Two different plaintexts are encrypted under identical seeds AND an
identical nonce.

**Budget.** N = 200 pairs, ≈ 0.2 s wall-clock.

**Verdict.** The reused-nonce ciphertext byte-equal rate (**0.02126**)
rises above the floor to roughly **5.4× the independent-stream floor** —
the expected structural consequence of identical nonces producing
identical per-chunk masks and noise positions, so the
nonce-deterministic container structure aligns across the pair. This is
recorded, not closed: **nonce reuse is a usage precondition the barrier
does not architecturally remove**, because the per-chunk masks repeat
under a reused nonce and the keystream-reuse structure persists beneath
the permutation. Even so, the ciphertext-level correlation stays far
below a usable plaintext-recovery channel — the nonce-independent CSPRNG
tail fill and the plaintext-dependent bytes dominate — and a full demask
of the colliding pair additionally requires Full KPA ([REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md),
Phase 2d, where a forced collision let a demasker reconstruct the pure
dataSeed stream; NIST STS on the reconstructed stream then passed
188/188 for BLAKE3 and separated it from the below-spec primitives). The
mitigating architectural fact is that the mandatory internal nonce
prevents caller-forced reuse; that is an API-discipline property, not a
barrier guarantee. Fresh-nonce operation (Probe 1) shows no correlation
rise.

#### Probe 3 — Related-seed differential (1-bit Δ)

**Attack.** The related-seed differential is **not reachable through the
shipped API** — the 8-seed intake draws independent CSPRNG components
and rejects pointer collisions. Forced here: a seed and its
1-bit-delta twin, every other seed identical, same plaintext, and a
fixed nonce so the seed's own effect is isolated rather than swamped by
fresh masks. Two channels are probed — dataSeed1 (keys one snake's
ChainHash render) and lockSeed (keys the barrier permutation for every
chunk).

**Budget.** N = 128 Δ pairs per channel, ≈ 0.2 s wall-clock.

**Verdict.** Null for exploitability — neither channel leaves a
low-weight, position-predictable differential a trace could follow. The
dataSeed1 delta produces a ciphertext bit-diff fraction of **0.24029**:
structurally scoped to one snake's third of the payload, then diffused
across a broader ciphertext region by the barrier permutation and the
COBS / interleave, landing well above the one-snake floor (≈ 0.167). The
lockSeed delta produces a bit-diff fraction of **0.47753**, approaching
full avalanche (0.5) because it re-draws every per-chunk mask triple.
The contrast is the **8-seed isolation made observable**: each seed's
influence is scoped to its own channel, and the barrier diffuses the
delta rather than localising it. A differential attacker sees a
decorrelated ciphertext, not a gradient. Pre-v0.3.0 related-seed matrix
detail (the 1008-cell single-axis XOR-differential sweep) is preserved
in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md), Phase 2e, where the PRF-grade primitives were
neutralised on every primitive-attributable axis.

#### Probe 4 — Full KPA at N derivations sharing state

**Attack.** The worst-case baseline: the attacker holds N complete
plaintext / ciphertext pairs produced under one fixed 8-seed bundle with
fresh nonces, and tries to recover any seed component. Round-trip
integrity is verified on every pair, so the attacker's known plaintext
is real. The aggregable quantity — pairwise ciphertext byte-equal rate
across all pairs — is the correlation an attacker aggregating N pairs
would hope to see rise above the floor.

**Budget.** N = 64 pairs (C(64,2) = 2016 comparisons), ≈ 0.07 s
wall-clock. The seed-recovery brute force itself is **mathematically
bounded and documented, not run** — attempts the architecture rules out
in advance are not executed against wall-clock (coordinator budget
decision).

**Verdict.** Null — the shared derivation state produces no cross-message
ciphertext correlation (pairwise byte-equal **0.00464**, at the 0.00391
floor). Seed recovery is **instance-formulation-bounded, not
solver-bounded**: even granting the 48 known plaintext bits of a chunk
under Full KPA, the per-chunk mask triple has roughly **2^57.80**
preimages and is unobservable without the lockSeed, so no per-bit
constraint can be written down and there is no ranking signal among the
roughly 2^70.20 masks. Combined with the per-pixel 1:1 signal / noise
ambiguity of the underlying pixel construction (Proof 1), the attacker
holds no gradient. That ≈ 2^70.20 mask space is realised in full and
balanced form — and the two-step reduction avoids the gcd anti-collapse
trap — as measured at the barrier core in
[Phase 4 Probe C2](#42-probe-c2--mask-space-structural-uniformity-and-the-gcd-anti-collapse-trap),
which this track cites as the shared primitive-agnostic core rather than
re-running it. The residual honest caveat inherited from the
pre-v0.3.0 Full KPA analysis survives verbatim: **systematic partial PRF
inversion is a real, non-absorbed threat the architecture raises cost
against but does not eliminate, and total PRF inversion circumvents the
barrier entirely.** The closure is conditional on the primitive behaving
as a PRF. Pre-v0.3.0 Full KPA obstacle detail (Proof 4a's interlocking
obstacles, the Phase 2b per-pixel KL floor at ≈ 1.4× the theoretical
bins/N floor, the Phase 2c startPixel rank-fraction ≈ 0.5) is preserved
in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md).

### CPA (chosen-plaintext, fresh nonce)

Under fresh-nonce CPA the attack surface reduces to statistical
ciphertext properties. The pre-v0.3.0 record placed ITB ciphertext at
the finite-sample statistical floor — indistinguishable from
`/dev/urandom` within the tested tolerance — across the full primitive
spectrum on every statistical surface measured (Phase 1 structural / FFT
/ Markov, Phase 2b per-pixel KL, Phase 3b NIST STS), including
attacker-friendly rotation-invariant probes ([REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md), Phase
3a). With fresh nonces each message draws fresh masks, noise positions,
rotations, and startPixels; the always-on 48-bit permutation adds a
further keyed re-mapping whose lane assignment is a hidden per-chunk
secret. Chosen plaintext gives the attacker no observable handle on any
of these. The verdict is **closure under the PRF assumption with fresh
nonces**, resting on ciphertext indistinguishability at the
sample-bounded statistical floor plus the additional keyed permutation.
The two mode-agnostic phases that were run under Triple (structural /
FFT / Markov and NIST STS) produced results indistinguishable from
Single; the full 48-bit always-on statistical surface is a follow-on
re-verification phase, and any empirical claim carried forward is scoped
to what was actually run.

**Scope of the "indistinguishable from `/dev/urandom`" claim.**
[Phase 4 §4.0](#40-the-single-most-important-finding--layer-attribution)
establishes that the Triple + Interlocked Barrier layer alone produces a
COBS-framed container whose byte histogram carries a fixed `0x00`
signature — primitive-agnostic container framing, not a primitive leak —
and that the outer-cipher wrapper is the layer that whitens the wire to
the uniform floor. The statistical-floor claim here therefore applies to
the **wrapped** wire and to the per-pixel / KL payload-channel probes
(Phase 2b) and reconstructed-stream NIST STS, not to the raw barrier-only
byte histogram, which a byte chi-square detects at the container-signature
level regardless of primitive.

### PRF-grade versus broken-primitive equivalence

The pre-v0.3.0 record broke below-spec primitives (CRC128 fully
GF(2)-linear, FNV-1a invertible, MD5 broken) and never broke a PRF-grade
primitive. Under the always-on 48-bit barrier, **both classes converge
to the same observable outcome — no measurable signal at the tested
sample sizes — but reach it by two different mechanisms:**

- **PRF-grade primitive (BLAKE3 representative) — architectural
  closure.** The primitive is already null by the PRF assumption; the
  ChainHash output is indistinguishable from random before the barrier
  is applied. The barrier adds an instance-formulation
  under-determination on top of an already-null primitive. The
  observable was null pre-barrier and stays null. Probe 1 and Probe 4
  corroborate the null empirically (crib and pairwise ciphertext
  byte-equal both at the 0.00391 floor).

- **Below-spec broken primitive — architectural under-determination.**
  The primitive leaks in isolation, and the pre-v0.3.0 suite recovered a
  working key from CRC128 in about one second and from FNV-1a in about
  eight single-core hours — but **only** against Single Ouroboros with
  the overlay disengaged ([REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md), Phase 2f / 2g). Under the
  always-on 48-bit barrier the attacker cannot formulate the linear or
  invertible system at all: the bit-position-to-lane mapping is a hidden
  per-chunk ≈ 2^70.20 secret, so the GF(2)-linear pixel-independent
  collapse that broke CRC128 has no analogue. A would-be-broken
  primitive is masked to null.

The equivalence is that **the barrier's mask-formulation
under-determination is the dominant term regardless of the primitive's
own strength.** For a PRF the primitive supplies the null and the
barrier is redundant-but-additive; for a broken primitive the barrier
supplies the null the primitive fails to. The two attributions differ;
the observable outcome does not. Because the below-spec closure is an
instance-formulation argument rather than an appeal to primitive
strength, it holds without invoking the PRF assumption for that class —
though it, too, is stated as an architectural claim under fresh nonces,
not an independently certified result, and remains conditional on the
absence of a structural shortcut against the barrier's own reduction
arithmetic.

### Qualifications carried on every claim

- **PRF-conditional.** All PRF-grade closure claims hold under the
  assumption that the configured primitive is a secure PRF. Total PRF
  inversion collapses the argument; the barrier raises cost against
  partial PRF weakness but does not substitute for the PRF.
- **Fresh-nonce-conditional.** Closure assumes unique per-message
  nonces. Nonce reuse (Probe 2) re-exposes a keystream-reuse structure
  the barrier does not architecturally remove.
- **Barrier-layer scoped.** These verdicts concern the Interlocked
  Barrier plus Triple split. Parallax and the outer-cipher wrapper are
  independent additional layers not credited here.
- **Architectural, corroborated, not independently certified.** The
  closure argument rests on the mask-space counting plus the empirical
  probes recorded here and the pre-v0.3.0 evidence for the shared pixel
  construction. ITB has had no external cryptanalysis or formal
  certification, and the strong claims are stated conditionally for that
  reason.
- **Sample-bounded.** Every empirical verdict is bounded by the tested
  sample size N and must be read as "no measurable signal at N", never
  as an absolute.

## Phase 4 — Construction-level creative probes (Triple + Interlocked Barrier)

The attack families in the earlier phases target a chosen primitive: a broken
lab control (see the [broken-primitive stress phase](#broken-primitive-re-verification--fnv-1a-and-crc128))
or a PRF-grade representative (see the
[PRF-grade null-result phase](#prf-grade-primitive-re-verification)). This phase targets the
**construction itself** — the properties that do not depend on which hash keys
the barrier. Each probe drives either the wire produced through the Triple
facade or the barrier's own kernels directly, and each reports a
sample-bounded verdict at the tested sample size. Every wire statistic is
computed from bytes an attacker holding the ciphertext already has; no seed,
key, or plaintext is consulted to steer any measurement.

The probes are shipped as Go tests (`harness_test.go` in the root package for
the barrier-kernel probes; `triple/harness_wire_test.go` for the facade wire
probes). Both files gate their full-sample statistical loops behind the
`ITB_HARNESS_FULL=1` environment variable so the default `go test ./...` run
stays fast; the sample sizes recorded below are the `ITB_HARNESS_FULL=1`
figures.

### 4.0 The single most important finding — layer attribution

The centrepiece result of this phase is a clarification of **which layer
delivers which property**. The v0.3.0 stack composes three independently
toggleable layers on the payload: parallax (pre-inner multiplexing), the itb
Triple Ouroboros split plus the always-on 48-bit Interlocked Barrier, and the
format-deniability **outer cipher** wrapper. Every probe in this phase forces
parallax off and toggles only the wrapper, so the measured wire is contributed
by the barrier layer alone (wrapper off) or by the barrier layer plus the outer
cipher (wrapper on).

Taken alone, the **Triple + Interlocked Barrier layer does not produce a
uniform-random wire at the byte-value level.** Its wire is a COBS-framed pixel
container whose byte histogram carries a fixed, publicly-explained signature:
the COBS terminator `0x00` is over-represented by roughly **+4.75 %** against
the uniform expectation, with one companion value showing a comparable spike,
and the remaining values distributed within a fraction of a percent of uniform.
The Shannon entropy of the pooled wire stays at **≈ 7.99998 bits/byte** and the
wire is **incompressible** (flate best-compression ratio 1.0003), because the
signature is a low-mass, two-value bias rather than exploitable structure — but
a byte-histogram chi-square, being the sharp instrument for exactly this kind
of granular bias, does detect it. At N = 8000 messages of 256-byte plaintext
the barrier-only byte chi-square sits at **≈ 1720–1850** (df = 255, uniform
5-sigma acceptance band [142, 368]).

Engaging the outer cipher whitens the wire to the finite-sample uniform floor:
the same byte chi-square drops to **≈ 254–260** (inside the band) and the
`0x00` deviation collapses from +4.75 % to **± 0.05 %**. **The outer cipher is
the layer that delivers wire-level format deniability; the barrier layer is
not designed to, and does not, whiten the container's byte histogram on its
own.** This is consistent with the barrier's architectural role — it adds a
per-chunk keyed permutation on top of the pixel container, not a stream-cipher
whitening pass — and it scopes every "indistinguishable from random" claim
precisely: such a claim applies to the **wrapped wire**, or to the per-pixel /
KL candidate-distinguisher probes that operate on the payload channel, **not**
to the raw byte histogram of the barrier-only container.

The finding is primitive-agnostic: the container framing is applied identically
regardless of which hash keys the seeds, so a broken primitive and a PRF-grade
primitive produce the same `0x00` signature when the wrapper is off. Any
wire-level uniformity measurement in the broken-primitive or PRF-grade phases
that ran with the wrapper disengaged sees this container signature; it is not a
primitive leak.

### 4.1 Probe C1 — cross-profile wire distinguishability and mode ambiguity

**Question.** Can an attacker holding a ciphertext tell, from wire byte
statistics alone, whether it was produced by the **Streaming AEAD** MAC profile
or the **Non-AEAD** profile? The mode-ambiguity doctrine ships both with a
wire-identical envelope so that a MITM cannot assume a MAC-check oracle exists;
this probe tests that doctrine empirically at the byte-histogram level.

**Setup.** The Triple facade encrypts N = 8000 fresh-random 256-byte messages
under each of `streaming-aead-triple-mac-v1` and `streaming-noaead-triple-v1`,
parallax off, at both wrapper postures. Each message draws a fresh internal
nonce from crypto/rand. The pooled wire byte histograms feed three statistics:
per-profile byte-value chi-square against uniform, per-profile Shannon entropy
and flate compressibility, and — the load-bearing statistic — the **two-sample
homogeneity chi-square** between the AEAD pool and the Non-AEAD pool (df = 255).

**Result.**

| Posture | AEAD wire chi² | Non-AEAD wire chi² | `0x00` dev (both) | AEAD↔Non-AEAD homogeneity χ² |
|---|---|---|---|---|
| Wrapper off (barrier only) | 1719.0 | 1852.7 | +4.75 % | **275.5** |
| Wrapper on (outer cipher) | 260.4 | 254.3 | ±0.05 % | **263.2** |

Pooled entropy 7.99998–8.00000 bits/byte and flate ratio 1.0003 in every cell.

**Verdict — mode ambiguity holds (sample-bounded).** The two-sample
homogeneity chi-square between the AEAD and Non-AEAD pools is **inside the
uniform acceptance band whether or not the outer cipher is engaged**
(275.5 wrapper-off, 263.2 wrapper-on, band top 368). The two modes carry one
identical container law — the `0x00` signature is +4.75 % in **both**, so it
cancels in the two-sample test — and no wire byte statistic separates them at
the tested sample size. Presence or absence of a MAC is not betrayed by the
wire byte histogram, because the MAC rides inside the encryption envelope and
the Non-AEAD path fills the corresponding envelope region with CSPRNG dummy
content of matching length.

**Positive control.** The barrier-only per-profile chi-square (1719 / 1853,
far above the band) confirms the probe is genuinely sensitive: it detects the
container signature that is actually present, so the in-band homogeneity result
is a real null and not a probe that trivially passes. Engaging the outer cipher
independently pulls each mode's chi-square into the band, re-confirming §4.0.

**Cross-reference.** The
[broken-primitive stress phase](#broken-primitive-re-verification--fnv-1a-and-crc128) and the
[PRF-grade null-result phase](#prf-grade-primitive-re-verification) can run the same
two-sample homogeneity test on their primitive's wire; the mode-ambiguity
result is expected to reproduce, since the container framing that carries the
signature is primitive-agnostic.

### 4.2 Probe C2 — mask-space structural uniformity and the gcd anti-collapse trap

**Question.** Does the per-chunk mask-triple derivation actually realise the
architectural **≈ 2^70.20** balanced-partition space the KPA closure argument
rests on, or does an implementation detail collapse it to a structured subset?

**Setup.** This is a white-box structural harness, not an attack — no seed,
key, or plaintext is recovered. The package-private kernel
`rankToMaskTriple48`, reachable from a root-package test, is fed N = 200000
random 128-bit values (crypto/rand), with the gcd-trap witness at N = 500000.
Three measurements are collected: the three balanced-partition invariants on
every draw; the uniformity of the reduced indices; and the residue-class
coverage that distinguishes the shipped two-step reduction from the rejected
same-rank double-mod.

**Result.**

- **Invariants — 100 % of draws.** Every mask triple satisfies
  `popcount(m0) = popcount(m1) = popcount(m2) = 16`,
  `m0 | m1 | m2 = 0x0000_FFFF_FFFF_FFFF`, and pairwise-disjoint lanes. No draw
  violated any invariant.
- **Balance.** Each of the 48 payload bit positions lands in lane 0 with
  empirical frequency 16/48 ± the sampling floor; the maximum per-bit deviation
  is **2.05 sigma** across all 48 positions.
- **Index uniformity.** The low bits of the two reduced indices are uniform:
  chi-square 294.2 and 243.0 over 256 bins (df = 255, band [142, 368]).
- **gcd anti-collapse trap.** The gcd of the two partition constants is
  `gcd(C(48,16), C(32,16)) = 66861 = 3² · 17 · 19 · 23`. Under the shipped
  two-step reduction the fraction of draws landing on the residue diagonal
  `idx0 ≡ idx1 (mod 66861)` is **1.600 × 10⁻⁵**, matching the full-space
  expectation `1/66861 ≈ 1.496 × 10⁻⁵`. The rejected same-rank double-mod would
  confine **every** draw to that diagonal (fraction 1.0). The measured
  off-diagonal spread is the empirical witness that the reduction reaches the
  full residue grid, not the 1/66861 subset the naive alternative would expose.

**Verdict — null structural deviation.** The mask space is full and balanced at
the tested sample size, and the two-step reduction demonstrably avoids the
residue-class trap. The architectural mask-space cardinality claim is
corroborated at the derivation layer; no implementation detail collapses the
space. This is a structural-correctness result, not a security proof — it
confirms the counting argument is faithfully implemented, under the standing
assumption that the lockSeed's PRF output is indistinguishable from the uniform
128-bit input fed here.

**Primitive-agnostic.** The barrier core is identical regardless of which hash
keys the lockSeed; the broken-primitive and PRF-grade phases cite C2 as the
shared core rather than re-running it.

### 4.3 Probe C3 — tail-fill CSPRNG residue, size-stability of the container signature

**Question.** Small plaintexts leave the wire dominated by the container floor
and CSPRNG tail fill. Does that fill introduce a size-dependent artefact — a
distinguisher keyed on plaintext length beyond the length the wire already
reveals?

**Setup.** The Non-AEAD profile (wrapper off) encrypts N = 8000 wires at each
of plaintext sizes {1, 6, 32, 4096} bytes. Per size the pooled wire yields
entropy, flate ratio, byte chi-square, and the `0x00` over-representation.

**Result.**

| Plaintext size | Pooled bytes | Entropy | flate | `0x00` dev |
|---|---|---|---|---|
| 1 | 79.2 M | 7.99998 | 1.0003 | +5.33 % |
| 6 | 79.2 M | 7.99998 | 1.0003 | +4.90 % |
| 32 | 79.2 M | 7.99998 | 1.0003 | +5.12 % |
| 4096 | 79.2 M | 7.99998 | 1.0003 | +5.21 % |

**Verdict — null size-leak.** The container signature is size-stable: the
`0x00` over-representation ranges only over [4.90 %, 5.33 %] across a four-order
plaintext-size span, and entropy and incompressibility are constant. The
tail-fill-dominated small-plaintext wire carries the **same** container law as
the payload-dominated large-plaintext wire, so no size-dependent fill anomaly
is present at the tested sample size. The container framing is applied
uniformly across the container floor, and the tail fill inherits the same COBS
byte law rather than a distinct one that would betray the boundary between
payload and fill.

### 4.4 Probe C4 — cross-snake independence

**Question.** Triple Ouroboros splits the payload across three interleaved
snakes with independent per-snake dataSeeds and startPixels, and the barrier
scatters each 48-bit chunk across three disjoint lanes. Under that independence
the three streams should carry no cross-correlation. A deviation would flag a
barrier or interleave bug that couples the snakes.

**Setup — two complementary angles.**

- **C4b, kernel layer.** The package-private `chunk48lock` kernel is driven
  with N = 200000 random 48-bit chunk words under fresh random mask triples;
  the Pearson correlation between the three lane outputs is measured. This
  isolates the barrier's own split, free of COBS framing.
- **C4a, wire layer.** N = 30000 wires of one fixed 300-byte plaintext (fresh
  nonce each) are aligned column-wise; the maximum absolute Pearson correlation
  between wire byte-columns at lags 1–6 over a 128-column window is measured.
  This is the end-to-end wire view, container framing included.

**Result.**

- **C4b (kernel).** r01 = −0.00294, r02 = −0.00119, r12 = 0.00098; max |r| =
  **0.00294** against the sampling floor 0.00224 (N = 200000). Cross-lane
  correlation sits at the sampling floor.
- **C4a (wire).** max |r| = **0.02025** against the sampling floor 0.00577
  (N = 30000) — roughly 3.5× the floor, below the 8× acceptance threshold.

**Verdict — null cross-snake coupling at the barrier; a small container-framing
residual at the wire.** The kernel-layer correlation is exactly at the sampling
floor, so the barrier's split introduces no linear coupling between the three
lanes. The wire-layer correlation is mildly elevated above its floor; the
attribution is the marginal COBS-container `0x00` clustering (adjacent bytes are
weakly co-biased toward the terminator value), **not** a barrier cross-snake
leak — the kernel-layer probe, which bypasses COBS entirely, shows no such
residual. Engaging the outer cipher would remove the wire-layer residual, as
§4.0 shows for the byte-histogram signature. The barrier and interleave are
independent across snakes at the tested sample sizes.

### 4.5 Probe C5 — cumulative bias floor across many-chunk wires

**Question.** The barrier's mask draw carries a fixed, publicly-known per-chunk
relative deviation of ≈ 2^-57.8, accumulating to ≈ 2^-34.4 over a maximum-size
message. Is any cumulative bias measurable, and does the observed wire deviation
track the sampling floor rather than a systematic drift?

**Setup.** The barrier kernel angle (C5-core) pools the lane-output bits over
N = 300000 chunks and measures per-bit balance. The wire angle pools the bytes
of N = 4000 wires of 4096-byte random plaintext at both wrapper postures
(≈ 39.6 M bytes each) and measures per-bit-of-byte balance.

**Result.**

- **C5-core (kernel).** Maximum per-bit deviation 1.773 × 10⁻³ against the
  sampling floor 1.826 × 10⁻³ (maxZ = 1.94). The architectural per-chunk bias
  2^-57.8 ≈ 3.99 × 10⁻¹⁸ is roughly fifteen orders of magnitude below this
  detection floor.
- **C5 (wire).** Barrier-only maximum per-bit deviation 2.379 × 10⁻⁴ (maxZ =
  2.99, container tilt); wrapped 1.605 × 10⁻⁴ (maxZ = 2.02), against the
  sampling floor 1.588 × 10⁻⁴. The architectural per-message bias 2^-34.4 ≈
  4.41 × 10⁻¹¹ is roughly seven orders of magnitude below this floor.

**Verdict — no measurable cumulative bias from the barrier math (sample-bounded,
documented-not-brute-forced).** The kernel-layer per-bit deviation tracks the
sampling floor, and the architectural per-chunk bias is far below detectability
at the tested sample size — turning that granularity into a confident
distinguisher would require on the order of 2^115.6 chunk samples, beyond any
attainable budget, so it is documented from the reduction arithmetic rather than
brute-forced. At the wire the small barrier-only tilt is the container signature
of §4.0, which the outer cipher removes (wrapped balance at the sampling floor).
The correct framing is "no measurable cumulative bias at the tested sample
size", not "no bias exists": the architectural constant is a granularity below
the attainable detection floor, not a claim of zero.

### 4.6 Probe C6 — nonce-freshness and per-message wire divergence

**Question.** Does a fixed plaintext under a fixed session map to a large orbit
of distinct ciphertexts, as the fresh-nonce under-determination argument
predicts? This corroborates the ambiguity-dominance count (≈ 2^57.80 preimages
per chunk) empirically without brute-forcing the preimage space.

**Setup.** A single facade session (`Init` once, Non-AEAD profile, wrapper off)
encrypts the **same** 256-byte plaintext N = 10000 times. Each call draws a
fresh internal nonce. Measured: the count of distinct wires, and the mean
pairwise Hamming distance over the wire body across a bounded sample of pairs.

**Result.** 10000 distinct wires out of 10000 — no collision. Mean pairwise
Hamming distance **0.4998** of the body bits (ideal 0.5). Every body position
varies across the pool.

**Verdict — null collision.** A fixed plaintext under a fixed session maps to a
fully-diversified observed-ciphertext orbit at the tested sample size: the
internal per-call nonce drives fresh masks, fresh noise positions, and fresh
per-snake offsets on every message, so the wire body is effectively an
independent random draw per message. This is empirical corroboration of the
fresh-nonce under-determination — the observed orbit is large and
collision-free — without enumerating the ≈ 2^57.80 preimage space the
architectural argument counts. The result is a witness, not a proof: it
confirms the observed behaviour matches the architecture at N = 10000, under the
standing PRF and fresh-nonce assumptions.

### 4.7 Phase 4 summary

| Probe | Layer | Sample size | Verdict |
|---|---|---|---|
| C1 mode ambiguity | facade wire | 8000 msg × 4 cells | Modes indistinguishable (homogeneity in-band); outer cipher whitens container signature |
| C2 mask-space | barrier kernel | 200k–500k draws | Full balanced space; gcd trap avoided; null structural deviation |
| C3 tail-fill | facade wire | 8000 msg × 4 sizes | Size-stable container signature; null size-leak |
| C4 cross-snake | kernel + wire | 200k / 30k | Null coupling at barrier; small container residual at wire |
| C5 cumulative bias | kernel + wire | 300k / 39.6 M B | No measurable bias; tracks sampling floor |
| C6 nonce freshness | facade wire | 10000 msg | All wires distinct; ~50 % pairwise Hamming |

Every construction-level probe returns a null or an explained-container result
at the tested sample sizes. The one non-trivial finding — that the
Triple + Interlocked Barrier layer's raw wire carries a COBS-container byte
signature that the outer cipher, not the barrier, whitens — is a scoping
clarification, not a weakness: it tells the reader exactly which layer to credit
for wire-level format deniability, and it removes an over-claim that a
barrier-only wire is byte-histogram-uniform. All results are conditional on the
configured primitive behaving as a secure PRF and on fresh per-message nonces,
and all empirical statements are bounded by the tested sample size.

**Reproduction.**

```
# Barrier-kernel structural probes (root package): C2, C4b, C5-core.
ITB_HARNESS_FULL=1 go test -run 'TestHarnessC[245]' -v ./

# Facade wire probes (triple package): C1, C3, C4a, C5, C6.
ITB_HARNESS_FULL=1 go test -run 'TestHarnessC[13456]' -v ./triple/

# Default (fast smoke) run — small sample, every assertion still exercised:
go test -run TestHarness ./ ./triple/
```

## Cross-track synthesis

The three tracks converge on one sample-bounded, PRF-conditional outcome — **no measurable signal at the tested sample sizes under the stated threat models** — reached through complementary evidence.

**Broken and PRF-grade primitives converge by two mechanisms.** The [equivalence claim](#prf-grade-versus-broken-primitive-equivalence) states it in full: for a PRF-grade primitive the primitive itself supplies the null and the barrier is redundant-but-additive (**architectural closure**); for a below-spec broken primitive the barrier supplies the null the primitive fails to (**architectural under-determination**), because the bit-position-to-lane mapping is a hidden per-chunk ≈ 2^70.20 secret and the GF(2)-linear pixel-independent collapse that broke CRC128 pre-v0.3.0 has no analogue. The broken-primitive track's empty shadow-K survivor sets and the PRF-grade track's floor-level crib and pairwise byte-equal rates are the two halves of the same finding.

**The shared barrier core is measured once.** Both primitive tracks rest on the ≈ 2^70.20 mask-space cardinality and on 3-snake independence. These are primitive-agnostic and are corroborated at the derivation and kernel layers by [Phase 4 Probe C2](#42-probe-c2--mask-space-structural-uniformity-and-the-gcd-anti-collapse-trap) (full balanced mask space, gcd anti-collapse trap avoided) and [Probe C4b](#44-probe-c4--cross-snake-independence) (cross-lane decorrelation at the sampling floor); neither primitive track re-runs them.

**Wire-level claims are scoped to the wrapped wire.** [Phase 4 §4.0](#40-the-single-most-important-finding--layer-attribution) establishes that the barrier layer alone does not whiten the container's byte histogram — the `0x00` COBS signature is primitive-agnostic container framing, not a primitive leak. The PRF-grade track's fresh-nonce CPA statistical-floor claim therefore applies to the **wrapped** wire and to the per-pixel / KL payload-channel probes, not to the raw barrier-only byte histogram. The broken-primitive track's closure is a key-recovery / shadow-K survivor claim rather than a wire-histogram indistinguishability claim, so §4.0 does not rescope it.

## Conclusion

Across the two primitive tracks and the construction-level probe phase, the v0.3.0 re-verification produced a uniform null verdict at the tested sample sizes: the broken-primitive controls yield empty shadow-K survivor sets with no anchoring crib shift; the PRF-grade representative sits at the independent-stream floor on the crib and Full KPA probes; and every construction-level probe returns a null or an explained-container result. The one condition that surfaces any signal is nonce reuse — a lab-only assumption a caller cannot force — and even there the correlation stays far below a plaintext-recovery channel.

The architectural closure narrative is that the always-on 48-bit Interlocked Barrier moves the KPA / CPA closure to the **instance-formulation layer**: a known crib no longer anchors a fixed bit-to-lane mapping, so the linear system a broken primitive would expose cannot be written down, and the mask has ≈ 2^57.80 preimages per chunk that no per-bit constraint can rank. The layer-attribution finding closes the pass with a scoping correction rather than a weakness: wire-level format deniability is a property of the outer-cipher wrapper, and every "indistinguishable from random" claim is scoped accordingly to the wrapped wire or the payload-channel probes.

All verdicts are sample-bounded and, where they invoke primitive strength, PRF-conditional. The closure is an architectural claim corroborated by these measurements and by the pre-v0.3.0 evidence for the shared pixel construction, not an independently certified result. Total or systematic PRF inversion circumvents the barrier; nonce reuse re-exposes container structure the barrier does not remove; and upstream key-management, side channels, key compromise, implementation defects, and CCA via a deployment decryption oracle sit outside what the barrier itself closes and are treated at the construction level in SECURITY.md and PROOFS.md. The complete pre-v0.3.0 empirical detail remains in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md).

## Pre-v0.3.0 empirical archive

The complete pre-v0.3.0 empirical record — the full Phase 1 through Phase 3b suite, every result table, and every Single-Ouroboros / overlay-off measurement — is preserved verbatim in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md). The v0.3.0 re-verification above supersedes it for the shipped construction; the archive is retained for the pre-v0.3.0 evidence the tracks cross-reference. The retired phase headings below are anchor bridges that resolve inbound references from the sibling documentation to their archived location.

### Phase 2a extension — hash-agnostic bias-neutralization audit (axis-1 + axis-2)

Archived in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md) under the identically-named section. The primitive-shelf bias-neutralization methodology is carried forward in HARNESS.md.

### Phase 2d — Nonce-Reuse

Archived in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md) § Phase 2d — Nonce-Reuse: the 96-cell Partial KPA matrix, demasker validation, and NIST STS PRF-separation result. The v0.3.0 nonce-reuse verdicts are in the [broken-primitive](#crc128-nonce-reuse-two-ciphertexts) and [PRF-grade](#probe-2--nonce-reuse-correlation-lab-only-assumption) tracks above.

### What a successful Partial KPA demask actually gets the attacker

Archived in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md) under the identically-named Phase 2d subsection: a successful demask yields the hash-output stream, never new plaintext beyond the attacker's own Full KPA input.

### Phase 2e — Related-seed differential

Archived in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md) § Phase 2e — Related-seed differential: the 1008-cell single-axis XOR-differential sweep. The v0.3.0 related-seed verdict is in the [PRF-grade track](#prf-grade-primitive-re-verification) and the [broken-primitive track](#related-seed-differential).

### Phase 2g — Multi Crib KPA against FNV-1a + ITB (SAT-based)

Archived in [REDTEAM-v0.2.md](archive/REDTEAM-v0.2.md) § Phase 2g — Multi Crib KPA against FNV-1a + ITB (SAT-based): the ≈ 8 h single-core SAT recovery against Single / overlay-off. The v0.3.0 FNV-1a verdict is in the [broken-primitive track](#fnv-1a-lo-lane-sat).

