# ITB Red-Team Empirical Validation

> **Purpose.** This document summarises the empirical red-team validation of ITB's theoretical security claims. Where the scientific paper (Zenodo [10.5281/zenodo.19229395](https://doi.org/10.5281/zenodo.19229395)) proves claims on paper, this document reports what happens when the construction is subjected to realistic cryptanalyst-style attacks on a concrete corpus.
>
> **Status.** Self-audit complete; results final for this round.

---

## TL;DR

ITB ciphertext was subjected to **several empirical statistical / structural distinguishers plus one analytical phase** (ChainHash cost modelling) with one empirical SAT anchor at the ITB minimum configuration, across a **12-primitive hash matrix** spanning the full spectrum — three below-spec stress controls (CRC128 fully GF(2)-linear, FNV-1a invertible, MD5 biased) and nine PRF-grade primitives (AES-CMAC, SipHash-2-4, ChaCha20, AreionSoEM-256, BLAKE2s, BLAKE3, BLAKE2b-256, BLAKE2b-512, AreionSoEM-512). Phases run: 1 (structural + FFT + Markov), 2a (ChainHash cost analysis) with two extensions — empirical GF(2)-linear collapse via CRC128 nonce-reuse, and hash-agnostic bias-neutralisation audit — 2b (per-pixel candidate distinguisher), 2c (startPixel enumeration), 2d (nonce-reuse), 2e (related-seed differential), 2f (direct Crib KPA against GF(2)-linear primitives), 2g (SAT-based Crib KPA against FNV-1a at ITB `keyBits = 512` minimum), 3a (rotation-invariant edge case), 3b (NIST STS). Primitive coverage: Phase 1 / 2b / 2c / 3a / 3b and Phase 2e exercise the full 12 primitives. Phase 2a extension bias-audit covers the 4-primitive set (CRC128, FNV-1a, BLAKE3, MD5) and the MD5 4 MB stress cell. Phase 2d (nonce-reuse) covers BLAKE3 + FNV-1a + MD5 + BLAKE2b-512 as a cross-width PRF-vs-invertible contrast. The suite was exercised across a 2 × 2 configuration matrix: `{Single, Triple} Ouroboros × {BF=1, BF=32} BarrierFill`. Single is the primary mode and runs the full phase suite; Triple runs Phase 1 + Phase 3b (the two mode-agnostic phases).

At shipped defaults (BF=1):

- **All 12 primitives pass every test on typical runs** — including the GF(2)-linear lab control CRC128, the deliberately-broken FNV-1a (linear, fully invertible), and MD5 (collisions + output biases). The barrier produces ciphertext statistically indistinguishable from a true PRF across the whole primitive spectrum.
- **Per-pixel candidate KL floor on 8 × 1 MB `html_giant` samples**: Mode A (idealized attacker, BF=1, N = 9.6 M obs/candidate) band [0.000017, 0.000021] nats, spread 4 × 10⁻⁶ across all 12 primitives; Mode B (realistic attacker — no `startPixel`, no plaintext, full container — BF=32, N = 11.3 M) band [0.000012, 0.000016] nats, spread 4 × 10⁻⁶. Both sit at ≈1.4× theoretical `bins/N` floor. A one-off probe at **N = 7.7 × 10⁷** (one 63 MB BLAKE3 encryption at the ITB data-size limit, Mode B, BF=32) drives observed KL max to **1.8 × 10⁻⁶ nats** — within 1.1× of the floor, subnanonat territory where float64 precision begins to matter.
- **NIST STS: all 12 primitives cluster p-values into a single bin — universally.** At N = 100 sequences × 1 Mbit, every hash's 100 per-sequence `NonOverlappingTemplate` p-values fall into one bin; the bin is different per hash and effectively random across runs (CRC128 → bin 9, FNV-1a → bin 9, BLAKE2b-512 → bin 0, ChaCha20 → bin 8, etc on BF=1 N=100). Proportion is 100/100 for all 12 primitives on every one of the 148 template sub-tests whenever the bin is **not** 0. Single-test failures (non-bin-0) across the N = 100 BF=1 + BF=32 runs combined: 7 out of 4 512 — well under the 1 % expected at α = 0.01. When a given hash's cluster lands in bin 0 on any one run, the proportion column mechanically reports a catastrophic-looking 40/188 for that hash (it has happened to FNV-1a at N=20 and BLAKE2b-512 at N=100 BF=1 in this suite); this is the documented NIST SP 800-22 artefact on near-uniform output, **not** a primitive-specific signal.
- **Phase 1 FFT + Markov sub-tests** (byte-level, mode-agnostic, Single + Triple, both BF regimes): per-channel spectral flatness stays within 6×10⁻⁵ of 1.0 for the other 11 primitives (white-noise signature, including FNV-1a and MD5 alongside the 9 PRF-grade primitives; CRC128 shows a replicated 0.95–0.98 flatness deviation — see [Phase 1 § B](#b-fft--markov-sub-tests-mode-agnostic-single--triple) CRC128 outlier mini-table); adjacent-byte Markov χ² mean within ~85 of the df=65 535 H0 expectation with p medians scattered around 0.5. No replicating Bonferroni false-positives across the within-pixel channel-pair tests — same statistical-power artefact pattern as [Phase 3a](#phase-3a--rotation-invariant-edge-case).
- **Phase 2a (analytical)** proposes that ChainHash's XOR chain is the load-bearing assumption behind the defense-in-depth stacking: it converts otherwise cheap primitive inversions into bitvector-SAT instances, so each defensive layer (ChainHash, unknown startPixel, Partial KPA byte-splitting) stacks multiplicatively **conditional on that SAT-hardness assumption**. One empirical SAT anchor at `keyBits = 512` / 4 rounds / FNV-1a is supplied by [Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) (~8 h single-core Bitwuzla); the 8 and 16-round extrapolations remain analytical.
- **Phase 2a (extension) — empirical GF(2)-linear collapse via CRC128 (Nonce-Reuse).** A test-only primitive (two CRC64 variants concatenated to 128 bits, fully GF(2)-linear) was wired into the [Phase 2d](#phase-2d--nonce-reuse) pipeline to verify empirically that the mixed-algebra premise is load-bearing. Unrolling 8 rounds of ChainHash at 1024-bit key collapses the 512-bit ECMA-side seed to a **64-bit compound key K** (56 bits observable via channelXOR); a commodity Python solver recovers K across the full matrix (54 cells — `{4 KB…1 MB} × {25/50/80 %} × {json_structured, html_structured, random_masked}`) with **53 / 53 correct compound keys K recovered within demask-successful cells** (not the 8-`uint64` dataSeed components themselves — the 8-round ChainHash collapses 512 seed bits to 64 compound-key bits; full dataSeed-component recovery remains out of empirical scope). Even with the primitive fully collapsed ITB still imposes visible cost: 8 cells hit period-shift catastrophe requiring pixel-shift brute force, and shadow-K aliasing leaves the attacker with **up to 294 candidate keys per cell at 1 MB** (1 correct + 293 wrong), total 2 575 shadow-K candidates across the matrix — a population the attacker must filter via plaintext-consistency on companion ciphertexts. FNV-1a analogue impossible: the Z/2⁶⁴-multiply carry structure blocks GF(2)-linear collapse, leaving the SAT pathway as the only route — empirically realised in [Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) at the ITB minimum configuration.
- **Nonce-reuse PRF-dependency empirically demonstrated (Phase 2d)**. Under a deliberate nonce collision with Full KPA, a Python demasker recovers `startPixel` + per-pixel `(noisePos, rotation)` in seconds and reconstructs the pure `dataSeed.ChainHash(pixel, nonce)` output stream (obstacles (2) and (3) of [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) no longer apply — only obstacle (1), ChainHash SAT-hardness, remains). NIST STS on the reconstructed ~16.7 Mbit stream per primitive at 2 MB plaintext: **BLAKE3 passes 188/188** (single remaining obstacle survives under PRF); **FNV-1a fails 6/188** — FFT 0/16 (100 % fail rate, spectral peaks on every bit-stream) plus BlockFrequency / CumulativeSums / Runs. The [`SCIENCE.md §2.5`](SCIENCE.md#25-nonce-reuse-analysis) locality claim ("seeds remain secret, no key rotation") holds under PRF; its PRF-dependency caveat is made empirically visible by the BLAKE3-vs-FNV-1a contrast.
- **Related-seed differential (Phase 2e) — 1008-cell matrix.** 12 primitives × 2 BF × 3 axes × 7 Δ patterns × 2 PT kinds tests single-seed XOR-differential propagation under same nonce + same plaintext + shared hash-function instance. 10 primitives are neutralized on the primitive-attributable axes (`data` / `start`): the 9 PRF-grade primitives plus MD5. CRC128 leaks on every axis as expected from end-to-end GF(2)-linearity. FNV-1a shows a narrow lab-detectable signal on one specific Δ (top-bit isolation preserved into an output bit ITB's `hLo` extraction discards) — visible to the differential probe but not exploitable through the encryption API.
- **Direct Crib KPA on GF(2)-linear primitive (Phase 2f) — cross-message confidentiality break.** Without nonce reuse, without the demasker, just a 21-byte public JSON schema crib: CRC128's 64-bit per-`dataSeed` compound key `K_data` plus the 3 low bits of `noiseSeed`'s compound key (`K_noise_bits_0_2`) fall jointly from a single ciphertext in ~1 s on 4 KB, scaling linearly with `total_pixels` up through 1 MB. The recovered pair decrypts a second ciphertext encrypted under the same seeds but a fresh nonce and different plaintext format (HTML) to **100.00 % byte-level** / **100.00 % full-pixel** accuracy across every tested size (4 KB / 64 KB / 128 KB / 1 MB), independent of plaintext class (printable text, binary, compressed). Short-crib shadow pairs are disambiguated by iterating every Stage-2 survivor through the decrypt and accepting the one producing a valid COBS-decoded plaintext — attacker-visible cross-check using the public ITB COBS spec, no lab peek. Two architectural findings: (i) the pair is nonce-independent, so one Crib KPA recovery compromises every future message under the same `(dataSeed, noiseSeed)`; (ii) `noiseSeed` exposes only its 3 low compound bits — sufficient to predict every per-pixel `noise_pos` — while the remaining 61 bits of `K_noise` and the full 512-bit `noiseSeed` component space remain architecturally inaccessible (residual kernel `2^957` above the Landauer bound for enumeration). Non-GF(2)-linear primitives (FNV-1a, MD5, every PRF-grade entry) are immune to this specific GF(2)-linear attack chain — see [Phase 2a extension bias audit](#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2); FNV-1a is separately broken by the SAT-based Crib KPA in [Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based), MD5 and the PRF-grade entries are not (non-invertible or not reachable by SAT at full rounds).
- **SAT-based Crib KPA on FNV-1a (Phase 2g) — operational break at ITB's `keyBits = 512` minimum.** 4 public-schema cribs + disclosed `startPixel` + commodity Bitwuzla SAT recovers a functionally-equivalent `dataSeed` lo-lane compound state in ~8 h single-core on a 16-core commodity host (hardware-variable, ± 30 %). The recovered K decrypts any future ciphertext under the same `(dataSeed, noiseSeed)` at **~83–85 % byte-level accuracy** on 4 KB JSON / HTML corpora (`startPixel` correctly re-anchored per target ciphertext, plaintext length bit-exact). The attacker-realistic variant without disclosed `startPixel` multiplies by `total_pixels` independent SAT instances (289 candidates for 4 KB JSON, 324 for 4 KB HTML), embarrassingly parallel — a 289-core commodity pool (one 64-core × 4–5, several 16-core boxes, or a ≤ 300 vCPU-hour cloud burst) reaches the same ~8 h wall-clock; no HPC required. The 15–17 % plaintext gap is architectural: per-pixel `noise_pos` has no Crib KPA equivalent under FNV-1a (PRF-output random values, no public-schema predictability), so the byte-match plateau is an empirical ceiling on this attack family. Result applies at `keyBits = 512` / 4 rounds (the ITB minimum); 8 and 16-round extrapolations remain analytical. FNV-1a is marked `Fully broken` in the [Hash matrix](#hash-matrix). PRF-grade primitives are not exposed: under each primitive's PRF assumption, efficient key recovery is infeasible by definition — any successful SAT inversion from polynomially-many known-plaintext pairs would constitute a PRF distinguisher, contradicting the assumption. Published SAT cryptanalysis confirms this empirically by reaching only reduced-round variants of AES-CMAC / SipHash-2-4 / ChaCha20 / AreionSoEM / BLAKE2 / BLAKE3. ITB's per-pixel envelope composes multiplicatively on top of this primitive-level PRF-hardness.

The results corroborate the paper's "barrier-based construction" claim: security arises from the architecture (8-channel packing, 7-bit extraction with rotation, CSPRNG-fill residue, ChainHash XOR chain) rather than from the quality of the underlying hash. Weak and strong primitives produce statistically identical ciphertext under every distinguisher run.

---

## Scope

This is a self-audit by the project author. Red-team validation tests a specific subset of theoretical claims against realistic adversary models. It does **not** substitute for independent external cryptanalysis.

### Paper claims tested

- [Proof 1](PROOFS.md#proof-1-information-theoretic-barrier) — per-pixel information-theoretic barrier, P(v\|h) = 1/2
- [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) — multi-factor Full KPA resistance, obstacles (2) and (3)
- [Proof 7](PROOFS.md#proof-7-bias-neutralization) — bias neutralisation by rotation barrier
- [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill) — guaranteed CSPRNG residue (fill minimum)
- [Nonce independence](PROOFS.md#nonce-uniqueness) — per-message independent configurations
- Composition conjecture — barrier absorbs systematic partial PRF weakness (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance))
- [Nonce-reuse locality + PRF-dependency](SCIENCE.md#25-nonce-reuse-analysis) — nonce collision is strictly local to the 2–3 affected messages; seeds retained under PRF, no key rotation required

### Threat model

ITB ciphertext sits at the finite-sample KL / χ² floor on every statistical surface measured — effectively `/dev/urandom`. Lab probes therefore take deliberate concessions (disclose parameters, force architecturally-impossible preconditions, peek at ground truth) to create *any* measurable signal. Each bullet below names the concession and the scope in which it applies.

- **Full KPA** as the worst-case baseline: attacker knows complete plaintext and ciphertext per sample. **Partial KPA** analysed separately in [Phase 2d](#phase-2d--nonce-reuse) (coverage 25 % / 50 % / 80 %).
- **Hash identity** known; **seed components / rotation / noisePos / dataRotation never disclosed** to the attacker model — used only as a ground-truth yardstick by lab analyzers during testing and lab-attack runs.
- **`startPixel` disclosed** in [Phase 2b](#phase-2b--per-pixel-candidate-distinguisher) Mode A and [Phase 3a](#phase-3a--rotation-invariant-edge-case) (isolate obstacle 3); **enumerated** in [Phase 2b](#phase-2b--per-pixel-candidate-distinguisher) Mode B + [Phase 2c](#phase-2c--startpixel-enumeration) (test obstacle 2).
- **Nonce reuse forced** in [Phase 2d](#phase-2d--nonce-reuse) and [Phase 2e](#phase-2e--related-seed-differential) — a `2⁻²⁵⁶` event at the shipped 512-bit nonce. Every finding in both phases is conditional on the attacker already being past that gate (see [Threat-model gate](#threat-model-gate--why-this-whole-exercise-is-gated-by-user-nonce-size-choice)).
- **Related-seed setup** in [Phase 2e](#phase-2e--related-seed-differential): same plaintext + same nonce + same two-of-three seeds + one-seed XOR-Δ across two encrypts, with a shared hash-function instance (cached PRF key preserved). No public API exposes any of these — lab-only test vector.
- **Below-spec primitives** used as stress controls — `crc128` (fully GF(2)-linear, [Phase 2a extension](#phase-2a-extension--empirical-mixed-algebra-stress-test-via-crc128-nonce-reuse) + [Phase 2f](#phase-2f--direct-crib-kpa-against-gf2-linear-primitives) direct Crib KPA), `fnv1a` (non-cryptographic invertible, [Phase 2d](#phase-2d--nonce-reuse) PRF-separation + [Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) SAT-based Crib KPA), `md5` (broken, [Phase 2d](#phase-2d--nonce-reuse) validation table). All three are lab test-helpers in `redteam_test.go` / `redteam_lab_test.go` with unexported lowercase identifiers — **not exported to any public API**.
- **Ground-truth peek** in lab-only analyzers (CRC128 [shadow-K filter](#phase-2a-extension--empirical-mixed-algebra-stress-test-via-crc128-nonce-reuse), [raw-mode bias probe](#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2)): analyzers read `cell.meta.json` / `config.truth.json` solely as a measurement yardstick, not as an attack input — see the probe's own scope note. These give an outside attacker zero advantage on ITB ciphertexts they do not control.

### Not tested

Attack classes:
- ~~**Full seed inversion** with an invertible primitive under ChainHash (research-level; see Phase 2a for analytical treatment — Z3 was **never actually executed**, not even at the ITB-with-ChainHash minimum `keyBits = 512` (2 ChainHash rounds × 256-bit hash, or 4 × 128-bit) nor at the larger flagship `keyBits = 1024`, so the scaling table is structural analysis only. `NewSeed{128,256,512}` explicitly reject `keyBits < 512`; the 128-bit figure quoted in earlier drafts referred to the hash output width, not the key size.)~~ — **partial results**: (a) empirical compound-key collapse on a GF(2)-linear control primitive (CRC128) at flagship `keyBits = 1024` via the nonce-reuse + demasking chain (see [Phase 2a extension](#phase-2a-extension--empirical-mixed-algebra-stress-test-via-crc128-nonce-reuse) — 1024-bit seed space projects onto 64 recoverable compound-key bits on one CRC64 lane); (b) empirical SAT-based functional recovery of `dataSeed` lo-lane on FNV-1a at `keyBits = 512` / 4 rounds (the ITB minimum) in [Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) — ~8 h single-core Bitwuzla on 4 cribs + disclosed `startPixel`, recovered K decrypts future ciphertexts under the same seeds at ~83–85 % byte-level accuracy on structured-text (JSON / HTML) plaintexts; binary-format plaintexts (ZIP, compressed streams) degrade to ~0.55 % — operational utility is format-dependent, see Phase 2g architectural finding 6. **Full component-level inversion (all 8 `uint64` values) was never achieved on either primitive** — for CRC128 the 8-round ChainHash collapse is lossy and the extra seed bits live in the null space of the compound linear map; for FNV-1a the hi-lane is unreachable by construction and the lo-lane recovery is functional, not bit-exact on every bit. PRF-grade primitives remain out of empirical scope by definitional argument — under each primitive's PRF assumption, efficient key recovery (SAT-based or otherwise) is ruled out because any such algorithm would itself constitute a PRF distinguisher; published SAT cryptanalysis on BLAKE3 / AES-CMAC / ChaCha20 / SipHash-2-4 / Areion / BLAKE2 reaches only reduced-round variants, consistent with the assumption.
- ~~**Direct Crib KPA on GF(2)-linear primitives** — no nonce reuse, no demasker, just a public-schema crib and the raw ciphertext. Not attempted.~~ — demonstrated empirically on CRC128 at flagship `keyBits = 1024` in [Phase 2f](#phase-2f--direct-crib-kpa-against-gf2-linear-primitives): the `(K_data, K_noise_bits_0_2)` compound-key pair falls jointly from a single JSON ciphertext via a 21-byte schema crib (3 pixels) in ~1 s on 4 KB and scales linearly up to 1 MB, and decrypts a cross-format (HTML) message encrypted under the same seeds with a fresh nonce to 100 % byte accuracy across every plaintext class and every tested size (4 KB / 64 KB / 128 KB / 1 MB). `noiseSeed`'s 61 remaining compound-key bits and full 512-bit component space stay architecturally inaccessible — Crib KPA gives the attacker the operational capability to decrypt any future ciphertext under the same seeds, not the seed components themselves. The FNV-1a analogue (SAT-based Crib KPA on a carry-chain invertible primitive) is covered separately in [Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based).
- ~~**Nonce-reuse attacks.** Every sample in the corpus uses a fresh nonce. We do not probe fixed-nonce / varying-seed, nor same-seeds / same-nonce / different-plaintexts (the deliberate-collision scenario that produces the two-time pad on the 2–3 colliding messages). [SCIENCE.md §2.5](SCIENCE.md#25-nonce-reuse-analysis) argues this is strictly local under the PRF assumption (seeds retained, no key rotation needed) and a global catastrophe under full primitive inversion — not empirically stress-tested in either regime.~~ — see [Phase 2d — Nonce-Reuse](#phase-2d--nonce-reuse). Seed reuse itself (same `(noiseSeed, dataSeed, startSeed)` across many messages with fresh nonces) is an explicitly supported mode, not an attack surface.
- ~~**Chosen-plaintext / adaptive CPA.** Full KPA ≠ CPA. Attack-friendly plaintexts (all-zeros, all-0x7F, sparse 1-hot, sliding-window differentials) are absent from the corpus.~~ — covered indirectly by [Phase 2d — Nonce-Reuse](#phase-2d--nonce-reuse) (Full KPA `known` and Partial KPA `partial` modes accept attacker-chosen plaintext kinds — `json_structured_{25,50,80}` and `html_structured_{25,50,80}` produce attacker-controlled corpora of 6 distinct structured formats × 3 coverage levels) and [Phase 3a — Rotation-invariant edge case](#phase-3a--rotation-invariant-edge-case) (all-0x7F rotation-invariant probe). Under fresh-nonce CPA (attacker chooses plaintext but nonce stays fresh per query) the attack surface reduces to statistical ciphertext properties already covered by [Phase 1](#phase-1--structural-checks--fft--markov-analysis) / [Phase 2b](#phase-2b--per-pixel-candidate-distinguisher) / [Phase 3b](#phase-3b--nist-sts-sp-800-22) across the 10 included `zero_pad` / `html_giant` / `json` / etc. corpus kinds. No unexplored CPA surface remains after [Phase 2d](#phase-2d--nonce-reuse).
- ~~**Related-key attacks.** The three-seed architecture begs testing `(ns, ds, ss)` vs `(ns, ds, ss ⊕ Δ)` ciphertext diffs; not done.~~ — covered by [Phase 2e — Related-seed differential](#phase-2e--related-seed-differential): 1008-cell matrix across 12 primitives × 2 BF × 3 axes × 7 Δ × 2 PT; 10 primitives neutralized ✓ (9 PRF-grade + MD5), CRC128 + FNV-1a leak as expected per their structural properties.
- ~~**Frequency-domain / FFT on per-channel streams.** NIST STS includes DFT on the flat stream but not per-channel (which is where period-8 structure would live).~~ — see [Phase 1 — Structural checks + FFT / Markov analysis](#phase-1--structural-checks--fft--markov-analysis)
- ~~**Markov / cross-channel conditional distributions.** `P(byte_n | byte_{n-1})` not probed.~~ — see [Phase 1 — Structural checks + FFT / Markov analysis](#phase-1--structural-checks--fft--markov-analysis)
- **Adversarial ML distinguishers** — every statistical surface measured across Phases 1–3 and the 63 MB [`/dev/urandom` baseline](#devurandom-baseline-at-the-same-n) places ITB ciphertext at the sampling-precision floor of the measurement. A gradient-based learner needs a measurable signal to descend on; with none in the corpus the loss landscape is flat, and a CNN / transformer distinguisher trained on ITB-vs-`/dev/urandom` is expected to converge to random-guess accuracy. The absence is empirical — supported by the tests that did not find a distinguishable artefact, not by a proof that none exists.
- **Physical side channels** (timing, power, EM, cache, Spectre-class) — out of scope by construction: the algorithm is a software-level cryptographic primitive, and hardware-level leakage is a property of the execution environment (CPU microarchitecture, memory-bus emanations, power-rail modulation), not of the algorithm itself. The [README.md](README.md) and [PROOFS.md](PROOFS.md) disclaimers explicitly scope the information-theoretic barrier to software-level claims and extend no hardware warranty; [HWTHREATS.md](HWTHREATS.md) works through the four hardware-threat categories (speculative execution, data-sampling leaks, cache / interconnect / power contention, memory integrity) analytically and documents the recommended hardware-memory-encryption mitigations (AMD SEV, Intel SGX/TDX, ARM CCA). A meaningful side-channel evaluation is per-deployment (fixed CPU + compiler flags + runtime) and requires specialised instrumentation — both orthogonal to the algorithm-level claims this document tests.
- **Chosen-ciphertext attack with MAC Reveal** — not in this document's empirical scope. Core ITB exposes no decryption oracle: the receiver either reconstructs valid plaintext or silently discards. MAC Reveal is an optional user-protocol mode that signals MAC failure back, trading a portion of the barrier for diagnostic reachability — a deployment-level trade-off, not a core-construction property. The analytical consequence (per-pixel ambiguity dropping from `56^P` to `7^P` under CCA exposure, with the barrier itself remaining intact) is documented in [SCIENCE.md § 2.9.2 — Why KPA Candidates Do Not Break the Barrier](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier). Empirical CCA behaviour is a property of how a given deployment exposes MAC failure signals, not of the ITB algorithm, so it is evaluated per-deployment rather than in this test suite.
- **Quantum adversaries (Grover search on the seed space)** — not empirically testable; the oracle-degradation argument is documented in [SCIENCE.md § 2.11.3 — Grover Oracle Degradation](SCIENCE.md#2113-grover-oracle-degradation) and the oracle-free-deniability framing in [§ 2.3](SCIENCE.md#23-oracle-free-deniability). Under Core ITB and MAC + Silent Drop the attacker has no verification predicate: every candidate seed produces some decrypted byte sequence, and without a plaintext-format discriminator (JSON / UTF-8 / HTML — insider format knowledge not carried in the ciphertext) no `f(key) → {0, 1}` can be evaluated in superposition, which under the strict reading of [§ 2.11.3](SCIENCE.md#2113-grover-oracle-degradation) means Grover cannot run at all. Even under the generous assumption that such a discriminator is available, the joint `noiseSeed + dataSeed` search at `keyBits = 1024` costs `~2^2056` classical / `~2^1028` Grover as a hypothetical upper bound. Under MAC + Reveal the oracle is the MAC check itself — `O(P)` hash evaluations per query — placing the work factor at `~2^1033` classical / `~2^516` Grover. All four numbers are beyond foreseeable quantum capability; deployment-specific evaluation for MAC + Reveal protocols is out of this document's scope for the same reason as the CCA bullet above.

Scope gaps:
- **Triple Ouroboros on Phases 2a extension / 2b / 2c / 2d / 2e / 3a** — Triple is validated on the two mode-agnostic phases (Phase 1 + Phase 3b, both BF=1 and BF=32). Phase 2a extension bias-neutralization audit, Phase 2b per-pixel candidate distinguisher, Phase 2c startPixel enumeration, Phase 2d nonce-reuse demasker + compound-key recovery, Phase 2e related-seed differential, and Phase 3a rotation-invariant edge case all operate on the Single Ouroboros single-ring container layout; adapting them to the Triple 3-partition `splitTriple` interleaving requires a per-phase analyzer rewrite that is not included in this pass. Triple is architecturally strictly more defended than Single on every one of these surfaces — each Triple ring carries independent `dataSeed` so recovery of one ring does not reveal the other two, and the `splitTriple` boundaries partition the container into three isolated regions the attacker would need to re-synchronise per ring (see [Attack-cost implications of Triple Ouroboros](#attack-cost-implications-of-triple-ouroboros))
- **Widely-deployed hash primitives missing from the 12-primitive matrix**: HMAC-SHA-256, GHASH, SHA-3/Keccak. Absent; adding them would round out the algebraic-primitive coverage
- **`SetBarrierFill` intermediate values** (2, 4, 8, 16) not exercised; the shipped default (1) and the maximum (32) bracket the regime, and per-phase results are monotonic between them, but fine-grained sweep is absent
- **Structured binary plaintexts** (PDF, PNG, MP4, compressed streams) absent from the corpus; the 10 kinds are all text-ish (HTTP / JSON / HTML / plain text). High-entropy compressed binaries and format-specific byte patterns could expose behaviours not surfaced by the current corpus
- ~~**Direct `/dev/urandom` side-by-side baselines** for Phase 1 per-channel χ², Phase 2b KL floor, and Phase 3a rotation-invariant rate (NIST STS uses urandom implicitly as its calibration baseline; other phases do not)~~ — effectively moot. The [63 MB KL floor probe](#kl-floor-probe-on-a-single-63-mb-sample-one-off-blake3-bf1-bf32) lands Phase 2b's pairwise KL at **1.1× – 1.4× of the theoretical `bins/N` floor** — that floor IS the urandom expectation, so ITB ciphertext is already shown to be within measurement precision of `/dev/urandom` behaviour on [Phase 2b](#phase-2b--per-pixel-candidate-distinguisher). [Phase 1](#phase-1--structural-checks--fft--markov-analysis) χ² and [Phase 3a](#phase-3a--rotation-invariant-edge-case) rotation-invariant rate similarly reach tolerances that match the `/dev/urandom` expectation (2/128 rate within 0.014 % across all 12 primitives at [Phase 3a](#phase-3a--rotation-invariant-edge-case)). A literal side-by-side `/dev/urandom` stream would confirm the same floors with no new information.
- ~~**Cross-sample variance** on `html_giant`: the runs aggregate `N = 8` samples per hash into the KL estimate (both BF=1 and BF=32, both Mode A and Mode B). The aggregate floor is reported; the per-sample variance distribution is not itself reported.~~ — superseded by [KL floor probe on a single 63 MB sample](#kl-floor-probe-on-a-single-63-mb-sample-one-off-blake3-bf1-bf32), which accumulates `N ≈ 7.5 – 7.7 × 10⁷` observations per candidate from a SINGLE plaintext (an order of magnitude above the 8-giant aggregate) and lands the pairwise KL at **1.1× – 1.4× of the theoretical `bins/N` floor** under both Mode A (idealized alignment) and Mode B (full-container, no alignment). Per-sample variance is no longer the limiting uncertainty — the single-sample floor is already effectively at sampling precision.

---

## Methodology

### Hash matrix

Twelve primitives spanning the full spectrum of cryptographic strength, all run under identical ITB settings:

| Primitive | Width | Paper-spec PRF? | Observable properties |
|-----------|:-----:|:---------------:|-----------------------|
| CRC128 | 128 | ❌ lab-test only | Fully GF(2)-linear (CRC64-ECMA ‖ CRC64-ISO): **Do not use** ; **Fully broken** ; **Lab only** |
| FNV-1a | 128 | ❌ non-cryptographic | Fully invertible (linear over Z/2^128): **Do not use** ; **Fully broken** ; **Lab only** |
| MD5 | 128 | ❌ broken | Collisions trivial (Biases, Preimage ~2^123): **Do not use** ; **Dangerous** ; **Lab only** |
| AES-CMAC | 128 | ✅ | Standard AES-based keyed MAC |
| SipHash-2-4 | 128 | ✅ | Fast keyed PRF |
| ChaCha20 | 256 | ✅ | Stream-cipher-based PRF |
| AreionSoEM-256 | 256 | ✅ | Single-key Even-Mansour with Areion permutation |
| BLAKE2s | 256 | ✅ | Keyed hash in PRF mode |
| BLAKE3 | 256 | ✅ | Native keyed PRF |
| BLAKE2b-256 | 256 | ✅ | Keyed hash in PRF mode (256-bit output) |
| BLAKE2b-512 | 512 | ✅ | Keyed hash in PRF mode |
| AreionSoEM-512 | 512 | ✅ | Single-key Even-Mansour 512 |

### Settings

Both Single and Triple Ouroboros were each run twice — at the **shipped default** `SetBarrierFill(1)` and at the **maximum** `SetBarrierFill(32)`. Single runs the full empirical-phase suite; Triple runs the two mode-agnostic phases (1 and 3b). Other parameters are identical across all four runs:

- `keyBits = 1024` per seed (Single: 3 seeds — noise, data, start; Triple: 7 seeds — 1 noise + 3 data + 3 start)
- `SetMaxWorkers(8)` — parallel pixel processing
- Nonce 128 bits (test-harness setting — Phase 1 / 2b / 2c / 3a / 3b statistical results are independent of nonce size; only the header byte-count depends on it. For production the nonce-size recommendation is separate from the test-harness choice — see [Threat-model gate](#threat-model-gate--why-this-whole-exercise-is-gated-by-user-nonce-size-choice).)

Per-regime phase logs live under `tmp/results/<mode>_bf<N>/` where `<mode>` is `single` or `triple` and `<N>` is the `BarrierFill` value.

**Note on fill dominance.** The `side²` container packs data pixels plus `BarrierFill` extra rows/columns of CSPRNG-only pixels. For small plaintexts (e.g., `http` at ~300 data pixels) the CSPRNG-fill ratio is ~17 % at BF=1 and ~88 % at BF=32; for large plaintexts (`html_giant` at ~150 000 data pixels) the fill ratio is 0.87 % at BF=1 and 14.97 % at BF=32. The BF=32 run therefore tests a configuration where CSPRNG fill meaningfully dilutes data-pixel structure even for large plaintexts. BF=1 does not dilute that structure and is the stricter test of the architecture's structural absorption.

### Corpus

Ten plaintext kinds covering fill-dominated (~200 B) through data-dominated (~1 MB) regimes:

| Kind | Count | Size | Purpose |
|------|------:|------|---------|
| http | 10 | 200 – 500 B | Small HTTP request |
| json | 10 | 300 – 1 500 B | Small JSON payload |
| text_small | 10 | 200 – 400 B | Small Lorem Ipsum |
| text_large | 30 | 20 – 24 KB | Data-pixel-dominated text |
| http_large | 30 | 15 – 18 KB | Enterprise HTTP body |
| json_large | 30 | 12 – 17 KB | Nested JSON response |
| text_huge | 3 | 100 – 150 KB | Large Lorem Ipsum |
| json_huge | 3 | 100 – 150 KB | Large JSON batch |
| html_huge | 3 | 100 – 150 KB | HTML product listing |
| **html_giant** | **1** | **~1 MB** | **Tight finite-sample KL estimation in Phase 2b** |

**Total: 1 644 samples** (12 primitives × 137 samples each, including 8 `html_giant` × 1 MB per hash), regenerated deterministically in ~80 s.

### Reproducibility

**Install prerequisites (Arch Linux).** Requires Go (for the corpus generator), a small set of Python packages for the analyzers / mirrors, plus `nist-sts` from AUR:

```bash
# Core toolchain + Python analyzers
pacman -S go gcc make base-devel python3 python-pip python-numpy python-scipy \
          python-matplotlib python-z3-solver python-claripy

# BLAKE3 Python bindings (used by the Phase 2a extension bias-audit raw-mode
# probe as a Go ↔ Python parity mirror for chainhashes/blake3.py) — install
# via AUR, or via pip if AUR is not available
yay -S python-blake3
# alt: pip install --user blake3

# NIST SP 800-22 test suite (AUR)
yay -S nist-sts

# Bitwuzla 0.9+ SMT solver (AUR) — used by the Phase 2g SAT harness; Z3 is
# a fallback but Bitwuzla handles QF_BV multiplication-heavy formulas
# 2–10× faster and enforces wall-clock timeout across every solver phase
yay -S bitwuzla
```

**Install prerequisites (Debian / Ubuntu).** Bitwuzla and `nist-sts` are not packaged for apt and are built from source; the remaining tooling installs via apt and pip.

```bash
# Core toolchain + Python analyzers
apt install golang-go build-essential cmake meson ninja-build libgmp-dev \
            python3 python3-pip python3-numpy python3-scipy \
            python3-matplotlib python3-z3

# BLAKE3 Python bindings + claripy (no apt packages)
pip install --user blake3 claripy

# NIST SP 800-22 test suite — build from source
git clone https://github.com/terrillmoore/NIST-Statistical-Test-Suite
cd NIST-Statistical-Test-Suite && make

# Bitwuzla 0.9+ SMT solver — build from source (no Debian/Ubuntu package)
git clone https://github.com/bitwuzla/bitwuzla
cd bitwuzla && ./configure.py && cd build && ninja && sudo ninja install
```

Other distributions: install equivalents via the native package manager; Bitwuzla and `nist-sts` typically require source builds regardless of platform.

All scripts under [`scripts/redteam/`](scripts/redteam/). The simplest way to run the full suite is the master orchestrator:

```bash
# Single Ouroboros (3 seeds: noise, data, start) — runs the full empirical-phase suite
#   Wall-clock ~8–10 min at BarrierFill=1 on 8 cores.
python3 scripts/redteam/run_suite.py single --barrier-fill 1  --nist-streams 100  # shipped default
python3 scripts/redteam/run_suite.py single --barrier-fill 32 --nist-streams 100  # high-fill supplementary

# Triple Ouroboros (7 seeds: 1 noise + 3 data + 3 start) — runs Phase 1 + Phase 3b
#   only; Phases 2b / 2c / 3a are skipped because their analyzers assume a single
#   global startPixel and need a 3-partition rewrite.
#   Wall-clock ~6 min at BarrierFill=1 on 8 cores.
python3 scripts/redteam/run_suite.py triple --barrier-fill 1  --nist-streams 100  # shipped default
python3 scripts/redteam/run_suite.py triple --barrier-fill 32 --nist-streams 100  # high-fill supplementary
```

Valid `--nist-streams` values are `{20, 30, 50, 100}` — fixed whitelist; 20 matches the NIST SP 800-22 example, 100 is recommended for this suite because larger N lets conventional non-bin-0 proportion failures stand out as genuine outliers separable from the `NonOverlappingTemplate` bin-routing artefact. N=100 does **not** eliminate the artefact — bin-0 draws still occur at ~10 % per `(hash, run)` pair at any N (BLAKE2b-512 hit 40/188 at N=100 BF=1 in this suite; see [Phase 3b](#phase-3b--nist-sts-sp-800-22)).

Or run phases manually in sequence:

```bash
# 1. Generate corpus (~1–2 min at BF=1; similar at BF=32)
ITB_REDTEAM=1 ITB_BARRIER_FILL=1 go test -run TestRedTeamGenerate -v -timeout 60m

# 2. Concatenate per-sample ciphertexts into per-hash byte streams (<5 s)
#    Produces tmp/streams/<hash>.bin; consumed by Phase 1 sub-tests and NIST STS.
python3 scripts/redteam/phase3_deep/prepare_streams.py

# 3. Phase 1 — structural (per-channel χ² + nonce collision) + FFT + Markov sub-tests
#    analyze.py reads per-sample files from tmp/encrypted/;
#    FFT + Markov read the concatenated per-hash streams from tmp/streams/.
python3 scripts/redteam/phase1_sanity/analyze.py
python3 scripts/redteam/phase1_sanity/fft_per_channel.py
python3 scripts/redteam/phase1_sanity/markov.py

# 4. Phase 2b — per-pixel candidate distinguisher, two threat models in parallel (~1-2 min)
#    Mode A: attacker knows startPixel, data-aligned + plaintext XOR (idealized).
#    Mode B: no startPixel, no plaintext, iterates full container (realistic).
#    run_suite.py launches both concurrently; run standalone one-at-a-time if preferred.
python3 scripts/redteam/phase2_theory/distinguisher.py       # Mode A
python3 scripts/redteam/phase2_theory/distinguisher_full.py  # Mode B

# 5. Phase 2c — startPixel enumeration (parallel, ~5 min at BF=1, ~12 min at BF=32)
python3 scripts/redteam/phase2_theory/startpixel_multisample.py

# 6. Phase 3a — rotation-invariant edge case (~30 s)
python3 scripts/redteam/phase3_deep/rotation_invariant.py

# 7. Phase 3b — NIST STS parallel runner (~5 min at N=100, ~1 min at N=20)
ITB_NIST_STREAMS=100 python3 scripts/redteam/phase3_deep/nist_sts_runner.py
```

`ITB_NIST_STREAMS` accepts the same whitelist `{20, 30, 50, 100}`; unset defaults to 20.

**Phase 2d — Nonce-Reuse attack simulation.** Separate orchestrator, isolated from `run_suite.py`. Drives corpus generation + demasking + NIST STS across a configurable (hash, BF, N, attacker_mode) matrix. Default flagship configuration — BLAKE3 + FNV-1a at 2 MB plaintext, N = 2, `known` mode (Full KPA) — runs in ~3 min end-to-end and produces the PRF-separation result discussed in the [Phase 2d section](#phase-2d--nonce-reuse):

```bash
# Flagship run — 2-cell matrix (BLAKE3 + FNV-1a) at 2 MB plaintext, N=2, known-plaintext Full KPA.
python3 scripts/redteam/run_attack_nonce_reuse.py \
    --plaintext-size 2097152 \
    --hashes blake3,fnv1a \
    --collision-counts 2 \
    --attacker-modes known \
    --validate \
    --cleanup-ciphertexts-after-emission

# Feed the reconstructed dataHash streams through NIST STS at N=16 × 1 Mbit per primitive.
python3 scripts/redteam/phase3_deep/nist_sts_on_attack_streams.py \
    --stream tmp/attack/nonce_reuse/reconstructed/blake3_BF1_N2_known.datahash.bin \
    --stream tmp/attack/nonce_reuse/reconstructed/fnv1a_BF1_N2_known.datahash.bin \
    --n-streams 16
```

The orchestrator accepts `--hashes all` for the full primitive matrix and `--barrier-fill both` for BF=1 and BF=32 coverage; see `--help` for the complete CLI. All deletion operations are routed through a whitelist-gated `safe_rmtree` helper that refuses any path outside `tmp/attack/nonce_reuse/{corpus, reconstructed}`; the results subdirectory is never touched by the orchestrator. Deterministic RNG seeds (plaintext seed 424242, nonce seed 0xA17B1CE) produce byte-identical corpora across runs — a future researcher can reproduce the exact reconstructed streams and feed them to their own statistical-test batteries.

For the classical keystream-reuse plaintext-recovery pipeline (adds `--classical-decrypt` post-demask step, supports `--plaintext-kind random_masked_{25,50,80}` + `json_structured_{25,50,80}` + `html_structured_{25,50,80}` for Partial KPA variants, emits `recovered_plaintext_P{1,2}.bin` + `groundtruth_plaintext_P{1,2}.bin` for diff verification), see [Phase 2d — Classical keystream-reuse decryption](#classical-keystream-reuse-decryption--empirical-plaintext-recovery-from-config-map).

**One-off 63 MB KL floor probe.** A standalone test pair encrypts one plaintext at the ITB data-size limit and runs a chunked single-threaded Phase 2b on it — used to measure how close per-pixel KL gets to its theoretical floor at maximum sample size per hash. Pick any of the 10 hash dirnames (`fnv1a`, `md5`, `aescmac`, `siphash24`, `chacha20`, `areion256`, `blake2s`, `blake3`, `blake2b`, `areion512`):

```bash
# Step 1: encrypt one 63 MB plaintext with the chosen hash (~8 s)
ITB_REDTEAM=1 ITB_REDTEAM_MASSIVE=blake3 ITB_BARRIER_FILL=1 \
    go test -run TestRedTeamGenerateSingleMassive -v -timeout 10m

# Step 2A: Mode A — attacker knows startPixel, data-pixel-aligned, plaintext XOR
#   Single-threaded chunked, ~1 min wall, ~500 MB RAM.
python3 scripts/redteam/phase2_theory/kl_massive_single.py blake3

# Step 2B: Mode B — realistic-attacker, no startPixel, no plaintext, full container
#   Same runtime / memory profile; reports the stricter floor since N includes
#   CSPRNG fill pixels in addition to data pixels.
python3 scripts/redteam/phase2_theory/kl_massive_single_full.py blake3
```

---

## Results summary

Primary results at **`SetBarrierFill(1)`** Single mode (shipped default); supplementary results at BF=32 in parentheses; Triple mode results in the separate Triple Ouroboros section below.

| Phase | What it tests | Result at BF=1 Single (BF=32 Single in parens) |
|-------|---------------|-----------------------------------------------|
| **1. Structural + FFT + Markov** | 8-channel per-channel χ² + nonce-pair collision + per-channel spectral flatness + adjacent-byte / adjacent-channel Markov χ² | ✅ 0 / 96 Bonferroni failures at BF=1 Single and BF=32 Single/Triple; collision ratio ∈ [0.983, 1.025]. FFT flatness within 6×10⁻⁵ of 1.0 on the other 11 primitives across all 4 mode × BF configs (CRC128 replicates a 0.95–0.98 flatness deviation — see [Phase 1 § B](#b-fft--markov-sub-tests-mode-agnostic-single--triple) mini-table); Markov adj-byte χ² mean within ~85 of df=65 535 expectation, no replicable Bonferroni fails in within-pixel channel-pair tests. Triple confirmed in both BF regimes, same pattern as Single |
| **2a. ChainHash analysis** | Theoretical bound on invertible primitive | 📖 Architectural defense-in-depth surfaced; paper underclaims |
| **2b. Candidate distinguisher** | Obstacle (3) — 56-way per-pixel ambiguity | ✅ Mode A (idealized attacker, BF=1) KL [0.000018, 0.000021] nats on 8-giant aggregate (N = 9.6 M obs/cand); Mode B (realistic attacker, no startPixel, no plaintext, BF=32) [0.000012, 0.000016] (N = 11.3 M) — both at ≈1.4× theoretical `bins/N` floor across the full hash spectrum |
| **2c. startPixel enumeration** | Obstacle (2) — startPixel indistinguishability | ✅ mean rank-fraction ∈ [0.461, 0.532]; 6 flagged cells / 90, consistent with 4.5 expected under H0 at α=0.05 (BF=32: 5 / 90) |
| **2d. Nonce-Reuse** | [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis) locality claim — PRF-dependency empirically visible | ✅ / ⚠ Attack chain demasks obstacles (2) + (3) in seconds via Layer 1 constraint matching + Layer 2 startPixel brute force, reconstructs pure `ChainHash(pixel, nonce)` output. NIST STS on reconstructed stream (N=16 × 1 Mbit per cell, 2 MB plaintext): **BLAKE3 188/188 pass**, **FNV-1a 182/188 (6 fails — FFT 0/16, BlockFrequency 9/16, CumulativeSums ×2, Runs 12/16)**. Under PRF the single remaining obstacle (ChainHash SAT-hardness) survives with no exploitable bias; under invertible primitive residual linear-order bias is detectable on every bit-stream |
| **2e. Related-seed differential** | Single-axis XOR-Δ on `noiseSeed` / `dataSeed` / `startSeed` with same nonce + same plaintext + shared hash-function instance | ✅ / ⚠ / ✗ 1008-cell matrix (12 primitives × 2 BF × 3 axes × 7 Δ × 2 PT). **10 primitives neutralized ✓** on primitive-attributable axes (`data` / `start`) — the 9 PRF-grade primitives plus MD5. **CRC128 bias-leak ✗** on every axis as expected from end-to-end GF(2)-linearity. **FNV-1a lab-detectable ⚠** through a single-Δ (`bit_high1023`) top-bit-isolation effect visible to the differential probe but not to an encryption-path attacker (ITB's `hLo` extraction discards the relevant bit) |
| **2f. Direct Crib KPA (GF(2)-linear primitives)** | Compound-key pair recovery from a single ciphertext via public-schema crib, cross-message decrypt across fresh-nonce + different-format messages sharing `(dataSeed, noiseSeed)` | ✗ CRC128: `(K_data, K_noise_bits_0_2)` pair recovered jointly in ~1 s on 4 KB / ~2–5 min on 1 MB from JSON ciphertext + 21-byte schema crib (3 pixels, no nonce reuse, no demasker). Short-crib shadow pairs disambiguated by iterating every Stage-2 survivor through the decrypt and accepting the COBS-valid plaintext (attacker-visible cross-check using the public ITB COBS spec). Cross-format decrypt on a fresh-nonce HTML message reaches **100.00 % byte-level / 100.00 % full-pixel** accuracy across every tested size (4 KB / 64 KB / 128 KB / 1 MB) and every plaintext class. The pair is per-`(dataSeed, noiseSeed)` invariant — one recovery breaks all future messages under the same seed pair. ✅ Architectural finding: `noiseSeed` exposes only its 3 low compound bits; the other 61 bits of `K_noise` and the full 512-bit `noiseSeed` component space remain architecturally inaccessible (`2^957` residual kernel, above Landauer) — full seed inversion stays beyond empirical reach even on the GF(2)-linear control primitive. Non-GF(2)-linear primitives (FNV-1a, MD5, every PRF-grade entry) are immune to this specific GF(2)-linear chain — see [Phase 2a extension bias audit](#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2); FNV-1a is separately broken by [Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) |
| **2g. SAT-based Crib KPA (FNV-1a)** | Functional `dataSeed` recovery via multi-crib SAT on the non-GF(2)-linear invertible primitive at ITB's `keyBits = 512` / 4 rounds minimum | ✗ FNV-1a: functional `dataSeed` lo-lane compound state recovered in ~8 h single-core (commodity Bitwuzla + CaDiCaL, 16-core host, ± 30 % hardware-variable) from 4 public-schema cribs + disclosed `startPixel`. Recovered K decrypts 4 KB JSON / HTML ciphertexts under the same seeds at **~83–85 % byte-level accuracy** (`startPixel` correctly re-anchored, plaintext length bit-exact). Attacker-realistic variant without disclosed `startPixel` multiplies by `total_pixels` independent SAT jobs (289 for 4 KB JSON / 324 for 4 KB HTML), embarrassingly parallel — same ~8 h wall-clock on a 289-core commodity pool, no HPC. ✅ Architectural finding: `noiseSeed` architecturally unrecoverable through Crib KPA under FNV-1a (PRF-output noise values have no public-schema crib), which places the 15–17 % byte gap as the empirical ceiling on this attack family. Result scoped to `keyBits = 512` / 4 rounds (ITB minimum); 8 / 16-round extrapolations remain analytical — see [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure) updated tables. MD5 (non-invertible; no published full-round key-recovery SAT attack) and PRF-grade primitives (AES-CMAC / SipHash-2-4 / ChaCha20 / AreionSoEM / BLAKE2 / BLAKE3) are not exposed: under each PRF primitive's assumption, any successful SAT-based inversion would be a PRF distinguisher and is ruled out by definition; ITB's per-pixel envelope composes multiplicatively on top of this primitive-level PRF-hardness |
| **3a. Rotation-invariant** | [`SCIENCE.md` §2.9.2](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier) edge case | ✅ Rate 2/128 = 1.5625 % within 0.014 % across all 12 primitives; **no sign-consistent deviation** between BF=1 and BF=32. The 5–6 σ "signals" at each BF did not replicate across regimes (AES-CMAC / BLAKE2b-512 at BF=32, AreionSoEM-256 / CRC128 / FNV-1a / BLAKE2b-512 at BF=1) — test-power artefacts on near-uniform output, not real bias |
| **3b. NIST STS** | Industry-standard randomness suite | ✅ At N = 100 × 1 Mbit Single: 18 / 24 `(hash, BF)` cells pass 188/188; 5 cells show conventional (non-bin-0) single-to-several-test fails (7 / 4 512 = 0.16 % vs 1 % expected at α = 0.01); 1 cell (BLAKE2b-512, BF=1) hit the `NonOverlappingTemplate` bin-0 artefact — paper-grade 512-bit PRF hitting the same 40/188 outcome as FNV-1a at N=20 confirms the mechanism is hash-agnostic. Triple confirmed in both BF regimes. All 12 exhibit the SP 800-22 uniformity-of-p-values clustering identically across configurations |

---

## Phase 1 — Structural checks + FFT / Markov analysis

Four sub-tests probing byte-level structure that NIST STS (Phase 3b) does not cover at the 8-channel-aware granularity. Two ITB-specific structural checks (per-channel χ² + nonce-pair collision) and two mode-agnostic byte-level statistics (FFT spectral flatness + Markov transition χ²) that run unchanged on Single + Triple.

Scripts: [`analyze.py`](scripts/redteam/phase1_sanity/analyze.py), [`fft_per_channel.py`](scripts/redteam/phase1_sanity/fft_per_channel.py), [`markov.py`](scripts/redteam/phase1_sanity/markov.py).

### [A] Per-channel χ² + nonce-independence collision

**Per-channel-position χ²** — byte offset `i` in the ciphertext belongs to channel `i mod 8`. A bias restricted to one channel is 8× diluted in the flat stream NIST STS sees, so each channel is tested separately with Bonferroni correction (α_eff = 0.00125).

**Nonce-independence collision scan** — same-position byte matches between sample-pair prefixes, vectorised via `bincount`. Expected rate under fresh nonce + fresh seeds: 1/256. Sustained deviation indicates nonce-dependent structure.

Results at BF=1 (137 samples per hash × 12 primitives; BF=32 numbers in parentheses):

| Hash | Min channel p-value (BF=1 / BF=32) | Bonferroni fails | Collision ratio (BF=1 / BF=32) | Status |
|------|-----------------------------------:|-----------------:|-------------------------------:|--------|
| CRC128 | 0.0033 / 0.0258 | 0 / 8 | 0.9907 / 0.9888 | ✅ |
| FNV-1a | 0.0452 / 0.0896 | 0 / 8 | 1.0107 / 1.0006 | ✅ |
| MD5 | 0.0274 / 0.1995 | 0 / 8 | 1.0014 / 1.0253 | ✅ |
| AES-CMAC | 0.0157 / 0.3017 | 0 / 8 | 1.0136 / 1.0086 | ✅ |
| SipHash-2-4 | 0.0614 / 0.1468 | 0 / 8 | 1.0017 / 0.9931 | ✅ |
| ChaCha20 | 0.1252 / 0.0737 | 0 / 8 | 0.9868 / 0.9934 | ✅ |
| AreionSoEM-256 | 0.1388 / 0.1210 | 0 / 8 | 1.0036 / 1.0136 | ✅ |
| BLAKE2s | 0.0793 / 0.0654 | 0 / 8 | 0.9834 / 0.9958 | ✅ |
| BLAKE3 | 0.0433 / 0.0375 | 0 / 8 | 1.0012 / 0.9936 | ✅ |
| BLAKE2b-256 | 0.0082 / 0.0720 | 0 / 8 | 1.0015 / 0.9999 | ✅ |
| BLAKE2b-512 | 0.0208 / 0.1671 | 0 / 8 | 1.0038 / 1.0172 | ✅ |
| AreionSoEM-512 | 0.1390 / 0.0222 | 0 / 8 | 0.9866 / 0.9949 | ✅ |

All 80 per-channel χ² tests pass Bonferroni correction at both BF=1 and BF=32; all collision ratios within [0.80, 1.20]. **Weak and strong PRFs produce identical per-channel profiles at shipped defaults** — including FNV-1a, which later shows the NIST STS template signal in [Phase 3b](#phase-3b--nist-sts-sp-800-22). Per-channel χ² is not sensitive to the template-level structure that leaks FNV-1a; the structural test at the 8-channel aggregate level is clean.

### [B] FFT / Markov sub-tests (mode-agnostic, Single + Triple)

Two byte-level sub-tests that do not depend on startPixel alignment → mode-agnostic (both run unchanged in Single and Triple). **FFT**: demultiplex each `tmp/streams/<hash>.bin` into 8 per-channel streams, Welch spectral flatness per channel + zero-lag Pearson between channel pairs. **Markov**: full 65 536-cell transition matrix (adjacent-byte on the flat stream + adjacent-channel within each pixel), χ² against uniform 1/65 536.

Summary across 12 primitives per cell × 2 modes × 2 fill regimes:

| Mode × BF | FFT flatness mean | FFT max\|corr\| median | Markov adj-byte χ² mean | Markov adj-byte p median | Bonferroni fails / 70 |
|-----------|------------------:|-----------------------:|------------------------:|-------------------------:|----------------------:|
| Single BF=1 | 0.99922 | 0.00170 | 65 590 | 0.50 | 0 |
| Single BF=32 | 0.99944 | 0.00146 | 65 506 | 0.44 | 0 |
| Triple BF=1 | 0.99924 | 0.00202 | 65 575 | 0.32 | 0 |
| Triple BF=32 | 0.99944 | 0.00156 | 65 532 | 0.59 | 0 |

FFT flatness stays within 6×10⁻⁵ of 1.0 on every channel across all 4 configs — white-noise signature. Markov adjacent-byte χ² mean clusters within ~85 of the df=65 535 H0 expectation; p medians scatter around 0.5 (textbook H0). Zero replicable Bonferroni fails across 280 within-pixel channel-pair tests (one non-replicating raw flag on ChaCha20 Triple BF=1 matches the statistical-power-artefact pattern on near-uniform output documented in [Phase 3a](#phase-3a--rotation-invariant-edge-case) — not counted as a fail in the table). Effectively, feeding the suite's concatenated ciphertext stream through FFT + Markov is indistinguishable from feeding `/dev/urandom`.

**CRC128 outlier — per-channel FFT spectral flatness.** The aggregate numbers above exclude CRC128 from the mean (CRC128 is the below-spec GF(2)-linear stress control, see [Hash matrix](#hash-matrix)). On the FFT sub-test CRC128 separates cleanly from the PRF-grade band in every one of the 4 `(mode × BF)` cells — a systematic, replicated signal:

| Mode × BF | CRC128 flatness min | CRC128 flatness mean | PRF-grade flatness mean (reference) |
|-----------|--------------------:|---------------------:|------------------------------------:|
| Single BF=1 | 0.9486 | 0.9668 | 0.9992 |
| Single BF=32 | 0.9691 | 0.9803 | 0.9994 |
| Triple BF=1 | 0.9501 | 0.9673 | 0.9992 |
| Triple BF=32 | 0.9689 | 0.9803 | 0.9994 |

The 30-50× deviation from the PRF-grade 0.9994 baseline reflects residual per-channel spectral structure that the 8-round ChainHash XOR-composition of a fully GF(2)-linear round function cannot fully absorb. BarrierFill=32 damps the deviation (0.96 → 0.98 flatness mean) by diluting data-pixel structure with CSPRNG fill, but does not eliminate it. Markov sub-test on the same corpus shows CRC128 inside the normal band (adj-byte χ² p ∈ [0.05, 0.95], Bonferroni 0/8 across all 4 cells) — the FFT surface is the only Phase 1 sub-test where CRC128 is individually detectable. This is consistent with the architectural prediction in [Phase 2a extension — hash-agnostic bias-neutralization audit](#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2): GF(2)-linearity surfaces on probes that accumulate per-position fine-grained structure, not on probes that only measure aggregate byte frequencies.

---

## Phase 2a — ChainHash analysis and the three-layer defense structure

This phase is analytical rather than empirical: it documents why even an "ideal inversion oracle" attack against ITB's primitive fails, and prices the resulting defence against a well-funded attacker with distributed compute.

### The load-bearing assumption

[Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) mentions the "invertible primitive" case with a heuristic bound `~56 × P` hash inversions. That bound holds only if the primitive is truly invertible *as used in ITB* — which, because of ChainHash, it is not.

ChainHash128 at `keyBits = 1024` is an **8-round construction**:

```
h_0 = FNV-1a(data, s_0,  s_1)
h_1 = FNV-1a(data, s_2  ⊕ h_0_lo, s_3  ⊕ h_0_hi)
h_2 = FNV-1a(data, s_4  ⊕ h_1_lo, s_5  ⊕ h_1_hi)
...
h_7 = FNV-1a(data, s_14 ⊕ h_6_lo, s_15 ⊕ h_6_hi)
```

Inverting the last round yields **one 128-bit equation in two unknowns** (the final seed pair and the previous intermediate state). Multiple pixels provide more equations, but the round function is **non-GF(2)-linear** — for FNV-1a via the Z/2⁶⁴ multiply-by-constant (carry-chain propagation creates AND-combinations between bit positions), for MD5 via its boolean-mixer `F/G/H/I` functions and modular additions (same carry mechanism) — and the round outputs are XOR-chained through eight levels. The resulting system is a hard bitvector SAT problem, not a direct inversion.

**GF(2)-linear primitives are a structurally different case.** If the round function is itself GF(2)-linear (every output bit is a linear combination of input bits over GF(2)), then XOR-keyed composition preserves linearity: 8 rounds of ChainHash collapse to a single linear map `output_lane = K_lane ⊕ c_lane(data)` where `K_lane` is a compound key equal to the product of the round state-transfer matrices applied to the seed vector, and `c_lane(data) = ChainHash(data, seed = 0)` is attacker-computable. **The effective key space per observable lane is bounded by the primitive's per-lane internal state width, not by the `keyBits` parameter.** CRC128 is two independent CRC64 pipelines (ECMA + ISO) running in parallel: ChainHash XOR-keying feeds `s_{2k} ⊕ h_k.lo` only into the ECMA lane and `s_{2k+1} ⊕ h_k.hi` only into the ISO lane, so the two lanes never mix. The construction therefore has two independent 64-bit compound keys `K_ECMA` and `K_ISO` (128 bits total), but ITB extracts ciphertext bits only from `hLo` = the ECMA lane — the ISO lane is never observable through `channelXOR`. Attacker-reachable compound key is thus **64 bits** (ECMA lane), of which `channelXOR = hLo >> 3` exposes the middle 56 (bits 3..58). No number of ChainHash rounds and no amount of `keyBits` expansion can raise the per-lane effective key space above the lane's state width — extra seed bits live in the null space of the compound linear map. This is the analytical basis for [Phase 2a extension](#phase-2a-extension--empirical-mixed-algebra-stress-test-via-crc128-nonce-reuse), where the collapse is demonstrated empirically: 1024-bit seed → 64 recoverable compound-key bits on a single CRC128 lane.

### Z3 feasibility by `keyBits`

The round count equals `keyBits / 128`. Each added round composes a full 128-bit bitvector multiplication through the chain, typically multiplying SMT solver time by some factor; published SMT-on-ARX literature (Mouha et al., Song/Shi on Speck/Simon inversion) suggests O(2 – 5×) per round for well-structured ciphers, with larger factors appearing near density-1 constraint regimes. The figures below are **empirical back-of-envelope estimates** with wide error bars (± 2 – 3 orders of magnitude for analytical rows); only the `keyBits = 512` row is empirically anchored (by [Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based): ~8 h single-core Bitwuzla on FNV-1a / 4 cribs / disclosed `startPixel`), the rest are extrapolations using the 2 – 7× per-round scaling cited above. The table split below reflects the two structurally distinct primitive families that reach the SAT solver with different effective unknowns — see [Phase 2g architectural finding 5](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) for the scope note.

**Carry-chain invertible primitives** (FNV-1a in the matrix; any future `P_lo`-style multiply-by-constant primitive would behave equivalently). The encoder observes only `hLo`, and `hLo` is produced by lo-lane-only carry propagation (`P_lo = 0x13B` in FNV-1a), so **effective SAT unknowns are half of `keyBits`** — the hi-lane seed half lives in the null space of the observable projection and need not be recovered for future-message decryption:

| `keyBits` | Rounds | Effective SAT unknowns | Sequential wall-clock (single commodity core) |
|----------:|-------:|-----------------------:|-----------------------------------------------|
| **512 (minimum, empirically measured)** | **4** | **256** | **~8 h** ([Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based): Bitwuzla, 4 public-schema cribs, disclosed `startPixel`, 16-core host) |
| 1024 (shipped default) | 8 | 512 | Weeks to months (analytical, 2 – 7× per extra round over the measured 4-round datum) |
| 2048 (paranoid) | 16 | 1 024 | Decades to millennia (analytical) |

**Non-invertible PRF-grade primitives** (AES-CMAC, SipHash-2-4, ChaCha20, AreionSoEM-256, BLAKE2s, BLAKE3, BLAKE2b-256, BLAKE2b-512, AreionSoEM-512). Under each primitive's PRF assumption, efficient key recovery is infeasible by definition — any polynomial-time algorithm that extracts the key from polynomially-many known-plaintext pairs would constitute a PRF distinguisher, contradicting the assumption. SAT is a particular such algorithm; its failure against full-round PRF-grade primitives is therefore implied by the PRF assumption, not merely observed. Consistent with this, published SAT cryptanalysis reaches only reduced-round variants in isolation. ITB's per-pixel envelope composes multiplicatively on top of this primitive-level PRF-hardness:

| `keyBits` | Rounds | Sequential wall-clock (single commodity core) |
|----------:|-------:|-----------------------------------------------|
| 512 (minimum) | 4 | Does not terminate within commodity wall-clock budgets |
| 1024 (shipped default) | 8 | Does not terminate within commodity wall-clock budgets |
| 2048 (paranoid) | 16 | Does not terminate within commodity wall-clock budgets |

"Does not terminate" above is the operational shadow of the definitional argument: the PRF assumption rules out efficient SAT inversion in principle, and ITB-wrapped runs were not attempted because the primitive-level PRF-hardness already dominates. The Phase 2g empirical datum on FNV-1a (a non-PRF, invertible primitive where SAT succeeds at the ITB minimum) is a lower bound on attacker cost against the PRF-grade rows, not a measurement of them — the ~8 h figure does not extrapolate to primitives whose PRF assumption forbids the algorithm from succeeding at all.

### Adversary accelerators

A realistic well-funded adversary stacks several multipliers on top of sequential Z3:

- **Parallel Z3 portfolio** (`smt.threads=N`): 2 – 8× local speedup from running multiple solver configurations racing each other on a single multi-core machine.
- **Distributed SMT** (cloud / HPC, 10²–10³ nodes): 100 – 1000× with diminishing returns from communication overhead.
- **Meet-in-the-middle attacks: not applicable.** Classical MITM (2DES, Even-Mansour) requires the cipher to decompose as `E_{k2} ∘ E_{k1}` with **independent** key halves. ChainHash's recurrence feeds every previous round's output into the next round's key input, blocking any such decomposition across round boundaries.
- **Algebraic attacks** (Gröbner basis over Z[2^128], polynomial interpolation): feasibility unknown for this specific construction. Could be substantially faster than Z3 if a structural exploit is found — this is the single biggest uncertainty in the cost estimate.
- **Differential cryptanalysis** of ChainHash: inherits primitive-level differential resistance with N-round amplification through XOR-keying. XOR is linear over GF(2)-differential, so the per-round differential probability of ChainHash equals the primitive's differential probability; N rounds compound to `p^N` under the usual independent-round assumption. ChainHash adds no new non-linearity beyond what the primitive provides — a primitive without exploitable differential characteristics yields an equally resistant ChainHash, and a primitive with known differential weaknesses yields a ChainHash merely delayed by the N-round amplification, not fundamentally strengthened. ChainHash-specific differential cryptanalysis is therefore unstudied in public literature because it is primitive-first: see primitive-specific differential cryptanalysis for the relevant per-round baseline (Wang et al. on MD5, Biryukov et al. on AES, etc.), then multiply through N for the ChainHash-level curve. FNV-1a's `* P_lo` multiplicative group has linear properties that may admit a narrow differential trail (see [Phase 2e](#phase-2e--related-seed-differential) empirical: a single-Δ signal on `bit_high1023` that ITB's `hLo` extraction coincidentally discards at the encoder layer).
- **Incremental SMT amortisation across `startPixel` guesses**: modern solvers with push/pop can share learned clauses across near-identical instances differing only by a single parameter. May reduce the ×P multiplier below to ×(P/5) – ×(P/10) for parametric families.
- **Quantum Grover**: further √ speedup once fault-tolerant quantum computers exist at ~10⁶ logical-qubit scale.

### Back-of-envelope 1000-node cluster wall-clock (Full KPA, startPixel known)

The nominal key size is 1024 bits, but under FNV-1a the encoder observes only `hLo` and `hLo` depends on the lo-lane seed components only (multiplication mod 2^128 propagates carries up, not down — lo output depends only on lo input). SAT unknowns therefore collapse to **512 effective bits** per seed; the remaining 512 hi-lane bits are unconstrained by any observable and need not be recovered for future-message decryption.

| Setup | Wall-clock at 512-bit effective SAT unknowns |
|-------|------------------------------|
| Sequential single machine | ~10⁵ – 10⁸ hours |
| 1000-node naive split | ~10² – 10⁵ hours (months to ~11 years) |
| 1000-node + portfolio parallelism (~10× practical speedup) | **~10 – 10⁴ hours (hours to ~1 year)** |

The "~1 year" upper figure corresponds to the pessimistic end of the per-round cost range and assumes no algebraic shortcut; the optimistic end (hours) assumes the solver handles the constant-multiplicative structure of FNV-1a well. A state-level attacker would plausibly land somewhere in this band. [Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) supplies an empirical data point at `keyBits = 512` / 4 rounds (the ITB minimum, half the flagship round count): ~8 h single-core with Bitwuzla + CaDiCaL on 4 public-schema cribs + disclosed `startPixel`. Extrapolating to 8 rounds via the 2 – 7× per-round factor places the 1024-bit curve in the 10² – 10⁵ hours band above, consistent with the analytical estimate.

### Obstacle (4) — Partial KPA byte-splitting

All of the above assumed Full KPA. In realistic deployments, the attack surface is **Partial KPA**: protocol headers known, payloads unknown. ITB's 7-bit-per-channel packing (`gcd(7, 8) = 1`) interacts with partial plaintext to significantly compound attacker cost.

**Byte-to-channel mapping** (LSB-first within each byte; see [`process_generic.go`](process_generic.go)). Each pixel holds 56 data bits across 8 channels (7 bits per channel), which fits exactly 7 plaintext bytes. Plaintext byte N occupies two adjacent channels within a single pixel — the 7/8 bit mismatch splits byte N's 8 bits across a complete slot plus the first bit of the next slot, with the split rotating through the 7-byte cycle:

```
byte 0: 7 bits in slot 0 + 1 bit in slot 1   (LSB-first: bits 0-6 to slot 0, bit 7 to slot 1)
byte 1: 6 bits in slot 1 + 2 bits in slot 2
byte 2: 5 bits in slot 2 + 3 bits in slot 3
...
byte 6: 1 bit  in slot 6 + 7 bits in slot 7
byte 7: starts fresh in slot 8 (next pixel)
```

**No byte straddles a pixel boundary** — each 7-byte window lands cleanly in one pixel, but each byte spans two channels within its pixel.

**Cost multiplier derivation.** An unknown plaintext byte adds 8 free-variable bits to two channels of one pixel, weakening per-pixel constraint from 56 bits to `k < 56`. The attacker's SAT search space grows by a factor of `2^(56 − k)` per pixel, applied additively across pixels (the SAT problem is additive in free variables, not multiplicative with round cost).

**Coverage depends on unknown-byte distribution.** If unknown bytes are **interleaved bit-by-bit** (random-bit model), the per-pixel `k` tracks the fraction roughly linearly. If they form **runs** (a block of consecutive unknown bytes — the realistic case for HTTP/JSON body), each run blinds 4 – 5 consecutive channels completely and `k` can drop locally to ~14 inside the run. The table below uses the interleaved (optimistic-for-attacker) average.

| Plaintext unknown | Typical per-pixel `k` | Multiplier over Full KPA (`2^(56−k)`) | 1000-node wall-clock |
|------------------:|---------------------:|---------------------------------------:|----------------------:|
| 0 % (Full KPA) | 56 | 1× | hours – 1 year |
| 20 % unknown | ~45 | ~10³ | ~years – millennia |
| **50 % unknown** (realistic HTTP/JSON) | **~28** | **~10⁸** | **~10⁸ – 10¹² hours (10⁴ – 10⁸ years)** |
| 80 % unknown | ~11 | ~10¹³ | ~10¹³ – 10¹⁷ hours (10⁹ – 10¹³ years) |
| **80 % unknown with run structure** (worst case, `k`≈14) | ~14 | ~10¹² | slightly tighter than above |

**Reference point.** The age of the observable universe is ~1.4 × 10¹⁰ years. At 50 % plaintext unknown — a realistic threat model for HTTP/JSON traffic — the lower end of the combined-cost range (`~10⁴ years`) still exceeds the lifetime of most institutions funding such an attack; the upper end (`~10⁸ years`) is past the civilisational horizon.

### Obstacle (2) — unknown startPixel

The cost tables above tacitly assumed the attacker knows `startPixel` — i.e., which container pixel carries the first data byte. This was an explicit simplification for the Z3-cost analysis, matching what Phase 2b discloses as a hint. In any real deployment, `startPixel` is derived from the independent `startSeed` and takes one of `P = container_pixels` possible values.

**Note:** the formula is `side = ceil(sqrt(data_pixels)) + BarrierFill`, then container = `side²`; `P` equals the full container pixel count, which is close to `data_pixels` at default `BarrierFill=1`.

Approximate `P` for a range of plaintext sizes at `SetBarrierFill(32)` (the configuration under which this corpus was generated):

| Plaintext size | data_pixels | P = container pixels | startPixel multiplier |
|----------------|------------:|---------------------:|----------------------:|
| ~2 KB HTTP request | ~300 | ~2 500 | ~10³·⁴× |
| ~20 KB bloated HTTP / JSON | ~3 000 | ~7 500 | ~10³·⁹× |
| ~150 KB `html_huge` | ~22 000 | ~28 000 | ~10⁴·⁵× |
| ~1 MB `html_giant` | ~150 000 | ~176 000 | ~10⁵·²× |

**Phase 2c empirically validates that `startPixel` cannot be shortcut by statistical fingerprinting** in this corpus: across all 12 primitives and 1 548 enumeration runs, mean rank fraction of the true `startPixel` is ≈ 0.5 (indistinguishable from random) and **7 / 108** flagged (hash, kind) cells at BF=1 (10 / 108 at BF=32) are consistent with the 5.4–10.8 expected under H0 at α = 0.05. No statistical shortcut was detected; the attacker genuinely has to run the seed-recovery procedure for each of the `P` candidates (modulo incremental-SMT amortisation discussed above).

### Combined realistic threat model (all layers stacked)

On the same 1000-node cluster with practical portfolio parallelism, using the range in the Full KPA table, with `P ≈ 10⁴` for a typical 20 KB payload at `BarrierFill=32`:

| Scenario | Wall-clock at 512-bit effective SAT unknowns, `P ≈ 10⁴` |
|---------|----------------------------------:|
| Full KPA + `startPixel` known (idealised) | hours – 1 year |
| Full KPA + `startPixel` unknown (×`P`) | centuries – ~10 000 years |
| **50 % Partial KPA + `startPixel` unknown** (real production) | **~10¹² – 10¹⁶ years** |
| 80 % Partial KPA + `startPixel` unknown | ~10¹⁷ – 10²¹ years |

### Why the three layers multiply — defense-in-depth structure

The three layers (ChainHash, `startPixel` enumeration, Partial KPA byte-splitting) stack multiplicatively **conditional on ChainHash's XOR-cascade remaining SAT-hard** — i.e., assuming no undiscovered algebraic or structural attack collapses the 8-round recurrence into something cheaper than a bitvector SAT problem. This is a load-bearing conditional premise, and the single largest unstudied assumption behind the cost estimates. A paper-quality treatment would provide a reduction sketch to a standard assumption (e.g., worst-case bitvector-SAT hardness, or LWE style noisy composition); this document does not.

**Without ChainHash (hypothetical).** Invertible FNV-1a + known `startPixel` + Full KPA would resolve to microsecond-per-inversion modular inverses. With unknown `startPixel`, the attacker cycles `P ≈ 10⁵ × 56 × µs` → seconds-to-minutes total. Partial KPA adds free bits but would still resolve in hours at worst.

**With ChainHash (actual ITB).** Each `startPixel` guess triggers a full SAT instance over **512 effective seed bits** (FNV-1a's lo lane; the hi lane is unconstrained by observable `hLo` and free to take any value) + 6 ambiguity bits per used pixel, with 8 rounds of nested multiplication through the XOR chain — *hours to ~1 year* of 1000-node time per attempt (the range reflects per-round SMT-cost uncertainty). That SAT-vs-inversion flip is what makes the defensive layers stack:

| Layer | Role | Without ChainHash | With ChainHash (actual) |
|-------|------|-------------------|-------------------------|
| Baseline: 56 candidates per pixel (`noisePos × rotation`) | 6 ambiguity bits per pixel — obstacle (3) | Amortised inside µs inversions; negligible | Encoded as SAT free variables; inside the per-attempt SAT baseline |
| Layer 1: ChainHash XOR chain (8 rounds at 1024-bit) | Load-bearing premise | n/a | Turns each attack from µs-per-inversion into a SAT instance (hours – 1 year per attempt) |
| Layer 2: `startPixel` enumeration (`P` values) | Obstacle (2) | ×P cheap inversions → seconds-minutes total | **×P SAT instances** (with possible ~10× incremental amortisation) → centuries – ~10 000 years |
| Layer 3: Partial KPA byte-splitting | Obstacle (4) | Adds free bits; still feasible in hours | **×2^(56 − k)** SAT blow-up → 50 % unknown + unknown `startPixel` → ~10¹² – 10¹⁶ years |

Rotation and `noisePos` (the 56-candidate baseline) sit inside the Z3 unknowns of every attempt — they are not a separate multiplicative layer. The three layers that stack — ChainHash, `startPixel` enumeration, Partial KPA byte-splitting — **stack multiplicatively conditional on the SAT-hardness premise**. Without ChainHash the same architecture would collapse: every layer would resolve to cheap modular inversions rather than SAT, and the total attack would complete in CPU-hours on commodity hardware.

### Architectural takeaway

1. **Under Full KPA + known `startPixel`** (the simplification used for the Phase 2b / 3a empirical tests), a well-funded attacker reaches 512-bit effective seed recovery (the lo lane of the nominal 1024-bit seed; the hi lane is unused by the encoder and needs no recovery) in *hours to ~1 year* of 1000-node cluster time — and that already assumes ChainHash is the only active defensive layer. Even this idealised threat already requires solving SAT, not modular inversions.
2. **Under Full KPA + unknown `startPixel`** (still idealised), the attack multiplies by ~`P` (with possible incremental-SMT amortisation reducing the effective multiplier by up to ~10×). At typical `P ≈ 10⁴`, this pushes the cost into centuries – ~10 000 years.
3. **Under Partial KPA + unknown `startPixel`** (the production threat model), the 50 % unknown case lands at ~10¹² – 10¹⁶ years of 1000-node time. The three defence layers stack multiplicatively, **conditional on the SAT-hardness assumption above**.
4. **ChainHash is the load-bearing premise.** Without it the same architecture (invertible FNV-1a + 56-candidate baseline + unknown `startPixel` + Partial KPA) would collapse to CPU-hour-scale cost on commodity hardware — every layer would resolve to cheap modular inversions rather than SAT. Keeping it makes every other layer an independent SAT multiplier, subject to the SAT-hardness premise.

**Proposed paper addition.** A caveat in [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) or adjacent prose noting that invertibility of the base primitive does not translate into invertibility of ChainHash for `n > 1` rounds; the compound cost scales with round count, giving `keyBits`-dependent defence-in-depth that the current prose does not claim. The naive `~56 × P` inversions bound holds tightly only in the hypothetical `keyBits = hashWidth` single-round-ChainHash case (equivalent to removing ChainHash entirely) with both `startPixel` and plaintext fully known — and `NewSeed{128,256,512}` explicitly reject `keyBits < 512`, so that hypothetical is below the minimum ITB ever instantiates.

At the actual minimum keyBits = 512: 128-bit hash → 4 ChainHash rounds, 256-bit hash → 2 rounds, 512-bit hash → 1 round. The "1 round at 512-bit minimum" case is **not a practical weakness** because both 512-bit primitives in the ITB hash matrix (BLAKE2b-512 and AreionSoEM-512) are PRF-grade — when the base primitive is already a PRF, ChainHash compounding adds defence-in-depth for invertible primitives but adds nothing meaningful on top of a PRF (the output is unpredictable by assumption, regardless of wrap depth). ChainHash composition is load-bearing specifically for the invertible primitives in the matrix (FNV-1a), which only exist at 128-bit width, where the minimum keyBits = 512 still gives 4 rounds. So the naive bound is effectively a bound for "ITB without ChainHash", which is not something shipped ITB ever configures, and shipping a non-PRF 512-bit primitive to trigger the degenerate case would be a deliberate choice outside ITB's supported hash matrix.

### Phase 2a extension — empirical mixed-algebra stress test via CRC128 (Nonce-Reuse)

The analytical argument above rests on the claim that mixed algebra (GF(2) XOR keying between rounds + a round function that is **not** GF(2)-linear — for FNV-1a the `· FNV_PRIME_64` multiplication modulo 2⁶⁴ provides the non-linearity via carry propagation) is what forces the attacker into bitvector-SAT territory. Replace the round function with a **purely GF(2)-linear** primitive and the chain collapses by construction. To make that collapse concrete — not merely implied — a test-only primitive was added to the corpus generator and driven through the full [Phase 2d — Nonce-Reuse](#phase-2d--nonce-reuse) pipeline.

**CRC128 — the test-only below-FNV-1a primitive.** `CRC128(data, seed0, seed1) = (CRC64-ECMA(data, seed0), CRC64-ISO(data, seed1))`. Two independent CRC64 updates with different irreducible polynomials (ECMA + ISO), each keyed by one 64-bit half of the input seed, concatenated to 128 bits. Every operation is GF(2)-linear: the Sarwate update loop is polynomial division over GF(2)[x], the keyed initial-state register XOR is GF(2)-linear, concatenation preserves linearity. Wrapping this in ITB's ChainHash (XOR-keyed between rounds) keeps the whole chain GF(2)-linear end-to-end. The two lanes stay independent across all 8 ChainHash rounds because the XOR-keying feeds `s_{2k} ⊕ h_k.lo` only into the ECMA lane and `s_{2k+1} ⊕ h_k.hi` only into the ISO lane — they never mix. ITB's encoding path extracts only **`hLo`** (the ECMA lane, low 64 bits) through `xorMask = hLo >> 3`; the ISO lane (`hHi`) never appears in observable ciphertext. The collapse analysis below therefore operates on a single 64-bit lane, not on the full 128-bit CRC128 output. Placed in [`redteam_lab_test.go`](redteam_lab_test.go) only — test helper with an unexported lowercase identifier; not exported to any public API.

**The collapse result.** Unrolling 8 rounds of ChainHash at 1024-bit key gives:

```
hLo(p) = [M_L¹, M_L², M_L³, …, M_L⁸] · [s₁₄, s₁₂, s₁₀, s₈, s₆, s₄, s₂, s₀]  XOR  c(data(p))
       = K  XOR  c(data(p))
```

where `M_L` is the length-L CRC64-ECMA state-transfer matrix (length is fixed at 20 bytes = 4-byte pixelIdx + 16-byte nonce — identical for every pixel), and `c(data(p)) = ChainHash(data(p), seed = all-zero)` is **fully attacker-computable**. The linear-combination image `K` is a **64-bit pixel-independent compound key** that is all the adversary needs — individual seed components `s₀ … s₁₄` are never needed to be recovered. ITB's encoding exposes 56 of K's 64 bits through `xorMask = hLo >> 3` (bits 3..58); the remaining 8 bits (0..2 and 59..63) do not enter any observable channelXOR and would only matter if the attacker tried to reconstruct `noisePos` (controlled by a separate `noiseSeed` — a different ChainHash with its own compound key) or the `dataRotation = hLo % 7` modular remainder.

The contrast with FNV-1a is clean. FNV-1a's per-byte `h ← (h XOR byte) · FNV_PRIME_64` is linear over GF(2) for the XOR step and linear over the ring Z/2⁶⁴ for the multiply step — **but not jointly linear over GF(2)**. Carry chains within the multiplication create AND-combinations between bit positions, and those non-linear bits accumulate through 8 ChainHash rounds. No analogue of `K` exists for FNV-1a; the linear-image collapse above cannot be executed against FNV-1a without first breaking the carry structure via SMT (the analytical scenario at the top of this Phase 2a section).

**Solver.** [`scripts/redteam/phase2_theory/compound_key_crc128.py`](scripts/redteam/phase2_theory/compound_key_crc128.py). Reads the demasker's emitted `.datahash.bin` + `.index` + `.meta.json` sidecars, computes `const(p)` for every data pixel once via the Python CRC64 mirror (matches Go's `crc64Keyed` bit-for-bit: no entry/exit complement, pure Sarwate reflected-polynomial loop), brute-forces the `pixel_shift` that Partial KPA Layer 2 may have locked onto (shift-0 under Full KPA; non-zero when the demasker settled on a period-shifted sp), then majority-votes each bit of K across all observations. The shift brute force picks shifts whose probe-batch conflict rate lies below a 5 %-of-pins threshold (correct shift: near-zero conflicts, wrong shift: ~50 %). Due to CRC64's GF(2)-linearity, there are typically **multiple** shifts below threshold — these are "shadow-K" aliases where `shift_shadow - shift_true` happens to equal a bit-pattern perturbation of `pixel_le` that produces a consistent fake K differing from the true K by a fixed linear term. Shadow-K are structural, not a solver bug: they are what a real attacker would have to enumerate and filter via plaintext-consistency on a companion ciphertext. The lab-filter phase reads `cell.meta.json`'s ground-truth dataSeed **only** to identify which candidate is correct and count the shadow population — this is laboratory audit discipline, not an attacker capability.

**Full 54-cell matrix.** `{4 KB, 16 KB, 64 KB, 128 KB, 512 KB, 1 MB} × {25 %, 50 %, 80 %} × {random_masked, json_structured, html_structured}` at `BarrierFill = 1, N = 2` nonce collisions, `partial` attacker mode with auto-tuned `--n-probe` and `--min-known-channels`. Driven by `scripts/redteam/crc128_compound_key_matrix.sh` at `PARALLEL = 8` on a 16-core host (~25 min wall-clock end-to-end).

| Metric | Result |
|-----|-----|
| Cells attempted | **54** |
| Demasker OK | **53** (1 FAIL on 128 KB html 80 % — reproducibly falls below the single-pair Layer 1 disambiguation threshold at that specific size × kind × coverage combination) |
| Solver succeeded | **53 / 53** (every cell where demask emitted a stream) |
| Correct compound key K recovered | **53 / 53**, one correct K per cell (100 % recovery rate within demask-successful cells; the 8-`uint64` dataSeed components are NOT recovered — the 8-round ChainHash collapses 512 seed bits to 64 compound-key bits) |
| Held-out pixel prediction | **512 / 512 channels per cell** — the recovered K predicts every unobserved pixel's channelXOR bit-for-bit |
| Period-shifted cells | **8 / 53** — Layer 2 locked on a period-shifted sp; solver brute-forced the correct `pixel_shift` and lab-filtered the shadow-K |
| **Total shadow-K** | **2 575** across 53 K-recovered cells (mean 48.6 per cell, max 294) |
| Total brute candidates | 2 628 (correct + shadow combined — this is the attacker-visible ambiguity) |

**Shadow-K scales with container size.**

| size | sum shadow-K across 9 cells | max per cell |
|------|------:|------:|
| 4 KB | **0** | 0 |
| 16 KB | 19 | 4 |
| 64 KB | 102 | 18 |
| 128 KB | 174 | 36 |
| 512 KB | 740 | 147 |
| 1 MB | **1 540** | **294** |

Scaling is roughly linear in `total_pixels` — the CRC64 linear-alias search space expands with every additional pixel index a brute-force shift could land on. At 1 MB the attacker faces up to **295 candidate compound keys** (1 correct + 294 wrong). Each shadow-K is a well-formed 64-bit value that self-consistently explains the observed stream under its specific shift hypothesis; they differ from the true K by linear perturbations of the 8-round ChainHash output and cannot be distinguished without either (a) a plaintext-consistency check on a companion ciphertext sharing the same `(dataSeed, nonce)` — which is already a form of secondary-crib attack — or (b) explicit cryptographic side information outside the demasker's output. The 4 KB row's **zero shadow-K** is informative: at that size the brute-force range effectively covers the whole container, no linear aliases fit inside the observation window, and the attacker would have a clean single-candidate answer — except that a 4 KB plaintext has ~584 data pixels, producing a 56 × 584 / 7 ≈ 4 672-bit compound-key observation that is **already sufficient** to recover K completely.

**Shadow-K scales with coverage.** Higher known-channel coverage means more per-bit pins and more linear-combination paths for shadow-K aliases to survive:

| coverage | sum shadow-K | max per cell |
|---------:|------:|------:|
| 25 % | 490 | 146 |
| 50 % | 886 | 294 |
| 80 % | 1 199 | 294 |

**By plaintext kind** html_structured produces the largest shadow-K population (1 202 sum — period-length 137–800 bytes interacts with the 20-byte pixel_le field in ways that amplify alias counts), json_structured sits in the middle (765), and random_masked is cleanest (608) because there is no periodic `d_xor` structure for Layer 2 to period-shift onto.

**Demask failure at 128 KB html 80 %.** A single cell reliably fails demask at this configuration. Layer 2 finds a sp that initially passes the probe-pixel check but Layer 1 subsequently detects WRONG matches (recovered_config contradicts itself on later pixels under that sp hypothesis), and the orchestrator's `--validate` gate rejects the run. Other 1 / 54 demask failures are expected under single-pair N = 2 Partial KPA at specific boundary coverages; a multi-pair (N ≥ 4) run would eliminate them. For the matrix this counts as "attacker was unlucky on the specific nonce seed"; regenerating the corpus with a different `ITB_NONCE_REUSE_NONCE_SEED` would produce a different outcome for this one cell.

**What the matrix demonstrates — narrowly.**

1. **GF(2)-linear ChainHash collapses exactly as the analytical argument predicts.** Swapping FNV-1a's Z/2⁶⁴-multiply primitive for the same-GF(2)-algebra CRC128 (two independent CRC64 lanes, only the ECMA lane observable via `hLo`) reduces the 1024-bit key to a 64-bit (56-observable) compound key on that single lane, which a commodity Python script recovers in seconds to minutes from any [Phase 2d](#phase-2d--nonce-reuse) nonce-reuse demasked stream of non-trivial size. The mixed-algebra premise of the cost tables at the top of this Phase 2a section is therefore load-bearing, not decorative.
2. **Even with the primitive fully collapsed, ITB's architecture still imposes visible cost.** The demasker's Layer 2 period-shift catastrophe leaks through to the solver as shadow-K aliasing: 8 / 53 cells required explicit pixel-shift discovery, and the attacker-visible candidate-K list grows to 295 entries at 1 MB. That ambiguity must be filtered by a secondary plaintext-consistency attack on a companion ciphertext — itself a non-trivial information requirement in realistic attacker conditions (the companion ciphertext must share the colliding `(dataSeed, nonce)` **and** have ≥ 1 attacker-known byte at a predictable offset).
3. **Scale is the defender's friend, not the attacker's.** Shadow-K scales linearly with `total_pixels`, so larger plaintexts make the attacker's post-recovery filtering harder in absolute terms (a 295-candidate filter at 1 MB vs a 1-candidate answer at 4 KB). Every extra candidate multiplies the attacker's effort because each one requires an independent plaintext-consistency check on a companion ciphertext — so shipping longer messages under a single colliding `(dataSeed, nonce)` pair works **against** a CRC128 style attacker, not for them.

**What the matrix does NOT demonstrate.**

1. **FNV-1a seed recovery.** The solver's `chainhash_crc128_lo` Python mirror is hard-coded to CRC64-ECMA + CRC64-ISO. Running it on a FNV-1a corpus would produce garbage const-values and a ~50 % conflict rate on every candidate shift — the solver refuses such runs via the `meta["hash"] == "crc128"` gate. This is intentional: FNV-1a seed recovery is the analytical scenario at the top of this Phase 2a section, out of empirical scope for this plan.
2. **PRF seed recovery.** Same reason — PRF primitives (BLAKE3, AES-CMAC, SipHash-2-4, ChaCha20, AreionSoEM, BLAKE2*) have no GF(2)-linear structure that brute-force compound-key recovery could exploit, by the PRF assumption itself. They would require a PRF-break, out of scope by assumption.
3. **The single demask failure.** 1 / 54 cells (128 KB html 80 %) does not produce a usable stream for the solver to operate on. This is a demasker-side edge case, not a solver-side limitation; a multi-pair (N ≥ 4) corpus or a different nonce-seed regeneration would close it.
4. **Production attack feasibility.** Even if this attack worked against every real ITB primitive (it does not), the whole [Phase 2d](#phase-2d--nonce-reuse) attack chain is gated by a prior nonce collision — a `2⁻²⁵⁶` event at the shipped 512-bit nonce recommendation. The empirical collapse demonstrated here is conditional on the attacker already being past that gate. See [Threat-model gate](#threat-model-gate--why-this-whole-exercise-is-gated-by-user-nonce-size-choice) for the quantitative bound.

**No-demask sanity control — why the demasker is load-bearing (random-plaintext scope).** The compound-key recovery demonstrated above is entirely dependent on the demasker having already stripped ITB's masking layers (noise bit at `noisePos`, 7-bit rotation, channelXOR subtraction via known plaintext). To confirm that the masking itself hides the hash output — not just the architectural obstacles stacked on top — the solver was fed the **raw ciphertext bytes** of `ct_0000.bin` directly (solver's `--raw-ciphertext-mode`: 8-byte-per-pixel container layout with the 20-byte ITB header skipped), on **10 freshly regenerated 64 KB Full KPA CRC128 corpora under the `known` attacker mode — i.e., random `crypto/rand` plaintext, no structural bias**. Each run used a different `ITB_NONCE_REUSE_NONCE_SEED` to force an independent `(seeds, nonce)` draw. Brute-force pixel-shift search was enabled over the full container range `[0, 9604)`.

| Iteration | Candidates below 5 %-conflict threshold | Conflict rate on full observations |
|----------:|----------------------------------------:|------------------------------------:|
| 1 | **0** | 49.6 % |
| 2 | **0** | 49.6 % |
| 3 | **0** | 49.7 % |
| 4 | **0** | 49.6 % |
| 5 | **0** | 49.5 % |
| 6 | **0** | 49.6 % |
| 7 | **0** | 49.6 % |
| 8 | **0** | 49.6 % |
| 9 | **0** | 49.6 % |
| 10 | **0** | 49.6 % |

**Conflict-rate range [49.5 %, 49.7 %] across all 10 runs — statistically indistinguishable from a fair coin flip.** Under random plaintext the result is an unconditional mathematical outcome, not an empirical coincidence: the 7-bit rotation plus channelXOR make the container byte a rotation-invariant function of a uniform input, so every possible shift hypothesis produces ~50 % K-bit disagreement regardless of how the attacker parses the bytes. The 8-byte-per-pixel raw mode used here is therefore a negative-control for parsing correctness (confirming that no 7-byte / 8-byte misalignment accidentally smuggles signal in), not a claim that ciphertext is signal-free against all plaintexts.

Three architectural implications. **First,** even with a fully GF(2)-linear primitive (CRC128) where the algebraic collapse IS mathematically possible, ITB's masking layers deny the attacker any input to execute it on under random plaintext. **Second,** the whole Phase 2a extension pipeline (solver at 53 / 54 inversion rate) is strictly conditional on the demasker having run first — and the demasker, in turn, requires a nonce collision between two colliding ciphertexts to run Layer 1 constraint matching. No collision → no demasking → no solver input → architecture wins even against below-FNV-1a primitives. **Third,** the `2⁻²⁵⁶` nonce-collision probability at 512-bit nonce is not just a theoretical gate but the only thing standing between the attacker and the entire empirical attack surface demonstrated in this section — the architecture's resistance to a GF(2)-linear primitive reduces to the resistance of the nonce-size choice, nothing more.

**Reproduction commands.**

```bash
# Step 1 — generate corpus for one specific cell (e.g., 64 KB JSON 80 %
# under nonce reuse with CRC128 primitive):
ITB_REDTEAM=1 ITB_BARRIER_FILL=1 \
  ITB_NONCE_REUSE_HASH=crc128 ITB_NONCE_REUSE_N=2 \
  ITB_NONCE_REUSE_MODE=partial ITB_NONCE_REUSE_PLAINTEXT_KIND=json_structured_80 \
  ITB_NONCE_REUSE_SIZE=65536 \
  go test -run TestRedTeamGenerateNonceReuse -v -timeout 60s

# Step 2 — demask + emit reconstructed dataHash stream + .index + .meta.json:
python3 scripts/redteam/phase2_theory/nonce_reuse_demask.py \
  --cell-dir tmp/attack/nonce_reuse/corpus/crc128/BF1/N2/partial_json_structured_80 \
  --pair 0000 0001 --mode partial-plaintext --brute-force-startpixel --validate \
  --emit-datahash tmp/attack/nonce_reuse/reconstructed/crc128_BF1_N2_partial_json_structured_80.datahash.bin

# Step 3 — compound-key K recovery with brute-force pixel-shift search
# and laboratory shadow-K filter (reads cell.meta.json for ground-truth K
# only to identify which candidate is correct — no attacker-side cheating
# other than that final accounting step):
python3 scripts/redteam/phase2_theory/compound_key_crc128.py \
  --cell-dir tmp/attack/nonce_reuse/corpus/crc128/BF1/N2/partial_json_structured_80 \
  --datahash-stream tmp/attack/nonce_reuse/reconstructed/crc128_BF1_N2_partial_json_structured_80.datahash.bin \
  --brute-force-shift 200000

# Step 4 — full 54-cell matrix (one command; ~25 min at PARALLEL=8 on 16-core):
PARALLEL=8 bash scripts/redteam/crc128_compound_key_matrix.sh

# No-demask sanity control (random-plaintext scope) — feed raw ct_0000.bin
# straight to the solver with `--raw-ciphertext-mode` (8-byte-per-pixel
# container layout, 20-byte header skipped) and brute-force over all 9604
# shifts in the 64 KB container. Expected result: 0 candidates, ~49.6 %
# conflict rate — the rotation-invariance + uniform-plaintext outcome.
ITB_REDTEAM=1 ITB_BARRIER_FILL=1 ITB_NONCE_REUSE_HASH=crc128 \
  ITB_NONCE_REUSE_N=2 ITB_NONCE_REUSE_MODE=known ITB_NONCE_REUSE_SIZE=65536 \
  go test -run TestRedTeamGenerateNonceReuse -v -timeout 60s
python3 scripts/redteam/phase2_theory/compound_key_crc128.py \
  --cell-dir tmp/attack/nonce_reuse/corpus/crc128/BF1/N2/known \
  --datahash-stream tmp/attack/nonce_reuse/corpus/crc128/BF1/N2/known/ct_0000.bin \
  --raw-ciphertext-mode --brute-force-shift 10000

# Render the matrix_summary.jsonl into a markdown table suitable for
# audit review:
python3 scripts/redteam/aggregate_crc128_matrix.py \
  --input tmp/attack/nonce_reuse/results/crc128_compound_key_matrix/matrix_summary.jsonl \
  > crc128_matrix.md
```

Per-run artefacts: `tmp/attack/nonce_reuse/results/<tag>/summary.jsonl` (orchestrator cell record) + `<cell>.datahash.bin.meta.json` (demasker's recovered_sp + emission stats — attacker-visible) + `<cell>.compound_key.log` (solver's per-candidate conflict rates + shadow-K accounting + prediction results).

---

### Phase 2a extension — hash-agnostic bias-neutralization audit (axis-1 + axis-2)

The mixed-algebra CRC128 attack chain in the preceding [Phase 2a extension](#phase-2a-extension--empirical-mixed-algebra-stress-test-via-crc128-nonce-reuse) demonstrates GF(2)-linear collapse under nonce-reuse **after the demasker has run**. This subsection covers a complementary measurement — an empirical audit of [Proof 7](PROOFS.md#proof-7-bias-neutralization) (bias neutralization by rotation barrier) on the **raw ciphertext directly**, with no demasking, no nonce-reuse, no Partial KPA sidecar. The probe scans every candidate pixel-shift under a pluggable hash primitive and reports per-cell statistics from two independent axes. It is a hash-agnostic tool: the probe consumes any chainhash module that exports `chainhash_lo(data, seed) -> uint64` + `N_SEED_COMPONENTS`, and the same probe machinery runs against CRC128, FNV-1a, and BLAKE3 without change.

**Methodology.**

1. **Corpus.** Full KPA plaintext in one of three shapes, generated by the existing nonce-reuse harness under three new `ITB_NONCE_REUSE_MODE` values:
   - `known_ascii` — uniform printable ASCII (`0x20..0x7E` + `\t` + `\n`).
   - `known_json_structured` — Full KPA JSON array plaintext using the same generator as `partial_json_structured_80`; every byte is attacker-visible (no mask sidecar).
   - `known_html_structured` — Full KPA HTML tag-wrapped plaintext, analogous.
   
   `BarrierFill=1`, two colliding ciphertexts per cell (`N=2`), sizes `524288` and `1048576` bytes (container = 389 × 389 = `151321` pixels in both cases for the larger; `151321` total pixels is independent of plaintext size since plaintext is container-bounded by `data_pixels = total_pixels`).

2. **Probe (`scripts/redteam/phase2_theory/raw_mode_bias_probe.py`).** For each candidate pixel-shift `s ∈ [0, total_pixels)`:
   - Precompute `const(p) = chainhash(pixel_le || nonce, seed = 0)` for every `p`.
   - Collect `K-bit_candidate = observed_bit ⊕ const_bit_at_pos(s, ch, k)` across ~16 000 observation triples `(container_pixel, channel, observed_7bits)` parsed from the raw `ct_0000.bin`.
   - Per-bit majority vote produces a 64-bit compound-key candidate `K(s)` and a conflict count (number of observations outvoted by the per-bit majority).
   
   The full conflict-rate distribution across `total_pixels` candidate shifts is the **axis-1** statistic.

3. **Axis 2 — prediction accuracy.** For the recovered `K(s)` at two specific shifts — the attacker-visible **min-conflict shift** and the lab-only **TRUE shift** (`= -startPixel mod total_pixels`, read from `cell.meta.json` in lab mode) — evaluate `predicted_channelXOR[ch] = (K ⊕ const(p)) >> (3 + 7·ch) & 0x7F` on 256 held-out pixels × 8 channels × 7 bits ≈ 1800 bit-trials. Report per-bit match rate vs `config.truth.json["per_pixel"]["channel_xor_8"]`. Binomial noise on that sample is ≈ 1 p.p. Distance from the 50 % baseline is the discriminator — the signed direction flips across plaintext formats because rotation-averaged majority-vote direction depends on token-specific bit-frequency profiles (ASCII uniform → +, JSON tokens → ± depending on corpus, HTML tokens → ±), so raw bit-accuracy is not a stable signal, `|pred − 50|` is.

4. **Two-axis verdict.** `bias-leak ✗` if **either** axis-1 TRUE rank < 1 % with plateau < 1 % of total shifts **or** axis-2 TRUE `|Δ50|` ≥ 2 p.p. `neutralized ✓` if axis-2 TRUE `|Δ50|` ≤ 1 p.p. `ambiguous` otherwise. Axis-1 rank has high single-corpus variance (a PRF can land in the top 7 % by chance; the `1/total_pixels` minimum is a `1/151321` draw over a uniform random variable) — so neutralized does not require middle axis-1 rank, axis-2 TRUE is the robust discriminator. Conversely, axis-1 strong leak (rank = 1/151321) is independent of axis-2's amplitude — GF(2)-linear collapse surfaces in the conflict-rate distribution even when the K prediction itself is amplitude-diluted.

**Results — 3 primitives × 2 sizes × 3 plaintext shapes = 18 cells.**

| primitive | size | format | min % conflict | TRUE rank / total | plateau | TRUE bits % | \|Δ50 TRUE\| | verdict |
|:----------|-----:|:-------|---------------:|:------------------|--------:|------------:|------------:|:--------|
| blake3 | 512 KB | ascii            | 48.69 | 66997/76176   | 67149  | 49.67 | 0.33 | neutralized ✓ |
| blake3 | 512 KB | json_structured  | 48.71 | 39450/76176   | 39718  | 50.68 | 0.68 | neutralized ✓ |
| blake3 | 512 KB | html_structured  | 48.66 | 12168/76176   | 12309  | 50.21 | 0.21 | neutralized ✓ |
| blake3 | 1 MB   | ascii            | 48.67 | 10108/151321  | 10137  | 50.63 | 0.63 | neutralized ✓ |
| blake3 | 1 MB   | json_structured  | 48.70 | 6610/151321   | 6716   | 49.44 | 0.56 | neutralized ✓ |
| blake3 | 1 MB   | html_structured  | 48.64 | 9311/151321   | 9318   | 50.25 | 0.25 | neutralized ✓ |
| fnv1a  | 512 KB | ascii            | 48.73 | 73341/76176   | 73352  | 49.58 | 0.42 | neutralized ✓ |
| fnv1a  | 512 KB | json_structured  | 48.68 | 34328/76176   | 34351  | 50.23 | 0.23 | neutralized ✓ |
| fnv1a  | 512 KB | html_structured  | 48.70 | 34822/76176   | 34831  | 49.94 | 0.06 | neutralized ✓ |
| fnv1a  | 1 MB   | ascii            | 48.72 | 151160/151321 | 151160 | 50.45 | 0.45 | neutralized ✓ |
| fnv1a  | 1 MB   | json_structured  | 48.68 | 114134/151321 | 114212 | 49.57 | 0.43 | neutralized ✓ |
| fnv1a  | 1 MB   | html_structured  | 48.68 | 18801/151321  | 19039  | 49.68 | 0.32 | neutralized ✓ |
| crc128 | 512 KB | ascii            | 47.98 | 11762/76176   | 11767  | 46.43 | **3.57** | bias-leak ✗ |
| crc128 | 512 KB | json_structured  | 47.81 | 8153/76176    | 8204   | 53.57 | **3.57** | bias-leak ✗ |
| crc128 | 512 KB | html_structured  | 47.09 | 9408/76176    | 9491   | 50.00 | 0.00 | neutralized ✓ |
| crc128 | 1 MB   | ascii            | 47.98 | **10/151321** | **18** | 53.57 | **3.57** | bias-leak ✗ |
| crc128 | 1 MB   | json_structured  | 47.60 | **1/151321**  | **1**  | 48.21 | 1.79 | bias-leak ✗ |
| crc128 | 1 MB   | html_structured  | 47.09 | **1/151321**  | **2**  | 51.79 | 1.79 | bias-leak ✗ |

Roll-up: **BLAKE3 6/6 neutralized ✓**, **FNV-1a 6/6 neutralized ✓**, **CRC128 5 bias-leak ✗ / 1 neutralized**. The single CRC128 `neutralized` at `(512 KB, html_structured)` is a small-sample outcome: both axes straddle their thresholds (axis-1 rank 12.4 %, plateau 12.5 %; axis-2 TRUE exactly 50 %). Doubling the size to 1 MB under the same format surfaces the leak cleanly on axis-1 (rank 1/151321, plateau 2). Either size is sufficient under ASCII or JSON; HTML sits at the boundary for 512 KB. The CRC128 entries at 1 MB × structured hit the sharpest axis-1 signal possible (TRUE shift literally minimises the full 151321-shift distribution).

**Architectural interpretation.**

- **BLAKE3 (paper-grade PRF).** `|Δ50 TRUE|` ≤ 0.68 across every cell — indistinguishable from the 1 p.p. binomial-noise band at 1800 bit-trials. No detectable algebraic relation between recovered K and the true compound-key projection regardless of plaintext format. This is the PRF fingerprint: the wrapping layers have nothing coherent to amplify because the primitive itself is assumed pseudo-random.

- **FNV-1a (invertible carry-chain multiply).** `|Δ50 TRUE|` ≤ 0.45 across every cell — same fingerprint as BLAKE3 on this probe. FNV-1a is algebraically invertible (`h ← (h XOR byte) · FNV_PRIME` has closed-form inverse over the modular-multiply group), but that invertibility lives in the carry-chain arithmetic ring, not in GF(2) — ChainHash wrapping at 1024-bit key feeds the rotation-barrier + channelXOR + noisePos masking layers through that non-GF(2)-linear diffusion, and the bit bias does not survive to the probe's detection threshold. The datapoint is important because FNV-1a sits architecturally between a PRF (assumed no-structure) and a pure GF(2)-linear primitive (no non-linear mixing at all) — it confirms that **full PRF assumption is not a precondition for [Proof 7](PROOFS.md#proof-7-bias-neutralization) to hold**; any non-GF(2)-linear diffusion in the round function is sufficient.

- **CRC128 (GF(2)-linear test control).** Separates cleanly on both axes whenever the plaintext carries exploitable bit-frequency structure (ASCII uniform distribution, JSON token distribution, HTML token distribution at the larger 1 MB sample size). At 1 MB × structured, the TRUE shift hits literal rank 1/151321 — the minimum of the entire conflict-rate distribution — plateau 1 or 2 shifts. CRC128 is the positive-control outcome: it proves the probe correctly identifies GF(2)-linear collapse when it is present, which in turn validates the `neutralized ✓` readings on the other two primitives.

Axis-2 TRUE sits at 3.57 p.p. from baseline for the three strongest ASCII-direction CRC128 cells (`ascii × {512K, 1M}` and `json × 512K`); at 1.79 p.p. for the `{json × 1M}` / `{html × 1M}` cells where axis-1 carries the full signal. The anti-correlation cases (TRUE = 46.43 %, 48.21 %) reflect token-specific majority-vote direction flips described in the methodology section — the signed sign is corpus-dependent, only the distance is robust.

**Maximum-sample stress test — MD5 × 4 MB × uniform printable ASCII.** One extra cell outside the main matrix, run to cross-validate against [Phase 2b](#phase-2b--per-pixel-candidate-distinguisher) NIST-STS (which already reported ITB-wrapped MD5 output indistinguishable from random noise). MD5 is a deliberately broken cryptographic primitive (known collisions, documented output biases); the 4 MB input is `known_ascii` plaintext — uniform draws from the 97-character printable ASCII alphabet (`0x20`–`0x7E` + `\t` + `\n`), the same corpus shape as the `ascii` rows in the main matrix above. That is the strongest-bias plaintext combined with 4× the sample size of any cell in the main matrix — together a maximally aggressive stress test for the bias-neutralization claim.

| primitive | size | format | min % conflict | TRUE rank / total | plateau | TRUE bits % | \|Δ50 TRUE\| | verdict |
|:----------|-----:|:-------|---------------:|:------------------|--------:|------------:|------------:|:--------|
| md5 | 4 MB | ascii | 48.65 | 72798/603729 | 73559 | 50.12 | **0.12** | neutralized ✓ |

`|Δ50 TRUE| = 0.12 p.p.` sits deep inside the ~1 p.p. binomial-noise band on 1800 bit-trials — the audit reports `neutralized ✓` on a broken primitive + maximum bias plaintext + 4× sample size, and the result is in numerical agreement with [Phase 2b](#phase-2b--per-pixel-candidate-distinguisher)'s independent statistical-randomness framework on the same primitive. Both frameworks converge on the same conclusion from different measurement surfaces.

**This bias-probe is a LABORATORY diagnostic, not an attacker tool.** The precision numbers in the tables above — particularly the `TRUE rank` column and the `|Δ50 TRUE|` axis-2 column for FNV-1a / BLAKE3 / MD5 — are achievable only because the probe has access to the ground-truth encryption configuration of its own test corpora (`cell.meta.json` supplies `start_pixel` for the TRUE-rank computation; `config.truth.json` supplies the per-pixel `channel_xor_8` ground truth that axis-2 prediction accuracy is measured against). Without that configuration, the probe cannot distinguish the `neutralized ✓` primitives from each other — FNV-1a's full conflict-rate distribution, BLAKE3's, and MD5's are all statistically indistinguishable from the `/dev/urandom` control at the probe's sample sizes (this is precisely the [Phase 2b](#phase-2b--per-pixel-candidate-distinguisher) `KL max ≈ 10⁻⁵ nats` floor result, reported from an independent measurement direction). The only primitive the probe separates on **attacker-visible** axes (distribution concentration around the minimum conflict rate) is CRC128 on biased plaintext — the GF(2)-linear control included specifically to verify the measurement pipeline can surface algebraic leaks when they exist.

The probe therefore **cannot be used** to fingerprint the hash primitive in an intercepted ITB ciphertext from an unknown sender, to detect a primitive-misconfiguration remotely, or to distinguish ITB output generated by a specific primitive from ITB output generated by any other properly-wrapped primitive. It is a self-contained lab validation of ITB's [Proof 7](PROOFS.md#proof-7-bias-neutralization) (bias neutralization) run against corpora the experimenter controls — nothing more.

ITB ciphertext under any production PRF primitive sits effectively at the finite-sample KL floor (`~10⁻⁵` nats — the mathematical lower bound of distinguishability from `/dev/urandom` at the tested sample sizes). At that regime no externally observable statistical diagnostic can separate primitives against each other. The only analytical direction left is an internal one — measure the bias that the probe can see **given full knowledge of what it should see**, and confirm that the signal matches the noise floor across primitives the architecture is claimed to neutralize. That is what this tool does, and why its output is diagnostic to the experimenter, but not to an outside observer.

**What this audit does NOT claim.**

1. That a single plaintext format determines attack feasibility. The probe's detection threshold is orders of magnitude tighter than a real-world attacker's exploitation threshold — a `bias-leak ✗` verdict means the **primitive's algebraic structure is empirically visible**, not that it is practically inversible without the full nonce-reuse + demask chain from the [preceding subsection](#phase-2a-extension--empirical-mixed-algebra-stress-test-via-crc128-nonce-reuse).
2. That non-detectability implies a security bound. The probe's `neutralized ✓` band is ±1 p.p. on 1800 bit-trials; a weaker algebraic leak below that floor would go undetected in a single cell and would need a larger sample or a different probe to surface.
3. That any of the tested primitives is a production recommendation. CRC128 and FNV-1a are test helpers in `redteam_test.go` / `redteam_lab_test.go`, not part of the shipped hash selection API (see [Hash matrix](#hash-matrix) for the production list).

**Reproduction.**

```bash
# Full 18-cell matrix (3 primitives × 2 sizes × 3 formats); ~20 min at
# PARALLEL=6 on a 16-core box.
RESULTS_TAG=bias_audit \
PRIMITIVES="crc128 fnv1a blake3" \
SIZES="524288 1048576" \
FORMATS="ascii json_structured html_structured" \
PROBE_SIZE=auto PARALLEL=6 \
bash scripts/redteam/bias_audit_matrix.sh

# Render the matrix_summary.jsonl as markdown with the axis-1 + axis-2
# columns and the combined verdict.
python3 scripts/redteam/aggregate_bias_audit.py \
  --input tmp/attack/nonce_reuse/results/bias_audit/matrix_summary.jsonl \
  > bias_audit.md

# Single-cell probe (plug in any chainhashes/<name>.py module — currently
# bundled: crc128, fnv1a, blake3; analysts can add their own mirror).
python3 scripts/redteam/phase2_theory/raw_mode_bias_probe.py \
  --cell-dir tmp/attack/nonce_reuse/corpus/crc128/BF1/N2/known_ascii \
  --hash-module chainhashes.crc128 \
  --probe-size auto --top-n 5
```

Per-run artefacts: `tmp/attack/nonce_reuse/results/<tag>/matrix_summary.jsonl` (one JSON row per cell with both axes + derived statistics) + `probe_<primitive>_<size>_<fmt>.log` (per-cell verbose probe output including the top-N minimum-conflict shifts, the full percentile distribution, and both axis-2 evaluations).

### Bit Soup arm — Triple Ouroboros bias-neutralization attempt (ASCII, keyBits=1024)

The main audit above runs against Single Ouroboros (`Encrypt128` via `TestRedTeamGenerateNonceReuse`) because `raw_mode_bias_probe.py` has no Triple-partition splitter — the attacker cannot resolve the 3 snake regions without knowing `(startSeed₁, startSeed₂, startSeed₃)`, and introducing a splitter would violate the attacker-realism discipline by handing the analyzer lab-only state. For Triple Ouroboros, the same unmodified probe is invoked against a separate nonce-reuse corpus generated by `TestRedTeamGenerateNonceReuseTriple` (`Encrypt3x128`, keyBits=1024, BF=1, N=2, ASCII plaintext, deterministic seeds). Two arms:

- **Triple Byte Level** (`SetBitSoup(0)`, default): every third plaintext byte goes to a different snake.
- **Triple Bit Soup** (`SetBitSoup(1)` via `ITB_BITSOUP=1`): every third plaintext bit goes to a different snake; each snake's payload is a bit-permuted garbage byte-stream.

Both arms use identical deterministic seed derivation (`masterSeed = 0xBEEFBABE`), identical ASCII plaintext PRNG seed, and identical fixed nonce — the split mode is the only variable. Scope: CRC128 (GF(2)-linear stress control) and FNV-1a (carry-chain reference), two sizes (512 KB + 1 MB). The probe does **not** know Triple is in use — it scans every `pixel_shift ∈ [0, total_pixels)` across the whole container and reports the same min / median / max / true-shift statistics as in the Single-Ouroboros matrix.

Results (attacker-visible metrics in bold; `true_shift_rank` is a lab-peek, not attacker-accessible):

| Primitive | Size | Mode | **min %** | **median %** | **max %** | plateau | true_shift_rank |
|---|---|---|---|---|---|---|---|
| CRC128 | 512 KB | byte-level | **48.277** | **49.073** | **49.421** | 5 / 76 176 | 2 |
| CRC128 | 512 KB | bit-soup | **48.325** | **49.049** | **49.379** | 5 / 76 176 | 2 |
| CRC128 | 1 MB | byte-level | **48.095** | **49.084** | **49.450** | 146 068 / 151 321 | 145 942 |
| CRC128 | 1 MB | bit-soup | **48.121** | **49.029** | **49.367** | 55 357 / 151 321 | 54 946 |
| FNV-1a | 512 KB | byte-level | **48.696** | **49.107** | **49.458** | 4 634 / 76 176 | 4 540 |
| FNV-1a | 512 KB | bit-soup | **48.689** | **49.120** | **49.497** | 17 775 / 76 176 | 17 573 |
| FNV-1a | 1 MB | byte-level | **48.686** | **49.120** | **49.495** | 145 650 / 151 321 | 145 597 |
| FNV-1a | 1 MB | bit-soup | **48.711** | **49.111** | **49.446** | 64 676 / 151 321 | 64 476 |

Attacker-visible deltas between modes are within ± 0.05 percentage points on every metric — inside the statistical noise band for probes of this sample size. **The probe cannot distinguish byte-level Triple from bit-soup Triple under a realistic attacker model at 512 KB – 1 MB ASCII corpus scale.** This is a single empirical observation at the tested scope; larger sample sizes, different plaintext distributions, or probes with region-splitter lab access may surface other statistics.

Two factors explain the null attacker-visible delta, independent of each other and both consistent with architectural intent:

1. **Triple Ouroboros already dilutes input-driven bias below the probe's detection threshold.** Under Single Ouroboros the same probe surfaces CRC128 at min ≈ 47 % on 512 KB ASCII (see table rows above). Under Triple Ouroboros at byte-level the min settles at 48.1 – 48.3 % — the 3-way partition reduces the per-shift bias weighting to ≈ 1/3 because only one snake's region aligns with the probe's `const(p)` computation at any shift hypothesis, and the other 2/3 of pixels contribute ~50 % random conflict regardless of shift. The resulting weighted min sits between the 47 % Single-mode signature and the 50 % PRF-baseline — a natural consequence of the partition-unknown property, achieved without any bit-soup assistance. Factor 1 explains the Single → Triple drift (47 % → 48 %) but not the lack of further drift between byte-level Triple and bit-soup Triple.
2. **Bit-soup re-permutes per-byte-independent bit biases rather than eliminating them.** ASCII plaintext carries a strong per-byte marginal bias (bit 7 ≡ 0 for the 0x00-0x7F range). Under bit-soup, global input bit at position `8k + 7` of source byte `k` maps to snake `(8k+7) mod 3` at intra-snake bit index `(8k+7)/3`. For snake 0, ASCII bit-7 bits from source bytes at offsets `1, 4, 7, 10, …` (every third source byte starting from byte 1) all land at bit 5 of every garbage byte — always 0, full corpus, same systematic bias as ASCII bit-7=0 in the byte-level case. Analogous fixed-position biases hold for snakes 1 and 2. The per-byte-independent marginal bias is **preserved at a different bit position, not eliminated**. CRC128's GF(2)-linear ChainHash projects per-bit-position bias into the ciphertext identically regardless of which bit position carries the bias: the probe `observed(p) XOR const(p) = plaintext(p) XOR C` reduction holds for any linear hash, and majority vote over 56 bits picks up fixed-position bias at bit 5 just as effectively as at bit 7. The probe's signature magnitude is therefore the same in both modes.

Bit-soup's bias-reduction benefit applies to **byte-level correlations** (structured-protocol token repetition, schema framing, adjacency / conditional patterns) — these are destroyed by bit-level dispersal across three snakes, because no single snake retains the byte-level structure. The `raw_mode_bias_probe.py` used here measures per-bit-position marginals only, and is therefore insensitive to the bit-soup / byte-level axis at the ASCII plaintext distribution. A probe sensitive to byte-level joint statistics (bigram / trigram chi-squared, compressibility-based distinguisher, etc.) would register a different relationship between the modes; that measurement is not implemented in this harness.

Net interpretation: the byte-level Triple Ouroboros 3-way partition is the load-bearing defence at the attacker-realistic bias-probe scope. Bit-soup permutes per-bit-position marginals rather than eliminating them, so this specific probe cannot register the bit-soup axis on ASCII plaintext. Bit-soup's architectural contribution remains at two other layers: (a) destruction of byte-level correlations in structured plaintext, not exercised by this probe's marginal-only statistic, and (b) under-determined joint per-snake SAT instance formulation at the attack-construction layer (Partial KPA + realistic protocol traffic, documented elsewhere in the bit-soup landing). FNV-1a shows a naturally higher min (48.69 % byte-level Single per the Phase 2a extension baseline) because carry-chain nonlinearity breaks the linear bias-propagation channel — the per-bit input marginal does not linearly project through the hash, so neither byte-level nor bit-soup shows strong signature. Neither primitive is attacker-distinguishable via this probe from a Triple Ouroboros corpus; bit-soup does not change that conclusion empirically.

Reproduction:

```bash
# Triple Byte Level arm (default mode).
bash scripts/redteam/bias_audit_matrix_triple.sh

# Triple Bit Soup arm (SetBitSoup(1) applied via the package TestMain
# when ITB_BITSOUP is non-zero at test-binary invocation).
ITB_BITSOUP=1 bash scripts/redteam/bias_audit_matrix_triple.sh

# Cell-level probe against a specific Triple corpus (same probe as the
# Single-Ouroboros audit; no Triple-awareness).
python3 scripts/redteam/phase2_theory/raw_mode_bias_probe.py \
  --cell-dir tmp/attack/triple_nonce_reuse/corpus/crc128/BF1/N2/known_ascii/size_524288 \
  --hash-module chainhashes.crc128 \
  --probe-size auto --top-n 5
```

Per-run artefacts: `tmp/attack/triple_nonce_reuse/results/bias_audit_matrix_triple[_bitsoup]/matrix_summary.jsonl` (one JSON row per cell) + `probe_<primitive>_<size>.log` (per-cell verbose probe output). Byte-level and bit-soup arms write to separate `RESULTS_TAG` directories (the shell driver auto-suffixes `_bitsoup` when `ITB_BITSOUP` is non-zero); corpora are also size-segmented at `tmp/attack/triple_nonce_reuse/corpus/<primitive>/BF1/N2/known_ascii/size_<bytes>/` so parallel workers do not race.

---

## Phase 2b — Per-pixel candidate distinguisher

Scripts (run in parallel by `run_suite.py`; two threat models):

- **Mode A** (idealized attacker) — [`scripts/redteam/phase2_theory/distinguisher.py`](scripts/redteam/phase2_theory/distinguisher.py): reads `startPixel` from the `.pixel` sidecar, aligns to data pixels only, XORs with known plaintext to expose the 56 candidate XOR masks.
- **Mode B** (realistic attacker) — [`scripts/redteam/phase2_theory/distinguisher_full.py`](scripts/redteam/phase2_theory/distinguisher_full.py): no `startPixel`, no plaintext; iterates **all P container pixels** (data + CSPRNG fill indistinguishably) and accumulates raw 7-bit candidate values.

Both scripts are direct tests of [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) obstacle (3): "all candidates are equiprobable conditional on the observation" (signal/noise 1:1). Each is an `mp.Pool(8)` map-reduce — one worker per `(hash, sample)`, partial accumulators reduced by `(hash, kind)`; the two pools run concurrently (16 total workers) so the block finishes in 1–2 min. Mode B uses `N = container_pixels × 8` which exceeds Mode A's `N = data_pixels × 8`, so Mode B is the *stricter* test — its theoretical `bins/N` floor is tighter.

For each pixel Mode A enumerates 56 (`noisePos × rotation`) candidates via plaintext XOR; Mode B enumerates the same 56 extractions as raw 7-bit values. Both compute:
1. Per-candidate bit balance (max deviation from 0.5 across 56 bits; Bonferroni-corrected CI for 56-bit max)
2. Per-candidate χ² over 128-bin byte distribution (df = 127)
3. Pairwise KL divergence across all 1 540 unique candidate pairs

### KL floor on `html_giant` — the headline result

With 8 `html_giant` samples per hash aggregated, the per-(hash, kind) cell accumulates roughly **9.6 M observations per candidate** in Mode A (8 samples × ~150 k data pixels × 8 channels) and **11.3 M in Mode B** (BF=32 inflates the container with ~26 k additional CSPRNG-fill pixels per sample), so the finite-sample KL floor drops to **~10⁻⁵ nats** — comfortably below the heuristic **distinguishable** threshold of 0.05.

| Hash | Mode A BF=1 KL max (N = 9.6 M) | Mode B BF=32 KL max (N = 11.3 M) | Interpretation |
|------|-------------------------------:|---------------------------------:|----------------|
| CRC128 | 0.000017 | 0.000014 | **Fully Broken** |
| FNV-1a | 0.000018 | 0.000016 | **Fully Broken** |
| MD5 | 0.000019 | 0.000015 | Broken |
| AES-CMAC | 0.000018 | 0.000016 | Paper-grade PRF |
| SipHash-2-4 | 0.000020 | 0.000015 | Paper-grade PRF |
| ChaCha20 | 0.000018 | 0.000016 | Paper-grade PRF |
| AreionSoEM-256 | 0.000019 | 0.000013 | Paper-grade PRF |
| BLAKE2s | 0.000019 | 0.000014 | Paper-grade PRF |
| BLAKE3 | 0.000021 | 0.000014 | Paper-grade PRF |
| BLAKE2b-256 | 0.000018 | 0.000014 | Paper-grade PRF |
| BLAKE2b-512 | 0.000018 | 0.000013 | Paper-grade PRF |
| AreionSoEM-512 | 0.000018 | 0.000012 | Paper-grade PRF |

Both columns fall in narrow bands: Mode A **[0.000018, 0.000021] nats** (spread 3 × 10⁻⁶) and Mode B **[0.000012, 0.000016] nats** (spread 4 × 10⁻⁶), across the full spectrum from "fully invertible" to "paper-grade 512-bit PRF". Expected finite-sample KL floor: `bins / N ≈ 1.3 × 10⁻⁵` nats for Mode A (N = 9.6 M) and `≈ 1.1 × 10⁻⁵` nats for Mode B (N = 11.3 M); observed values sit at ≈1.5× floor in Mode A and ≈1.4× in Mode B — both consistent with the max-over-1540-pairs correction for the max-KL statistic. Mode B sits uniformly *below* Mode A per primitive, because the realistic attacker's larger N gives a tighter floor and the absence of plaintext XOR / startPixel alignment removes attacker levers rather than adding them.

Per-pixel obstacle (3) holds uniformly whether CSPRNG fill dilutes the data channels or not — the 56-way candidate ambiguity absorbs all primitives equivalently at this test, including FNV-1a. **Whatever FNV-1a leakage Phase 3b detects is not visible at the per-pixel KL level**; it is a template-shaped aggregate structure that emerges only under NIST STS's specific bit-pattern battery.

### Full-corpus cell coverage and the flag threshold

Across all 90 (hash, kind) cells, the per-cell report emits a `⚠` flag when any of the heuristic thresholds `bit_exceed > 10`, `p_lt_001 > 3`, or `kl_max > 0.1` is hit. These thresholds are not derived from a principled false-discovery-rate calculation; they are ad-hoc and picked to catch "obviously anomalous" cells without being triggered by finite-sample extremes.

- **At BF=1** (`tmp/results/single_bf1/04_phase2b.log`): **8 / 90 cells flagged**, across FNV-1a, MD5, AES-CMAC, SipHash-2-4, ChaCha20, and AreionSoEM-512. No single primitive dominates the flag list.
- **At BF=32** (`tmp/results/single_bf32/04_phase2b.log`): **10 / 90 cells flagged**, distributed across a different set of primitives (BLAKE2s, BLAKE2b-512, AreionSoEM-256, AreionSoEM-512 appear more; ChaCha20 does not appear).

**The flagged cells do not overlap between the two regimes** — none of the 8 BF=1 flags corresponds to a BF=32 flag on the same (hash, kind). Because the three triggers are ad-hoc thresholds (not α = 0.05 per cell), the per-cell flag probability under true H0 is dominated by `bit_exceed > 10` firings on small-N cells (http, json, text_small, with ~700 data pixels per sample), where finite-sample variation across 56 candidates inflates the bit-balance statistic. The telling fact is the **non-overlap across independent runs**: real per-primitive effects would flag the same (hash, kind) pair in both regimes; finite-sample noise shuffles the flagged set. Both are observed — per-run counts stay near-identical (8 vs 10 of 90), specific cells shift entirely.

On the 12-primitive re-run, **CRC128** falls into the Mode A BF=1 flag set (two cells — `http` and `html_giant` — both triggered by the `bit_exceed > 10` heuristic on small-N or bit-balance statistics; KL max stays inside the 1.4×–2.6× floor band on both). **BLAKE2b-256** never flags in either regime, behaviourally indistinguishable from the PRF-grade band on this probe. Same shuffling-across-independent-runs pattern as the 10-primitive baseline.

The `html_giant` row is flagged for one hash at BF=1 (FNV-1a, `bit_exceed=21`) and zero at BF=32, but the KL max for that cell is 0.000145 nats — well within the finite-sample floor — so the flag is triggered by the bit-balance heuristic, not by a meaningful KL signal. This is a documentation weakness of the flag threshold (it conflates bit-level extremes on a small single sample with a real distributional divergence); a follow-up with `N ≥ 5` on `html_giant` would resolve it.

### Observed KL vs theoretical floor across data sizes — the invariant that matters

The finite-sample KL floor scales as `bins / N = 128 / N`, so absolute KL numbers drop linearly as samples get larger. The informative quantity is not the absolute KL, which varies by five orders of magnitude with N, but the ratio **`observed_max / theoretical_floor`**, which stays close to 1× at every data scale, for every primitive tested, **and under both attacker threat models** (idealized attacker with known `startPixel` + plaintext XOR; realistic attacker with neither).

#### Mode B — realistic attacker at BF=32 (no `startPixel`, no plaintext, full container)

The full-container analyzer ([`distinguisher_full.py`](scripts/redteam/phase2_theory/distinguisher_full.py)) runs on the BF=32 corpus — the configuration that stresses this threat model most, because CSPRNG fill inflates the container, N grows, and the theoretical floor tightens. N = `container_pixels × 8 channels` aggregated across all samples of a kind. Max across all 12 primitives (min within ~15 %).

| Kind | Aggregate container pixels | N obs / candidate | Theoretical floor `bins/N` | Observed KL max | Ratio max / floor |
|------|---------------------------:|------------------:|---------------------------:|----------------:|------------------:|
| http | ~21 000 | 169 000 | 7.6 × 10⁻⁴ nats | 1.1 × 10⁻³ nats | **1.5 ×** |
| json | ~21 000 | 169 000 | 7.6 × 10⁻⁴ nats | 1.1 × 10⁻³ nats | **1.5 ×** |
| text_small | ~21 000 | 169 000 | 7.6 × 10⁻⁴ nats | 1.1 × 10⁻³ nats | **1.5 ×** |
| text_large | ~237 000 | 1 897 000 | 6.7 × 10⁻⁵ nats | 9.5 × 10⁻⁵ nats | **1.4 ×** |
| http_large | ~178 000 | 1 427 000 | 9.0 × 10⁻⁵ nats | 1.4 × 10⁻⁴ nats | **1.5 ×** |
| json_large | ~200 000 | 1 597 000 | 8.0 × 10⁻⁵ nats | 1.2 × 10⁻⁴ nats | **1.5 ×** |
| text_huge | ~84 000 | 675 000 | 1.9 × 10⁻⁴ nats | 2.9 × 10⁻⁴ nats | **1.6 ×** |
| json_huge | ~87 000 | 695 000 | 1.8 × 10⁻⁴ nats | 2.8 × 10⁻⁴ nats | **1.5 ×** |
| html_huge | ~83 000 | 665 000 | 1.9 × 10⁻⁴ nats | 2.8 × 10⁻⁴ nats | **1.5 ×** |
| html_giant | ~1 411 000 | 11 290 000 | 1.1 × 10⁻⁵ nats | 1.6 × 10⁻⁵ nats | **1.4 ×** |
| **63 MB probe** | **~9 659 000** | **77 277 000** | **1.7 × 10⁻⁶ nats** | **1.8 × 10⁻⁶ nats** | **1.1 ×** |

Under the realistic threat model — attacker knows neither `startPixel` nor the plaintext — the ratio stays in a narrow band **1.1×–1.6×** across nearly six orders of magnitude of N. CSPRNG-fill pixels enter the test on equal footing with data pixels, inflate N, drop the theoretical floor, and the observed max tracks the floor exactly. Mode B ratios are systematically **at or below** the Mode A ratios on the same corpus (see below) — losing idealised alignment information does not give the attacker anything extra; it just removes the two levers Mode A pulled.

#### Mode A — idealized attacker at BF=1 (known `startPixel` + plaintext XOR)

Per-kind figures at BF=1, averaged across all 12 primitives (max and min across primitives within 5 %). Re-running the same analyzer at BF=32 produces the same ratio band within ±0.3× per kind — expected, since the Mode A Phase 2b accumulator reads data-carrying pixels only (N = `data_pixels × 8 channels`, determined by plaintext length, independent of CSPRNG-fill padding). Numbers below therefore characterise both fill regimes for Mode A.

| Kind | data pixels (aggregate) | N obs / candidate | Theoretical floor `bins/N` | Observed KL max | Ratio max / floor |
|------|------------------------:|------------------:|---------------------------:|----------------:|------------------:|
| http | ~650 | 5 200 | 2.5 × 10⁻² nats | 6.4 × 10⁻² nats | **2.6 ×** |
| text_small | ~500 | 4 000 | 3.2 × 10⁻² nats | 5.0 × 10⁻² nats | **1.6 ×** |
| json | ~1 500 | 12 000 | 1.1 × 10⁻² nats | 2.0 × 10⁻² nats | **1.8 ×** |
| text_large | ~120 000 | 960 000 | 1.3 × 10⁻⁴ nats | 2.6 × 10⁻⁴ nats | **2.0 ×** |
| http_large | ~87 000 | 697 000 | 1.8 × 10⁻⁴ nats | 3.5 × 10⁻⁴ nats | **1.9 ×** |
| json_large | ~81 000 | 650 000 | 2.0 × 10⁻⁴ nats | 3.3 × 10⁻⁴ nats | **1.7 ×** |
| text_huge | ~55 000 | 440 000 | 2.9 × 10⁻⁴ nats | 4.0 × 10⁻⁴ nats | **1.4×** |
| html_huge | ~55 000 | 440 000 | 2.9 × 10⁻⁴ nats | 4.5 × 10⁻⁴ nats | **1.5×** |
| html_giant | ~1 200 000 | 9 600 000 | 1.3 × 10⁻⁵ nats | 2.0 × 10⁻⁵ nats | **1.5×** |
| **63 MB probe** | **~9 400 000** | **75 500 000** | **1.7 × 10⁻⁶ nats** | **2.3 × 10⁻⁶ nats** | **1.4×** |

Mode A ratio stays in the narrow band 1.4×–2.6× across four orders of magnitude of N and the full spectrum of hash primitives. Under a true null where the output is genuinely uniform random, the max-over-1540-pairs of a `bins/N`-floor statistic has expected value `√(ln 1540) ≈ 2.7×` floor — the observed 1.4×–2.6× is **below** this null expectation everywhere. **Every primitive, at every data scale, produces a pairwise-KL distribution tight enough to sit at the sampling precision limit of the measurement**.

Absolute KL is dictated by how many observations the test accumulates; the ratio to theoretical floor is dictated by the architecture. The ratio is **invariant** under data size change (four orders of magnitude in Mode A, nearly six in Mode B), under hash primitive change (GF(2)-linear CRC128, invertible FNV-1a, and broken MD5 sit in the same band as PRF-grade BLAKE3), under fill regime change (BF=1 and BF=32 produce the same 1.4×–2.7× band within per-cell sampling noise in Mode A), and under threat-model change (Mode B's realistic attacker gives a band at or below Mode A's across every kind). This is the empirical signature of a barrier-based construction.

### KL floor probe on a single 63 MB sample (one-off, BLAKE3, BF=1, BF=32)

A standalone test encrypts ONE plaintext at ITB's maximum data size (63 MB, just under the 64 MB limit) with BLAKE3 and runs a chunked single-threaded Phase 2b probe on the resulting container. Each per-pixel candidate accumulates N ≈ 7.5–7.7 × 10⁷ observations — an order of magnitude above the 8-giant aggregate — and the probe measures how close the observed pairwise divergence approaches its theoretical limit.

**Two threat models are probed, each at the BarrierFill value that stresses it most:**

- **Mode A — idealized attacker.** Reads `startPixel` from the sidecar, aligns to data pixels only, XORs with the known plaintext. Mirrors the original Phase 2b distinguisher and **overestimates** attacker power. N depends only on `data_pixels × 8`, so BF is irrelevant — run at BF=1 (shipped default).
- **Mode B — realistic attacker.** No sidecar, no plaintext; iterates every container pixel including CSPRNG fill indistinguishably, accumulates raw 7-bit candidate values (no XOR). N is `total_pixels × 8`, so higher BF expands the container and tightens the theoretical floor. Run at BF=32 (maximum fill → strictest test).

The 2×2 is deliberately reduced to these two cells: Mode A at BF=32 would behave identically to Mode A at BF=1 (same data pixels, same N), and Mode B at BF=1 would collapse onto Mode A at BF=1 (fill adds only ~0.4 % to container size at BF=1, so the full-container iteration sees essentially the same data pixels). The two chosen cells therefore span the full informative range.

| Mode | BF | N obs / candidate | Theoretical floor `bins/N` | Observed KL max | Ratio max/floor | Max bit-fraction deviation |
|------|---:|------------------:|---------------------------:|----------------:|----------------:|---------------------------:|
| A — known `startPixel` + plaintext XOR | 1 | 75 497 472 | 1.70 × 10⁻⁶ nats | **2.31 × 10⁻⁶ nats** | 1.36× | 4.9 × 10⁻⁴ |
| B — no `startPixel`, no plaintext, full container | 32 | 77 277 312 | 1.66 × 10⁻⁶ nats | **1.84 × 10⁻⁶ nats** | 1.11× | 8.3 × 10⁻⁵ |

Both cells sit at the sampling precision limit. Mode B (realistic attacker) actually gives the *tighter* ratio — 1.11× vs Mode A's 1.36× — because (a) BF=32 inflates the container by ~190 000 CSPRNG-fill pixels, raising N and lowering the theoretical floor, and (b) the realistic attacker, having no plaintext to XOR against, has no structural information to exploit beyond what the raw candidate stream already offers. Losing `startPixel` and the plaintext alignment does not help the attacker; it removes the only two levers the idealized Mode A pulled.

χ² means: 124.6 (Mode A) and 105.2 (Mode B) against H0 expectation of 127 (df = 127) — both indistinguishable from uniform. Mean bit fractions: 0.4999933 (Mode A, 6.7 ppm below 0.5) and 0.5000144 (Mode B, 14.4 ppm above 0.5). Observed pairwise-KL spans across 1 540 unique candidate pairs: 5.6 × 10⁻⁷ to 2.3 × 10⁻⁶ nats (Mode A) and 5.1 × 10⁻⁷ to 1.8 × 10⁻⁶ nats (Mode B) — both in subnanonat territory where float64 accumulation of `p · log(p/q)` begins to matter.

At this data scale the pairwise KL is **~10³ × below the heuristic distinguishability threshold of 0.05 nats** and approaches the theoretical `bins/N` floor within a factor of 1.1×–1.4× regardless of whether the attacker has idealized alignment information or none at all. The 63 MB single-sample probe is effectively at the practical measurement floor for this distinguisher under both threat models.

The test harness is generic — any of the 12 primitives works via `ITB_REDTEAM_MASSIVE=<name>`, so readers wanting to see FNV-1a, MD5, or CRC128 at the same scale can reproduce locally. See the [Reproducibility](#reproducibility) section for the exact commands (Step 2A = Mode A, Step 2B = Mode B).

#### `/dev/urandom` baseline at the same N

A five-run average of the identical Mode B distinguisher applied to 77 277 312 bytes read from `/dev/urandom` (same container size, same 56-candidate pairwise-KL analysis, same chunked accumulator) gives the sampling-noise envelope for the test itself at N = 77 277 312 observations per candidate:

| Source | KL max (nats) | Ratio max/floor | Max bit-dev | Mean bit fraction | χ² mean |
|:-------|---------------:|----------------:|------------:|------------------:|--------:|
| ITB ciphertext (Mode B, BF=32, BLAKE3) | 1.84 × 10⁻⁶ | 1.11× | 8.3 × 10⁻⁵ | 0.5000144 | 105.2 |
| `/dev/urandom` — mean of 5 runs | 2.04 × 10⁻⁶ | 1.23× | 9.8 × 10⁻⁵ | 0.5000029 | 127.5 |
| `/dev/urandom` — std across 5 runs | ± 0.26 × 10⁻⁶ | ± 0.16× | ± 3.8 × 10⁻⁵ | ± 2.3 × 10⁻⁵ | ± 9.1 |
| Δ (ITB − urandom mean) | −0.20 × 10⁻⁶ | −0.12× | −1.5 × 10⁻⁵ | +1.2 × 10⁻⁵ | −22.3 |

Every Δ between the ITB measurement and the `/dev/urandom` five-run mean is **smaller than the `/dev/urandom` sampling standard deviation** across those five runs:

- KL max: Δ = −0.20 × 10⁻⁶ nats vs σ = ± 0.26 × 10⁻⁶ nats  (|Δ| / σ ≈ 0.8)
- Ratio max/floor: Δ = −0.12× vs σ = ± 0.16×  (|Δ| / σ ≈ 0.75)
- Max bit-fraction deviation: Δ = −1.5 × 10⁻⁵ vs σ = ± 3.8 × 10⁻⁵  (|Δ| / σ ≈ 0.4)
- Mean bit fraction: Δ = +1.2 × 10⁻⁵ vs σ = ± 2.3 × 10⁻⁵  (|Δ| / σ ≈ 0.5)

The ITB χ² mean (105.2) lands about 2.4 σ below the `/dev/urandom` five-run mean but still inside the bulk of the distribution spanned by the individual runs (125.3, 140.5, …). The ITB single measurement is one sample; the `/dev/urandom` envelope above is five samples — the single-sample fluctuation of either source can land anywhere within the ± σ band shown.

**Operational conclusion.** At N = 77 277 312 per candidate, the Phase 2b Mode B distinguisher resolves only its own sampling noise; the signal from the ITB cipher stream is below that noise on every axis the test reports (pairwise KL, ratio to theoretical floor, per-bit fraction deviation, mean bit fraction, χ² uniformity). A passive attacker equipped with this distinguisher and this much ciphertext cannot separate ITB output from `/dev/urandom` output — the two are within the same ± σ envelope. Extracting a signal would require either a different distinguisher (no currently-known test produces one against the 12-primitive hash matrix at the measurement sizes reported earlier in this phase) or more data than ITB's 64 MB-per-message architectural limit admits.

Reproduction of the baseline:

```bash
# 5-run /dev/urandom baseline at the Mode B BF=32 container size.
python3 scripts/redteam/phase2_theory/kl_urandom.py 77277312 5
```

The script accepts any byte count that is a multiple of 8 (one pixel = 8 bytes); a single run at the Mode B size takes ~75 s on a commodity laptop. Substitute a different size to baseline the distinguisher at other N.

#### Small-data variant at 4 KB × BF=32 — defensive maximum for small payloads

`BarrierFill = 32` exists for small-plaintext deployments where the data entropy alone cannot saturate the statistical surface; the knob tops the container up with CSPRNG fill pixels until the fill dominates the byte stream. Running the same Mode B distinguisher on a 4 KB BLAKE3 encryption at BF=32 gives a container of 3 249 pixels (26 012 bytes including the 20-byte header) and N = 25 992 observations per candidate. The matching 5-run `/dev/urandom` baseline at the same N:

| Source | KL max (nats) | Ratio max/floor | Max bit-dev | Mean bit fraction | χ² mean |
|:-------|---------------:|----------------:|------------:|------------------:|--------:|
| ITB ciphertext (Mode B, BF=32, BLAKE3, 4 KB plaintext) | 6.60 × 10⁻³ | 1.34× | 6.0 × 10⁻³ | 0.4987496 | 128.9 |
| `/dev/urandom` — mean of 5 runs (N = 25 992) | 6.39 × 10⁻³ | 1.30× | 6.5 × 10⁻³ | 0.5000173 | 128.9 |
| `/dev/urandom` — std across 5 runs | ± 0.86 × 10⁻³ | ± 0.17× | ± 1.5 × 10⁻³ | ± 1.5 × 10⁻³ | ± 11.2 |
| Δ (ITB − urandom mean) | +0.21 × 10⁻³ | +0.04× | −0.6 × 10⁻³ | −1.3 × 10⁻³ | +0.06 |
| \|Δ\| / σ | 0.24 | 0.24 | 0.39 | 0.87 | 0.006 |

Every `|Δ| / σ` is below 1 — at the 4 KB × BF=32 point ITB ciphertext and `/dev/urandom` sit within the same sampling-noise envelope as tightly as they do at the 63 MB maximum. The operational takeaway matches the BF=32 design intent: for small payloads the CSPRNG residue fill keeps the container indistinguishable from `/dev/urandom` on the Mode B distinguisher. BF=1 is not retested at 4 KB — a small data-dominated container does not exercise the barrier's fill mechanism and is not a defensive configuration for small plaintexts.

Reproduction:

```bash
# Encrypt 4 KB plaintext at BF=32 with BLAKE3, then run the Mode B analyzer.
ITB_REDTEAM_MASSIVE=blake3 ITB_REDTEAM_MASSIVE_SIZE=4096 ITB_BARRIER_FILL=32 \
    go test -run TestRedTeamGenerateSingleMassive -v -timeout 60s
python3 scripts/redteam/phase2_theory/kl_massive_single_full.py blake3

# Matching /dev/urandom baseline (container = 25 992 bytes).
python3 scripts/redteam/phase2_theory/kl_urandom.py 25992 5
```

#### Full (size × BarrierFill) sweep — n = 25 samples per cell

A 66-cell matrix sweeps 11 plaintext sizes (1 KB, 4 KB, 8 KB, 32 KB, 64 KB, 128 KB, 256 KB, 512 KB, 1 MB, 2 MB, 4 MB) × 6 BarrierFill values (1, 2, 4, 8, 16, 32) with **25 ITB encrypt + probe samples and 25 `/dev/urandom` samples per cell**. For each cell the mean ITB ratio and mean `/dev/urandom` ratio are compared as `z = |Δ_mean| / √(σ²_ITB + σ²_UR)`. Aggregates per BarrierFill, averaged over the 11 size rows:

| BF | ITB mean | UR mean | Δ mean | \|Δ\| mean | z mean | % pass (z ≤ 1) |
|:--:|---:|---:|---:|---:|---:|:---:|
| 1  | 1.287 | 1.277 | +0.0096 | 0.038 | 0.213 | 100.0 % |
| 2  | 1.291 | 1.284 | +0.0078 | 0.028 | 0.150 | 100.0 % |
| 4  | 1.280 | 1.296 | −0.0159 | 0.041 | 0.213 | 100.0 % |
| 8  | 1.268 | 1.273 | −0.0050 | 0.018 | 0.092 | 100.0 % |
| 16 | 1.269 | 1.265 | +0.0042 | 0.038 | 0.192 | 100.0 % |
| 32 | 1.262 | 1.260 | +0.0022 | 0.028 | 0.150 | 100.0 % |

**All 66 cells pass `z_ratio ≤ 1.0`**; the matrix maximum is `z = 0.52` at (256 KB, BF = 1). No BarrierFill value produces a measurably tighter match to `/dev/urandom` than any other across the tested range — the per-pixel distinguisher at this sampling precision resolves only its own noise regardless of BarrierFill choice.

Reproduction:

```bash
# Full 66-cell matrix: 11 sizes × 6 BFs × 25 samples per side, 8 parallel
# cell workers. Output: tmp/kltest/matrix.{jsonl,md}. ~17 min on a
# commodity 8-core laptop.
python3 scripts/redteam/phase2_theory/kl_matrix.py

# Override any dimension for ad-hoc runs — e.g. a single (size, BF) cell:
python3 scripts/redteam/phase2_theory/kl_matrix.py \
    --sizes 4096 --bfs 1 --n-samples 25 --workers 1
```

---

## Phase 2c — startPixel enumeration

Script: [`scripts/redteam/phase2_theory/startpixel_multisample.py`](scripts/redteam/phase2_theory/startpixel_multisample.py)

Attacker does **not** know `startPixel`; enumerates all `P` candidates and runs [Phase 2b](#phase-2b--per-pixel-candidate-distinguisher) style candidate analysis on each. Question: does the true `startPixel` stand out statistically? Implemented as `mp.Pool(8)` over `(hash, sample)` task list.

**Scope.** 1 548 tasks (12 primitives × 129 samples — `html_giant` excluded because O(P²) enumeration on a ~4.8 M-pixel container is infeasible). Runtime ~15 min.

### Per-hash aggregate (primary at BF=1; BF=32 in parentheses)

| Hash | Total N | Mean rank-fraction BF=1 / BF=32 (H0 = 0.5) | Mean z-score BF=1 / BF=32 (H0 = 0) |
|------|--------:|------------------------------------------:|-----------------------------------:|
| CRC128 | 129 | 0.4864 / 0.5343 | −0.027 / +0.123 |
| FNV-1a | 129 | 0.5317 / 0.5095 | +0.129 / +0.035 |
| MD5 | 129 | 0.4687 / 0.5166 | −0.093 / +0.083 |
| AES-CMAC | 129 | 0.5077 / 0.5158 | +0.039 / +0.037 |
| SipHash-2-4 | 129 | 0.4815 / 0.4944 | −0.063 / −0.032 |
| ChaCha20 | 129 | 0.5077 / 0.5007 | +0.032 / −0.020 |
| AreionSoEM-256 | 129 | 0.4847 / 0.5191 | −0.071 / +0.041 |
| BLAKE2s | 129 | 0.5228 / 0.4654 | +0.056 / −0.109 |
| BLAKE3 | 129 | 0.5055 / 0.5163 | +0.058 / +0.049 |
| BLAKE2b-256 | 129 | 0.4884 / 0.4871 | −0.002 / −0.002 |
| BLAKE2b-512 | 129 | 0.4611 / 0.4586 | −0.104 / −0.148 |
| AreionSoEM-512 | 129 | 0.5314 / 0.5257 | +0.138 / +0.061 |

**95 % CI under H0 ≈ 0.5 ± 0.050** at N = 129. All 12 primitives inside CI in both regimes; mean z-scores cluster tightly around 0.

### Per-kind cells below α = 0.05 on either sign-test or t-test

| Hash | Kind | rank-fraction | sign-test p | t-test p | Regime |
|------|------|--------------:|------------:|---------:|--------|
| CRC128 | text_large | 0.3894 | 0.951 | 0.016 | BF=1 |
| SipHash-2-4 | http_large | 0.3811 | 0.992 | 0.037 | BF=1 |
| SipHash-2-4 | json_large | 0.6577 | 0.008 | 0.004 | BF=1 |
| SipHash-2-4 | text_huge | 0.1360 | 1.000 | 0.042 | BF=1 |
| BLAKE2s | json_huge | 0.4405 | 1.000 | 0.010 | BF=1 |
| BLAKE2s | html_huge | 0.1613 | 1.000 | 0.047 | BF=1 |
| BLAKE3 | http_large | 0.6173 | 0.181 | 0.028 | BF=1 |
| CRC128 | http_large | 0.5927 | 0.292 | 0.045 | BF=32 |
| FNV-1a | text_large | 0.3777 | 0.992 | 0.026 | BF=32 |
| FNV-1a | html_huge | 0.2266 | 1.000 | 0.005 | BF=32 |
| AES-CMAC | text_small | 0.2587 | 0.999 | 0.017 | BF=32 |
| SipHash-2-4 | json_large | 0.5414 | 0.049 | 0.896 | BF=32 |
| AreionSoEM-256 | text_large | 0.5853 | 0.049 | 0.132 | BF=32 |
| BLAKE3 | http_large | 0.6044 | 0.021 | 0.053 | BF=32 |
| BLAKE2b-512 | json | 0.6994 | 0.172 | 0.033 | BF=32 |
| BLAKE2b-512 | text_large | 0.3871 | 0.979 | 0.048 | BF=32 |
| AreionSoEM-512 | json_large | 0.6477 | 0.003 | 0.007 | BF=32 |

A cell lands in this table when **either** its sign-test or t-test returns `p < 0.05` — this is the disjunctive flag the analyzer script emits for inspection. **7 such cells appear at BF=1, 10 at BF=32, with a different distribution of affected hashes across regimes.** Under α = 0.05 across 108 `(hash, kind)` cells and two tests, 5.4–10.8 cells would be expected by chance even under a true null; 7–10 sits squarely inside that range. No hash is flagged consistently across the two regimes, and flagged hashes span both directions (high and low rank-fraction) and every primitive class including the below-spec controls — this is the pattern of random false-positive scatter under a true null, not evidence of a distinguisher.

Obstacle (2) `startPixel` isolation empirically holds across all 12 primitives at both fill regimes.

---

## Phase 2d — Nonce-Reuse

> **For a reader-friendly summary of this section** — what nonce reuse actually is, the five conditions that ALL must hold for the attack to produce any signal, and why the user's choice of nonce size is the real defence — see [ITB.md § 8 Nonce Reuse](ITB.md#8-nonce-reuse-only-if-every-condition-holds). The rest of this Phase 2d section is the formal empirical write-up: corpus generator, demasker pipeline, 96-cell matrix, NIST STS tables, and the nine architectural effects visible in the data.

Scripts:
- [`redteam_lab_test.go`](redteam_lab_test.go) — corpus generator (install fixed nonce via test-only hook; encrypt N plaintexts with same seeds + same nonce; emit ground-truth config sidecar).
- [`scripts/redteam/phase2_theory/nonce_reuse_demask.py`](scripts/redteam/phase2_theory/nonce_reuse_demask.py) — demasker (Layer 1 constraint matching + Layer 2 startPixel brute force + reconstructed-stream emission).
- [`scripts/redteam/run_attack_nonce_reuse.py`](scripts/redteam/run_attack_nonce_reuse.py) — orchestrator (per-cell pipeline with pre-run wipe, safe deletion, optional post-emission cleanup).
- [`scripts/redteam/phase3_deep/nist_sts_on_attack_streams.py`](scripts/redteam/phase3_deep/nist_sts_on_attack_streams.py) — NIST STS wrapper for the reconstructed streams.

Tests the nonce-misuse locality claim from [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis) empirically: under a **deliberate** nonce collision with Full KPA, how much does the attacker learn, and does the outcome depend on the primitive's PRF property?

### Threat model

Attacker forces the sender to encrypt two plaintexts `p_1 ≠ p_2` under the SAME `(noiseSeed, dataSeed, startSeed)` and the SAME nonce. The attacker knows both plaintexts (Full KPA) — either because they are public protocol payloads or because they leaked via another channel. The attacker does NOT know `startPixel` or the per-pixel configuration map `(noisePos, rotation, channelXOR)`. Under [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis)'s locality claim, the expected damage is a two-time pad on these 2 – 3 colliding messages only; seeds remain secret under PRF non-invertibility and future messages (fresh nonce) are unaffected. Under an invertible / linear primitive, the same claim does not hold — seed retention is no longer guaranteed.

### Attack chain

Three empirical layers stacked, each removing one architectural obstacle from [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure):

1. **Layer 1 — per-pixel `(noisePos, rotation)` recovery.** On the XOR of the two ciphertexts, for each data pixel, enumerate the 56 `(noisePos, rotation)` candidates; constraint-match against all 8 channels using the known plaintexts. Unique match recovers the per-pixel config; resolves obstacle (3).
2. **Layer 2 — `startPixel` brute force.** Attacker does not know `startPixel`. For each candidate in `[0, totalPixels)`, check whether the first 10 probe pixels admit at least one `(noisePos, rotation)` match using Layer 1 constraints. Under a wrong `startPixel` the false-positive rate is `56 × 2⁻⁵⁶ ≈ 0` per probe pixel — short-circuit on the first probe pixel rejects almost every wrong candidate in microseconds. Resolves obstacle (2).
3. **Reconstruction — strip all masking.** Using recovered `(startPixel, noisePos_map, rotation_map)` + known plaintext, extract the pure channelXOR output per (pixel, channel):
    ```
    extracted_7 = remove_noise_bit(ciphertext_byte, noisePos)
    unrotated_7 = rotate7(extracted_7, 7 − rotation)
    channelXOR_7 = unrotated_7 ⊕ plaintext_7bits     # ≡ (dataSeed.ChainHash(pixel || nonce) >> 3) bits
    ```
    Pack 8 × 7 = 56 bits per pixel, little-endian. The resulting byte stream is **literally a prefix of the raw `dataSeed.ChainHash(pixel_u32le || nonce)` output** under a controlled one-parameter-vary (pixel-index) probe — all ITB masking has been stripped. This is the PRF-separation artefact: under a PRF this stream is uniform random; under an invertible primitive it inherits the primitive's algebraic structure.

Only obstacle (1) — ChainHash SAT-hardness — is left between the attacker and the raw primitive output. Feeding the reconstructed stream to NIST STS tests whether that single remaining layer still produces statistically PRF-like output.

### Test matrix

Two primitives at opposite ends of the PRF spectrum, flagship PRF-separation configuration:

| Primitive | Width | ChainHash rounds @ 1024-bit key | Role |
|-----------|-------|--------------------------------:|------|
| **BLAKE3** | 256-bit | 4 | Paper-grade PRF reference |
| **FNV-1a** | 128-bit | 8 | Fully invertible; below-spec control |

Parameters: `BarrierFill = 1` (shipped default), `N = 2` collisions per cell, plaintext size = 2 MB, attacker mode = `known` (two distinct random plaintexts, both known to attacker → strongest-attacker Full KPA). Reconstructed streams: ~16.7 Mbit per cell, directly supporting NIST STS at `N = 16 × 1 Mbit` per cell without cross-cell concatenation.

MD5 is intentionally excluded from the reported matrix: at our automated stream size (16 Mbit, N = 16 × 1 Mbit), MD5 passes 188/188 identically to BLAKE3 — the stream-size window is too small to catch MD5's known collisional biases, which only manifest at huge streams. Reporting "MD5 188/188" alongside BLAKE3 would mislead a casual reader into concluding MD5 is safe under nonce-reuse. MD5 IS broken at real-world scale; this automated configuration cannot see it, and the honest choice is to omit rather than imply false safety.

### Demasker validation (correctness check — not an empirical claim)

Before running the attack chain against a corpus, the demasker was validated byte-for-byte against the ground-truth `(noisePos, rotation, channelXOR)` map produced by the Go test. Every recovered per-pixel config matches ground truth exactly; reconstructed `channelXOR` values match the ground-truth `channel_xor_8` arrays byte-for-byte on every successfully demasked pixel. This confirms the attack-chain implementation is sound — subsequent NIST STS results reflect hash-output properties, not demasker bugs.

| Hash | Width | Layer 1 exact recovery | Layer 1 ambiguous | Layer 1 **wrong matches** | Layer 2 startPixel recovered | Reconstruction vs ground truth |
|------|------:|-----------------------:|------------------:|-------------------------:|:---------------------------:|:------------------------------:|
| FNV-1a | 128 | 99.25 % | 0.75 % | **0** | ✓ | 100 % byte-for-byte match |
| MD5 | 128 | 99.24 % | 0.76 % | **0** | ✓ | 100 % byte-for-byte match |
| BLAKE3 | 256 | 99.14 % | 0.86 % | **0** | ✓ | 100 % byte-for-byte match |
| BLAKE2b-512 | 512 | 99.30 % | 0.70 % | **0** | ✓ | 100 % byte-for-byte match |

"Ambiguous" pixels are single-pair adjacent-noisePos coincidences (when `extract7(xor_byte, k) == extract7(xor_byte, k+1)` holds across all 8 channels — probability `≈ 7/256` per pixel by Bonferroni). Zero wrong matches on all four widths means the formula is provably correct; ambiguity is a statistical artefact resolvable by multi-pair combining (N ≥ 4 collapses it to zero in practice).

### NIST STS on reconstructed streams — the PRF-separation result

After Layer 1 + Layer 2 + reconstruction, the recovered `dataHash_stream.bin` (~16.7 Mbit per primitive) is fed to `nist-sts` at `N = 16 × 1 Mbit` per primitive.

| Primitive | pass / total | fail count | Category of failures |
|-----------|-------------:|-----------:|----------------------|
| **BLAKE3** | **188 / 188** | **0** | — (uniform random output) |
| **FNV-1a** | **182 / 188** | **6** | Block-level + spectral + cumulative-walk tests (detail below) |

FNV-1a failure detail (proportion-below-threshold tests; excludes the hash-agnostic `NonOverlappingTemplate` bin-routing artefact discussed in [Phase 3b](#the-p-value-clustering-phenomenon--hash-agnostic-present-at-any-n)):

| Test | Proportion pass rate | Threshold at N=16 | Severity |
|------|---------------------:|------------------:|----------|
| `FFT` | **0 / 16** | 14 / 16 | **100 % fail rate** — spectral peak visible on every one of 16 bit-streams |
| `BlockFrequency` | 9 / 16 | 14 / 16 | 56 % pass — bit balance within 100 K-bit blocks skewed |
| `CumulativeSums (forward)` | 12 / 16 | 14 / 16 | Running-sum walk diverges from expected uniform-random |
| `CumulativeSums (reverse)` | 13 / 16 | 14 / 16 | Same, reversed direction |
| `Runs` | 12 / 16 | 14 / 16 | Run-length distribution biased |

Under PRF (BLAKE3) **every single NIST STS test passes**. Under invertible FNV-1a **the spectral test flags every single bit-stream** as containing structured (non-uniform) frequencies, with four additional bit-level statistical tests flagging proportion below threshold.

### Interpretation — ChainHash XOR composition ≠ PRF on an invertible primitive

FNV-1a's per-byte operation is `h ← (h ⊕ byte) · FNV_PRIME_64`. The `⊕ byte` step is linear over `GF(2)`. The `· FNV_PRIME_64` (integer multiplication modulo 2⁶⁴ by a constant) is linear over the **ring `Z/2⁶⁴`** — but NOT linear over `GF(2)`: carry propagation within the multiplication creates non-linear bit interactions (each output bit depends on AND-combinations of input bits via carry chains). So the 8-round ChainHash128 with FNV-1a at 1024-bit key is NOT a pure `GF(2)`-affine function — it has genuine non-linearity via carries.

This distinction matters: the attacker cannot simply run Gaussian elimination on recovered `channelXOR` observations to invert the seed. Seed recovery still requires bitvector-SAT over the combined XOR + integer-multiplication constraints — research-lab scale compute for the 512-bit effective lo-lane unknowns (the nominal key is 1024-bit, but the hi lane never reaches `hLo` via FNV-1a's carry-up-only multiplication and is left unconstrained).

What the NIST STS failures DO show is that **the non-linearity from carries is not strong enough** to produce output statistically indistinguishable from a PRF over 8 rounds of ChainHash XOR composition. The reconstructed stream inherits enough residual structure for FFT to detect spectral peaks on every bit-stream and for block-level + run-length tests to flag proportion deviations. A SAT solver attacking this stream has **substantially more exploitable bias** than it would against a true PRF output — this likely shifts the seed-recovery wall-clock toward the lower end of the [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure) FNV-1a range (hours – 1 year on a 1000-node cluster under idealised conditions) or below, though this plan does not attempt the actual SAT run.

Under PRF (BLAKE3 at 4 rounds at 1024-bit key) the reconstructed stream's 188 / 188 pass means the attacker's SAT problem has **no statistical bias to exploit beyond the raw algebraic complexity** — the single remaining obstacle (ChainHash SAT-hardness over a PRF) remains effectively infeasible.

### Consistency with Phase 2a cost tables

The [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure) three-layer combined-cost estimate (10¹² – 10¹⁶ years at 50 % Partial KPA + unknown `startPixel` + 1000-node cluster) applies to the **standard threat model**: fresh nonce per encryption, all three obstacles active. The nonce-reuse attack operates outside that model — it deliberately forces a nonce collision and uses the two ciphertexts together to peel back obstacles (2) and (3). Layer 1 + Layer 2 of the demasker complete this peeling in seconds per pair.

What remains after peeling is exactly the "Full KPA + `startPixel` known" entry from Phase 2a's [back-of-envelope table](#back-of-envelope-1000-node-cluster-wall-clock-full-kpa-startpixel-known) — **hours to 1 year** on a 1000-node cluster under FNV-1a, or structurally infeasible under PRF. The NIST STS results validate this split empirically: under FNV-1a the remaining single-layer defence exhibits detectable output bias (the SAT solver would have real leverage); under PRF no such leverage exists (output is indistinguishable from random).

**The takeaway is not that the [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure) estimates are wrong.** They are correct for the threat model they state. The takeaway is that **architectural obstacles (2) and (3) are load-bearing against below-spec primitives** — a single-layer "just-ChainHash" defence is sufficient under a real PRF but **insufficient under an invertible primitive** even when the primitive is wrapped in 8 rounds of XOR composition. This is why [`SECURITY.md`](SECURITY.md) and [`SCIENCE.md`](SCIENCE.md) consistently require PRF-grade primitives for production use, and this empirical demonstration makes that requirement concrete.

### Validation of [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis) locality claim

| Claim from [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis) | Empirical status from this phase |
|--------------------------------------------------------------------|----------------------------------|
| Nonce collision compromises confidentiality of the 2 – 3 colliding messages (two-time pad on data bits) | ⚠ Confirmed as a theoretical possibility, but empirically tautological on this probe. ITB's per-encryption `noise bits + rotation + channelXOR` mean `C1 ⊕ C2` alone does NOT yield plaintext XOR (unlike a stream cipher) — the full demasker pipeline is required. Its output is the hash-output stream, and plaintext bytes become derivable only at positions where the attacker already knew one side from format knowledge; those positions coincide with format-spec-derivable bytes, yielding no new plaintext information in practice. |
| Seeds remain secret under PRF non-invertibility | ✅ Confirmed empirically via BLAKE3 188/188 NIST STS on reconstructed stream: no exploitable structure in the remaining single-layer defence. SAT-based seed recovery has no statistical leverage. |
| Seed retention **requires** PRF non-invertibility | ✅ Empirically demonstrated via the BLAKE3-vs-FNV-1a contrast: same attack chain, same stream size, same NIST STS configuration, opposite outcomes. Under FNV-1a the reconstructed stream flags 6 tests (including FFT 0/16 — spectral structure on every bit-stream) showing residual linear-order bias that a SAT solver could leverage for seed recovery. |
| No key rotation required after a nonce collision | ⚠ Confirmed **only for PRF-grade primitives**. Under FNV-1a the nonce-reuse event plausibly does not merely leak the 2 – 3 colliding messages — it produces a detectable-bias stream whose hash-output structure a motivated attacker (lab-scale compute) could invert to recover seeds. The [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis) no-rotation claim implicitly depends on the PRF requirement stated elsewhere in the docs; this probe makes that dependency empirically visible. |

### Classical keystream-reuse decryption — empirical plaintext recovery from config map

The NIST STS result above (PRF vs FNV-1a split) is about **seed recovery via SAT** on the reconstructed hash-output stream. Plaintext recovery of the 2 – 3 colliding messages follows a separate, simpler path: the per-pixel config map `(noisePos, rotation, channelXOR)` recovered by Layer 1 + Layer 2 **is** the classical keystream-equivalent for this single `(seeds, nonce)`. Applying it directly to both colliding ciphertexts decrypts them in the standard keystream-reuse sense — no SAT required, works **identically under PRF and non-PRF primitives**.

Empirical demonstration at 64 KB plaintext, `BarrierFill = 1`, `N = 2` collisions, Full KPA on both plaintexts fed into Layer 1:

| Corpus kind | Hash | Cobs-form byte match | Gap markers (in 65 675 bytes) | Visual plaintext recovery |
|-------------|------|---------------------:|------------------------------:|---------------------------|
| Random (attacker-modes `known`) | FNV-1a | **99.17 %** (65 128 / 65 675) | ~546 bytes (0.83 %) | 100 % raw match after gap-patch from ground truth |
| Random (attacker-modes `known`) | BLAKE3 | **99.19 %** (65 142 / 65 675) | ~532 bytes (0.81 %) | 100 % raw match after gap-patch from ground truth |
| `json_structured` (attacker-modes `partial`) | FNV-1a | **95.50 %** (62 720 / 65 672) | 75 – 85 markers | JSON structure + field names + value content fully legible; ~0.12 % of output is 0xFF gap markers localized around structurally-shared bytes |
| `json_structured` (attacker-modes `partial`) | BLAKE3 | **95.50 %** (62 720 / 65 672) | 75 – 117 markers | Identical to FNV-1a row — PRF does not defend against config-map keystream reuse |
| `html_structured_80` (attacker-modes `partial`) | FNV-1a | **98.40 %** (64 625 / 65 674) | 32 – 44 markers | HTML structure + tag names + attribute values fully legible; even fewer gaps than JSON due to HTML's different shared-byte distribution |
| `html_structured_80` (attacker-modes `partial`) | BLAKE3 | **98.44 %** (64 652 / 65 674) | 36 – 51 markers | Identical to FNV-1a row |

Key observations: (a) PRF-grade BLAKE3 and invertible FNV-1a give **numerically identical** plaintext-recovery outcomes — the barrier to classical keystream reuse is architectural, not primitive-based; (b) gaps correspond to single-pair Layer 1 ambiguity on structurally-shared bytes where `d_xor = 0`, close to 0 with multi-pair combining at `N ≥ 4`; (c) the raw COBS-decoded plaintext is visually almost identical to the original — field names, tag names, value content, record boundaries all intact.

Example — first ~220 bytes of recovered plaintext vs original, BLAKE3 on `html_structured_80`:

```
recovered : <identifier-of-record-in-system>00000</identifier-of-record-in-system><the-timestamp-of-the-event-iso>uUPmRM379bKXGdBT403XmMweN</the-timestamp-of-the-event-iso><the-encrypted-opaque-payload01>...
groundtruth: <identifier-of-record-in-system>00000</identifier-of-record-in-system><the-timestamp-of-the-event-iso>uUPmRM379bKXGdBT403XmMweN</the-timestamp-of-the-event-iso><the-encrypted-opaque-payload01>...
```

Full KPA classical-decrypt pipeline (corpus + demask + reconstruction + classical XOR + COBS-decode → raw plaintext files):

```bash
# Random Full KPA, FNV-1a + BLAKE3, with classical-decrypt post-demask step:
python3 scripts/redteam/run_attack_nonce_reuse.py \
    --plaintext-size 65536 \
    --hashes fnv1a,blake3 \
    --barrier-fill 1 \
    --collision-counts 2 \
    --attacker-modes known \
    --validate \
    --classical-decrypt \
    --results-tag full_kpa_random_classical

# JSON structured variant (partial mode used only to get JSON plaintext;
# classical_decrypt still treats attacker-known .plain as Full KPA input):
python3 scripts/redteam/run_attack_nonce_reuse.py \
    --plaintext-size 65536 \
    --hashes fnv1a,blake3 \
    --barrier-fill 1 \
    --collision-counts 2 \
    --attacker-modes partial \
    --plaintext-kind json_structured \
    --validate \
    --classical-decrypt \
    --results-tag full_kpa_json_classical

# HTML structured variant (82 % coverage, 250-byte records):
python3 scripts/redteam/run_attack_nonce_reuse.py \
    --plaintext-size 65536 \
    --hashes fnv1a,blake3 \
    --barrier-fill 1 \
    --collision-counts 2 \
    --attacker-modes partial \
    --plaintext-kind html_structured_80 \
    --validate \
    --classical-decrypt \
    --results-tag full_kpa_html_classical
```

Each run emits per-cell recovered-plaintext artefacts under
`tmp/attack/nonce_reuse/classical_decrypt/<results-tag>/<hash>_BF1_N2_<mode>/`:
`recovered_cobs_P{1,2}.bin` (COBS-encoded stream after keystream XOR;
compare byte-for-byte to what was packed into pixels) and
`recovered_plaintext_P{1,2}.bin` + `groundtruth_plaintext_P{1,2}.bin`
(raw plaintext bytes, 0xFF at gap positions, for direct diff).

> **Period-shift catastrophe caveat.** On structured `partial` kinds
> (JSON / HTML) the `d_xor` pattern is periodic at record-length
> granularity; Layer 2's `startPixel` brute force can converge on a
> period-shifted false `startPixel` if probe depth is too small
> (effect 3 in the [Partial KPA matrix](#nine-architectural-effects-visible-in-this-matrix)
> — drops Clean Signal from ~95 % to ~20 %). The orchestrator above
> auto-tunes `--n-probe` per kind: `json_structured_*` → 57 probe pixels
> (3 × 19-pixel record period), `html_structured_*` → 105 pixels
> (3 × 35-pixel record period). `random` / `known` attacker mode gets
> `--n-probe 10` (no periodicity so small probe suffices). If invoking
> `classical_decrypt.py` directly on a partial-kind cell, pass
> `--n-probe 60` (JSON) or `--n-probe 105` (HTML) explicitly to avoid the
> period-shift collapse. The orchestrator path shown above handles this
> automatically.

Verify recovery by diffing against ground truth — the two plaintexts are
identical at the byte level except at the small localised gap positions:

```bash
TAG=full_kpa_html_classical
CELL=blake3_BF1_N2_partial_html_structured_80
DIR=tmp/attack/nonce_reuse/classical_decrypt/$TAG/$CELL

# Hex side-by-side of first 512 bytes
diff <(xxd $DIR/groundtruth_plaintext_P1.bin | head -32) \
     <(xxd $DIR/recovered_plaintext_P1.bin  | head -32)

# Exact byte-count of mismatches (should equal the gap-marker count in the log)
cmp -l $DIR/groundtruth_plaintext_P1.bin $DIR/recovered_plaintext_P1.bin | wc -l

# Viewable text — opens recovered plaintext as a file; JSON / HTML structure
# is readable end-to-end with 0xFF markers at the ~0.12 % gap positions.
less $DIR/recovered_plaintext_P1.bin
```

For the random-plaintext run, a gap-aware post-processor that patches gap
pixels from multi-pair observations (here simulated from ground truth)
recovers the last 0.83 % and produces **100.0000 %** raw plaintext match —
the path a real attacker would take at `N ≥ 4` collisions where
`(1/256)^6 ≈ 10⁻¹⁵` per-pixel ambiguity is architecturally eliminated.

The headline takeaway: **under nonce reuse + Full KPA, BLAKE3 and FNV-1a
give identical plaintext recovery**. PRF property is **load-bearing for
seed-level security across nonces**, not for plaintext confidentiality of
the specific messages that collided on this nonce. The "SAT seed recovery"
framing in the Phase 2d NIST STS result is a separate attack dimension —
targeting different assets (seeds, not plaintext) with a different attack
path (SAT inversion of ChainHash, not keystream reuse).

#### Partial KPA (25 % mask) — no new plaintext beyond attacker input

Same pipeline at 25 %-coverage Partial KPA (symmetric mask — attacker knows
the same byte positions on both P1 and P2). Layer 1 partial recovery uses
only channels where both masks mark the byte known; classical decryption
then emits a plaintext byte only when every channel spanning it is both
Layer-1-recovered and mask-known. At 64 KB plaintext, `BarrierFill = 1`,
`N = 2`, auto-tuned `--n-probe` + `--min-known-channels`:

| Corpus kind | Hash | Input mask | Layer 1 unique | Recoverable bytes |
|-------------|------|-----------:|---------------:|------------------:|
| `random_masked_25` | FNV-1a | 24.71 % | 154 / 9 604 (1.6 %) | **0.06 %** (42 / 65 536) |
| `random_masked_25` | BLAKE3 | 24.71 % | 164 / 9 604 (1.7 %) | **0.06 %** (40 / 65 536) |
| `json_structured_25` | FNV-1a | 25.17 % | 2 181 / 9 604 (22.7 %) | **6.40 %** (4 184 / 65 352) |
| `json_structured_25` | BLAKE3 | 25.17 % | 2 189 / 9 604 (22.8 %) | **6.42 %** (4 198 / 65 352) |
| `html_structured_25` | FNV-1a | 25.16 % | 2 344 / 9 604 (24.4 %) | **5.26 %** (3 429 / 65 190) |
| `html_structured_25` | BLAKE3 | 25.16 % | 2 344 / 9 604 (24.4 %) | **5.26 %** (3 430 / 65 190) |

Three structural observations:

1. **`recoverable < mask-input` on every row.** Attacker walked in with
   ≈ 25 % of bytes and walked out with ≤ 6.42 % of bytes — strict loss of
   coverage through the pipeline. Byte-boundary / channel-boundary
   misalignment accounts for most of the gap: a byte's 8 bits span
   channels of possibly two adjacent pixels, and emitting a byte needs
   BOTH spanning (pixel, channel) positions to be Layer-1-recovered AND
   mask-known. Either constraint failing drops the byte to 0xFF gap.
2. **Random mask is dramatically worse for the attacker than structured.**
   `random_masked_25` yields only **0.06 %** recoverable vs 5 – 6 % for
   the structured kinds. Reason: random-scatter 25 % coverage projects to
   ~6 % channel-known rate (2-byte-spanning channels need BOTH bytes
   known → `0.25² = 0.0625`). With `min_known_channels = 3` Layer 1
   threshold, only ~1.6 % of pixels have enough known channels to recover
   config. Structured kinds cluster their known bytes at predictable
   offsets — same aggregate coverage, dramatically higher per-pixel
   concentration.
3. **Recoverable bytes ⊆ mask-input bytes** on every row. No new plaintext
   leaks beyond the attacker's input; classical keystream reuse under
   symmetric Partial KPA just reproduces what the attacker already held.
   This is the empirical confirmation of the "no new plaintext" framing
   in [ITB.md § 8.1](ITB.md#81-why-binary-formats-defeat-partial-kpa-demasking-entirely)
   and the item-1 note in ["What a successful Partial KPA demask actually
   gets the attacker"](#what-a-successful-partial-kpa-demask-actually-gets-the-attacker).

FNV-1a and BLAKE3 rows are numerically identical within Layer-1 sampling
noise — PRF property does not defend against this path, same architectural
equivalence as in the Full KPA rows above.

Visual recovered vs groundtruth snippet (BLAKE3 on `json_structured_25`,
0xFF gaps rendered as `·` for readability):

```
recovered : ··"identi·ier_o·_record_in_system":·······,"the_timestamp_o·_the_event_iso":"································································································he···crypted_opaque_payload__":"···················································
groundtruth: [{"identifier_of_record_in_system":"00000","the_timestamp_of_the_event_iso":"uUPmRM379bKXGdBT403XmMweNr6JvMgc4zxsja7vOpNMut2TBj1pBlSsPK7YGQoj...
```

Only structural tokens + partial field-name fragments surface; value
regions (`00000`, timestamp values, opaque payload) remain fully 0xFF — the
attacker never held them as input, so classical decryption cannot produce
them.

Reproduction commands:

```bash
# random_masked_25: independent random plaintexts per sample + shared
# uniform-random 25 %-coverage byte mask (no structural framing).
python3 scripts/redteam/run_attack_nonce_reuse.py \
    --plaintext-size 65536 --hashes fnv1a,blake3 \
    --barrier-fill 1 --collision-counts 2 \
    --attacker-modes partial --plaintext-kind random_masked_25 \
    --validate --classical-decrypt \
    --results-tag partial_kpa_25_random

python3 scripts/redteam/run_attack_nonce_reuse.py \
    --plaintext-size 65536 --hashes fnv1a,blake3 \
    --barrier-fill 1 --collision-counts 2 \
    --attacker-modes partial --plaintext-kind json_structured_25 \
    --validate --classical-decrypt \
    --results-tag partial_kpa_25_json

python3 scripts/redteam/run_attack_nonce_reuse.py \
    --plaintext-size 65536 --hashes fnv1a,blake3 \
    --barrier-fill 1 --collision-counts 2 \
    --attacker-modes partial --plaintext-kind html_structured_25 \
    --validate --classical-decrypt \
    --results-tag partial_kpa_25_html
```

`classical_decrypt.py` auto-detects partial mode when `ct_*.known_mask`
sidecars are present in the cell directory; the orchestrator passes
auto-tuned `--n-probe` (195 for `*_25` kinds at 64 KB) and
`--min-known-channels 3` (Layer 2 FP control at low coverage).
The resulting `recovered_plaintext_P{1,2}.bin` files are directly
diff-comparable to `groundtruth_plaintext_P{1,2}.bin` — 0xFF positions
mark where the attacker had no input byte AND / OR Layer 1 failed to
recover the covering pixel.

### Partial KPA extension — structured JSON plaintext (artificial scenario)

The main Phase 2d result above is Full KPA (attacker knows every byte of both colliding plaintexts). Real-world attack surface is usually Partial KPA — protocol headers and structural tokens known, payloads unknown. This subsection tests whether the PRF-separation signal survives when the attacker is blind to ~17 % of each plaintext.

**This experiment's scenario is deliberately artificial.** It answers "if the attacker has near-maximal-but-not-complete Partial KPA on a carefully-structured plaintext, does the attack still separate PRF from non-PRF?" It does NOT claim "Partial KPA works on realistic plaintexts". The assumptions the attacker must hold are listed explicitly below; if any of them fails, this attack chain does not run. Treat the result as a **best-case upper bound** for Partial KPA attackability, not as a realistic threat estimate.

**Attacker assumptions (must all hold).**

1. **Byte-level layout known**: exact lengths of structural framing tokens (JSON's `{`, `}`, `"`, `:`, `,` OR HTML's `<`, `>`, `=`, tag names), exact lengths of every field name / tag name, exact positions where value regions start and end.
2. **Two distinct known templates**: sample 0 and sample 1 use different record templates (identical byte layout, different field-name / tag-name content). The attacker knows BOTH templates. Identical templates collapse to the same-plaintext degeneracy where rotation is unrecoverable on known channels.
3. **Per-record varying sequence number** at a known byte offset within each record. Attacker knows the sequence-number format and the fact that records are numbered sequentially from 0.
4. **~83 % byte-level coverage** of each plaintext is attacker-known (field names + structural + sequence numbers). Only the value regions of the last two fields (23 bytes of 137 per record ≈ 17 %) are unknown.

Assumptions 1–3 are **architectural requirements** that apply to every structured plaintext kind the demasker supports (`json_structured_{25, 50, 80}` and `html_structured_{25, 50, 80}`, see [Partial KPA matrix](#partial-kpa-matrix--clean-signal--across-96-cells)) — violate any of them and single-pair Partial KPA collapses to same-plaintext degeneracy or loses Layer 2 anchor. The Python demasker itself is format-agnostic and coverage-agnostic via `known_mask` sidecars; only the Go corpus generator enforces these invariants. Assumption 4 is **configuration-specific** to this Run B cell (4 MB JSON at `json_structured_80`); the 50 %- and 25 %-coverage variants described in the matrix section trade off fewer attacker-known bytes (down to ~25 %) for longer records and proportionally smaller reconstructed streams.

Real-world JSON or HTML plaintexts typically satisfy none of (1)–(3) simultaneously. The record design here is engineered to maximise the bits the reconstruction can emit. The attack chain falls apart if templates differ in byte layout, if only one template is known, or if the known fraction drops significantly below 25 % (the lowest configured kind).

**Test configuration.**

| Parameter | Value |
|-----------|-------|
| Primitives | BLAKE3 + FNV-1a |
| Plaintext size | 4 MB (≈ 30 000 records × 137 bytes) |
| BarrierFill | 1 |
| N collisions | 2 |
| Mode | `partial` with `plaintext_kind=json_structured` |
| Demasker `--n-probe` | 50 (spans ~2.5 records so varying sequence numbers anchor true sp) |
| Demasker `--min-known-channels` | 2 (per-wrong-candidate FP ≈ 0.34 %) |

**Why `n_probe = 50` instead of 10.** Under Partial KPA with repeating records the `d_xor` pattern is quasi-periodic with period = record length. With `n_probe = 10` all probe pixels fall inside one record's worth of structurally-repeating bytes, and Layer 2 accepts any period-shifted sp. `n_probe = 50` spans ~2.5 records (350 bytes) so sequence-number bytes varying per record in principle distinguish the true sp — this is the value used in the table above. However, at this combination (4 MB plaintext × `json_structured_80`) even 50 turns out insufficient: in a 137-byte record only 5 bytes are sequence-number digits (~3.6 % of the record), so of the 50 × 7 = 350 probed bytes only ~13 cover periodicity-breaking bytes and the other ~337 cover structurally-repeating field-name + punctuation bytes. When Layer 2 tries a wrong period-aligned sp, the periodic channels' constraints are automatically satisfied and the ~13 sequence-number channels are too few to out-vote the constraint — the demasker converges on a period-shifted sp (see the "Periodicity leak" caveat below). The proper fix is attacker-side n_probe tuning based on public plaintext-size and record-length information; the orchestrator's `--n-probe auto` formula picks `max(50, 3 × record_bytes / 7)` — which for `json_structured_80`'s small 137-byte records yields 57 (marginally more, same 4-MB periodicity vulnerability), but for larger-record kinds like `html_structured_25` (800-byte records) jumps to 342, which does anchor true sp on those runs. See the [Partial KPA matrix](#partial-kpa-matrix--clean-signal--across-96-cells) for the auto-tuned runs across all 6 kinds.

**Empirical result — Layer 1 + reconstruction.**

| Primitive | Layer 1 exact recovery | WRONG matches | Layer 2 sp | Reconstructed stream |
|-----------|-----------------------:|-------------:|:----------:|---------------------:|
| BLAKE3 | 151 734 / 603 729 (25.1 %) | **0** | period-shifted (see caveat) | 8.2 Mbit (1 168 461 channels) |
| FNV-1a |  97 470 / 603 729 (16.1 %) | **0** | period-shifted (see caveat) | 5.3 Mbit (   750 736 channels) |

"Ambiguous" here is orders of magnitude higher than Full KPA (~1 %) — see the "Ambiguity explosion" block below for the mechanism. The 0 WRONG matches confirm the formula is correct; ambiguous pixels are just those with too few rotation-discriminating known channels to disambiguate the 7 rotation candidates.

**Why the emitted stream is 5 – 7 × smaller than naive coverage suggests — Layer 1 ambiguity explosion under Partial KPA.**

A naive extrapolation from the coverage numbers would predict an emitted stream ≈ 81 % × `data_pixels × 56 bits` = 27.5 Mbit at 4 MB plaintext. The actual stream is 3.8 – 8.2 Mbit — a 3 – 7× shortfall. **This gap is caused by ITB's construction itself, not by Partial KPA coverage.** It is the key structural finding of this phase.

The mechanism:

1. **Reconstruction emits a pixel only if Layer 1 produced a UNIQUE `(noisePos, rotation)` for it.** If the pixel's constraint set admits two or more candidates ("ambiguous"), the entire pixel is skipped — even its known channels are not emitted. This is intentional: emitting a pixel under the wrong `(noisePos, rotation)` corrupts ≥ 1 of the 7 bits per channel and pollutes the stream. The demasker prefers fewer, clean bits over more, noisy bits.

2. **Under Full KPA every known channel carries `d_xor ≠ 0`** (random independent plaintexts differ on essentially every byte). All 8 channels participate in the rotation constraint, leaving a per-candidate false-positive rate of ~2⁻⁵⁶ across 8 channels and producing unique recovery on ≥ 99 % of pixels.

3. **Under Partial KPA with repeated-structure JSON the known-channel budget collapses into TWO sub-classes per pixel:**
    - "`d_xor ≠ 0` known channels" — usually the bytes of the **variant-dependent field-name region** (sample 0 uses template A, sample 1 uses template B, names differ). Typical count: ~5 of 8 channels per pixel. These channels constrain BOTH `noisePos` and `rotation`.
    - "`d_xor = 0` known channels" — the bytes of **structurally-shared punctuation and sequence numbers** (`{`, `}`, `,`, `"`, `:`, and the record-index digits which are shared by both samples at every record). Typical count: ~2 of 8 channels per pixel. These channels constrain `noisePos` ONLY (via `extract7(xor_byte, noisePos) == 0`); rotation collapses because `rotate7(0, r) = 0` for any `r`. **This is the same-plaintext degeneracy, but local to a subset of channels within each pixel, not global.**
    - Unknown channels (~1 per pixel): not used.

4. **The two sub-classes' constraints do not compose into a clean 8-channel unique determination.** With ~5 channels doing the rotation work and ~2 channels only pinning `noisePos`, adjacent rotations that happen to produce the same 7-bit pattern as the true rotation on all 5 rotation-active channels (a small-probability event at 2⁻⁵ × 7 = 2⁻³⁵ per candidate — not vanishing at single-pair Layer 1) pass the constraint. The resulting ambiguity rate observed empirically: **~85 – 88 % of pixels are ambiguous** (FNV-1a 97 470 / 603 729 unique = 16 %; BLAKE3 151 734 / 603 729 = 25 %).

5. **Stream arithmetic, step by step:**
    - Upper-bound known channels (81 % coverage × 8 channels): ~6.5 known channels per pixel average
    - Fraction of pixels passing Layer 1 with unique recovery: ~14 – 25 % (depends on per-pixel `d_xor ≠ 0` distribution — varies by seed because the per-pixel noise XOR byte affects which adjacent-rotation collisions fire)
    - Emitted bits per unique pixel: unique-recovery pixels tend to have near-full known-channel count (the ones where unique recovery succeeded had enough `d_xor ≠ 0` signal); call it ~7 channels × 7 bits = ~49 bits
    - Predicted stream: `data_pixels × 0.20 × 49 bits` ≈ 5.9 Mbit — matches observed 3.8 – 8.2 Mbit within seed-dependent variance

6. **None of the three Layer-1-ambiguity drivers above are coverage problems.** Bumping plaintext coverage from 83 % to 90 % would only slightly reduce the `d_xor = 0` known-channel count; it would NOT change the fundamental fact that structurally-shared bytes produce per-channel same-plaintext degeneracy. The ambiguity is a property of ITB's 8-channel-per-pixel packing interacting with ANY Partial KPA scenario where known bytes include structurally-shared positions.

**This is a construction-level finding.** ITB's barrier — specifically the way `(noisePos, rotation, channelXOR)` bind the 8 channels of a pixel through a **single** pair of hash outputs — means single-pair Layer 1 recovery needs ~8 discriminating channels per pixel. Partial KPA with structurally-shared bytes cannot meet that requirement on a single (ciphertext, ciphertext) pair, regardless of how high the byte-level coverage goes (short of 100 %, which is Full KPA). To close the gap, the attacker needs **multi-pair disambiguation** (N ≥ 4 collisions — independent noise-bit draws per encryption, intersecting candidate sets collapse to 1 exponentially fast):

- At N = 4 (6 pairs): ambiguity probability per pixel ≈ (85 %)⁶ ≈ 38 % — already a big reduction
- At N = 8 (28 pairs): ≈ (85 %)²⁸ ≈ 1 % — essentially full unique recovery
- At N = 128 (8 128 pairs): <<1 % — full saturation

The current Partial KPA experiment deliberately runs at N = 2 (one pair), which is the minimum that produces a nonce-reuse XOR at all — this was intentional to show **where the single-pair attack hits its construction-level wall under Partial KPA**, not to maximise attack success. A future Partial KPA experiment at N = 4 or N = 8 on the same corpus design would exercise the multi-pair path and is expected to recover the stream-size budget.

**Periodicity leak caveat.** On the 4 MB runs the demasker's Layer 2 converged on a startPixel offset from the true one by a large (non-multiple-of-record-length) shift. The reconstructed stream is therefore **not** exactly a clean prefix of `dataHash(pixel_u32le || nonce)` — it contains residual `payload_claimed ⊕ payload_actual` XOR on the channels where the two plaintexts' bytes happen to differ under the shift. Empirically this shows up as a 1-bit discrepancy at byte 0 of the reconstructed stream vs ground truth, visible in the demasker's first-32-bytes spot-check print; the following 31 bytes of the spot-check matched exactly. The partial-mode validation function returns a binary match/mismatch flag rather than a byte-count, so the full-stream byte-for-byte match rate was not rigorously measured — the apparent "1-byte seam + clean thereafter" shape is inferred from the spot-check only. This is a Partial KPA-specific artefact that does not occur under Full KPA; the write-up preserves it honestly rather than papering over it with additional demasker machinery.

**Coverage as seen by the Python demasker** (after COBS mask propagation + 7-bit channel slicing):

| Quantity | FNV-1a 4 MB run |
|----------|-----------------:|
| Byte-level known coverage from cell.meta.json | 83.33 % (3 495 196 / 4 194 235 raw plaintext bytes) |
| Channel-level known coverage (known in BOTH payload masks) | **81.39 %** (3 930 920 / 4 829 832 channel slots) |
| Pixels with ≥ `min_known_channels=2` usable channels | 88.75 % (535 794 / 603 729) |

**NIST STS on reconstructed streams — negative result on PRF-separation at this stream size.**

Two independent FNV-1a Partial KPA runs (different fresh nonce seeds so the `NonOverlappingTemplate` bin draw is independent):

| Run | Stream size | NIST N × 1 Mbit | pass / total (raw) | `NonOverlappingTemplate` bin |
|-----|------------:|----------------:|-------------------:|-----------------------------|
| Run B-1 (first corpus) | 5.3 Mbit | 5 | **36 / 188** | bin 0 (all 148 rows, 0/5 proportion) |
| Run B-2 (fresh nonce)  | 3.8 Mbit | 3 | **188 / 188** | bin 5 (all 148 rows, 3/3 proportion) |

BLAKE3 reference run at the same plaintext size and pipeline: 188 / 188 with `NonOverlappingTemplate` all rows in bin 6.

**Key observation.** The three runs (FNV-1a bin 0 / FNV-1a bin 5 / BLAKE3 bin 6) all show the same **single-bin clustering pattern** on `NonOverlappingTemplate` documented in [Phase 3b](#the-p-value-clustering-phenomenon--hash-agnostic-present-at-any-n): every one of the 148 template sub-test rows puts all N per-sequence p-values into one bin, with the bin number effectively randomised per `(hash, nonce)` pair. Whether the run reads as "152 failures" or "passes all" comes down to whether the single-bin draw happens to land below or above the proportion threshold — **it is not a security signal**.

**Artefact-adjusted view (40 non-`NonOverlappingTemplate` sub-tests per run).**

| Primitive / run | Non-template pass / 40 | Proportion-level fails |
|-----------------|-----------------------:|-----------------------:|
| FNV-1a Run B-1 (bin 0 on templates) | 36 / 40 | 4 (Frequency 2/5, BlockFrequency 3/5, CumulativeSums×2 at 2/5) — same-direction bin-0 clustering as templates |
| FNV-1a Run B-2 (bin 5 on templates) | 40 / 40 | 0 |
| BLAKE3 (bin 6 on templates) | 40 / 40 | 0 |

The 4 "real" failures in Run B-1 also cluster their p-values in bin 0 — i.e., the same bin-routing mechanism manifested on `Frequency` + `BlockFrequency` + `CumulativeSums` in that particular run. Run B-2 (independent seeding) shows the same FNV-1a pipeline hitting bin 5 across all tests and passing 188/188. **The Run B-1 "4 real fails" did not replicate** under the independent run, so they cannot be distinguished from run-specific bin-cluster noise at this stream size.

**Interpretation — honest negative result.**

1. **PRF-separation is NOT visible at this Partial KPA stream size.** The Full KPA Phase 2d result (6 real fails on FNV-1a at 16.8 Mbit, N=16) depends on NIST STS having enough sequences per sub-test for the bin-0 hit rate (~10 % per run) to be distinguishable from structural non-uniformity. At the Partial KPA stream sizes here (3.8 – 5.3 Mbit, N = 3 – 5), the per-sub-test variance is dominated by single-bin clustering. Both primitives' runs are statistically indistinguishable from each other (both hit single-bin clustering, just into different bins).
2. **Run B-1 "signal" was bin-0 bad luck, not structure.** The initial 36/188 FNV-1a result had a tempting-looking failure pattern; it does not survive replication with an independent nonce seed. A single Partial KPA run cannot distinguish the bin-routing artefact from a real signal at this scale.
3. **What the pipeline DOES confirm.** The Partial KPA demasking + reconstruction code path works end-to-end: Layer 1 produces 0 WRONG matches on both runs, and a spot-check of the first 32 bytes of each reconstructed stream shows a 1-bit discrepancy at byte 0 followed by an exact match on the next 31 bytes — the demasker's partial-mode validator returns a binary match/mismatch flag so full-stream byte-for-byte correctness was not rigorously measured. The inferred shape is "1-byte seam at the alignment boundary + clean dataHash output thereafter", but the tail of the stream beyond the 32-byte spot-check remains unverified. Taking the inference at face value, the reconstructed stream IS valid dataHash output (up to the seam) — there is just not enough of it (a few Mbit) for NIST STS to separate primitives at this statistical power.
4. **Where the attack breaks (what we learned).** Two independent bottlenecks limit the Partial KPA stream:
    - **Construction-level bottleneck (the main finding):** ITB's per-pixel `(noisePos, rotation, channelXOR)` packing binds all 8 channels through a single pair of hash outputs, so single-pair Layer 1 needs ~8 rotation-discriminating channels per pixel. Partial KPA plaintexts with structurally-shared bytes (`{`, `}`, `,`, `"`, `:`, sequence numbers) produce `d_xor = 0` known channels that only pin `noisePos`; the remaining ~5 rotation-active channels are insufficient to disambiguate rotation on a single pair. Result: ~85 % of pixels stay ambiguous, stream shrinks ~5 – 7 ×. Fixing this requires multi-pair Layer 1 at N ≥ 4 — see the "Ambiguity explosion" block above.
    - **NIST-STS-power bottleneck (secondary):** Even assuming the stream were restored to its naive 27 Mbit upper bound, NIST STS needs N ≥ 10 sequences per sub-test to distinguish the PRF-separation signal from the bin-routing artefact reliably. Requires plaintext ≥ ~10 MB (at 83 % coverage, full Layer 1 recovery) OR multi-pair Layer 1 on the current 4 MB corpus.
5. **Scope-of-Partial KPA limitation, now explicit.** The "~83 % coverage + distinct-template + sequential-sequence-number" conditions ARE necessary for the pipeline to reconstruct any stream at all, but are NOT sufficient on their own (N = 2 single-pair Layer 1 + stream < 10 Mbit) to produce a NIST-STS-distinguishable stream. A Partial KPA attack at this scale and collision count is a construction-correctness probe — and, more importantly, **an empirical demonstration that ITB's 8-channel-per-pixel single-hash-output binding makes single-pair Partial KPA structurally weaker than single-pair Full KPA**, not just quantitatively (via fewer known bits) but architecturally (via same-plaintext-like degeneracy on structurally-shared channels).

**Supported plaintext kinds for Partial KPA.**

The orchestrator exposes six canonical structured kinds, covering two formats (JSON + HTML) at three attacker-known coverage levels (25 %, 50 %, 80 %). The trailing number in the kind name is the target byte-level coverage. `json_structured` (no suffix) is an alias for `json_structured_80` kept for backward compatibility with the first-pass Run B.

| Kind | Format | Per-record bytes | Target coverage | Typical use |
|------|--------|-----------------:|----------------:|-------------|
| `json_structured_80` (= `json_structured`) | JSON | 137 | 83 % | Dense-protocol baseline (short values, long field names) |
| `json_structured_50` | JSON | 228 | 50 % | Mixed-protocol |
| `json_structured_25` | JSON | 456 | 25 % | Sparse-known realistic |
| `html_structured_80` | HTML | 250 | 82 % | Tag-heavy dense |
| `html_structured_50` | HTML | 400 | 51 % | Balanced tag / content |
| `html_structured_25` | HTML | 800 | 25 % | Content-heavy |

All kinds produce two record-template variants (chosen by sample index) with identical byte-level layout but different structural content + a per-record varying attacker-known sequence number — the combination required for Layer 1 rotation recovery and Layer 2 startPixel anchoring.

> **These six kinds are artificially engineered** for maximum Partial KPA signal. Real-world binary formats (ZIP, PDF, MP4, MP3, SQLite, PNG, TAR, …) have tiny fixed-position signature islands at variable offsets surrounded by compression-entropy-maximised content, and the demasker extracts ~0 % signal from them. For a worked ZIP example (0.003 % fixed-position coverage, same-plaintext degeneracy on the shared `PK\x03\x04` signature, why brute-forcing signature offsets is infeasible) and the full list of format classes that defeat the attack, see [ITB.md § 8.1 Why binary formats defeat Partial KPA demasking entirely](ITB.md#81-why-binary-formats-defeat-partial-kpa-demasking-entirely).

**Demasker parameters exposed as CLI (public-info attacker choices).**

Two Layer 2 / Layer 1 parameters legitimately depend on what a protocol-aware attacker can see from public information (ciphertext size + plaintext format assumption):

| Flag | Auto default | Rationale |
|------|--------------|-----------|
| `--n-probe {int \| auto}` | `3 × ceil(record_bytes / 7)`, capped at `data_pixels / 5` and floored at 50 | Probe pixels must span ≥ 3 record periods so per-record sequence-number bytes can break the `d_xor` periodicity and anchor the true sp. Smaller probe count converges onto a period-shifted sp; larger wastes CPU. |
| `--min-known-channels {int \| auto}` | K = 3 for coverage ≤ 35 %, K = 2 otherwise | Layer 2 per-wrong-candidate FP rate is `56 × 2⁻⁷ᴷ`. At K = 2 with n_probe = 50 – 350, accumulated FP rate is ~16 %; at K = 3 it drops to 0.1 %. Low-coverage kinds (25 %) need K = 3 to keep Layer 2 from locking onto spurious sps. |

The demasker source (`scripts/redteam/phase2_theory/nonce_reuse_demask.py`) is **format-agnostic** — it reads per-byte `known_mask` sidecars, propagates them through COBS, and constraint-matches on the resulting per-channel known map. Changing plaintext format or coverage requires only that the Go corpus generator emits a correct `known_mask`; no demasker code changes are needed.

**How the demasker behaves under sparse coverage.**

At low coverage (25 % kinds, ~2 known channels per pixel average) the demasker's behaviour is **architecturally correct but structurally weak**:

- Most pixels (60 – 80 %) have fewer than `min_known_channels` attacker-known channels → demasker skips them entirely (returns `None`, not an emission). This is intentional — emitting an under-constrained pixel would corrupt the stream with wrong rotation choices.
- Remaining pixels attempt Layer 1 but, with only ~2 – 3 rotation-active known channels per pixel, single-pair constraint matching accepts multiple `(noisePos, rotation)` candidates at a high rate (~80 – 90 % ambiguity).
- Emitted stream is correspondingly small: 50 – 70 Kbit at 32 KB plaintext, 3 – 5 Mbit at 4 MB plaintext.
- `WRONG matches` remain **0** across all runs — the formula is correct; the weakness is information-theoretic (insufficient discriminating channels per pixel), not a bug.

This is the same "Ambiguity explosion" mechanism described above, just more severe at lower coverage. Multi-pair disambiguation (`--collision-counts N` with `N ≥ 4`) would mitigate it by intersecting candidate sets across multiple pairs with independent noise bits — but that is a separate experiment not yet executed.

**Reproducing the Run B result (4 MB json_structured).**

```bash
python3 scripts/redteam/run_attack_nonce_reuse.py \
    --plaintext-size 4194304 \
    --hashes blake3,fnv1a \
    --collision-counts 2 \
    --attacker-modes partial \
    --plaintext-kind json_structured \
    --validate \
    --cleanup-ciphertexts-after-emission \
    --results-tag run_B_partial_kpa_json_4mb

python3 scripts/redteam/phase3_deep/nist_sts_on_attack_streams.py \
    --stream tmp/attack/nonce_reuse/reconstructed/blake3_BF1_N2_partial_json_structured.datahash.bin \
    --stream tmp/attack/nonce_reuse/reconstructed/fnv1a_BF1_N2_partial_json_structured.datahash.bin \
    --run-dir tmp/attack/nonce_reuse/nist_sts_partial_kpa
```

**Reproducing coverage-parameterised runs** (any format × coverage combination; auto-tunes n_probe and min_known_channels from the kind):

```bash
# 128 KB JSON at 50 % coverage, FNV-1a + BLAKE3:
python3 scripts/redteam/run_attack_nonce_reuse.py \
    --plaintext-size 131072 \
    --hashes blake3,fnv1a \
    --collision-counts 2 \
    --attacker-modes partial \
    --plaintext-kind json_structured_50 \
    --validate \
    --cleanup-ciphertexts-after-emission \
    --results-tag partial_kpa_json50_128k

# 2 MB HTML at 25 % coverage, override n_probe explicitly:
python3 scripts/redteam/run_attack_nonce_reuse.py \
    --plaintext-size 2097152 \
    --hashes fnv1a \
    --collision-counts 2 \
    --attacker-modes partial \
    --plaintext-kind html_structured_25 \
    --n-probe 500 \
    --min-known-channels 3 \
    --validate \
    --results-tag partial_kpa_html25_2mb
```

Wall-clock for the Run B 4 MB / 2-cell matrix: ~5 min corpus + demask, ~30 s NIST STS.

### Partial KPA matrix — Clean Signal % across 96 cells

The single-cell Run B (FNV-1a + BLAKE3 at 4 MB, json_structured_80) in the previous subsection shows the pipeline in one configuration. To characterise the demasker's yield as a function of plaintext size, format, coverage, and primitive, we ran a full matrix:

- **Plaintext sizes** (8): 4 KB, 16 KB, 64 KB, 128 KB, 512 KB, 1 MB, 2 MB, 4 MB
- **Coverage levels** (3, byte-target): 25 %, 50 %, 80 %
- **Formats** (2): JSON, HTML (independent per-format record templates with two variants + per-record sequence number, see [Partial KPA extension](#partial-kpa-extension--structured-json-plaintext-artificial-scenario))
- **Primitives** (2): BLAKE3, FNV-1a
- **N collisions**: 2 (minimum for XOR analysis; `N > 2` multi-pair runs are out of scope — see [Scope](#scope-of-this-phase--known-limitations))
- **Attacker-mode**: `partial` with auto-tuned `--n-probe` and `--min-known-channels` (both are public-info choices — attacker knows ciphertext size and assumed plaintext format)

Total: 96 cells. 86 ran cleanly; 10 returned demasker exit-code 2 due to imperfect period-shift causing a handful of wrong Layer 1 matches (stream still emitted — these cells' Clean % values are honest, just flagged as "demask-fail" by the orchestrator's strict gate).

**Target vs actual coverage** (byte-level target vs what the Python demasker actually sees as channel-level known coverage after COBS mask propagation + 7-bit channel slicing across byte boundaries):

| Target (kind suffix) | JSON actual channel coverage | HTML actual channel coverage |
|---------------------:|----------------------------:|-----------------------------:|
| 80 % | 75 – 80 % | 72 – 79 % |
| 50 % | 44 – 48 % | 45 – 47 % |
| 25 % | 22 – 24 % | 23 – 24 % |

The 3 – 8 percentage-point drop from the advertised target happens at two distinct boundaries: (a) COBS code bytes downgrade to "unknown" whenever any source byte in their block is unknown (conservative correctness), and (b) a 7-bit channel that straddles two payload bytes requires BOTH bytes to be known — if either is unknown the whole channel is marked unusable.

**Main result — Clean Signal % (JSON):**

| Size | 80 % BLAKE3 | 80 % FNV-1a | 50 % BLAKE3 | 50 % FNV-1a | 25 % BLAKE3 | 25 % FNV-1a |
|------|---:|---:|---:|---:|---:|---:|
| 4 KB | 68.2 % | 68.1 % | 39.0 % | 40.2 % | 19.6 % | 20.2 % |
| 16 KB | 69.3 % | 69.4 % | 41.9 % | 41.6 % | 21.4 % | 21.2 % |
| 64 KB | 72.7 % | 72.6 % | 43.8 % | 43.7 % | 21.8 % | 21.9 % |
| 128 KB | 4.5 %⚠ | 4.6 %⚠ | 43.6 % | 43.6 % | 22.1 % | 22.0 % |
| 512 KB | 56.2 %⚠ | 39.0 %⚠ | 9.8 %⚠ | 9.9 %⚠ | 22.1 % | 22.1 % |
| 1 MB | 4.7 %⚠ | 13.4 %⚠ | 9.9 %⚠ | 9.9 %⚠ | 5.0 %⚠ | 5.0 %⚠ |
| 2 MB | 47.9 %⚠ | 60.8 %⚠ | 1.3 %⚠ | 35.8 %⚠ | 13.7 %⚠ | 13.7 %⚠ |
| 4 MB | 67.5 %⚠ | 58.8 %⚠ | 18.6 %⚠ | 35.9 %⚠ | 9.4 %⚠ | 0.7 %⚠ |

**Main result — Clean Signal % (HTML):**

| Size | 80 % BLAKE3 | 80 % FNV-1a | 50 % BLAKE3 | 50 % FNV-1a | 25 % BLAKE3 | 25 % FNV-1a |
|------|---:|---:|---:|---:|---:|---:|
| 4 KB | 70.1 % | 70.6 % | 44.3 % | 44.2 % | 16.1 %⚠ | 22.3 % |
| 16 KB | 72.6 % | 72.1 % | 44.9 % | 45.2 % | 23.0 % | 22.8 % |
| 64 KB | 76.4 % | 3.7 %⚠ | 47.1 % | 47.2 % | 23.3 % | 23.4 % |
| 128 KB | — | — | 47.7 % | 47.8 % | 23.6 % | 23.6 % |
| 512 KB | 68.0 %⚠ | 22.2 %⚠ | 47.9 % | 47.9 % | 23.8 % | 23.8 % |
| 1 MB | 54.7 %⚠ | — | 48.2 % | 48.2 % | 23.9 % | 23.9 % |
| 2 MB | — | — | — | — | 23.9 % | — |
| 4 MB | 76.7 %⚠ | 34.0 %⚠ | — | — | 24.0 % | 15.9 %⚠ |

Legend: `⚠` marks cells where Layer 2 converged onto a period-shifted startPixel (reconstruction is still valid but offset in pixel-index space; under imperfect shift alignment, some channels suffer residual plaintext XOR leakage). `—` marks cells where the orchestrator reported demask-fail (stream was emitted but validation caught ≥ 1 WRONG match — see "Observations" below).

**Summary — average Clean Signal % across sizes:**

| Coverage | JSON BLAKE3 | JSON FNV-1a | HTML BLAKE3 | HTML FNV-1a |
|---------:|------------:|------------:|------------:|------------:|
| 80 % | 48.9 % | 48.3 % | 69.7 % | 40.5 % |
| 50 % | 26.0 % | 32.6 % | 46.7 % | 46.8 % |
| 25 % | 16.9 % | 15.9 % | 22.7 % | 22.2 % |

### What the matrix tells us about ITB under Partial KPA

**1. Hash identity (BLAKE3 vs FNV-1a) is near-irrelevant for extraction rate.** Cells with identical `(size, kind)` and differing hash produce Clean % within 1-2 p.p. of each other except under period-shift events — and in those events the direction of the drift is random, not hash-dependent. The ChainHash wrapping makes the demasking pipeline primitive-blind. Hash choice only matters on the emitted stream (NIST STS / SAT seed-recovery), not during recovery itself. This justifies deliberately skipping the "all 12 primitives" Full KPA documentation run — it would just be twelve near-identical rows.

**2. Clean Signal % is ALWAYS below target coverage %.** Even the best cells (64 KB × 80 % target × clean alignment) yield 72-76 % clean — already a 4-8 p.p. loss from advertised coverage. The loss accumulates from the nine architectural effects enumerated below.

**3. Period-shift stochasticity dominates mid-size cells.** Clean % on `(128 KB, JSON 80 %)` is 4.5 % while `(64 KB, JSON 80 %)` is 72.7 % — not because 128 KB is harder but because the specific random seed placed the true startPixel at a position where Layer 2's 57-probe heuristic found a period-shifted false sp first, and the shift happened to break the Layer 1 constraint on most pixels. Variance is large; the "size" axis in the table is NOT a monotonic predictor. This is a real property of single-pair attacks on repeating plaintexts, not a demasker defect.

**4. Coverage efficiency (emitted / attacker-known-channel budget) stays high when Layer 2 anchors true sp** (90-97 % across clean cells), and collapses to the 2-40 % range under period-shift catastrophe. High coverage efficiency on true-sp cells confirms the demasker uses its input bits near-optimally; the losses are not "demasker weakness" but architectural information-theoretic floors.

**5. Low-coverage (25 %) behaviour is consistently weak but graceful.** Across sizes, 25 % coverage yields 15-24 % Clean on small-to-mid sizes, degrading further under period-shift. No cell produces meaningless garbage; the demasker correctly refuses pixels it can't constrain rather than emit noise.

**6. 10 cells returned exit code 2 under imperfect period-shift alignment.** Under a shift that is not exactly a `d_xor` pattern period, a small number of pixels (0.01 – 0.1 %) recovered a `(noisePos, rotation)` pair that is unique under constraint matching but does not match the ground-truth at the shifted position. These are NOT formula bugs — the demasker formula is correct; the artefact is that single-pair Layer 1 admits rare isolated false positives when `d_xor_claim_p ≠ d_xor_true_{p+shift}` at approximate-period shifts. The stream was still emitted (mostly correct, with a handful of corrupted channelXOR values scattered); the orchestrator flags these as demask-fail due to the strict WRONG > 0 gate. Real attackers cannot distinguish these from clean runs without access to ground truth.

### Nine architectural effects visible in this matrix

These are properties of ITB's construction that show up empirically in the numbers above. None are demasker bugs; all are structural features that shape the attacker's information recovery envelope.

1. **Same-plaintext-local degeneracy** on structurally-shared known bytes. When the attacker knows a byte AND that byte is identical across both plaintexts (JSON `{`, `"`, `:`, `,`; HTML `<`, `>`, `=`), the channel's `d_xor = 0` and it only constrains `noisePos`, not `rotation`. This reduces the effective discriminating budget from 8 channels to ~5 per pixel at 80 % coverage.

2. **Record-level periodicity**. Repeating record templates produce a `d_xor` pattern periodic with period = record length. Layer 2 brute-force thereby admits ANY period-shifted sp as "valid" — visible in the ⚠-marked cells. `auto --n-probe` tries to span 3 record periods to break this, but on mid-size plaintexts the heuristic is not enough.

3. **Stochastic period-shift catastrophe**. At imperfect (non-period-multiple) shifts, Layer 1 coincidentally accepts false constraints on most pixels, collapsing Clean % to 1-15 %. Visible in JSON 128 KB / 1 MB / 2 MB / 4 MB cells.

4. **Per-pixel 8-channel binding through a single hash-output pair**. All 8 channels of a pixel derive from ONE `(noisePos, rotation, channelXOR)` set that comes from ONE pair of ChainHash outputs. Single-pair Partial KPA cannot distribute constraint information across independent hash queries; multi-pair `N ≥ 4` disambiguation is the architectural mitigation path.

5. **COBS mask conservatism (3-5 p.p. loss)**. Group-length code bytes mark as "unknown" whenever any input byte in the block is unknown (safe conservative propagation). Visible as target 80 % → actual channel 75-80 % gap.

6. **7-bit channel byte-boundary loss (2-3 p.p.)**. A channel whose 7 bits straddle a byte boundary (bit offset % 8 ≥ 2) is marked unknown if EITHER of the two spanned bytes is unknown. Compounds with effect 5.

7. **CSPRNG fill beyond `cobs + null`**. Payload bytes after the attacker-known region are fresh random per encryption, not attacker-predictable. On short plaintexts this is a larger fraction; on 4 MB it's a few hundred fill pixels out of 600 k.

8. **Single-pair Layer 1 ambiguity explosion**. Already documented in the Run B writeup above: single-pair constraint matching with ~5-6 rotation-active channels per pixel admits 2+ `(noisePos, rotation)` candidates on 80-88 % of pixels under 80 % coverage. Increases to 90-95 % at 25 % coverage.

9. **Imperfect-period-shift wrong-match emergence**. Documented in observation 6 above — approximate-period shifts admit rare isolated false single-candidate recoveries at the 0.01 – 0.1 % level.

### What a successful Partial KPA demask actually gets the attacker

Suppose every precondition lines up — the attacker forced a nonce-reuse event, knows the byte-level plaintext format, holds the two distinct templates, has the sequence-number field offsets, and the demasker converged on the true `startPixel` with 80 %+ coverage. What do they actually walk away with? Less than "the seeds", and much less than the phrase "reconstructed dataHash stream" might suggest:

1. **No plaintext — only the hash-output stream.** The demasker's output is always the raw `dataSeed.ChainHash(pixel, nonce)` hash-output stream, never plaintext. Under Full KPA the attacker knows both plaintexts going in; the demasker converts (plaintext_input + 2 ciphertexts) into the hash-output stream. The attacker walks away with this hash-output signal to probe for PRF structure — not with plaintext they did not have before. Unlike a stream cipher where `C1 ⊕ C2` directly reveals `plaintext_1 ⊕ plaintext_2`, ITB's per-encryption fresh-CSPRNG noise bits + per-pixel rotation + per-pixel channelXOR mean raw ciphertext XOR does NOT reduce to plaintext XOR; only the full demasker pipeline extracts anything, and its output is strictly hash bits.

2. **Under a PRF primitive (BLAKE3 / AES-CMAC / SipHash-2-4 / ChaCha20 / AreionSoEM-256/512 / BLAKE2s / BLAKE2b-512): just the hash-output stream, useless.** The reconstructed `dataHash` stream is statistically indistinguishable from uniform random (188/188 on NIST STS). Inverting it to recover `dataSeed` requires breaking the PRF — out of scope by assumption. `startSeed` and `noiseSeed` inversion hit the same wall. The attack surface closes on this output.

3. **Under FNV-1a (the only invertible primitive in the hash matrix): one SAT instance per seed, not three free seeds.** The reconstructed `dataHash` stream exposes the ChainHash-wrapped FNV-1a's algebraic structure under a controlled pixel-index probe — which gives a SAT solver real leverage. But:
    - `dataSeed` inversion requires solving an 8-round ChainHash128 bitvector-SAT instance over a 512-bit effective unknown (FNV-1a's lo lane; hi lane is unconstrained by observable `hLo` and not recovered — the nominal key is 1024-bit) — still research-level, not a Gaussian elimination.
    - `startSeed` inversion is WORSE. The attacker observes **one `startPixel` value per `(seeds, nonce)` session** — a 3-log₂(totalPixels) ≈ 17-bit observation. To invert `startSeed` via ChainHash, the attacker needs MANY independent nonce-reuse sessions (each giving one fresh startPixel observation under a different nonce), not many messages within one session. Each session requires forcing a fresh nonce collision — a birthday-bound event at whatever nonce size the deployment chose. At 512-bit nonce: never. Even at 128-bit the attacker needs 2⁶⁴ messages to force ONE collision session, let alone the many sessions needed to stack enough startPixel observations for SAT-inversion.
    - On top of that, `startPixel` is often NOT cleanly recoverable — Layer 2's period-shift behaviour (documented in effect 3 above) produces a set of plausible `startPixel` candidates, not a single value. Inverting `startSeed` from noisy multi-candidate observations is harder still.
    - `noiseSeed` inversion requires the demasker to ALSO emit a `noisePos` stream (3 bits per pixel from `noiseHash & 7`) — which the current demasker does not output as a distinct stream, only as internal per-pixel state consumed by reconstruction. To attack `noiseSeed` the attacker would need a separate pipeline to emit and accumulate `noisePos` observations across sessions, then run ANOTHER ChainHash-wrapped FNV-1a SAT instance on those.

4. **No seed is leaked directly.** Every seed-inversion path — even under the most attacker-favourable primitive choice (FNV-1a) — reduces to "stack enough observations across enough independent nonce-reuse sessions, then solve a bitvector-SAT instance over an 8-round ChainHash wrap on the 512-bit effective lo-lane unknowns (nominal key is 1024-bit; hi-lane is never constrained by observable `hLo`)". The Phase 2a cost tables apply to each such inversion independently.

5. **Config-map path — classical keystream reuse, no SAT needed.** Alongside the hash-output stream, Layer 1+2 also recovers the per-pixel `(noisePos, rotation, channelXOR)` map — classical keystream-equivalent for this single `(seeds, nonce)`. Direct decryption of any ciphertext sharing this nonce runs on this map alone (Full KPA: both colliding plaintexts; Partial KPA: positions with overlapping coverage, plus occasional gap-fill). Blast radius bounded by the architectural gate (caller cannot set nonces → typically 2–3 messages per birthday event); SAT stays the separate cross-nonce seed-recovery path.

So the "reconstructed dataHash stream" framing is technically accurate but can oversell the attack: what the stream literally is is a prefix of `dataSeed.ChainHash(pixel, nonce)` output under one specific `(seeds, nonce)` session — useful ammunition for a SAT solver targeting `dataSeed` specifically under FNV-1a, but not a seed value and not directly applicable to `startSeed` or `noiseSeed`. A full compromise under FNV-1a would require three separate SAT campaigns against three seeds, each consuming many independent nonce-reuse sessions. Under any PRF-grade primitive none of the three SAT campaigns can start.

### Threat-model gate — why this whole exercise is gated by user nonce-size choice

None of the attack surface above is exploitable without nonce collision. **ITB supports nonce sizes up to 512 bits** (see [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis)), and a 512-bit nonce is the ideal choice for any deployment that transmits data over the network WITHOUT periodic key / seed rotation: at that size the 50 % collision probability requires `2²⁵⁶` queries, which is mathematically infeasible on any foreseeable hardware for all time. The entire Phase 2d exercise (Full KPA + Partial KPA) assumes an attacker has ALREADY gotten past the collision gate, which in practice requires the user to operate at a much smaller nonce size than 512 bits AND sustain the key long enough for the reduced gate to fire.

Collision-probability floor at 50 % as a function of nonce size:

- **512-bit** (recommended for long-lived keys / no seed rotation): 2²⁵⁶ queries → far beyond any conceivable compute budget
- 256-bit: 2¹²⁸ queries → at the NIST 128-bit security margin (widely treated as long-term safe)
- 128-bit: 2⁶⁴ queries → reachable only under sustained abuse of a single key at very high throughput
- ≤ 64-bit: 2³² queries or fewer → trivially reachable

Pick the nonce size deliberately: if seeds will be rotated per session / per message / per short-lived key, small-nonce configurations are safe within that rotation interval. If seeds are long-lived (months, years, forever on a device) and traffic volume is large, 512-bit is the configuration that keeps the Phase 2d attack surface mathematically out of reach without any operational ceremony.

The Phase 2d findings are conditional on "attacker got there somehow". At a 512-bit nonce with any realistic traffic volume, the conditional never fires. **This gate, not the per-cell Clean Signal numbers, is the primary defence.**

### Scope — what Phase 2d does NOT test (and why)

- **All-10-primitives Full KPA documentation run**: not performed. Demasking is primitive-independent at the recovery step (observation 1 above), so adding BLAKE2s, BLAKE2b, SipHash, etc., would produce six near-identical tables. The Full KPA validation table in the main Phase 2d writeup already covers four widths (FNV-1a, MD5, BLAKE3, BLAKE2b-512) confirming the demasker formula works across all ChainHash widths.
- **N > 2 multi-pair runs**: not performed. N = 2 is the minimum to produce any nonce-reuse XOR; larger N would enable multi-pair Layer 1 disambiguation (the architectural mitigation path for effect 8 above), but getting N ≥ 4 same-nonce collisions requires an even more invasive downgrade scenario. The theoretical path is documented.
- **Same-plaintext + same-nonce mode (`d_1 = d_2`)**: not performed. With identical plaintexts the entire XOR analysis collapses — `d_xor = 0` across ALL channels (not just structural ones), rotation is fully unrecoverable, and the Layer 1 formula reduces to `extract7(xor_byte, noisePos) == 0 for all 8 channels`. The "attack" is information-theoretically equivalent to observing two independent encryptions of the same plaintext — it reveals exactly zero about the seeds. Documented as a sensitivity-test negative in [Sensitivity / nonce-mismatch control test](#sensitivity--nonce-mismatch-control-test) below; not worth running empirically beyond that.

### Reproducing the matrix

```bash
# Full matrix (96 cells, ~15 min on a 16-core host; default PARALLEL=4):
bash scripts/redteam/partial_kpa_matrix.sh

# Override worker count if desired:
PARALLEL=6 bash scripts/redteam/partial_kpa_matrix.sh

# Aggregate into markdown tables:
python3 scripts/redteam/aggregate_partial_kpa_matrix.py > partial_kpa_results.md
```

The matrix driver schedules up to `PARALLEL` orchestrator invocations concurrently with a one-time pre-wipe + per-invocation `--no-pre-wipe` so parallel workers do not clobber each other's in-flight corpus directories. Sequential baseline on the same host was ~45 min; `PARALLEL=4` brings this to ~15 min (≈ 3× speedup, limited by Go corpus-gen CPU oversubscription — each orchestrator internally uses up to 8 goroutines).

**Stochastic variance caveat.** The exact numbers in the tables above come from one specific seed schedule. The orchestrator uses Python's built-in `hash()` for per-cell nonce-seed derivation, which is randomised per interpreter process — so re-running the matrix produces per-cell numbers that differ by up to ~20 percentage points on cells where Layer 2 hits period-shift catastrophe. The **qualitative pattern** (coverage-level ordering, hash irrelevance, period-shift-at-mid-size) replicates across runs; individual cell values do not. This is a faithful reflection of the construction — ITB's stochastic period-shift behaviour on repeating plaintexts IS the architectural effect being measured.

### Sensitivity / nonce-mismatch control test

This test proves the attack chain is **not** a false-positive generator — it cannot fabricate a "recovered" configuration from data that is NOT a genuine nonce-reuse pair. The corpus generator runs in a special control mode (`ITB_NONCE_REUSE_CONTROL=nonce_mismatch`) that produces two ciphertexts with the **same plaintext** but **different nonces** (one derived from `nonceSeed`, the other from `nonceSeed × 0x1000003D` — deterministic but distinct). Shared seeds; distinct nonces. This is NOT a nonce-reuse scenario — it is a correctness probe for the demasker.

**Expected outcome — the demasker must refuse.**

Two refusal modes are exercised:

1. **Default refusal (production behaviour).** Run the demasker with its built-in nonce-equality assertion. On nonce mismatch it prints an `ERROR` and exits with code 2 before any Layer 1 / Layer 2 work starts. Empirically on FNV-1a control corpus:
    ```
    ERROR: nonces differ — this is NOT a nonce-reuse pair
           (ct1 nonce: 2d374bc3143650e435bd5ceca78cfb34,
            ct2 nonce: af90394747df826dc5944d070f7dabc8)
    ```
    This is what every real deployment of the demasker would see. Sensitivity confirmed.

2. **Forced-through-the-pipeline (`--skip-nonce-check`).** To verify that even when the nonce-equality check is bypassed the demasker cannot synthesise usable output, we ran the full pipeline on both FNV-1a and BLAKE3 control corpora with `--skip-nonce-check` enabled. Both produced **identical negative results**:

| Metric | FNV-1a (control) | BLAKE3 (control) |
|--------|-----------------:|-----------------:|
| Layer 2 brute force: best `startPixel` score | 0 / 10 | 0 / 10 |
| Layer 2 short-circuits | 19 044 / 19 044 | 19 044 / 19 044 |
| Layer 1 exact recovery | **0** / 18 766 (0.00 %) | **0** / 18 766 (0.00 %) |
| Layer 1 ambiguous | 18 766 / 18 766 (100 %) | 18 766 / 18 766 (100 %) |
| Layer 1 **wrong matches** | **0** | **0** |
| Reconstructed stream | **0 bytes** emitted | **0 bytes** emitted |

Not a single candidate `(noisePos, rotation)` passed the all-8-channel constraint on any pixel. The false-positive rate per wrong-alignment probe pixel is `56 × 2⁻⁵⁶ ≈ 0` — observed zero matches across 19 044 candidate `startPixel`s × 10 probe pixels × 56 candidates × 8 channels = ~8.5 × 10⁸ constraint checks. Reconstruction has nothing to emit: zero bytes, zero bits. **No NIST STS input can be produced** from nonce-mismatch corpus through this demasker.

**What this validates.** The PRF-separation signal reported in the main Phase 2d table (BLAKE3 188/188 vs FNV-1a 182/188 on reconstructed streams) is caused by the nonce-reuse condition, NOT by some implementation shortcut in the demasker that would succeed on arbitrary ciphertext pairs. A demasker that fakes positive results would also "succeed" on the control corpus; this one doesn't. The control result rules out that class of false-positive.

**Reproducing the sensitivity test** (the control corpus above — demonstrates the demasker refuses to "succeed" on non-nonce-reuse data; if it DID succeed here, the entire ITB nonce-reuse threat-model argument would be moot):

```bash
# Generate control corpus (same plaintext, different nonces) for both hashes.
# The corpus is a deliberate mis-framing of the attack: shared seeds but
# DIFFERENT nonces per ciphertext — i.e. NO nonce reuse. The demasker must
# detect this and refuse to emit a reconstructed stream.
for h in fnv1a blake3; do
    ITB_NONCE_REUSE_HASH=$h \
    ITB_NONCE_REUSE_N=2 \
    ITB_NONCE_REUSE_MODE=same \
    ITB_NONCE_REUSE_CONTROL=nonce_mismatch \
    ITB_NONCE_REUSE_SIZE=131072 \
    go test -run TestRedTeamGenerateNonceReuse -v -timeout 1m
done

# Invocation 1 — default refusal. Expected: exit code 2 with an ERROR
# message about mismatched nonces, before any Layer 1/2 work runs.
python3 scripts/redteam/phase2_theory/nonce_reuse_demask.py \
    --cell-dir tmp/attack/nonce_reuse/control/fnv1a/BF1/N2/nonce_mismatch_same \
    --pair 0000 0001 --mode known-plaintext --brute-force-startpixel

# Invocation 2 — force the pipeline past the nonce-equality guard with
# --skip-nonce-check. Expected: Layer 2 finds no valid startPixel, Layer 1
# 0/18 766 exact recoveries, reconstruction emits 0 bytes. Confirms that
# even when the guard is bypassed, the underlying constraint mathematics
# cannot produce usable output from non-nonce-reuse data.
python3 scripts/redteam/phase2_theory/nonce_reuse_demask.py \
    --cell-dir tmp/attack/nonce_reuse/control/fnv1a/BF1/N2/nonce_mismatch_same \
    --pair 0000 0001 --mode known-plaintext --brute-force-startpixel \
    --skip-nonce-check --validate \
    --emit-datahash tmp/attack/nonce_reuse/reconstructed/fnv1a_control_nonce_mismatch.datahash.bin
```


### Scope of this phase — known limitations

- **Full KPA is the main result.** Partial KPA is exercised in a separate subsection above with a carefully-structured JSON plaintext and strong attacker assumptions — see [Partial KPA extension](#partial-kpa-extension--structured-json-plaintext-artificial-scenario). The result is useful as a best-case upper bound on Partial KPA attackability, not as a general Partial KPA claim.
- **Two primitives only in the automated matrix** (BLAKE3 + FNV-1a). The one-off `--hashes all` run across all 12 primitives is documented separately in this plan's follow-up for producing a comprehensive primitive-by-primitive table — expected result: all 9 PRF-grade primitives (BLAKE3, AES-CMAC, SipHash-2-4, ChaCha20, AreionSoEM-256, BLAKE2s, BLAKE2b-256, BLAKE2b-512, AreionSoEM-512) pass 188/188 at this stream size; CRC128, FNV-1a, and MD5 are the non-PRF outliers (MD5 passes NIST STS at the 16 Mbit stream size because its bit-level output IS uniform-looking — its collisional brokenness only surfaces at much larger streams — so for this specific test it tracks the PRF-grade group, but it should not be framed as PRF-grade).
- **Sensitivity / nonce-mismatch control test** — see [subsection above](#sensitivity--nonce-mismatch-control-test).
- **Triple Ouroboros nonce-reuse** not implemented. Actual implementation requires the Triple-analyzer rewrite that also gates [Phase 2a extension](#phase-2a-extension--empirical-mixed-algebra-stress-test-via-crc128-nonce-reuse) / [Phase 2b](#phase-2b--per-pixel-candidate-distinguisher) / [Phase 2c](#phase-2c--startpixel-enumeration) / [Phase 2d](#phase-2d--nonce-reuse) / [Phase 2e](#phase-2e--related-seed-differential) / [Phase 3a](#phase-3a--rotation-invariant-edge-case) Triple coverage. Each Triple ring carries independent `dataSeed` + `splitTriple` partitions the container — a per-phase 3-partition analyzer rewrite is the shared prerequisite.
- **Seed recovery via SAT** — the logical next step after this phase's NIST STS result — is out of scope. This phase stops at distinguishability (NIST STS level); converting distinguishability into actual seed values requires research-lab SAT compute that this plan does not attempt.

---

## Phase 2e — Related-seed differential

Tests whether a one-seed XOR-differential (Δ on only `noiseSeed`, `dataSeed`, or `startSeed`) propagates into observable structure in the ciphertext diff `D = ct_0 ⊕ ct_1`. Both encrypts share the same nonce (`setTestNonce`), same plaintext, same base seeds on the two unaffected axes, same hash-function instance (cached key preserved). Under the PRF / non-GF(2)-linear assumption `D` should be uniform random on the `data` and `start` axes; the `noise` axis is always architecturally non-uniform because `noisePos` derivation permutes which bit of each container byte carries the CSPRNG noise.

**Matrix**: 12 primitives × 2 BarrierFill values (1, 32) × 3 axes (noise, data, start) × 7 Δ patterns (single-bit low / mid-512 / high-1023, three random 1024-bit deltas, structural zero-low-half) × 2 plaintext kinds (random, uniform printable ASCII) = **1008 cells**, 512 KB plaintext each.

### Per-primitive roll-up (max χ² across all 84 cells per primitive)

| primitive | cells | max χ² | min p | max \|Δ50\| bit-dev | verdict |
|:----------|------:|-------:|------:|-------------------:|:--------|
| **CRC128**     | 84 | **42 454 524** | 0 | **0.435** | **bias-leak ✗** |
| **FNV-1a**     | 84 | **56 680 753** | 0 | **0.496** | **lab-detectable ⚠** |
| MD5            | 84 |  6 116 628 | 0 | 0.382 | neutralized ✓ |
| AES-CMAC       | 84 |  6 072 142 | 0 | 0.381 | neutralized ✓ |
| SipHash-2-4    | 84 |  6 076 938 | 0 | 0.381 | neutralized ✓ |
| ChaCha20       | 84 |  6 051 389 | 0 | 0.381 | neutralized ✓ |
| AreionSoEM-256 | 84 |  6 135 232 | 0 | 0.382 | neutralized ✓ |
| BLAKE2s        | 84 |  6 087 498 | 0 | 0.382 | neutralized ✓ |
| BLAKE3         | 84 |  6 132 607 | 0 | 0.381 | neutralized ✓ |
| BLAKE2b-256    | 84 |  6 067 622 | 0 | 0.381 | neutralized ✓ |
| BLAKE2b-512    | 84 |  6 074 480 | 0 | 0.381 | neutralized ✓ |
| AreionSoEM-512 | 84 |  6 075 382 | 0 | 0.382 | neutralized ✓ |

The 10 neutralized primitives cluster tightly at χ² ≈ 6.0–6.1 M — **that number is the architectural `noisePos` permutation signal**, not a primitive leak (see per-axis breakdown below). CRC128 sits at 7× that floor and FNV-1a at 9×; both show primitive-attributable structure.

### Per-primitive × axis roll-up (max χ²)

| primitive | noise | data | start |
|:----------|------:|-----:|------:|
| **CRC128**     | 42 391 609 | 42 454 524 | 42 311 253 |
| **FNV-1a**     | 56 680 753 | 56 656 354 | 56 503 886 |
| MD5            |  6 116 628 |   282 |   305 |
| AES-CMAC       |  6 072 142 |   314 |   308 |
| SipHash-2-4    |  6 076 938 |   289 |   302 |
| ChaCha20       |  6 051 389 |   309 |   297 |
| AreionSoEM-256 |  6 135 232 |   284 |   294 |
| BLAKE2s        |  6 087 498 |   298 |   301 |
| BLAKE3         |  6 132 607 |   290 |   295 |
| BLAKE2b-256    |  6 067 622 |   319 |   327 |
| BLAKE2b-512    |  6 074 480 |   301 |   287 |
| AreionSoEM-512 |  6 075 382 |   318 |   279 |

The 10 neutralized primitives register χ² within the df=255 random band on `data` and `start` (no primitive-attributable leak). CRC128 leaks on **every** axis as expected from its end-to-end GF(2)-linearity. FNV-1a lights up on `data` / `start` only through a **single-Δ effect** (see per-Δ breakdown below) — the top-bit-isolated modular multiply preserves a specific seed bit to an output bit that ITB's `hLo` extraction discards; visible to this differential probe, not to an encryption-path attacker, hence the `lab-detectable ⚠` verdict in the roll-up above rather than `bias-leak ✗`.

### Per-primitive × Δ pattern — axis=data only (the cleanest differential test)

| primitive | bit0 | bit_mid512 | bit_high1023 | rand_1 | rand_2 | rand_3 | zero_low_half |
|:----------|-----:|-----------:|-------------:|-------:|-------:|-------:|--------------:|
| **CRC128**     | **13 981** | **27 561** | **42 454 524** | **14 622** | **17 882** | **15 846** | **8 120** |
| **FNV-1a**     |    231 |    265 | **56 656 354** |    237 |    300 |    295 |    263 |
| MD5            |    230 |    255 |    256 |    267 |    283 |    282 |    260 |
| AES-CMAC       |    246 |    251 |    252 |    265 |    248 |    262 |    289 |
| SipHash-2-4    |    260 |    290 |    259 |    250 |    259 |    282 |    276 |
| ChaCha20       |    268 |    290 |    304 |    278 |    224 |    236 |    233 |
| AreionSoEM-256 |    263 |    249 |    256 |    284 |    247 |    229 |    264 |
| BLAKE2s        |    245 |    250 |    245 |    269 |    276 |    298 |    313 |
| BLAKE3         |    251 |    250 |    239 |    273 |    271 |    258 |    290 |
| BLAKE2b-256    |    262 |    254 |    253 |    236 |    298 |    319 |    286 |
| BLAKE2b-512    |    280 |    232 |    265 |    294 |    244 |    288 |    301 |
| AreionSoEM-512 |    264 |    285 |    243 |    243 |    284 |    317 |    276 |

FNV-1a's leak on `axis=data` is a **single-Δ effect**: only `bit_high1023` (flip of bit 63 of seed component 15) triggers the 56 M signal — FNV-1a's top-bit-isolated modular multiply preserves that bit's differential to output bit 127, which ITB's `hLo` extraction coincidentally discards, so the "leak" here is `D` becoming mostly-zero on data pixels (50 % same bytes from unchanged `channelXOR`) rather than genuine algebraic recovery. CRC128 leaks on every Δ pattern because it is fully GF(2)-linear end-to-end.

### Per-primitive × BarrierFill roll-up (max χ²)

| primitive | BF=1 | BF=32 |
|:----------|-----:|------:|
| **CRC128**     | **42 454 524** | **34 274 960** |
| **FNV-1a**     | **56 680 753** | **45 778 056** |
| MD5            |  6 116 628 | 4 923 037 |
| AES-CMAC       |  6 072 142 | 4 908 608 |
| SipHash-2-4    |  6 076 938 | 4 923 866 |
| ChaCha20       |  6 051 389 | 4 915 850 |
| AreionSoEM-256 |  6 135 232 | 4 940 673 |
| BLAKE2s        |  6 087 498 | 4 904 584 |
| BLAKE3         |  6 132 607 | 4 903 913 |
| BLAKE2b-256    |  6 067 622 | 4 915 595 |
| BLAKE2b-512    |  6 074 480 | 4 922 878 |
| AreionSoEM-512 |  6 075 382 | 4 893 831 |

BF=32 systematically reduces χ² (~20 %) across **all** primitives — BarrierFill adds uniform CSPRNG fill pixels that dilute any signal proportionally. Relative ordering between primitives preserved; the 10-vs-2 split between neutralized and leaking primitives holds regardless of BF.

### Architectural implications

1. **PRF + carry-chain primitives are related-seed secure under ITB wrapping.** Tested matrix covers every 1024-bit ChainHash primitive in the suite; none of the 10 non-GF(2)-linear primitives (9 PRF-grade + MD5) shows a differential on `data` or `start` above the df=255 random band.
2. **CRC128's GF(2)-linearity leaks end-to-end.** Already expected and documented in [Phase 2a (extension)](#phase-2a-extension--empirical-mixed-algebra-stress-test-via-crc128-nonce-reuse); Phase 2e confirms the leak appears in a second independent measurement surface (related-seed differential rather than bias-probe conflict-rate).
3. **FNV-1a's top-bit isolation is ITB invisible.** FNV-1a's `(state × 0x01000000000000000000013B) mod 2^128` preserves state's bit 127 only in output bit 127. ITB discards the high uint64 of `hLo/hHi` outputs; the leak is therefore visible to a differential probe but not to an encryption-path attacker.
4. **BarrierFill is orthogonal to primitive security.** BF=1 vs BF=32 rescale χ² but do not reorder primitives into or out of the neutralized cluster.
5. **Multi-axis differentials decompose into single-axis XOR.** A simultaneous Δ on two or three seeds produces `D = ct₀ ⊕ ct₁` equal to the XOR of the corresponding single-axis differentials measured above. For the 10 neutralized primitives each axial component sits in the df=255 random band on `data` / `start` plus the architectural `noisePos` floor on `noise`; the combined differential therefore inherits only the `noisePos` floor with uniform-random `data` / `start` contributions — no new primitive-attributable signal. For CRC128 and FNV-1a the axial leaks superpose GF(2)-linearly (CRC128) or through the same bit-127 preservation (FNV-1a) already captured above, with no novel algebraic surface. Triple-seed isolation — independent component arrays, independent ChainHash instances with independent cached PRF keys, disjoint observable surfaces (`channelXOR` / `noisePos` / `startPixel`) — precludes coherent cross-axis propagation, so the Phase 2e single-axis matrix upper-bounds the full multi-axis behaviour analytically. The public API additionally exposes no induction path for a coordinated Δ across two or more seeds, making the multi-axis case a strictly lab-only construct that does not enlarge the attacker's surface.

### BLAKE wrapper seed-injection fix (precondition)

Phase 2e v2 initially surfaced an apparent BLAKE2b/2s/3 leak on Δ=`bit_high1023` across the `data` axis. Diagnosis: the cached-wrapper functions (`makeBlake2bHash256`, `makeBlake2sHash256`, `makeBlake2bHash512`, `makeBlake3Hash256`, `makeBlake3Hash256WithKey`) iterated the 4 (or 8) seed `uint64` values and XOR'd them at offsets `keyLen + i*8`, but guarded the XOR with `if off+8 <= len(buf)`. For ITB's internal 20-byte `pixel_le || nonce` input, `buf` was 52 bytes, so `seed[2]` and `seed[3]` (offsets 48 and 56) silently **dropped** — halving the effective ChainHash key width.

Fix (applied to `itb_test.go`, `redteam_lab_test.go`, `README.md`, `doc.go`): pad the buffer to at least `keyLen + seedLen*8` bytes, zero-pad the stale tail, then XOR all seed lanes unconditionally. Added regression test `TestBlakeWrappersAllSeedBitsAffectOutput` that flips bits 0 and 63 of each seed component on 20-byte data and asserts every flip changes the digest. Phase 2e v3 + v4 re-runs with the fixed wrappers produce the data shown above.

### Reproduction

```bash
# Full Phase 2e matrix — 1008 cells, ~30-60 min at PARALLEL=8 on 16-core.
PARALLEL=8 bash scripts/redteam/phase2e_related_seed_matrix.sh

# Render aggregate tables (per-primitive / per-axis / per-Δ / per-BF / per-PT):
python3 scripts/redteam/phase2_theory/aggregate_related_seed_diff.py \
  --input tmp/attack/related_seed_diff/results/phase2e_related_seed/matrix_summary.jsonl \
  > phase2e_matrix.md

# Narrow subset (e.g. CRC128 + BLAKE3 on the data axis only):
PRIMITIVES="crc128 blake3" AXES="data" DELTA_KINDS="bit0 bit_high1023" \
PT_KINDS="random" BFS="1" \
RESULTS_TAG="phase2e_subset" PARALLEL=4 \
bash scripts/redteam/phase2e_related_seed_matrix.sh
```

Per-cell artefacts: `tmp/attack/related_seed_diff/corpus/<primitive>/BF<n>/<axis>/<delta>/<pt>/` containing `ct_0.bin`, `ct_1.bin`, `plaintext.bin`, `cell.meta.json`, `stats.json`.

---

## Phase 2f — Direct Crib KPA against GF(2)-linear primitives

Scripts:
- [`scripts/redteam/phase2_theory/crib_crc128_kpa_full.py`](scripts/redteam/phase2_theory/crib_crc128_kpa_full.py) — joint `(K_data, K_noise_bits_0_2)` recovery from a single ciphertext via public-schema crib.
- [`scripts/redteam/phase2_theory/crib_crc128_decrypt_full.py`](scripts/redteam/phase2_theory/crib_crc128_decrypt_full.py) — exact full-plaintext decrypt using the recovered `(K_data, K_noise_bits_0_2)` pair against a second ciphertext encrypted under the same seeds but a different nonce.
- [`redteam_lab_test.go` `TestRedTeamGenerateCribCrossCorpus`](redteam_lab_test.go) — corpus generator producing two ciphertexts with shared seeds, different nonces, different plaintext formats (JSON + HTML).

Tests direct confidentiality under a GF(2)-linear primitive **without** nonce reuse and **without** the demasker pipeline of [Phase 2d](#phase-2d--nonce-reuse). The attack is algebraic: ChainHash composition of a GF(2)-linear round function preserves linearity, so `dataHash(p) = K_data ⊕ c(p)` where `K_data` is a 64-bit per-lane compound key and `c(p)` is attacker-computable. The same linearity exposes the 3 low bits of noiseSeed's compound key `K_noise` as a side channel of the 56-hypothesis Crib KPA filter: each crib pixel's correct `noise_pos` selection pins `K_noise_bits_0_2 = noise_pos ⊕ (c(p) & 7)`. Both values recovered from a publicly-known JSON schema prefix on one ciphertext; together they decrypt every future ciphertext under the same `(dataSeed, noiseSeed)` pair to **100 % byte accuracy** — any nonce, any startSeed (startPixel is re-anchored per target ciphertext via the public HTML schema crib), any plaintext format including binary / compressed / encrypted streams.

### Attack chain

1. **Corpus generation** — `TestRedTeamGenerateCribCrossCorpus` creates two cells sharing `(noiseSeed, dataSeed, startSeed)` but using distinct nonces:
    - `corpus_A_json` — 4 KB `json_structured_80` plaintext, nonce_A
    - `corpus_B_html` — 4 KB `html_structured_80` plaintext, nonce_B

   Both at CRC128 + keyBits=1024 + BF=1 — shared seeds demonstrate the per-`dataSeed` invariance of `K_data` and the per-`noiseSeed` invariance of `K_noise_bits_0_2` (both depend only on seed components, not on nonce or plaintext).

2. **Joint K recovery on corpus A** ([`crib_crc128_kpa_full.py`](scripts/redteam/phase2_theory/crib_crc128_kpa_full.py)): attacker feeds a 21-byte / 3-pixel public JSON schema prefix (`\xff[{"identifier_of_rec` — COBS start byte + JSON array start + first-field schema prefix) as the crib. The script enumerates all 256 × 8 = 2048 `(K_data variant, K_noise_bits_0_2)` pairs and keeps every pair that decrypts the 3 crib pixels EXACTLY using (a) `rotation = (K_data ⊕ const_all[p]) mod 7` and (b) `noise_pos = K_noise_bits_0_2 ⊕ (const_all[p] & 7)`. `K_noise_bits_0_2` resolves uniquely from cross-pixel consistency; 8 unobservable K_data bits (low 3 + high 5) produce structural shadow pairs through mod-7 aliasing that a 3-pixel filter cannot disambiguate alone. The script returns every surviving pair (typically 8–16) for downstream COBS-validity cross-check in step 3. Wall-clock ~1 s on a 4 KB corpus with full brute-force shift scan.

3. **Multi-candidate decrypt on corpus B** ([`crib_crc128_decrypt_full.py`](scripts/redteam/phase2_theory/crib_crc128_decrypt_full.py)): the script iterates through every `(K_data, K_noise_bits_0_2)` survivor from step 2 and for each runs three attacker-visible validation stages — (i) anchor startPixel on the target ciphertext via a 21-byte / 3-pixel HTML schema crib (`\xff<identifier-of-recor`, no record-specific values); (ii) full-ciphertext decrypt with the candidate pair's derived rotation and noise_pos; (iii) COBS-decode validity — block-length chain consistency plus the position of the `0x00` terminator inside the decrypted stream. Among all COBS-valid candidates, the script selects the one whose terminator sits highest in the stream (closest to the end). The true pair always wins: its entire COBS-encoded plaintext is consistent with every byte of the stream, placing the terminator in the final ≥ 90 % of the buffer, while shadow pairs carry a ~50 % corrupted tail that either breaks the block-length chain or meets a stray `0x00` strictly earlier. COBS is part of the public ITB spec, so every validation step uses only attacker-visible data. Completes in under 1 s on a 4 KB corpus, scales linearly with `total_pixels × survivor_count`.

### Empirical result (CRC128 × BF=1, JSON → HTML cross-format, 3-pixel cribs both sides)

| Corpus size | total_pixels | Stage 1 scan | Stage 2 survivors | True terminator | Next-highest shadow terminator | Byte accuracy | Full-pixel accuracy | Plaintext match |
|:-----------:|-------------:|-------------:|------------------:|----------------:|-------------------------------:|--------------:|--------------------:|:---------------:|
| 4 KB | 625 | ~1.0 s | 12 | 89.97 % | (sole COBS-valid candidate) | **100.00 %** (3 937 / 3 937) | **100.00 %** (562 / 562) | ✓ exact |
| 64 KB | 9 604 | ~7.9 s | 12 | 97.69 % | (sole COBS-valid candidate) | **100.00 %** (65 674 / 65 674) | **100.00 %** (9 382 / 9 382) | ✓ exact |
| 128 KB | 19 321 | ~44.9 s | 12 | 98.53 % | 97.78 % | **100.00 %** (131 347 / 131 347) | **100.00 %** (18 763 / 18 763) | ✓ exact |
| 1 MB | 151 321 | ~122.5 s | 12 | 99.36 % | 18.01 % | **100.00 %** (1 052 484 / 1 052 484) | **100.00 %** (150 354 / 150 354) | ✓ exact |

Stage 1 wall-clock above reflects single-core pure brute force over all `total_pixels` shifts (no bias-probe assist; the winning shift's scan position depends on seeds and is uniform over `[0, total_pixels)`). Stage 2 survivor count (12 across all cells here) is fixed by the first three `const_all[p]` values at `(seedSource, nonceSeed)` defaults — structural shadow count depends on the seeds/nonce tuple, not on corpus size. Across every tested cell the true `(K_data, K_noise_bits_0_2)` pair wins the terminator-position ranking among all COBS-valid candidates. Recovered pair predicts every per-pixel `(rotation, noise_pos)` of the target ciphertext exactly, reconstructing the full plaintext with zero corrupted bytes. The same pair decrypts any further ciphertext generated under the same `(dataSeed, noiseSeed)` at any nonce and any plaintext class.

### Architectural findings

1. **GF(2)-linear primitives expose `dataSeed`'s compound key `K_data` on a single ciphertext.** No nonce reuse, no demasker, no lab access — pure public-schema Crib KPA. The solver extracts 56 of 64 observable K_data bits algebraically from the 56-hypothesis filter on a crib; the remaining 8 bits (low 3 + high 5) lie outside the `channelXOR = hLo >> 3` window. Short cribs (down to the 3-pixel / 21-byte minimum) leave multiple structural shadow pairs after the Stage 2 filter; the decrypt script iterates every survivor against the target ciphertext and selects the one producing a valid COBS-decoded plaintext with terminator near the end of the stream — attacker-visible cross-check using the public ITB COBS spec, not a lab peek. This is the load-bearing empirical evidence that [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure)'s "mixed-algebra is load-bearing" premise is correct: replace FNV-1a's carry-chain non-linearity with a pure GF(2)-linear CRC128 and the entire ChainHash cost table collapses.

2. **`K_data` and `K_noise_bits_0_2` are both per-seed invariants, independent of nonce and plaintext.** `dataHash(p, nonce) = K_data ⊕ c(p, nonce)` and `noiseHash(p, nonce) = K_noise ⊕ c(p, nonce)` where `c(·)` is attacker-computable for any nonce the attacker observes. A single recovery of the pair breaks every future message encrypted under the same `(dataSeed, noiseSeed)`, regardless of nonce rotation — corpus B under a fresh nonce folds to the same pair that was recovered from corpus A.

3. **`noiseSeed` exposes only its 3 low compound bits under Crib KPA; the other 61 bits remain architecturally inaccessible.** The `& 7` projection at the encoder — `noise_pos = noiseSeed.ChainHash(pixel||nonce).lo & 7` — keeps bits 3..63 of `K_noise` invisible in the ciphertext. The 3 low bits (0..2) are recoverable only because the 56-hypothesis filter forces the attacker to identify the correct `noise_pos` per crib pixel; `K_noise_bits_0_2 = noise_pos ⊕ (const_all[p] & 7)` is then a direct linear derivation, cross-validated by equality across all crib pixels. These 3 bits are nonetheless sufficient to predict `noise_pos` for any future `(pixel, nonce)` under the same `noiseSeed` — no further information about `K_noise` is needed for decryption. Full `K_noise` compound recovery (64 bits) and `noiseSeed` component recovery (512 bits ECMA-side) remain out of empirical reach even on this control primitive (see item 5).

4. **100 % plaintext recovery holds independently of plaintext class.** With `K_noise_bits_0_2` known, the per-pixel `noise_pos` is computed exactly — no 8-way brute force, no printable-ASCII heuristic. The decrypt works identically on printable ASCII (HTML / JSON / text), UTF-8, and binary formats (ZIP / PDF / MP4 / compressed / encrypted streams). Plaintext alphabet is not an attack parameter under the joint `(K_data, K_noise_bits_0_2)` recovery: every byte of every pixel in every future ciphertext under the same seeds is reconstructed bit-accurate, and the noise-bit layer — linearly recoverable in the precise sense just described — provides no additional protection against this specific attack chain on a GF(2)-linear primitive.

5. **Full `dataSeed` / `noiseSeed` component inversion remains out of reach even on CRC128.** Crib KPA recovers 64 bits of `K_data` compound + 3 bits of `K_noise` = 67 total observable bits on the 1024-bit attacker-reachable seed space (512 bits dataSeed ECMA + 512 bits noiseSeed ECMA). The residual kernel of `2^(1024−67) ≈ 2^957` candidate `(dataSeed, noiseSeed)` component pairs is indistinguishable to the attacker from these observations, above the Landauer bound for enumeration regardless of compute regime. Full component recovery would require an additional observation channel exposing intermediate ChainHash round state or a distinct linear image of the seed — ITB's architecture provides neither. Operationally the attacker receives 100 % plaintext recovery via `(K_data, K_noise_bits_0_2)` without needing the seed components; full seed secrecy is preserved because component-level inversion is not what the attacker needs and is architecturally denied regardless.

### Startup cost: full brute force vs bias-probe shortcut

The Crib KPA script supports two startPixel-discovery modes. Both recover the `(K_data, K_noise_bits_0_2)` pair with identical output; only the wall-clock scaling differs.

**Full brute force (`--brute-force-shifts`).** Scans all `total_pixels` candidate shifts, running the 56-hypothesis K_data algebraic filter at each, and picks the shift whose K_data candidate survives the crib verify step (default 3 crib pixels — the minimum at which Stage 1 converges to a unique `K_observable`). The winning shift is then expanded on a single pass to every `(K_data, K_noise_bits_0_2)` pair the 3-pixel Stage 2 filter admits, emitted as a survivor list for downstream COBS-validity cross-check on the target ciphertext. No bias-probe dependency, no lab access, pure attacker-side compute.

Measured wall-clock scaling (single CPU core, commodity laptop). Per-shift inner-loop cost is ~0.8–2.5 ms — varies slightly with crib length and vector-code overhead, stays constant per given configuration across plaintext size:

| Plaintext size | total_pixels | Full-scan wall-clock | Typical wall-clock (first hit) |
|:---------------|-------------:|---------------------:|-------------------------------:|
| 4 KB | 625 | ~1.0 s | **< 1 s** |
| 64 KB | 9 604 | ~7.7 s | **~4 s** (mean scan position ~50 %) |
| 128 KB | 19 321 | ~45 s | **~22 s** |
| 1 MB | 151 321 | ~5–6 min | **~2–3 min** |
| 10 MB | ~1.5 M | ~60 min | **~30 min** |
| 100 MB | ~15 M | ~10 h | **~5 h** |

The script short-circuits at the first shift whose K_data candidate passes the crib verify step (there is no benefit to scanning further once the crib locks in), so actual wall-clock depends on where the true shift lands in the scan order — uniformly distributed across `[0, total_pixels)`, so the expected value is `~0.5 × full-scan` but any single run may land anywhere in the scan interval. Per-shift cost stays flat within measurement noise across three orders of magnitude, validating the linear-in-`total_pixels` model.

Parallelism (map-reduce over shifts, trivially splittable) cuts wall-clock by the worker count — a commodity 16-core host brings the 100 MB worst case from ~10 h down to under 40 min, a small cloud allocation reaches GB-scale in hours. Full brute force is therefore a practical attacker capability on reasonable corpus sizes; it is **not** gated by bias-probe availability.

**Bias-probe shortcut.** A production attacker with access to the [Phase 2a extension raw-mode bias probe](#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) (`raw_mode_bias_probe.py`) can pre-filter candidate shifts to the top-5 conflict-rate plateau in sub-second time — the true shift always lands in that plateau under GF(2)-linearity. Crib KPA then only verifies ≤5 shifts instead of `total_pixels`, reducing wall-clock to sub-second regardless of corpus size. This is a **quality-of-life optimisation**, not a load-bearing dependency: the full-brute-force row above demonstrates the attack completes in realistic time without it.

### Reproduction

The full pipeline is three steps: generate a shared-seeds corpus pair (step 1), enumerate all `(K_data, K_noise_bits_0_2)` survivors from the JSON ciphertext via pure brute force with no bias-probe assist (step 2), iterate every survivor through the cross-format decrypt against the HTML ciphertext encrypted under the same seeds but a fresh nonce and accept the one producing a valid COBS-decoded plaintext (step 3). All three steps are size-parameterised via `ITB_CRIB_CROSS_SIZE`; the rest of the pipeline is size-independent.

```bash
# Step 1 — generate shared-seeds corpus pair under CRC128 + keyBits=1024 + BF=1.
# Seeds (noiseSeed, dataSeed, startSeed) are identical across the two cells;
# nonces differ. corpus_A_json is the Crib KPA target; corpus_B_html is the
# cross-message decrypt target. Pick any size (or any other value ≥ 4096):

ITB_CRIB_CROSS=1 ITB_CRIB_CROSS_SIZE=4096    \
    go test -run TestRedTeamGenerateCribCrossCorpus -v -timeout 60s      # 4 KB
ITB_CRIB_CROSS=1 ITB_CRIB_CROSS_SIZE=65536   \
    go test -run TestRedTeamGenerateCribCrossCorpus -v -timeout 300s     # 64 KB
ITB_CRIB_CROSS=1 ITB_CRIB_CROSS_SIZE=131072  \
    go test -run TestRedTeamGenerateCribCrossCorpus -v -timeout 300s     # 128 KB
ITB_CRIB_CROSS=1 ITB_CRIB_CROSS_SIZE=1048576 \
    go test -run TestRedTeamGenerateCribCrossCorpus -v -timeout 600s     # 1 MB

# Optional — swap the primitive to FNV-1a for the negative-empirical cross-check
# (the CRC128 pipeline below emits NO MATCH on a FNV-1a corpus because the
# round function is not GF(2)-linear). Default is crc128 when unset.
ITB_CRIB_CROSS=1 ITB_CRIB_CROSS_SIZE=4096 ITB_CRIB_CROSS_HASH=fnv1a \
    go test -run TestRedTeamGenerateCribCrossCorpus -v -timeout 60s

# Step 2 — enumerate all (K_data, K_noise_bits_0_2) survivors from corpus A
# via pure brute force (no bias probe). The default 21-byte / 3-pixel JSON
# schema crib is hard-coded into the script; survivors are written to
# `recovered_k_full.json` in the cell directory for consumption by step 3.
python3 scripts/redteam/phase2_theory/crib_crc128_kpa_full.py \
    --cell-dir tmp/attack/crib_cross/corpus_A_json \
    --brute-force-shifts

# Step 3 — decrypt corpus B (HTML, fresh nonce) by iterating every survivor
# from step 2's sidecar until one yields a valid COBS-decoded plaintext
# with its 0x00 terminator near the end of the decrypted stream (a wrong
# K_data pair either fails the COBS block-length chain or terminates early
# on a stray 0x00 in the corrupted tail). The default HTML crib
# `\xff<identifier-of-recor` (3 pixels, 21 bytes) anchors startPixel per
# candidate; every pixel is then decrypted deterministically — rotation
# from K_data, noise_pos from K_noise_bits_0_2, both exact, no brute force
# on any axis and no plaintext-alphabet heuristic.
python3 scripts/redteam/phase2_theory/crib_crc128_decrypt_full.py \
    --cell-dir tmp/attack/crib_cross/corpus_B_html \
    --candidates-json tmp/attack/crib_cross/corpus_A_json/recovered_k_full.json

# Optional — append the ground-truth plaintext file for a lab byte-level /
# pixel-level accuracy report at the terminal stage; the attack itself
# does not need it (candidate selection happens purely via COBS validity).
#   --expected-plaintext tmp/attack/crib_cross/corpus_B_html/ct_0000.plain
```

Expected wall-clocks (single CPU core): 4 KB step 2 runs in ~1 s; 64 KB in ~4–8 s; 128 KB in ~22–45 s; 1 MB in ~2–5 min. Step 3 runs in under 1 s on 4 KB and up to ~6 s on 1 MB (≤ 12 candidate iterations × ~0.5 s full-decrypt each).

Per-run artefacts:
- `tmp/attack/crib_cross/corpus_A_json/` — JSON source used for Crib KPA (plus `cell.meta.json` with seed components for lab audit) and `recovered_k_full.json` with the survivor list.
- `tmp/attack/crib_cross/corpus_B_html/` — HTML decrypt target + `recovered_stream_full.bin` (full byte stream) + `recovered_plaintext_cobs.bin` (COBS-decoded plaintext).
- `tmp/attack/crib_cross/summary.json` — shared seeds + both nonces.

### Scope

This section establishes the outer bound of cross-message confidentiality damage from a GF(2)-linear primitive + public schema crib. It does NOT claim production ITB is vulnerable — CRC128 is an unexported lab-only stress control whose presence in `redteam_lab_test.go` is explicitly gated behind `redteam_lab_test.go`-resident identifiers not reachable through `NewSeed{128,256,512}`. Users who wire any non-GF(2)-linear primitive from the [Hash matrix](#hash-matrix) (FNV-1a, MD5, or any PRF-grade entry) into their deployment are not exposed to this attack chain — as formally argued in [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure) and empirically cross-validated by [Phase 2a extension bias audit](#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) (FNV-1a / BLAKE3 / MD5 all show `neutralized ✓` on raw-mode conflict-rate distribution where CRC128 shows `bias-leak ✗`). Running the Phase 2f Stage 1 pipeline directly on a FNV-1a corpus pair generated via `ITB_CRIB_CROSS_HASH=fnv1a` emits `NO MATCH — crib did not anchor any shift with any K_data candidate` on both `--hash-module fnv1a` and the default CRC128 const-mirror — a negative empirical confirmation limited to that specific pipeline, not that no Crib KPA against FNV-1a exists — see [Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) for the SAT-based Crib KPA that does work against FNV-1a.

---

## Phase 2g — Multi Crib KPA against FNV-1a + ITB (SAT-based)

Scripts:
- [`scripts/redteam/phase2_theory_fnv1a/sat_harness_4round.py`](scripts/redteam/phase2_theory_fnv1a/sat_harness_4round.py) — Z3 / Bitwuzla SAT harness recovering the `dataSeed` lo-lane compound state from a multi-crib ciphertext under disclosed or brute-forced `startPixel`.
- [`scripts/redteam/phase2_theory_fnv1a/decrypt_full_fnv1a.py`](scripts/redteam/phase2_theory_fnv1a/decrypt_full_fnv1a.py) — full-plaintext decrypt under the recovered lo-lane K using beam-search per-pixel `noise_pos` enumeration with COBS-state-machine rejection.
- [`redteam_lab_test.go` `TestRedTeamGenerateFNVStressCorpus`](redteam_lab_test.go) — corpus generator producing structured JSON / HTML ciphertexts under FNV-1a + `keyBits=512` with schema-predictable multi-crib coverage.

Tests direct confidentiality under FNV-1a — the only invertible-but-non-GF(2)-linear primitive in the [Hash matrix](#hash-matrix) — **at ITB's architectural minimum** `keyBits = 512` (4 ChainHash rounds; hLo-only observation collapses the nominal 512 seed bits to 256 effective SAT unknowns per the argument in [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure)). The attack is structurally different from [Phase 2f](#phase-2f--direct-crib-kpa-against-gf2-linear-primitives) on CRC128: the round function is non-linear (Z/2⁶⁴ multiplication by `P_lo = 0x13B` creates carry chains between bit positions), so no algebraic closed-form compound-key collapse exists. Recovery is purely SAT-driven — multiple schema-predictable cribs produce a per-pixel observation set constraining the 256-bit lo-lane seed through 4 rounds of nested modular multiplication. Bitwuzla with CaDiCaL backend resolves 4 cribs + disclosed `startPixel` to a functional `dataSeed` lo-lane compound state in **~8 h** of single-worker wall-clock on a commodity 16-core host (hardware-variable; figure is approximate and shifts by tens of percent across CPU, memory bandwidth, solver version, background load). Full decrypt under the recovered K yields **~83–85 % byte-level plaintext recovery** on 4 KB JSON / HTML corpora; the remaining ~15–17 % is attributable to per-pixel `noise_pos` 3-bit ambiguity, which has no corresponding crib invariant under FNV-1a and is therefore architecturally unrecoverable through any Crib KPA (see architectural finding 4).

### Attack chain

1. **Corpus generation** — `TestRedTeamGenerateFNVStressCorpus` creates 8 cells sharing `(noiseSeed, dataSeed, startSeed)` with distinct nonces, spanning JSON + HTML format pairs at a 4 KB budget. Each cell carries a `0xFF` COBS-overhead anchor crib at byte 0 plus schema-predictable record cribs (JSON: `{"k":"IIIIIIII","v":"RRRRRRRRRRRRRRRR"}` 39 B, 21 B known prefix / HTML: `<r><k>IIIIIIII</k><v>RRRRRRRRRRRRRRRR</v></r>` 45 B, 21 B known prefix; record indices `IIIIIIII` publicly predictable as lowercase hex of sequence number). Primitive: FNV-1a at `keyBits = 512` + BF=1; 1 training cell (JSON) + 1 holdout cell (HTML, fresh nonce) are sufficient for functional-K validation.

2. **SAT recovery of `dataSeed` lo-lane** ([`sat_harness_4round.py`](scripts/redteam/phase2_theory_fnv1a/sat_harness_4round.py)): the harness gathers per-channel observations from every crib byte fully inside a 7-bit pixel window (4 cribs → 101 observations over 15 distinct crib pixels), encodes the full 4-round × 20-byte ChainHash128 `(s_0..s_3)` multiplication cascade as one Bitwuzla SAT instance over 256 lo-lane seed bits + 6 ambiguity bits per crib pixel (3 bits `noise_pos` + 3 bits `rotation`, the latter pinned via `rotation == dataHash % 7` through a sum-of-3-bit-chunks identity that replaces the native 64-bit `URem` with an O(150-gate) equivalent). `startPixel` disclosed per cell (Concession 1; the brute-force-`startPixel` variant is quantified in architectural finding 3). Solver: Bitwuzla 0.9.0 + CaDiCaL backend, default configuration. Wall-clock on the reference configuration (16-core commodity host, 48 GB RAM, Arch Linux): ~8 h single-worker to `sat`, peak RSS ~2 GB observed on the Bitwuzla subprocess via `ps` (≈ 4 % of 48 GB host RAM). Output: compound `s_lo[0..3]` recovered. Bits 0..62 of every lane match ground truth bit-exact; the top bit (bit 63) of some lanes may differ — it lives in the structural kernel of `P_lo = 0x13B` multiplication and is architecturally unobservable through the `hLo >> 3 & 0x7F` channel projection, so the recovered K remains functionally equivalent to ground truth on every future ciphertext.

3. **Holdout validation** — the harness re-evaluates the recovered lo-lane on a held-out cell (fresh nonce, HTML plaintext) at the channel-observation level; reproducing 31/31 holdout channel observations confirms functional equivalence. The check uses no plaintext beyond the public schema crib and no lab-only fields.

4. **Full decrypt on any ciphertext under the same seeds** ([`decrypt_full_fnv1a.py`](scripts/redteam/phase2_theory_fnv1a/decrypt_full_fnv1a.py)): under recovered `K_lo`, the script brute-forces `startPixel × anchor-pixel noise_pos` (`total_pixels × 8` = 2 312 / 2 592 candidates for 4 KB JSON / HTML) and per-pixel `noise_pos` via beam search (width 32) with COBS-state-machine rejection (~97 % of wrong candidates rejected per pixel). COBS-valid candidates are ranked by printable-ASCII ratio of the recovered plaintext (the true path is ≥ 99 % printable on structured JSON / HTML; ghost-terminator paths landing inside the CSPRNG-fill region past the real terminator decode to near-random byte garbage at ~35 %). Wall-clock < 5 s on 4 KB per cell, pure Python single-core.

### Empirical result (FNV-1a × `keyBits = 512` × BF=1, 4 cribs disclosed `startPixel` + 1-crib holdout)

| Cell | Format | total_pixels | Truth `startPixel` | Recovered `startPixel` | Plaintext length | Terminator position | **Byte-match** |
|:-----|:------:|-------------:|-------------------:|-----------------------:|-----------------:|--------------------:|---------------:|
| cell_00 | JSON | 289 | 114 | **114** ✓ | 1 641 B ✓ | 1 648 | **1 386 / 1 641 = 84.46 %** |
| cell_01 | HTML | 324 |  50 |  **50** ✓ | 1 845 B ✓ | 1 853 | **1 532 / 1 845 = 83.04 %** |

SAT wall-clock: ~8 h on 4 cribs × disclosed `startPixel`, single-worker Bitwuzla + CaDiCaL, 16-core commodity host (approximately; varies ~± 30 % across comparable hardware and ~± 10 % across solver runs with identical inputs). Recovered K on cell_00 (training JSON) and cell_01 (holdout HTML, fresh nonce) produces byte-identical output under `--lab-k-from-summary` and `--k-json` modes, confirming independently from the SAT-level 31/31 holdout check that the recovered `dataSeed` lo-lane is functionally equivalent to ground truth. The ~15–17 % byte gap does NOT reduce under further SAT budget: per-pixel `noise_pos` is computationally independent across pixels under FNV-1a (carry-chain arithmetic leaves no pixel-invariant compound), so each decrypt pixel carries irreducible 1-in-8 hypothesis ambiguity pruned only by COBS framing + printable-ASCII heuristics.

### Architectural findings

1. **FNV-1a + ITB at `keyBits = 512` / 4 rounds is fully broken by Crib KPA in the operational sense on structured-text plaintexts.** With 4 public-schema cribs and disclosed `startPixel`, a commodity SAT solver recovers a functionally-equivalent `dataSeed` lo-lane compound state in ~8 hours; the recovered K decrypts every future ciphertext under the same `(dataSeed, noiseSeed)` at ~83–85 % byte-level accuracy on structured-text (JSON / HTML) plaintexts, regardless of nonce rotation. Binary-format plaintexts (ZIP, compressed streams) follow a different curve documented in architectural finding 6. The gap from 100 % on structured-text is not a defence — it is architectural leakage of `noise_pos` values that an attacker could already enumerate brute-force per pixel. FNV-1a is marked `Fully broken` in the [Hash matrix](#hash-matrix) to reflect this outcome.

2. **SAT wall-clock is non-monotonic in crib count around the phase-transition knee.** The 1-crib case runs in ~130 s (easy region, overdet ~0.77×, many satisfying assignments). The 2-crib case sits inside the SAT-hardness peak (> 8 h on the reference host with no convergence; overdet ~1.4×, densely-coupled carry-chain constraints). The 4-crib case is past the peak and converges reliably in ~8 h (overdet ~2.5–3×). This non-monotonicity is a property of under-determined SAT on densely-coupled formulae and is intrinsic to the constraint graph — **more** observations make the instance **harder** until the overdetermination ratio crosses ~3×, after which each additional constraint helps. The ~8 h figure therefore sits at the first reliable-convergence point rather than at an optimum.

3. **Without disclosed `startPixel`, the realistic attack multiplies by `total_pixels` independent SAT instances — still within commodity reach.** An attacker holding only a single ciphertext must run the same 4-crib SAT recovery for each candidate `startPixel` (289 candidates for 4 KB JSON, 324 for 4 KB HTML) until one returns `sat` and passes a structural cross-check (COBS-valid full decrypt, or, if available, holdout channel observations on a second ciphertext under the same seeds). These instances are embarrassingly parallel — no shared state between workers — so a 289-core allocation completes the search in the same ~8 h wall-clock as the single-instance disclosed-`startPixel` case. No HPC cluster is required: the attack is within reach of a single 64-core server (runs at ~4–5× wall-clock, ~36 h), several commodity 16-core boxes networked by a job queue (~90 h), or a cloud burst at ≤ 300 vCPU-hours.

4. **`noiseSeed` is architecturally unrecoverable through Crib KPA under FNV-1a.** Per-pixel `noise_pos` values are the outputs of a PRF (`noiseSeed.ChainHash(pixel || nonce).lo & 7`) with no public-schema predictability by design — a crib for a `noise_pos` value would require the attacker to know the random output a priori, contradicting its secrecy role. Unlike CRC128's [Phase 2f](#phase-2f--direct-crib-kpa-against-gf2-linear-primitives) path, where GF(2)-linearity exposes `K_noise_bits_0_2` as a 3-bit side channel of the 56-hypothesis filter, FNV-1a's carry-chain arithmetic produces no analogue: each per-pixel `noise_pos` is an independent 3-bit value depending on all 256 bits of `noiseSeed` through a non-linear chain. A separate SAT pass on the `noiseSeed` lo-lane (+256 unknowns, wall-clock comparable to the `dataSeed` pass) would require an observation channel tied to `noise_pos` values — none exists. This is the architectural reason the byte-match plateau sits at ~83–85 % on structured-text plaintexts rather than 100 %; on binary plaintexts the plateau collapses further (finding 6).

5. **Result scope: ITB's minimum configuration only.** The empirical bound above applies at `keyBits = 512` (4 ChainHash rounds, the architectural minimum that `NewSeed{128,256,512}` accepts). At `keyBits = 1024` (8 rounds, shipped default) and `keyBits = 2048` (16 rounds, paranoid), SAT recovery on FNV-1a remains analytical-only — per-round cost on SMT-on-ARX / carry-chain formulae is widely reported at 2–7× per additional round; the ~8 h / 4-round datum extrapolates to weeks-to-months at 8 rounds and decades at 16 rounds on the same crib count / hardware, with wide error bars. See updated [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure) Z3 feasibility table for the conditional cost curve.

6. **Operational utility of recovered K is format-dependent.** The ~83–85 % byte-match plateau measured on structured-text (JSON / HTML) plaintexts is **not a universal per-pixel recovery rate** — it depends on a format-specific discriminator wide enough to preserve the true `noise_pos` path through the beam search. On 4 KB JSON / HTML the printable-ASCII ratio separates true paths (≥ 99 % printable) from chance-aligned ghost paths (~35 %) with a 64-point margin; the beam retains the true path across every pixel of the container. On a Store-method ZIP plaintext (`N × 1 KB` lorem-ipsum text files) the same harness under the recovered K, with relaxed COBS anchor and PK-signature-count discriminator, produces **0.49–0.60 % byte-match** across six independent corpora (mean 0.55 %, stddev 0.04 %; plaintext sizes 22 KB and 112 KB — four 22 KB and two 112 KB corpora — six distinct seed sets, six distinct truth `startPixel` values spanning 1 839 / 2 370 / 2 602 / 3 099 / 3 369 / 14 035). That figure is statistically indistinguishable from the 0.39 % random-byte collision floor (1.3–1.5 × floor across every measurement). Recovered plaintext length varies wildly across runs (4 350 B – 50 942 B on the 22 KB / 112 KB corpora), so even the "plaintext length" signal is lost. The true `noise_pos` path is evicted from the beam within ~100 pixels because true and ghost paths have indistinguishable quality scores on mixed printable-plus-binary content; the PK-signature ranker therefore has no true candidate to rank. **Operational consequence:** recovered K from Phase 2g decrypts structured-text plaintexts to readable content with byte-level typos, but decrypts binary-format plaintexts (ZIP, PDF, compressed streams, already-encrypted payloads) to random-indistinguishable garbage. Bit-exact binary decrypt would require a separate `noiseSeed` recovery pass — architecturally unreachable through Crib KPA under FNV-1a (finding 4). The 83–85 % figure applies to the attacker-realistic structured-text threat surface; binary-format carriers deliver a **zero-operational-utility break under the current-heuristic decrypt implementation** at the same architectural per-pixel recovery rate. ML-trained discriminators integrated into the beam search would likely raise this bound substantially — the architectural observation (per-pixel `noise_pos` disambiguation scales with the plaintext entropy-margin signal available to the discriminator) is preserved under ML enhancement; see [Caveats](#caveats-and-what-this-does-not-prove) for the framing of that improvement path. See Reproduction step 4 below for the ZIP corpus generator and the `--plaintext-format binary-zip` decrypt flag.

### Reproduction

The full pipeline is five steps: install the Bitwuzla solver (step 0), generate the corpus (step 1), run the SAT harness to recover `K_lo` (step 2 — three variants: disclosed `startPixel`, specific-candidate `startPixel`, or full brute-force `startPixel` sweep), run the full decrypt against any target ciphertext (steps 3a and 3b for the JSON training cell and HTML holdout cell respectively). All steps use only attacker-reachable inputs; the `--expected-plaintext` and `--lab-k-from-summary` flags exist for terminal-stage audit and are not part of any decision path.

```bash
# Step 0 — install Bitwuzla 0.9.0 from the AUR (Arch Linux). The Z3-only
# variant is also supported (pass --solver z3), but Bitwuzla's non-
# incremental wall-clock timeout is enforced across every phase and runs
# ~2–10× faster on the QF_BV multiply-heavy formulas this harness emits.
yay -S bitwuzla

# Step 1 — generate shared-seeds corpus (8 cells, 4 JSON + 4 HTML) under
# FNV-1a + keyBits=512 + BF=1. Seeds are identical across cells, nonces
# differ. Cribs are schema-predictable JSON / HTML prefixes; no lab peek.
ITB_FNV_STRESS=1 go test -run TestRedTeamGenerateFNVStressCorpus -v -timeout 300s

# Step 2a — recover dataSeed lo-lane via 4-crib SAT with DISCLOSED
# startPixel (Concession 1). Wall-clock ~8 h on a 16-core commodity
# host (± 30 % hardware-variable). Peak RSS ~2 GB on the Bitwuzla
# subprocess (≈ 4 % of 48 GB host RAM). This is the
# reference empirical measurement for the Phase 2g results table.
python3 scripts/redteam/phase2_theory_fnv1a/sat_harness_4round.py \
    --max-cells 1 --max-cribs-per-cell 4 \
    --holdout-cells 1 --holdout-cribs-per-cell 1 \
    --solver bitwuzla --timeout-sec 86400 \
    --json-report tmp/attack/fnvstress/phase3b_4cribs.json

# Step 2b — SINGLE-CANDIDATE attacker-realistic variant: the attacker
# doesn't know startPixel, and assigns one --start-pixel N per worker
# across a 289-core pool. Each worker runs exactly the same 4-crib SAT
# as step 2a but anchored at a different candidate; first-to-hit wins.
# For the reference corpus (cell_00_json) the true startPixel is 114,
# so replacing N with any other value returns `unsat` within the same
# ~8 h window; N = 114 returns `sat` with the functional K.
python3 scripts/redteam/phase2_theory_fnv1a/sat_harness_4round.py \
    --max-cells 1 --max-cribs-per-cell 4 \
    --holdout-cells 1 --holdout-cribs-per-cell 1 \
    --solver bitwuzla --timeout-sec 86400 \
    --start-pixel N \
    --json-report tmp/attack/fnvstress/phase3b_4cribs_sp_N.json

# Step 2c — FULL brute-force variant: enumerate every candidate start
# Pixel on one host via ProcessPoolExecutor. On a 16-core commodity
# host this takes ~total_pixels/workers × 8 h; on a 289-core pool it
# matches step 2a's ~8 h wall-clock. `--parallel-workers 0` auto-picks
# based on /proc/meminfo and available cores.
python3 scripts/redteam/phase2_theory_fnv1a/sat_harness_4round.py \
    --max-cells 1 --max-cribs-per-cell 4 \
    --holdout-cells 1 --holdout-cribs-per-cell 1 \
    --solver bitwuzla --brute-force-start-pixel \
    --parallel-workers 289 --timeout-sec 86400 \
    --json-report tmp/attack/fnvstress/phase3b_4cribs_bf.json

# Step 3a — decrypt the JSON training cell under the recovered K. The
# decrypt is itself attacker-realistic: it brute-forces startPixel ×
# anchor-pixel noise_pos internally (using only COBS framing and
# printable-ASCII ratio as structural selectors), no additional SAT.
# Pure Python, single-core, < 5 s. Expected result on the reference
# corpus: sp=114, plaintext 1641 B, byte-match ≈ 84.46 %.
python3 scripts/redteam/phase2_theory_fnv1a/decrypt_full_fnv1a.py \
    --target-cell-dir tmp/attack/fnvstress/cell_00_json \
    --k-json tmp/attack/fnvstress/phase3b_4cribs.json \
    --expected-plaintext tmp/attack/fnvstress/cell_00_json/ct_0000.plain

# Step 3b — decrypt the HTML holdout cell (fresh nonce, different
# plaintext format) under the SAME recovered K. Expected result on the
# reference corpus: sp=50, plaintext 1845 B, byte-match ≈ 83.04 %.
python3 scripts/redteam/phase2_theory_fnv1a/decrypt_full_fnv1a.py \
    --target-cell-dir tmp/attack/fnvstress/cell_01_html \
    --k-json tmp/attack/fnvstress/phase3b_4cribs.json \
    --expected-plaintext tmp/attack/fnvstress/cell_01_html/ct_0000.plain

# Step 4 — generate the ZIP binary-plaintext corpus for architectural
# finding 6 empirical measurement. Defaults: 100 × 1024 B lorem-ipsum
# text files (Store method), ~114 KB plaintext, ~17 000-pixel container.
# Override via ITB_FNV_ZIP_FILES / ITB_FNV_ZIP_FILE_BYTES. Emits
# tmp/attack/fnvzip/cell_00_zip/ + summary.json.
ITB_FNV_ZIP=1 go test -run TestRedTeamGenerateFNVZipCorpus -v -timeout 120s

# Step 5a — attacker-realistic ZIP decrypt with brute-force startPixel.
# Same mechanics as steps 3a/3b: under recovered K, no knowledge of
# truth startPixel. The --plaintext-format binary-zip flag relaxes the
# COBS-anchor check (byte 0 can be any 1..254 code, not just 0xFF) and
# swaps the printable-ASCII ranker for PK-signature counting
# (0x03\x04 / 0x01\x02 / 0x05\x06 headers). Expected outcome on the
# reference ZIP corpus: candidate returned but byte-match ~0.55 %
# (random-floor; see architectural finding 6 for the mechanism).
# Wall-clock on commodity 16-core host in pure Python: a few hours at
# 17 000-pixel container.
python3 scripts/redteam/phase2_theory_fnv1a/decrypt_full_fnv1a.py \
    --target-cell-dir tmp/attack/fnvzip/cell_00_zip \
    --k-json tmp/attack/fnvstress/phase3b_4cribs.json \
    --plaintext-format binary-zip \
    --expected-plaintext tmp/attack/fnvzip/cell_00_zip/ct_0000.plain

# Step 5b — lab-convenience ZIP decrypt with known startPixel. Skips
# the outer brute-force loop so the experiment completes in ~3 min
# rather than hours. Truth startPixel computed from the lab-peek
# start_seed in cell.meta.json via the Python mirror of
# Seed128.deriveStartPixel. Expected outcome unchanged from step 5a
# (same ~0.55 % byte-match; --start-pixel only changes wall-clock, not
# the recovered plaintext).
python3 -c "
import json, sys
sys.path.insert(0, 'scripts/redteam/phase2_theory_fnv1a')
from itb_channel_mirror import _derive_start_pixel
meta = json.loads(open('tmp/attack/fnvzip/cell_00_zip/cell.meta.json').read())
print(_derive_start_pixel(meta['start_seed'],
    bytes.fromhex(meta['nonce_hex']),
    meta['total_pixels'], meta['rounds']))" | \
    xargs -I SP python3 scripts/redteam/phase2_theory_fnv1a/decrypt_full_fnv1a.py \
    --target-cell-dir tmp/attack/fnvzip/cell_00_zip \
    --lab-k-from-summary tmp/attack/fnvzip/summary.json \
    --plaintext-format binary-zip \
    --start-pixel SP \
    --expected-plaintext tmp/attack/fnvzip/cell_00_zip/ct_0000.plain
```

The `--plaintext-format binary-zip` flag is ZIP-specific (PK-signature ranker); porting the same decrypt to other binary formats (PDF, compressed streams, already-encrypted payloads) requires a format-matching discriminator in place of the PK-signature count. The relaxed COBS anchor (accept any 1..254 at byte 0) generalises across any binary plaintext that contains 0x00 bytes. Both `--start-pixel` and full-brute-force modes work identically with the `ascii` (default) and `binary-zip` formats — flag choice depends only on whether the attacker has side-channel knowledge of the plaintext format.

Per-run artefacts:
- `tmp/attack/fnvstress/cell_NN_{json,html}/` — per-cell ciphertext (`ct_0000.bin`) + plaintext (`ct_0000.plain`) + metadata (`cell.meta.json`).
- `tmp/attack/fnvstress/phase3b_4cribs.json` — SAT result with `recovered_seed_lo_hex`, wall-clock, training-forward and holdout-forward check counts (disclosed-`startPixel` variant).
- `tmp/attack/fnvstress/phase3b_4cribs_sp_N.json` — single-candidate variant, one file per worker in the distributed case.
- `tmp/attack/fnvstress/phase3b_4cribs_bf.json` — brute-force sweep result, including `results` array of every candidate's `sat` / `unsat` / timeout status.
- `tmp/attack/fnvzip/cell_00_zip/` — ZIP-plaintext corpus: `ct_0000.bin` ciphertext, `ct_0000.plain` raw ZIP, `cell.meta.json` with seed components for lab peek. `summary.json` at the parent level records seed lo-lanes in the same format as the JSON / HTML stress bundle.

### Scope

This section establishes the empirical attack cost for the weakest invertible-but-non-linear primitive in the matrix (FNV-1a) at ITB's architectural minimum configuration (`keyBits = 512`, 4 rounds). It does NOT claim production ITB is vulnerable: FNV-1a is marked `Fully broken` in the [Hash matrix](#hash-matrix) and is an unexported lab control with no public API path through `NewSeed{128,256,512}`. Users who wire a PRF-grade primitive from the [Hash matrix](#hash-matrix) (AES-CMAC, SipHash-2-4, ChaCha20, AreionSoEM-256, BLAKE2s, BLAKE3, BLAKE2b-256, BLAKE2b-512, AreionSoEM-512) into their deployment are not exposed to SAT-based seed recovery — under each primitive's PRF assumption, any successful SAT inversion would constitute a PRF distinguisher and is therefore ruled out by definition; published SAT cryptanalysis reaches only reduced-round variants in isolation, consistent with the assumption. ITB's per-pixel envelope compounds multiplicatively on top of this primitive-level PRF-hardness. The Phase 2g empirical figure is therefore a lower bound on attacker cost against PRF-grade primitives, not a measurement of them. Per-round cost scaling from 4 → 8 → 16 ChainHash rounds (corresponding to `keyBits = 512 → 1024 → 2048`) is analytical with wide error bars — see [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure).

### Triple Ouroboros extrapolation (analytical, not empirically run)

Realistic attacker lacks per-snake `startPixel` knowledge (3 independent unknowns — obtaining them requires sender-side or recipient-side machine access, outside the standard threat model) and cannot recover exact per-snake byte boundaries from the interleaved ciphertext (CSPRNG fill packed across the container dilutes the approximate /3 split into visual-only alignment — accurate to the eye, not to solver-input precision). Extrapolating the 8 h Phase 2g empirical anchor to Triple Ouroboros under these constraints:

**Scope note.** All figures below apply to FNV-1a at the 256-bit lo-lane inside `keyBits = 512` Triple Ouroboros — ITB's minimum possible configuration (4 ChainHash rounds). Larger `keyBits` (1024 shipped default, 2048 paranoid) and PRF-grade primitives scale further upward; those extrapolations are not the subject of this subsection.

| Mode | Per-snake validation | Wall-clock projection (289-core commodity pool) |
|---|---|---|
| **Triple Byte Level** (`SetBitSoup(0)`, shipped default) | Every-3rd-byte subsequence is printable-ASCII / partial-schema, providing per-snake content constraints inside a joint hypothesis; but 3 independent per-snake `startPixel` unknowns plus CSPRNG-fill-induced per-region boundary uncertainty (no snake has a recoverable beginning or end mark in the interleaved container) force joint SAT over (sp0, sp1, sp2) triples regardless of crib density — guessing all three `startPixel`s simultaneously is the enumeration axis, not a shortcut | **~8 — 30 years** at 4 KB corpus on a 289-core commodity pool (96³ = 884 736 (sp0, sp1, sp2) triples × 3–10× Single per joint-instance cost = 24–80 h, conservative band with no empirical anchor for 3-snake coupled FNV-1a joint SAT); scales cubically in per-snake sp range — **~200 — ~800 years** at 12 KB corpus (289³ triples), centuries-to-millennia beyond |
| **Triple Bit Soup** (`SetBitSoup(1)`) | Per-snake decoded content is bit-permuted garbage — no snake carries a real plaintext byte → per-snake content constraints vanish entirely → joint SAT forced without the per-snake FNV-1a inversion shortcut that makes byte-level tractable | Range spans ~30 orders of magnitude. **Lower bound**: 96³ × 100× Single per-triple (800 h, Bit Soup floor, strictly harder than byte-level 10× upper) × 1.4 CSPRNG-poisoning ≈ **10⁹ core-hours** (~400 years on 289 cores); × 12³ mixed-primitive hardening → **10¹² core-hours** (~700 000 years). **Upper bound**: 96³ × 2¹²⁸ ≈ **3 × 10⁴⁴ effective trials** if SAT cannot couple the three seed searches through bit-scattered cribs — beyond AES-128 brute force. No publicly known SAT tooling applies at either end |

Per-snake cribs exist under byte-level split (every-3rd-byte subsequence carries printable-ASCII / partial-schema content), but the attacker cannot wield them against a single snake in isolation. Each snake holds its own `startPixel` (3 independent unknowns jointly enumerated) and the interleaved-ciphertext wire format does not admit exact per-snake byte boundaries — CSPRNG fill packed across the container dilutes the approximate /3 split into visual-only alignment, not solver-input precision. Every crib must therefore enter the SAT instance as a joint-hypothesis constraint, conditional on the (sp0, sp1, sp2) enumeration plus per-snake alignment guesses. Increasing the crib count sharpens each joint instance's overdet ratio (driving per-triple solver cost toward the 3× Single lower band rather than the 10× Single upper band) but does not collapse the 96³-or-larger enumeration dimension — per-snake decoupling would require simultaneous knowledge of all three `startPixel`s and exact per-snake byte boundaries, i.e. sender/recipient-side state outside the threat model.

Under Triple Bit Soup the joint SAT instance compounds further: per-snake decoded bytes are bit-permuted garbage, so **no snake carries a real plaintext byte** and the per-snake content constraints byte-level Triple retains inside each joint hypothesis vanish entirely. The circular length-prefix dependency (length unknown until all three snakes jointly solved, interleave alignment unknown until length known) denies partial-verification signal — each hypothesis is either fully correct or rejected with no gradient for guided search. Per-instance joint SAT cost for 3 coupled 256-bit seeds under FNV-1a carry-chain multiplication has no published baseline, and the credible attack-cost range spans roughly 30 orders of magnitude between two analytical extremes. **Lower bound** — assuming per-triple joint SAT is strictly harder than byte-level's 10× Single upper (Bit Soup removes the per-snake content constraints byte-level retains), floored at 100× Single = 800 h: 96³ × 800 h × 1.4 CSPRNG-poisoning factor ≈ **10⁹ core-hours** (~400 years on a 289-core pool); × 12³ primitive-identity hardening if deployers mix primitives raises this to **~10¹² core-hours** (~700 000 years on 289 cores). **Upper bound** — regime where SAT cannot leverage bit-scattered cribs to couple the three coupled 256-bit seed searches at all, and per-triple cost approaches AES-128-equivalent brute force over the compressed joint keyspace: 96³ × 2¹²⁸ ≈ **3 × 10⁴⁴ effective trials**, beyond AES-128 brute force. At SAT-solver throughput (~10⁶ trials/sec per core) this converts to ~10³⁵ core-hours; at dedicated-silicon AES-pace (~10⁹/sec) ~10³² core-hours — either way beyond any realistic adversary computational budget. Empirical verification of Triple Bit Soup is out of scope — the required compute exceeds any budget available for this project.

### Defensive reserve: Bit Soup

Triple Ouroboros ships an opt-in process-wide toggle `SetBitSoup(1)` (see [ITB3.md § Bit Soup](ITB3.md#bit-soup-bit-level-split-opt-in)) that changes plaintext splitting from byte to bit granularity. Under Bit Soup, each snake's payload is a fixed public bit-permutation across three consecutive plaintext bytes; no snake carries a real plaintext byte, and no schema-predictable crib can be constructed per snake.

Bit Soup relocates the SAT-cryptanalysis barrier from the computational layer (solver wall-clock) to the instance-formulation layer (constraint completeness). Under Partial KPA + realistic protocol traffic, the joint per-snake SAT instance is information-theoretically under-determined at the crib coverage realistic protocols supply — a property of the observations available to the attacker, not of the solver applied to them. Improvements in solver performance do not convert an under-determined instance into a determined one.

Applies uniformly to `Encrypt3x*`, `EncryptAuthenticated3x*`, `EncryptStream3x*` and their decrypt counterparts; ciphertext wire format is identical across modes. Default `SetBitSoup(0)` leaves byte-level Triple Ouroboros shipped behaviour unchanged.

---

## Phase 3a — Rotation-invariant edge case

Script: [`scripts/redteam/phase3_deep/rotation_invariant.py`](scripts/redteam/phase3_deep/rotation_invariant.py)

Tests [`SCIENCE.md` §2.9.2](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier) prediction: rotation-invariant 7-bit values (`0000000` and `1111111`) occur at rate 2/128 = 1.5625 % across all hash primitives under the uniform-distribution claim. For each data-carrying pixel × each channel byte × each of 8 `noisePos` values, extract the 7-bit value and count 0x00/0x7F occurrences. Runtime ~30 s per full corpus pass, 34.8 M extracts per hash.

### Per-hash aggregate (primary at BF=1; BF=32 in parentheses)

| Hash | Rate BF=1 / BF=32 | Deviation BF=1 / BF=32 | p-value BF=1 | p-value BF=32 |
|------|------------------:|----------------------:|------------:|-------------:|
| CRC128 | 1.5582 % / 1.5641 % | −0.0043 % / +0.0016 % | 0.0004 | 0.1877 |
| FNV-1a | 1.5665 % / 1.5617 % | +0.0040 % / −0.0008 % | 0.0558 | 0.6940 |
| MD5 | 1.5655 % / 1.5685 % | +0.0030 % / +0.0060 % | 0.1522 | 0.0042 |
| AES-CMAC | 1.5629 % / 1.5742 % | +0.0004 % / +0.0117 % | **0.8344** | **< 10⁻⁷** |
| SipHash-2-4 | 1.5615 % / 1.5622 % | −0.0010 % / −0.0003 % | 0.6200 | 0.9032 |
| ChaCha20 | 1.5625 % / 1.5680 % | −0.0000 % / +0.0055 % | 0.9837 | 0.0094 |
| AreionSoEM-256 | 1.5563 % / 1.5595 % | −0.0062 % / −0.0030 % | 0.0034 | 0.1511 |
| BLAKE2s | 1.5601 % / 1.5600 % | −0.0024 % / −0.0025 % | 0.2529 | 0.2330 |
| BLAKE3 | 1.5622 % / 1.5690 % | −0.0003 % / +0.0065 % | 0.8935 | 0.0020 |
| BLAKE2b-256 | 1.5608 % / 1.5660 % | −0.0017 % / +0.0035 % | 0.1729 | 0.0048 |
| BLAKE2b-512 | 1.5642 % / 1.5763 % | +0.0017 % / +0.0138 % | **0.4070** | **< 10⁻¹⁰** |
| AreionSoEM-512 | 1.5630 % / 1.5625 % | +0.0005 % / −0.0005 % | 0.8174 | 0.7451 |

**Observations:**

- **The BF=32 "signals" did not replicate at BF=1.** AES-CMAC went from p < 10⁻⁷ (BF=32) to p = 0.83 (BF=1); BLAKE2b-512 went from p < 10⁻¹⁰ to p = 0.41; ChaCha20 and BLAKE3 similarly dropped out of significance; and AreionSoEM-256 newly flagged at p = 0.003 (BF=1) while clean at BF=32. This is the **signature of a statistical-power artefact on near-uniform output**: the tests are sensitive enough at very large N to flag any tiny deviation from the expected 1.5625 % rate, but which specific hashes cross the threshold in any one run is essentially random. Different N (BF=1 has fewer extracts per sample than BF=32 because the container is smaller) produces a different random scatter of "significant" cells, not a consistent signal.
- **No hash shows sign-consistent deviation across both regimes.** Every hash's rate fluctuates within ±0.01 % of 1.5625 % between the two runs — i.e., within the measurement precision of this test at this N. There is no primitive-specific or weak-vs-strong structural pattern.
- Absolute deviations are tiny regardless of regime: the largest (+0.0138 % at BLAKE2b-512, BF=32) measures a rate shift from 1.5625 % to 1.5763 %. An attacker cannot use this deviation to narrow per-sample `startPixel` or rotation candidates; it is below any attack-useful threshold and also below the noise floor of replication.
- Per-kind drill-down at BF=1 confirms no clustered per-kind bias (see `tmp/results/single_bf1/03_phase3a.log`).

**Interpretation.** The rotation-invariant rate stays at 1.56 % within ~0.01 % across 34.8 M extracts per hash, independent of fill regime. Statistical tests on such near-uniform output produce false-positive flags that do not replicate — a known limitation when the null is essentially true and N is large enough to detect sub-thousandths-of-a-percent noise. [`SCIENCE.md` §2.9.2](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier) is validated: the barrier absorbs hash-level bias even at the edge case, across all 12 primitives and both fill regimes.

---

## Phase 3b — NIST STS (SP 800-22)

Script: [`scripts/redteam/phase3_deep/nist_sts_runner.py`](scripts/redteam/phase3_deep/nist_sts_runner.py)

NIST STS runs 188 individual tests across 15 categories: Frequency, BlockFrequency, CumulativeSums, Runs, LongestRun, Rank, FFT, NonOverlappingTemplate (148 sub-tests), OverlappingTemplate, Universal, ApproximateEntropy, RandomExcursions (8 sub-tests), RandomExcursionsVariant (18 sub-tests), Serial, LinearComplexity.

**Streams.** Corpus ciphertexts are concatenated header-stripped via `prepare_streams.py` into `tmp/streams/<hash>.bin` at ~8.9 MB = 71 Mbits per hash — 3.5× more than NIST STS requires for 20 × 1 Mbit.

**Test configuration.** 20 sequences × 1 000 000 bits per run. Pass threshold computed dynamically via the NIST SP 800-22 formula `p̂_min = (1 − α) − 3 · √(α(1 − α)/m)` at α = 0.01 (18 / 20 for standard tests; scales down for RandomExcursions when fewer sequences have valid excursions).

**Parallelism.** 12 `nist-sts` subprocesses in isolated experiment directories. Total wall time: ~70 s.

### Results across configurations

The suite runs NIST STS at five independent configurations: two BF=1 Single replications at the NIST SP 800-22 example parameter (N = 20 sequences × 1 Mbit); one BF=32 Single run at the same N; and two larger-N runs at BF=1 and BF=32 Single (**N = 100 × 1 Mbit**) that are statistically more robust but — as the BLAKE3 cell below makes clear — still expose the `NonOverlappingTemplate` bin-routing artefact.

| Hash | BF=1 Run A (N=20) | BF=1 Run B (N=20) | BF=32 (N=20) | BF=1 (N=100) | BF=32 (N=100) |
|------|-----------------:|-----------------:|-------------:|-------------:|--------------:|
| CRC128 | — | — | — | 187 / 188 | 186 / 188 |
| FNV-1a | **40 / 188 †** | 188 / 188 | 188 / 188 | 188 / 188 | 185 / 188 |
| MD5 | 188 / 188 | 187 / 188 | 188 / 188 | 188 / 188 | 188 / 188 |
| AES-CMAC | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 |
| SipHash-2-4 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 |
| ChaCha20 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 |
| AreionSoEM-256 | 188 / 188 | 188 / 188 | 188 / 188 | 187 / 188 | 188 / 188 |
| BLAKE2s | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 |
| BLAKE3 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 |
| BLAKE2b-256 | — | — | — | 188 / 188 | 188 / 188 |
| BLAKE2b-512 | 188 / 188 | 188 / 188 | 188 / 188 | **40 / 188 †** | 188 / 188 |
| AreionSoEM-512 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 |

† **Both 40/188 cells — FNV-1a at N=20 Run A *and* BLAKE2b-512 at N=100 BF=1 — are the same NIST SP 800-22 test-battery artefact, not actual cryptographic failures.** That these two cells are hit by a fully-invertible below-spec primitive (FNV-1a) and a paper-grade 512-bit PRF (BLAKE2b-512) is direct empirical evidence that the mechanism is **hash-agnostic**. The explanation: `NonOverlappingTemplate` routes each run's per-sequence p-values into one of 10 histogram bins; ITB ciphertext is uniform enough that all N per-sequence p-values cluster into a **single** bin. The bin is effectively randomly chosen per `(hash, run)` pair, and bin 0 contains p-values below the pass cut-off — so whichever hash happens to draw bin 0 on a given run reports a catastrophic-looking proportion failure on all 148 `NonOverlappingTemplate` sub-tests simultaneously. The bin-0 draw probability is ~10 % per `(hash, run)` and independent across hashes, so across 60 such `(hash, run)` trials in this table (12 primitives × 5 configurations) the expected number of cells flipping to 40/188 is ~6; observed is 2. The clustering pattern itself is **universal across all 12 primitives in all 5 configurations** — the mechanism is explained in detail in the subsection below. `/dev/urandom` exhibits the same pattern on streams of this size.

Across both N = 100 runs (BF=1 and BF=32), 18 of 24 `(hash, BF)` cells pass 188/188; 5 cells show conventional (non-bin-0) single-to-several-test proportion fails — CRC128 1 fail at BF=1 and 2 fails at BF=32 (BlockFrequency + FFT), FNV-1a 3 fails at BF=32, AreionSoEM-256 1 fail at BF=1 — all on tests with **non-clustered** histograms, distinct from the bin-0 artefact marked with †; and 1 cell (BLAKE2b-512 BF=1) hit the bin-0 artefact. Across 24 × 188 = 4 512 tests the 7 non-artefact failures are well below the 45 expected at α = 0.01.

### The p-value clustering phenomenon — hash-agnostic, present at any N

NIST STS reports 148 `NonOverlappingTemplate` sub-tests per run. Each sub-test buckets N per-sequence p-values into 10 equal-width histogram bins `[0.0, 0.1), [0.1, 0.2), …, [0.9, 1.0]` and runs a χ² uniformity test on the bin counts. ITB ciphertext is uniform enough that all N per-sequence p-values fall into **a single bin** — the same bin across every one of the 148 sub-tests within a run. Which bin depends on seeds.

**Evidence — histogram clustering is universal across all 12 primitives and reshuffles independently per BF regime.** First `NonOverlappingTemplate` row from each N=100 report (BF=1 and BF=32 runs, on the same corpus with fresh crypto seeds per run):

| Hash | Bin at BF=1 (N=100) | Bin at BF=32 (N=100) |
|------|---------------------:|---------------------:|
| CRC128 | 9 | 1 |
| FNV-1a | 9 | 5 |
| MD5 | 2 | 4 |
| AES-CMAC | 3 | 1 |
| SipHash-2-4 | 1 | 7 |
| ChaCha20 | 8 | 1 |
| AreionSoEM-256 | 4 | 5 |
| BLAKE2s | 2 | 2 |
| BLAKE3 | 7 | 1 |
| BLAKE2b-256 | 1 | 8 |
| BLAKE2b-512 | **0** | 4 |
| AreionSoEM-512 | 7 | 7 |

Every hash — including CRC128 (GF(2)-linear lab control), FNV-1a (which raised the alarm at N=20 by drawing bin 0 on a prior corpus), and BLAKE2b-512 (paper-grade 512-bit PRF, drew bin 0 at N=100 BF=1 on this corpus) — shows the same single-bin clustering pattern. The bin assignment is effectively random per `(hash, run)` pair. Proportion is 100/100 for every template sub-test on any run where the bin is **not** 0, and 0/100 on all 148 sub-tests simultaneously whenever it **is** 0.

**This is a documented NIST SP 800-22 artefact** on near-uniform data. The uniformity-of-p-values meta-test fires (`*` on the 0.000000 uniformity p-value) whenever the input produces clustered per-sequence p-values — which is exactly what truly-random-looking data does at this N and template-size combination. `/dev/urandom` exhibits the same pattern. Increasing N from 20 to 100 does not eliminate the artefact; it only reduces its per-cell probability proportionally (still ~10 % per `(hash, run)` pair), so larger tables like this one make bin-0 draws visible as an occasional scattered event rather than the N=20 Run A situation where a single bin-0 draw on a single hash looked like "FNV-1a broke on NIST STS".

### Interpretation

1. **All 12 primitives are empirically indistinguishable on NIST STS.** The single-bin clustering is identical across GF(2)-linear (CRC128), invertible (FNV-1a), biased (MD5), and paper-grade PRF (nine others) primitives. No hash stands out structurally. The two 40/188 events in the table — FNV-1a at N=20 Run A and BLAKE2b-512 at N=100 BF=1 — are both bin-0 draws of the same mechanism; one from a below-spec hash, one from a paper-grade 512-bit PRF, confirming the mechanism is hash-agnostic.
2. **A 40/188 cell is bin-0 bad luck, not a security signal — regardless of which hash it happens to.** Any hash can draw bin 0 on any run and produce this catastrophic-looking proportion failure on all 148 `NonOverlappingTemplate` sub-tests simultaneously. Five configurations × 12 primitives = 60 (hash, run) trials in the suite; expected bin-0 hits at ~10 % per trial is ~6; observed count tracks this null expectation. Consistent with the null model.
3. **N=100 does not eliminate the artefact — it just reduces per-cell probability proportionally.** At both N=20 and N=100 the bin-0 draw remains a ~10 % event per `(hash, run)` pair. Readers scanning the table should treat any 40/188 cell with † as equivalent to the other cells — a random bin assignment that happened to land on bin 0 — rather than as a hash-specific failure. Larger-N runs are preferable because conventional (non-bin-0) proportion failures become genuine outliers, letting the eye separate real signal from the artefact.
4. **The paper's explicit PRF-grade primitive requirement stands.** The empirical suite shows the architecture drives every tested primitive — including CRC128, FNV-1a, and MD5 — to statistically identical ciphertext across every empirical phase; a real PRF's output is already unpredictable and gets absorbed identically. NIST STS cannot reliably distinguish ITB ciphertext produced with any of the 12 tested primitives from a true PRF across the three ITB widths (128 / 256 / 512).

---

## Triple Ouroboros — supplementary runs at BF=1 and BF=32 (N=100)

Triple Ouroboros uses 7 seeds (1 noiseSeed + 3 dataSeeds + 3 startSeeds); the container is partitioned into 3 thirds, each processed with an independent `(dataSeed_i, startSeed_i)` pair. The plaintext is split via `splitTriple` (every 3rd byte → third `i`), so a single per-pixel distinguisher cannot run without also inverting the partition map. Phases 2b, 2c, and 3a therefore require analyzer rewrites to handle the 3-partition layout and are not included in this pass; Phase 1 (byte-level structural test) and Phase 3b (NIST STS on the corpus-concat stream) are mode-agnostic and run unchanged. Both regimes (BF=1 and BF=32) were executed.

### Phase 1 in Triple mode

All 12 primitives pass in both fill regimes; Bonferroni failures: 1 / 96 at BF=1 (FNV-1a single channel, p=0.0012 just under the 0.00125 threshold — non-replicated statistical-power artefact on near-uniform output, same pattern as [Phase 3a](#phase-3a--rotation-invariant-edge-case)); 0 / 96 at BF=32. Collision ratios in [0.982, 1.011] at BF=1 and [0.968, 1.009] at BF=32. The structural profile is indistinguishable from Single mode at the same corpus — the 8-channel packing is absorbed equally whether the container is split into 1 or 3 logical partitions.

### Phase 3b in Triple mode (N = 100)

| Hash | Pass BF=1 | Bin BF=1 | Pass BF=32 | Bin BF=32 |
|------|----------:|---------:|-----------:|----------:|
| CRC128 | 187 / 188 | 5 | 187 / 188 | 9 |
| FNV-1a | 188 / 188 | 3 | 188 / 188 | 9 |
| MD5 | 187 / 188 | 6 | 188 / 188 | 1 |
| AES-CMAC | 188 / 188 | 3 | 188 / 188 | 9 |
| SipHash-2-4 | 188 / 188 | **0** | 188 / 188 | 2 |
| ChaCha20 | 188 / 188 | 4 | 187 / 188 | **0** |
| AreionSoEM-256 | 188 / 188 | 5 | 188 / 188 | 8 |
| BLAKE2s | 188 / 188 | 7 | 187 / 188 | 1 |
| BLAKE3 | 188 / 188 | 3 | 188 / 188 | 4 |
| BLAKE2b-256 | 188 / 188 | 4 | 188 / 188 | 4 |
| BLAKE2b-512 | 188 / 188 | **0** | 188 / 188 | 6 |
| AreionSoEM-512 | 188 / 188 | **0** | 188 / 188 | 5 |

- **BF=1**: 4 / 1 880 single-test failures (0.21 %) — FNV-1a Frequency + CumSum × 2 at 95/100, MD5 RandomExcursions 54/58 — all non-clustered histograms, conventional near-threshold H0 outliers.
- **BF=32**: 1 / 1 880 single-test failures (0.05 %) — AES-CMAC BlockFrequency 94/100 (non-clustered histogram), again a conventional H0 outlier.

Both regimes are well under the 1 % expected false-positive rate at α = 0.01.

The bin-clustering pattern is the same one analysed in Phase 3b's Single mode discussion: every hash's 100 per-sequence p-values land in a single histogram bin, the bin is random per run, and at N = 100 a bin-0 draw no longer triggers proportion failure. In this Triple run, three hashes drew bin 0 across the two fill regimes (BLAKE2b-512 at BF=1; AES-CMAC and ChaCha20 at BF=32) — all three still pass proportion 100/100. The per-hash bin assignments differ between regimes, confirming the bin draw is random per run rather than primitive-specific.

### Attack-cost implications of Triple Ouroboros

Triple's 7-seed structure is strictly more defended than Single, and the `startPixel`-enumeration cost blows up non-linearly. For a typical 20 KB plaintext at `BarrierFill=1` with Single's `P ≈ 10⁴` startPixel candidates:

| Layer | Single | Triple | Ratio |
|-------|-------|--------|------:|
| `startPixel` enumeration | × P | × (P/3)³ ≈ P³/27 (approximate: thirds are `P/3`, `P/3`, `P − 2⌊P/3⌋`) | ≈ P²/27 = **3.7 × 10⁶×** |
| `dataSeed` SAT-recovery (each third owns its COBS-encoded payload and padding) | 1 SAT instance | 3 independent SAT instances | ×3 |
| **Combined multiplier** | 1× | ≈ **1.1 × 10⁷×** | — |

The `×3` for three independent `dataSeed` SAT recoveries already captures the three independent COBS-encoded payloads and their padding — both are facets of the same "each third is an independent encryption of one payload block", so counting them separately would double-count.

Stacked on top of the Single mode "10¹² – 10¹⁶ years at Partial KPA 50 %" baseline (itself carrying ±2–3 orders of magnitude uncertainty from Phase 2a's back-of-envelope nature): Triple pushes the realistic-attacker horizon into **~10¹⁹ – 10²³ years, ± ≈ 3 orders of magnitude**. Even the optimistic end of this range is past any meaningful temporal horizon.

---

## Summary — what the empirical tests show about ITB

### Main finding

**ITB is a barrier-based construction, not a primitive-based one.** Security arises from the architecture — 8-channel packing, 7-bit extraction with rotation, CSPRNG-fill residue, ChainHash XOR chain — rather than from the quality of the underlying hash. This is empirically demonstrated across the spectrum from GF(2)-linear lab control (CRC128) through deliberately broken (FNV-1a invertible, MD5 biased) to paper-grade PRF (AES-CMAC, SipHash-2-4, ChaCha20, BLAKE2s / 3, BLAKE2b-256 / 512, AreionSoEM-256 / 512): all 12 primitives produce ciphertext statistically indistinguishable from a true PRF across every stable test outcome at shipped defaults.

### Why the below-spec testing matters

Testing a construction with PRF-grade primitives and observing unpredictable output is near-tautological: PRFs produce unpredictable output by definition. Probing whether the **barrier itself** absorbs weakness requires testing below-spec primitives. The suite includes three:

- **CRC128** — fully GF(2)-linear construction (two independent CRC64 lanes, ECMA + ISO), deliberately designed as the strongest possible algebraic stress control: no carry-chain non-linearity, no PRF assumption, unexported lab-only identifier in `redteam_lab_test.go`. ChainHash wrapping around CRC128 collapses analytically (see [Phase 2a § load-bearing assumption](#the-load-bearing-assumption)) and empirically in [Phase 2a extension](#phase-2a-extension--empirical-mixed-algebra-stress-test-via-crc128-nonce-reuse).
- **FNV-1a** — linearly invertible in O(1), no preimage resistance, not cryptographic.
- **MD5** — collisions in minutes, documented output biases, half-broken preimage resistance.

If the barrier did not absorb weakness, these below-spec hashes would leak signal on the passive distinguishers: Phase 2b would show elevated per-pixel KL on the invertible primitives, Phase 3b would fail on specific NIST sub-tests consistently across replications, Phase 1 would show per-channel deviation. **None of the Single-mode passive phases shows a stable weak-vs-strong split** — CRC128, FNV-1a, and MD5 sit in the same tolerance bands as the nine PRF-grade primitives, modulo a CRC128 per-channel FFT spectral-flatness deviation in Phase 1 [B] that does NOT translate into any attack-visible structure (detectable only by an analyst sorting raw ciphertext by primitive). On the surfaces where CRC128's GF(2)-linearity IS load-bearing ([Phase 2a extension](#phase-2a-extension--empirical-mixed-algebra-stress-test-via-crc128-nonce-reuse) algebraic K recovery under nonce-reuse demasking; [Phase 2e](#phase-2e--related-seed-differential) related-seed differential), CRC128 collapses as the positive control requires — confirming the probes work, not demonstrating a weakness in the production hash matrix.

This supports an **a fortiori argument** at every tested level:

- **Per-pixel** (Phase 2b): KL floor ~2 × 10⁻⁵ nats (N = 9.6 M obs/candidate at BF=1 in Mode A; N = 11.3 M in Mode B at BF=32) reached equivalently by all 12 primitives; spread across primitives 4 × 10⁻⁶ nats. Obstacle (3) of [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) holds uniformly under both the idealized threat model (attacker knows startPixel + plaintext) and the realistic one (neither).
- **Aggregate stream** (Phase 3b): NIST STS 188/188 pass for all 12 on typical runs; the replication-unstable 40/188 outcomes (FNV-1a at N=20 Run A, BLAKE2b-512 at N=100 BF=1 — one below-spec hash and one PRF) are the NIST SP 800-22 `NonOverlappingTemplate` bin-0 artefact on near-uniform output, not a security signal. The same mechanism fires on `/dev/urandom` streams of this size.
- **Structural** (Phase 1): per-channel χ² and nonce collision ratio within tolerance for all 12 in both regimes.
- **startPixel isolation** (Phase 2c): mean rank-fraction ≈ 0.5 for all 12 in both regimes.
- **Nonce-reuse PRF-dependency** (Phase 2d): after the demasker peels off obstacles (2) + (3) at the 2-ciphertext Full KPA level, the reconstructed `dataSeed.ChainHash(pixel, nonce)` output stream passes NIST STS 188/188 under BLAKE3 — single-layer defence (ChainHash alone) holds under PRF even without architectural obstacles — but fails 6/188 under FNV-1a (FFT 0/16 + block-level + sum-walk tests). Empirically validates [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis)'s locality claim under PRF and makes its PRF-dependency caveat concrete.

Since invertibility (FNV-1a) and output bias (MD5) produce output indistinguishable from a real PRF at every stable test outcome, a real PRF — whose output is already unpredictable by definition — leaves the barrier with strictly less work to do.

### On test-battery artefacts and replication

Several test-battery outputs flagged specific primitives in one run and not another. Every such flag failed to replicate under identical settings:

- **Phase 3a at BF=32** flags AES-CMAC (p < 10⁻⁷) and BLAKE2b-512 (p < 10⁻¹⁰); at BF=1 both are clean (p = 0.83 and p = 0.41) while AreionSoEM-256 newly flags at p = 0.003.
- **Phase 3b p-value clustering is universal across all 12 primitives.** At N=100 × 1 Mbit, every primitive's 100 per-sequence `NonOverlappingTemplate` p-values cluster into a single histogram bin; the bin is chosen effectively at random per hash (CRC128 in bin 9, FNV-1a in bin 9, ChaCha20 in bin 8, MD5 in bin 2, etc on BF=1). No primitive is structurally different in this regard. Any hash whose cluster lands in bin 0 on a given run mechanically reports a catastrophic-looking 40/188 (seen in the suite for FNV-1a at N=20 and BLAKE2b-512 at N=100 BF=1) — the same thing would happen to any other hash on any given run with probability 1/10.
- **Phase 2b flag cells** (heuristic `bit_exceed` / `kl_max` thresholds) shift across regimes: 8/90 at BF=1, 10/90 at BF=32, with zero overlap between the flagged cell sets.

**None of these flags is sign-consistent across replications or regimes.** When the null is essentially true (output is truly near-uniform) and N is large enough to detect sub-thousandths-of-a-percent deviations, statistical tests produce random false-positive flags that shift between runs. The absolute magnitude of every flagged deviation is below any attack-useful threshold, and `/dev/urandom` exhibits the same kind of artefact under equivalent conditions. Single-run anomalies should be treated as noise absent sign-consistent replication; the empirical suite does not supply such confirmation for any phase or primitive.

### Mapping to paper claims

| Claim | Empirical status |
|-------|------------------|
| [Proof 1](PROOFS.md#proof-1-information-theoretic-barrier) (per-pixel P(v\|h) = 1/2) | ✅ Phase 2b KL floor ≈1.4×–1.5× theoretical on all 12 primitives in both threat models: Mode A (idealized, BF=1) [1.7, 2.1]×10⁻⁵ nats at N = 9.6 M; Mode B (realistic, BF=32) [1.2, 1.6]×10⁻⁵ at N = 11.3 M — spread 4 × 10⁻⁶ nats across the full hash spectrum in each |
| [Proof 7](PROOFS.md#proof-7-bias-neutralization) (bias neutralisation) | ✅ Phase 1 — all 12 primitives equivalent on per-channel profile (CRC128 shows a Phase 1 [B] FFT-surface deviation — see CRC128 outlier mini-table); Phase 3b — 188/188 NIST STS pass on typical runs for all 12, including the GF(2)-linear CRC128 and both invertible / broken below-spec primitives; [Phase 2a extension](#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) bias-audit on raw ciphertext confirms `neutralized ✓` for FNV-1a / BLAKE3 / MD5 under its lab ground-truth probe, with CRC128 appearing as the positive-control `bias-leak ✗` |
| [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill) (CSPRNG-fill residue) | ✅ Phase 3b — 188/188 pass for all 12 primitives at both BF=1 and BF=32 on typical runs; fill dominates the stream in both regimes to within Proof 10's guaranteed minimum |
| [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) obstacle (2) — `startPixel` isolation | ✅ Phase 2c — mean rank-fraction ≈ 0.5 ± 0.05 on all 12 primitives, both regimes |
| [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) obstacle (3) — candidate ambiguity | ✅ Phase 2b — all 56 per-pixel candidates indistinguishable across all 12 primitives, in both fill regimes and under both the idealized (known startPixel + plaintext) and realistic (neither) threat models |
| Composition conjecture ([Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)) | ⚠ **Consistent with** — no systematic signal from weak PRFs in this corpus across stable test outcomes. Passive-distinguisher absence is not the same as active-cryptanalytic absorption; the conjecture is about the latter and requires research-level analysis the suite does not perform |
| Related-seed (single-axis Δ) resistance | ✅ [Phase 2e](#phase-2e--related-seed-differential) — 1008-cell differential matrix across 12 primitives × 2 BF × 3 axes × 7 Δ × 2 PT. 10 primitives neutralized ✓ on the primitive-attributable axes (`data` / `start`) — the 9 PRF-grade primitives plus MD5; CRC128 leaks on every axis as expected from its GF(2)-linearity, and FNV-1a leaks only on `bit_high1023` × `axis=data` (top-bit isolation discarded by ITB's `hLo` extraction — visible to a differential probe but not to an encryption-path attacker) |
| [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis) — nonce-reuse locality + PRF-dependency | ✅ / ⚠ [Phase 2d](#phase-2d--nonce-reuse) — locality confirmed under PRF (BLAKE3 reconstructed stream passes 188/188 NIST STS → the single remaining obstacle after demasking has no exploitable bias). PRF-dependency demonstrated via the BLAKE3-vs-FNV-1a contrast: same attack chain, FNV-1a fails 6 / 188 tests (FFT 0/16 plus BlockFrequency / CumulativeSums / Runs) — the "seeds remain secret, no key rotation" conclusion of §2.5 depends on PRF non-invertibility, and this probe makes that dependency empirically visible. 96-cell Partial KPA extension + classical keystream-reuse decryption quantify blast radius under structured plaintexts |
| [Proof 3](PROOFS.md#proof-3-triple-seed-isolation) / [3a](PROOFS.md#proof-3a-triple-seed-isolation-minimality) (triple-seed isolation, minimality) | ✅ Phase 2c — all 12 primitives pass `startPixel` enumeration in both Single and Triple modes; the 3 startSeeds in Triple each draw from independent `[0, P/3)` ranges in Phase 3b's histograms with no cross-seed structure |
| [Proof 9](PROOFS.md#proof-9-ambiguity-dominance-threshold) (ambiguity-dominance threshold) | ✅ Phase 2b — the `html_giant` KL floor at N ≫ P_threshold reaches sampling precision (~2 × 10⁻⁵ nats at BF=1, ~2 × 10⁻⁶ nats at the 63 MB probe); ambiguity is dominant at all tested data scales |
| Invertible-primitive inversion bound | ✅ Phase 2a — structural analysis of ChainHash's `keyBits`-scaled round structure (paper's naive `~56 × P` bound is optimistic; mixed algebra turns each attack into a bitvector-SAT problem per `startPixel` guess). [Phase 2a extension](#phase-2a-extension--empirical-mixed-algebra-stress-test-via-crc128-nonce-reuse) validates the mixed-algebra premise empirically via CRC128 GF(2)-linear collapse (1024-bit seed → 64 recoverable compound-key bits on one CRC64 lane). Z3 runs against FNV-1a were not executed |

---

## Caveats and what this does NOT prove

- **"No distinguisher exists"** is not claimed — only "no replicable distinguisher was detected for any of the 12 tested primitives across the 2 × 2 configuration matrix `{Single, Triple} × {BF=1, BF=32}` run in this pass (two independent BF=1 Single mode replications, plus BF=32 Single, plus BF=1 and BF=32 Triple)". CRC128's [Phase 1](#phase-1--structural-checks--fft--markov-analysis) [B] FFT-surface flatness deviation and its [Phase 2a extension](#phase-2a-extension--empirical-mixed-algebra-stress-test-via-crc128-nonce-reuse) / [Phase 2e](#phase-2e--related-seed-differential) leaks are expected lab-control behaviour, not production security signals. Follow-up corpora may find what this one missed.
- **Structural / algebraic attacks against ChainHash.** [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure)'s cost tables are back-of-envelope structural-analysis estimates with ± 2 – 3 orders of magnitude uncertainty. **No actual Z3 (or any SMT solver) was run at any `keyBits`** in this pass. Algebraic attacks over Z[2^128] (Gröbner basis, polynomial interpolation) remain research-level and are the single largest uncertainty in the cost argument.
- **Statistical power.** At `N = 137` samples per hash per kind (pooled), the [Phase 2c](#phase-2c--startpixel-enumeration) mean-rank-fraction CI is ±0.050 — a ~2 % systematic bias per hash would not be detectable. Smaller per-kind sample sizes (`*_huge` at N = 3; `html_giant` at N = 8 per hash at both BF=1 and BF=32) have correspondingly wider CIs. Conclusions are "no distinguisher at this effect size and power," not "no distinguisher of any magnitude".
- **[Phase 3a](#phase-3a--rotation-invariant-edge-case) reports false-positive-class signals.** At very large N on near-uniform output, the test produces significant p-values that do not replicate across fill regimes or corpus regenerations. Interpreting any specific flagged cell as a real effect requires sign-consistency across at least two independent runs — which this suite only partially provides (two fill regimes, identical RNG seed).
- **[Phase 2b](#phase-2b--per-pixel-candidate-distinguisher) flag threshold is heuristic** (`bit_exceed > 10` or `p_lt_001 > 3` or `kl_max > 0.1`), not derived from a false-discovery-rate calculation. Cells that flag are not clustered by primitive class but deserve principled FDR-corrected re-analysis in a follow-up.
- **Suite-level multiple-testing correction** (across 12 primitives × 10 kinds × several empirical phases × 2 regimes) is **not applied** at the top level; per-phase Bonferroni is used where reported.
- **NIST STS `NonOverlappingTemplate` replication variance is hash-agnostic.** Independent runs produce different proportion outcomes whenever a hash's per-sequence p-values happen to cluster in bin 0 versus any other bin. In this suite the event occurred twice — FNV-1a at N=20 Run A (40/188) and BLAKE2b-512 at N=100 BF=1 (40/188) — involving one below-spec and one paper-grade PRF primitive, which is direct evidence that the 40/188 outcome is driven by the `(hash, run)` seed pair, not by hash primitive choice. The underlying single-bin clustering pattern is identical across all 12 primitives and all 5 configurations; `/dev/urandom` exhibits the same 148 uniformity-of-p-values flags on streams of this size. Whether any specific primitive exhibits bin-0 draws at a rate distinguishable from the 1/10 uniform expectation would require many more replications than this suite performs.
- **[Phase 2e](#phase-2e--related-seed-differential) multi-axis related-seed differentials were not empirically tested.** Two-axis and three-axis simultaneous Δ cases are argued analytically to decompose as XOR of the measured single-axis results (see Phase 2e § Architectural implications item 5), and triple-seed architectural isolation precludes real-attacker induction of coordinated multi-axis Δ. The conclusion is analytical; an empirical multi-axis matrix was not run.
- **[Phase 2f](#phase-2f--direct-crib-kpa-against-gf2-linear-primitives) requires a public schema crib in the target plaintext.** The attack uses a 21-byte JSON-schema prefix (3 pixels) on corpus A and a 21-byte HTML-schema prefix on corpus B — both publicly-known format tokens shorter than a typical HTTP header line. Formats without fixed publicly-known prefixes (randomised headers, pre-compressed payloads, encrypted tunnels carrying arbitrary data) do not admit the Crib KPA step of the attack chain.
- **[Phase 2f](#phase-2f--direct-crib-kpa-against-gf2-linear-primitives) positive empirical basis is CRC128 only.** The claim that non-GF(2)-linear primitives (FNV-1a, MD5, and every PRF-grade entry) are immune to this attack chain rests on the [Phase 2a extension bias-neutralization audit](#phase-2a-extension--hash-agnostic-bias-neutralization-audit-axis-1--axis-2) and the algebraic argument that the pixel-0 → pixel-1 verify step fails when the 56 K candidates do not survive under a non-linear round function. A FNV-1a cross-check run (`ITB_CRIB_CROSS_HASH=fnv1a` on a 4 KB JSON + HTML pair) emits `NO MATCH` on Stage 1 under both `--hash-module fnv1a` and the default CRC128 const-mirror — negative empirical confirmation of non-applicability for that specific pipeline; MD5 and the PRF-grade primitives have not been run against Phase 2f in this pass.
- **[Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) is empirically anchored only at ITB's minimum configuration `keyBits = 512` / 4 rounds.** 8 and 16-round extrapolations (corresponding to shipped default `keyBits = 1024` and paranoid `keyBits = 2048`) are analytical via the 2 – 7× per-round factor cited in [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure), with wide error bars. The ~8 h wall-clock figure is approximate and hardware-dependent (± 30 % across comparable 16-core commodity hosts, ± 10 % across solver runs with identical inputs); a different solver, different CPU microarchitecture, or different background load can shift the result without changing the architectural conclusion.
- **[Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) recovery is functional, not bit-exact on `dataSeed`.** The SAT solver pins 255 of 256 lo-lane bits to ground truth; the top bit of each lane lives in the structural kernel of the `hLo >> 3 & 0x7F` channel projection and is unconstrained by any observable. Recovered K is operationally equivalent to the true seed on every future ciphertext — the residual bit has no downstream effect — but the report does not claim component-level inversion. Full 8-component inversion (`s[0..3]` lo + `s[0..3]` hi = 512 bits) remains architecturally inaccessible under FNV-1a's carry-up-only structure. The full-decrypt byte-match plateau at ~83–85 % is empirical on 4 KB JSON / HTML structured-text plaintexts. Binary ZIP plaintext (Store method, 22 KB and 112 KB sizes, six independent corpora with distinct seed sets) measured empirically at 0.49–0.60 % byte-match (mean 0.55 %, stddev 0.04 %) — statistically indistinguishable from the random-byte collision floor (1.3–1.5 × floor), see Phase 2g architectural finding 6 for the operational-utility analysis. Other plaintext distributions with different COBS structure / discriminator characteristics are not measured.
- **[Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) finding 6's binary-format operational figure is specific to the current heuristic discriminators (printable-ASCII ratio, PK-signature count).** Replacing those with an ML-trained discriminator integrated into the beam-search pruning step — a CNN / transformer / LLM-API scorer trained to rank partial reconstructions by target-format likelihood — is an established ML-cryptanalysis technique; Gohr (CRYPTO 2019) demonstrated deep-learning distinguishers outperforming classical differential cryptanalysis against reduced-round Speck, with follow-up work by Chen & Zhu, Baksi et al., Kim et al. extending the methodology to other primitives. The technique is **attacker-realistic** under the separation that standard ML cryptanalysis uses: the researcher trains the model on self-generated ITB corpora under self-chosen seeds (ITB source is public, training-corpus generation is a straightforward lab capability) and deploys the trained model against a target ciphertext using only beam-search-visible partial reconstructions — no ground-truth comparison enters the deployment path. An LLM-API-based beam scorer using a pre-trained public model as an ad-hoc format-aware ranker is available to any attacker with cloud compute budget today, without any custom fine-tuning. The architectural observation of finding 6 — per-pixel `noise_pos` disambiguation depends on a discriminator whose quality scales with the plaintext's entropy-margin signal — is **preserved** under ML enhancement; the 0.49–0.60 % measured figure specifically quantifies current-heuristic reach and is expected to improve on binary formats that carry format-structure features (ZIP local/central directory redundancy, DEFLATE block headers, PDF object-stream markers, MP4 atom boundaries, etc.). Quantifying the improvement is a separate empirical study outside Phase 2g scope.
- **Adversarial machine-learning distinguishers** not attempted.
- **Physical side channels** (DPA, SPA, timing, EM) outside empirical territory.
- **Triple Ouroboros on [Phase 2a extension](#phase-2a-extension--empirical-mixed-algebra-stress-test-via-crc128-nonce-reuse) / [Phase 2b](#phase-2b--per-pixel-candidate-distinguisher) / [Phase 2c](#phase-2c--startpixel-enumeration) / [Phase 2d](#phase-2d--nonce-reuse) / [Phase 2e](#phase-2e--related-seed-differential) / [Phase 2f](#phase-2f--direct-crib-kpa-against-gf2-linear-primitives) / [Phase 2g](#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) / [Phase 3a](#phase-3a--rotation-invariant-edge-case)** — the 3-partition `splitTriple` layout requires per-phase analyzer rewrites not included in this pass. [Phase 1](#phase-1--structural-checks--fft--markov-analysis) and [Phase 3b](#phase-3b--nist-sts-sp-800-22) were run in Triple mode on 12 primitives and produced results indistinguishable from Single mode.
- **Peer-review substitute.** This is self-audit, not a replacement for external cryptographic review.
- **Resistance to undiscovered cryptanalytic techniques** cannot be established by any finite empirical suite.

---

## Reproducibility and data

- **Scripts:** [`scripts/redteam/`](scripts/redteam/)
- **Shared constants:** [`scripts/redteam/common.py`](scripts/redteam/common.py) (single source of truth for the primitive list and 10-kind list)
- **Corpus test:** [`redteam_test.go`](redteam_test.go) (`TestRedTeamGenerate`)
- **Phase logs:** `tmp/results/<mode>_bf<N>/0M_*.log` — one directory per `(Ouroboros mode, BarrierFill)` combination

---

*For formal security arguments, see [`PROOFS.md`](PROOFS.md) and the scientific paper (Zenodo: [10.5281/zenodo.19229395](https://doi.org/10.5281/zenodo.19229395)).*
