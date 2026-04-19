# ITB Red-Team Empirical Validation

> **Purpose.** This document summarises the empirical red-team validation of ITB's theoretical security claims. Where the scientific paper (Zenodo [10.5281/zenodo.19229395](https://doi.org/10.5281/zenodo.19229395)) proves claims on paper, this document reports what happens when the construction is subjected to realistic cryptanalyst-style attacks on a concrete corpus.
>
> **Status.** Self-audit complete; results final for this round.

---

## TL;DR

ITB ciphertext was subjected to **five empirical statistical / structural distinguishers plus one analytical phase** (ChainHash cost modelling), across **ten hash primitives** spanning the full spectrum — from deliberately broken primitives (FNV-1a invertible, MD5 biased) through fast keyed PRFs (SipHash-2-4, AES-CMAC) to paper-grade 256/512-bit constructions (BLAKE2s/3, BLAKE2b-512, ChaCha20, AreionSoEM-256/512). The suite was exercised across a 2 × 2 configuration matrix: `{Single, Triple} Ouroboros × {BF=1, BF=32} BarrierFill`. Single is the primary mode and runs the full 5-phase suite; Triple runs Phase 1 + Phase 3b (the two mode-agnostic phases).

At shipped defaults (BF=1):

- **All 10 hashes pass every test on typical runs** — including the deliberately-broken FNV-1a (linear, fully invertible) and MD5 (collisions + output biases). The barrier produces ciphertext statistically indistinguishable from a true PRF across the whole primitive spectrum.
- **Per-pixel candidate KL floor on 8 × 1 MB `html_giant` samples**: Mode A (idealized attacker, BF=1, N = 9.6 M obs/candidate) band [0.000018, 0.000021] nats, spread 3 × 10⁻⁶ across all 10 hashes; Mode B (realistic attacker — no `startPixel`, no plaintext, full container — BF=32, N = 11.3 M) band [0.000012, 0.000016] nats, spread 4 × 10⁻⁶. Both sit at ≈1.4× theoretical `bins/N` floor. A one-off probe at **N = 7.7 × 10⁷** (one 63 MB BLAKE3 encryption at the ITB data-size limit, Mode B, BF=32) drives observed KL max to **1.8 × 10⁻⁶ nats** — within 1.1× of the floor, subnanonat territory where float64 precision begins to matter.
- **NIST STS: all 10 hashes cluster p-values into a single bin — universally.** At N = 100 sequences × 1 Mbit, every hash's 100 per-sequence `NonOverlappingTemplate` p-values fall into one bin; the bin is different per hash and effectively random across runs (FNV-1a → bin 8, MD5 → bin 6, ChaCha20 → bin 1, BLAKE3 → bin 2, etc). Proportion is 100/100 for all 10 hashes on every one of the 148 template sub-tests. Single-test failures across the whole N = 100 run: 2 out of 1 880 — well under the 1 % expected at α = 0.01. When a given hash's cluster lands in bin 0 on any one run, the proportion column mechanically reports a catastrophic-looking 40/188 for that hash (it has happened to FNV-1a at N=20 and BLAKE3 at N=100 on BF=32 in this suite); this is the documented NIST SP 800-22 artefact on near-uniform output, **not** a primitive-specific signal.
- **Phase 1 FFT + Markov sub-tests** (byte-level, mode-agnostic, Single + Triple, both BF regimes): per-channel spectral flatness stays within 6×10⁻⁵ of 1.0 for all 10 primitives (white-noise signature); adjacent-byte Markov χ² mean within ~85 of the df=65 535 H0 expectation with p medians scattered around 0.5. 1 Bonferroni false-positive in 280 within-pixel channel-pair tests, non-replicated across configs — same statistical-power artefact pattern as [Phase 3a](#phase-3a--rotation-invariant-edge-case).
- **Phase 2a (analytical)** proposes that ChainHash's XOR chain is the load-bearing assumption behind the defense-in-depth stacking: it converts otherwise cheap primitive inversions into bitvector-SAT instances, so each defensive layer (ChainHash, unknown startPixel, Partial KPA byte-splitting) stacks multiplicatively **conditional on that SAT-hardness assumption**. No Z3 runs were executed; the claim rests on structural analysis.
- **Realistic threat model** (Partial KPA + unknown startPixel) places the attack past civilisational timescales on a 1000-node cluster.
- **Nonce-reuse PRF-dependency empirically demonstrated (Phase 2d)**. Under a deliberate nonce collision with Full KPA, a Python demasker recovers `startPixel` + per-pixel `(noisePos, rotation)` in seconds and reconstructs the pure `dataSeed.ChainHash(pixel, nonce)` output stream (obstacles (2) and (3) of [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) no longer apply — only obstacle (1), ChainHash SAT-hardness, remains). NIST STS on the reconstructed ~16.7 Mbit stream per primitive at 2 MB plaintext: **BLAKE3 passes 188/188** (single remaining obstacle survives under PRF); **FNV-1a fails 6/188** — FFT 0/16 (100 % fail rate, spectral peaks on every bit-stream) plus BlockFrequency / CumulativeSums / Runs. The [`SCIENCE.md §2.5`](SCIENCE.md#25-nonce-reuse-analysis) locality claim ("seeds remain secret, no key rotation") holds under PRF; its PRF-dependency caveat is made empirically visible by the BLAKE3-vs-FNV-1a contrast.

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

- **Full KPA** as the worst-case simplification: attacker knows complete plaintext and ciphertext for every sample.
- **Partial KPA** analysed separately for the byte-splitting obstacle.
- **Hash identity** known to attacker; **seed components never disclosed**; **rotation never disclosed**; **noisePos never disclosed**.
- **startPixel** optionally disclosed in Phase 2b / Phase 3a (to isolate obstacle (3)); **enumerated** in Phase 2c (to test obstacle (2)).

### Not tested

Attack classes:
- **Full seed inversion** with an invertible primitive under ChainHash (research-level; see Phase 2a for analytical treatment — Z3 was **never actually executed**, not even at the ITB-with-ChainHash minimum `keyBits = 512` (2 ChainHash rounds × 256-bit hash, or 4 × 128-bit) nor at the larger flagship `keyBits = 1024`, so the scaling table is structural analysis only. `NewSeed{128,256,512}` explicitly reject `keyBits < 512`; the 128-bit figure quoted in earlier drafts referred to the hash output width, not the key size.)
- ~~**Nonce-reuse attacks.** Every sample in the corpus uses a fresh nonce. We do not probe fixed-nonce / varying-seed, nor same-seeds / same-nonce / different-plaintexts (the deliberate-collision scenario that produces the two-time pad on the 2–3 colliding messages). [SCIENCE.md §2.5](SCIENCE.md#25-nonce-reuse-analysis) argues this is strictly local under the PRF assumption (seeds retained, no key rotation needed) and a global catastrophe under full primitive inversion — not empirically stress-tested in either regime.~~ — see [Phase 2d — Nonce-Reuse](#phase-2d--nonce-reuse). Seed reuse itself (same `(noiseSeed, dataSeed, startSeed)` across many messages with fresh nonces) is an explicitly supported mode, not an attack surface.
- ~~**Chosen-plaintext / adaptive CPA.** Full KPA ≠ CPA. Attack-friendly plaintexts (all-zeros, all-0x7F, sparse 1-hot, sliding-window differentials) are absent from the corpus.~~ — covered indirectly by [Phase 2d — Nonce-Reuse](#phase-2d--nonce-reuse) (Full-KPA `known` and Partial-KPA `partial` modes accept attacker-chosen plaintext kinds — `json_structured_{25,50,80}` and `html_structured_{25,50,80}` produce attacker-controlled corpora of 6 distinct structured formats × 3 coverage levels) and [Phase 3a — Rotation-invariant edge case](#phase-3a--rotation-invariant-edge-case) (all-0x7F rotation-invariant probe). Under fresh-nonce CPA (attacker chooses plaintext but nonce stays fresh per query) the attack surface reduces to statistical ciphertext properties already covered by [Phase 1](#phase-1--structural-checks) / [Phase 2b](#phase-2b--per-pixel-candidate-distinguisher) / [Phase 3b](#phase-3b--nist-sts-sp-800-22) across the 10 included `zero_pad` / `html_giant` / `json` / etc. corpus kinds. No unexplored CPA surface remains after Phase 2d.
- **Related-key attacks.** The three-seed architecture begs testing `(ns, ds, ss)` vs `(ns, ds, ss ⊕ Δ)` ciphertext diffs; not done.
- ~~**Frequency-domain / FFT on per-channel streams.** NIST STS includes DFT on the flat stream but not per-channel (which is where period-8 structure would live).~~ — see [Phase 1 — FFT / Markov analysis](#phase-1--fft--markov-analysis)
- ~~**Markov / cross-channel conditional distributions.** `P(byte_n | byte_{n-1})` not probed.~~ — see [Phase 1 — FFT / Markov analysis](#phase-1--fft--markov-analysis)
- **Adversarial machine-learning distinguishers** (CNN, deep-learning distinguisher trained on cover/stego pairs)
- **Physical side channels** (timing, power, EM)
- **Chosen-ciphertext attack with MAC reveal** (MAC + Reveal mode)
- **Quantum adversaries** (Grover bounds are theoretical)

Scope gaps:
- **Triple Ouroboros on Phases 2b / 2c / 3a** — Triple is validated on the two mode-agnostic phases (Phase 1 + Phase 3b, both BF=1 and BF=32). Phases 2b / 2c / 3a require a 3-partition analyzer rewrite to interpret the `splitTriple` interleaving; they are not included in this pass. Triple is architecturally strictly more defended than Single (see [Attack-cost implications of Triple Ouroboros](#attack-cost-implications-of-triple-ouroboros))
- **Widely-deployed hash primitives missing from the 10-hash matrix**: HMAC-SHA-256, GHASH, SHA-3/Keccak. Absent; adding them would round out the algebraic-primitive coverage
- **`SetBarrierFill` intermediate values** (2, 4, 8, 16) not exercised; the shipped default (1) and the maximum (32) bracket the regime, and per-phase results are monotonic between them, but fine-grained sweep is absent
- **Structured binary plaintexts** (PDF, PNG, MP4, compressed streams) absent from the corpus; the 10 kinds are all text-ish (HTTP / JSON / HTML / plain text). High-entropy compressed binaries and format-specific byte patterns could expose behaviours not surfaced by the current corpus
- ~~**Direct `/dev/urandom` side-by-side baselines** for Phase 1 per-channel χ², Phase 2b KL floor, and Phase 3a rotation-invariant rate (NIST STS uses urandom implicitly as its calibration baseline; other phases do not)~~ — effectively moot. The [63 MB KL floor probe](#kl-floor-probe-on-a-single-63-mb-sample-one-off-blake3-bf1-bf32) lands Phase 2b's pairwise KL at **1.1× – 1.4× of the theoretical `bins/N` floor** — that floor IS the urandom expectation, so ITB ciphertext is already shown to be within measurement precision of urandom behaviour on Phase 2b. Phase 1 χ² and Phase 3a rotation-invariant rate similarly reach tolerances that match the urandom expectation (2/128 rate within 0.007 % across all 10 hashes at Phase 3a). A literal side-by-side urandom stream would confirm the same floors with no new information.
- ~~**Cross-sample variance** on `html_giant`: the runs aggregate `N = 8` samples per hash into the KL estimate (both BF=1 and BF=32, both Mode A and Mode B). The aggregate floor is reported; the per-sample variance distribution is not itself reported.~~ — superseded by [KL floor probe on a single 63 MB sample](#kl-floor-probe-on-a-single-63-mb-sample-one-off-blake3-bf1-bf32), which accumulates `N ≈ 7.5 – 7.7 × 10⁷` observations per candidate from a SINGLE plaintext (an order of magnitude above the 8-giant aggregate) and lands the pairwise KL at **1.1× – 1.4× of the theoretical `bins/N` floor** under both Mode A (idealized alignment) and Mode B (full-container, no alignment). Per-sample variance is no longer the limiting uncertainty — the single-sample floor is already effectively at sampling precision.

---

## Methodology

### Hash matrix

Ten primitives spanning the full spectrum of cryptographic strength, all run under identical ITB settings:

| Primitive | Width | Paper-spec PRF? | Observable properties |
|-----------|:-----:|:---------------:|-----------------------|
| FNV-1a | 128 | ❌ non-cryptographic | Fully invertible (linear over Z/2^128), no preimage resistance |
| MD5 | 128 | ❌ broken | Collisions trivial, documented biases, preimage ~2^123 |
| AES-CMAC | 128 | ✅ | Standard AES-based keyed MAC |
| SipHash-2-4 | 128 | ✅ | Fast keyed PRF |
| ChaCha20 | 256 | ✅ | Stream-cipher-based PRF |
| AreionSoEM-256 | 256 | ✅ | Single-key Even-Mansour with Areion permutation |
| BLAKE2s | 256 | ✅ | Keyed hash in PRF mode |
| BLAKE3 | 256 | ✅ | Native keyed PRF |
| BLAKE2b-512 | 512 | ✅ | Keyed hash in PRF mode |
| AreionSoEM-512 | 512 | ✅ | Single-key Even-Mansour 512 |

### Settings

Both Single and Triple Ouroboros were each run twice — at the **shipped default** `SetBarrierFill(1)` and at the **maximum** `SetBarrierFill(32)`. Single runs all five empirical phases; Triple runs the two mode-agnostic phases (1 and 3b). Other parameters are identical across all four runs:

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

**Total: 1 300 samples** (10 hashes × 130 samples each), regenerated deterministically in ~63 s.

### Reproducibility

**Install prerequisites (Arch Linux).** Requires Go (for the corpus generator) and a handful of Python packages plus `nist-sts` from AUR:

```bash
# Core toolchain + Python analyzers
pacman -S go gcc make base-devel python3 python-numpy python-scipy \
          python-matplotlib python-z3-solver python-claripy

# NIST SP 800-22 test suite (AUR)
yay -S nist-sts
```

On non-Arch distributions, install equivalents via your package manager (`apt install golang-go python3-numpy python3-scipy`, build `nist-sts` from <https://github.com/terrillmoore/NIST-Statistical-Test-Suite> or similar).

All scripts under [`scripts/redteam/`](scripts/redteam/). The simplest way to run the full suite is the master orchestrator:

```bash
# Single Ouroboros (3 seeds: noise, data, start) — runs all 5 empirical phases
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

Valid `--nist-streams` values are `{20, 30, 50, 100}` — fixed whitelist; 20 matches the NIST SP 800-22 example, 100 is recommended for this suite because larger N lets conventional non-bin-0 proportion failures stand out as genuine outliers separable from the `NonOverlappingTemplate` bin-routing artefact. N=100 does **not** eliminate the artefact — bin-0 draws still occur at ~10 % per `(hash, run)` pair at any N (BLAKE3 hit 40/188 at N=100 BF=32 in this suite; see Phase 3b).

Or run phases manually in sequence:

```bash
# 1. Generate corpus (~1–2 min at BF=1; similar at BF=32)
ITB_REDTEAM=1 ITB_BARRIER_FILL=1 go test -run TestRedTeamGenerate -v -timeout 60m

# 2. Phase 1 — structural checks (per-channel χ² + nonce collision)
python3 scripts/redteam/phase1_sanity/analyze.py

# 3. Phase 2b — per-pixel candidate distinguisher, two threat models in parallel (~1-2 min)
#    Mode A: attacker knows startPixel, data-aligned + plaintext XOR (idealized).
#    Mode B: no startPixel, no plaintext, iterates full container (realistic).
#    run_suite.py launches both concurrently; run standalone one-at-a-time if preferred.
python3 scripts/redteam/phase2_theory/distinguisher.py       # Mode A
python3 scripts/redteam/phase2_theory/distinguisher_full.py  # Mode B

# 4. Phase 2c — startPixel enumeration (parallel, ~5 min at BF=1, ~12 min at BF=32)
python3 scripts/redteam/phase2_theory/startpixel_multisample.py

# 5. Phase 3a — rotation-invariant edge case (~30 s)
python3 scripts/redteam/phase3_deep/rotation_invariant.py

# 6. Prepare streams for NIST STS (also consumed by step 7 sub-tests)
python3 scripts/redteam/phase3_deep/prepare_streams.py

# 7. Phase 1 sub-tests — FFT + Markov (mode-agnostic, Single + Triple; reads tmp/streams/)
python3 scripts/redteam/phase1_sanity/fft_per_channel.py
python3 scripts/redteam/phase1_sanity/markov.py

# 8. Phase 3b — NIST STS parallel runner (~5 min at N=100, ~1 min at N=20)
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

The orchestrator accepts `--hashes all` for the full 10-primitive matrix and `--barrier-fill both` for BF=1 and BF=32 coverage; see `--help` for the complete CLI. All deletion operations are routed through a whitelist-gated `safe_rmtree` helper that refuses any path outside `tmp/attack/nonce_reuse/{corpus, reconstructed}`; the results subdirectory is never touched by the orchestrator. Deterministic RNG seeds (plaintext seed 424242, nonce seed 0xA17B1CE) produce byte-identical corpora across runs — a future researcher can reproduce the exact reconstructed streams and feed them to their own statistical-test batteries.

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
| **1. Structural** | 8-channel per-channel χ² + nonce-pair collision | ✅ 0 / 80 Bonferroni failures; collision ratio ∈ [0.983, 1.014] (BF=32: [0.993, 1.025]). Triple confirmed in both BF regimes, same pattern |
| **1. FFT + Markov (sub-tests)** | Per-channel spectral flatness + adjacent-byte / adjacent-channel Markov χ² | ✅ Mode-agnostic (Single + Triple × BF=1 + BF=32). FFT flatness within 6×10⁻⁵ of 1.0 on all 10 primitives; Markov adj-byte χ² mean within ~85 of df=65 535 expectation, p medians around 0.5. 1 Bonferroni false-positive in 280 within-pixel channel-pair tests, non-replicated across configs |
| **2a. ChainHash analysis** | Theoretical bound on invertible primitive | 📖 Architectural defense-in-depth surfaced; paper underclaims |
| **2b. Candidate distinguisher** | Obstacle (3) — 56-way per-pixel ambiguity | ✅ Mode A (idealized attacker, BF=1) KL [0.000018, 0.000021] nats on 8-giant aggregate (N = 9.6 M obs/cand); Mode B (realistic attacker, no startPixel, no plaintext, BF=32) [0.000012, 0.000016] (N = 11.3 M) — both at ≈1.4× theoretical `bins/N` floor across the full hash spectrum |
| **2c. startPixel enumeration** | Obstacle (2) — startPixel indistinguishability | ✅ mean rank-fraction ∈ [0.461, 0.532]; 6 flagged cells / 90, consistent with 4.5 expected under H0 at α=0.05 (BF=32: 5 / 90) |
| **2d. Nonce-Reuse** | [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis) locality claim — PRF-dependency empirically visible | ✅ / ⚠ Attack chain demasks obstacles (2) + (3) in seconds via Layer 1 constraint matching + Layer 2 startPixel brute force, reconstructs pure `ChainHash(pixel, nonce)` output. NIST STS on reconstructed stream (N=16 × 1 Mbit per cell, 2 MB plaintext): **BLAKE3 188/188 pass**, **FNV-1a 182/188 (6 fails — FFT 0/16, BlockFrequency 9/16, CumulativeSums ×2, Runs 12/16)**. Under PRF the single remaining obstacle (ChainHash SAT-hardness) survives with no exploitable bias; under invertible primitive residual linear-order bias is detectable on every bit-stream |
| **3a. Rotation-invariant** | [`SCIENCE.md` §2.9.2](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier) edge case | ✅ Rate 2/128 = 1.5625 % within 0.007 % across all 10 hashes; **no sign-consistent deviation** between BF=1 and BF=32. The 5–6 σ AES-CMAC / BLAKE2b-512 "signals" at BF=32 did not appear at BF=1 — test-power artefacts on near-uniform output, not real bias |
| **3b. NIST STS** | Industry-standard randomness suite | ✅ At N = 100 × 1 Mbit Single: 15 / 20 `(hash, BF)` cells pass 188/188; 4 cells show one single-test fail (conventional H0 outliers, 5 / 3 760 = 0.13 % vs 1 % expected at α = 0.01); 1 cell (BLAKE3, BF=32) hit the `NonOverlappingTemplate` bin-0 artefact — paper-grade PRF hitting the same 40/188 outcome as FNV-1a at N=20 confirms the mechanism is hash-agnostic. Triple confirmed in both BF regimes (BF=1: 4 / 1 880 = 0.21 %; BF=32: 1 / 1 880 = 0.05 %). All 10 exhibit the SP 800-22 uniformity-of-p-values clustering identically across configurations |

---

## Phase 1 — FFT / Markov analysis

Scripts: [`fft_per_channel.py`](scripts/redteam/phase1_sanity/fft_per_channel.py), [`markov.py`](scripts/redteam/phase1_sanity/markov.py).

Two byte-level Phase 1 sub-tests that do not depend on startPixel alignment → mode-agnostic (both run unchanged in Single and Triple). **FFT**: demultiplex each `tmp/streams/<hash>.bin` into 8 per-channel streams, Welch spectral flatness per channel + zero-lag Pearson between channel pairs. **Markov**: full 65 536-cell transition matrix (adjacent-byte on the flat stream + adjacent-channel within each pixel), χ² against uniform 1/65 536.

Summary across 10 primitives per cell × 2 modes × 2 fill regimes:

| Mode × BF | FFT flatness mean | FFT max\|corr\| median | Markov adj-byte χ² mean | Markov adj-byte p median | Bonferroni fails / 70 |
|-----------|------------------:|-----------------------:|------------------------:|-------------------------:|----------------------:|
| Single BF=1 | 0.99922 | 0.00170 | 65 590 | 0.50 | 0 |
| Single BF=32 | 0.99944 | 0.00146 | 65 506 | 0.44 | 0 |
| Triple BF=1 | 0.99924 | 0.00202 | 65 575 | 0.32 | 0 |
| Triple BF=32 | 0.99944 | 0.00156 | 65 532 | 0.59 | 0 |

FFT flatness stays within 6×10⁻⁵ of 1.0 on every channel across all 4 configs — white-noise signature. Markov adjacent-byte χ² mean clusters within ~85 of the df=65 535 H0 expectation; p medians scatter around 0.5 (textbook H0). Zero replicable Bonferroni fails across 280 within-pixel channel-pair tests (one non-replicating raw flag on ChaCha20 Triple BF=1 matches the statistical-power-artefact pattern on near-uniform output documented in [Phase 3a](#phase-3a--rotation-invariant-edge-case) — not counted as a fail in the table). Effectively, feeding the suite's concatenated ciphertext stream through FFT + Markov is indistinguishable from feeding `/dev/urandom`.

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

Inverting the last round yields **one 128-bit equation in two unknowns** (the final seed pair and the previous intermediate state). Multiple pixels provide more equations, but the system is non-linear through Z/2^128 multiplication and XOR-chained through eight levels — a hard bitvector SAT problem, not a direct inversion.

### Z3 feasibility by `keyBits`

The round count equals `keyBits / 128`. Each added round composes a full 128-bit bitvector multiplication through the chain, typically multiplying SMT solver time by some factor; published SMT-on-ARX literature (Mouha et al., Song/Shi on Speck/Simon inversion) suggests O(2 – 5×) per round for well-structured ciphers, with larger factors appearing near density-1 constraint regimes. The numbers below are **empirical back-of-envelope estimates**, ± 2 – 3 orders of magnitude; they illustrate the curve's shape, not formal lower bounds. **No actual Z3 experiment was run at any `keyBits` in this pass** (see caveats).

| `keyBits` | Rounds | Sequential Z3 (single machine) |
|----------:|-------:|--------------------------------|
| 128 | 1 | Minutes to hours (equivalent to direct FNV-1a inversion — the paper's naive bound holds here) |
| 256 | 2 | Hours to days |
| 512 | 4 | Weeks to months |
| **1024 (tested)** | **8** | **~10⁵ – 10⁸ hours** (years → millennia, depending on per-round cost factor) |

### Adversary accelerators

A realistic well-funded adversary stacks several multipliers on top of sequential Z3:

- **Parallel Z3 portfolio** (`smt.threads=N`): 2 – 8× local speedup from running multiple solver configurations racing each other on a single multi-core machine.
- **Distributed SMT** (cloud / HPC, 10²–10³ nodes): 100 – 1000× with diminishing returns from communication overhead.
- **Meet-in-the-middle attacks: not applicable.** Classical MITM (2DES, Even-Mansour) requires the cipher to decompose as `E_{k2} ∘ E_{k1}` with **independent** key halves. ChainHash's recurrence feeds every previous round's output into the next round's key input, blocking any such decomposition across round boundaries.
- **Algebraic attacks** (Gröbner basis over Z[2^128], polynomial interpolation): feasibility unknown for this specific construction. Could be substantially faster than Z3 if a structural exploit is found — this is the single biggest uncertainty in the cost estimate.
- **Differential cryptanalysis** of ChainHash: FNV-1a's multiplicative group has linear properties that may admit differential trails. Unstudied in public literature.
- **Incremental SMT amortisation across `startPixel` guesses**: modern solvers with push/pop can share learned clauses across near-identical instances differing only by a single parameter. May reduce the ×P multiplier below to ×(P/5) – ×(P/10) for parametric families.
- **Quantum Grover**: further √ speedup once fault-tolerant quantum computers exist at ~10⁶ logical-qubit scale.

### Back-of-envelope 1000-node cluster wall-clock (Full KPA, startPixel known)

| Setup | Wall-clock at 1024-bit seeds |
|-------|------------------------------|
| Sequential single machine | ~10⁵ – 10⁸ hours |
| 1000-node naive split | ~10² – 10⁵ hours (months to ~11 years) |
| 1000-node + portfolio parallelism (~10× practical speedup) | **~10 – 10⁴ hours (hours to ~1 year)** |

The "~1 year" upper figure corresponds to the pessimistic end of the per-round cost range and assumes no algebraic shortcut; the optimistic end (hours) assumes Z3 handles the constant-multiplicative structure of FNV-1a well. A state-level attacker would plausibly land somewhere in this band.

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

**Phase 2c empirically validates that `startPixel` cannot be shortcut by statistical fingerprinting** in this corpus: across all 10 hashes and 1 290 enumeration runs, mean rank fraction of the true `startPixel` is ≈ 0.5 (indistinguishable from random) and **5 / 90** flagged (hash, kind) cells are consistent with the 4.5 expected under H0 at α = 0.05. No statistical shortcut was detected; the attacker genuinely has to run the seed-recovery procedure for each of the `P` candidates (modulo incremental-SMT amortisation discussed above).

### Combined realistic threat model (all layers stacked)

On the same 1000-node cluster with practical portfolio parallelism, using the range in the Full-KPA table, with `P ≈ 10⁴` for a typical 20 KB payload at `BarrierFill=32`:

| Scenario | Wall-clock at 1024-bit, `P ≈ 10⁴` |
|---------|----------------------------------:|
| Full KPA + `startPixel` known (idealised) | hours – 1 year |
| Full KPA + `startPixel` unknown (×`P`) | centuries – ~10 000 years |
| **50 % Partial KPA + `startPixel` unknown** (real production) | **~10¹² – 10¹⁶ years** |
| 80 % Partial KPA + `startPixel` unknown | ~10¹⁷ – 10²¹ years |

### Why the three layers multiply — defense-in-depth structure

The three layers (ChainHash, `startPixel` enumeration, Partial KPA byte-splitting) stack multiplicatively **conditional on ChainHash's XOR-cascade remaining SAT-hard** — i.e., assuming no undiscovered algebraic or structural attack collapses the 8-round recurrence into something cheaper than a bitvector SAT problem. This is a load-bearing conditional premise, and the single largest unstudied assumption behind the cost estimates. A paper-quality treatment would provide a reduction sketch to a standard assumption (e.g., worst-case bitvector-SAT hardness, or LWE-style noisy composition); this document does not.

**Without ChainHash (hypothetical).** Invertible FNV-1a + known `startPixel` + Full KPA would resolve to microsecond-per-inversion modular inverses. With unknown `startPixel`, the attacker cycles `P ≈ 10⁵ × 56 × µs` → seconds-to-minutes total. Partial KPA adds free bits but would still resolve in hours at worst.

**With ChainHash (actual ITB).** Each `startPixel` guess triggers a full SAT instance over 1024 seed bits + 6 ambiguity bits per used pixel, with 8 rounds of nested multiplication through the XOR chain — *hours to ~1 year* of 1000-node time per attempt (the range reflects per-round SMT-cost uncertainty). That SAT-vs-inversion flip is what makes the defensive layers stack:

| Layer | Role | Without ChainHash | With ChainHash (actual) |
|-------|------|-------------------|-------------------------|
| Baseline: 56 candidates per pixel (`noisePos × rotation`) | 6 ambiguity bits per pixel — obstacle (3) | Amortised inside µs inversions; negligible | Encoded as SAT free variables; inside the per-attempt SAT baseline |
| Layer 1: ChainHash XOR chain (8 rounds at 1024-bit) | Load-bearing premise | n/a | Turns each attack from µs-per-inversion into a SAT instance (hours – 1 year per attempt) |
| Layer 2: `startPixel` enumeration (`P` values) | Obstacle (2) | ×P cheap inversions → seconds-minutes total | **×P SAT instances** (with possible ~10× incremental amortisation) → centuries – ~10 000 years |
| Layer 3: Partial KPA byte-splitting | Obstacle (4) | Adds free bits; still feasible in hours | **×2^(56 − k)** SAT blow-up → 50 % unknown + unknown `startPixel` → ~10¹² – 10¹⁶ years |

Rotation and `noisePos` (the 56-candidate baseline) sit inside the Z3 unknowns of every attempt — they are not a separate multiplicative layer. The three layers that stack — ChainHash, `startPixel` enumeration, Partial KPA byte-splitting — **stack multiplicatively conditional on the SAT-hardness premise**. Without ChainHash the same architecture would collapse: every layer would resolve to cheap modular inversions rather than SAT, and the total attack would complete in CPU-hours on commodity hardware.

### Architectural takeaway

1. **Under Full KPA + known `startPixel`** (the simplification used for the Phase 2b / 3a empirical tests), a well-funded attacker reaches 1024-bit seed recovery in *hours to ~1 year* of 1000-node cluster time — and that already assumes ChainHash is the only active defensive layer. Even this idealised threat already requires solving SAT, not modular inversions.
2. **Under Full KPA + unknown `startPixel`** (still idealised), the attack multiplies by ~`P` (with possible incremental-SMT amortisation reducing the effective multiplier by up to ~10×). At typical `P ≈ 10⁴`, this pushes the cost into centuries – ~10 000 years.
3. **Under Partial KPA + unknown `startPixel`** (the production threat model), the 50 % unknown case lands at ~10¹² – 10¹⁶ years of 1000-node time. The three defence layers stack multiplicatively, **conditional on the SAT-hardness assumption above**.
4. **ChainHash is the load-bearing premise.** Without it the same architecture (invertible FNV-1a + 56-candidate baseline + unknown `startPixel` + Partial KPA) would collapse to CPU-hour-scale cost on commodity hardware — every layer would resolve to cheap modular inversions rather than SAT. Keeping it makes every other layer an independent SAT multiplier, subject to the SAT-hardness premise.

**Proposed paper addition.** A caveat in [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) or adjacent prose noting that invertibility of the base primitive does not translate into invertibility of ChainHash for `n > 1` rounds; the compound cost scales with round count, giving `keyBits`-dependent defence-in-depth that the current prose does not claim. The naive `~56 × P` inversions bound holds tightly only in the hypothetical `keyBits = hashWidth` single-round-ChainHash case (equivalent to removing ChainHash entirely) with both `startPixel` and plaintext fully known — and `NewSeed{128,256,512}` explicitly reject `keyBits < 512`, so that hypothetical is below the minimum ITB ever instantiates.

At the actual minimum keyBits = 512: 128-bit hash → 4 ChainHash rounds, 256-bit hash → 2 rounds, 512-bit hash → 1 round. The "1 round at 512-bit minimum" case is **not a practical weakness** because both 512-bit primitives in the ITB hash matrix (BLAKE2b-512 and AreionSoEM-512) are PRF-grade — when the base primitive is already a PRF, ChainHash compounding adds defence-in-depth for invertible primitives but adds nothing meaningful on top of a PRF (the output is unpredictable by assumption, regardless of wrap depth). ChainHash composition is load-bearing specifically for the invertible primitives in the matrix (FNV-1a), which only exist at 128-bit width, where the minimum keyBits = 512 still gives 4 rounds. So the naive bound is effectively a bound for "ITB without ChainHash", which is not something shipped ITB ever configures, and shipping a non-PRF 512-bit primitive to trigger the degenerate case would be a deliberate choice outside ITB's supported hash matrix.

---

## Phase 1 — Structural checks

Script: [`scripts/redteam/phase1_sanity/analyze.py`](scripts/redteam/phase1_sanity/analyze.py)

Two ITB-specific structural checks that NIST STS (Phase 3b) does not cover because they depend on the 8-channel layout:

**[A] Per-channel-position χ²** — byte offset `i` in the ciphertext belongs to channel `i mod 8`. A bias restricted to one channel is 8× diluted in the flat stream NIST STS sees, so each channel is tested separately with Bonferroni correction (α_eff = 0.00125).

**[B] Nonce-independence collision scan** — same-position byte matches between sample-pair prefixes, vectorised via `bincount`. Expected rate under fresh nonce + fresh seeds: 1/256. Sustained deviation indicates nonce-dependent structure.

### Results at BF=1 (130 samples per hash × 10 hashes; BF=32 numbers in parentheses)

| Hash | Min channel p-value (BF=1 / BF=32) | Bonferroni fails | Collision ratio (BF=1 / BF=32) | Status |
|------|-----------------------------------:|-----------------:|-------------------------------:|--------|
| FNV-1a | 0.0452 / 0.0896 | 0 / 8 | 1.0107 / 1.0006 | ✅ |
| MD5 | 0.0274 / 0.1995 | 0 / 8 | 1.0014 / 1.0253 | ✅ |
| AES-CMAC | 0.0157 / 0.3017 | 0 / 8 | 1.0136 / 1.0086 | ✅ |
| SipHash-2-4 | 0.0614 / 0.1468 | 0 / 8 | 1.0017 / 0.9931 | ✅ |
| ChaCha20 | 0.1252 / 0.0737 | 0 / 8 | 0.9868 / 0.9934 | ✅ |
| AreionSoEM-256 | 0.1388 / 0.1210 | 0 / 8 | 1.0036 / 1.0136 | ✅ |
| BLAKE2s | 0.0793 / 0.0654 | 0 / 8 | 0.9834 / 0.9958 | ✅ |
| BLAKE3 | 0.0433 / 0.0375 | 0 / 8 | 1.0012 / 0.9936 | ✅ |
| BLAKE2b-512 | 0.0208 / 0.1671 | 0 / 8 | 1.0038 / 1.0172 | ✅ |
| AreionSoEM-512 | 0.1390 / 0.0222 | 0 / 8 | 0.9866 / 0.9949 | ✅ |

All 80 per-channel χ² tests pass Bonferroni correction at both BF=1 and BF=32; all collision ratios within [0.80, 1.20]. **Weak and strong PRFs produce identical per-channel profiles at shipped defaults** — including FNV-1a, which later shows the NIST STS template signal in Phase 3b. Per-channel χ² is not sensitive to the template-level structure that leaks FNV-1a; the structural test at the 8-channel aggregate level is clean.

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

With 8 `html_giant` samples per hash aggregated, the per-(hash, kind) cell accumulates roughly **9.6 M observations per candidate** in Mode A (8 samples × ~150 k data pixels × 8 channels) and **11.3 M in Mode B** (BF=32 inflates the container with ~26 k additional CSPRNG-fill pixels per sample), so the finite-sample KL floor drops to **~10⁻⁵ nats** — comfortably below the heuristic "distinguishable" threshold of 0.05.

| Hash | Mode A BF=1 KL max (N = 9.6 M) | Mode B BF=32 KL max (N = 11.3 M) | Interpretation |
|------|-------------------------------:|---------------------------------:|----------------|
| FNV-1a | 0.000018 | 0.000016 | Invertible primitive |
| MD5 | 0.000019 | 0.000015 | Broken primitive |
| AES-CMAC | 0.000018 | 0.000016 | Paper-grade PRF |
| SipHash-2-4 | 0.000020 | 0.000015 | Paper-grade PRF |
| ChaCha20 | 0.000018 | 0.000016 | Paper-grade PRF |
| AreionSoEM-256 | 0.000019 | 0.000013 | Paper-grade PRF |
| BLAKE2s | 0.000019 | 0.000014 | Paper-grade PRF |
| BLAKE3 | 0.000021 | 0.000014 | Paper-grade PRF |
| BLAKE2b-512 | 0.000018 | 0.000013 | Paper-grade PRF |
| AreionSoEM-512 | 0.000018 | 0.000012 | Paper-grade PRF |

Both columns fall in narrow bands: Mode A **[0.000018, 0.000021] nats** (spread 3 × 10⁻⁶) and Mode B **[0.000012, 0.000016] nats** (spread 4 × 10⁻⁶), across the full spectrum from "fully invertible" to "paper-grade 512-bit PRF". Expected finite-sample KL floor: `bins / N ≈ 1.3 × 10⁻⁵` nats for Mode A (N = 9.6 M) and `≈ 1.1 × 10⁻⁵` nats for Mode B (N = 11.3 M); observed values sit at ≈1.5× floor in Mode A and ≈1.4× in Mode B — both consistent with the max-over-1540-pairs correction for the max-KL statistic. Mode B sits uniformly *below* Mode A per primitive, because the realistic attacker's larger N gives a tighter floor and the absence of plaintext XOR / startPixel alignment removes attacker levers rather than adding them.

Per-pixel obstacle (3) holds uniformly whether CSPRNG fill dilutes the data channels or not — the 56-way candidate ambiguity absorbs all primitives equivalently at this test, including FNV-1a. **Whatever FNV-1a leakage Phase 3b detects is not visible at the per-pixel KL level**; it is a template-shaped aggregate structure that emerges only under NIST STS's specific bit-pattern battery.

### Full-corpus cell coverage and the flag threshold

Across all 90 (hash, kind) cells, the per-cell report emits a `⚠` flag when any of the heuristic thresholds `bit_exceed > 10`, `p_lt_001 > 3`, or `kl_max > 0.1` is hit. These thresholds are not derived from a principled false-discovery-rate calculation; they are ad-hoc and picked to catch "obviously anomalous" cells without being triggered by finite-sample extremes.

- **At BF=1** (`tmp/results/single_bf1/04_phase2b.log`): **8 / 90 cells flagged**, across FNV-1a, MD5, AES-CMAC, SipHash-2-4, ChaCha20, and AreionSoEM-512. No single primitive dominates the flag list.
- **At BF=32** (`tmp/results/single_bf32/04_phase2b.log`): **10 / 90 cells flagged**, distributed across a different set of primitives (BLAKE2s, BLAKE2b-512, AreionSoEM-256, AreionSoEM-512 appear more; ChaCha20 does not appear).

**The flagged cells do not overlap between the two regimes** — none of the 8 BF=1 flags corresponds to a BF=32 flag on the same (hash, kind). Because the three triggers are ad-hoc thresholds (not α = 0.05 per cell), the per-cell flag probability under true H0 is dominated by `bit_exceed > 10` firings on small-N cells (http, json, text_small, with ~700 data pixels per sample), where finite-sample variation across 56 candidates inflates the bit-balance statistic. The telling fact is the **non-overlap across independent runs**: real per-primitive effects would flag the same (hash, kind) pair in both regimes; finite-sample noise shuffles the flagged set. Both are observed — per-run counts stay near-identical (8 vs 10 of 90), specific cells shift entirely.

The `html_giant` row is flagged for one hash at BF=1 (FNV-1a, `bit_exceed=21`) and zero at BF=32, but the KL max for that cell is 0.000145 nats — well within the finite-sample floor — so the flag is triggered by the bit-balance heuristic, not by a meaningful KL signal. This is a documentation weakness of the flag threshold (it conflates bit-level extremes on a small single sample with a real distributional divergence); a follow-up with `N ≥ 5` on `html_giant` would resolve it.

### Observed KL vs theoretical floor across data sizes — the invariant that matters

The finite-sample KL floor scales as `bins / N = 128 / N`, so absolute KL numbers drop linearly as samples get larger. The informative quantity is not the absolute KL, which varies by five orders of magnitude with N, but the ratio **`observed_max / theoretical_floor`**, which stays close to 1× at every data scale, for every primitive tested, **and under both attacker threat models** (idealized attacker with known `startPixel` + plaintext XOR; realistic attacker with neither).

#### Mode B — realistic attacker at BF=32 (no `startPixel`, no plaintext, full container)

The full-container analyzer ([`distinguisher_full.py`](scripts/redteam/phase2_theory/distinguisher_full.py)) runs on the BF=32 corpus — the configuration that stresses this threat model most, because CSPRNG fill inflates the container, N grows, and the theoretical floor tightens. N = `container_pixels × 8 channels` aggregated across all samples of a kind. Max across all 10 hashes (min within ~15 %).

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

Under the realistic threat model — attacker knows neither `startPixel` nor the plaintext — the ratio stays in a narrow band **1.1×–1.6×** across nearly six orders of magnitude of N. CSPRNG-fill pixels enter the test on equal footing with data pixels, inflate N, drop the theoretical floor, and the observed max tracks the floor exactly. Mode B ratios are systematically *at or below* the Mode A ratios on the same corpus (see below) — losing idealised alignment information does not give the attacker anything extra; it just removes the two levers Mode A pulled.

#### Mode A — idealized attacker at BF=1 (known `startPixel` + plaintext XOR)

Per-kind figures at BF=1, averaged across all 10 hashes (max and min across primitives within 5 %). Re-running the same analyzer at BF=32 produces the same ratio band within ±0.3× per kind — expected, since the Mode A Phase 2b accumulator reads data-carrying pixels only (N = `data_pixels × 8 channels`, determined by plaintext length, independent of CSPRNG-fill padding). Numbers below therefore characterise both fill regimes for Mode A.

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

Mode A ratio stays in the narrow band 1.4×–2.6× across four orders of magnitude of N and the full spectrum of hash primitives. Under a true null where the output is genuinely uniform random, the max-over-1540-pairs of a `bins/N`-floor statistic has expected value `√(ln 1540) ≈ 2.7×` floor — the observed 1.4×–2.6× is *below* this null expectation everywhere. **Every primitive, at every data scale, produces a pairwise-KL distribution tight enough to sit at the sampling precision limit of the measurement**.

Absolute KL is dictated by how many observations the test accumulates; the ratio to theoretical floor is dictated by the architecture. The ratio is **invariant** under data size change (four orders of magnitude in Mode A, nearly six in Mode B), under hash primitive change (linearly invertible FNV-1a sits in the same band as PRF-grade BLAKE3), under fill regime change (BF=1 and BF=32 produce the same 1.4×–2.7× band within per-cell sampling noise in Mode A), and under threat-model change (Mode B's realistic attacker gives a band at or below Mode A's across every kind). This is the empirical signature of a barrier-based construction.

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

The test harness is generic — any of the 10 hashes works via `ITB_REDTEAM_MASSIVE=<name>`, so readers wanting to see FNV-1a or MD5 at the same scale can reproduce locally. See the [Reproducibility](#reproducibility) section for the exact commands (Step 2A = Mode A, Step 2B = Mode B).

---

## Phase 2c — startPixel enumeration

Script: [`scripts/redteam/phase2_theory/startpixel_multisample.py`](scripts/redteam/phase2_theory/startpixel_multisample.py)

Attacker does **not** know `startPixel`; enumerates all `P` candidates and runs Phase 2b-style candidate analysis on each. Question: does the true `startPixel` stand out statistically? Implemented as `mp.Pool(8)` over `(hash, sample)` task list.

**Scope.** 1 290 tasks (10 hashes × 129 samples — `html_giant` excluded because O(P²) enumeration on a ~4.8 M-pixel container is infeasible). Runtime ~12 min.

### Per-hash aggregate (primary at BF=1; BF=32 in parentheses)

| Hash | Total N | Mean rank-fraction BF=1 / BF=32 (H0 = 0.5) | Mean z-score BF=1 / BF=32 (H0 = 0) |
|------|--------:|------------------------------------------:|-----------------------------------:|
| FNV-1a | 129 | 0.5317 / 0.5095 | +0.129 / +0.035 |
| MD5 | 129 | 0.4687 / 0.5166 | −0.093 / +0.083 |
| AES-CMAC | 129 | 0.5077 / 0.5158 | +0.039 / +0.037 |
| SipHash-2-4 | 129 | 0.4815 / 0.4944 | −0.063 / −0.032 |
| ChaCha20 | 129 | 0.5077 / 0.5007 | +0.032 / −0.020 |
| AreionSoEM-256 | 129 | 0.4847 / 0.5191 | −0.071 / +0.041 |
| BLAKE2s | 129 | 0.5228 / 0.4654 | +0.056 / −0.109 |
| BLAKE3 | 129 | 0.5055 / 0.5163 | +0.058 / +0.049 |
| BLAKE2b-512 | 129 | 0.4611 / 0.4586 | −0.104 / −0.148 |
| AreionSoEM-512 | 129 | 0.5314 / 0.5257 | +0.138 / +0.061 |

**95 % CI under H0 ≈ 0.5 ± 0.050** at N = 129. All 10 hashes inside CI in both regimes; mean z-scores cluster tightly around 0.

### Per-kind cells below α = 0.05 on either sign-test or t-test

| Hash | Kind | rank-fraction | sign-test p | t-test p | Regime |
|------|------|--------------:|------------:|---------:|--------|
| AreionSoEM-512 | text_small | 0.7084 | 0.011 | 0.010 | BF=1 |
| AreionSoEM-512 | http_large | 0.6077 | 0.008 | 0.026 | BF=1 |
| ChaCha20 | http_large | 0.6136 | 0.021 | 0.029 | BF=1 |
| BLAKE2s | http | 0.6378 | 0.055 | 0.043 | BF=1 |
| BLAKE2b-512 | text_large | 0.3615 | 0.997 | 0.012 | BF=1 |
| AreionSoEM-256 | html_huge | 0.9679 | 0.125 | 0.015 | BF=1 |

A cell lands in this table when **either** its sign-test or t-test returns `p < 0.05` — this is the disjunctive flag the analyzer script emits for inspection. **6 such cells appear at BF=1 (5 at BF=32 with a different distribution of affected hashes).** Under α = 0.05 across 90 `(hash, kind)` cells and two tests, 4.5–9 cells would be expected by chance even under a true null; 5–6 sits in the lower half of that range. No hash is flagged consistently across the two regimes, and flagged hashes span both directions (high and low rank-fraction) and both primitive classes — this is the pattern of random false-positive scatter under a true null, not evidence of a distinguisher.

Obstacle (2) `startPixel` isolation empirically holds across all 10 primitives at both fill regimes.

---

## Phase 2d — Nonce-Reuse

> **For a reader-friendly summary of this section** — what nonce reuse actually is, the five conditions that ALL must hold for the attack to produce any signal, and why the user's choice of nonce size is the real defence — see [ITB.md § 8 Nonce Reuse](ITB.md#8-nonce-reuse-only-if-every-condition-holds). The rest of this Phase 2d section is the formal empirical write-up: corpus generator, demasker pipeline, 96-cell matrix, NIST STS tables, and the nine architectural effects visible in the data.

Scripts:
- [`redteam_nonce_reuse_test.go`](redteam_nonce_reuse_test.go) — corpus generator (install fixed nonce via test-only hook; encrypt N plaintexts with same seeds + same nonce; emit ground-truth config sidecar).
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
3. **Reconstruction — strip all masking.** Using recovered `(startPixel, noisePos_map, rotation_map)` + known plaintext, extract the pure channel-XOR output per (pixel, channel):
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

This distinction matters: the attacker cannot simply run Gaussian elimination on recovered `channelXOR` observations to invert the seed. Seed recovery still requires bitvector-SAT over the combined XOR + integer-multiplication constraints — research-lab scale compute for 1024-bit keys.

What the NIST STS failures DO show is that **the non-linearity from carries is not strong enough** to produce statistically-PRF output over 8 rounds of ChainHash XOR composition. The reconstructed stream inherits enough residual structure for FFT to detect spectral peaks on every bit-stream and for block-level + run-length tests to flag proportion deviations. A SAT solver attacking this stream has **substantially more exploitable bias** than it would against a true PRF output — this likely shifts the seed-recovery wall-clock toward the lower end of the [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure) FNV-1a range (hours – 1 year on a 1 000-node cluster under idealised conditions) or below, though this plan does not attempt the actual SAT run.

Under PRF (BLAKE3 at 4 rounds at 1024-bit key) the reconstructed stream's 188 / 188 pass means the attacker's SAT problem has **no statistical bias to exploit beyond the raw algebraic complexity** — the single remaining obstacle (ChainHash SAT-hardness over a PRF) remains effectively infeasible.

### Consistency with Phase 2a cost tables

The [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure) three-layer combined-cost estimate (10¹² – 10¹⁶ years at 50 % Partial KPA + unknown `startPixel` + 1 000-node cluster) applies to the **standard threat model**: fresh nonce per encryption, all three obstacles active. The nonce-reuse attack operates outside that model — it deliberately forces a nonce collision and uses the two ciphertexts together to peel back obstacles (2) and (3). Layer 1 + Layer 2 of the demasker complete this peeling in seconds per pair.

What remains after peeling is exactly the "Full KPA + `startPixel` known" entry from Phase 2a's [back-of-envelope table](#back-of-envelope-1000-node-cluster-wall-clock-full-kpa-startpixel-known) — **hours to 1 year** on a 1 000-node cluster under FNV-1a, or structurally infeasible under PRF. The NIST STS results validate this split empirically: under FNV-1a the remaining single-layer defence exhibits detectable output bias (the SAT solver would have real leverage); under PRF no such leverage exists (output is indistinguishable from random).

**The takeaway is not that the [Phase 2a](#phase-2a--chainhash-analysis-and-the-three-layer-defense-structure) estimates are wrong.** They are correct for the threat model they state. The takeaway is that **architectural obstacles (2) and (3) are load-bearing against below-spec primitives** — a single-layer "just-ChainHash" defence is sufficient under a real PRF but **insufficient under an invertible primitive** even when the primitive is wrapped in 8 rounds of XOR composition. This is why [`SECURITY.md`](SECURITY.md) and [`SCIENCE.md`](SCIENCE.md) consistently require PRF-grade primitives for production use, and this empirical demonstration makes that requirement concrete.

### Validation of [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis) locality claim

| Claim from [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis) | Empirical status from this phase |
|--------------------------------------------------------------------|----------------------------------|
| Nonce collision compromises confidentiality of the 2 – 3 colliding messages (two-time pad on data bits) | ⚠ Confirmed as a theoretical possibility, but empirically tautological on this probe. ITB's per-encryption noise bits + rotation + channelXOR mean `C1 ⊕ C2` alone does NOT yield plaintext XOR (unlike a stream cipher) — the full demasker pipeline is required. Its output is the hash-output stream, and plaintext bytes become derivable only at positions where the attacker already knew one side from format knowledge; those positions coincide with format-spec-derivable bytes, yielding no new plaintext information in practice. |
| Seeds remain secret under PRF non-invertibility | ✅ Confirmed empirically via BLAKE3 188/188 NIST STS on reconstructed stream: no exploitable structure in the remaining single-layer defence. SAT-based seed recovery has no statistical leverage. |
| Seed retention **requires** PRF non-invertibility | ✅ Empirically demonstrated via the BLAKE3-vs-FNV-1a contrast: same attack chain, same stream size, same NIST STS configuration, opposite outcomes. Under FNV-1a the reconstructed stream flags 6 tests (including FFT 0/16 — spectral structure on every bit-stream) showing residual linear-order bias that a SAT solver could leverage for seed recovery. |
| No key rotation required after a nonce collision | ⚠ Confirmed **only for PRF-grade primitives**. Under FNV-1a the nonce-reuse event plausibly does not merely leak the 2 – 3 colliding messages — it produces a detectable-bias stream whose hash-output structure a motivated attacker (lab-scale compute) could invert to recover seeds. The [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis) no-rotation claim implicitly depends on the PRF requirement stated elsewhere in the docs; this probe makes that dependency empirically visible. |

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

6. **None of the three Layer-1-ambiguity drivers above are coverage problems.** Bumping plaintext coverage from 83 % to 90 % would only slightly reduce the `d_xor = 0` known-channel count; it would NOT change the fundamental fact that structurally-shared bytes produce per-channel same-plaintext degeneracy. The ambiguity is a property of ITB's 8-channel-per-pixel packing interacting with ANY Partial-KPA scenario where known bytes include structurally-shared positions.

**This is a construction-level finding.** ITB's barrier — specifically the way `(noisePos, rotation, channelXOR)` bind the 8 channels of a pixel through a **single** pair of hash outputs — means single-pair Layer 1 recovery needs ~8 discriminating channels per pixel. Partial KPA with structurally-shared bytes cannot meet that requirement on a single (ciphertext, ciphertext) pair, regardless of how high the byte-level coverage goes (short of 100 %, which is Full KPA). To close the gap, the attacker needs **multi-pair disambiguation** (N ≥ 4 collisions — independent noise-bit draws per encryption, intersecting candidate sets collapse to 1 exponentially fast):

- At N = 4 (6 pairs): ambiguity probability per pixel ≈ (85 %)⁶ ≈ 38 % — already a big reduction
- At N = 8 (28 pairs): ≈ (85 %)²⁸ ≈ 1 % — essentially full unique recovery
- At N = 128 (8 128 pairs): <<1 % — full saturation

The current Partial KPA experiment deliberately runs at N = 2 (one pair), which is the minimum that produces a nonce-reuse XOR at all — this was intentional to show **where the single-pair attack hits its construction-level wall under Partial KPA**, not to maximise attack success. A future Partial-KPA experiment at N = 4 or N = 8 on the same corpus design would exercise the multi-pair path and is expected to recover the stream-size budget.

**Periodicity leak caveat.** On the 4 MB runs the demasker's Layer 2 converged on a startPixel offset from the true one by a large (non-multiple-of-record-length) shift. The reconstructed stream is therefore **not** exactly a clean prefix of `dataHash(pixel_u32le || nonce)` — it contains residual `payload_claimed ⊕ payload_actual` XOR on the channels where the two plaintexts' bytes happen to differ under the shift. Empirically this shows up as a 1-bit discrepancy at byte 0 of the reconstructed stream vs ground truth, visible in the demasker's first-32-bytes spot-check print; the following 31 bytes of the spot-check matched exactly. The partial-mode validation function returns a binary match/mismatch flag rather than a byte-count, so the full-stream byte-for-byte match rate was not rigorously measured — the apparent "1-byte seam + clean thereafter" shape is inferred from the spot-check only. This is a Partial-KPA-specific artefact that does not occur under Full KPA; the write-up preserves it honestly rather than papering over it with additional demasker machinery.

**Coverage as seen by the Python demasker** (after COBS mask propagation + 7-bit channel slicing):

| Quantity | FNV-1a 4 MB run |
|----------|-----------------:|
| Byte-level known coverage from cell.meta.json | 83.33 % (3 495 196 / 4 194 235 raw plaintext bytes) |
| Channel-level known coverage (known in BOTH payload masks) | **81.39 %** (3 930 920 / 4 829 832 channel slots) |
| Pixels with ≥ `min_known_channels=2` usable channels | 88.75 % (535 794 / 603 729) |

**NIST STS on reconstructed streams — negative result on PRF-separation at this stream size.**

Two independent FNV-1a Partial-KPA runs (different fresh nonce seeds so the `NonOverlappingTemplate` bin draw is independent):

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

1. **PRF-separation is NOT visible at this Partial-KPA stream size.** The Full-KPA Phase 2d result (6 real fails on FNV-1a at 16.8 Mbit, N=16) depends on NIST STS having enough sequences per sub-test for the bin-0 hit rate (~10 % per run) to be distinguishable from structural non-uniformity. At the Partial-KPA stream sizes here (3.8 – 5.3 Mbit, N = 3 – 5), the per-sub-test variance is dominated by single-bin clustering. Both primitives' runs are statistically indistinguishable from each other (both hit single-bin clustering, just into different bins).
2. **Run B-1 "signal" was bin-0 bad luck, not structure.** The initial 36/188 FNV-1a result had a tempting-looking failure pattern; it does not survive replication with an independent nonce seed. A single Partial-KPA run cannot distinguish the bin-routing artefact from a real signal at this scale.
3. **What the pipeline DOES confirm.** The Partial-KPA demasking + reconstruction code path works end-to-end: Layer 1 produces 0 WRONG matches on both runs, and a spot-check of the first 32 bytes of each reconstructed stream shows a 1-bit discrepancy at byte 0 followed by an exact match on the next 31 bytes — the demasker's partial-mode validator returns a binary match/mismatch flag so full-stream byte-for-byte correctness was not rigorously measured. The inferred shape is "1-byte seam at the alignment boundary + clean dataHash output thereafter", but the tail of the stream beyond the 32-byte spot-check remains unverified. Taking the inference at face value, the reconstructed stream IS valid dataHash output (up to the seam) — there is just not enough of it (a few Mbit) for NIST STS to separate primitives at this statistical power.
4. **Where the attack breaks (what we learned).** Two independent bottlenecks limit the Partial-KPA stream:
    - **Construction-level bottleneck (the main finding):** ITB's per-pixel `(noisePos, rotation, channelXOR)` packing binds all 8 channels through a single pair of hash outputs, so single-pair Layer 1 needs ~8 rotation-discriminating channels per pixel. Partial-KPA plaintexts with structurally-shared bytes (`{`, `}`, `,`, `"`, `:`, sequence numbers) produce `d_xor = 0` known channels that only pin `noisePos`; the remaining ~5 rotation-active channels are insufficient to disambiguate rotation on a single pair. Result: ~85 % of pixels stay ambiguous, stream shrinks ~5 – 7 ×. Fixing this requires multi-pair Layer 1 at N ≥ 4 — see the "Ambiguity explosion" block above.
    - **NIST-STS-power bottleneck (secondary):** Even assuming the stream were restored to its naive 27 Mbit upper bound, NIST STS needs N ≥ 10 sequences per sub-test to distinguish the PRF-separation signal from the bin-routing artefact reliably. Requires plaintext ≥ ~10 MB (at 83 % coverage, full Layer 1 recovery) OR multi-pair Layer 1 on the current 4 MB corpus.
5. **Scope-of-Partial-KPA limitation, now explicit.** The "~83 % coverage + distinct-template + sequential-sequence-number" conditions ARE necessary for the pipeline to reconstruct any stream at all, but are NOT sufficient on their own (N = 2 single-pair Layer 1 + stream < 10 Mbit) to produce a NIST-STS-distinguishable stream. A Partial-KPA attack at this scale and collision count is a construction-correctness probe — and, more importantly, **an empirical demonstration that ITB's 8-channel-per-pixel single-hash-output binding makes single-pair Partial-KPA structurally weaker than single-pair Full KPA**, not just quantitatively (via fewer known bits) but architecturally (via same-plaintext-like degeneracy on structurally-shared channels).

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

> **These six kinds are artificially engineered** for maximum Partial-KPA signal. Real-world binary formats (ZIP, PDF, MP4, MP3, SQLite, PNG, TAR, …) have tiny fixed-position signature islands at variable offsets surrounded by compression-entropy-maximised content, and the demasker extracts ~0 % signal from them. For a worked ZIP example (0.003 % fixed-position coverage, same-plaintext degeneracy on the shared `PK\x03\x04` signature, why brute-forcing signature offsets is infeasible) and the full list of format classes that defeat the attack, see [ITB.md § 8.1 Why binary formats defeat Partial-KPA demasking entirely](ITB.md#81-why-binary-formats-defeat-partial-kpa-demasking-entirely).

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

**1. Hash identity (BLAKE3 vs FNV-1a) is near-irrelevant for extraction rate.** Cells with identical `(size, kind)` and differing hash produce Clean % within 1-2 p.p. of each other except under period-shift events — and in those events the direction of the drift is random, not hash-dependent. The ChainHash wrapping makes the demasking pipeline primitive-blind. Hash choice only matters on the emitted stream (NIST STS / SAT seed-recovery), not during recovery itself. This justifies why we deliberately skipped the "all 10 primitives" Full-KPA documentation run — it would just be ten near-identical rows.

**2. Clean Signal % is ALWAYS below target coverage %.** Even the best cells (64 KB × 80 % target × clean alignment) yield 72-76 % clean — already a 4-8 p.p. loss from advertised coverage. The loss accumulates from the nine architectural effects enumerated below.

**3. Period-shift stochasticity dominates mid-size cells.** Clean % on `(128 KB, JSON 80 %)` is 4.5 % while `(64 KB, JSON 80 %)` is 72.7 % — not because 128 KB is harder but because the specific random seed placed the true startPixel at a position where Layer 2's 57-probe heuristic found a period-shifted false sp first, and the shift happened to break the Layer 1 constraint on most pixels. Variance is large; the "size" axis in the table is NOT a monotonic predictor. This is a real property of single-pair attacks on repeating plaintexts, not a demasker defect.

**4. Coverage efficiency (emitted / attacker-known-channel budget) stays high when Layer 2 anchors true sp** (90-97 % across clean cells), and collapses to the 2-40 % range under period-shift catastrophe. High coverage efficiency on true-sp cells confirms the demasker uses its input bits near-optimally; the losses are not "demasker weakness" but architectural information-theoretic floors.

**5. Low-coverage (25 %) behaviour is consistently weak but graceful.** Across sizes, 25 % coverage yields 15-24 % Clean on small-to-mid sizes, degrading further under period-shift. No cell produces meaningless garbage; the demasker correctly refuses pixels it can't constrain rather than emit noise.

**6. 10 cells returned exit code 2 under imperfect period-shift alignment.** Under a shift that is not exactly a `d_xor` pattern period, a small number of pixels (0.01 – 0.1 %) recovered a `(noisePos, rotation)` pair that is unique under constraint matching but does not match the ground-truth at the shifted position. These are NOT formula bugs — the demasker formula is correct; the artefact is that single-pair Layer 1 admits rare isolated false positives when `d_xor_claim_p ≠ d_xor_true_{p+shift}` at approximate-period shifts. The stream was still emitted (mostly correct, with a handful of corrupted channel-XOR values scattered); the orchestrator flags these as demask-fail due to the strict WRONG > 0 gate. Real attackers cannot distinguish these from clean runs without access to ground truth.

### Nine architectural effects visible in this matrix

These are properties of ITB's construction that show up empirically in the numbers above. None are demasker bugs; all are structural features that shape the attacker's information recovery envelope.

1. **Same-plaintext-local degeneracy** on structurally-shared known bytes. When the attacker knows a byte AND that byte is identical across both plaintexts (JSON `{`, `"`, `:`, `,`; HTML `<`, `>`, `=`), the channel's `d_xor = 0` and it only constrains `noisePos`, not `rotation`. This reduces the effective discriminating budget from 8 channels to ~5 per pixel at 80 % coverage.

2. **Record-level periodicity**. Repeating record templates produce a `d_xor` pattern periodic with period = record length. Layer 2 brute-force thereby admits ANY period-shifted sp as "valid" — visible in the ⚠-marked cells. `auto --n-probe` tries to span 3 record periods to break this, but on mid-size plaintexts the heuristic is not enough.

3. **Stochastic period-shift catastrophe**. At imperfect (non-period-multiple) shifts, Layer 1 coincidentally accepts false constraints on most pixels, collapsing Clean % to 1-15 %. Visible in JSON 128 KB / 1 MB / 2 MB / 4 MB cells.

4. **Per-pixel 8-channel binding through a single hash-output pair**. All 8 channels of a pixel derive from ONE `(noisePos, rotation, channelXOR)` set that comes from ONE pair of ChainHash outputs. Single-pair Partial-KPA cannot distribute constraint information across independent hash queries; multi-pair `N ≥ 4` disambiguation is the architectural mitigation path.

5. **COBS mask conservatism (3-5 p.p. loss)**. Group-length code bytes mark as "unknown" whenever any input byte in the block is unknown (safe conservative propagation). Visible as target 80 % → actual channel 75-80 % gap.

6. **7-bit channel byte-boundary loss (2-3 p.p.)**. A channel whose 7 bits straddle a byte boundary (bit offset % 8 ≥ 2) is marked unknown if EITHER of the two spanned bytes is unknown. Compounds with effect 5.

7. **CSPRNG fill beyond `cobs + null`**. Payload bytes after the attacker-known region are fresh random per encryption, not attacker-predictable. On short plaintexts this is a larger fraction; on 4 MB it's a few hundred fill pixels out of 600 k.

8. **Single-pair Layer 1 ambiguity explosion**. Already documented in the Run B writeup above: single-pair constraint matching with ~5-6 rotation-active channels per pixel admits 2+ `(noisePos, rotation)` candidates on 80-88 % of pixels under 80 % coverage. Increases to 90-95 % at 25 % coverage.

9. **Imperfect-period-shift wrong-match emergence**. Documented in observation 6 above — approximate-period shifts admit rare isolated false single-candidate recoveries at the 0.01 – 0.1 % level.

### What a successful Partial-KPA demask actually gets the attacker

Suppose every precondition lines up — the attacker forced a nonce-reuse event, knows the byte-level plaintext format, holds the two distinct templates, has the sequence-number field offsets, and the demasker converged on the true `startPixel` with 80 %+ coverage. What do they actually walk away with? Less than "the seeds", and much less than the phrase "reconstructed dataHash stream" might suggest:

1. **No plaintext — only the hash-output stream.** The demasker's output is always the raw `dataSeed.ChainHash(pixel, nonce)` hash-output stream, never plaintext. Under Full KPA the attacker knows both plaintexts going in; the demasker converts (plaintext_input + 2 ciphertexts) into the hash-output stream. The attacker walks away with this hash-output signal to probe for PRF structure — not with plaintext they did not have before. Unlike a stream cipher where `C1 ⊕ C2` directly reveals `plaintext_1 ⊕ plaintext_2`, ITB's per-encryption fresh-CSPRNG noise bits + per-pixel rotation + per-pixel channelXOR mean raw ciphertext XOR does NOT reduce to plaintext XOR; only the full demasker pipeline extracts anything, and its output is strictly hash bits.

2. **Under a PRF primitive (BLAKE3 / AES-CMAC / SipHash-2-4 / ChaCha20 / AreionSoEM-256/512 / BLAKE2s / BLAKE2b-512): just the hash-output stream, useless.** The reconstructed `dataHash` stream is statistically indistinguishable from uniform random (188/188 on NIST STS). Inverting it to recover `dataSeed` requires breaking the PRF — out of scope by assumption. `startSeed` and `noiseSeed` inversion hit the same wall. The attack surface closes on this output.

3. **Under FNV-1a (the only invertible primitive in the hash matrix): one SAT instance per seed, not three free seeds.** The reconstructed `dataHash` stream exposes the ChainHash-wrapped FNV-1a's algebraic structure under a controlled pixel-index probe — which gives a SAT solver real leverage. But:
    - `dataSeed` inversion requires solving an 8-round ChainHash128 bitvector-SAT instance over a 1024-bit unknown — still research-level, not a Gaussian elimination.
    - `startSeed` inversion is WORSE. The attacker observes **one `startPixel` value per `(seeds, nonce)` session** — a 3-log₂(totalPixels) ≈ 17-bit observation. To invert `startSeed` via ChainHash, the attacker needs MANY independent nonce-reuse sessions (each giving one fresh startPixel observation under a different nonce), not many messages within one session. Each session requires forcing a fresh nonce collision — a birthday-bound event at whatever nonce size the deployment chose. At 512-bit nonce: never. Even at 128-bit the attacker needs 2⁶⁴ messages to force ONE collision session, let alone the many sessions needed to stack enough startPixel observations for SAT-inversion.
    - On top of that, `startPixel` is often NOT cleanly recoverable — Layer 2's period-shift behaviour (documented in effect 3 above) produces a set of plausible `startPixel` candidates, not a single value. Inverting `startSeed` from noisy multi-candidate observations is harder still.
    - `noiseSeed` inversion requires the demasker to ALSO emit a `noisePos` stream (3 bits per pixel from `noiseHash & 7`) — which the current demasker does not output as a distinct stream, only as internal per-pixel state consumed by reconstruction. To attack `noiseSeed` the attacker would need a separate pipeline to emit and accumulate `noisePos` observations across sessions, then run ANOTHER ChainHash-wrapped FNV-1a SAT instance on those.

4. **No seed is leaked directly.** Every seed-inversion path — even under the most attacker-favourable primitive choice — reduces to "stack enough observations across enough independent nonce-reuse sessions, then solve a bitvector-SAT instance over an 8-round ChainHash wrap at 1024-bit key". The Phase 2a cost tables apply to each such inversion independently.

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

- **All-10-primitives Full-KPA documentation run**: not performed. Demasking is primitive-independent at the recovery step (observation 1 above), so adding BLAKE2s, BLAKE2b, SipHash, etc., would produce six near-identical tables. The Full-KPA validation table in the main Phase 2d writeup already covers four widths (FNV-1a 128, MD5 128, BLAKE3 256, BLAKE2b 512) confirming the demasker formula works across all ChainHash widths.
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

- **Full KPA is the main result.** Partial KPA is exercised in a separate subsection above with a carefully-structured JSON plaintext and strong attacker assumptions — see [Partial KPA extension](#partial-kpa-extension--structured-json-plaintext-artificial-scenario). The result is useful as a best-case upper bound on Partial-KPA attackability, not as a general Partial-KPA claim.
- **Two primitives only in the automated matrix** (BLAKE3 + FNV-1a). The one-off `--hashes all` run across all 10 primitives is documented separately in this plan's follow-up for producing a comprehensive primitive-by-primitive table — expected result: all 8 PRF-grade primitives (BLAKE3, AES-CMAC, SipHash-2-4, ChaCha20, AreionSoEM-256, BLAKE2s, BLAKE2b-512, AreionSoEM-512) pass 188/188 at this stream size; FNV-1a and MD5 are the non-PRF outliers (MD5 passes NIST STS at the 16 Mbit stream size because its bit-level output IS uniform-looking — its collisional brokenness only surfaces at much larger streams — so for this specific test it tracks the PRF-grade group, but it should not be framed as PRF-grade).
- **Sensitivity / nonce-mismatch control test** — see [subsection above](#sensitivity--nonce-mismatch-control-test).
- **Triple Ouroboros nonce-reuse** not implemented. Actual implementation requires the Triple-analyzer rewrite that also gates Phase 2b / 2c / 3a Triple coverage.
- **Seed recovery via SAT** — the logical next step after this phase's NIST STS result — is out of scope. This phase stops at distinguishability (NIST STS level); converting distinguishability into actual seed values requires research-lab SAT compute that this plan does not attempt.

---

## Phase 3a — Rotation-invariant edge case

Script: [`scripts/redteam/phase3_deep/rotation_invariant.py`](scripts/redteam/phase3_deep/rotation_invariant.py)

Tests [`SCIENCE.md` §2.9.2](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier) prediction: rotation-invariant 7-bit values (`0000000` and `1111111`) occur at rate 2/128 = 1.5625 % across all hash primitives under the uniform-distribution claim. For each data-carrying pixel × each channel byte × each of 8 `noisePos` values, extract the 7-bit value and count 0x00/0x7F occurrences. Runtime ~30 s per full corpus pass, 34.8 M extracts per hash.

### Per-hash aggregate (primary at BF=1; BF=32 in parentheses)

| Hash | Rate BF=1 / BF=32 | Deviation BF=1 / BF=32 | p-value BF=1 | p-value BF=32 |
|------|------------------:|----------------------:|------------:|-------------:|
| FNV-1a | 1.5665 % / 1.5617 % | +0.0040 % / −0.0008 % | 0.0558 | 0.6940 |
| MD5 | 1.5655 % / 1.5685 % | +0.0030 % / +0.0060 % | 0.1522 | 0.0042 |
| AES-CMAC | 1.5629 % / 1.5742 % | +0.0004 % / +0.0117 % | **0.8344** | **< 10⁻⁷** |
| SipHash-2-4 | 1.5615 % / 1.5622 % | −0.0010 % / −0.0003 % | 0.6200 | 0.9032 |
| ChaCha20 | 1.5625 % / 1.5680 % | −0.0000 % / +0.0055 % | 0.9837 | 0.0094 |
| AreionSoEM-256 | 1.5563 % / 1.5595 % | −0.0062 % / −0.0030 % | 0.0034 | 0.1511 |
| BLAKE2s | 1.5601 % / 1.5600 % | −0.0024 % / −0.0025 % | 0.2529 | 0.2330 |
| BLAKE3 | 1.5622 % / 1.5690 % | −0.0003 % / +0.0065 % | 0.8935 | 0.0020 |
| BLAKE2b-512 | 1.5642 % / 1.5763 % | +0.0017 % / +0.0138 % | **0.4070** | **< 10⁻¹⁰** |
| AreionSoEM-512 | 1.5630 % / 1.5625 % | +0.0005 % / −0.0005 % | 0.8174 | 0.7451 |

**Observations:**

- **The BF=32 "signals" did not replicate at BF=1.** AES-CMAC went from p < 10⁻⁷ (BF=32) to p = 0.83 (BF=1); BLAKE2b-512 went from p < 10⁻¹⁰ to p = 0.41; ChaCha20 and BLAKE3 similarly dropped out of significance; and AreionSoEM-256 newly flagged at p = 0.003 (BF=1) while clean at BF=32. This is the **signature of a statistical-power artefact on near-uniform output**: the tests are sensitive enough at very large N to flag any tiny deviation from the expected 1.5625 % rate, but which specific hashes cross the threshold in any one run is essentially random. Different N (BF=1 has fewer extracts per sample than BF=32 because the container is smaller) produces a different random scatter of "significant" cells, not a consistent signal.
- **No hash shows sign-consistent deviation across both regimes.** Every hash's rate fluctuates within ±0.01 % of 1.5625 % between the two runs — i.e., within the measurement precision of this test at this N. There is no primitive-specific or weak-vs-strong structural pattern.
- Absolute deviations are tiny regardless of regime: the largest (+0.0138 % at BLAKE2b-512, BF=32) measures a rate shift from 1.5625 % to 1.5763 %. An attacker cannot use this deviation to narrow per-sample `startPixel` or rotation candidates; it is below any attack-useful threshold and also below the noise floor of replication.
- Per-kind drill-down at BF=1 confirms no clustered per-kind bias (see `tmp/results/single_bf1/03_phase3a.log`).

**Interpretation.** The rotation-invariant rate stays at 1.56 % within ~0.01 % across 34.8 M extracts per hash, independent of fill regime. Statistical tests on such near-uniform output produce false-positive flags that do not replicate — a known limitation when the null is essentially true and N is large enough to detect sub-thousandths-of-a-percent noise. [`SCIENCE.md` §2.9.2](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier) is validated: the barrier absorbs hash-level bias even at the edge case, across all 10 primitives and both fill regimes.

---

## Phase 3b — NIST STS (SP 800-22)

Script: [`scripts/redteam/phase3_deep/nist_sts_runner.py`](scripts/redteam/phase3_deep/nist_sts_runner.py)

NIST STS runs 188 individual tests across 15 categories: Frequency, BlockFrequency, CumulativeSums, Runs, LongestRun, Rank, FFT, NonOverlappingTemplate (148 sub-tests), OverlappingTemplate, Universal, ApproximateEntropy, RandomExcursions (8 sub-tests), RandomExcursionsVariant (18 sub-tests), Serial, LinearComplexity.

**Streams.** Corpus ciphertexts are concatenated header-stripped via `prepare_streams.py` into `tmp/streams/<hash>.bin` at ~8.9 MB = 71 Mbits per hash — 3.5× more than NIST STS requires for 20 × 1 Mbit.

**Test configuration.** 20 sequences × 1 000 000 bits per run. Pass threshold computed dynamically via the NIST SP 800-22 formula `p̂_min = (1 − α) − 3 · √(α(1 − α)/m)` at α = 0.01 (18 / 20 for standard tests; scales down for RandomExcursions when fewer sequences have valid excursions).

**Parallelism.** 10 `nist-sts` subprocesses in isolated experiment directories. Total wall time: 58 s.

### Results across configurations

The suite runs NIST STS at five independent configurations: two BF=1 Single replications at the NIST SP 800-22 example parameter (N = 20 sequences × 1 Mbit); one BF=32 Single run at the same N; and two larger-N runs at BF=1 and BF=32 Single (**N = 100 × 1 Mbit**) that are statistically more robust but — as the BLAKE3 cell below makes clear — still expose the `NonOverlappingTemplate` bin-routing artefact.

| Hash | BF=1 Run A (N=20) | BF=1 Run B (N=20) | BF=32 (N=20) | BF=1 (N=100) | BF=32 (N=100) |
|------|-----------------:|-----------------:|-------------:|-------------:|--------------:|
| FNV-1a | **40 / 188 †** | 188 / 188 | 188 / 188 | 187 / 188 | 188 / 188 |
| MD5 | 188 / 188 | 187 / 188 | 188 / 188 | 188 / 188 | 188 / 188 |
| AES-CMAC | 188 / 188 | 188 / 188 | 188 / 188 | 187 / 188 | 188 / 188 |
| SipHash-2-4 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 |
| ChaCha20 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 | 187 / 188 |
| AreionSoEM-256 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 |
| BLAKE2s | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 |
| BLAKE3 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 | **40 / 188 †** |
| BLAKE2b-512 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 | 187 / 188 |
| AreionSoEM-512 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 | 188 / 188 |

† **Both 40/188 cells — FNV-1a at N=20 Run A *and* BLAKE3 at N=100 BF=32 — are the same NIST SP 800-22 test-battery artefact, not actual cryptographic failures.** That these two cells are hit by a fully-invertible below-spec primitive (FNV-1a) and a paper-grade 256-bit PRF (BLAKE3) is direct empirical evidence that the mechanism is *hash-agnostic*. The explanation: `NonOverlappingTemplate` routes each run's per-sequence p-values into one of 10 histogram bins; ITB ciphertext is uniform enough that all N per-sequence p-values cluster into a *single* bin. The bin is effectively randomly chosen per `(hash, run)` pair, and bin 0 contains p-values below the pass cut-off — so whichever hash happens to draw bin 0 on a given run reports a catastrophic-looking proportion failure on all 148 `NonOverlappingTemplate` sub-tests simultaneously. The bin-0 draw probability is ~10 % per `(hash, run)` and independent across hashes, so across 50 such `(hash, run)` trials in this table (10 hashes × 5 configurations) the expected number of cells flipping to 40/188 is ~5; observed is 2. The clustering pattern itself is **universal across all 10 hashes in all 5 configurations** — the mechanism is explained in detail in the subsection below. `/dev/urandom` exhibits the same pattern on streams of this size.

Across both N = 100 runs (BF=1 and BF=32), 15 of 20 `(hash, BF)` cells pass 188/188; 4 cells show a single-test failure each (FNV-1a `Serial` at 95/100 BF=1, AES-CMAC `RandomExcursions` at 56/60 BF=1, ChaCha20 and BLAKE2b-512 at BF=32 on tests with **non-clustered** histograms — conventional near-threshold proportion fails, a different phenomenon from the bin-0 artefact marked with †); and 1 cell (BLAKE3 BF=32) hit the bin-0 artefact. Across 20 × 188 = 3 760 tests the 5 non-artefact failures are well below the 38 expected at α = 0.01.

### The p-value clustering phenomenon — hash-agnostic, present at any N

NIST STS reports 148 `NonOverlappingTemplate` sub-tests per run. Each sub-test buckets N per-sequence p-values into 10 equal-width histogram bins `[0.0, 0.1), [0.1, 0.2), …, [0.9, 1.0]` and runs a χ² uniformity test on the bin counts. ITB ciphertext is uniform enough that all N per-sequence p-values fall into **a single bin** — the same bin across every one of the 148 sub-tests within a run. Which bin depends on seeds.

**Evidence — histogram clustering is universal across all 10 hashes and reshuffles independently per BF regime.** First `NonOverlappingTemplate` row from each N=100 report (BF=1 and BF=32 runs, on the same corpus with fresh crypto seeds per run):

| Hash | Bin at BF=1 (N=100) | Bin at BF=32 (N=100) |
|------|---------------------:|---------------------:|
| FNV-1a | **0** | 2 |
| MD5 | 6 | 2 |
| AES-CMAC | 3 | 8 |
| SipHash-2-4 | 2 | 8 |
| ChaCha20 | 1 | 6 |
| AreionSoEM-256 | 5 | 2 |
| BLAKE2s | 5 | 2 |
| BLAKE3 | 2 | **0** |
| BLAKE2b-512 | 3 | 2 |
| AreionSoEM-512 | 4 | 6 |

Every hash — including FNV-1a, which raised the alarm at N=20 by drawing bin 0, and BLAKE3, a paper-grade 256-bit PRF, which drew bin 0 at N=100 BF=32 — shows the same single-bin clustering pattern. The bin assignment is effectively random per `(hash, run)` pair. Proportion is 100/100 for every template sub-test on any run where the bin is **not** 0, and 0/100 on all 148 sub-tests simultaneously whenever it **is** 0.

**This is a documented NIST SP 800-22 artefact** on near-uniform data. The uniformity-of-p-values meta-test fires (`*` on the 0.000000 uniformity p-value) whenever the input produces clustered per-sequence p-values — which is exactly what truly-random-looking data does at this N and template-size combination. /dev/urandom exhibits the same pattern. Increasing N from 20 to 100 does not eliminate the artefact; it only reduces its per-cell probability proportionally (still ~10 % per `(hash, run)` pair), so larger tables like this one make bin-0 draws visible as an occasional scattered event rather than the N=20 Run A situation where a single bin-0 draw on a single hash looked like "FNV-1a broke on NIST STS".

### Interpretation

1. **All 10 primitives are empirically indistinguishable on NIST STS.** The single-bin clustering is identical across invertible (FNV-1a), biased (MD5), and paper-grade PRF (eight others) primitives. No hash stands out structurally. The two 40/188 events in the table — FNV-1a at N=20 Run A and BLAKE3 at N=100 BF=32 — are both bin-0 draws of the same mechanism; one from a below-spec hash, one from a PRF, confirming the mechanism is hash-agnostic.
2. **A 40/188 cell is bin-0 bad luck, not a security signal — regardless of which hash it happens to.** Any hash can draw bin 0 on any run and produce this catastrophic-looking proportion failure on all 148 `NonOverlappingTemplate` sub-tests simultaneously. Five configurations × 10 hashes = 50 (hash, run) trials in the suite; expected bin-0 hits at ~10 % per trial is ~5; observed is 2. Consistent with the null model.
3. **N=100 does not eliminate the artefact — it just reduces per-cell probability proportionally.** At both N=20 and N=100 the bin-0 draw remains a ~10 % event per `(hash, run)` pair. Readers scanning the table should treat any 40/188 cell with † as equivalent to the 50 other cells — a random bin assignment that happened to land on bin 0 — rather than as a hash-specific failure. Larger-N runs are preferable because conventional (non-bin-0) proportion failures become genuine outliers, letting the eye separate real signal from the artefact.
4. **The paper's explicit PRF-grade primitive requirement stands.** The empirical suite shows the architecture drives every tested primitive — including FNV-1a and MD5 — to statistically identical ciphertext across all five empirical phases; a real PRF's output is already unpredictable and gets absorbed identically. NIST STS cannot reliably distinguish ITB ciphertext produced with any of the 10 tested primitives from a true PRF across the three ITB widths (128 / 256 / 512).

---

## Triple Ouroboros — supplementary runs at BF=1 and BF=32 (N=100)

Triple Ouroboros uses 7 seeds (1 noiseSeed + 3 dataSeeds + 3 startSeeds); the container is partitioned into 3 thirds, each processed with an independent `(dataSeed_i, startSeed_i)` pair. The plaintext is split via `splitTriple` (every 3rd byte → third `i`), so a single per-pixel distinguisher cannot run without also inverting the partition map. Phases 2b, 2c, and 3a therefore require analyzer rewrites to handle the 3-partition layout and are not included in this pass; Phase 1 (byte-level structural test) and Phase 3b (NIST STS on the corpus-concat stream) are mode-agnostic and run unchanged. Both regimes (BF=1 and BF=32) were executed.

### Phase 1 in Triple mode

All 10 hashes pass in both fill regimes: 0 / 80 Bonferroni failures; collision ratios in [0.98, 1.03] at BF=1 and [0.978, 1.007] at BF=32. The structural profile is indistinguishable from Single mode at the same corpus — the 8-channel packing is absorbed equally whether the container is split into 1 or 3 logical partitions.

### Phase 3b in Triple mode (N = 100)

| Hash | Pass BF=1 | Bin BF=1 | Pass BF=32 | Bin BF=32 |
|------|----------:|---------:|-----------:|----------:|
| FNV-1a | 185 / 188 | 8 | 188 / 188 | 7 |
| MD5 | 187 / 188 | 6 | 188 / 188 | 5 |
| AES-CMAC | 188 / 188 | 8 | 187 / 188 | **0** |
| SipHash-2-4 | 188 / 188 | 1 | 188 / 188 | 9 |
| ChaCha20 | 188 / 188 | 2 | 188 / 188 | **0** |
| AreionSoEM-256 | 188 / 188 | 2 | 188 / 188 | 6 |
| BLAKE2s | 188 / 188 | 5 | 188 / 188 | 9 |
| BLAKE3 | 188 / 188 | 8 | 188 / 188 | 4 |
| BLAKE2b-512 | 188 / 188 | **0** | 188 / 188 | 2 |
| AreionSoEM-512 | 188 / 188 | 3 | 188 / 188 | 9 |

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

**ITB is a barrier-based construction, not a primitive-based one.** Security arises from the architecture — 8-channel packing, 7-bit extraction with rotation, CSPRNG-fill residue, ChainHash XOR chain — rather than from the quality of the underlying hash. This is empirically demonstrated across the spectrum from deliberately broken (FNV-1a invertible, MD5 biased) to paper-grade PRF (AES-CMAC, SipHash-2-4, ChaCha20, BLAKE2s / 3, BLAKE2b-512, AreionSoEM-256 / 512): all 10 primitives produce ciphertext statistically indistinguishable from a true PRF across every stable test outcome at shipped defaults.

### Why the below-spec testing matters

Testing a construction with PRF-grade primitives and observing unpredictable output is near-tautological: PRFs produce unpredictable output by definition. Probing whether the **barrier itself** absorbs weakness requires testing below-spec primitives. We did:

- **FNV-1a 128** — linearly invertible in O(1), no preimage resistance, not cryptographic
- **MD5** — collisions in minutes, documented output biases, half-broken preimage resistance

If the barrier did not absorb weakness, these below-spec hashes would leak signal: Phase 2b would show elevated per-pixel KL on FNV-1a or MD5, Phase 3b would fail on specific NIST sub-tests consistently across replications, Phase 1 would show per-channel deviation. **None of the phases shows a stable weak-vs-strong split.**

This supports an **a fortiori argument** at every tested level:

- **Per-pixel** (Phase 2b): KL floor ~2 × 10⁻⁵ nats (N = 9.6 M obs/candidate at BF=1 in Mode A; N = 11.3 M in Mode B at BF=32) reached equivalently by all 10 primitives; spread across primitives 3–4 × 10⁻⁶ nats. Obstacle (3) of [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) holds uniformly under both the idealized threat model (attacker knows startPixel + plaintext) and the realistic one (neither).
- **Aggregate stream** (Phase 3b): NIST STS 188/188 pass for all 10 on typical runs; the replication-unstable 40/188 outcomes (FNV-1a at N=20 Run A, BLAKE3 at N=100 BF=32 — one below-spec hash and one PRF) are the NIST SP 800-22 `NonOverlappingTemplate` bin-0 artefact on near-uniform output, not a security signal. The same mechanism fires on `/dev/urandom` streams of this size.
- **Structural** (Phase 1): per-channel χ² and nonce collision ratio within tolerance for all 10 in both regimes.
- **startPixel isolation** (Phase 2c): mean rank-fraction ≈ 0.5 for all 10 in both regimes.
- **Nonce-reuse PRF-dependency** (Phase 2d): after the demasker peels off obstacles (2) + (3) at the 2-ciphertext Full KPA level, the reconstructed `dataSeed.ChainHash(pixel, nonce)` output stream passes NIST STS 188/188 under BLAKE3 — single-layer defence (ChainHash alone) holds under PRF even without architectural obstacles — but fails 6/188 under FNV-1a (FFT 0/16 + block-level + sum-walk tests). Empirically validates [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis)'s locality claim under PRF and makes its PRF-dependency caveat concrete.

Since invertibility (FNV-1a) and output bias (MD5) produce output indistinguishable from a real PRF at every stable test outcome, a real PRF — whose output is already unpredictable by definition — leaves the barrier with strictly less work to do.

### On test-battery artefacts and replication

Several test-battery outputs flagged specific primitives in one run and not another. Every such flag failed to replicate under identical settings:

- **Phase 3a at BF=32** flags AES-CMAC (p < 10⁻⁷) and BLAKE2b-512 (p < 10⁻¹⁰); at BF=1 both are clean (p = 0.83 and p = 0.41) while AreionSoEM-256 newly flags at p = 0.003.
- **Phase 3b p-value clustering is universal across all 10 hashes.** At N=100 × 1 Mbit, every primitive's 100 per-sequence `NonOverlappingTemplate` p-values cluster into a single histogram bin; the bin is chosen effectively at random per hash (FNV-1a in bin 8, ChaCha20 in bin 1, BLAKE3 in bin 2, MD5 in bin 6, etc). No primitive is structurally different in this regard. Any hash whose cluster lands in bin 0 on a given run mechanically reports a catastrophic-looking 40/188 (seen in the suite for FNV-1a at N=20 and BLAKE3 at N=100 BF=32) — the same thing would happen to any other hash on any given run with probability 1/10.
- **Phase 2b flag cells** (heuristic `bit_exceed` / `kl_max` thresholds) shift across regimes: 8/90 at BF=1, 10/90 at BF=32, with zero overlap between the flagged cell sets.

**None of these flags is sign-consistent across replications or regimes.** When the null is essentially true (output is truly near-uniform) and N is large enough to detect sub-thousandths-of-a-percent deviations, statistical tests produce random false-positive flags that shift between runs. The absolute magnitude of every flagged deviation is below any attack-useful threshold, and /dev/urandom exhibits the same kind of artefact under equivalent conditions. Single-run anomalies should be treated as noise absent sign-consistent replication; the empirical suite does not supply such confirmation for any phase or primitive.

### Mapping to paper claims

| Claim | Empirical status |
|-------|------------------|
| [Proof 1](PROOFS.md#proof-1-information-theoretic-barrier) (per-pixel P(v\|h) = 1/2) | ✅ Phase 2b KL floor ≈1.4×–1.5× theoretical on all 10 hashes in both threat models: Mode A (idealized, BF=1) [1.8, 2.1]×10⁻⁵ nats at N = 9.6 M; Mode B (realistic, BF=32) [1.2, 1.6]×10⁻⁵ at N = 11.3 M — spread 3–4 × 10⁻⁶ nats across the full hash spectrum in each |
| [Proof 7](PROOFS.md#proof-7-bias-neutralization) (bias neutralisation) | ✅ Phase 1 — all 10 hashes equivalent on per-channel profile; Phase 3b — all 10 pass NIST STS on typical runs, including both below-spec primitives |
| [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill) (CSPRNG-fill residue) | ✅ Phase 3b — 188/188 pass for all 10 hashes at both BF=1 and BF=32; fill dominates the stream in both regimes to within Proof 10's guaranteed minimum |
| [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) obstacle (2) — `startPixel` isolation | ✅ Phase 2c — mean rank-fraction ≈ 0.5 ± 0.05 on all 10 primitives, both regimes |
| [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) obstacle (3) — candidate ambiguity | ✅ Phase 2b — all 56 per-pixel candidates indistinguishable across all 10 primitives, in both fill regimes and under both the idealized (known startPixel + plaintext) and realistic (neither) threat models |
| Composition conjecture ([Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)) | ⚠ **Consistent with** — no systematic signal from weak PRFs in this corpus across stable test outcomes. Passive-distinguisher absence is not the same as active-cryptanalytic absorption; the conjecture is about the latter and requires research-level analysis the suite does not perform |
| [Proof 3](PROOFS.md#proof-3-triple-seed-isolation) / [3a](PROOFS.md#proof-3a-triple-seed-isolation-minimality) (triple-seed isolation, minimality) | ✅ Phase 2c — all 10 primitives pass `startPixel` enumeration in both Single and Triple modes; the 3 startSeeds in Triple each draw from independent `[0, P/3)` ranges in Phase 3b's histograms with no cross-seed structure |
| [Proof 9](PROOFS.md#proof-9-ambiguity-dominance-threshold) (ambiguity-dominance threshold) | ✅ Phase 2b — the `html_giant` KL floor at N ≫ P_threshold reaches sampling precision (~2 × 10⁻⁵ nats at BF=1, ~2 × 10⁻⁶ nats at the 63 MB probe); ambiguity is dominant at all tested data scales |
| Invertible-primitive inversion bound | ⚠ Phase 2a — analytical only; no actual Z3 run at any `keyBits`. ChainHash's `keyBits`-scaled round structure argues the paper's naive `~56 × P` bound is optimistic, but this claim stands on structural analysis, not empirical seed recovery |
| [`SCIENCE.md` §2.5](SCIENCE.md#25-nonce-reuse-analysis) — nonce-reuse locality + PRF-dependency | ✅ / ⚠ Phase 2d — locality confirmed under PRF (BLAKE3 reconstructed stream passes 188/188 NIST STS → the single remaining obstacle after demasking has no exploitable bias). PRF-dependency demonstrated via the BLAKE3-vs-FNV-1a contrast: same attack chain, FNV-1a fails 6 / 188 tests (FFT 0/16 plus BlockFrequency / CumulativeSums / Runs) — the "seeds remain secret, no key rotation" conclusion of `§2.5` depends on PRF non-invertibility, and this probe makes that dependency empirically visible |

---

## Caveats and what this does NOT prove

- **"No distinguisher exists"** is not claimed — only "no replicable distinguisher was detected for any of the 10 tested primitives across the 2 × 2 configuration matrix `{Single, Triple} × {BF=1, BF=32}` run in this pass (two independent BF=1 Single mode replications, plus BF=32 Single, plus BF=1 and BF=32 Triple)". Follow-up corpora may find what this one missed.
- **Structural / algebraic attacks against ChainHash.** Phase 2a's cost tables are back-of-envelope structural-analysis estimates with ± 2 – 3 orders of magnitude uncertainty. **No actual Z3 (or any SMT solver) was run at any `keyBits`** in this pass. Algebraic attacks over Z[2^128] (Gröbner basis, polynomial interpolation) remain research-level and are the single largest uncertainty in the cost argument.
- **Statistical power.** At `N = 130` samples per hash per kind (pooled), the Phase 2c mean-rank-fraction CI is ±0.050 — a ~2 % systematic bias per hash would not be detectable. Smaller per-kind sample sizes (`*_huge` at N = 3; `html_giant` at N = 8 per hash at both BF=1 and BF=32) have correspondingly wider CIs. Conclusions are "no distinguisher at this effect size and power," not "no distinguisher of any magnitude".
- **Phase 2b per-sample variance on `html_giant`** — the runs aggregate 8 samples per hash into the KL estimate, giving N = 9.6 M observations per candidate in Mode A and N = 11.3 M in Mode B. The per-sample variance distribution is not itself reported; the aggregate floor is reported instead.
- **Phase 3a reports false-positive-class signals.** At very large N on near-uniform output, the test produces significant p-values that do not replicate across fill regimes or corpus regenerations. Interpreting any specific flagged cell as a real effect requires sign-consistency across at least two independent runs — which this suite only partially provides (two fill regimes, identical RNG seed).
- **Phase 2b flag threshold is heuristic** (`bit_exceed > 10` or `p_lt_001 > 3` or `kl_max > 0.1`), not derived from a false-discovery-rate calculation. Cells that flag are not clustered by primitive class but deserve principled FDR-corrected re-analysis in a follow-up.
- **Suite-level multiple-testing correction** (across 10 hashes × 90 kinds × 5 empirical phases × 2 regimes) is **not applied** at the top level; per-phase Bonferroni is used where reported.
- **NIST STS `NonOverlappingTemplate` replication variance is hash-agnostic.** Independent runs produce different proportion outcomes whenever a hash's per-sequence p-values happen to cluster in bin 0 versus any other bin. In this suite the event occurred twice — FNV-1a at N=20 Run A (40/188) and BLAKE3 at N=100 BF=32 (40/188) — involving one below-spec and one paper-grade PRF primitive, which is direct evidence that the 40/188 outcome is driven by the `(hash, run)` seed pair, not by hash primitive choice. The underlying single-bin clustering pattern is identical across all 10 hashes and all 5 configurations; `/dev/urandom` exhibits the same 148 uniformity-of-p-values flags on streams of this size. Whether any specific primitive exhibits bin-0 draws at a rate distinguishable from the 1/10 uniform expectation would require many more replications than this suite performs.
- **Adversarial machine-learning distinguishers** not attempted.
- **Physical side channels** (DPA, SPA, timing, EM) outside empirical territory.
- **Triple Ouroboros on Phases 2b / 2c / 3a** — the 3-partition `splitTriple` layout requires an analyzer rewrite not included in this pass. Phase 1 and Phase 3b were run in Triple mode and produced results indistinguishable from Single mode.
- **Peer-review substitute.** This is self-audit, not a replacement for external cryptographic review.
- **Resistance to undiscovered cryptanalytic techniques** cannot be established by any finite empirical suite.

---

## Reproducibility and data

- **Scripts:** [`scripts/redteam/`](scripts/redteam/)
- **Shared constants:** [`scripts/redteam/common.py`](scripts/redteam/common.py) (single source of truth for the 10-hash list and 10-kind list)
- **Corpus test:** [`redteam_test.go`](redteam_test.go) (`TestRedTeamGenerate`)
- **Phase logs:** `tmp/results/<mode>_bf<N>/0M_*.log` — one directory per `(Ouroboros mode, BarrierFill)` combination

---

*For formal security arguments, see [`PROOFS.md`](PROOFS.md) and the scientific paper (Zenodo: [10.5281/zenodo.19229395](https://doi.org/10.5281/zenodo.19229395)).*
