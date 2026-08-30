# ITB Security Reference

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

**Companion document to [SCIENCE.md](SCIENCE.md).** This file is the audit-oriented operational reference — composition modes matrix, cross-scheme comparisons, deployment threat model, design-rationale tables, compliance framing, and the explicit non-closed threats list. The formal construction and proofs live in [SCIENCE.md](SCIENCE.md) and [PROOFS.md](PROOFS.md); the accessible-explanation narrative lives in [ITB.md](ITB.md). Sections cross-referenced below point to the authoritative source for each topic.

## Security Policy

**Supported versions.** Active development tracks `main`. Security fixes land on `main` first; older tags receive backports only when the maintainer judges the fix worth backporting (rare given the pre-release status).

| Version | Supported |
|---|---|
| `main` (HEAD) | ✓ |
| earlier tagged releases | — |

**Reporting a vulnerability.** Private reports preferred via [GitHub Security Advisories](https://github.com/everanium/itb/security/advisories/new). Discord channel for coordination: [discord.gg/wRYF8shHpd](https://discord.gg/wRYF8shHpd). Email contact is intentionally not published — Discord and Security Advisories cover both informal triage and formal disclosure.

**Triage and response.** Best-effort triage within 14 days. Pre-release status means no SLA or commercial support is implied. Responses are individually authored, not template-driven.

**Coordinated disclosure.** Findings against the construction — cryptanalytic attacks, theoretical weaknesses, implementational flaws — are most welcome and prepared for academic publication. A 90-day coordinated disclosure window is the default; faster public disclosure may be appropriate when a fix lands quickly or the finding is already public via parallel discovery. The ITB construction was published to invite scrutiny, not to claim closed-form security — cryptanalytic findings under the author's own attribution are explicitly encouraged.

**Out of scope.** Hardware-level attacks (DPA/SPA, Spectre, Meltdown, Rowhammer, cache timing, fault injection), supply-chain attacks against dependencies, attacks against the host OS / language runtime / hardware platform itself. See the Disclaimer above.

## 1. ITB Composition Modes

| Property | Core ITB (no MAC) | MAC + Silent Drop‡‡ | MAC + Reveal |
|---|---|---|---|
| Integrity | ✗ | ✓ | ✓ |
| Deniability | ✓ Full (structural) | ✓ Full | ✓ Full (full-capacity MAC) |
| CCA oracle | No oracle exists | No oracle (silent) | Noise position only (noiseSeed) |
| noiseSeed config | ✓ Barrier intact | ✓ Barrier intact | ✗ Leaked via CCA |
| dataSeed config (per-snake) | ✓ Barrier intact | ✓ Barrier intact | ✓ **Independent** (zero CCA leak) |
| lockSeed config | ✓ Barrier intact | ✓ Barrier intact | ✓ **Independent** (zero CCA leak) |
| startSeed config (per-snake) | ✓ Barrier intact | ✓ Barrier intact | ✓ **Independent** (zero CCA leak) |
| Data rotation + XOR | ✓ | ✓ | ✓ (rotation barrier) |
| Interlocked Barrier — Part 1 (per-chunk permutation, non-disableable) | ✓ Intact | ✓ Intact | ✓ Intact (lockSeed independent of noiseSeed) |
| Interlocked Barrier — Part 2 (per-pixel absorption, non-disableable)† | ✓ Intact | ✓ Intact | Partial — noise position leaked; rotation + XOR + CSPRNG residue intact via dataSeed |
| Brute-force impact of leak | — | — | noiseSeed eliminated¶: P × 2^(2×keyBits) → P × 2^keyBits |

† Software-level property under the random-container model; no guarantees against hardware-level attacks (see Disclaimer). The information-theoretic barrier under passive observation applies to Part 2 (per-pixel absorption, `P(v | h) = 1/2` from [Proof 1](PROOFS.md#proof-1-information-theoretic-barrier)); Part 1's per-chunk mask permutation is a PRF-conditional layer keyed by the lockSeed ([Proof 11](PROOFS.md#proof-11-48-bit-interlocked-barrier-mask-space)), and the two parts always run together as the shipped indivisible barrier composition (see [SCIENCE.md § 1.5 Interlocked Barrier](SCIENCE.md#15-the-48-bit-interlocked-barrier)).

¶ CCA eliminates noise bits (12.5 %), but CSPRNG fill bytes remain encrypted in data bit positions by dataSeed — indistinguishable from plaintext ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

‡‡ MAC + Silent Drop assumes the attacker is unaware of MAC presence. If the attacker knows MAC is inside (e.g., insider knowledge), the encrypted MAC tag serves as a local verification oracle during brute-force — the attacker decrypts with candidate keys, computes MAC(payload), and checks against the embedded tag without requiring recipient response. Search cost remains P × 2^(2·keyBits) (same as Core ITB — no CCA, noiseSeed not leaked, both seeds must be searched jointly), but the attacker can now verify candidates. Without insider knowledge: no verification → plausible deniability. Grover: √P × 2^keyBits.

For the underlying PRF requirements, 8-seed isolation proof, and multi-factor KPA argument, see [SCIENCE.md § 1.1 ChainHash](SCIENCE.md#11-chainhash), [§ 2.3 8-Seed Isolation](SCIENCE.md#23-8-seed-isolation-theorems-3-3a), [§ 2.6 Multi-Factor Full KPA Resistance](SCIENCE.md#26-multi-factor-full-kpa-resistance-theorem-4a). For cross-cipher key-size and primitive-requirement comparisons and the AEAD comparison matrix, see [SCIENCE.md § 4 Comparison with Existing Ciphers](SCIENCE.md#4-comparison-with-existing-ciphers). For the byte-splitting property analysis, see [SCIENCE.md § 2.10 Byte-Splitting Property](SCIENCE.md#210-byte-splitting-property).

## 2. CCA Oracle Leak Comparison

| Scheme | CCA Leak (MAC result revealed) |
|---|---|
| AES-CBC + MAC-then-Encrypt‡ | Padding oracle → full plaintext (POODLE, Lucky13) |
| AES-CTR + MAC-then-Encrypt | Bit-flip oracle → data structure |
| ITB + MAC-Inside (full capacity) | Noise position only (3 bits / pixel, no data); CSPRNG fill persists in data positions ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)) |
| AES-GCM (AEAD) | None (MAC rejects before decryption) |
| ChaCha20-Poly1305 (AEAD) | None (MAC rejects before decryption) |

‡ Deprecated construction (TLS 1.0 / 1.1, RFC 8996). Included for historical context only.

For the CCA leak upper bound proof and ITB's noise-position-only bound, see [SCIENCE.md § 2.8 CCA Leak Upper Bound](SCIENCE.md#28-cca-leak-upper-bound-theorem-6) and [Proof 6](PROOFS.md#proof-6-cca-leak-upper-bound).

## 3. Attack Resistance Summary

The always-on Interlocked Barrier ([SCIENCE.md § 1.5](SCIENCE.md#15-the-48-bit-interlocked-barrier)) is a per-chunk 48-bit PRF-keyed permutation drawn from a ≈ 2^70.20 mask space. It applies uniformly across every column in the table below; the barrier's contribution to the KPA / Crib KPA / CPA columns is architectural and PRF-conditional, and stacks on top of the pixel-level obstacles listed per cell.

| Attack | Core ITB | MAC + Silent Drop‡‡ | MAC + Reveal | MAC + Reveal + KPA |
|---|---|---|---|---|
| Ciphertext-only (COA) | ✓ IT barrier† | ✓ IT barrier† | ✓ IT barrier† | ✓ IT barrier† |
| Known-plaintext (KPA) | ✓ 4-factor under PRF (PRF non-invertibility + Interlocked Barrier per-chunk ≈ 2^70.20 + 7-rotation × 8-noisePos + startPixel); byte-split adds 5th factor under Partial KPA† | ✓ 4-factor (same as Core)† | ✓ 4-factor under PRF (PRF + Interlocked Barrier per-chunk ≈ 2^70.20 + rotation 7^P + startPixel); byte-split adds 5th factor under Partial KPA (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)) | ✓ 4-factor under PRF (PRF + Interlocked Barrier per-chunk ≈ 2^70.20 + rotation 7^P + startPixel); byte-split adds 5th factor under Partial KPA\* (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)) |
| Chosen-plaintext (CPA) | ✓ Independent maps + fresh per-message barrier draws | ✓ Independent maps + fresh per-message barrier draws | ✓ Independent maps + fresh per-message barrier draws | ✓ Independent maps + fresh per-message barrier draws |
| Chosen-ciphertext (CCA) | ✓ No oracle | ✓ No oracle | noiseSeed leaked; dataSeed / lockSeed / startSeed safe§§ | noiseSeed leaked; dataSeed / lockSeed / startSeed safe§§ |
| Brute-force (classical) | P × 2^(2·keyBits)††† | P × 2^(2·keyBits)††† | P × 2^keyBits\*\* | P × 2^keyBits\*\* |
| Brute-force (Grover) | √P × 2^keyBits††† | √P × 2^keyBits††† | √P × 2^(keyBits/2)\*\* | √P × 2^(keyBits/2)\*\* |
| Map guessing | 2^(62P) | 2^(62P) | 2^(59P) | 2^(59P) |
| Nonce reuse | Lab-only (not reachable via shipped API); Part 1 lane-scrambles the XOR††; empirical plaintext recovery null | Lab-only; Part 1 lane-scrambles†† → null recovery | Lab-only; Part 1 lane-scrambles†† → null recovery | Lab-only; Part 1 lane-scrambles†† → null recovery |
| Bit-flipping | Undetected | Detected (MAC) | Detected (MAC) | Detected (MAC) |
| Padding oracle | N/A (no padding) | N/A (no padding) | N/A (no padding) | N/A (no padding) |
| Quantum structural (Simon, BHT) | Conjectured mitigated | Conjectured mitigated | Conjectured mitigated | Conjectured mitigated |

† IT barrier is a software-level property under the random-container model; no guarantees against hardware-level attacks (see Disclaimer).

\* Per-bit XOR hides XOR masks under passive observation; with an invertible primitive, naive pixel-level inversion would attempt seed recovery, but the always-on Interlocked Barrier's Part 1 permutation forecloses the SAT anchor at instance-formulation (see [REDTEAM.md § FNV-1a lo-lane SAT](REDTEAM.md#fnv-1a-lo-lane-sat--architecturally-foreclosed)).

\*\* MAC + Reveal: CCA reveals noisePos but not startPixel (startPixel determined by independent startSeed + nonce, not transmitted). startPixel enumerated as [0, P). Total: P × 2^keyBits classical, √P × 2^(keyBits/2) Grover. At 1024-bit keys under the unified `MinPixels` floor (P = 400): classical ~2^1033, Grover ~2^516. With invertible primitive under KPA: the always-on Interlocked Barrier's per-chunk mask permutation (Part 1, keyed by lockSeed independent of noiseSeed) forecloses the SAT anchor even under the maximum-peek attacker regime — Bitwuzla returns UNSAT on the naive-crib anchor with FNV-1a on every seed role (see [REDTEAM.md § FNV-1a lo-lane SAT](REDTEAM.md#fnv-1a-lo-lane-sat--architecturally-foreclosed)). Full multi-factor obstacle enumeration in [SCIENCE.md § 2.6](SCIENCE.md#26-multi-factor-full-kpa-resistance-theorem-4a).

††† Core ITB and MAC + Silent Drop (no oracle): attacker must jointly search noiseSeed and dataSeed — without dataSeed, noiseSeed output is indistinguishable from random, so independent attack on noiseSeed is impossible. Joint search space: 2^(2·keyBits). startSeed contributes only P (startPixel candidates, enumerated as [0, P)), not 2^keyBits. Total: P × 2^(2·keyBits). Grover: √P × 2^keyBits. At 1024-bit keys under the unified `MinPixels` floor (P = 400): classical ~2^2057, Grover ~2^1028.

§§ CCA removes noise bits (12.5 % of container), but CSPRNG fill bytes encrypted by dataSeed persist in data bit positions, indistinguishable from plaintext. The information-theoretic barrier is reduced, not fully eliminated ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

**Nonce reuse is local.** The shipped wire carries two independent nonces (`main_nonce` and `interlock_nonce`) drawn per encrypt from crypto/rand and enforced pairwise-distinct at the API, so caller-side reuse is not reachable through the shipped surface. Under a lab-forced dual-slot / main-only / interlock-only collision, plaintext recovery is null under every attacker-realistic probe at the tested sample sizes (see [REDTEAM.md § Nonce reuse](REDTEAM.md#nonce-reuse-lab-only)): the barrier's per-chunk PRF-keyed 48-bit mask permutation removes the demask anchor even under the maximum-leverage dual-slot collision (modifier †† below). Seeds remain secret (PRF non-invertibility blocks ChainHash inversion), so future messages with fresh nonces are unaffected — **no key rotation required**. A single nonce collision provides too few observations for Simon, BHT, or quantum structural algebraic attacks. Unlike AES-GCM where nonce reuse leaks the GHASH key H and enables forgery until key rotation (global catastrophe affecting all subsequent messages), ITB nonce collision is **strictly local** — ITB is nonce-misuse-resistant under the PRF assumption. For the usage-precondition framing and the demasking disclaimer, see [ITB.md § 9 Nonce Reuse](ITB.md#9-nonce-reuse-a-usage-precondition-not-an-absorbed-threat).

†† Interlocked Barrier modifier. The always-on Interlocked Barrier removes the demask entry point on the colliding messages: the per-chunk PRF-keyed 48-bit mask triple is applied before COBS, so the two-time-pad XOR yields lane-compressed bits `l₀(P₁) ‖ l₁(P₁) ‖ l₂(P₁) ⊕ l₀(P₂) ‖ l₁(P₂) ‖ l₂(P₂)` interpretable only with `lockSeed` and PRF-opaque under the PRF assumption. Empirically, plaintext recovery is null under every attacker-realistic dual-slot / main-only / interlock-only collision probe at the tested sample sizes (see [REDTEAM.md § Nonce reuse](REDTEAM.md#nonce-reuse-lab-only)). See [SCIENCE.md § 1.5](SCIENCE.md#15-the-48-bit-interlocked-barrier) and [§ 2.15](SCIENCE.md#215-48-bit-interlocked-barrier-mask-space-theorem-11) for the full barrier construction.

## 4. Information-Theoretic Barrier Metrics

### Container Bit Accounting (per pixel)

| Metric | Bits | Percentage |
|---|---|---|
| Total container bits | 64 | 100 % |
| Data bits | 56 | 87.5 % |
| Noise bits | 8 | 12.5 % |

### Configuration Bit Accounting (per pixel: noiseSeed + dataSeed)

| Source | Config bits | CCA leak | Protected |
|---|---|---|---|
| noiseSeed (noise position) | 3 | 3 (100 % of noiseSeed)§ | 0 |
| dataSeed (rotation + XOR) | 59 | **0** (independent seed) | **59 (100 %)** |
| **Total** | **62** | **3 (4.8 %)** | **59 (95.2 %)** |

§ CCA reveals noise bit positions, but does not eliminate all ambiguity: CSPRNG fill bytes in data positions remain encrypted by dataSeed, indistinguishable from plaintext ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

### Barrier Strength (1024-bit key)

Every entry point applies the CCA-resistant `MinPixels` floor uniformly, so the auth-side envelope covers Core ITB, MAC + Silent Drop, and MAC + Reveal — one row per metric, no plain-vs-auth split.

| Metric | Value |
|---|---|
| MinPixels | 365 → 400 (20 × 20) |
| Noise barrier | 2^3200 |
| Landauer bound (blind enumeration) | ~2^306 |
| Blind-enumeration exponent vs Landauer | 10.5× (3200 / 306) |
| Config map space | 2^24800 |
| Key space | 2^1024 |
| Mask-space cardinality per chunk (Interlocked Barrier) | ≈ 2^70.20 |
| PRF-preimage count per mask triple | ≈ 2^57.80 |

The Landauer row bounds the cost of blind enumeration of the noise-barrier space; it does not bound structural attacks that do not enumerate.

Under CCA (MAC + Reveal) the noise positions are revealed but CSPRNG fill in data positions persists as residual ambiguity ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)); the noise-barrier headline is stated at the unified `MinPixels` floor. For the noise-barrier bound derivation, see [Proof 5](PROOFS.md#proof-5-noise-barrier-bound); for the per-chunk mask-space derivation, see [Proof 11](PROOFS.md#proof-11-48-bit-interlocked-barrier-mask-space).

### Practical Value of 4.8 % CCA Leak

| Information | Gained by attacker? |
|---|---|
| Plaintext bits | Zero |
| XOR mask bits | Zero |
| Start pixel | Unknown |
| Interlocked Barrier — Part 1 (per-chunk 48-bit mask permutation) | Zero — lockSeed independent of noiseSeed; per-chunk mask triple stays PRF-opaque (drawn from ≈ 2^70.20 balanced partitions per chunk keyed by lockSeed + interlock_nonce, unobservable without lockSeed) |
| Key-space reduction | noiseSeed eliminated: P × 2^(2·keyBits) → P × 2^keyBits |
| Brute-force speedup | Search space halved in exponent (two seeds → one seed); the barrier's per-chunk mask enumeration (≈ 2^70.20 masks per chunk) stacks on top |
| Grover reduction | √P × 2^keyBits → √P × 2^(keyBits/2) (noiseSeed eliminated from search); the barrier's per-chunk mask enumeration is not amenable to Grover (no observable anchor to search against) |
| CSPRNG residue after CCA | Persists: fill bytes in data positions encrypted by dataSeed ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)) |

## 5. Noise-Density Optimality (Why 8/1)

| Format | Data / px | Noise / px | Overhead | CCA Config Leak | Barrier (1024-bit, unified P) |
|---|---|---|---|---|---|
| 8/1 (ITB) | 56 | 8 | 1.14× | 4.8 % | 2^3200 |
| 6/2 | 48 | 16 | 1.33× | 8.9 % | 2^3136 |
| 5/3 | 40 | 24 | 1.60× | 12.2 % | 2^5400 |
| 4/4 | 32 | 32 | 2.00× | 17.1 % | 2^8192 |

8/1 is Pareto-optimal among the analyzed noise-density configurations. The Barrier column for 8/1 is stated at the unified `MinPixels = 400` floor from §4; the other rows carry each format's own `data_bits × MinPixels(format)` for the illustrative comparison. All noise-barrier exponents place blind enumeration above the Landauer bound; that scopes to enumeration cost, not to structural attack resistance.

## 6. MAC Placement Design Space

| MAC Placement | Covers Noise | Deniability | CCA Leak | Circular Dependency |
|---|---|---|---|---|
| Inside (full capacity) | No | ✓ Preserved | Noise position only | None |
| Inside (plaintext only) | No | ✓ Preserved | Noise pos + spatial | None |
| Outside (header) | Yes | ✗ Broken | None | Verification oracle |
| Inside (full container) | N/A | N/A | N/A | Tag invalidates itself |

Implemented: Inside (full capacity) — every shipped MAC-authenticated Low-Level entry point (`EncryptAuth3x{128,256,512}Cfg`) and every `triple.Pipeline` profile that enables MAC. Other placements are theoretical alternatives, not implemented. For the composition analysis, see [SCIENCE.md § 2.13 MAC-Inside-Encrypt Composition](SCIENCE.md#213-mac-inside-encrypt-composition).

## 7. Known Theoretical Threats

| Threat | Exploit requires | Practical risk | Mitigation |
|---|---|---|---|
| Interlock combinadic unrank index-select timing (DPA/SPA class) | Oscilloscope on CPU die, > 10 GHz, lab access | Same class as DPA on any cipher | Constant-time VPERMT2Q / VPERMD select over precomputed C(p, k) table, no software side-channel |
| rotateBits7 shift timing (DPA/SPA class) | Oscilloscope on CPU die, > 10 GHz, lab access | Same class as DPA on any cipher | Register-only, no software side-channel |
| Container size metadata | Network observation | Metadata only | Inherent to all ciphers, no crypto advantage |
| Non-CSPRNG container | Deployer misconfiguration | Degrades barrier | crypto/rand mandatory, non-CSPRNG unsupported |
| COBS decode truncation | Wrong seed / tampered data | None | Core ITB: returns raw decoded bytes (plausible deniability, no oracle); Authenticated: MAC rejects before COBS decode |
| Bit-flip false null (DoS) | Data bit modification | None (with MAC) | MAC verified before null search; noise flips do not affect decrypted data |
| CGO AVX2 side-channel | Co-located attacker | None (see below) | All AVX2 ops constant-time; identical to Pure Go |
| Spectre v1 / v2 / v4, Downfall, etc. | Secret-dependent memory access gadget | No known gadget in ITB data path | Register-only ops; no `table[secret_index]` |
| MDS, Zenbleed (stale data) | CPU buffer residue | Seeds may remain in buffers | Not ITB-specific; identical for all ciphers |
| Rowhammer, RAMBleed | DRAM bit flips / reads | Memory corruption / leakage | Not ITB-specific; ECC memory recommended |
| Heap memory exposure | Memory dump, debugger, Meltdown | Seeds, cached hash keys in heap | Not ITB-specific; secureWipe on intermediate buffers |

For detailed per-CVE analysis of 20+ hardware attacks (Spectre variants, Downfall, Hertzbleed, MDS, Zenbleed, Rowhammer), see [HWTHREATS.md](HWTHREATS.md).

### CGO Backend Side-Channel Equivalence

The optional C pixel processing backend (`CGO_ENABLED=1`, GCC `-O3 -mavx2`) was verified for side-channel equivalence with the Pure Go backend:

| Concern | Status | Detail |
|---|---|---|
| AVX2 / AVX-512 / GFNI / VBMI / AES-NI / BMI2 instruction timing | **Constant-time** | `vpxor`, `vpand`, `vpor`, `vpsrlq`, `vpsllvw`, `vpsrlvw`, `vpermb`, `vpmultishiftqb`, `vgf2p8affineqb`, `vpternlogq`, `vpshufb`, `vpermd`, `aesenc`, `vaesenc`, `pextq`, `pdepq` — fixed latency on supporting Intel / AMD microarchitectures across the five shipped pixel tiers (Tier A: AVX-512F+BW+VL+GFNI+VBMI on Ice Lake+ / Zen 4+; Tier A′: AVX-512F+BW+VL on Skylake-X+ / Cascade Lake+ / Rocket Lake+ / Zen 4+; Tier B: AVX2+GFNI; Tier B′: AVX2-only on Haswell+ / Zen 1+; Tier C: portable scalar C) and the ChainHash / interlock kernel tiers (AVX-512F ZMM, AVX2 YMM, XMM AES-NI, scalar Go). See [HWTHREATS.md § Category 5](HWTHREATS.md#category-5-instruction-set-side-channel-profile) for the per-instruction inventory |
| `dataHash % 7` | **Constant-time** | GCC optimizes to `imulq` multiply-by-reciprocal, no `div` instruction |
| `% totalPixels` (pixel wrap) | Variable-time `idivl` | Not secret: totalPixels = W × H from public header |
| Container access pattern | Same as Pure Go | `container[pixelOffset]` — startPixel cache pattern unchanged |
| Hash array access | Sequential | No data-dependent indexing |
| Spectre | Not applicable | No secret-dependent array indexing |
| L1 micro-batching | **Improves** cache resistance | 8 KB batches harder to observe via Flush+Reload than full arrays |

The analysis applies equally to ARM64 NEON auto-vectorization: `veor`, `vand`, `vorr`, `vshl`, `vshr` are constant-time on ARM. ARM `sdiv` (for `% totalPixels`) is variable-time but operates on public data only. ARM has no frequency throttling from NEON (unlike Intel AVX-512).

Both backends produce identical ciphertext. Switching between `CGO_ENABLED=0` (Pure Go pixel kernel; Go-assembly hash ASM stays engaged) and `CGO_ENABLED=1` (C + SIMD pixel kernel) does not change the security model on any platform.

## 8. Hash Function Compliance

Every shipped registry primitive is a PRF-grade construction that satisfies the requirements catalogued in [SCIENCE.md § 1.1 ChainHash](SCIENCE.md#11-chainhash) and [§ 2.6 Multi-Factor Full KPA Resistance](SCIENCE.md#26-multi-factor-full-kpa-resistance-theorem-4a). Tests and benchmarks cover every registry entry across the 128 / 256 / 512-bit widths shipped by the ChainHash surface; the concrete registry list is authoritative in `hashes/registry.go`. For per-primitive technical notes (Areion-SoEM proofs, BLAKE / ChaCha20 kernels, AES-CMAC construction, SipHash keying), see the `hashes/CONSTRUCTIONS.md` reference.

For key-size and primitive-requirement comparisons vs AES / ChaCha20 / Threefish, see [SCIENCE.md § 4 Comparison with Existing Ciphers](SCIENCE.md#4-comparison-with-existing-ciphers). For the effective key-size table by hash width (128 / 256 / 512), see [SCIENCE.md § 6 Implementation](SCIENCE.md#6-implementation) and [ITB.md § 4 8-Seed Isolation](ITB.md#4-8-seed-isolation).

## 9. Threat models NOT closed by the barrier

Framed as «outside the barrier's threat model» where that is the honest description, and as «conditional» where the barrier's closure depends on a precondition. None of these is a claim that the barrier is weak — they are the boundary of what the barrier addresses. The full cryptographer verdict enumerating these classes appears in the pre-flight review; the summary sentence from that verdict is preserved here verbatim:

> Closure of the KPA / CPA families is conditional on a secure PRF and fresh nonces; total inversion or a reused nonce is outside what the barrier closes.

- **Total or systematic PRF inversion.** The barrier is explicitly PRF-conditional. Total inversion of the configured primitive lets the attacker resolve the per-chunk masks, the startPixels, and the seed components algorithmically, collapsing every architectural obstacle. Systematic partial PRF inversion is raised in cost but not eliminated. Outside the barrier's power to close.
- **Nonce reuse.** Closure of the CPA / KPA families is conditional on fresh per-message nonces on both header slots — the main nonce that feeds the per-pixel and per-snake derivations and the independent interlock nonce that feeds the barrier's per-chunk mask draws. Under joint collision of both, the barrier's per-chunk masks repeat; the shipped API generates each of the two nonces internally per call, which prevents caller-side reuse, but that is an API-discipline property, not a construction-level guarantee. Simultaneous collision on both slots requires a CSPRNG hardware fault. Empirically the lab-forced dual-slot collision recovers zero plaintext bytes at the tested sample sizes (see [REDTEAM.md § Nonce reuse](REDTEAM.md#nonce-reuse-lab-only)) — the structural closure argument is conditional; the empirical outcome is null.
- **Upstream key-management / related-seed supply.** The 8-seed API draws independent CSPRNG components and rejects both pointer and byte-level `Components` collisions, so related-seed differentials do not arise through the shipped surface. A defective upstream KDF that supplies correlated seeds is outside the construction's control. Threat-model boundary, not a barrier property.
- **Physical side channels** (timing, power, EM, cache, speculative execution). Out of scope by construction — leakage is a property of the execution environment, not the algorithm. The barrier's own kernels are written to a constant-time discipline (mask-merge only, no secret-dependent branches or memory accesses; the deterministic reduction avoids rejection sampling precisely to stay branch-free), but a deployment-level side-channel evaluation is per-CPU, per-compiler, and orthogonal to the algorithm-level claims. See [HWTHREATS.md](HWTHREATS.md) for the per-instruction inventory.
- **Key-material compromise.** If the seeds or the derived state leak through any channel, confidentiality is lost by definition. The barrier assumes secret seeds.
- **Implementation defects in the shipped Go code.** The architectural argument assumes the code correctly implements the construction. Bugs in the unrank kernels, the reduction, the interleave, or the seed plumbing would be defects the architecture cannot self-correct. The test suite demands byte-level asm ↔ Go parity, directed reduction-boundary vectors at the exact gcd / preimage-cut points, and mask disjointness / popcount assertions rather than roundtrip tests alone.
- **Fault injection.** Active perturbation of the running computation is a hardware-execution threat outside the algorithm's model.
- **CCA via a deployment decryption oracle.** Core ITB and MAC + Silent Drop expose no oracle; MAC + Reveal is an optional deployment mode whose CCA behaviour is per-deployment and bounded by [Proof 6](PROOFS.md#proof-6-cca-leak-upper-bound) (noise position, 3 bits per pixel). Whether an oracle exists at all is a protocol choice, not a barrier property.
- **Quantum key recovery.** The seed-space search under Grover is a hypothetical upper-bound argument, not something the barrier addresses directly; the oracle-degradation framing applies (under Silent Drop there is no verification predicate for Grover to run against). Post-key quantum recovery is outside the barrier's threat model. For the full quantum resistance analysis, see [SCIENCE.md § 3.3 Quantum Resistance](SCIENCE.md#33-quantum-resistance-conjectured).
- **Undiscovered cryptanalysis.** No finite argument, architectural or empirical, establishes resistance to techniques not yet known. The construction has had no external cryptanalysis or formal certification. For the scope and maturity disclaimer, see [SCIENCE.md § 7 Scope and Maturity Disclaimer](SCIENCE.md#scope-and-maturity-disclaimer).
