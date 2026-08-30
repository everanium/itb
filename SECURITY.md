# ITB Security Reference

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Comprehensive security comparison tables for ITB (Information-Theoretic Barrier) across three composition modes: Core (no MAC), MAC + Silent Drop, MAC + Reveal. For detailed proofs and analysis, see [SCIENCE.md](SCIENCE.md).

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

**Cryptographic context.** The deeper construction-level properties — composition modes, attack resistance, barrier metrics, byte-splitting, information-theoretic bounds, the always-on Interlocked Barrier, threat-model boundary — are catalogued in the numbered sections below. Refer there for the substantive cryptographic content; this section governs disclosure process only.

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

† Software-level property under the random-container model; no guarantees against hardware-level attacks (see Disclaimer). The information-theoretic barrier under passive observation applies to Part 2 (per-pixel absorption, `P(v | h) = 1/2` from [Proof 1](PROOFS.md#proof-1-information-theoretic-barrier)); Part 1's per-chunk mask permutation is a PRF-conditional layer keyed by the lockSeed ([Proof 11](PROOFS.md#proof-11-48-bit-interlocked-barrier-mask-space)), and the two parts always run together as the shipped indivisible barrier composition.

¶ CCA eliminates noise bits (12.5%), but CSPRNG fill bytes remain encrypted in data bit positions by dataSeed — indistinguishable from plaintext ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

## 2. Hash Function Requirements

8-seed architecture: `noiseSeed` (noise positions), `lockSeed` (per-chunk Interlocked Barrier permutation, §18), `dataSeed1..3` (per-snake rotation + XOR, zero side-channel), `startSeed1..3` (per-snake pixel offset). Every seed is drawn as an independent CSPRNG component and enforced pairwise-distinct at the API surface by byte-level `Components` comparison in addition to pointer identity.

PRF-grade hash functions are required. PRF property guarantees all necessary sub-properties (input sensitivity, chain survival, non-affine mixing, avalanche, non-invertibility) by definition.

PRF weakness decomposes into three cases. **Total inversion** defeats the construction via algorithmic seed recovery (see [Proof 4a Asymmetry note](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)). **Occasional/sporadic partial inversion** is absorbed by the architecture: recovered candidates are indistinguishable from the false-positive distribution produced by the Interlocked Barrier's per-chunk mask permutation (Part 1, ≈ 2^70.20 masks per chunk), per-snake startPixel isolation, per-pixel 1:1 ambiguity (Part 2), and byte-splitting under Partial KPA. **Systematic partial inversion** is a real non-absorbed threat — the architecture raises the cost but does not eliminate the attack. No such systematic weakness is currently known to reduce the Full KPA work factor below the Theorem 4a bound.

| # | Requirement | Purpose |
|---|---|---|
| — | PRF / PRP / PRG | Required; PRF and barrier are complementary — neither sufficient alone (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)) |
| — | Collision resistance | Absorbed by random container (defense-in-depth) |
| — | Bias / distribution | Absorbed by rotation barrier ([Proof 7](PROOFS.md#proof-7-bias-neutralization), defense-in-depth) |
| — | Population count | Absorbed by random container (defense-in-depth) |
| — | Bit Independence (BIC) | Absorbed by random container (defense-in-depth) |
| — | Sparse/dense key | Absorbed by random container (defense-in-depth) |

## 3. Comparison with Other Ciphers: Key Size

| Cipher | Maximum Key Size | Effective Security |
|---|---|---|
| AES | 256 bits | 256 bits |
| ChaCha20 | 256 bits | 256 bits |
| Twofish | 256 bits | 256 bits |
| Serpent | 256 bits | 256 bits |
| Threefish | 1024 bits | 1024 bits |
| ITB + BLAKE3 | 2048 bits | 2048 bits |

**Note.** 256-bit keys are widely considered sufficient for all foreseeable classical and quantum threats. Larger key sizes provide defense-in-depth margin.

## 4. Comparison with Other Ciphers: Primitive Requirements

| Cipher | Minimum Primitive Requirement |
|---|---|
| AES-CTR | PRP (strong) |
| ChaCha20 | PRF |
| Salsa20 | PRF |
| ITB | PRF |

## 5. Authenticated Encryption Comparison

| Property | MtE (TLS 1.0) | OTR | Signal | AEAD (GCM) | ITB |
|---|---|---|---|---|---|
| Tag encrypted inside | ✓ | ✗ | ✗ | ✗ | ✓ |
| MAC covers fill | ✗ | ✗ | ✗ | ✗ | ✓ |
| Interlocked Barrier — Part 1 (per-chunk permutation) | ✗ | ✗ | ✗ | ✗ | ✓ |
| Interlocked Barrier — Part 2 (per-pixel absorption)† | ✗ | ✗ | ✗ | ✗ | ✓ |
| 8-seed isolation (per-chunk / per-pixel / per-snake) | ✗ | ✗ | ✗ | ✗ | ✓ |
| Oracle-free deniability | ✗ | Partial | Partial | ✗ | ✓ |
| CCA spatial pattern eliminated | ✗ | — | — | ✓ | ✓ |
| Nonce reuse behaviour | Confidentiality lost on colliding messages | — | — | Catastrophic — GHASH key H leaked, permanent forgery until key rotation | Plaintext recovery null under lab-forced dual-slot collision (§1 footnote ††; see [REDTEAM.md § Nonce reuse](REDTEAM.md#nonce-reuse-lab-only)); no key rotation required |
| Padding oracle | Vulnerable (POODLE, Lucky13) | — | — | N/A (no padding) | N/A (no padding) |
| Hash requirement | PRF/PRP | PRF | PRF | PRP | PRF |
| Maturity / standardization | TLS 1.0-1.1 | OTR v3/v4 | Signal Protocol | NIST SP 800-38D | **None** |

† Software-level property under the random-container model; no guarantees against hardware-level attacks (see Disclaimer).

## 6. CCA Oracle Leak Comparison

| Scheme | CCA Leak (MAC result revealed) |
|---|---|
| AES-CBC + MAC-then-Encrypt‡ | Padding oracle → full plaintext (POODLE, Lucky13) |
| AES-CTR + MAC-then-Encrypt | Bit-flip oracle → data structure |
| ITB + MAC-Inside (full capacity) | Noise position only (3 bits/pixel, no data); CSPRNG fill persists in data positions ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)) |
| AES-GCM (AEAD) | None (MAC rejects before decryption) |
| ChaCha20-Poly1305 (AEAD) | None (MAC rejects before decryption) |

‡ Deprecated construction (TLS 1.0/1.1, RFC 8996). Included for historical context only.

## 7. Attack Resistance Summary

The always-on Interlocked Barrier (§18) is a per-chunk 48-bit PRF-keyed permutation drawn from a ≈ 2^70.20 mask space. It applies uniformly across every column in the table below; the barrier's contribution to the KPA / Crib KPA / CPA columns is architectural and PRF-conditional, and stacks on top of the pixel-level obstacles listed per cell.

| Attack | Core ITB | MAC + Silent Drop‡‡ | MAC + Reveal | MAC + Reveal + KPA |
|---|---|---|---|---|
| Ciphertext-only (COA) | ✓ IT barrier† | ✓ IT barrier† | ✓ IT barrier† | ✓ IT barrier† |
| Known-plaintext (KPA) | ✓ 3-factor under PRF (PRF + 7-rotation × 8-noisePos + startPixel); byte-split activates under Partial KPA† | ✓ 3-factor (same as Core)† | ✓ 3-factor under PRF (PRF + rotation 7^P + startPixel); byte-split activates under Partial KPA (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)) | ✓ 3-factor under PRF (PRF + rotation 7^P + startPixel); byte-split activates under Partial KPA* (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)) |
| Chosen-plaintext (CPA) | ✓ Independent maps | ✓ Independent maps | ✓ Independent maps | ✓ Independent maps |
| Chosen-ciphertext (CCA) | ✓ No oracle | ✓ No oracle | noiseSeed leaked, dataSeed safe§§ | noiseSeed leaked, dataSeed safe§§ |
| Brute-force (classical) | P × 2^(2×keyBits)††† | P × 2^(2×keyBits)††† | P × 2^keyBits** | P × 2^keyBits** |
| Brute-force (Grover) | √P × 2^keyBits††† | √P × 2^keyBits††† | √P × 2^(keyBits/2)** | √P × 2^(keyBits/2)** |
| Map guessing | 2^(62P) | 2^(62P) | 2^(59P) | 2^(59P) |
| Nonce reuse | Two-time pad†† | Two-time pad†† | Two-time pad†† | Two-time pad†† |
| Bit-flipping | Undetected | Detected (MAC) | Detected (MAC) | Detected (MAC) |
| Padding oracle | N/A (no padding) | N/A (no padding) | N/A (no padding) | N/A (no padding) |
| Quantum structural (Simon, BHT) | Conjectured mitigated | Conjectured mitigated | Conjectured mitigated | Conjectured mitigated |

† IT barrier is a software-level property under the random-container model; no guarantees against hardware-level attacks (see Disclaimer).

\* Per-bit XOR hides XOR masks under passive observation; with invertible hash, seed recoverable via inversion.

\** MAC + Reveal: CCA reveals noisePos but not startPixel (startPixel determined by independent startSeed + nonce, not transmitted). startPixel enumerated as [0, P). Total: P × 2^keyBits classical, √P × 2^(keyBits/2) Grover. At 1024-bit keys under the unified `MinPixels` floor (P=400): classical ~2^1033, Grover ~2^516. With invertible hash under KPA: seed recoverable in ~56 × P hash inversions (P startPixel candidates × 56 configs per reference pixel, no CCA required). Under PRF, Full KPA requires simultaneously three independent obstacles at the pixel layer: (1) inverting ChainHash, AND (2) guessing startPixel from independent startSeed (no leak from noiseSeed/dataSeed), AND (3) resolving 7-rotation and 8-noisePos ambiguity per pixel at signal/noise 1:1 (all 56 candidates equally consistent with observation). Under Partial KPA, a 4th obstacle is effective: gcd(7,8)=1 byte-splitting blocks per-channel candidate formulation when adjacent bytes are unknown. The always-on Interlocked Barrier (§18) contributes a further per-chunk 2^70.20 mask-space enumeration under the PRF assumption. PRF non-invertibility and the architectural layers combine conjunctively, not redundantly: an attacker with partial PRF inversion still faces P startPixel candidates to enumerate and 56-fold per-pixel ambiguity to disambiguate without a verification oracle.

††† Core ITB and MAC + Silent Drop (no oracle): attacker must jointly search noiseSeed and dataSeed — without dataSeed, noiseSeed output is indistinguishable from random, so independent attack on noiseSeed is impossible. Joint search space: 2^(2×keyBits). startSeed contributes only P (startPixel candidates, enumerated as [0, P)), not 2^keyBits. Total: P × 2^(2×keyBits). Grover: √P × 2^keyBits. At 1024-bit keys under the unified `MinPixels` floor (P=400): classical ~2^2057, Grover ~2^1028.

§§ CCA removes noise bits (12.5% of container), but CSPRNG fill bytes encrypted by dataSeed persist in data bit positions, indistinguishable from plaintext. The information-theoretic barrier is reduced, not fully eliminated ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

**Nonce reuse is local.** The shipped wire carries two independent nonces (`main_nonce` and `interlock_nonce`) drawn per encrypt from crypto/rand and enforced pairwise-distinct at the API, so caller-side reuse is not reachable through the shipped surface. Under a lab-forced dual-slot / main-only / interlock-only collision, plaintext recovery is null under every attacker-realistic probe at the tested sample sizes (see [REDTEAM.md § Nonce reuse](REDTEAM.md#nonce-reuse-lab-only)): the barrier's per-chunk PRF-keyed 48-bit mask permutation removes the demask anchor even under the maximum-leverage dual-slot collision (modifier †† below). Seeds remain secret (PRF non-invertibility blocks ChainHash inversion), so future messages with fresh nonces are unaffected — **no key rotation required**. A single nonce collision provides too few observations for Simon, BHT, or quantum structural algebraic attacks. Unlike AES-GCM where nonce reuse leaks the GHASH key H and enables forgery until key rotation (global catastrophe affecting all subsequent messages), ITB nonce collision is **strictly local** — ITB is nonce-misuse-resistant under the PRF assumption. For the usage-precondition framing and the demasking disclaimer, see [ITB.md § 9 Nonce Reuse](ITB.md#9-nonce-reuse-a-usage-precondition-not-an-absorbed-threat).

†† Interlocked Barrier modifier. The always-on Interlocked Barrier removes the demask entry point on the colliding messages: the per-chunk PRF-keyed 48-bit mask triple is applied before COBS, so the two-time-pad XOR yields lane-compressed bits `l₀(P₁)‖l₁(P₁)‖l₂(P₁) ⊕ l₀(P₂)‖l₁(P₂)‖l₂(P₂)` interpretable only with `lockSeed` and PRF-opaque under the PRF assumption. See §18 for the full Interlocked Barrier construction.

‡‡ MAC + Silent Drop assumes the attacker is unaware of MAC presence. If the attacker knows MAC is inside (e.g., insider knowledge), the encrypted MAC tag serves as a local verification oracle during brute-force — the attacker decrypts with candidate keys, computes MAC(payload), and checks against the embedded tag without requiring recipient response. Search cost remains P × 2^(2×keyBits) (same as Core ITB — no CCA, noiseSeed not leaked, both seeds must be searched jointly), but the attacker can now verify candidates. Without insider knowledge: no verification → plausible deniability. Grover: √P × 2^keyBits.

## 8. Byte-Splitting Property

Since `gcd(DataBitsPerChannel, BitsPerByte) = gcd(7, 8) = 1`, plaintext bytes never align with channel boundaries. Every plaintext byte is split across exactly 2 channels with independent per-channel XOR masks.

| Property | Byte-aligned ciphers (AES-CTR, ChaCha20) | ITB |
|---|---|---|
| Plaintext byte → ciphertext mapping | 1 byte → 1 byte | 1 byte → 2 channels (7/8 non-aligned) |
| Byte-level analysis | Straightforward | Structurally impossible without startPixel |
| Partial KPA (know byte k, not k±1) | Byte k directly analyzable | Cannot compute channel bits (channel mixes 2 bytes) |
| 7 worst-case candidates (Full KPA + CCA + startPixel) | N/A | noisePos known from CCA, 7 rotation candidates remain; without CCA: 56 (8 noisePos × 7 rotation) |

This property is a structural consequence of the 8/1 noise format, not a deliberately engineered feature. See [SCIENCE.md Section 2.9.1](SCIENCE.md#291-byte-splitting-property-78-non-alignment) for detailed analysis.

## 9. Information-Theoretic Barrier Metrics

### Container Bit Accounting (per pixel)

| Metric | Bits | Percentage |
|---|---|---|
| Total container bits | 64 | 100% |
| Data bits | 56 | 87.5% |
| Noise bits | 8 | 12.5% |

### Configuration Bit Accounting (per pixel: noiseSeed + dataSeed)

| Source | Config bits | CCA leak | Protected |
|---|---|---|---|
| noiseSeed (noise position) | 3 | 3 (100% of noiseSeed)§ | 0 |
| dataSeed (rotation + XOR) | 59 | **0** (independent seed) | **59 (100%)** |
| **Total** | **62** | **3 (4.8%)** | **59 (95.2%)** |

§ CCA reveals noise bit positions, but does not eliminate all ambiguity: CSPRNG fill bytes in data positions remain encrypted by dataSeed, indistinguishable from plaintext ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

### Barrier Strength (1024-bit key)

Every entry point applies the CCA-resistant `MinPixels` floor uniformly, so the auth-side envelope covers Core ITB, MAC + Silent Drop, and MAC + Reveal — one row per metric, no plain-vs-auth split.

| Metric | Value |
|---|---|
| MinPixels | 365 → 400 (20×20) |
| Noise barrier | 2^3200 |
| Landauer bound (blind enumeration) | ~2^306 |
| Blind-enumeration exponent vs Landauer | 10.5× (3200/306) |
| Config map space | 2^24800 |
| Key space | 2^1024 |

The Landauer row bounds the cost of blind enumeration of the noise-barrier space; it does not bound structural attacks that do not enumerate.

Under CCA (MAC + Reveal) the noise positions are revealed but CSPRNG fill in data positions persists as residual ambiguity ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)); the noise-barrier headline is stated at the unified `MinPixels` floor.

### Practical Value of 4.8% CCA Leak

| Information | Gained by attacker? |
|---|---|
| Plaintext bits | Zero |
| XOR mask bits | Zero |
| Start pixel | Unknown |
| Key-space reduction | noiseSeed eliminated: P × 2^(2×keyBits) → P × 2^keyBits |
| Brute-force speedup | Search space halved in exponent (two seeds → one seed) |
| Grover reduction | √P × 2^keyBits → √P × 2^(keyBits/2) (noiseSeed eliminated from search) |
| CSPRNG residue after CCA | Persists: fill bytes in data positions encrypted by dataSeed ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)) |

## 10. Noise-Density Optimality (Why 8/1)

| Format | Data/px | Noise/px | Overhead | CCA Config Leak | Barrier (1024-bit, unified P) |
|---|---|---|---|---|---|
| 8/1 (ITB) | 56 | 8 | 1.14× | 4.8% | 2^3200 |
| 6/2 | 48 | 16 | 1.33× | 8.9% | 2^3136 |
| 5/3 | 40 | 24 | 1.60× | 12.2% | 2^5400 |
| 4/4 | 32 | 32 | 2.00× | 17.1% | 2^8192 |

8/1 is Pareto-optimal among the analyzed noise-density configurations. The Barrier column for 8/1 is stated at the unified `MinPixels = 400` floor from §9; the other rows carry each format's own `data_bits × MinPixels(format)` for the illustrative comparison. All noise-barrier exponents place blind enumeration above the Landauer bound; that scopes to enumeration cost, not to structural attack resistance.

## 11. Effective Key Size by Hash Width

Nominal key is `Components × Width`; the effective security bound is the smaller of the nominal key and the register-arithmetic ceiling of the width. The three widths shipped by every native primitive appear below; the concrete primitives at each width follow the canonical registry order.

| Native Width | Components per Seed | Nominal Key | Effective Bound |
|---|---|---|---|
| 128 bits | 16 | 1024 bits | 1024 bits |
| 256 bits | 32 | 2048 bits | 2048 bits |
| 512 bits | 32 | 2048 bits | 2048 bits |

### Seed Alignment by Width

| Seed Type | Hash Type | Bits Alignment | Components per Round | Components Alignment |
|---|---|---|---|---|
| `Seed128` | `HashFunc128` (128-bit) | ×128 | 2 | ×2 |
| `Seed256` | `HashFunc256` (256-bit) | ×256 | 4 | ×4 |
| `Seed512` | `HashFunc512` (512-bit) | ×512 | 8 | ×8 |

## 12. MAC Placement Design Space

| MAC Placement | Covers Noise | Deniability | CCA Leak | Circular Dependency |
|---|---|---|---|---|
| Inside (full capacity) | No | ✓ Preserved | Noise position only | None |
| Inside (plaintext only) | No | ✓ Preserved | Noise pos + spatial | None |
| Outside (header) | Yes | ✗ Broken | None | Verification oracle |
| Inside (full container) | N/A | N/A | N/A | Tag invalidates itself |

Implemented: Inside (full capacity) — every shipped MAC-authenticated Low-Level entry point (`EncryptAuthenticated3x{128,256,512}Cfg`) and every `triple.Pipeline` profile that enables MAC. Other placements are theoretical alternatives, not implemented.

## 13. Known Theoretical Threats

| Threat | Exploit requires | Practical risk | Mitigation |
|---|---|---|---|
| rotateBits7 shift timing (DPA/SPA class) | Oscilloscope on CPU die, >10GHz, lab access | Same class as DPA on any cipher | Register-only, no software side-channel |
| Container size metadata | Network observation | Metadata only | Inherent to all ciphers, no crypto advantage |
| Non-CSPRNG container | Deployer misconfiguration | Degrades barrier | crypto/rand mandatory, non-CSPRNG unsupported |
| COBS decode truncation | Wrong seed / tampered data | None | Core ITB: returns raw decoded bytes (plausible deniability, no oracle); Authenticated: MAC rejects before COBS decode |
| Bit-flip false null (DoS) | Data bit modification | None (with MAC) | MAC verified before null search; noise flips do not affect decrypted data |
| CGO AVX2 side-channel | Co-located attacker | None (see below) | All AVX2 ops constant-time; identical to Pure Go |
| Spectre v1/v2/v4, Downfall, etc. | Secret-dependent memory access gadget | No known gadget in ITB data path | Register-only ops; no `table[secret_index]` |
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
| `% totalPixels` (pixel wrap) | Variable-time `idivl` | Not secret: totalPixels = W×H from public header |
| Container access pattern | Same as Pure Go | `container[pixelOffset]` — startPixel cache pattern unchanged |
| Hash array access | Sequential | No data-dependent indexing |
| Spectre | Not applicable | No secret-dependent array indexing |
| L1 micro-batching | **Improves** cache resistance | 8KB batches harder to observe via Flush+Reload than full arrays |

The analysis applies equally to ARM64 NEON auto-vectorization: `veor`, `vand`, `vorr`, `vshl`, `vshr` are constant-time on ARM. ARM `sdiv` (for `% totalPixels`) is variable-time but operates on public data only. ARM has no frequency throttling from NEON (unlike Intel AVX-512).

Both backends produce identical ciphertext. Switching between `CGO_ENABLED=0` (Pure Go pixel kernel; Go-assembly hash ASM stays engaged) and `CGO_ENABLED=1` (C + SIMD pixel kernel) does not change the security model on any platform. See [SCIENCE.md §4](SCIENCE.md#known-theoretical-threats) "Known Theoretical Threats" point 6 for detailed analysis.

## 14. Hash Function Compliance

Every shipped registry primitive is a PRF-grade construction that satisfies the §2 requirements. Tests and benchmarks cover every registry entry across the 128 / 256 / 512-bit widths shipped by the ChainHash surface; the concrete registry list is authoritative in `hashes/registry.go`.

## 15. Security Properties Summary

| Property | ITB |
|---|---|
| Information-theoretic barrier* | Two mechanisms: random-container noise absorption (CSPRNG) + encoding ambiguity (56^P without CCA from 8-noisePos × 7-rotation, 7^P under CCA from rotation only). Architectural layers denying the point of application: independent startSeed (startPixel not transmitted) under Full KPA, plus gcd(7,8)=1 byte-splitting under Partial KPA. All combine under PRF assumption via [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) |
| Key space | Up to 2^2048 |
| Grover resistance | √P × 2^keyBits (Core/Silent Drop) to √P × 2^(keyBits/2) (MAC + Reveal); O(P) full decryption per candidate (all modes) |
| Plausible deniability | ✓ All modes (wrong seed → garbage indistinguishable from valid plaintext) |
| Encoding ambiguity | ✓ All modes (7^P unverifiable rotation combinations, survives CCA; CSPRNG residue persists in data positions, [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)) |
| 8-seed isolation | ✓ All modes (noiseSeed / lockSeed / dataSeed1..3 / startSeed1..3 independent CSPRNG components, pointer-distinct at the API surface; CCA leaks noiseSeed only) |
| Oracle-free deniability | ✓ Core ITB / MAC + Silent Drop (no oracle); MAC + Reveal has CCA oracle but limited to noise positions |
| Known-plaintext resistance | 3-factor under PRF assumption for Full KPA at the pixel layer: PRF non-invertibility (verification) + independent startSeed + 7-rotation × 8-noisePos per-pixel ambiguity at signal/noise 1:1. gcd(7,8) byte-splitting is a 4th factor effective only under Partial KPA (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance), [SCIENCE.md §2.9.2](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier)). The always-on Interlocked Barrier (§18) contributes a further per-chunk 2^70.20 PRF-keyed mask-space enumeration and a 3-snake unknown-offset split. |
| Chosen-plaintext resistance | Independent maps |
| Noise absorption* | ✓ Core ITB / MAC + Silent Drop (CSPRNG noise bit at unknown position; noise bits bypassed by CCA in MAC + Reveal, but CSPRNG fill in data positions persists — [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)) |
| Noise barrier (min container) | 2^3200 (1024-bit, unified P=400) to 2^6272 (2048-bit, unified P=784) |
| Storage overhead | 1.14× (56 data bits per 64-bit pixel) |
| Hash function requirement | PRF |
| PRF output consumed per pixel | 64 bits per ChainHash call (architectural cap independent of native primitive width; 50 % / 25 % / 12.5 % of 128 / 256 / 512-bit output, the remainder discarded by the per-pixel encoder). Truncation preserves PRF-conditional security but does not strengthen it; the discarded portion is architecturally invisible to the encryption path, closing structural weaknesses concentrated in those bits (FNV-1a top-bit-isolation case documented in [REDTEAM.md § Broken-primitive stress](REDTEAM.md#broken-primitive-stress--fnv-1a-and-crc128)) — defense-in-depth against partial PRF-failure, not an upgrade of PRF-conditional security under PRF-grade primitives. See [SCIENCE.md §1.1.3](SCIENCE.md#113-per-pixel-config-extraction-and-effective-security). |
| Nonce | 128/256/512-bit per-message (default 512-bit, mandatory) |
| Authentication | Optional (MAC-Inside-Encrypt, pluggable) |
| Deniable authentication | ✓ (tag encrypted inside container) |
| Classical cryptanalytic techniques | Blocked: differential, linear, algebraic, slide, related-key, integral, boomerang, interpolation, cube — PRF output absorbed by random container, unobservable ([SCIENCE.md §2.9.2](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier)) |
| Quantum structural attacks | Conjectured mitigated (IT barrier is computation-model-independent; not independently verified) |
| Grover oracle | Degraded: no oracle without MAC; with MAC-Inside each query requires full decryption O(P). Per-candidate O(P) cost applies to all modes |

\* Software-level property under the random-container model. No guarantees against hardware-level attacks (see Disclaimer).

### Per-Candidate Decryption Cost

Each brute-force candidate (classical or Grover oracle query) requires full container decryption — processing all P pixels with ChainHash. This applies to all composition modes (Core ITB, MAC + Silent Drop, MAC + Reveal). The per-query cost grows linearly with data size, making larger messages more expensive to attack.

Approximate empirical example: 1024-bit key, ~10 ns/hash (average across PRF functions on a typical modern CPU), 8 ChainHash rounds, 2 hash calls per pixel (noiseSeed + dataSeed). Actual times vary by hash function, key size, and hardware.

| Data size | P (pixels) | Hash calls per candidate | Time per candidate | vs AES (~1 ns/candidate) |
|---|---|---|---|---|
| 1 KB | 400 (unified `MinPixels`) | 6,400 | ~64 µs | ~64,000× slower |
| 4 MB | 602,176 | 9,634,816 | ~96 ms | ~96,000,000× slower |
| 16 MB | 2,408,704 | 38,539,264 | ~385 ms | ~385,000,000× slower |
| 64 MB | 9,628,609 | 154,057,744 | ~1.5 s | ~1,500,000,000× slower |

Grover oracle queries have the same O(P) per-candidate cost — ChainHash rounds are sequential and not parallelizable by quantum algorithms. See [SCIENCE.md §2.12](SCIENCE.md#212-per-candidate-decryption-cost) for detailed analysis.

## 16. Quantum Resistance (Conjectured)

The noise-absorption layer under passive observation (COA) is computation-model-independent: provided the container is generated from a source indistinguishable from true uniform randomness, every observed byte value is compatible with every possible hash output (∀v, ∀h : ∃c : embed(c,h,d)=v), regardless of classical, quantum, or any future computational model. A quantum computer cannot extract information that does not exist in the observation. This property scopes to the noise-absorption layer under passive observation; under active seed-recovery (KPA / CPA / CCA) the closure is computational and admits Grover speedup on the seed-space brute-force, per the bounds below. Whether this layered architecture translates into practical quantum resistance across all attack scenarios has not been formally proven or independently verified.

| Quantum Algorithm | AES-CTR / ChaCha20 | ITB |
|---|---|---|
| **Grover** (brute-force) | Efficient oracle (single block verify); 2^128 for 256-bit key | No oracle (Core ITB) or expensive oracle (MAC-Inside: full decryption per query) |
| **Simon** (periodicity) | Relies on PRF/PRP computational strength | Conjectured mitigated: aperiodic config map (nonce per message) |
| **BHT** (collision finding) | Relies on PRF/PRP computational strength | Conjectured mitigated: Core/Silent Drop — container absorbs collisions; MAC + Reveal — encoding ambiguity (7 candidates) |
| **Quantum differential/linear** | Relies on PRF/PRP computational strength | Conjectured mitigated: Core/Silent Drop — container limits structural relations; MAC + Reveal — encoding ambiguity (7 candidates) |
| **Q2 superposition queries** | Theoretically applicable (oracle accepts superposition inputs) | Not applicable: MAC oracle is inherently classical (network request → accept/reject) |

**Q1 vs Q2 models.** In the Q2 model (quantum superposition queries to oracle), constructions such as Luby-Rackoff, Even-Mansour, and Keyed Sum of Permutations become vulnerable. ITB's MAC oracle is inherently classical — it accepts a concrete container over a network and returns accept/reject. Superposition queries are physically impossible. Core ITB and MAC + Silent Drop have no external oracle (if the attacker has insider knowledge of MAC presence, local verification is possible — see ‡‡). This means the Q2 model is inapplicable by design, not by cryptographic countermeasure.

The fundamental difference between ITB's noise-absorption layer (under COA) and traditional ciphers under quantum attack: AES and ChaCha20 rely on **computational hardness** across every attack model — their security degrades with more computational power (Grover: √ speedup). ITB's noise-absorption barrier under passive observation relies on **information absence** — no computation (classical or quantum) helps when the information is not in the observation; this is an information-theoretic property scoped to the COA layer, not a construction-wide claim. Under active seed-recovery ITB reverts to computational hardness like AES / ChaCha20.

AES-256 and ChaCha20 are widely considered quantum-resistant for practical purposes (2^128 Grover bound). ITB's random-container architecture may provide an additional architectural layer of resistance to quantum structural algorithms, but this is a conjectured property that has not been independently verified. See [SCIENCE.md §2.11](SCIENCE.md#211-quantum-resistance-analysis) for detailed analysis. See also [SCIENCE.md §2.9.2](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier) for why KPA candidates do not break the barrier.

Under the unified `MinPixels` floor from §9 (every entry point applies the auth-side envelope), the joint-seed search covers both `noiseSeed` and `dataSeed`. At 1024-bit key (P=400): Core / MAC + Silent Drop ~2^2057 classical, ~2^1028 Grover; MAC + Reveal ~2^1033 classical, ~2^516 Grover. At 2048-bit key (P=784): Core / MAC + Silent Drop ~2^4106 / ~2^2053; MAC + Reveal ~2^2058 / ~2^1029.

## 17. Maturity and Scope

ITB is a new construction without prior peer review or independent cryptanalysis. The contribution is theoretical: demonstrating that Full KPA resistance at the pixel layer is 3-factor under the PRF assumption (PRF non-invertibility + independent startSeed + per-pixel 1:1 ambiguity), with gcd(7,8)=1 byte-splitting as a 4th factor effective only under Partial KPA. PRF non-invertibility closes the candidate-verification step; architectural layers deny the attacker a usable reference pixel (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)). The always-on Interlocked Barrier (§18) contributes a per-chunk ≈ 2^70.20 mask-space enumeration and a 3-snake unknown-offset split on top of the pixel-layer factors. Performance is not a design goal.

| Aspect | Status |
|---|---|
| Peer review | None (first publication) |
| Independent cryptanalysis | None |
| Formal proof (simulation-based) | Planned (see [SCIENCE.md §7](SCIENCE.md#7-research-directions)) |
| Implementation audit | Not performed |
| Core barrier (∀v, ∀h : ∃c : embed(c,h,d)=v) | Noise absorption — compatibility proof, hash-independent ([Proof 1](PROOFS.md#proof-1-information-theoretic-barrier)) |
| Rotation barrier (7^P configurations) | Encoding ambiguity — 7 unverifiable rotations per pixel, PRF-dependent ([Proof 4](PROOFS.md#proof-4-rotation-barrier)) |
| 8-seed isolation (independent CSPRNG components, pointer-distinct at API surface) | noiseSeed / lockSeed / dataSeed1..3 / startSeed1..3; CCA/cache leaks contained ([Proof 3](PROOFS.md#proof-3-8-seed-isolation)) |
| Interlocked Barrier (per-chunk 2^70.20 mask-space) | Architectural claim under the PRF assumption (§18) |
| Active attack analysis (CCA, MITM) | Self-analysis, invites scrutiny |
| Side-channel mitigations | Implemented, not independently audited |

Potential vulnerability classes: (1) fundamental — barrier invalidation under unconsidered attack model (unlikely, barrier is probability-theoretic); (2) implementational — edge cases, timing, off-by-one (correctable). See [SCIENCE.md §4](SCIENCE.md#scope-and-maturity-disclaimer) "Scope and Maturity Disclaimer" for detailed discussion.

## 18. Interlocked Barrier

The Interlocked Barrier is the always-on, non-disableable per-chunk keyed bit-permutation layered on top of the Triple Ouroboros split. Every 6-byte (48-bit) chunk of the interleaved payload is partitioned into three disjoint 16-of-48 lanes `(l₀, l₁, l₂)` by a balanced mask triple `(m₀, m₁, m₂)` with `popcount(mᵢ) = 16` and `m₀ ∪ m₁ ∪ m₂ = 2^48 − 1`. Every chunk draws its own mask triple via a per-chunk PRF call keyed by the `lockSeed` and the nonce; the mask is unobservable to the attacker without the `lockSeed`.

### Mask-space cardinality

The count of balanced partitions per chunk is:

- `A = C(48, 16) = 2,254,848,913,647` (log₂ ≈ 41.04) — choices for `m₀`
- `B = C(32, 16) = 601,080,390` (log₂ ≈ 29.16) — choices for `m₁` from the 32 bits `m₀` leaves free (`m₂` is then determined)
- `|mask triples| = A · B ≈ 2^70.20`

Under the PRF assumption the per-chunk draws are computationally indistinguishable from independent uniform selections from the ≈ 2^70.20 mask space. Because the draw is per-chunk and PRF-keyed, the mask of one chunk carries no information about the mask of any other; a known-plaintext crib supplies plaintext bits but the mapping from those bits to observed lane positions is a fresh ≈ 2^70.20-way secret at each chunk. The solver has no fixed bit-position-to-lane anchor: every crib chunk multiplies attacker enumeration by ≈ 2^70.20 without contributing a constraint that couples across chunks. The known-plaintext instance stays under-determined regardless of crib density, and solver throughput cannot convert an under-determined instance into a determined one.

### Exact-B reduction and the gcd anti-collapse trap

Each 128-bit PRF output reduces to a pair `(idx₀, idx₁)` via a two-step divmod: `idx₁ = rank mod B`, `idx₀ = ⌊rank / B⌋ mod A`. This reaches the full `[0, A) × [0, B)` space near-uniformly. The rejected alternative — reducing the same rank by both moduli directly, `(rank mod A, rank mod B)` — reaches only pairs `(a, b)` with `a ≡ b (mod gcd(A, B))`; here `gcd(A, B) = 66861 = 3² · 17 · 19 · 23`, so the same-rank double-mod would confine the draw to ≈ 1 / 66861 ≈ 1.5 × 10⁻⁵ of the pair space — a structured subset that would hand the attacker a 66861×-restricted mask space through the back door. Naming `gcd(A, B) = 66861` here is a good-faith showing that full-space coverage is a deliberate property of the construction, not an accident.

### Bias distribution — granularity, not a distinguisher

The two-step reduction is deterministic and constant-time; rejection sampling is avoided precisely to keep the kernel branch-free under the constant-time discipline. It carries a small, fixed, publicly-known per-chunk deviation: the `2^128 mod (A · B)` lowest-indexed pairs receive one extra preimage, giving a per-chunk relative deviation ≈ **2^-57.8**. Accumulated over a maximum-size message of 2^23.42 chunks, the conservative linear bound is ≈ **2^-34.4** per message. Turning this granularity into a confident distinguisher would require ≈ `1/ε² ≈ 2^115.6` chunk samples, i.e. ≈ 2^92 maximum-size messages — well beyond any attainable sample budget. The biased event is a property of PRF output (one-way by assumption) and is unobservable beneath the barrier / noise / fill stack, so it exposes no key or plaintext channel even in principle. This figure is an **architectural constant** derived from the reduction arithmetic; the "no distinguisher" consequence is bounded by the attainable sample size and is phrased as such.

### Algebraic under-determination at 48 known bits per chunk

Even granting the attacker the 48 known plaintext bits of a chunk under Full KPA, the observation does not determine the chunk's mask: the number of preimages per mask triple is `⌊2^128 / (A · B)⌋ ≈ 2^57.80`, and any candidate mask is consistent with the observation. Combined with the per-pixel 1:1 signal/noise ambiguity of the underlying pixel construction ([Proof 1](PROOFS.md#proof-1-information-theoretic-barrier): `P(observed | hash) = 1/2`), the attacker has no ranking signal among the ≈ 2^70.20 masks. The barrier's contribution is structural: it adds a hidden per-chunk permutation whose knowledge is required before any per-bit constraint can even be written down.

### Composition with the Triple split and the 8-seed hierarchy

Triple Ouroboros splits the plaintext across three interleaved snakes with independent per-snake offsets and configurations. A known crib maps onto three unknown-offset streams whose per-snake boundaries are not recoverable from the interleaved container. Compounding this, the 8 mandatory seeds — `noiseSeed`, `lockSeed`, `dataSeed1..3`, `startSeed1..3` — are drawn as independent CSPRNG components and enforced pairwise-distinct at the API surface by byte-level `Components` comparison in addition to pointer identity (so byte-identical seed material reaching the API through blob import or the Low-Level constructors is rejected on the same gate). The `lockSeed` keys the barrier's permutation channel independently of the `noiseSeed` that keys the noise-position channel, so a structural shortcut against one primitive channel cannot leak into another's derivation. The barrier's mask-space cardinality, the 3-snake enumeration dimension, and the 8-seed isolation compose into an instance-formulation barrier under the PRF assumption.

### Wire-format neutrality and dispatch

The ciphertext wire format is unaffected by the barrier — the outbound container is byte-identical to the un-barriered layout that would result from a hypothetical bypass. The barrier is symmetric: encrypt and decrypt derive identical masks from the shared `lockSeed` and chunk index. The barrier cannot be disabled; there is no runtime knob, no configuration, no environment variable, no compile-time flag that turns it off. The `lockSeed` slot is one of the 8 mandatory seeds at every entry point, and every Low-Level `*Cfg` entry (as well as every `triple.Pipeline` profile) takes the barrier as a construction invariant.

## 19. Threat models NOT closed by the barrier

Framed as "outside the barrier's threat model" where that is the honest description, and as "conditional" where the barrier's closure depends on a precondition. None of these is a claim that the barrier is weak — they are the boundary of what the barrier addresses. The full cryptographer verdict enumerating these classes appears in the pre-flight review; the summary sentence from that verdict is preserved here verbatim:

> Closure of the KPA/CPA families is conditional on a secure PRF and fresh nonces; total inversion or a reused nonce is outside what the barrier closes.

- **Total or systematic PRF inversion.** The barrier is explicitly PRF-conditional. Total inversion of the configured primitive lets the attacker resolve the per-chunk masks, the startPixels, and the seed components algorithmically, collapsing every architectural obstacle. Systematic partial PRF inversion is raised in cost but not eliminated. Outside the barrier's power to close.
- **Nonce reuse.** Closure of the CPA / KPA families is conditional on fresh per-message nonces on both header slots — the main nonce that feeds the per-pixel and per-snake derivations and the independent interlock nonce that feeds the barrier's per-chunk mask draws. Under joint collision of both, the barrier's per-chunk masks repeat and the keystream-reuse structure is not removed. The shipped API generates each of the two nonces internally per call, which prevents caller-side reuse, but that is an API-discipline property, not a construction-level guarantee. Conditional, not closed.
- **Upstream key-management / related-seed supply.** The 8-seed API draws independent CSPRNG components and rejects both pointer and byte-level `Components` collisions, so related-seed differentials do not arise through the shipped surface. A defective upstream KDF that supplies correlated seeds is outside the construction's control. Threat-model boundary, not a barrier property.
- **Physical side channels** (timing, power, EM, cache, speculative execution). Out of scope by construction — leakage is a property of the execution environment, not the algorithm. The barrier's own kernels are written to a constant-time discipline (mask-merge only, no secret-dependent branches or memory accesses; the deterministic reduction avoids rejection sampling precisely to stay branch-free), but a deployment-level side-channel evaluation is per-CPU, per-compiler, and orthogonal to the algorithm-level claims. See [HWTHREATS.md](HWTHREATS.md) for the per-instruction inventory.
- **Key-material compromise.** If the seeds or the derived state leak through any channel, confidentiality is lost by definition. The barrier assumes secret seeds.
- **Implementation defects in the shipped Go code.** The architectural argument assumes the code correctly implements the construction. Bugs in the unrank kernels, the reduction, the interleave, or the seed plumbing would be defects the architecture cannot self-correct. The test suite demands byte-level asm ↔ Go parity, directed reduction-boundary vectors at the exact gcd / preimage-cut points, and mask disjointness / popcount assertions rather than roundtrip tests alone.
- **Fault injection.** Active perturbation of the running computation is a hardware-execution threat outside the algorithm's model.
- **CCA via a deployment decryption oracle.** Core ITB and MAC + Silent Drop expose no oracle; MAC + Reveal is an optional deployment mode whose CCA behaviour is per-deployment and bounded by [Proof 6](PROOFS.md#proof-6-cca-leak-upper-bound) (noise position, 3 bits per pixel). Whether an oracle exists at all is a protocol choice, not a barrier property.
- **Quantum key recovery.** The seed-space search under Grover is a hypothetical upper-bound argument, not something the barrier addresses directly; the oracle-degradation framing applies (under Silent Drop there is no verification predicate for Grover to run against). Post-key quantum recovery is outside the barrier's threat model.
- **Undiscovered cryptanalysis.** No finite argument, architectural or empirical, establishes resistance to techniques not yet known. The construction has had no external cryptanalysis or formal certification.
- **Empirical re-verification of the 48-bit line.** The pre-existing empirical measurements were obtained on the shared pixel construction over a 12-primitive spectrum and support the pixel-layer ambiguity claims. The barrier's KPA closure is an architectural claim under the PRF assumption, corroborated by that pixel-layer evidence, not yet re-verified empirically end-to-end on the 48-bit line at the sample sizes that reached the archived KL floor.
