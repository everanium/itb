# ITB Security Reference

> **Disclaimer.** ITB is an experimental construction without peer review or formal certification. The information-theoretic barrier is a software-level property, reinforced by two independent barrier mechanisms: noise absorption from CSPRNG, and encoding ambiguity (56^P without CCA, 7^P under CCA) from triple-seed isolation. Architectural layers deny the point of application: independent startSeed and 8-noisePos ambiguity from independent noiseSeed under Full KPA, plus gcd(7,8)=1 byte-splitting under Partial KPA. Full KPA defense is 3-factor under PRF assumption (4-factor under Partial KPA) — see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance). It provides no guarantees against hardware-level attacks (DPA/SPA, Spectre, Meltdown, Rowhammer, cache timing, undiscovered side-channels). PRF-grade hash functions are required. No warranty is provided.

Comprehensive security comparison tables for ITB (Information-Theoretic Barrier) across three composition modes: Core (no MAC), MAC + Silent Drop, MAC + Reveal. For detailed proofs and analysis, see [SCIENCE.md](SCIENCE.md).

## 1. ITB Composition Modes

| Property | Core ITB (no MAC) | MAC + Silent Drop‡‡ | MAC + Reveal |
|---|---|---|---|
| Integrity | ✗ | ✓ | ✓ |
| Deniability | ✓ Full (structural) | ✓ Full | ✓ Full (full-capacity MAC) |
| CCA oracle | No oracle exists | No oracle (silent) | Noise position only (noiseSeed) |
| noiseSeed config | ✓ Barrier intact | ✓ Barrier intact | ✗ Leaked via CCA |
| dataSeed config | ✓ Barrier intact | ✓ Barrier intact | ✓ **Independent** (zero CCA leak) |
| Data rotation + XOR | ✓ | ✓ | ✓ (rotation barrier) |
| Information-theoretic barrier† | ✓ Intact | ✓ Intact | ✓ dataSeed protected |
| Brute-force impact of leak | — | — | noiseSeed eliminated¶: P × 2^(2×keyBits) → P × 2^keyBits |

† Software-level property under the random-container model; no guarantees against hardware-level attacks (see Disclaimer).

¶ CCA eliminates noise bits (12.5%), but CSPRNG fill bytes remain encrypted in data bit positions by dataSeed — indistinguishable from plaintext ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

## 2. Hash Function Requirements

Triple-seed architecture: noiseSeed (noise positions), dataSeed (rotation + XOR, zero side-channel), startSeed (pixel offset).

PRF-grade hash functions are required. PRF property guarantees all necessary sub-properties (input sensitivity, chain survival, non-affine mixing, avalanche, non-invertibility) by definition.

PRF weakness decomposes into three cases. **Total inversion** defeats the construction via algorithmic seed recovery (see [Proof 4a Asymmetry note](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)). **Occasional/sporadic partial inversion** is absorbed by the architecture: recovered candidates are indistinguishable from the false-positive distribution produced by startPixel isolation, per-pixel 1:1 ambiguity, and byte-splitting under Partial KPA. **Systematic partial inversion** is a real non-absorbed threat — the architecture raises the cost but does not eliminate the attack. No such systematic weakness is currently known to reduce the Full KPA work factor below the Theorem 4a bound.

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
| Information-theoretic barrier† | ✗ | ✗ | ✗ | ✗ | ✓ |
| Oracle-free deniability | ✗ | Partial | Partial | ✗ | ✓ |
| CCA spatial pattern eliminated | ✗ | — | — | ✓ | ✓ |
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

| Attack | Core ITB | MAC + Silent Drop‡‡ | MAC + Reveal | MAC + Reveal + KPA |
|---|---|---|---|---|
| Ciphertext-only (COA) | ✓ IT barrier† | ✓ IT barrier† | ✓ IT barrier† | ✓ IT barrier† |
| Known-plaintext (KPA) | ✓ 3-factor under PRF (PRF + 7-rotation × 8-noisePos + startPixel); byte-split activates under Partial KPA† | ✓ 3-factor (same as Core)† | ✓ 3-factor under PRF (PRF + rotation 7^P + startPixel); byte-split activates under Partial KPA (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)) | ✓ 3-factor under PRF (PRF + rotation 7^P + startPixel); byte-split activates under Partial KPA* (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)) |
| Chosen-plaintext (CPA) | ✓ Independent maps | ✓ Independent maps | ✓ Independent maps | ✓ Independent maps |
| Chosen-ciphertext (CCA) | ✓ No oracle | ✓ No oracle | noiseSeed leaked, dataSeed safe§§ | noiseSeed leaked, dataSeed safe§§ |
| Brute-force (classical) | P × 2^(2×keyBits)††† | P × 2^(2×keyBits)††† | P × 2^keyBits** | P × 2^keyBits** |
| Brute-force (Grover) | √P × 2^keyBits††† | √P × 2^keyBits††† | √P × 2^(keyBits/2)** | √P × 2^(keyBits/2)** |
| Map guessing | 2^(62P) | 2^(62P) | 2^(59P) | 2^(59P) |
| Nonce reuse | Two-time pad | Two-time pad | Two-time pad | Two-time pad |
| Bit-flipping | Undetected | Detected (MAC) | Detected (MAC) | Detected (MAC) |
| Padding oracle | N/A (no padding) | N/A (no padding) | N/A (no padding) | N/A (no padding) |
| Quantum structural (Simon, BHT) | Conjectured mitigated | Conjectured mitigated | Conjectured mitigated | Conjectured mitigated |

† IT barrier is a software-level property under the random-container model; no guarantees against hardware-level attacks (see Disclaimer).

\* Per-bit XOR hides XOR masks under passive observation; with invertible hash, seed recoverable via inversion.

\** MAC + Reveal: CCA reveals noisePos but not startPixel (startPixel determined by independent startSeed + nonce, not transmitted). startPixel enumerated as [0, P). Total: P × 2^keyBits classical, √P × 2^(keyBits/2) Grover. At 1024-bit keys (P=400): classical ~2^1033, Grover ~2^516. With invertible hash under KPA: seed recoverable in ~56 × P hash inversions (P startPixel candidates × 56 configs per reference pixel, no CCA required). Under PRF, Full KPA requires simultaneously three independent obstacles: (1) inverting ChainHash, AND (2) guessing startPixel from independent startSeed (no leak from noiseSeed/dataSeed), AND (3) resolving 7-rotation and 8-noisePos ambiguity per pixel at signal/noise 1:1 (all 56 candidates equally consistent with observation). Under Partial KPA, a 4th obstacle is effective: gcd(7,8)=1 byte-splitting blocks per-channel candidate formulation when adjacent bytes are unknown. PRF non-invertibility and the architectural layers combine conjunctively, not redundantly: an attacker with partial PRF inversion still faces P startPixel candidates to enumerate and 56-fold per-pixel ambiguity to disambiguate without a verification oracle.

††† Core ITB and MAC + Silent Drop (no oracle): attacker must jointly search noiseSeed and dataSeed — without dataSeed, noiseSeed output is indistinguishable from random, so independent attack on noiseSeed is impossible. Joint search space: 2^(2×keyBits). startSeed contributes only P (startPixel candidates, enumerated as [0, P)), not 2^keyBits. Total: P × 2^(2×keyBits). Grover: √P × 2^keyBits. At 1024-bit keys (P=196): classical ~2^2056, Grover ~2^1028.

§§ CCA removes noise bits (12.5% of container), but CSPRNG fill bytes encrypted by dataSeed persist in data bit positions, indistinguishable from plaintext. The information-theoretic barrier is reduced, not fully eliminated ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

**Nonce reuse is local.** Two-time pad applies only to the colliding 2–3 messages (confidentiality of those messages compromised). Seeds remain secret (PRF non-invertibility blocks ChainHash inversion), so future messages with fresh nonces are unaffected — **no key rotation required**. A single nonce collision provides too few observations for Simon, BHT, or quantum structural algebraic attacks. Unlike AES-GCM where nonce reuse leaks the GHASH key H and enables forgery until key rotation (global catastrophe affecting all subsequent messages), ITB nonce collision is **strictly local** — ITB is nonce-misuse-resistant under the PRF assumption. For the five conditions that ALL must hold before nonce reuse extracts any signal at all, see [ITB.md § 8 Nonce Reuse](ITB.md#8-nonce-reuse-only-if-every-condition-holds); for the empirical 96-cell Partial KPA matrix + NIST STS PRF-separation, see [REDTEAM.md § Phase 2d — Nonce-Reuse](REDTEAM.md#phase-2d--nonce-reuse).

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

### Configuration Bit Accounting (per pixel, triple-seed: noise + data)

| Source | Config bits | CCA leak | Protected |
|---|---|---|---|
| noiseSeed (noise position) | 3 | 3 (100% of noiseSeed)§ | 0 |
| dataSeed (rotation + XOR) | 59 | **0** (independent seed) | **59 (100%)** |
| **Total** | **62** | **3 (4.8%)** | **59 (95.2%)** |

§ CCA reveals noise bit positions, but does not eliminate all ambiguity: CSPRNG fill bytes in data positions remain encrypted by dataSeed, indistinguishable from plaintext ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

### Barrier Strength (1024-bit key)

| Metric | Value |
|---|---|
| MinPixels (Encrypt/Stream) | 177 → 196 (14×14) |
| MinPixels (Auth) | 365 → 400 (20×20) |
| Noise barrier (P=196)‖ | 2^1568 |
| Noise barrier (P=400)‖ | 2^3200 |
| Landauer limit | ~2^306 |
| Beyond Landauer (P=196) | 5.1× (1568/306) |
| Config map space (P=196) | 2^12152 |
| Config map space (P=400) | 2^24800 |
| Key space | 2^1024 |

‖ Noise barrier applies to Core ITB / MAC + Silent Drop. Under CCA (MAC + Reveal), noise positions are revealed but CSPRNG fill in data positions persists as residual ambiguity ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

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

| Format | Data/px | Noise/px | Overhead | CCA Config Leak | Barrier (1024-bit, min) |
|---|---|---|---|---|---|
| 8/1 (ITB) | 56 | 8 | 1.14× | 4.8% | 2^1568 |
| 6/2 | 48 | 16 | 1.33× | 8.9% | 2^3136 |
| 5/3 | 40 | 24 | 1.60× | 12.2% | 2^5400 |
| 4/4 | 32 | 32 | 2.00× | 17.1% | 2^8192 |

8/1 is Pareto-optimal among the analyzed noise-density configurations. All barriers exceed the Landauer limit.

## 11. Effective Key Size by Hash Function

| Hash Function | Output Width | API | Components | Nominal Key | Effective Bound |
|---|---|---|---|---|---|
| SipHash-2-4, AES-CMAC | 128 bits | `Encrypt128` | 16 | 1024 bits | 1024 bits |
| BLAKE2b-256, BLAKE2s, BLAKE3 | 256 bits | `Encrypt256` | 32 | 2048 bits | 2048 bits |
| BLAKE2b-512 | 512 bits | `Encrypt512` | 32 | 2048 bits | 2048 bits |

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

Implemented: Inside (full capacity) — `EncryptAuthenticated128` / `EncryptAuthenticated256` / `EncryptAuthenticated512`. Other placements are theoretical alternatives, not implemented.

## 13. Known Theoretical Threats

| Threat | Exploit requires | Practical risk | Mitigation |
|---|---|---|---|
| rotateBits7 shift timing (DPA/SPA class) | Oscilloscope on CPU die, >10GHz, lab access | Same class as DPA on any cipher | Register-only, no software side-channel |
| Container size metadata | Network observation | Metadata only | Inherent to all ciphers, no crypto advantage |
| Non-CSPRNG container | Deployer misconfiguration | Degrades barrier | crypto/rand mandatory, non-CSPRNG unsupported |
| COBS decode truncation | Wrong seed / tampered data | None | Core ITB: returns raw decoded bytes (plausible deniability, no oracle); Authenticated: MAC rejects before COBS decode |
| Bit-flip false null (DoS) | Data bit modification | None (with MAC) | MAC verified before null search; noise flips do not affect decrypted data |
| CGO AVX2 side-channel | Co-located attacker | None (see below) | All AVX2 ops constant-time; identical to pure Go |
| Spectre v1/v2/v4, Downfall, etc. | Secret-dependent memory access gadget | No known gadget in ITB data path | Register-only ops; no `table[secret_index]` |
| MDS, Zenbleed (stale data) | CPU buffer residue | Seeds may remain in buffers | Not ITB-specific; identical for all ciphers |
| Rowhammer, RAMBleed | DRAM bit flips / reads | Memory corruption / leakage | Not ITB-specific; ECC memory recommended |
| Heap memory exposure | Memory dump, debugger, Meltdown | Seeds, cached hash keys in heap | Not ITB-specific; secureWipe on intermediate buffers |

For detailed per-CVE analysis of 20+ hardware attacks (Spectre variants, Downfall, Hertzbleed, MDS, Zenbleed, Rowhammer), see [HWTHREATS.md](HWTHREATS.md).

### CGO Backend Side-Channel Equivalence

The optional C pixel processing backend (`CGO_ENABLED=1`, GCC `-O3 -mavx2`) was verified for side-channel equivalence with the pure Go backend:

| Concern | Status | Detail |
|---|---|---|
| AVX2 instruction timing | **Constant-time** | `vpxor`, `vpand`, `vpor`, `vpsllw`, `vpsrlw` — fixed latency on Intel |
| `dataHash % 7` | **Constant-time** | GCC optimizes to `imulq` multiply-by-reciprocal, no `div` instruction |
| `% totalPixels` (pixel wrap) | Variable-time `idivl` | Not secret: totalPixels = W×H from public header |
| Container access pattern | Same as pure Go | `container[pixelOffset]` — startPixel cache pattern unchanged |
| Hash array access | Sequential | No data-dependent indexing |
| Spectre | Not applicable | No secret-dependent array indexing |
| L1 micro-batching | **Improves** cache resistance | 8KB batches harder to observe via Flush+Reload than full arrays |

The analysis applies equally to ARM64 NEON auto-vectorization: `veor`, `vand`, `vorr`, `vshl`, `vshr` are constant-time on ARM. ARM `sdiv` (for `% totalPixels`) is variable-time but operates on public data only. ARM has no frequency throttling from NEON (unlike Intel AVX-512).

Both backends produce identical ciphertext. Switching between `CGO_ENABLED=0` (pure Go) and `CGO_ENABLED=1` (C + SIMD) does not change the security model on any platform. See [SCIENCE.md §4](SCIENCE.md#known-theoretical-threats) "Known Theoretical Threats" point 6 for detailed analysis.

## 14. Hash Function Compliance

PRF-grade hash functions (Areion-SoEM-256, Areion-SoEM-512, SipHash-2-4, AES-CMAC, BLAKE2b-256, BLAKE2s, BLAKE3, BLAKE2b-512) satisfy all requirements. Tests and benchmarks cover all listed hash functions across 128/256/512-bit widths.

## 15. Security Properties Summary

| Property | ITB |
|---|---|
| Information-theoretic barrier* | Two mechanisms: random-container noise absorption (CSPRNG) + encoding ambiguity (56^P without CCA from 8-noisePos × 7-rotation, 7^P under CCA from rotation only). Architectural layers denying the point of application: independent startSeed (startPixel not transmitted) under Full KPA, plus gcd(7,8)=1 byte-splitting under Partial KPA. All combine under PRF assumption via [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) |
| Key space | Up to 2^2048 |
| Grover resistance | √P × 2^keyBits (Core/Silent Drop) to √P × 2^(keyBits/2) (MAC + Reveal); O(P) full decryption per candidate (all modes) |
| Plausible deniability | ✓ All modes (wrong seed → garbage indistinguishable from valid plaintext) |
| Encoding ambiguity | ✓ All modes (7^P unverifiable rotation combinations, survives CCA; CSPRNG residue persists in data positions, [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)) |
| Triple-seed isolation | ✓ All modes (noiseSeed / dataSeed / startSeed independent; CCA leaks noiseSeed only) |
| Oracle-free deniability | ✓ Core ITB / MAC + Silent Drop (no oracle); MAC + Reveal has CCA oracle but limited to noise positions |
| Known-plaintext resistance | 3-factor under PRF assumption for Full KPA: PRF non-invertibility (verification) + independent startSeed + 7-rotation × 8-noisePos per-pixel ambiguity at signal/noise 1:1. gcd(7,8) byte-splitting is a 4th factor effective only under Partial KPA; see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance), [SCIENCE.md §2.9.2](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier) |
| Chosen-plaintext resistance | Independent maps |
| Noise absorption* | ✓ Core ITB / MAC + Silent Drop (CSPRNG noise bit at unknown position; noise bits bypassed by CCA in MAC + Reveal, but CSPRNG fill in data positions persists — [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)) |
| Noise barrier (min container) | 2^1568 (1024-bit, P=196) to 2^2888 (2048-bit, P=361) |
| Storage overhead | 1.14× (56 data bits per 64-bit pixel) |
| Hash function requirement | PRF |
| Nonce | 128/256/512-bit per-message (default 128-bit, mandatory) |
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
| 1 KB | 196 | 3,136 | ~31 µs | ~31,000× slower |
| 4 MB | 602,176 | 9,634,816 | ~96 ms | ~96,000,000× slower |
| 16 MB | 2,408,704 | 38,539,264 | ~385 ms | ~385,000,000× slower |
| 64 MB | 9,628,609 | 154,057,744 | ~1.5 s | ~1,500,000,000× slower |

Grover oracle queries have the same O(P) per-candidate cost — ChainHash rounds are sequential and not parallelizable by quantum algorithms. See [SCIENCE.md §2.12](SCIENCE.md#212-per-candidate-decryption-cost) for detailed analysis.

## 16. Quantum Resistance (Conjectured)

The information-theoretic barrier is computation-model-independent: provided the container is generated from a source indistinguishable from true uniform randomness, every observed byte value is compatible with every possible hash output (∀v, ∀h : ∃c : embed(c,h,d)=v), regardless of classical, quantum, or any future computational model. A quantum computer cannot extract information that does not exist in the observation. However, whether this property translates into practical quantum resistance across all attack scenarios has not been formally proven or independently verified.

| Quantum Algorithm | AES-CTR / ChaCha20 | ITB |
|---|---|---|
| **Grover** (brute-force) | Efficient oracle (single block verify); 2^128 for 256-bit key | No oracle (Core ITB) or expensive oracle (MAC-Inside: full decryption per query) |
| **Simon** (periodicity) | Relies on PRF/PRP computational strength | Conjectured mitigated: aperiodic config map (nonce per message) |
| **BHT** (collision finding) | Relies on PRF/PRP computational strength | Conjectured mitigated: Core/Silent Drop — container absorbs collisions; MAC + Reveal — encoding ambiguity (7 candidates) |
| **Quantum differential/linear** | Relies on PRF/PRP computational strength | Conjectured mitigated: Core/Silent Drop — container limits structural relations; MAC + Reveal — encoding ambiguity (7 candidates) |
| **Q2 superposition queries** | Theoretically applicable (oracle accepts superposition inputs) | Not applicable: MAC oracle is inherently classical (network request → accept/reject) |

**Q1 vs Q2 models.** In the Q2 model (quantum superposition queries to oracle), constructions such as Luby-Rackoff, Even-Mansour, and Keyed Sum of Permutations become vulnerable. ITB's MAC oracle is inherently classical — it accepts a concrete container over a network and returns accept/reject. Superposition queries are physically impossible. Core ITB and MAC + Silent Drop have no external oracle (if the attacker has insider knowledge of MAC presence, local verification is possible — see ‡‡). This means the Q2 model is inapplicable by design, not by cryptographic countermeasure.

The fundamental difference between ITB and traditional ciphers under quantum attack: AES and ChaCha20 rely on **computational hardness** — their security degrades with more computational power (Grover: √ speedup). ITB's barrier relies on **information absence** — no computation (classical or quantum) helps when the information is not in the observation. This is an information-theoretic property, not a computational assumption.

AES-256 and ChaCha20 are widely considered quantum-resistant for practical purposes (2^128 Grover bound). ITB's random-container architecture may provide an additional architectural layer of resistance to quantum structural algorithms, but this is a conjectured property that has not been independently verified. See [SCIENCE.md §2.11](SCIENCE.md#211-quantum-resistance-analysis) for detailed analysis. See also [SCIENCE.md §2.9.2](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier) for why KPA candidates do not break the barrier.

At 1024-bit key: Core/Silent Drop (P=196) ~2^2056 classical, ~2^1028 Grover. MAC + Reveal (P=400): ~2^1033 classical, ~2^516 Grover. At 2048-bit key: Core/Silent Drop (P=361) ~2^4104/~2^2052, MAC + Reveal (P=784): ~2^2058/~2^1029.

## 17. Maturity and Scope

ITB is a new construction without prior peer review or independent cryptanalysis. The contribution is theoretical: demonstrating that Full KPA resistance is 3-factor under PRF assumption (PRF non-invertibility + independent startSeed + per-pixel 1:1 ambiguity), with gcd(7,8)=1 byte-splitting as a 4th factor effective only under Partial KPA. PRF non-invertibility closes the candidate-verification step; architectural layers deny the attacker a usable reference pixel (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)). Performance is not a design goal.

| Aspect | Status |
|---|---|
| Peer review | None (first publication) |
| Independent cryptanalysis | None |
| Formal proof (simulation-based) | Planned (see [SCIENCE.md §7](SCIENCE.md#7-research-directions)) |
| Implementation audit | Not performed |
| Core barrier (∀v, ∀h : ∃c : embed(c,h,d)=v) | Noise absorption — compatibility proof, hash-independent ([Proof 1](PROOFS.md#proof-1-information-theoretic-barrier)) |
| Rotation barrier (7^P configurations) | Encoding ambiguity — 7 unverifiable rotations per pixel, PRF-dependent ([Proof 4](PROOFS.md#proof-4-rotation-barrier)) |
| Triple-seed isolation (I(dataSeed ; noiseSeed, startSeed) = 0) | Independent CSPRNG seeds, CCA/cache leaks contained ([Proof 3](PROOFS.md#proof-3-triple-seed-isolation)) |
| Active attack analysis (CCA, MITM) | Self-analysis, invites scrutiny |
| Side-channel mitigations | Implemented, not independently audited |

Potential vulnerability classes: (1) fundamental — barrier invalidation under unconsidered attack model (unlikely, barrier is probability-theoretic); (2) implementational — edge cases, timing, off-by-one (correctable). See [SCIENCE.md §4](SCIENCE.md#scope-and-maturity-disclaimer) "Scope and Maturity Disclaimer" for detailed discussion.

## 18. Bit Soup (Triple Ouroboros opt-in mode)

`SetBitSoup(1)` enables bit-granularity plaintext split for every Triple Ouroboros variant (`Encrypt3x*`, `EncryptAuthenticated3x*`, `EncryptStream3x*`). Under Bit Soup, no single snake holds a real plaintext byte — each snake's payload is a fixed public bit-permutation across three consecutive plaintext bytes. Bit Soup reduces SAT cryptanalysis to an under-determined instance under Partial KPA + realistic protocol traffic; the barrier is information-theoretic at the instance-formulation layer, not computational at the solver layer. Default `SetBitSoup(0)` leaves byte-level Triple Ouroboros shipped behaviour unchanged.

Ciphertext wire format is identical in both modes; no public header bit distinguishes them. See [ITB3.md](ITB3.md#bit-soup-bit-level-split-opt-in) for the accessible explanation and [REDTEAM.md Phase 2g](REDTEAM.md#phase-2g--multi-crib-kpa-against-fnv-1a--itb-sat-based) for the defensive framing in the SAT attack context.
