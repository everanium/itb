# ITB Security Reference

> **Disclaimer.** ITB is an experimental construction without peer review or formal certification. The information-theoretic barrier is a software-level property — it provides no guarantees against hardware-level attacks (DPA/SPA, Spectre, Meltdown, Rowhammer, cache timing, undiscovered side-channels). Non-cryptographic hash functions are intended solely for research purposes; using them in any real-world application is potentially dangerous and may compromise all security properties. For critical applications, use only PRF-grade hash functions. No warranty is provided.

Comprehensive security comparison tables for ITB (Information-Theoretic Barrier) across three composition modes: Core (no MAC), MAC + silent drop, MAC + reveal. For detailed proofs and analysis, see [SCIENCE.md](SCIENCE.md).

## 1. ITB Composition Modes

| Property | Core ITB (no MAC) | MAC + Silent Drop | MAC + Reveal |
|---|---|---|---|
| Integrity | ✗ | ✓ | ✓ |
| Deniability | ✓ Full (structural) | ✓ Full | ✓ Full (full-capacity MAC) |
| CCA oracle | No oracle exists | No oracle (silent) | Noise position only (noiseSeed) |
| noiseSeed config | ✓ Barrier intact | ✓ Barrier intact | ✗ Leaked via CCA |
| dataSeed config | ✓ Barrier intact | ✓ Barrier intact | ✓ **Independent** (zero CCA leak) |
| Data rotation + XOR | ✓ | ✓ | ✓ (rotation barrier) |
| Information-theoretic barrier† | ✓ Intact | ✓ Intact | ✓ dataSeed protected |
| Practical value of leak | — | — | Zero |

† Software-level property under the random-container model; no guarantees against hardware-level attacks (see Disclaimer).

## 2. Hash Function Requirements by Threat Model

Triple-seed architecture: noiseSeed (noise positions), dataSeed (rotation + XOR, zero side-channel), startSeed (pixel offset).

All five requirements apply universally to all three seeds in all modes.

| # | Requirement | Purpose |
|---|---|---|
| 1 | Full input sensitivity | Nonce participation, config diversity |
| 2 | XOR-chain survival | Prevent chain cancellation |
| 3 | Non-affine bit mixing | Prevent algebraic solving (Gröbner/SAT) |
| 4 | Avalanche | Prevent correlation and cube attacks |
| 5 | Non-invertibility | Prevent ChainHash inversion |
| — | PRF / PRP / PRG | Relaxed under the random-container model (PRF recommended) |
| — | Collision resistance | Relaxed (random container absorbs) |
| — | Bias / distribution | Relaxed (rotation barrier neutralizes) |
| — | Population count | Relaxed (XOR with random container absorbs) |
| — | Bit Independence (BIC) | Relaxed (stricter than assumed) |
| — | Sparse/dense key | Relaxed (random container hides config) |

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
| ITB | Requirements 1-5 (PRF recommended; weaker permitted for research) |

## 5. Authenticated Encryption Comparison

| Property | MtE (TLS 1.0) | OTR | Signal | AEAD (GCM) | ITB |
|---|---|---|---|---|---|
| Tag encrypted inside | ✓ | ✗ | ✗ | ✗ | ✓ |
| MAC covers padding | ✗ | — | — | ✓ | ✓ |
| Information-theoretic barrier† | ✗ | ✗ | ✗ | ✗ | ✓ |
| Oracle-free deniability | ✗ | Partial | Partial | ✗ | ✓ |
| CCA spatial pattern eliminated | ✗ | — | — | ✓ | ✓ |
| Resistant to padding oracle | ✗ | — | — | ✓ | ✓ |
| Hash requirement | PRF/PRP | PRF | PRF | PRP | Req 1-5 (PRF recommended) |
| Maturity / standardization | TLS 1.0-1.1 | OTR v3/v4 | Signal Protocol | NIST SP 800-38D | **None** |

† Software-level property under the random-container model; no guarantees against hardware-level attacks (see Disclaimer).

## 6. CCA Oracle Leak Comparison

| Scheme | CCA Leak (MAC result revealed) |
|---|---|
| AES-CBC + MAC-then-Encrypt‡ | Padding oracle → full plaintext (POODLE, Lucky13) |
| AES-CTR + MAC-then-Encrypt | Bit-flip oracle → data structure |
| ITB + MAC-inside (full capacity) | Noise position only (3 bits/pixel, no data) |
| AES-GCM (AEAD) | None (MAC rejects before decryption) |
| ChaCha20-Poly1305 (AEAD) | None (MAC rejects before decryption) |

‡ Deprecated construction (TLS 1.0/1.1, RFC 8996). Included for historical context only.

## 7. Attack Resistance Summary

| Attack | Core ITB | MAC + Silent Drop | MAC + Reveal | MAC + Reveal + KPA |
|---|---|---|---|---|
| Ciphertext-only (COA) | ✓ IT barrier† | ✓ IT barrier† | ✓ IT barrier† | ✓ IT barrier† |
| Known-plaintext (KPA) | ✓ IT barrier† | ✓ IT barrier† | ✓ Per-bit XOR | ✓ Per-bit XOR* |
| Chosen-plaintext (CPA) | ✓ Independent maps | ✓ Independent maps | ✓ Independent maps | ✓ Independent maps |
| Chosen-ciphertext (CCA) | ✓ No oracle | ✓ No oracle | noiseSeed leaked, dataSeed safe | noiseSeed leaked, dataSeed safe |
| Brute-force (classical) | 2^keyBits | 2^keyBits | 2^keyBits | 2^keyBits** |
| Brute-force (Grover) | 2^(keyBits/2) | 2^(keyBits/2) | 2^(keyBits/2) | 2^(keyBits/2)** |
| Map guessing | 2^(62P) | 2^(62P) | 2^(62P) | 2^(62P) |
| Nonce reuse | Two-time pad | Two-time pad | Two-time pad | Two-time pad |
| Bit-flipping | Undetected | Detected (MAC) | Detected (MAC) | Detected (MAC) |
| Padding oracle | N/A | N/A | ✓ No spatial pattern | ✓ No spatial pattern |
| Quantum structural (Simon, BHT) | Conjectured mitigated | Conjectured mitigated | Conjectured mitigated | Conjectured mitigated |

† IT barrier is a software-level property under the random-container model; no guarantees against hardware-level attacks (see Disclaimer).
\* Per-bit XOR hides XOR masks under passive observation; with invertible hash, seed recoverable via inversion (~P×2^14).
\** With invertible hash under KPA: seed recoverable in ~56 × P hash inversions (no CCA or startPixel required).

## 8. Information-Theoretic Barrier Metrics

### Container Bit Accounting (per pixel)

| Metric | Bits | Percentage |
|---|---|---|
| Total container bits | 64 | 100% |
| Data bits | 56 | 87.5% |
| Noise bits | 8 | 12.5% |

### Configuration Bit Accounting (per pixel, triple-seed: noise + data)

| Source | Config bits | CCA leak | Protected |
|---|---|---|---|
| noiseSeed (noise position) | 3 | 3 (100% of noiseSeed) | 0 |
| dataSeed (rotation + XOR) | 59 | **0** (independent seed) | **59 (100%)** |
| **Total** | **62** | **3 (4.8%)** | **59 (95.2%)** |

### Barrier Strength at Minimum Container (512-bit key)

| Metric | Value |
|---|---|
| MinPixels | 74 → 81 (9×9) |
| Noise barrier | 2^648 |
| Landauer limit | ~2^306 |
| Beyond Landauer | 2.1× (648/306) |
| Config map space | 2^5022 |
| Key space | 2^512 |

### Practical Value of ~5% CCA Leak

| Information | Gained by attacker? |
|---|---|
| Plaintext bits | Zero |
| XOR mask bits | Zero |
| Start pixel | Unknown |
| Key-space reduction | Zero |
| Brute-force speedup | Per-candidate (cheaper reject, same search space) |
| Grover reduction | Zero (2^(keyBits/2) unchanged) |

## 9. Noise-Density Optimality (Why 8/1)

| Format | Data/px | Noise/px | Overhead | CCA Config Leak | Barrier (512-bit, min) |
|---|---|---|---|---|---|
| 8/1 (ITB) | 56 | 8 | 1.14× | 4.8% | 2^648 |
| 6/2 | 48 | 16 | 1.33× | 8.9% | 2^1296 |
| 5/3 | 40 | 24 | 1.60× | 12.2% | 2^1944 |
| 4/4 | 32 | 32 | 2.00× | 17.1% | 2^2592 |

8/1 is Pareto-optimal among the analyzed noise-density configurations. All barriers exceed the Landauer limit.

## 10. Effective Key Size by Hash Function

| Hash Function | Output Width | API | Components | Nominal Key | Effective Bound |
|---|---|---|---|---|---|
| XXH3, HighwayHash-64 | 64 bits | `Encrypt` | 8 | 512 bits | 512 bits |
| SipHash-2-4, AES-CMAC, HighwayHash-128 | 128 bits | `Encrypt128` | 16 | 1024 bits | 1024 bits |
| HighwayHash-256, BLAKE2b, BLAKE2s, BLAKE3 | 256 bits | `Encrypt256` | 32 | 2048 bits | 2048 bits |
| BLAKE2b-512 | 512 bits | `Encrypt512` | 32 | 2048 bits | 2048 bits |

### Seed Alignment by Width

| Seed Type | Hash Type | Bits Alignment | Components per Round | Components Alignment |
|---|---|---|---|---|
| `Seed` | `HashFunc` (64-bit) | ×64 | 1 | any |
| `Seed128` | `HashFunc128` (128-bit) | ×128 | 2 | even |
| `Seed256` | `HashFunc256` (256-bit) | ×256 | 4 | ×4 |
| `Seed512` | `HashFunc512` (512-bit) | ×512 | 8 | ×8 |

## 11. Hash Function Excluded Class

| # | Excluded Function Type | Failure Mode | Applicable When |
|---|---|---|---|
| 1 | Constant functions | All pixels identical config | Always |
| 2 | XOR-cancelling (seed ⊕ f(data)) | Chain cancellation, identical configs | Always |
| 3 | Partial-input (reads only data[0]) | Nonce ignored, cross-message reuse | Always |
| 4 | Purely affine (h = h×c + byte) | Algebraic tractability (Gröbner/SAT) | MAC + reveal |
| 5 | No avalanche | Correlation/cube attacks | MAC + reveal |
| 6 | Invertible (seed from output+data) | Seed recovery via KPA + inversion | MAC + reveal + KPA |

## 12. MAC Placement Design Space

| MAC Placement | Covers Noise | Deniability | CCA Leak | Circular Dependency |
|---|---|---|---|---|
| **Inside (full capacity)** | **No** | **✓ Preserved** | **Noise position only** | **None** |
| *Inside (plaintext only)* | *No* | *✓ Preserved* | *Noise pos + spatial* | *None* |
| Outside (header) | Yes | ✗ Broken | None | Verification oracle |
| Inside (full container) | N/A | N/A | N/A | Tag invalidates itself |

**Bold:** implemented by `EncryptAuthenticated`. *Italic:* theoretical alternative, not implemented.

## 13. Known Theoretical Threats

| Threat | Exploit requires | Practical risk | Mitigation |
|---|---|---|---|
| rotateBits7 shift timing (DPA/SPA class) | Oscilloscope on CPU die, >10GHz, lab access | Same class as DPA on any cipher | Register-only, no software side-channel |
| Container size metadata | Network observation | Metadata only | Inherent to all ciphers, no crypto advantage |
| Non-CSPRNG container | Deployer misconfiguration | Degrades barrier | crypto/rand mandatory, non-CSPRNG unsupported |
| COBS decode truncation | Wrong seed / tampered data | None | Downstream null check returns "wrong seed" error |
| Bit-flip false null (DoS) | Data bit modification | None (with MAC) | MAC verified before null search; noise flips harmless |
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

Both backends produce identical ciphertext. Switching between `CGO_ENABLED=0` (pure Go) and `CGO_ENABLED=1` (C + SIMD) does not change the security model on any platform. See SCIENCE.md §4 "Known Theoretical Threats" point 6 for detailed analysis.

## 14. Hash Function Compliance

Production hash functions (XXH3, SipHash-2-4, AES-CMAC, HighwayHash, BLAKE2b, BLAKE2s, BLAKE3) satisfy all five requirements. Tests and benchmarks cover all listed hash functions across 64/128/256/512-bit widths.

## 15. Security Properties Summary

| Property | ITB |
|---|---|
| Key space | Up to 2^2048 |
| Grover resistance | 2^(keyBits/2) iterations × O(P) hash calls each |
| Oracle-free deniability | ✓ (structural) |
| Known-plaintext resistance | Under passive observation (IT barrier) |
| Chosen-plaintext resistance | Independent maps |
| Information-theoretic barrier* | dataSeed 100% protected under the random-container model |
| Noise barrier (min container) | 2^648 (512-bit) to 2^2592 (2048-bit) |
| Storage overhead | 1.14× (56 data bits per 64-bit pixel) |
| Hash function requirement | Requirements 1-5 (PRF recommended; weaker permitted for research) |
| Nonce | 128-bit per-message (mandatory) |
| Authentication | Optional (MAC-inside-encrypt, pluggable) |
| Deniable authentication | ✓ (tag encrypted inside container) |
| Quantum structural attacks | Conjectured mitigated (IT barrier is computation-model-independent; not independently verified) |
| Grover oracle | Degraded: no oracle without MAC; with MAC-inside each query requires full decryption O(P) |

\* Software-level property under the random-container model. No guarantees against hardware-level attacks (see Disclaimer).

## 16. Quantum Resistance (Conjectured)

The information-theoretic barrier is computation-model-independent: provided the container is generated from a source indistinguishable from true uniform randomness, every observed byte value is compatible with every possible hash output (∀v, ∀h : ∃c : embed(c,h,d)=v), regardless of classical, quantum, or any future computational model. A quantum computer cannot extract information that does not exist in the observation. However, whether this property translates into practical quantum resistance across all attack scenarios has not been formally proven or independently verified.

| Quantum Algorithm | AES-CTR / ChaCha20 | ITB |
|---|---|---|
| **Grover** (brute-force) | Efficient oracle (single block verify); 2^128 for 256-bit key | No oracle (core) or expensive oracle (MAC-inside: full decryption per query) |
| **Simon** (periodicity) | Relies on PRF/PRP computational strength | Conjectured mitigated: aperiodic config map (nonce per message) |
| **BHT** (collision finding) | Relies on PRF/PRP computational strength | Conjectured mitigated: random container absorbs collisions |
| **Quantum differential/linear** | Relies on PRF/PRP computational strength | Conjectured mitigated: random container limits structural relations |
| **Q2 superposition queries** | Theoretically applicable (oracle accepts superposition inputs) | Not applicable: MAC oracle is inherently classical (network request → accept/reject) |

**Q1 vs Q2 models.** In the Q2 model (quantum superposition queries to oracle), constructions such as Luby-Rackoff, Even-Mansour, and Keyed Sum of Permutations become vulnerable. ITB's MAC oracle is inherently classical — it accepts a concrete container over a network and returns accept/reject. Superposition queries are physically impossible. Core ITB (without MAC) has no oracle at all. This means the Q2 model is inapplicable by design, not by cryptographic countermeasure.

AES-256 and ChaCha20 are widely considered quantum-resistant for practical purposes (2^128 Grover bound). ITB's random-container architecture may provide an additional architectural layer of resistance to quantum structural algorithms, but this is a conjectured property that has not been independently verified. See SCIENCE.md §2.12 for detailed analysis.

At 512-bit key: 2^256 Grover. At 2048-bit key: 2^1024.

## 17. Maturity and Scope

ITB is a new construction without prior peer review or independent cryptanalysis. The contribution is theoretical: demonstrating that KPA resistance under passive observation is achievable with minimal hash function requirements (PRF/PRP/PRG relaxed under the random-container model) through an information-theoretic barrier. Performance is not a design goal.

| Aspect | Status |
|---|---|
| Peer review | None (first publication) |
| Independent cryptanalysis | None |
| Formal proof (simulation-based) | Planned (see SCIENCE.md §7) |
| Implementation audit | Not performed |
| Core barrier (∀v, ∀h : ∃c : embed(c,h,d)=v) | Compatibility proof, hash-independent |
| Active attack analysis (CCA, MITM) | Self-analysis, invites scrutiny |
| Side-channel mitigations | Implemented, not independently audited |

Potential vulnerability classes: (1) fundamental — barrier invalidation under unconsidered attack model (unlikely, barrier is probability-theoretic); (2) implementational — edge cases, timing, off-by-one (correctable). See SCIENCE.md §4 "Scope and Maturity Disclaimer" for detailed discussion.
