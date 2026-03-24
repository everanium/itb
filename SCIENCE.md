# ITB: Scientific Analysis

> **Disclaimer.** ITB is an experimental construction without peer review or formal certification. The information-theoretic barrier is a **software-level** property — it provides no guarantees against hardware-level attacks (DPA/SPA, Spectre, Meltdown, Rowhammer, cache timing, undiscovered side-channels). PRF-grade hash functions are required. No warranty is provided.

## Abstract

ITB (Information-Theoretic Barrier) is a parameterized symmetric cipher construction that achieves key sizes up to 2048 bits through chained hashing of independent key components. The random container creates an information-theoretic barrier between the construction's internal state and the observer, providing known-plaintext resistance under passive observation in the random-container model. PRF-grade hash functions are required. The barrier architecturally hardens the PRF by making hash output unobservable — an approach not previously formalized in symmetric cryptography. To my knowledge, no published symmetric cipher construction makes the primitive output architecturally unobservable.

## 1. Construction

### 1.1 ChainHash

Let H: {0,1}* × {0,1}^w → {0,1}^w be a keyed PRF-grade hash function with output width w bits (w ∈ {128, 256, 512}). Let S = (s_0, s_1, ..., s_{n-1}) be a seed of n independent uint64 components, where n = keyBits / 64.

ChainHash is defined as:

```
h_0 = H(data, s_0)
h_i = H(data, s_i ⊕ h_{i-1})    for i = 1, ..., n-1
ChainHash(data, S) = h_{n-1}
```

Each round consumes one component and the previous round's output. The XOR mixing of s_i with h_{i-1} ensures that all components influence the final output, and no component can be evaluated independently without knowledge of all preceding components' outputs.

### 1.1.1 ChainHash128

For 128-bit hash functions H128: {0,1}* × {0,1}^64 × {0,1}^64 → {0,1}^64 × {0,1}^64, the chain consumes 2 components per round with 128-bit intermediate state:

```
(hLo, hHi) = H128(data, s[0], s[1])
(hLo, hHi) = H128(data, s[2] ⊕ hLo, s[3] ⊕ hHi)
...
ChainHash128(data, S) = (hLo, hHi)  after n/2 rounds
```

Effective security: min(keyBits, 128 × numRounds). For 1024-bit key (16 components, 8 rounds): 1024-bit effective security (no bottleneck). Target hash functions: SipHash-2-4, AES-CMAC.

### 1.1.2 ChainHash256

For 256-bit hash functions H256: {0,1}* × {0,1}^256 → {0,1}^256, the chain consumes 4 components per round with 256-bit intermediate state:

```
h = H256(data, [s[0], s[1], s[2], s[3]])
h = H256(data, [s[4] ⊕ h[0], s[5] ⊕ h[1], s[6] ⊕ h[2], s[7] ⊕ h[3]])
...
ChainHash256(data, S) = h  after n/4 rounds
```

Effective security: min(keyBits, 256 × numRounds). For 2048-bit key (32 components, 8 rounds): 2048-bit effective security (no bottleneck). Target hash function: BLAKE3 keyed mode.

### 1.1.3 Per-Pixel Config Extraction and Effective Security

All three ChainHash variants produce wider output than needed for per-pixel configuration (only 62 bits required: 3 noise-position + 59 data-config). For ChainHash128, the low 64-bit half is used. For ChainHash256, element [0] of the [4]uint64 output is used. For ChainHash512, element [0] of the [8]uint64 output is used.

**Why extracting 64 bits from a wider hash preserves full effective key size.**

The effective key size is determined by two independent properties:

1. **Meet-in-the-middle resistance (intermediate state width).** A MITM attacker splits the chain at round k, enumerating forward partial keys (s_0..s_{k-1}) and backward partial keys (s_k..s_{n-1}), seeking a match on the intermediate state h_k. The bottleneck is the width of h_k — not the width of the extracted output. With 128-bit state (ChainHash128): 2^128. With 256-bit state (ChainHash256): 2^256. With 512-bit state (ChainHash512): 2^512. The 64-bit extraction is a post-chain operation that does not widen this bottleneck.

2. **Multi-call key discrimination.** Each pixel provides a 64-bit observation from an independent data input (counter || nonce). Across P pixels, the collective constraint is P × 64 bits. Two distinct keys produce the same 64-bit extraction on one pixel with probability 2^(-64); on all P pixels: 2^(-64P). At minimum container size:

    | Key size | Hash width | MinPixels | Container (square) | Constraint bits (P × 64) | Key bits |
    |---|---|---|---|---|---|
    | 1024 | 128 | 147 | 13×13 = 169 | 10816 | 1024 |
    | 2048 | 256 | 293 | 18×18 = 324 | 20736 | 2048 |
    | 2048 | 512 | 293 | 18×18 = 324 | 20736 | 2048 |

    In all cases, constraint bits >> key bits. The probability of two distinct keys producing identical observations across all pixels is negligible (2^(-5184) to 2^(-20736)), providing full key space discrimination.

**Conclusion.** The 64-bit per-pixel extraction does not reduce effective security for any hash width. The chain operates at full width internally, and MITM bottleneck equals the intermediate state width. Multi-call observations provide sufficient constraints for complete key discrimination at all widths. Based on the multi-call discrimination argument, the effective key sizes (1024/2048 bits) are expected to be fully realized for all widths.

### 1.1.4 Wider Hash Variants: Fewer Rounds, Wider MITM Bottleneck

A counterintuitive property of the ChainHash construction: wider hash variants process the same key material in fewer rounds, while providing a wider MITM bottleneck.

For a 512-bit key (8 components):

| ChainHash | Components/round | Rounds | Hash calls/pixel | MITM bottleneck |
|---|---|---|---|---|
| 128-bit | 2 | 4 | 4 | 2^128 |
| 256-bit | 4 | **2** | **2** | **2^256** |
| 512-bit | 8 | **1** | **1** | **2^512** |

All 8 components are consumed in every case — no key material is skipped. The difference is how many components are processed **simultaneously** per hash call.

**Why fewer rounds is not weaker:**

1. **Same total key material.** All 8 components pass through the chain regardless of width. ChainHash256 processes [s_0, s_1, s_2, s_3] in one call, then [s_4⊕h_0, s_5⊕h_1, s_6⊕h_2, s_7⊕h_3] in the next. No component is excluded.

2. **Wider intermediate state.** MITM requires enumerating possible intermediate values at a split point. With 256-bit state: 2^256 values. With 128-bit: 2^128. Wider state provides a harder MITM target.

3. **Fewer split points.** MITM can split the chain at any round boundary. 8 rounds = 7 potential split points. 2 rounds = 1 split point. Fewer options for the attacker.

4. **Deeper per-round mixing.** A 256-bit hash function internally mixes all 4 input components simultaneously through its non-linear structure (e.g., BLAKE3: 256-bit state with SIMD permutations). This is equivalent to or stronger than sequential processing through a narrower bottleneck.

**Performance consequence.** Each hash call has fixed overhead (state initialization, finalization). With heavy hash functions (BLAKE3: ~300ns/call, BLAKE2b: ~200ns/call), the round count dominates performance. ChainHash256 with 2 rounds is ~2× faster than ChainHash128 with 4 rounds for the same key size — while simultaneously providing a wider MITM bottleneck.

This property does not apply to lightweight hash functions (SipHash-2-4: ~10ns/call) where per-call overhead is negligible compared to pixel processing.

### 1.2 Per-Pixel Configuration

For an RGBWYOPA container of W × H pixels (8 channels per pixel), let N be a 128-bit nonce from crypto/rand.

**Start pixel:** `p_start = ChainHash(0x02 || N, startSeed) mod (W × H)`

**Per-pixel configuration:** For each pixel p, two independent ChainHash calls:
```
noiseHash = ChainHash(counter(p) || N, noiseSeed)    // 64-bit output
dataHash  = ChainHash(counter(p) || N, dataSeed)     // 64-bit output (independent seed)
```

From noiseSeed (3 config bits):
```
noise_pos = noiseHash & 7              // 0-7: noise bit position in channel
```

From dataSeed (59 config bits):
```
data_rotation = dataHash % 7           // 0-6: rotation amount (log₂7 ≈ 2.807 bits of entropy)
xor_bits = dataHash >> 3               // 56 XOR mask bits (nearly independent of rotation for PRF output)
channel_xor = (xor_bits >> (ch × 7)) & 0x7F   // per-channel 7-bit XOR mask
```

Each 8-bit channel carries 7 data bits and 1 noise bit. The noise_pos selects which of 8 bit positions (0-7) is the noise bit; the remaining 7 positions carry data. No bit position is deterministically data from the public format. Each data bit is XOR'd with its own independent mask bit from channel_xor. The container is generated from crypto/rand, ensuring the original pixel values are uniformly random.

**Per-pixel capacity:** 8 channels × 7 data bits = 56 data bits per pixel.
**Per-pixel noise:** 8 channels × 1 noise bit = 8 noise bits per pixel.
**Overhead:** 64/56 = 1.14×.

### 1.3 Message Framing

```
payload = COBS(message) || 0x00
```

COBS (Consistent Overhead Byte Stuffing) encodes arbitrary binary data so that 0x00 never appears in the encoded output. The null terminator 0x00 is unambiguous. Remaining capacity is filled with crypto/rand. Under encryption, the terminator becomes indistinguishable from other bytes.

### 1.4 Nonce Requirement

The nonce is mandatory. Without it, two messages encrypted with the same seed produce identical pixel configuration maps. An attacker observing two containers can XOR corresponding extracted bits to cancel the per-pixel XOR masks, obtaining data1 ⊕ data2 — a two-time pad at the bit level. The 128-bit nonce ensures with overwhelming probability that each message receives a unique configuration map (birthday collision at ~2^64 messages).

## 2. Security Analysis

### 2.1 Key Space

The construction's key space is 2^(64n) where n = number of components. Effective security is bounded by the internal state width of H.

**Single-call bottleneck.** After processing components s_0 through s_{k-1}, the intermediate state h_{k-1} is a single output of H — w bits wide. If two different partial keys produce the same h_{k-1}, remaining components cannot distinguish them. This limits a single ChainHash evaluation to w bits of effective key discrimination, where w is the hash output width. For ChainHash128: w = 128. For ChainHash256: w = 256. For ChainHash512: w = 512.

**Multi-call recovery.** ITB evaluates ChainHash independently for each pixel with different data inputs (counter || nonce). Collisions that exist for one data input do not persist across different inputs when the hash uses non-linear mixing (addition, multiplication), because XOR-of-sums is not translation-invariant. For all hash widths, only 64 bits of the output are extracted per pixel for config (Section 1.1.3). With P pixels, the collective constraint is P × 64 bits, which exceeds the key space at minimum container size (see Section 1.1.3 table).

For example, with a 128-bit hash and 1024-bit key (16 components): a single ChainHash128 call provides 128 bits of discrimination. But the minimum container has 147 pixels = 147 independent calls, providing 147 × 64 = 9408 constraint bits >> 1024 key bits. The full key space is utilized in all variants.

**Effective security by hash width:**

| Hash output width w | ChainHash | Components n | Nominal key bits | Effective bound |
|---|---|---|---|---|
| 128 (SipHash-2-4, AES-CMAC) | ChainHash128 | 16 | 1024 | 1024 |
| 256 (BLAKE3) | ChainHash256 | 32 | 2048 | 2048 |
| 512 (BLAKE2b) | ChainHash512 | 32 | 2048 | 2048 |

**Note:** The effective bound assumes the recommended component count for each hash width. Using more components than the hash can discriminate per call may not increase security proportionally, as it depends on the multi-call recovery rate for the specific hash function.

### 2.2 Brute-Force Resistance

**Classical.** An attacker must try all 2^(64n) seeds. Each attempt requires full extraction from the container. No shortcut is known.

**Meet-in-the-middle resistance.** Three independent barriers prevent MITM on ChainHash:

1. **Hash output unobservable.** The hash output is consumed by modification of a random container pixel (crypto/rand, never transmitted). The attacker observes the modified pixel but cannot reconstruct the hash output — the original pixel value is unknown. Without observing the chain's final output, the attacker cannot begin the "meet" step.

2. **Non-invertibility (PRF property).** Classical MITM splits the chain at intermediate state h_k, computing forward from the start and backward from the observation. The backward step requires inverting the hash at each chain position. With non-invertible hash, backward computation is infeasible. The attacker must enumerate all 2^w possible intermediate states (where w is the hash output width) for each second-half key, degrading MITM to cost 2^(keyBits/2 + w) — worse than brute force when keyBits ≤ 2w. For ChainHash128 (w=128, keyBits≤1024) and wider: this barrier alone is sufficient.

3. **Multi-call key discrimination.** Even if the hash were invertible and the output observable: a single ChainHash call with w-bit output distinguishes at most 2^w of 2^keyBits keys. But minimum container size guarantees P independent calls, providing P × w constraint bits >> keyBits. Collisions for one data input do not persist across different inputs (non-linear mixing). With P = 169 pixels and w = 128: 10816 constraint bits >> 1024 key bits. Key discrimination is expected to be complete regardless of intermediate state width, assuming hash collisions across independent inputs are uncorrelated.

Together, the three barriers are designed to make MITM harder than brute force at all supported key sizes.

**Quantum (Grover).** Grover complexity is O(2^(keyBits/2)) iterations, each requiring O(P) hash evaluations for full container decryption (where P = pixel count). At 1024 bits: 2^512 iterations — computationally infeasible with any foreseeable technology. At 2048 bits: 2^1024 — far beyond the Landauer thermodynamic limit (~2^306). Note that AES-256 with Grover bound 2^128 is widely considered quantum-resistant for practical purposes.

The oracle required by Grover is degraded under ITB's oracle-free design: no checksums, no headers, no magic bytes. The null terminator is encrypted and invisible without the correct seed.

### 2.3 Oracle-Free Deniability

Oracle-free deniability means no verification mechanism exists to distinguish correct from incorrect decryption — the attacker has no oracle to query.

ITB includes no verification metadata:

- No magic bytes or file format signatures.
- No message length header.
- No checksum or MAC.
- Null terminator encrypted — invisible without correct seed.
- No padding — triple-seed rotation barrier provides protection without padding schemes.

**Consequence:** given container C and candidate seed S', extraction produces some byte sequence D. The attacker has no efficient way to determine if D is the true plaintext or random noise. Every seed produces a "plausible" extraction. Under the random-container model, the construction is designed to provide indistinguishability under ciphertext-only attack.

### 2.4 Information-Theoretic Barrier and Hash Requirements

The random container creates an information-theoretic barrier between the construction's internal state and the observer. This barrier is the construction's central design idea. PRF-grade hash functions are required. The barrier provides additional architectural hardening by making hash output unobservable (Section 2.10, Definition 2).

#### 2.4.1 The Barrier: Passive Observation

**Claim.** Under passive observation (ciphertext-only and known-plaintext attacks), the hash output is not reconstructible from the container, regardless of hash function properties.

**Proof sketch.** The container C is generated from crypto/rand — each pixel byte is independently uniformly distributed. Consider the attacker's view of a single pixel (x, y) with observed channel value v.

The hash produced ChainHash(counter || nonce, seed) = h, from which noise_pos and per-bit xor masks were extracted.

**The attacker observes v but does not know:**
1. The original container value c at this pixel (crypto/rand, never transmitted).
2. Which noise_pos was selected (0-7).
3. What xor value was applied.
4. What data_bit was written.

Four unknowns, one observation — maximally underdetermined.

**Formal argument.** Let C[p,ch] ~ Uniform(0, 255) be the original container byte at pixel p, channel ch. Let C'[p,ch] be the byte after embedding. For ANY hash function H, every observed byte value is compatible with every possible hash output:

```
∀v, ∀h : ∃c : embed(c, h, d) = v
```

The original container byte C[p,ch] is uniformly random and never transmitted to the observer. Since the observer does not know C, any observed value v is consistent with any hash output h — no single-byte observation narrows the set of possible hash outputs. Under passive observation (COA, KPA), security is conjectured to reduce to key space exhaustion alone.

**Architectural difference from stream ciphers.** In widely deployed stream cipher constructions (ChaCha20, AES-CTR, Salsa20), keystream is XOR'd with plaintext directly — a well-studied design with robust security guarantees when the underlying primitive is strong. ITB takes a different architectural approach: it interposes a random container between the hash output and the observer.

#### 2.4.2 Beyond the Barrier: Active Attacks and Side Channels

The barrier ensures that hash output is unobservable under passive attacks (the *random-container model*: the container is generated from a CSPRNG and the original pixel values are never transmitted to the attacker). However, active attacks (CCA) and side channels can bypass the barrier by obtaining partial information about the hash configuration through non-observational means:

- **CCA with MAC-reveal** (Section 4.1–4.5): bit-flip oracle reveals noise positions (noiseSeed config, 3 bits/pixel).
- **Local CCA simulation**: attacker running on the same CPU can simulate CCA without a MAC oracle by encrypting with candidate seeds and comparing container patterns.
- **Cache side-channel** (Section 4, startPixel limitation): memory access patterns leak startPixel.
- **KPA + invertible hash**: with known plaintext and an invertible hash, the attacker tries all startPixel positions (P candidates) × 56 candidate configurations per pixel (8 noisePos × 7 rotation), computes candidate dataHash for each, inverts ChainHash → recovers dataSeed in ~56 × P hash inversions (P startPixel candidates × 56 configs, one reference pixel per candidate, verified by forward evaluation on a second pixel). This attack requires neither CCA nor startPixel knowledge. No architectural layer (noise, rotation, byte-splitting, startPixel) prevents this attack — all are defence-in-depth for non-invertible hash. Non-invertibility (PRF property) is the sole defense for the information-theoretic barrier.
- **MITM backward step** (Section 2.2): meet-in-the-middle on ChainHash requires inverting the hash at each chain position.

These attack vectors are blocked by PRF properties of the hash function, not by the barrier:

| PRF property | Blocks | Without it |
|---|---|---|
| Full input sensitivity | Nonce bypass | Same config for different nonces |
| Chain survival | XOR-cancellation | All pixels identical config |
| Non-affine mixing | Algebraic solving under CCA constraints | Gröbner basis / SAT solver recovers seed |
| Avalanche | Correlation / cube attacks | Correlated outputs → local CCA simulation |
| Non-invertibility | KPA + inversion, MITM backward step | Seed recovery in polynomial time |

**The barrier and PRF are complementary (symbiosis).** PRF-grade hash functions are required. The two properties protect each other: (1) PRF non-invertibility protects the barrier by preventing KPA candidate verification (56-candidate ambiguity unresolvable); (2) the barrier protects the PRF by absorbing hash collisions — the only theoretical weakness of a non-invertible hash. In a traditional cipher, collisions may be exploitable (the attacker observes the output directly). In ITB, two pixels with the same dataHash have different original container bytes (CSPRNG), making the collision invisible. Together, they address all analyzed threat models (COA, KPA, CPA, CCA, side-channel). In core ITB and MAC + Silent Drop (no oracle, passive observation only), the symbiosis makes the non-invertible hash function indistinguishable from an ideal random function — collisions absorbed, statistical patterns absorbed. With MAC + Reveal (CCA): noiseSeed config is leaked via oracle interaction, but dataSeed remains protected by PRF non-invertibility and triple-seed isolation.

### 2.5 Nonce Reuse Analysis

Each encryption generates a fresh 128-bit nonce from crypto/rand. Two encryptions with the same seed but different nonces produce independent configuration maps. By the birthday bound, nonce collision probability reaches ~50% after 2^64 messages. For practical safety margins, ~2^48 messages keep collision probability below 2^(−32).

**Impact of nonce collision:** attacker obtains two containers with the same hash configuration but different random containers. Per-pixel XOR masks cancel when comparing extracted bits — yielding data1 ⊕ data2. This is a two-time pad. The mandatory nonce prevents this.

### 2.6 Resistance to Known-Plaintext Attack

Even with fully known plaintext, the attacker cannot derive hash outputs because the original container pixel values are unknown (crypto/rand, never transmitted). Known-plaintext attack degrades to brute-force regardless of hash function properties.

Two barriers stand between the attacker and the hash outputs:
1. Unknown pixel position — seed-dependent start pixel and wrap-around make bit locations unknown.
2. Unknown original pixel value — crypto/rand container never transmitted.

### 2.7 Chosen-Plaintext Attack Resistance

Attacker can encrypt with their own seed and study their own configuration map. Knowledge of map_A (for seed_A) provides zero information about map_B (for seed_B), assuming independently generated seeds.

### 2.8 Map Guessing Attack

Instead of brute-forcing the seed, directly guess the per-pixel configuration map. Map space = 2^(62P) where P = pixel count (62 config bits per pixel: 3 noise-position + 3 data-rotation + 56 per-bit XOR). For minimum 1024-bit key container (P = 169, 13×13): 2^10478 >> 2^1024. Map guessing is astronomically harder than seed brute-force.

### 2.9 Per-Bit XOR and Known-Plaintext Resistance

**Design choice.** Each data bit has its own independent XOR mask bit (1:1 ratio), requiring 56 XOR bits + 3 rotation bits from dataSeed (59 of 64 bits) and 3 noise-position bits from noiseSeed. Total: ~62 config bits per pixel from two ChainHash calls (exact: log₂(8 × 7 × 2^56) = 61.807; 62 is the ceiling used for bit extraction).

**Rationale.** With per-channel XOR (1:7 ratio, 8 XOR bits per pixel for 8 channels), an attacker with known plaintext can efficiently determine the per-pixel configuration:

- Each channel has 7 data bits and 1 XOR bit that inverts all 7 simultaneously.
- Only 2 of 128 possible 7-bit patterns per channel are consistent with known data (original or fully inverted).
- P(wrong pixel position matches) ≈ (2/128)^8 = 2^{-48} — the attacker identifies the start pixel from a single pixel of known data.
- Once the start pixel is known, the full configuration map (bit-planes, XOR masks) and hence ChainHash outputs are recoverable.

This would degrade known-plaintext resistance from information-theoretic to computational, contradicting the construction's core security claim.

**Per-bit XOR (1:1) is designed to prevent this attack:**

- Each of the 7 data bits per channel has an independent XOR mask bit.
- For any observed channel value and any known plaintext, there exists a 7-bit XOR mask that produces consistency.
- P(single channel consistent with wrong position) = 1 — every position matches.
- Cross-channel independence: each channel has its own 7 XOR bits (56 independent bits total), so no cross-channel constraint allows filtering.
- The attacker cannot determine start pixel, bit-plane, or any configuration from known plaintext.

**Comparison of XOR strategies under known-plaintext attack:**

| Strategy | Config bits/pixel | P(wrong pixel consistent) | KPA resistance |
|---|---|---|---|
| No XOR | 6 (3 noise + 3 rotation) | ≈ 2^{-56} per config | Computational |
| 1:7 per-channel | 14 (3 noise + 3 rotation + 8 XOR) | ≈ 2^{-48} per config | Computational |
| **1:1 per-bit (ITB)** | **62 (3 noise + 3 rotation + 56 XOR)** | **1 (always consistent)** | **Information-theoretic** |

**Cost.** Two ChainHash calls per pixel (noiseSeed + dataSeed). For 1 MB of data with 8 channels: ceil(1048576 × 8 / 56) = ~149797 pixels × 2 = ~300K hash calls. Each pixel is independent — parallelizable across goroutines.

**Formal statement.** For per-bit XOR with random container:

```
∀ plaintext d, ∀ observed v, ∃ xor_mask :
    encode(d, xor_mask, bit_plane) is consistent with v
```

Known plaintext does not uniquely determine the per-pixel configuration: each pixel observation is consistent with 56 candidate configurations (8 noisePos × 7 rotation) without CCA, or 7 candidates (rotation only) when CCA reveals noisePos, and per-bit XOR ensures all candidates are valid. Multi-pixel key recovery requires computational search over the key space. Under passive observation, per-pixel security is information-theoretic; full-container security reduces to key space exhaustion.

### 2.9.1 Byte-Splitting Property (7/8 Non-Alignment)

A structural consequence of the RGBWYOPA 8/1 format: since `DataBitsPerChannel = 7` and `BitsPerByte = 8`, and `gcd(7, 8) = 1` (coprime), plaintext bytes never align with channel boundaries. Every plaintext byte is split across exactly 2 channels with a cyclically shifting split ratio.

**Split pattern.** For plaintext byte at position k in the data stream:

```
Byte 0:  [7 bits in Ch₀] [1 bit in Ch₁]     split 7/1
Byte 1:  [6 bits in Ch₁] [2 bits in Ch₂]    split 6/2
Byte 2:  [5 bits in Ch₂] [3 bits in Ch₃]    split 5/3
Byte 3:  [4 bits in Ch₃] [4 bits in Ch₄]    split 4/4
Byte 4:  [3 bits in Ch₄] [5 bits in Ch₅]    split 3/5
Byte 5:  [2 bits in Ch₅] [6 bits in Ch₆]    split 2/6
Byte 6:  [1 bit in Ch₆]  [7 bits in Ch₇]    split 1/7
Byte 7:  [7 bits in Ch₈] [1 bit in Ch₉]     split 7/1 (cycle repeats)
```

**Formal property:**

```
∀ plaintext byte b_k :
    b_k is embedded as fragment(C_i, 8 - offset_k) ∥ fragment(C_{i+1}, offset_k)
    where offset_k = (k × 8) mod 7
    each fragment independently XOR'd with per-channel mask and rotated
```

**Consequences:**

1. **Each plaintext byte is split across exactly 2 channels** — never 1, never 3. Maximum 2 because `DataBitsPerChannel (7) ≥ BitsPerByte - 1 (7)`.

2. **Each channel contains bits from 2 adjacent plaintext bytes** — mixed within a single 7-bit data unit, independently XOR'd and rotated. The attacker cannot isolate a single plaintext byte from one channel observation.

3. **Split ratio never repeats for adjacent bytes** — because `gcd(7, 8) = 1`, the cycle length is 7 before repeating. No two adjacent plaintext bytes share the same split pattern.

4. **Per-channel XOR masks are independent** — the two fragments of a plaintext byte are encrypted with different 7-bit XOR masks (extracted from different positions in the dataSeed hash output). Knowing one fragment's mask provides zero information about the other.

**Impact on attack complexity:**

| Attack scenario | Without byte-splitting | With byte-splitting (ITB) |
|---|---|---|
| Full KPA + CCA + startPixel (worst case) | 7 candidates per pixel (noisePos known from CCA) | 7 candidates per pixel (attacker knows both adjacent bytes) |
| Partial KPA (knows byte k, not k±1) | 56 candidates per pixel | Cannot compute expected channel bits (channel mixes 2 bytes, one unknown) |
| Full KPA + startPixel (no CCA) | 56 candidates per pixel (noisePos unknown) | 56 candidates (attacker knows both adjacent bytes) |
| Full KPA, startPixel unknown | 56 × totalPixels | Cannot determine bit alignment per channel → candidates not computable |

The 7 candidate count represents the worst-case theoretical minimum under full KPA + CCA + known startPixel (noisePos known from CCA, only 7 rotations remain). Without CCA, there are 56 candidates (8 noisePos × 7 rotation). Without startPixel knowledge, byte-splitting prevents the attacker from determining the bit alignment for any channel, making per-channel candidate computation infeasible.

**Comparison with byte-aligned ciphers.** In all widely deployed stream ciphers (AES-CTR, ChaCha20, Salsa20), the keystream is XOR'd with plaintext byte-by-byte: `ciphertext[i] = plaintext[i] ⊕ keystream[i]`. Each plaintext byte maps to exactly one ciphertext byte — byte-level analysis is straightforward. ITB's 7-bit channel width breaks this byte alignment, making byte-level analysis structurally impossible without knowledge of the bit offset (which depends on startPixel). This property is a structural consequence of the 8/1 noise format, not a deliberately engineered feature.

Note: rotation in ITB (0-6, secret, per-pixel from dataSeed) differs fundamentally from rotation in ARX ciphers (e.g., ChaCha20: fixed amounts 16/12/8/7, public). ChaCha20 rotation is a mixing operation with known amounts — reversible by design. ITB rotation is an encryption operation with secret amount — not reversible without dataSeed. This has not been independently verified.

### 2.9.2 Why KPA Candidates Do Not Break the Barrier

Under KPA, the attacker can compute 56 candidate dataHash values per pixel (8 noisePos × 7 rotation, or 7 with CCA). This raises the question: does the existence of computable candidates contradict the information-theoretic barrier?

**The barrier is intact.** Theorem 1 states: P(C'[p,ch] = v | h) = 1/2 for any hash output h. This holds under KPA because the noise bit originates from the CSPRNG-generated container, independent of both the hash output and the plaintext. The observation probability is 1/2 regardless of which candidate is the true hash output. This is a property of information theory, not a computational assumption.

**Candidates are ambiguity, not leakage.** The 56 candidates are not extracted from the observation — they are computed from the combination of (known plaintext + observed byte + candidate config). All 56 are equally consistent with the observation. The attacker does not learn which candidate is real. The barrier guarantees that the observation cannot distinguish between them.

**Multi-pixel ambiguity.** Across P pixels, the total candidate space is 56^P. For P = 169 (1024-bit key): 56^169 ≈ 2^987. Without ChainHash inversion, the attacker cannot verify any candidate combination — the ambiguity is preserved by the barrier and enforced by PRF non-invertibility.

**Hash inversion bypasses ambiguity, not the barrier.** With an invertible hash, the attacker resolves the ambiguity by inverting ChainHash: candidate dataHash → candidate dataSeed → verify on another pixel. This is a hash function failure (invertibility), not a barrier failure. The barrier still absorbs the hash output — the inversion provides an alternative path that does not depend on the observation.

**Formal summary:**
```
Barrier (Theorem 1):     ∀ consistent h : P(v | h) = 1/2     — noise bit independent of h
Compatibility (COA):     ∀v, ∀h : ∃c : embed(c, h, d) = v    — without KPA, all h consistent
Ambiguity (KPA):         56 consistent h per pixel            — barrier preserves ambiguity
PRF non-invertibility:   candidates → seed: impossible        — ambiguity unresolvable
Invertible hash:         candidates → seed: possible          — ambiguity resolved (hash failure)
```

**Worst-case combined attack (CCA + Full KPA + PRF):**
```
CCA (MAC-reveal)         → noisePos known (3 bits/pixel from noiseSeed)
                         → noise bit value known (random CSPRNG bit — useless)
                         → 7 rotation candidates remain (not 56)
Full KPA                 → 7 candidate dataHash values per pixel, all consistent
PRF (non-invertible)     → ChainHash inversion impossible → brute-force 2^keyBits
Grover                   → 2^(keyBits/2) with expensive oracle (MAC-inside: O(P) per query)
```

**Why advanced cryptanalytic techniques do not apply to the absorbed PRF output:**

The random container introduces a CSPRNG-generated component (noise bit) that is independent of the PRF computation. This breaks the prerequisites for standard and advanced attacks:

| Attack technique | Prerequisite | Why blocked by ITB |
|---|---|---|
| Differential cryptanalysis | Observable input/output difference propagation | Output absorbed by random container — differences unobservable |
| Linear cryptanalysis | Linear approximation between input and output bits | Noise bit (CSPRNG) destroys linearity — no exploitable correlation |
| Algebraic attack (Gröbner/SAT) | System of equations relating input to output | 56^P ambiguity — system has exponentially many consistent solutions |
| Slide attack | Repeating structure across rounds | ChainHash: each round uses independent component s_i ⊕ h_{i-1} |
| Related-key attack | Algebraic relationship between keys | Triple-seed: three independent CSPRNG keys, no relationship |
| Integral/Square attack | Balanced property over input set | Random container destroys balance — output is CSPRNG ⊕ PRF |
| Boomerang attack | Composable differential paths | No observable intermediate state — barrier absorbs all rounds |
| Interpolation attack | Low-degree polynomial representation | PRF output ⊕ CSPRNG noise — effective degree exceeds observation |
| Cube attack | Superpoly recovery from public variables | Noise bit independent of all public and secret variables |
| Side-channel (power/timing) | Secret-dependent operation timing | dataSeed: register-only operations (XOR, shift, AND) |

All techniques require **observing** a relationship between the PRF's input and output. The information-theoretic barrier makes this observation impossible: the PRF output is absorbed by the random container, and the noise bit from CSPRNG is independent of the PRF computation. The attacker observes (PRF output modified by random container + independent CSPRNG noise bit) — a mixture of two independent random sources that cannot be decomposed without knowing the original container values (never transmitted).

The table above describes blocking under Core ITB and MAC + Silent Drop (noise bit present). After CCA (MAC + Reveal), noise bits are identified and the noise absorption mechanism is bypassed for noiseSeed. The analyses remain blocked for a different reason: dataSeed rotation ambiguity (7 candidates per pixel, 7^P total) combined with PRF and triple-seed isolation. Differential analysis between two pixels yields 7 × 7 = 49 candidate pairs — PRF makes all pairs indistinguishable from random. Linear, algebraic, and all other techniques face the same problem: no actual hash output, only unverifiable candidates. The result is identical — no analysis technique is applicable — but the blocking mechanism shifts from noise absorption to encoding ambiguity.

**The analysis dichotomy.** Advanced cryptanalytic techniques are never applicable to ITB, regardless of hash function properties:

```
Hash invertible     → seed recovered via inversion   → advanced analysis unnecessary (attacker already has everything)
Hash non-invertible → barrier blocks PRF observation  → advanced analysis impossible (no observable input/output relation)
```

There is no intermediate state where advanced analysis is useful but full inversion is not. To apply differential, linear, algebraic, or any structural analysis, the attacker must observe the PRF output — the barrier prevents this. To bypass the barrier, the attacker must invert ChainHash — but inversion yields the seed directly, making analysis redundant.

In both cases, **the barrier itself is never broken**. The barrier consists of two mechanisms: (1) noise absorption — CSPRNG noise bit at unknown position makes the byte ambiguous (Theorem 1); (2) encoding ambiguity — 7 rotation candidates per pixel from dataSeed create 7^P unverifiable combinations (Theorem 4). CCA can bypass mechanism (1) by revealing noise positions, but mechanism (2) remains intact through triple-seed isolation. Hash inversion bypasses both mechanisms via a side path (hash function property), but does not break them — the observation still contains the ambiguity.

With an invertible hash, the attacker recovers the seed through invertibility — not through the observation. The barrier still absorbs the hash output (PRF or non-PRF); the attacker bypasses it via a side path that does not depend on the observation. The failure is in the hash function, not in the barrier. The barrier creates a clean dichotomy: either the hash is invertible (seed recovered via inversion, barrier intact) or it is not (protected by the barrier, analysis impossible).

**What about physically removing noise bits?** A natural objection: "the barrier is information-theoretic, but I can use CCA to find all noise positions, physically remove noise bits from the container, shift data bits into place — and then apply all 10 analyses to the cleaned data."

This does not work. After noise removal, the attacker has 7 "clean" data bits per channel: `rotate(plaintext ⊕ xor_mask, rotation)`. The data is still encrypted by dataSeed configuration (rotation + XOR). CCA revealed noiseSeed (noise positions), but dataSeed is a completely independent key (triple-seed isolation: I(dataSeed ; noiseSeed) = 0). Removing noise bits bypasses one wall (noiseSeed) but leaves the other wall intact (dataSeed).

Without KPA: the cleaned data is `rotate(unknown_plaintext ⊕ xor_mask, rotation)` — the attacker cannot separate plaintext from XOR mask without knowing either one. No candidates are computable. The dataSeed encryption layer provides full protection.

With Full KPA: the attacker computes 7 rotation candidates per pixel, each producing a valid candidate dataHash. The attacker cannot determine which of the 7 is correct from the observation. Across P pixels: 7^P ambiguity (for P = 169: 7^169 ≈ 2^474). This ambiguity is an information-theoretic property of the encoding (7 rotations in a 7-bit channel), not of the hash function — it holds for any H, PRF or non-PRF. Even after the data has been recovered through hash inversion, the observation still contains 7^P ambiguity. The barrier is never broken.

The noise bits are not what blocks the analyses. The analyses are blocked by the barrier's second mechanism: **dataSeed encoding ambiguity** (7 rotations per pixel, independent of noise). Removing noise = bypassing mechanism (1). Mechanism (2) continues through triple-seed isolation — dataSeed is a different independent key that CCA and noise removal cannot reach.

### 2.10 Hash Function Requirements Analysis

ITB requires PRF-grade hash functions. The PRF property guarantees all necessary sub-properties. The barrier provides additional architectural hardening:

| Requirement | Prevents | Without it |
|---|---|---|
| 1. Full input sensitivity | Nonce bypass | Same config for different nonces |
| 2. Chain survival | XOR-cancellation | All pixels get identical config |
| 3. Non-affine mixing | Algebraic solving (Gröbner/SAT) | Constraint system solvable |
| 4. Avalanche | Correlation/cube attacks, bias | Correlated outputs for consecutive inputs |
| 5. Non-invertibility | ChainHash inversion | Seed recovery from partial output |

**Required PRF-grade hash functions:**

| Hash | Width | Acceleration | Crypto Status | Effective Max Key |
|---|---|---|---|---|
| SipHash-2-4 | 128-bit | — | PRF | 1024 bits |
| AES-CMAC | 128-bit | AES-NI (hardware) | PRF | 1024 bits |
| BLAKE2b keyed | 256-bit | SSE | PRF | 2048 bits |
| BLAKE2s keyed | 256-bit | — | PRF | 2048 bits |
| BLAKE3 keyed | 256-bit | SIMD (AVX-512) | PRF | 2048 bits |
| BLAKE2b-512 keyed | 512-bit | SSE | PRF | 2048 bits |

**Key space utilization.** A single ChainHash128 call with 128-bit output discriminates 2^128 of 2^1024 seeds. But the minimum container makes 169 independent calls with different data inputs. Collisions for one input do not persist across inputs (XOR-of-sums is not translation-invariant). Collective constraint: 169 × 64 = 10816 bits >> 1024 key bits. The full key space is utilized.

**Conclusion.** Effective brute-force: 2^1024 classical (far beyond Landauer ~2^306), 2^512 Grover (far beyond Landauer). The information-theoretic barrier (2^1352 for 169 pixels) exceeds the key space under the random-container model.

With triple-seed architecture, dataSeed has zero side-channel exposure (register-only operations). PRF property applies universally to all three seeds, ensuring protection under all threat models including CCA, local CCA simulation, and cache side-channel combined attacks.

### 2.11 Quantum Resistance Analysis

ITB's random-container architecture may provide structural resistance to certain quantum attacks beyond the standard Grover bound. This is a conjectured consequence of the information-theoretic barrier and MAC-inside-encrypt design — not quantum-specific hardening — and has not been independently verified. AES-256 and ChaCha20 are widely considered quantum-resistant for practical purposes (2^128 Grover bound).

#### 2.11.1 Barrier Property Under the Random-Container Model

The core security property — every observed byte value is compatible with every possible hash output (∀v, ∀h : ∃c : embed(c,h,d) = v) for random container — is a statement from probability theory. Provided the container is generated from a source indistinguishable from true uniform randomness, it holds regardless of computational model: classical, quantum, or any future model. A quantum computer cannot extract information that does not exist in the observation. The original container pixels (crypto/rand) are never transmitted and cannot be recovered by any computation. However, whether this property translates into practical quantum resistance across all attack scenarios has not been formally proven or independently verified.

Under the random-container model, this is an information-theoretic property rather than a computational one. AES-CTR and ChaCha20 achieve quantum resistance through the computational strength of their underlying primitives — well-established constructions with decades of cryptanalysis confirming their robustness. ITB explores an alternative approach: interposing a random container between the internal state and the observer, which in principle limits the applicability of quantum structural analysis at the information level. This architectural difference has not been independently verified against quantum attacks.

#### 2.11.2 Quantum Algorithm Applicability

| Quantum Algorithm | Requires | ITB Status | Mechanism |
|---|---|---|---|
| **Grover** (brute-force) | Yes/no verification oracle | **Applicable** but degraded | Oracle exists but requires full decryption per query; O(2^(keyBits/2)) |
| **Simon** (periodicity) | Periodic function structure | **Conjectured mitigated** | Config map is aperiodic: ChainHash with 128-bit nonce per message |
| **BHT** (collision finding) | Observable collisions | **Conjectured mitigated** | Core/Silent Drop: random container absorbs collisions; MAC + Reveal: encoding ambiguity (7 candidates — collisions unidentifiable) |
| **Quantum differential** | Structural plaintext↔ciphertext relations | **Conjectured mitigated** | Random container limits structural relations |
| **Quantum linear** | Linear/affine input-output relations | **Conjectured mitigated** | Non-affine mixing (PRF property) + random container |
| **Future structural** | Observation of internal construction state | **Conjectured mitigated** | IT barrier: internal state unobservable under random-container model |

#### 2.11.3 Grover Oracle Degradation

Grover's algorithm requires a function f(key) → {0, 1} that can be evaluated in quantum superposition. In ITB:

**Core ITB (no MAC) and MAC + Silent Drop:** The oracle does not exist. Every candidate key produces some decrypted output. Without verification metadata (no magic bytes, no checksums, no cleartext MAC), f(key) has no way to return 1 for the correct key. Under MAC + Silent Drop, the MAC is present but the recipient never reveals the verification result — the attacker receives no accept/reject response, so no oracle can be constructed. Grover cannot run without a well-defined oracle.

**ITB + MAC-inside-encrypt:** The oracle exists but is maximally expensive. To evaluate f(key):
1. Decrypt128/256/512 entire container with candidate key
2. Split decrypted capacity into payload + MAC tag
3. Recompute MAC over payload
4. Compare → match = correct key (f = 1)

Each oracle query requires O(P) hash evaluations (P = pixel count) for full decryption. This does not reduce Grover's asymptotic complexity O(2^(keyBits/2)), but makes each query maximally expensive — unlike traditional ciphers where oracle evaluation is often a single block operation.

#### 2.11.4 Comparison with Traditional Ciphers Under Quantum Attack

| Cipher | Quantum Structural Attacks | Grover Oracle | Quantum Resistance |
|---|---|---|---|
| AES-CTR | Well-studied PRP; no known quantum structural attacks | Efficient (single block verify) | 2^128 Grover for AES-256; widely deployed |
| ChaCha20 | Well-studied PRF; no known quantum structural attacks | Efficient (single block verify) | 2^128 Grover; widely deployed |
| ITB | Random container limits structural analysis (not independently verified) | Expensive (full decryption) or absent (no MAC) | IT barrier (conjectured) + computational |

**Summary.** ITB's architecture provides two potential layers of quantum resistance: (1) the random container limits the applicability of quantum structural algorithms by making the construction's internal state unobservable under the random-container model (this property has not been independently verified against quantum attacks), and (2) Grover brute-force remains the primary quantum attack vector, degraded by expensive or absent oracle. At 1024-bit key: 2^512 Grover operations. At 2048-bit key: 2^1024. Both are beyond any foreseeable quantum capability. Note that AES-256 and ChaCha20 with their 2^128 Grover bound are widely considered quantum-resistant for practical purposes.

#### 2.11.5 Q1 vs Q2 Quantum Oracle Models

Recent work on quantum security distinguishes two models: Q1 (adversary performs quantum computation locally, but oracle access is classical) and Q2 (adversary can send quantum superposition queries to the oracle). Several constructions provably secure in the classical setting — Luby-Rackoff, Even-Mansour, Keyed Sum of Permutations — become vulnerable in the Q2 model because the oracle structurally accepts superposition inputs.

ITB's oracle model is inherently Q1:

- **Core ITB (no MAC):** No oracle exists. The adversary has no verification mechanism — Grover cannot construct f(key) → {0, 1}.
- **MAC + Silent Drop:** The MAC is present but the recipient never reveals the verification result. No oracle exists — the adversary receives no accept/reject response, so Grover cannot construct f(key) → {0, 1}.
- **MAC + Reveal:** The oracle is a physical network interaction: send a concrete container, receive accept/reject. Quantum superposition queries are physically impossible — the recipient's MAC verification operates on classical bytes, not superpositions.

The Q2 model is inapplicable to ITB by design, not by cryptographic countermeasure. This is an architectural observation that has not been independently verified.

## 3. Comparison with Existing Ciphers

### 3.1 Maximum Key Size

| Cipher | Maximum Key Size | Effective Security |
|---|---|---|
| AES | 256 bits | 256 bits |
| ChaCha20 | 256 bits | 256 bits |
| Twofish | 256 bits | 256 bits |
| Serpent | 256 bits | 256 bits |
| Threefish | 1024 bits | 1024 bits |
| ITB + BLAKE3 | 2048 bits | 2048 bits |

**Note.** 256-bit keys are widely considered sufficient for all foreseeable classical and quantum threats (2^128 Grover bound). Larger key sizes provide additional defense-in-depth margin but do not address any practical threat that 256-bit keys cannot already handle. ITB's support for larger keys is a consequence of its chained-hash architecture, not a claim that larger keys are necessary.

### 3.2 Hash Function Requirement Comparison

| Cipher | Minimum primitive requirement |
|---|---|
| AES-CTR | PRP (strong) |
| ChaCha20 | PRF |
| Salsa20 | PRF |
| ITB | PRF required; barrier hardens PRF by making hash output unobservable |


### 3.3 Authenticated Encryption Comparison

ITB's `EncryptAuthenticated128`/`EncryptAuthenticated256`/`EncryptAuthenticated512` implements deniable authenticated encryption: the MAC tag is encrypted inside the container, covering the full capacity (COBS + null + fill). This combines integrity protection with oracle-free deniability — a design trade-off not targeted by standard AEAD constructions, which prioritize different security goals.

**Closest known construction: MAC-then-Encrypt (MtE).** Used in TLS 1.0/1.1 (HMAC-SHA1 + AES-CBC). MtE encrypts the tag inside the ciphertext, providing a form of deniability. However, MtE was broken in practice because the underlying cipher exposes structural patterns: padding oracle attacks (POODLE on SSL 3.0, Lucky13 on TLS CBC) recover plaintext by exploiting CBC padding validation timing and error responses.

**Deniable encryption systems.** OTR achieves deniability through post-hoc MAC key publication (tag is cleartext during transmission). Signal Protocol uses ephemeral keys (tag not hidden). TrueCrypt/VeraCrypt provides container-level deniability via hidden volumes. Honey Encryption (Juels & Ristenpart, 2014) produces plausible plaintext for every key but does not hide an authentication tag.

**Comparison matrix:**

| Property | MtE (TLS 1.0)‡ | OTR | Signal | AEAD (GCM) | ITB |
|---|---|---|---|---|---|
| Tag encrypted inside ciphertext | ✓ | ✗ | ✗ | ✗ | ✓ |
| MAC covers padding | ✗ | — | — | ✓ | ✓ |
| Information-theoretic barrier† | ✗ | ✗ | ✗ | ✗ | ✓ |
| Oracle-free deniability | ✗ | Partial | Partial | ✗ | ✓ |
| CCA spatial pattern eliminated | ✗ | — | — | ✓ | ✓ |
| Resistant to padding oracle | ✗ | — | — | ✓ | ✓ |
| Hash function requirement | PRF/PRP | PRF | PRF | PRP | PRF |
| Maturity / peer review | Extensive | Extensive | Extensive | Extensive | **None** |
| Performance | High | High | High | High | Lower (per-pixel hashing) |
| Standardization | TLS 1.0-1.1 | OTR v3/v4 | Signal Protocol | NIST SP 800-38D | None |

† Software-level property under the random-container model; no guarantees against hardware-level attacks (see Disclaimer).

**Note.** AES-GCM and ChaCha20-Poly1305 are the recommended standards for authenticated encryption in virtually all production scenarios. ITB's MAC-inside-encrypt design explores a different point in the deniability-integrity design space. The combination of deniable authenticated encryption with a random-container barrier and minimal hash function requirements is, to our knowledge, unexplored in prior work — but this novelty should not be confused with maturity or proven security.

## 4. Limitations

- **Performance.** ChainHash invokes the hash function numRounds times per pixel (numRounds = n / componentsPerRound). At n=8 (512 bits): 4 rounds for 128-bit hash, 2 for 256-bit, 1 for 512-bit. Throughput limited by hash speed. Each pixel is independent (counter-mode, same principle as AES-CTR parallelization), enabling parallel encode and decode across goroutines with deterministic output regardless of worker count.

- **Internal state bottleneck.** Effective security limited by hash output width: 1024 bits for 128-bit hash, 2048 bits for 256-bit and 512-bit hash.

- **No authentication.** The core construction provides confidentiality only. Bit-flipping attacks are possible: an attacker can modify container bytes, altering decrypted data without detection. Integrity must be added externally via MAC-inside-encrypt: compute MAC over plaintext, append to plaintext, then encrypt the combined payload. The MAC is encrypted inside the container, preserving oracle-free deniability. Placing a MAC outside the container (in cleartext) would create a verification oracle, breaking deniability.

- **Container overhead.** RGBWYOPA encoding uses 56 data bits per 64-bit pixel (7 bits per 8-bit channel), giving 87.5% storage efficiency with 1.14× overhead. The remaining 1 noise bit per channel provides the information-theoretic barrier.

- **Heap memory exposure.** Sensitive data (seeds, plaintext, decoded payload) resides in heap memory during processing. An attacker with direct memory access (root, debugger, memory dump) can read keys and plaintext regardless of cipher strength. This is universal for ALL software symmetric ciphers (AES, ChaCha20, etc.) — not specific to ITB. The library mitigates by secure-wiping (`secureWipe`) all intermediate buffers (payload, decoded data, hash buffers) after use, minimizing the exposure window. For high-security deployments (financial, government, military), hardware memory encryption is **strongly recommended**: AMD SEV, Intel SGX/TDX, or ARM CCA. These encrypt RAM at the hardware level, protecting against physical and co-located attacks that no software cipher can prevent.

- **startPixel cache side-channel (known limitation).** The data embedding start position (`startPixel`) is derived from `startSeed` and determines the memory access pattern for container reads/writes. A co-located attacker observing CPU cache access patterns (Flush+Reload, Prime+Probe) can infer `startPixel`, leaking `log₂(totalPixels)` bits of one ChainHash output per encryption (~6 bits for minimum container, ~24 bits for 128MB data). Over multiple encryptions with the same `startSeed`, the attacker accumulates `(nonce, startPixel)` pairs. With a PRF-grade hash function (particularly non-invertibility and avalanche), these pairs cannot be used to recover the seed: non-invertible hash prevents algebraic inversion, and avalanche eliminates correlation between outputs for different nonces. The side-channel is exploitable **only** if the hash function lacks these PRF properties — which are universally required.

### Known Theoretical Threats

The following are theoretical attack surfaces that have been analyzed and accepted. None are practically exploitable under normal conditions.

**1. rotateBits7 shift timing (equivalent to DPA on AES).** The data rotation function uses variable shift amounts (0-6) derived from dataSeed. On some CPU architectures, variable bit shifts have latency differences of ~1 clock cycle (~0.3ns at 3.6GHz). If an attacker can measure per-pixel shift timing, they recover rotation values → rotation barrier broken → combined with CCA (noise positions) + KPA → dataSeed potentially recoverable. However, isolating individual shift operations requires a hardware oscilloscope on the CPU die with >10GHz sampling rate, separating single operations among millions per second. This is the same attack class as Differential Power Analysis (DPA) and Simple Power Analysis (SPA) on AES — well-studied attacks that require physical laboratory access to the chip, specialized equipment (EM probes, high-bandwidth oscilloscopes), and controlled measurement conditions. All software symmetric ciphers (AES, ChaCha20, Serpent) are equally vulnerable to DPA/SPA at this level. dataSeed's register-only design ensures no **software-observable** side-channel exists — only hardware-level emanation analysis applies. Note: even a successful DPA/SPA attack yields only the rotation value of individual pixels (not the key); recovering the key from rotation values requires inverting ChainHash, which is blocked by non-invertibility (PRF property). ITB does not claim DPA/SPA resistance, but the construction architecturally does not provide the attack surface that DPA exploits in table-lookup-based ciphers (e.g., AES S-box). This has not been independently verified.

**2. Container size metadata.** Container dimensions (width, height) are stored in the cleartext header, revealing approximate message length. This is inherent to any fixed-overhead cipher — AES-CTR, ChaCha20, and all stream ciphers expose ciphertext length ≈ plaintext length. Since ITB has no padding participating in the cryptographic construction, this metadata does not provide cryptographic advantage to the attacker — the same property holds for all fixed-overhead ciphers (AES-CTR, ChaCha20).

**3. crypto/rand generator trust.** The construction relies on `crypto/rand` for container generation, nonce, and seed creation. All major OS implementations (Linux `getrandom`, macOS `arc4random`, Windows `BCryptGenRandom`) are production-grade CSPRNGs with extensive security review. Using a non-CSPRNG source for container generation degrades the information-theoretic barrier. The library does not validate the random source — this is the deployer's responsibility. Non-CSPRNG usage is explicitly unsupported.

**4. COBS decode truncation.** Corrupted COBS-encoded data (from wrong seed or tampered container) may silently truncate during decode. The downstream null-terminator check catches this as "wrong seed" error — the caller never receives silently corrupted data. This is consistent with the oracle-free design: any decryption with wrong credentials produces an error, not partial data.

**5. Bit-flip DoS / false null terminator.** An attacker could attempt to flip data bits to create a false 0x00 null terminator, causing message truncation. With `EncryptAuthenticated128`/`256`/`512`: MAC is verified BEFORE null terminator search — any data bit modification fails MAC verification, and COBS decode is never reached. With core ITB (no MAC): bit-flip can truncate data, but this is the documented "No authentication" limitation. Noise bit flips do not affect the data stream and cannot create false terminators. No amplification or crash is possible — all paths return graceful errors with constant-time processing.

**6. CGO backend side-channel analysis.** The optional C pixel processing backend (compiled with GCC `-O3`, with `-mavx2` on x86-64 and NEON auto-vectorization on ARM64) was analyzed for side-channel equivalence with the pure Go implementation. Findings:

All SIMD instructions used by GCC auto-vectorization have **fixed latency** on both platforms — no data-dependent timing variation. The critical `dataHash % 7` operation (dataSeed rotation extraction) is optimized by GCC into a constant-time multiply-by-reciprocal sequence on both architectures — no division instruction on secret data.

The only variable-time division in the compiled output is for `(startPixel + p) % totalPixels` (pixel wrapping), where `totalPixels` is public (W×H in cleartext header). On x86-64: `idivl`. On ARM64: `sdiv`. Both are data-independent and present in both Go and C versions.

| Operation | x86-64 (AVX2) | ARM64 (NEON) | Constant-time? | Depends on secret? |
|---|---|---|---|---|
| XOR channels | `vpxor` | `veor` | Yes | dataSeed xorMask — not observable |
| Rotate 7-bit | `vpsllw`/`vpsrlw` | `vshl`/`vshr` | Yes | dataSeed rotation — not observable |
| Noise bit insert | `vpand`/`vpor` | `vand`/`vorr` | Yes | noiseSeed position — CCA-revealable only |
| `dataHash % 7` | `imulq` + `shrq` | `mul` + `sub` | Yes | dataSeed hash — constant-time multiply |
| `% totalPixels` | `idivl` | `sdiv` | **Variable-time** | **No** — totalPixels is public |
| Hash array read | Sequential `movq` | Sequential `ldr` | Yes | Index p is sequential, not secret |
| Container access | `container[pixelOffset]` | `container[pixelOffset]` | Cache-observable | startPixel — documented limitation |

Memory access patterns are identical between Go and C backends on both platforms. L1 micro-batching (512 pixels × 16 bytes = 8KB per C call) keeps hash arrays in L1 cache, making Flush+Reload observation harder than the full-array approach. ARM64 has no frequency throttling from NEON (unlike Intel AVX-512).

No speculative execution (Spectre) vulnerability: no secret-dependent array indexing exists. `noisePos` and `dataRotation` are used only as shift amounts and bitmasks, never as array indices.

**Conclusion:** The CGO backend preserves the side-channel security model of the pure Go implementation on all platforms. No new software-observable side-channel is introduced by SIMD auto-vectorization (AVX2 or NEON). The same DPA/SPA hardware-level threat (point 1) applies to both backends equally.

**7. Speculative execution, data sampling, and memory integrity attacks.** ITB's secret-dependent operations (`noisePos`, `dataRotation`, `channelXOR`) use only register operations (shift, XOR, AND, OR). There are no secret-dependent array accesses (no S-box, no T-tables). The CGO backend does not use `gather` instructions; AVX2 operations (`vpxor`, `vpand`, `vpor`, `vpsllw`, `vpsrlw`) are constant-weight and do not cause measurable frequency throttling.

**CPU speculative execution attacks (summary):**

| Attack class | Requires | ITB data path | Status |
|---|---|---|---|
| Spectre v1/v2/v4, Retbleed, Inception, Downfall, GhostRace, BHI, SLAM, Training Solo | Secret-dependent memory access gadget (`array[secret]`) | Register-only ops; no `table[secret_index]` | No known gadget |
| Hertzbleed (remote power/timing) | Data-dependent power → frequency throttling | Lightweight register XOR/shift; constant-weight AVX2 | No known attack surface |
| MDS, RFDS, Zenbleed (stale data sampling) | Stale data in CPU buffers | Seeds may remain in buffers; identical for AES/ChaCha20 | Not ITB-specific |

**Memory integrity attacks (summary):**

| Attack | ITB impact | Status |
|---|---|---|
| Rowhammer, RAMBleed | Could corrupt/read seeds in DRAM; affects all software equally | Not ITB-specific; ECC memory recommended |
| Meltdown (CVE-2017-5754) | Reads process memory (seeds, plaintext); identical for all ciphers | Not ITB-specific; KPTI mitigates |

ITB does not claim resistance to any hardware-level attack. However, the construction architecturally does not provide the disclosure gadget (`table[secret_index]`) required by speculative execution attacks. This has not been independently verified. See [HWTHREATS.md](HWTHREATS.md) for detailed per-CVE analysis.

### DPA/SPA Resistance Analysis

Differential Power Analysis (DPA) and Simple Power Analysis (SPA) exploit data-dependent power consumption patterns during cryptographic operations. Ciphers with secret-dependent table lookups (e.g., software S-box implementations) are vulnerable because each table index produces a distinct memory access pattern observable through power traces.

**ITB's data path contains no secret-dependent table lookups.** All dataSeed-derived operations are register-only:

| Operation | Instruction type | Power profile | Secret-dependent? |
|---|---|---|---|
| `dataHash % 7` | Register division | Constant | dataRotation derived |
| `dataHash >> 3` | Register shift | Constant | xorMask derived |
| `dataBits ^= channelXOR` | Register XOR | Constant | XOR mask applied |
| `rotateBits7(dataBits, rotation)` | Register shift | ~0.3ns variation | rotation value |

No memory access depends on dataSeed values. No cache line activation correlates with key material. The power profile of register XOR, shift, and AND operations does not vary with operand values on modern CPUs.

**Maximum information from a successful DPA/SPA attack:** the rotation value (0-6) of individual pixels — not the key. Recovering the key from rotation values requires inverting ChainHash, which is blocked by non-invertibility (PRF property). For comparison, DPA on software table-lookup implementations can recover the full key through correlation of table indices with power traces across multiple operations.

ITB does not claim formal DPA/SPA resistance. This analysis describes the architectural absence of the attack surface that DPA/SPA exploits, not a proven countermeasure. This has not been independently verified.

### Scope and Maturity Disclaimer

ITB is a new construction without prior peer review or independent cryptanalysis. The primary contribution is theoretical: demonstrating that PRF-grade hash functions can be architecturally hardened through an information-theoretic barrier that makes hash output unobservable under passive observation. Performance is not a design goal.

The author does not claim that ITB is the most secure symmetric cipher construction, nor that the analysis is exhaustive. As a first publication, the construction may contain overlooked vulnerabilities at two levels:

**1. Fundamental (barrier invalidation).** If the information-theoretic barrier does not hold as claimed — e.g., if the random container does not fully absorb hash outputs under some attack model not considered here — the core security guarantee would be invalidated. This is considered unlikely: the proof that every observed byte value is compatible with every possible hash output (∀v, ∀h : ∃c : embed(c,h,d) = v) is a direct consequence of probability theory, independent of the hash function. However, the interaction between the barrier and active attacks (CCA, side-channel, multi-message analysis) may have subtleties not captured by the current analysis.

**2. Implementational (correctable).** Edge cases in COBS framing, off-by-one errors in bit indexing, timing side-channels in constant-time operations, or insufficient secure-wiping coverage. These are correctable without redesigning the construction. The library includes mitigation for known side-channels (constant-iteration null search (no early break; branch prediction may leak message length), secureWipe with runtime.KeepAlive, register-only dataSeed operations), but the mitigations themselves have not been independently audited.

**Minimum container caveat.** The information-theoretic barrier strength depends on container size: 2^(8P) for P pixels. At minimum container (e.g., 169 pixels for 1024-bit key), the barrier is 2^1352 — well above the key space. However, for very small payloads where the container is only slightly larger than the minimum, the security margin above the key space is at its lowest. The construction does not provide security guarantees for containers smaller than MinPixels.

**Areas for reviewer scrutiny:**

- Whether PRF is sufficient (Definition 2), or whether additional properties are needed for attack models not considered.
- Whether the triple-seed isolation provides the claimed independence under all side-channel combinations.
- Whether the CCA leak analysis (Sections 4.1–4.7) correctly bounds the information extractable from the MAC oracle.
- Whether the ChainHash construction achieves the claimed effective key sizes through multi-call recovery (Section 1.1.3, 2.1).

### 4.1 Chosen-Ciphertext Attack and MAC Composition

The MAC-inside-encrypt pattern (see "No authentication" in Section 4) preserves deniability but does not provide CCA2 (adaptive chosen-ciphertext) resistance on its own. If the recipient reveals the MAC verification result (accept/reject) to an untrusted party, the response acts as an oracle:

1. Attacker flips bit N in the container.
2. Recipient decrypts, checks MAC, responds accept or reject.
3. Accept → bit N was a noise bit (modification did not affect data).
4. Reject → bit N was a data bit (modification corrupted the message).
5. Repeated for all bits → attacker recovers the noise position map (3 config bits per pixel).

**Triple-seed isolation limits the leak to noiseSeed only.** The CCA oracle reveals which bits are noise — this is the noise position (0-7) per pixel, determined by noiseSeed. Because noiseSeed, dataSeed, and startSeed are independent keys, this leak provides zero information about dataSeed (rotation + XOR masks, 59 config bits per pixel) or startSeed (pixel offset). The attacker learns 3 of 62 config bits per pixel (4.8%) — all from noiseSeed.

**Important:** the CCA oracle exists ONLY when MAC is added AND the verification result is revealed to the attacker (MAC + Reveal mode). The core construction (without MAC) and MAC + Silent Drop are structurally oracle-free — there is no verification mechanism to produce accept/reject responses (or the response is suppressed), so no oracle can exist regardless of implementation.

**ITB composition security matrix:**

| Scenario | Integrity | Deniability | CCA risk |
|---|---|---|---|
| ITB without MAC (core) | ✗ | ✓ Full (structural) | No oracle exists |
| ITB + MAC-inside + silent drop | ✓ | ✓ Full | ✗ None |
| MAC-inside (plaintext only) + reveal | ✓ | ✓ Partial | Noise position + spatial layout leak |
| MAC-inside (full capacity) + reveal | ✓ | ✓ Full | Noise position only (noiseSeed, no spatial leak) |
| ITB + Encrypt-then-MAC | ✓ | ✗ Broken | ✗ None |

Implemented: MAC-inside (full capacity) — `EncryptAuthenticated128`/`EncryptAuthenticated256`/`EncryptAuthenticated512`. The plaintext-only variant is a theoretical alternative, shown to demonstrate why full-capacity MAC was chosen: plaintext-only MAC leaks spatial layout (which container regions carry data vs fill), because fill-byte bit flips do not affect the MAC → "accept" reveals fill positions. Full-capacity MAC eliminates this by including fill in the MAC input.

**Comparison with other ciphers under CCA (MAC result revealed):**

| Scheme | CCA oracle leak |
|---|---|
| AES-CBC + MAC-then-Encrypt‡ | Padding oracle → full plaintext (POODLE, Lucky13) |
| AES-CTR + MAC-then-Encrypt | Bit-flip oracle → data structure |
| ITB + MAC-inside-encrypt | Noise position only (3 bits/pixel from noiseSeed, no data) |
| AES-GCM (Encrypt-then-MAC) | None (MAC rejects before decryption) |
| ChaCha20-Poly1305 (AEAD) | None (MAC rejects before decryption) |

‡ Deprecated construction (TLS 1.0/1.1, RFC 8996). Included for historical context only.

**Note.** AES-GCM and ChaCha20-Poly1305 prevent CCA entirely by verifying the MAC before decryption — the standard approach for authenticated encryption. ITB's MAC-inside-encrypt accepts a small CCA leak (noise positions only) as the cost of preserving deniability. Different design goals lead to different trade-offs.

**MAC scope matters.** If the MAC covers only the extracted plaintext, the CCA oracle additionally reveals which container regions carry padding vs COBS data (padding bit flips don't affect plaintext → "accept"), leaking the spatial layout, start pixel, and approximate message length. The library's `EncryptAuthenticated` avoids this by computing the MAC over the entire decrypted capacity (COBS + null terminator + fill). This makes every data bit "meaningful" — flipping any data bit changes the MAC input, producing "reject." The only remaining leak is noise position (noise bits → "accept"), with no spatial pattern.

Core ITB and MAC + Silent Drop have no CCA surface at all — deniability is a structural property of the construction, not a protocol-level guarantee.

**Mitigation is protocol-level, not library-level.** The recipient must not reveal individual MAC verification results to untrusted parties. Standard approaches:

- **Silent drop:** failed MAC → drop message, no error response. Used by Signal Protocol.
- **Constant-time response:** all responses identical regardless of MAC result.
- **No interactive protocol:** store-and-forward without acknowledgment.

This is the same requirement imposed on all MAC-based systems. Libraries (libsodium, Go crypto/cipher, OpenSSL) provide primitives; CCA mitigation is the protocol's responsibility.

### 4.2 Quantitative CCA Analysis: Bit-Plane Leak Impact

**Worked example.** 1024-byte plaintext, 1024-bit key, minimum container.

```
COBS(1024) = 1024 + ceil(1024/254) = 1024 + 5 = 1029 bytes
Payload = 1029 + 1 null = 1030 bytes
Pixels = ceil(1030×8 / 56) = ceil(147.14) = 148 → 13×13 = 169 pixels
Container = 169 × 8 channels = 1352 bytes = 10816 bits
```

**Attack cost.** The attacker flips each of 10816 bits individually, observing MAC accept/reject for each → 10816 queries to the recipient. Each query requires transmitting a modified container and awaiting a response. This is highly detectable by any monitoring system.

**Information gained.** Noise/data classification of all 10816 bits:

- **Noise bits identified:** 169 pixels × 8 channels × 1 bit = 1352 bits (12.5%)
- **Data bits identified:** 10816 − 1352 = 9464 bits (87.5%)
- **Noise position config (noiseSeed):** 169 pixels × 3 bits = 507 bits

The attacker obtains the noise position (0-7) for every pixel — this is the complete noiseSeed configuration. Due to triple-seed isolation, this reveals zero information about dataSeed (rotation + XOR) or startSeed (pixel offset).

**Why the noise map does not help:**

| Information | Leaked? | Bits | Source | Reason |
|---|---|---|---|---|
| Noise positions | Yes | 1352 | noiseSeed | CCA oracle (accept = noise bit) |
| Noise position config | Yes | 507 | noiseSeed | 3 bits/pixel, 100% of noiseSeed config |
| Noise bit values | Yes | 1352 | container | Visible but random, independent of key/data |
| Data bit values (encrypted) | Visible | 9464 | — | Each bit = actual_data ⊕ unknown_xor_mask |
| XOR masks | No | 0 | dataSeed | Per-bit XOR: no oracle distinguishes mask values |
| Data rotation | No | 0 | dataSeed | Register-only, unobservable |
| Start pixel | No | 0 | startSeed | No way to determine data-to-pixel mapping |
| Plaintext | No | 0 | — | Data bits encrypted, ordering unknown |
| dataSeed / startSeed | No | 0 | — | Independent seeds, CCA reveals only noiseSeed |

The 9464 data bits are visible but remain encrypted: each is XOR'd with an independent, unknown mask bit from dataSeed. The noise map strips away 1352 irrelevant bits, giving the attacker a cleaner view of the encrypted data — but the encryption (per-bit XOR + rotation + unknown start pixel) is untouched.

**Even with known plaintext + noise map, the data is not recoverable.** The attacker knows the COBS-encoded plaintext and which container bits carry data. To decrypt, they must map plaintext bits to container positions — this requires the start pixel (from startSeed, independent). Trying all 169 candidate start positions: for each, the attacker computes a candidate XOR mask = container_data ⊕ expected_data. With per-bit XOR (1:1), every candidate produces a valid mask (Section 2.9). The attacker cannot distinguish the correct start pixel from 168 wrong ones.

**Brute-force optimization.** The attacker can use the 507-bit noise position map as a fast candidate rejection test: compute candidate noise positions from noiseSeed → compare with leaked map → reject mismatches. Wrong noiseSeed values rejected with probability 1 − 2^(−507). However, the search space remains 2^512 per seed — the rejection test is cheaper per candidate but does not reduce the number of candidates. Grover complexity remains 2^(keyBits/2).

**Conclusion.** The CCA noise map exposes which 1352 of 10816 bits are noise and which 9464 are encrypted data — revealing the complete noiseSeed configuration (507 bits). Due to triple-seed isolation, this provides zero information about dataSeed or startSeed. The per-bit XOR encryption (dataSeed) and unknown start pixel (startSeed) are unaffected. The attacker expends 10816 detectable queries to gain near-zero practical advantage. For comparison, the padding oracle in TLS 1.0's MAC-then-Encrypt composition with AES-CBC was exploitable to recover full plaintext (POODLE, Lucky13), though this was a protocol-level vulnerability addressed in subsequent TLS versions.

### 4.3 Structural Upper Bound on CCA Leak

**Claim.** Bit-plane is the maximum information extractable via CCA against any ITB + MAC composition, regardless of MAC placement, protocol errors, or attacker strategy.

**Proof sketch.** The CCA oracle provides a binary response (accept/reject) per query — exactly 1 bit of information. Each bit in the container belongs to one of two classes:

1. **Noise bit** (1 per channel, position determined by bit-plane). Modification does not affect decrypted data → MAC passes → oracle responds "accept."
2. **Data bit** (7 per channel). Modification alters decrypted data → MAC fails → oracle responds "reject."

The oracle response perfectly classifies each bit as noise or data, revealing the noise position (0-7) for each pixel. This is the complete information content of the binary oracle.

**Why no further information is extractable:**

- **XOR masks (56 bits/pixel).** Flipping a data bit changes the decrypted value, but the oracle response is "reject" regardless of which data bit was flipped. The response does not distinguish between the 7 data bit positions within a channel or between channels. The per-bit XOR (1:1) ensures that any observed channel value is consistent with any plaintext under some mask — even with bit-plane known, the attacker cannot narrow down XOR values.

- **Start pixel.** The oracle response does not indicate where in the plaintext the modification occurred. The attacker knows "some data bit changed" but not which byte of the message was affected. Start pixel remains unknown.

- **Plaintext values.** Flipping a data bit reveals that the bit carries data, not what the data value was. The original value and the flipped value both produce "reject" (since both differ from the authentic MAC).

- **Multi-bit modifications.** Flipping N bits simultaneously still yields a single binary response. The information is at most 1 bit per query, not N bits. Multi-bit strategies cannot exceed the single-bit classification rate.

**This upper bound is a structural property of per-bit XOR (1:1).** With per-channel XOR (1:7), the oracle would additionally enable cross-channel consistency checks, leaking XOR masks (Section 2.9). The 1:1 design eliminates this by ensuring independent XOR per data bit — no consistency constraint exists between bits.

### 4.4 Why MAC Cannot Cover Noise Bits

A natural question: can the MAC cover the entire container including noise bits, achieving 100% reject (zero CCA leak)? No — this is not achievable within the current construction while preserving deniability.

**Circular dependency.** The MAC tag must be stored inside the container to preserve deniability (Section 4.1). But embedding the tag modifies the container's data bits. If the MAC is computed over the container (including noise), embedding the tag changes the MAC input, invalidating the tag:

```
1. Embed payload → container formed (noise bits fixed)
2. Compute MAC(entire container) → tag
3. Embed tag → container changes → MAC invalid
```

**Alternative: MAC in header (outside container).** Placing the MAC in the cleartext header eliminates the circular dependency — the MAC covers all container bytes including noise. However, the cleartext MAC serves as a brute-force verification oracle: the attacker tries candidate seeds, decrypts, recomputes the MAC, and checks against the public tag. This breaks oracle-free deniability (Section 2.3).

**Design space:**

| MAC placement | Covers noise | Deniability | CCA leak |
|---|---|---|---|
| Inside container (full capacity) | No | ✓ Preserved | Bit-plane only |
| Outside container (header) | Yes | ✗ Broken | None |

The library's `EncryptAuthenticated128`/`EncryptAuthenticated256`/`EncryptAuthenticated512` uses MAC-inside over the full capacity (COBS + null + fill). This is the optimal trade-off: deniability preserved, CCA leak limited to bit-plane (analyzed as harmless in Sections 4.2–4.3), and no circular dependency. The bit-plane leak (12.5% of bits classified as noise) yields zero practical advantage to the attacker — no plaintext, no XOR masks, no start pixel, no key-space reduction.

### 4.5 Structural Barrier Invariant Under CCA

**Claim.** Under CCA with MAC-reveal, the information-theoretic barrier protects 59 of 62 configuration bits per pixel (95.2%). This is a structural invariant of the RGBWYOPA 8/1 format, independent of the hash function.

**Proof.** The CCA leak originates from the container format, not the hash:

```
Channel = 8 bits: 7 data + 1 noise
Flip noise bit → decrypted data unchanged → MAC pass → "accept"
Flip data bit → decrypted data changed → MAC fail → "reject"
```

This classification works identically for any PRF-grade hash function (SipHash-2-4, BLAKE3, BLAKE2b). The hash determines WHICH bit position is noise, but the CCA oracle can always identify it via flip-test because noise bits structurally do not affect the decrypted payload.

**Exact accounting (two distinct metrics):**

```
Container bits per pixel:      64 (8 channels × 8 bits)
  Noise bits (CCA "accept"):    8 per pixel (12.5% of container)
  Data bits (CCA "reject"):    56 per pixel (87.5% of container)

Config bits per pixel (triple-seed):
  noiseSeed (noise position):          3 → 100% leaked under CCA
  dataSeed (rotation + XOR masks):    59 → 0% leaked (independent seed)
  Total config:                       62 → 4.8% leaked (noiseSeed only)
```

**Critical: triple-seed isolation.** The CCA leak affects ONLY noiseSeed (noise positions). dataSeed (rotation + XOR masks) is an independent secret — CCA compromise of noiseSeed provides zero information about dataSeed. Data rotation makes dataSeed's hash output completely unobservable even with known plaintext.

| Seed | Config bits/pixel | CCA leak | Protected | Exploitable? |
|---|---|---|---|---|
| noiseSeed | 3 | 100% | 0% | Harmless (only noise positions) |
| dataSeed | 59 | **0%** | **100%** | **Not observable** |
| Total | 62 | 4.8% | 95.2% | dataSeed independent |

The CCA leak percentage (4.8%) is a structural property of the RGBWYOPA 8/1 format and does not depend on the hash function. The rotation barrier prevents mapping plaintext to physical positions regardless of hash properties (Section 2.9). However, resistance to CCA + KPA still requires PRF properties (Section 2.4.2).

**Practical value of the 4.8% leak: zero.** The leaked noise position reveals which of 8 bit positions is noise in each channel — a structural classification, not data. It provides:

- Zero plaintext bits (data values remain XOR-encrypted)
- Zero XOR mask bits (56 independent masks per pixel, unobservable)
- Zero start pixel information (data-to-pixel mapping unknown)
- Zero key-space reduction (Grover unchanged at 2^(keyBits/2))
- Zero advantage over pure brute-force (bit-plane check is a cheaper reject test per candidate, not a smaller search space)

The 4.8% leak is the structural cost of noise position range {0-7} under CCA with MAC-reveal. This range was chosen to eliminate the FORMAT+KPA attack surface: with noise restricted to {0,1}, bits 2-7 are deterministically data from the public format, giving an attacker 86% of XOR config under KPA without any oracle. With {0-7}, no bit position is deterministically data — FORMAT knowledge provides 0% XOR config.

### 4.6 Noise-Density Paradox and Optimality of 8/1

**Paradox.** Increasing the number of noise bits per channel strengthens the information-theoretic barrier (more unknown bits per pixel) but simultaneously increases the CCA configuration leak, because more config bits are needed to describe the noise bit positions.

With N noise bits per channel (8 − N data bits), selecting N positions from 8 requires ⌈log₂ C(8, N)⌉ config bits per pixel for position selection, plus (8 − N) × 7 XOR bits for data protection:

| Format | Data/ch | Noise/ch | Data/px | Noise/px | Overhead | Config/px | CCA leak |
|---|---|---|---|---|---|---|---|
| 8/1 (ITB) | 7 | 1 | 56 | 8 | 1.14× | 62 | 4.8% |
| 6/2 | 6 | 2 | 48 | 16 | 1.33× | 56 | 8.9% |
| 5/3 | 5 | 3 | 40 | 24 | 1.60× | 49 | 12.2% |
| 4/4 | 4 | 4 | 32 | 32 | 2.00× | 41 | 17.1% |

**Barrier strength (1024-bit key):**

| Format | MinPixels | Min side | Barrier | vs Landauer (2^306) |
|---|---|---|---|---|
| 8/1 (ITB) | 147 → 169 | 13×13 | 2^1352 | 4.4× beyond |
| 6/2 | 171 → 196 | 14×14 | 2^3136 | 10.2× beyond |
| 5/3 | 205 → 225 | 15×15 | 2^5400 | 17.6× beyond |
| 4/4 | 256 → 256 | 16×16 | 2^8192 | 26.8× beyond |

Note: MinPixels = ceil(keyBits / dataBitsPerChannel) differs per format. Ratios are of exponents (1352/306 = 4.4), not of actual values.

All formats produce barriers far beyond the Landauer limit. Increasing noise strengthens the barrier but with diminishing returns — all are already physically unreachable.

**Why 8/1 is optimal.** The format simultaneously minimizes three metrics:

1. **CCA leak: 4.8%** — the lowest of any 8/1 design with full noise-position range {0-7}. More noise bits per channel require even more position-selection config bits.

2. **Overhead: 1.14×** — the most storage-efficient format. Each additional noise bit per channel costs 7 data bits per pixel (one per channel), increasing overhead from 1.14× to 1.33×, 1.60×, 2.00×.

3. **Barrier: 2^1352** — already 4.4× beyond the Landauer limit (~2^306). Further increase provides no practical security gain while degrading efficiency and increasing CCA leak.

The 8/1 format with noise range {0-7} sits at the Pareto frontier among the analyzed configurations. The 4.8% CCA leak is the cost of eliminating the FORMAT+KPA attack surface (Section 4.7), the 1.14× overhead is the minimum achievable with any noise at all, and the barrier exceeds physical limits by a comfortable margin.

### 4.7 Noise Position Range Paradox

**Design choice.** Noise position range {0-7} (3-bit config) was chosen over {0, 1} (1-bit config) to eliminate the FORMAT+KPA attack surface.

**The FORMAT+KPA vulnerability of restricted noise {0, 1}:** With noise restricted to positions 0 and 1, bits 2-7 are deterministically data from the public format. Under KPA (no CCA needed), the attacker computes XOR masks for bits 2-7 directly: `xor[1:6] = container_bits[2:7] XOR known_data[1:6]`. This yields 6 of 7 XOR bits per channel (86% of XOR config) without any oracle. With an invertible hash, the remaining 8 unknown bits per pixel (1 noise-position + 7 XOR[0]) are brute-forceable in ~P × 2^8 operations — seed recovery in polynomial time, even for core ITB without MAC.

**With noise range {0-7}:** No bit position is deterministically data. The attacker cannot compute ANY XOR bits from FORMAT knowledge alone — all 8 positions are uncertain without knowing the hash output. FORMAT+KPA yields 0% of XOR config.

**Trade-off:**

| Noise range | FORMAT+KPA XOR leak (no CCA) | CCA config leak | Total |
|---|---|---|---|
| {0, 1} | 86% (bits 2-7 public) | 1.7% (1/60) | **Seed recoverable without CCA** |
| **{0-7} (ITB)** | **0%** | **4.8%** | **4.8% under CCA only** |

The CCA leak increases from 1.7% to 4.8%, but the FORMAT+KPA attack is completely eliminated. This is a better trade-off: the 4.8% CCA leak is analyzed as harmless (Section 4.2–4.3), while the 86% FORMAT+KPA leak was exploitable with invertible hash functions.

## 5. Formal Definitions

**Definition 1 (ITB Security).** The construction with security parameter λ = keyBits is (t, ε)-secure if no adversary running in time t can distinguish encryption of a chosen message from a uniformly random string of the same length, with advantage > ε, where ε ≤ t / 2^(λ/2) + negl(λ).

**Definition 2 (Hash Requirements).** The hash function H must be a PRF (pseudorandom function). PRF-grade hash functions provide all properties required by the construction: full input sensitivity, chain survival, non-affine mixing, avalanche, and non-invertibility. The random-container barrier provides additional architectural hardening by making hash output unobservable.

| PRF property | Formal condition | Excluded class | Attack prevented |
|---|---|---|---|
| Full input sensitivity | ∀ byte positions j, ∃ x₁, x₂ differing at j: H(x₁, s) ≠ H(x₂, s) for most s | Constant functions, partial-input functions | Nonce bypass, cross-message config reuse |
| Chain survival | H(data, seed) ≠ seed ⊕ f(data) for any f | XOR-cancelling functions | XOR-chain cancellation across even-length chains |
| Non-affine mixing | Output bits are not expressible as linear/affine functions of input bits | Purely affine functions | Algebraic solving (Gröbner basis, SAT) |
| Avalanche | Single-bit input change flips ~50% of output bits | Functions without avalanche | Correlation attacks, cube attacks |
| Non-invertibility | Given H(data, seed) and data, seed is not efficiently recoverable | Invertible functions | ChainHash inversion, KPA + seed recovery, MITM backward step |

Triple-seed architecture isolates dataSeed (zero side-channel, register-only), but all PRF properties are still needed for all three seeds because: non-affine mixing prevents algebraic solving of constraint systems derived from CCA or local simulation, avalanche prevents correlation/cube attacks on consecutive ChainHash outputs, non-invertibility prevents ChainHash inversion when noise positions are revealed via CCA or local CCA simulation.

**Definition 3 (Oracle-Free Deniability).** For any container C and candidate seed S' ≠ S:

```
{Decrypt128/256/512(S', C)} ≈_c {U_|C|}
```

**Definition 4 (Information-Theoretic Barrier).** A software-level property under the random-container model. For random container C where each byte C[p,ch] ~ Uniform(0,255) independently, for ANY hash function H, every observed byte value is compatible with every possible hash output:

```
∀v, ∀h : ∃c : embed(c, h, d) = v
```

No single-byte observation narrows the set of possible hash outputs. A passive observer who does not know C cannot determine the hash configuration from the container. The joint distribution of C' differs from uniform because pixel configurations are correlated through the seed; exploiting this correlation requires computational search over the key space. PRF-grade hash functions are required. The barrier provides additional architectural hardening by making hash output unobservable (Section 2.4.2).

## 6. 512-bit Hash Support

The ITB architecture supports 512-bit hash functions. The construction uses `HashFunc512` with `[8]uint64` seed:

```
HashFunc512: func(data []byte, seed [8]uint64) [8]uint64
ChainHash512: 8 components per round, 512-bit intermediate state
Effective max key: min(keyBits, 512 × numRounds)
```

For a 2048-bit key (32 components): ChainHash512 completes in 4 rounds (vs 8 rounds for ChainHash256, 16 for ChainHash128). Fewer rounds = wider MITM bottleneck (2^512) + faster execution (Section 1.1.4).

**Hash functions:**

| Hash | Output | Key input | Status |
|---|---|---|---|
| BLAKE2b | up to 512 bits | up to 512 bits | Production (golang.org/x/crypto) |
| BLAKE3 (XOF mode) | arbitrary length | 256 bits + XOF | Production (github.com/zeebo/blake3) |
| AES-512 | 512 bits | 512 bits | Experimental (laboratory research) |

BLAKE2b is the primary 512-bit hash: native 512-bit key input and 512-bit output, keyed mode (PRF), available in Go's extended standard library. BLAKE3 in XOF (extendable output function) mode can produce 512-bit output but its native key input is 256 bits — the additional 256 bits need to be mixed into the data, similar to the cached wrapper approach.

The 512-bit variant enables a theoretical effective key ceiling of 4096 bits (if MaxKeyBits is extended) with only 8 ChainHash512 rounds. This would exceed any foreseeable classical or quantum brute-force capability.

## 7. Research Directions

- Formal simulation-based proof of hash independence in the ideal cipher model.
- Formal analysis of MAC-inside-encrypt composition with ITB.
- Formal comparison with Threefish-1024 security margins and performance.
