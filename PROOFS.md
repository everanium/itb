# ITB: Formal Proofs

> **Disclaimer.** These proofs are self-analysis by the author and have not been independently verified. ITB is an experimental construction. The information-theoretic barrier is a software-level property — it provides no guarantees against hardware-level attacks (DPA/SPA, Spectre, Meltdown, cache timing). No warranty is provided.

Formal security proofs for the ITB (Information-Theoretic Barrier) symmetric cipher construction.

## Notation

- H: hash function `func([]byte, uint64) uint64` satisfying Definition 2 (see SCIENCE.md)
- S = (s₀, s₁, ..., s₇): seed of 8 independent uint64 components
- N: 128-bit nonce from crypto/rand
- C[p]: original container byte at pixel p (crypto/rand, uniform over [0, 255])
- C'[p]: container byte after embedding
- ChainHash(data, S): iterated hash h₀=H(data,s₀), hᵢ=H(data,sᵢ⊕hᵢ₋₁)
- P: total pixel count in container
- Channels = 8 (RGBWYOPA)
- DataBitsPerChannel = 7

Proofs are stated in terms of generic ChainHash output. They apply equally to all width variants: 128-bit (HashFunc128, ChainHash128), 256-bit (HashFunc256, ChainHash256), and 512-bit (HashFunc512, ChainHash512) — the pixel processing and barrier properties are width-independent.

## Proof 1: Information-Theoretic Barrier

**Theorem.** For a random container C generated from crypto/rand and any hash function H satisfying Definition 2, the distribution of observed pixel values after embedding is independent of the hash output.

**Setup.** Consider one channel byte of pixel p. The original value C[p,ch] ~ Uniform(0, 255). The hash output determines: noise position noisePos (0-7), XOR mask channelXOR (7 bits), and rotation r (0-6).

Embedding replaces 7 of the 8 bit positions with encrypted data, preserving 1 noise bit at noisePos.

**Proof.** Let h denote the combined hash configuration for this pixel. The modified byte:

```
C'[p,ch] = insert(rotate(data_bits ⊕ channelXOR, r), C[p,ch], noisePos)
```

The `insert` operation preserves the original bit at position noisePos and writes 7 data bits at the remaining positions. The noise bit at noisePos retains its original value from C[p,ch].

For any fixed h (determining noisePos, channelXOR, r) and fixed data:
- The 7 data-bit positions are deterministic (function of data, channelXOR, r)
- The 1 noise-bit position retains C[p,ch]'s original bit at noisePos
- C[p,ch]'s bit at noisePos ~ Bernoulli(1/2) (uniform random bit)
- Therefore C'[p,ch] has exactly 2 possible values (noise bit = 0 or 1), each with probability 1/2

The attacker observes C'[p,ch] = v. For any candidate hash output h':
- There exist data bits and a noise bit value consistent with v under h'
- The observation v does not distinguish between hash outputs

Since C[p,ch] is independent of h (container generated before embedding), and the noise bit is the only random element in C'[p,ch]:

```
P(C'[p,ch] = v | h) = P(noise bit at noisePos matches v's bit at noisePos) = 1/2
```

This holds for ANY hash function H, including invertible ones. The hash output h is consumed by modification of a random value and is not reconstructible from the observation. ∎

## Proof 2: Per-Bit XOR KPA Resistance

**Theorem.** Under per-bit XOR (1:1), for any observed channel byte v and any known plaintext data bits d, there exists a 7-bit XOR mask m such that encoding d with mask m is consistent with v, for any noise position.

**Proof.** Given channel byte v and noise position noisePos:
1. Extract the 7 data-bit positions from v: `extracted = extract(v, noisePos)` (7 bits)
2. Un-rotate: for any candidate rotation r: `unrotated = rotate⁻¹(extracted, r)` (7 bits)
3. Compute candidate mask: `m = unrotated ⊕ d` (7 bits)

This m is uniquely determined and always exists (XOR is defined for all inputs). Therefore:

```
∀ d ∈ {0,1}⁷, ∀ v ∈ {0,...,255}, ∀ noisePos ∈ {0,...,7}, ∀ r ∈ {0,...,6}:
∃! m ∈ {0,1}⁷ : encode(d, m, r, noisePos) is consistent with v
```

The attacker with known plaintext d can compute a valid m for EVERY candidate position and rotation. All 56 candidates (8 noisePos × 7 rotation) per pixel are consistent with the observation — known plaintext does not uniquely determine the per-pixel configuration. Multi-pixel key recovery requires computational search over the key space.

**Corollary.** The attacker cannot determine the start pixel from known plaintext: every pixel position produces a valid (d, m) pair, making all P positions indistinguishable. ∎

## Proof 3: Triple-Seed Isolation

**Theorem.** In the triple-seed architecture, compromise of noiseSeed (via CCA) and/or startSeed (via cache side-channel) provides zero information about dataSeed.

**Proof.** The three seeds are generated independently from crypto/rand. By construction:

1. **noiseSeed → noisePos**: `noiseHash = ChainHash(counter||nonce, noiseSeed) & 7`
2. **dataSeed → rotation, XOR**: `dataHash = ChainHash(counter||nonce, dataSeed)`
3. **startSeed → startPixel**: `startPixel = ChainHash(0x02||nonce, startSeed) % totalPixels`

Each seed's ChainHash uses only its own components. No seed's components participate in another seed's computation.

**CCA compromise of noiseSeed:** The CCA oracle reveals noisePos for each pixel. This is a function of noiseSeed only. Since noiseSeed and dataSeed are independent random variables:

```
I(dataSeed ; noisePos₁, noisePos₂, ..., noisePos_P) = 0
```

where I denotes mutual information. The noise positions carry zero information about dataSeed.

**Cache side-channel compromise of startSeed:** The memory access pattern reveals startPixel. This is a function of startSeed only:

```
I(dataSeed ; startPixel) = 0
```

**Combined compromise:** Even with both noiseSeed and startSeed fully known:

```
I(dataSeed ; noiseSeed, startSeed) = 0
```

because all three are independently generated. The attacker knows the noise positions and data-to-pixel mapping, but dataSeed's rotation and XOR masks remain information-theoretically hidden.

**dataSeed side-channel:** dataSeed's hash output is consumed only by:
- `dataRotation = dataHash % 7` — register operation
- `xorMask = dataHash >> 3` — register operation
- `rotateBits7(dataBits, dataRotation)` — register-only shifts
- `dataBits ^= channelXOR` — register XOR

No memory access depends on dataSeed's values. No cache line, no memory pattern, no software-observable signal. ∎

## Proof 3a: Triple-Seed Isolation Minimality

**Theorem.** Three independent seeds is the minimum configuration such that compromise of any single configuration domain provides zero information about the remaining domains, under the documented attack surfaces (CCA for noise positions, cache side-channel for start pixel). This has not been independently verified.

**Proof.**

*Part 1: Three configuration domains.*

The construction defines three disjoint configuration domains:
- **N** (noise): noise bit position per pixel (3 bits/pixel), derived from noiseSeed
- **D** (data): rotation (3 bits) + per-bit XOR masks (56 bits) per pixel, derived from dataSeed
- **S** (start): pixel embedding offset (one per message), derived from startSeed

Each domain has a documented attack surface:
- N is recoverable via CCA with MAC-reveal (bit-flip → accept = noise bit)
- S is observable via cache side-channel (memory access pattern)
- D has zero software-observable side-channel (register-only operations)

*Part 2: Single seed — complete break.*

If one seed controls all three domains (N, D, S derived from same seed), CCA reveals N configuration (noise positions for all pixels). Since N and D are derived from the same seed, knowledge of N constrains the seed → D is recoverable. Complete configuration break.

*Part 3: Two seeds — all pairings create cross-domain leakage.*

Three possible 2-seed pairings exist. Each creates cross-domain leakage:

**(a) Seed₁ = {N}, Seed₂ = {D, S}:**
Cache side-channel reveals S (startPixel) from Seed₂. Under KPA, for each pixel the attacker has 56 candidate hash outputs (Section 2.9 in SCIENCE.md). S narrows the pixel-to-data mapping. Combined KPA + known S constrains Seed₂, leaking partial information about D. Cross-domain leak: S → D.

**(b) Seed₁ = {N, S}, Seed₂ = {D}:**
CCA reveals N from Seed₁. Cache reveals S from Seed₁. Both attack surfaces target the same seed. Multiple (nonce, startPixel) observations from cache side-channel provide constraints on Seed₁ → reduces search space for Seed₁ → N configuration obtained without CCA. Cross-domain leak: S → N.

**(c) Seed₁ = {N, D}, Seed₂ = {S}:**
CCA reveals N from Seed₁ (3 bits/pixel). Since N and D share Seed₁, CCA-derived N constraints reduce the effective key space of Seed₁. With KPA, the attacker knows plaintext and N configuration → 7 candidate D configurations per pixel (rotation 0-6), each fully determining the hash output → verification oracle for Seed₁. Cross-domain leak: N → D. This is the most severe pairing.

*Part 4: Three seeds — pairwise independence.*

With three seeds generated independently from crypto/rand:

```
I(noiseSeed ; dataSeed) = 0
I(noiseSeed ; startSeed) = 0
I(dataSeed ; startSeed) = 0
```

CCA reveals N (noiseSeed configuration). Since noiseSeed and dataSeed are independent random variables, I(dataSeed ; noiseSeed) = 0 — knowledge of the complete noiseSeed configuration provides zero information about dataSeed. Similarly for startSeed.

Cache reveals S (startSeed → startPixel). Since startSeed is independent of both noiseSeed and dataSeed, the leak is contained.

D has zero software-observable side-channel. Even combined CCA + cache + KPA provides: N configuration (from noiseSeed) + start pixel (from startSeed) + known plaintext. Per-bit XOR (1:1) ensures 7 candidate rotations per pixel remain valid (Section 2.9 in SCIENCE.md). Without information about dataSeed, the attacker cannot distinguish candidates → security reduces to brute-force over dataSeed key space.

Three seeds is therefore the minimum: fewer creates cross-domain leakage in every possible pairing; three achieves pairwise independence through CSPRNG-generated independent keys. ∎

## Proof 3b: ChainHash Full Component Utilization

**Theorem.** For any PRF-grade hash function H (which satisfies avalanche), ChainHash(data, S) with S = (s₀, s₁, ..., s_{n-1}) depends on all n components. No component can be changed without affecting the final output. This has not been independently verified.

**Proof.** By contradiction. Suppose component s_k (0 ≤ k ≤ n-1) does not influence the final output h_{n-1}.

ChainHash computes:
```
h₀ = H(data, s₀)
hᵢ = H(data, sᵢ ⊕ hᵢ₋₁)    for i = 1, ..., n-1
```

*Step 1: Changing s_k changes the input to round k.*
At round k, the second argument to H is `s_k ⊕ h_{k-1}` (or `s₀` for k=0). Changing s_k by even a single bit changes this argument by one bit.

*Step 2: Avalanche propagates the change.*
By the avalanche property (inherent in any PRF), a single-bit change in any input to H flips approximately 50% of output bits. Therefore h_k changes substantially when s_k changes.

*Step 3: The change cascades through subsequent rounds.*
At round k+1: the input is `s_{k+1} ⊕ h_k`. Since h_k changed (~50% of bits), this input changes, and by avalanche, h_{k+1} changes. By induction, every subsequent output h_{k+1}, h_{k+2}, ..., h_{n-1} changes.

*Step 4: Contradiction.*
The final output h_{n-1} changes when s_k changes. This contradicts the assumption that s_k does not influence h_{n-1}.

Since this holds for all k ∈ {0, ..., n-1}, all components influence the output.

**Role of chain survival (PRF property).** Chain survival prevents a separate failure mode: XOR-cancelling hash functions where H(data, k) = k ⊕ f(data). Such functions satisfy avalanche for individual calls, but in even-length chains the data dependency cancels:
```
h₁ = (s₁ ⊕ h₀) ⊕ f(data) = s₁ ⊕ s₀ ⊕ f(data) ⊕ f(data) = s₁ ⊕ s₀
```
All components are still utilized (summed via XOR), but the output loses dependence on the data input. Chain survival (satisfied by any PRF) prevents this, ensuring both component utilization and data sensitivity. ∎

## Proof 4: Rotation Barrier

**Theorem.** With unknown rotation r ∈ {0,...,6} from dataSeed, the attacker faces 7^P indistinguishable configurations for P pixels when using a non-invertible hash function.

**Proof.** Per-pixel, the attacker observes 7 data bits at known positions (after CCA reveals noisePos). These bits are `rotate(d ⊕ m, r)` where d is plaintext (known under KPA), m is XOR mask, and r is rotation.

For each candidate rotation r' ∈ {0,...,6}:
```
m' = rotate⁻¹(observed, r') ⊕ d
```

This produces a valid candidate XOR mask m'. There are exactly 7 valid (r', m') pairs per pixel. The attacker cannot determine which is correct without knowing dataSeed.

**With non-invertible hash (PRF property):** To verify a candidate (r', m'), the attacker would need to check if m' equals bits 3-58 of ChainHash(counter||nonce, dataSeed). This requires evaluating ChainHash with the correct dataSeed — but dataSeed is unknown, and ChainHash cannot be inverted.

The attacker cannot verify individual pixel rotations independently. The total configuration space is:

```
|{(r₁, r₂, ..., r_P) : rᵢ ∈ {0,...,6}}| = 7^P
```

For P = 169 (minimum container, 1024-bit key): 7^169 ≈ 10^143 ≈ 2^474 — exceeds the Landauer thermodynamic limit (~2^306 ≈ 10^92), and each of the 10^143 rotation configurations requires independent ChainHash evaluation to verify, making exhaustive search computationally infeasible with any foreseeable technology. The noise barrier (2^1352 for 169 pixels, Proof 5) independently exceeds the Landauer limit. ∎

## Proof 5: Noise Barrier Bound

**Theorem.** With Channels = 8 and MinPixels = ⌈keyBits / (Channels - 1)⌉, the noise barrier 2^(Channels × P) strictly exceeds the key space 2^keyBits.

**Proof.** For keyBits = 1024:

```
MinPixels = ⌈1024 / 7⌉ = 147
```

Square container: side = ⌈√147⌉ = 13, P = 169.

Noise barrier:
```
2^(8 × 169) = 2^1352
```

Key space: 2^1024.

```
1352 > 1024  ⟹  2^1352 > 2^1024  ✓
```

The barrier strictly exceeds the key space by a factor of 2^328.

**General:** For any keyBits and Channels = 8:
```
P ≥ ⌈keyBits / 7⌉
Barrier = 2^(8P) ≥ 2^(8 × ⌈keyBits/7⌉)
```

Since 8/7 > 1, we have 8 × ⌈(keyBits+6)/7⌉ > keyBits for all keyBits ≥ 1. ∎

## Proof 6: CCA Leak Upper Bound

**Theorem.** Under CCA with MAC-reveal, the noise position (3 bits per pixel from noiseSeed) is the maximum information extractable. Per-bit XOR prevents any further leakage.

**Proof.** The CCA oracle provides a binary response per query: accept (noise bit flipped, data unchanged, MAC passes) or reject (data bit flipped, data changed, MAC fails).

**Step 1: Noise bits produce "accept."** Flipping a noise bit at position noisePos does not modify any data bit in the decoded capacity. The MAC covers the decoded capacity → MAC passes → oracle responds "accept."

**Step 2: Data bits produce "reject."** Flipping a data bit modifies the corresponding bit in the decoded capacity. The MAC covers the entire capacity → MAC fails → oracle responds "reject."

**Step 3: Response is binary.** Each query yields exactly 1 bit of information. The response classifies the flipped bit as noise or data.

**Step 4: Classification determines noisePos.** For each channel byte (8 bits), exactly 1 produces "accept" (noise) and 7 produce "reject" (data). The position of the "accept" bit is noisePos. Per pixel: 8 channels share the same noisePos → 1 query per channel suffices.

**Step 5: No further information.** After classification, the attacker knows noisePos for each pixel (3 bits from noiseSeed). The 7 data bit positions are known, but their VALUES are protected by per-bit XOR:
- Each data bit = `rotate(plaintext_bit ⊕ xor_mask_bit, r)`
- XOR mask and rotation from dataSeed (independent of noiseSeed, Proof 3)
- Per Proof 2: any observed value is consistent with any plaintext under some (m, r)

Multi-bit flips yield a single binary response — no amplification beyond single-bit classification.

**Total CCA leak: 3 bits per pixel (noisePos) / 62 total config bits = 4.8%.** ∎

## Proof 7: Bias Neutralization

**Theorem.** The rotation barrier makes dataSeed output bias unobservable regardless of hash function output distribution.

**Proof.** Suppose H has output bias: some bits of ChainHash output are more likely 0 than 1. This affects:
- dataRotation = dataHash % 7 → some rotations more frequent
- channelXOR bits → some XOR values more probable

**Unobservability:** The attacker cannot observe dataSeed's hash output (Proof 3: triple-seed isolation). The bias manifests only in the encrypted data within the container:

```
container_data = insert(rotate(plaintext ⊕ biased_xor, biased_r), noise, noisePos)
```

Without knowing rotation r, the attacker observes rotated-and-XOR'd data. The rotation scrambles any statistical pattern:
- Different pixels use different rotations (from different dataHash evaluations)
- The attacker sees rotate(x, r) where r varies per pixel
- Without r, the mapping plaintext → observed bits is 7-to-1 ambiguous per pixel

**With non-invertible hash:** Even if the attacker detects statistical patterns in observed bits, they cannot verify candidate rotations (Proof 4). The bias provides a Bayesian prior (some rotations more likely), but without verification, this prior cannot be confirmed or exploited:

```
P(r = r' | observed) ≈ P(r = r') × P(observed | r = r') / P(observed)
```

Without the ability to evaluate P(observed | r = r') (requires dataSeed), the Bayesian update is vacuous. ∎

## Proof 8: Oracle-Free Deniability

**Theorem.** For any container C encrypted with seeds (nS, dS, sS) and any candidate seed tuple (nS', dS', sS') ≠ (nS, dS, sS), the output of Decrypt128/Decrypt256/Decrypt512(nS', dS', sS', C) is computationally indistinguishable from uniform random bytes.

**Proof.** Decrypt128/256/512 extracts a byte sequence by:
1. Computing startPixel from sS' (deterministic, different from true startPixel)
2. Computing noisePos from nS' for each pixel (deterministic, different from true)
3. Computing rotation and XOR from dS' for each pixel (deterministic, different from true)
4. Extracting, un-rotating, and XOR-decrypting 56 data bits per pixel

Since C was generated from crypto/rand (uniform bytes) and embedded using the true seeds (nS, dS, sS), the bits extracted with wrong seeds correspond to:
- Wrong noise positions → extracting a mix of true noise and true data bits
- Wrong rotation → un-rotating with incorrect r
- Wrong XOR → XOR-decrypting with incorrect mask

The extracted bytes are a deterministic but pseudorandom function of the wrong seeds applied to a random container. Without knowledge of the true seeds, the output is indistinguishable from uniform random.

**Structural guarantees:**
- No magic bytes or headers to distinguish correct from incorrect decryption
- No checksum or MAC in core ITB
- COBS null terminator: with wrong seeds, first 0x00 byte occurs at a random position → COBS decodes a random-length random byte sequence
- The probability that wrong seeds produce valid-looking output with a null terminator at a "reasonable" position is non-negligible — this is by design (deniability)

Under the random-container model, the construction provides indistinguishability under ciphertext-only attack. ∎

## Proof 9: MAC-inside-encrypt Composition

**Theorem.** `EncryptAuthenticated128`/`EncryptAuthenticated256`/`EncryptAuthenticated512` with MAC over full capacity (COBS + null + fill) is designed to prevent CCA spatial patterns and false null-terminator attacks (given a secure MAC function).

**Proof.**

**Part A: No spatial patterns.** The MAC covers the entire capacity: `tag = MAC(payload)` where `payload = [COBS data][0x00][crypto/rand fill]`.

Under CCA, flipping any bit:
- **COBS data bit** → payload changes → MAC(modified) ≠ tag → reject
- **Null terminator bit** → payload changes → MAC(modified) ≠ tag → reject
- **Fill byte bit** → payload changes → MAC(modified) ≠ tag → reject
- **MAC tag bit** → tag changes → tag ≠ MAC(payload) → reject
- **Noise bit** → payload unchanged → MAC(payload) = tag → accept

Every data bit position produces "reject." Only noise bits produce "accept." The response pattern is uniform across all pixels: 87.5% reject, 12.5% accept. No spatial pattern distinguishes COBS from fill regions.

**Part B: False null-terminator prevention.** MAC is verified BEFORE null-terminator search in DecryptAuthenticated128/256/512:

```
1. Decrypt128/256/512 entire capacity → decoded[]
2. Verify: MAC(decoded[:payloadLen]) == decoded[payloadLen:]
3. ONLY IF MAC passes: search for null terminator in decoded[:payloadLen]
```

Any bit modification (including creating a false 0x00) fails MAC verification at step 2. Step 3 is never reached with tampered data. ∎

## Proof 10: Nonce Uniqueness

**Theorem.** With 128-bit nonces from crypto/rand, the birthday collision probability reaches ~50% at 2^64 messages and is negligible for up to ~2^48 messages. A nonce collision affects only the colliding pair.

**Proof.** By the birthday paradox, the probability of at least one collision among n nonces drawn uniformly from {0,1}^128:

```
P(collision) ≈ 1 - e^(-n²/2^129) ≈ n²/2^129
```

For n = 2^64: P ≈ 2^128 / 2^129 = 1/2.

For n = 2^32 (4 billion messages): P ≈ 2^64 / 2^129 = 2^(-65) ≈ negligible.

**Impact of collision:** If nonce N is reused with the same seeds:
- Same noiseSeed + N → identical noise positions for both messages
- Same dataSeed + N → identical rotation and XOR masks
- Same startSeed + N → identical start pixel
- Different crypto/rand containers (generated independently)

The attacker with two containers C₁, C₂ sharing the same configuration can extract corresponding data bits and XOR them: `data₁ ⊕ data₂` (two-time pad at the bit level). This affects ONLY the colliding pair — all other messages with unique nonces remain secure.

**Mitigation:** The nonce is mandatory and internally generated from crypto/rand on every Encrypt128/256/512 call. The caller cannot reuse nonces by design. ∎
