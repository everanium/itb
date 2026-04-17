# ITB: Formal Proofs

> **Disclaimer.** These proofs are self-analysis by the author and have not been independently verified. ITB is an experimental construction. The information-theoretic barrier is a software-level property, reinforced by two independent barrier mechanisms: noise absorption from CSPRNG, and encoding ambiguity (56^P without CCA, 7^P under CCA) from triple-seed isolation. Architectural layers deny the point of application: independent startSeed and 8-noisePos ambiguity from independent noiseSeed under Full KPA, plus gcd(7,8)=1 byte-splitting under Partial KPA. Full KPA defense is 3-factor under PRF assumption (4-factor under Partial KPA) — see [Proof 4a](#proof-4a-multi-factor-full-kpa-resistance). It provides no guarantees against hardware-level attacks (DPA/SPA, Spectre, Meltdown, cache timing). No warranty is provided.

Formal security proofs for the ITB (Information-Theoretic Barrier) symmetric cipher construction.

## Notation

- H: PRF-grade hash function satisfying Definition 2 (see [SCIENCE.md](SCIENCE.md#5-formal-definitions))
- S = (s₀, s₁, ..., s_{n-1}): seed of n independent w-bit blocks (n = keyBits / w)
- N: 128-bit nonce from crypto/rand
- C[p]: original container byte at pixel p (crypto/rand, uniform over [0, 255])
- C'[p]: container byte after embedding
- ChainHash(data, S): iterated hash h₀=H(data,s₀), hᵢ=H(data,sᵢ⊕hᵢ₋₁)
- P: total pixel count in container
- Channels = 8 (RGBWYOPA)
- DataBitsPerChannel = 7

Proofs are stated in terms of generic ChainHash output. They apply equally to all width variants: 128-bit (HashFunc128, ChainHash128), 256-bit (HashFunc256, ChainHash256), and 512-bit (HashFunc512, ChainHash512) — the pixel processing and barrier properties are width-independent.

## Proof 1: Information-Theoretic Barrier

**Theorem.** For a random container C generated from crypto/rand and any hash function H satisfying [Definition 2](SCIENCE.md#5-formal-definitions), the distribution of observed pixel values after embedding is independent of the hash output.

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

This holds for any hash function H. The hash output h is consumed by modification of a random value and is not reconstructible from the observation. ∎

Note: this proof covers passive observation (Core ITB, MAC + Silent Drop). Under MAC + Reveal, noiseSeed config (3 bits/pixel) is additionally leaked via CCA oracle interaction — see [Proof 6](#proof-6-cca-leak-upper-bound).

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

The attacker with known plaintext d can compute a valid m for EVERY candidate position and rotation. All 56 candidates (8 noisePos × 7 rotation) per pixel are consistent with the observation without CCA. With CCA (noisePos known), 7 rotation candidates remain. Known plaintext does not uniquely determine the per-pixel configuration. Multi-pixel key recovery requires computational search over the key space.

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

**Theorem.** Three independent seeds are the minimum configuration such that compromise of any single configuration domain provides zero information about the remaining domains, under the documented attack surfaces (CCA for noise positions, cache side-channel for start pixel). This has not been independently verified.

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
Cache side-channel reveals S (startPixel) from Seed₂. Under KPA, for each pixel the attacker has 56 candidate hash outputs ([Section 2.9 in SCIENCE.md](SCIENCE.md#29-per-bit-xor-and-known-plaintext-resistance)). S narrows the pixel-to-data mapping. Combined KPA + known S constrains Seed₂, leaking partial information about D. Cross-domain leak: S → D.

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

D has zero software-observable side-channel. Even combined CCA + cache + KPA provides: N configuration (from noiseSeed) + start pixel (from startSeed) + known plaintext. Per-bit XOR (1:1) ensures 7 candidate rotations per pixel remain valid ([Section 2.9 in SCIENCE.md](SCIENCE.md#29-per-bit-xor-and-known-plaintext-resistance)). Without information about dataSeed, the attacker cannot distinguish candidates → security reduces to brute-force over dataSeed key space.

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

*Step 2: PRF property propagates the change.*
By the PRF property, H with altered input is computationally indistinguishable from a fresh uniform value. Therefore h_k differs substantially (with overwhelming probability) when s_k changes.

*Step 3: The change cascades through subsequent rounds.*
At round k+1: the input is `s_{k+1} ⊕ h_k`. Since h_k changed, this input changes; by the PRF property applied again, h_{k+1} is indistinguishable from fresh uniform and hence differs from the original. By induction, every subsequent output h_{k+1}, h_{k+2}, ..., h_{n-1} differs with overwhelming probability.

*Step 4: Contradiction.*
The final output h_{n-1} changes when s_k changes. This contradicts the assumption that s_k does not influence h_{n-1}.

Since this holds for all k ∈ {0, ..., n-1}, all components influence the output.

**Role of chain survival.** Chain survival prevents a separate failure mode: XOR-cancelling hash functions where H(data, k) = k ⊕ f(data). Such functions satisfy avalanche for individual calls, but in even-length chains the data dependency cancels:
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

**Under the PRF assumption (inversion is infeasible):** To verify a candidate (r', m'), the attacker would need to check if m' equals bits 3-58 of ChainHash(counter||nonce, dataSeed). This requires evaluating ChainHash with the correct dataSeed — but dataSeed is unknown, and ChainHash cannot be inverted.

The attacker cannot verify individual pixel rotations independently. The total configuration space is:

```
|{(r₁, r₂, ..., r_P) : rᵢ ∈ {0,...,6}}| = 7^P
```

For P = 196 (minimum Encrypt/Stream container, 1024-bit key): 7^196 ≈ 10^166 ≈ 2^550 — exceeds the Landauer thermodynamic limit (~2^306 ≈ 10^92), and each of the 10^166 rotation configurations requires independent ChainHash evaluation to verify, making exhaustive search computationally infeasible with any foreseeable technology. For P = 400 (minimum Auth container): 7^400 ≈ 2^1123. The noise barrier (2^1568 for 196 pixels, [Proof 5](#proof-5-noise-barrier-bound)) independently exceeds the Landauer limit. ∎

This proof covers one layer (rotation barrier). For the complete multi-factor Full KPA defense, see [Proof 4a](#proof-4a-multi-factor-full-kpa-resistance).

## Proof 4a: Multi-Factor Full KPA Resistance

**Theorem.** Under the PRF assumption, Full KPA brute-force seed recovery requires at least:
- P × 2^(2×keyBits) hash evaluations for Core ITB (joint noiseSeed + dataSeed search)
- P × 2^keyBits hash evaluations for MAC + Reveal (noiseSeed eliminated, dataSeed + startPixel enumeration)

with 7^P (or 56^P without CCA) per-pixel encoding ambiguity as an additional factor that any shortcut attack must also defeat. The attacker must simultaneously succeed on three independent obstacles — (1) PRF inversion, (2) enumeration of P startPixel candidates derived from an independent startSeed, (3) resolution of 7-rotation × 8-noisePos per-pixel ambiguity at signal/noise 1:1 — plus one Partial-KPA-specific obstacle, (4) gcd(7,8)=1 byte-splitting non-alignability, effective only under Partial KPA.

**Proof.** Obstacles (1)–(3) correspond to disjoint entropy sources and jointly determine the Full KPA brute-force cost; obstacle (4) is a Partial-KPA-specific defense:

**(1) PRF inversion.** Given a verified candidate dataHash h', recovering dataSeed from H(counter||nonce, dataSeed) = h' requires hash inversion ([Definition 2, SCIENCE.md §5](SCIENCE.md#5-formal-definitions)). Under the PRF assumption (which implies one-wayness), this is infeasible.

**(2) startPixel isolation.** startPixel = f(startSeed, nonce) where startSeed ⊥ noiseSeed ⊥ dataSeed ([Proof 3](#proof-3-triple-seed-isolation)). startPixel is not transmitted in the cleartext header. An attacker with full known plaintext does not know which pixel of the container corresponds to plaintext byte 0 — there are P candidate offsets with no feedback to narrow them.

**(3) Per-pixel ambiguity at 1:1 signal/noise.** Per [Proof 1](#proof-1-information-theoretic-barrier): P(v | h) = 1/2 for any observed byte v and any hash output h. Per [Proof 4](#proof-4-rotation-barrier): 7 rotation candidates remain indistinguishable after the barrier. Combined: 56 candidates per pixel (8 noisePos × 7 rotation), each equally consistent with the observation. Signal/noise ratio is 1:1 — the observation provides no ranking signal to the attacker. Formally: sup_{c,c'} Pr[c | obs] / Pr[c' | obs] = 1 — all candidates are equiprobable conditional on the observation.

**(4) Byte-splitting non-alignability (Partial KPA defense).** Per [SCIENCE.md §2.9.1](SCIENCE.md#291-byte-splitting-property-78-non-alignment): gcd(7,8)=1 guarantees every plaintext byte is split across exactly 2 channels. Under Partial KPA, where the attacker has incomplete plaintext, per-channel candidate formulation (a potential shortcut attack) is blocked because each channel depends on two bytes — missing one prevents candidate computation. Under Full KPA this shortcut is not available anyway (brute force enumerates seeds directly), so obstacle (4) has no additional defensive effect.

**Composition.** Obstacles (1)–(3) have disjoint entropy sources by [Proof 3](#proof-3-triple-seed-isolation) and jointly determine the Full KPA brute-force cost stated in the theorem. Full KPA defense is 3-factor under PRF assumption (PRF non-invertibility, startPixel isolation, per-pixel 1:1 ambiguity); gcd(7,8)=1 byte-splitting is a 4th factor effective only under Partial KPA. The obstacles are not independent sub-problems defeated sequentially but interlocking constraints.

**Composition conjecture.** Hash output bias and collisions are absorbed by the barrier ([Proof 7](#proof-7-bias-neutralization), BHT analysis). Occasional/sporadic PRF inversion events are additionally absorbed by startPixel isolation and per-pixel 1:1 ambiguity (obstacles 2, 3), plus gcd(7,8)=1 byte-splitting under Partial KPA (obstacle 4): recovered candidates become indistinguishable from the false-positive distribution. Systematic partial PRF inversion is a real (non-absorbed) threat that the barrier does not neutralize — the architecture raises cost but does not eliminate the attack — however, no such systematic weakness is currently known to reduce the Full KPA work factor below the theorem bound. Only total PRF inversion circumvents this via algorithmic seed recovery (see Asymmetry note).

**Asymmetry note.** Obstacle (1) (PRF non-invertibility) is asymmetrically privileged: a complete failure of PRF (total hash inversion) allows obstacles (2)–(4) to be resolved algorithmically via recovered seeds, whereas a complete failure of any architectural layer leaves PRF non-invertibility intact. The multi-factor property therefore protects against **partial** PRF weakening and **any degree** of architectural weakness, but not against **total** PRF inversion. ∎

## Proof 5: Noise Barrier Bound

**Theorem.** With Channels = 8, MinPixels = ⌈keyBits / log₂(56)⌉ for Encrypt/Stream and MinPixelsAuth = ⌈keyBits / log₂(7)⌉ for Auth, the noise barrier 2^(Channels × P) strictly exceeds the key space 2^keyBits.

**Proof.** For keyBits = 1024, Encrypt/Stream mode:

```
MinPixels = ⌈1024 / log₂(56)⌉ = ⌈1024 / 5.807⌉ = 177
```

Square container: side = ⌈√177⌉ = 14, P = 196.

Noise barrier:
```
2^(8 × 196) = 2^1568
```

Key space: 2^1024.

```
1568 > 1024  ⟹  2^1568 > 2^1024  ✓
```

The barrier strictly exceeds the key space by a factor of 2^544.

For keyBits = 1024, Auth mode:

```
MinPixelsAuth = ⌈1024 / log₂(7)⌉ = ⌈1024 / 2.807⌉ = 365
```

Square container: side = ⌈√365⌉ = 20, P = 400.

Noise barrier:
```
2^(8 × 400) = 2^3200
```

The barrier strictly exceeds the key space by a factor of 2^2176.

**General:** For Encrypt/Stream, P ≥ ⌈keyBits / log₂(56)⌉. Since 8 / log₂(56) = 8 / 5.807 ≈ 1.378 > 1, we have 8P > keyBits. For Auth, P ≥ ⌈keyBits / log₂(7)⌉. Since 8 / log₂(7) = 8 / 2.807 ≈ 2.850 > 1, we have 8P > keyBits. ∎

## Proof 6: CCA Leak Upper Bound

This proof applies to the MAC + Reveal mode only. Under Core ITB and MAC + Silent Drop, no CCA oracle exists and the leak is zero.

**Theorem.** Under CCA with MAC-reveal, the noise position (3 bits per pixel from noiseSeed) is the maximum information extractable about the configuration under this attack model. Per-bit XOR prevents any further leakage.

**Proof.** The CCA oracle provides a binary response per query: accept (noise bit flipped, data unchanged, MAC passes) or reject (data bit flipped, data changed, MAC fails).

**Step 1: Noise bits produce "accept."** Flipping a noise bit at position noisePos does not modify any data bit in the decoded capacity. The MAC covers the decoded capacity → MAC passes → oracle responds "accept."

**Step 2: Data bits produce "reject."** Flipping a data bit modifies the corresponding bit in the decoded capacity. The MAC covers the entire capacity → MAC fails → oracle responds "reject."

**Step 3: Response is binary.** Each query yields exactly 1 bit of information. The response classifies the flipped bit as noise or data.

**Step 4: Classification determines noisePos.** For each channel byte (8 bits), exactly 1 produces "accept" (noise) and 7 produce "reject" (data). The position of the "accept" bit is noisePos. Per pixel: 8 channels share the same noisePos → 8 queries per pixel suffice (testing each bit position in any single channel; all channels share the same noisePos).

**Step 5: No further information.** After classification, the attacker knows noisePos for each pixel (3 bits from noiseSeed). The 7 data bit positions are known, but their VALUES are protected by per-bit XOR:
- Each data bit = `rotate(plaintext_bit ⊕ xor_mask_bit, r)`
- XOR mask and rotation from dataSeed (independent of noiseSeed, [Proof 3](#proof-3-triple-seed-isolation))
- Per [Proof 2](#proof-2-per-bit-xor-kpa-resistance): any observed value is consistent with any plaintext under some (m, r)

Multi-bit flips yield a single binary response — no amplification beyond single-bit classification.

**Total CCA leak: 3 bits per pixel (noisePos) / 62 total config bits = 4.8%.** ∎

## Proof 7: Bias Neutralization

**Theorem.** The rotation barrier makes dataSeed output bias unobservable regardless of hash function output distribution.

**Proof.** Suppose H has output bias: some bits of ChainHash output are more likely 0 than 1. This affects:
- dataRotation = dataHash % 7 → some rotations more frequent
- channelXOR bits → some XOR values more probable

**Unobservability:** The attacker cannot observe dataSeed's hash output ([Proof 3](#proof-3-triple-seed-isolation): triple-seed isolation). The bias manifests only in the encrypted data within the container:

```
container_data = insert(rotate(plaintext ⊕ biased_xor, biased_r), noise, noisePos)
```

Without knowing rotation r, the attacker observes rotated-and-XOR'd data. The rotation scrambles any statistical pattern:
- Different pixels use different rotations (from different dataHash evaluations)
- The attacker sees rotate(x, r) where r varies from pixel to pixel
- Without r, the mapping plaintext → observed bits is 7-to-1 ambiguous per pixel

**With non-invertible hash:** Even if the attacker detects statistical patterns in observed bits, they cannot verify candidate rotations ([Proof 4](#proof-4-rotation-barrier)). The bias provides a Bayesian prior (some rotations more likely), but without verification, this prior cannot be confirmed or exploited:

```
P(r = r' | observed) ≈ P(r = r') × P(observed | r = r') / P(observed)
```

Without the ability to evaluate P(observed | r = r') (requires dataSeed), the Bayesian update is uninformative. ∎

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
- No checksum or MAC in Core ITB
- COBS null terminator: with wrong seeds, first 0x00 byte occurs at a random position → COBS decodes a random-length random byte sequence
- The probability that wrong seeds produce valid-looking output with a null terminator at a "reasonable" position is non-negligible — this is by design (deniability)

Under the random-container model, the construction provides indistinguishability under ciphertext-only attack. ∎

## Proof 9: Ambiguity Dominance Threshold

**Definition (Ambiguity-Based Security).** A construction has (k, P)-ambiguity-based security if, for key size k bits and container of P pixels, the number of observation-consistent configurations exceeds 2^k for P > P_threshold.

**Theorem.** For ITB with key size k bits:
- Under CCA (MAC + Reveal): P_threshold = ⌈k / log₂(7)⌉ ≈ ⌈k / 2.807⌉
- Without CCA (Core ITB / MAC + Silent Drop): P_threshold = ⌈k / log₂(56)⌉ ≈ ⌈k / 5.807⌉

Above P_threshold, encoding ambiguity exceeds the key space in the exponent.

**Proof.** Under CCA, each pixel has 7 rotation candidates ([Proof 4](#proof-4-rotation-barrier)). The total ambiguity is 7^P. The condition 7^P > 2^k is equivalent to:

```
P × log₂(7) > k
P > k / log₂(7)
P > k / 2.807
```

Without CCA, each pixel has 56 candidates (8 noisePos × 7 rotation). The condition 56^P > 2^k:

```
P × log₂(56) > k
P > k / log₂(56)
P > k / 5.807
```

**Concrete thresholds:**

| Key size | CCA (7^P > 2^k) | No CCA (56^P > 2^k) |
|---|---|---|
| 1024-bit | P > 365 pixels (~2.5 KB) | P > 177 pixels (~1.2 KB) |
| 2048-bit | P > 730 pixels (~5.0 KB) | P > 353 pixels (~2.4 KB) |

For any data volume above these thresholds, encoding ambiguity dominates the key space — the number of indistinguishable configurations exceeds the total number of possible keys. The MinPixels formula now guarantees ambiguity dominance at minimum container in all modes: Encrypt/Stream (P=196, no CCA) uses MinPixels = ⌈keyBits / log₂(56)⌉ which guarantees 56^P > 2^keyBits; Auth (P=400, CCA possible) uses MinPixelsAuth = ⌈keyBits / log₂(7)⌉ which guarantees 7^P > 2^keyBits. ∎

## Proof 10: Guaranteed CSPRNG Residue (No Perfect Fill)

**Theorem.** With container dimensions (side+1) × (side+1) where side = ⌈√(max(dataPixels, MinPixels))⌉, the container capacity strictly exceeds the maximum payload for any plaintext size. CSPRNG fill bytes are always present in the data bit positions after embedding.

**Motivation.** Under CCA (MAC + Reveal), the attacker identifies and removes noise bits (12.5% of container). The remaining 87.5% contains data bits: encrypted plaintext + COBS framing + CSPRNG fill. If the container were perfectly filled (zero CSPRNG fill), all data bits would carry known-structure content (COBS-encoded plaintext + null terminator). With CSPRNG fill present, a portion of the data bits carry random fill — indistinguishable from encrypted plaintext even after noise removal. This preserves information-theoretic ambiguity within the data bit positions.

**Proof.** Let s = ⌈√P_min⌉ where P_min = max(dataPixels, MinPixels). The current container uses P = s² pixels. With the `side++` modification, P' = (s+1)².

The maximum payload that produces side value s is bounded by the capacity of an s² container:

```
max_payload(s) ≤ s² × 7 bytes
```

(Since if payload required more than s² pixels, side would be s+1 or larger.)

The capacity of the (s+1)² container:

```
capacity(s+1) = (s+1)² × 7 = (s² + 2s + 1) × 7 bytes
```

The guaranteed CSPRNG fill (gap between capacity and maximum payload):

```
gap = capacity(s+1) - max_payload(s)
    ≥ (s² + 2s + 1) × 7 - s² × 7
    = (2s + 1) × 7 bytes
```

Since s ≥ 1: gap ≥ 21 bytes. For practical values (s ≥ 14 at 1024-bit key): gap ≥ 203 bytes.

**This gap is strictly positive for all s ≥ 1.** Perfect fill (gap = 0) is mathematically impossible. ∎

**Consequence for CCA resistance.** After CCA removes noise bits, the attacker observes 7 data bits per channel. These data bits contain:

1. Encrypted plaintext (COBS-encoded + null terminator)
2. Encrypted CSPRNG fill (guaranteed present by this theorem)

Both are encrypted identically by dataSeed (rotation + XOR). The attacker cannot distinguish encrypted plaintext from encrypted CSPRNG fill — both are processed by the same ChainHash-derived configuration. The CSPRNG fill provides information-theoretic ambiguity **within the data bit positions**, independent of and in addition to the rotation barrier (7^P, [Proof 4](#proof-4-rotation-barrier)).

**Guaranteed minimum CSPRNG fill by data size:**

| Data size | Side (s) | Min fill = 7×(2s+1) |
|---|---|---|
| MinPixels 1024-bit | 14 | 203 bytes |
| MinPixelsAuth 1024-bit | 20 | 287 bytes |
| 16 KB | 49 | 693 bytes |
| 1 MB | 388 | 5,439 bytes |
| 64 MB | 3,103 | 43,449 bytes |

The CSPRNG residue grows with data size: larger containers have proportionally more guaranteed fill. This is a structural property of the `side++` construction and does not depend on the hash function, key size, or plaintext content.

---

## Additional Theorems

The following theorems are well-known properties included for completeness. They are not numbered in the scientific paper.

## MAC-Inside-Encrypt Composition

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

## Nonce Uniqueness

**Theorem.** With 128-bit nonces from crypto/rand, the birthday collision probability reaches ~50% at 2^64 messages and remains practically safe for up to ~2^48 messages (collision probability ~2^{-33}). A nonce collision affects only the colliding pair.

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
