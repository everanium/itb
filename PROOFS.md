# ITB: Formal Proofs

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

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

<a name="proof-3-8-seed-isolation"></a>
## Proof 3: 8-Seed Isolation

**Theorem.** In the 8-seed architecture — noiseSeed, lockSeed, dataSeed1..3, startSeed1..3 — compromise of any proper subset of seeds provides zero information about the remaining seeds.

**Proof.** The 8 seeds are generated independently from crypto/rand and enforced pairwise-distinct at the API surface by byte-level `Components` comparison in addition to pointer identity, so byte-identical seed material reaching the API through blob import or the Low-Level constructors is rejected on the same gate. By construction:

1. **noiseSeed → noisePos**: `noiseHash = ChainHash(counter||nonce, noiseSeed) & 7`
2. **lockSeed → per-chunk Interlocked Barrier mask triple**: `rank = ChainHash(tag||groupIdx, deriveInterLockSeed(lockSeed, nonce))`; two-step unrank per [Proof 11](#proof-11-48-bit-interlocked-barrier-mask-space).
3. **dataSeed_i → per-snake rotation, XOR** (i ∈ {1,2,3}): `dataHash_i = ChainHash(counter||nonce, dataSeed_i)`
4. **startSeed_i → per-snake startPixel** (i ∈ {1,2,3}): `startPixel_i = ChainHash(0x02||nonce, startSeed_i) % totalPixels_i`

Each seed's ChainHash uses only its own components. No seed's components participate in another seed's computation.

**CCA compromise of noiseSeed:** The CCA oracle reveals noisePos for each pixel. This is a function of noiseSeed only. Since noiseSeed is independent of every other seed as a random variable:

```
I(dataSeed_i ; noisePos₁, noisePos₂, ..., noisePos_P) = 0     for every i ∈ {1,2,3}
I(startSeed_i ; noisePos₁, noisePos₂, ..., noisePos_P) = 0    for every i ∈ {1,2,3}
I(lockSeed ; noisePos₁, noisePos₂, ..., noisePos_P) = 0
```

where I denotes mutual information. The noise positions carry zero information about any other seed.

**Cache side-channel compromise of a single startSeed_i:** The memory access pattern reveals startPixel_i. This is a function of startSeed_i only:

```
I(dataSeed_j ; startPixel_i) = 0    for every j ∈ {1,2,3}
I(startSeed_j ; startPixel_i) = 0   for every j ≠ i
```

**Combined compromise:** Even with any strict subset S ⊊ {noiseSeed, lockSeed, dataSeed_{1..3}, startSeed_{1..3}} fully known:

```
I(seed ∈ ({all 8} \ S) ; S) = 0
```

because all 8 are independently generated (the pairwise independence between seeds is information-theoretic). The attacker knows whatever channels S controls but the remaining seeds' rotation, XOR masks, per-snake pixel offsets, and per-chunk barrier permutation remain unrecoverable — computationally so under the PRF assumption via cascade PRF binding, not information-theoretically (total PRF inversion recovers them via the [Asymmetry note](#proof-4a-multi-factor-full-kpa-resistance) of Proof 4a). Seed pairwise independence is information-theoretic; individual seed unrecoverability under Full KPA is PRF-conditional.

**dataSeed_i side-channel:** each dataSeed's hash output is consumed only by:
- `dataRotation = dataHash % 7` — register operation
- `xorMask = dataHash >> 3` — register operation
- `rotateBits7(dataBits, dataRotation)` — register-only shifts
- `dataBits ^= channelXOR` — register XOR

No memory access depends on dataSeed's values. No cache line, no memory pattern, no software-observable signal.

**lockSeed side-channel:** the barrier's per-chunk unrank consumes lockSeed-derived PRF output through combinadic table lookups over the `binomialC48 [49][17]uint64` table (§13 of ITB.md) with a fixed access pattern determined by loop indices, not by secret values; PEXT/PDEP kernels are constant-time by ISA specification. No secret-dependent branches or memory accesses. ∎

<a name="proof-3a-8-seed-isolation-minimality"></a>
## Proof 3a: 8-Seed Isolation Minimality

**Theorem.** 8 independent seeds — one per derivation domain — are the minimum configuration such that compromise of any single domain provides zero information about the remaining domains, under the documented attack surfaces (CCA for noise positions, cache side-channel for start pixels). Any layout with fewer seeds merges at least two domains onto one seed and creates cross-domain or cross-snake leakage. This has not been independently verified.

**Proof.**

*Part 1: 8 derivation domains.*

The construction defines 8 disjoint derivation domains, each keyed by its own seed:
- **N** (noise): noise bit position per pixel (3 bits/pixel), derived from noiseSeed
- **L** (lock): per-chunk Interlocked Barrier mask triple, derived from lockSeed
- **D₁, D₂, D₃** (data): rotation (3 bits) + per-bit XOR masks (56 bits) per pixel, derived from the per-snake dataSeed_i
- **S₁, S₂, S₃** (start): per-snake pixel embedding offset (one per message), derived from the per-snake startSeed_i

Each domain has a documented attack surface (see [Proof 3](#proof-3-8-seed-isolation)):
- N is recoverable via CCA with MAC-reveal (bit-flip → accept = noise bit)
- each S_i is observable via cache side-channel (memory access pattern)
- each D_i has zero software-observable side-channel (register-only operations)
- L has zero software-observable side-channel (fixed-pattern table lookups, constant-time kernels)

Parts 2–4 establish minimality for the pixel-layer domain types (N, D, S) on one snake; Part 5 lifts the argument to the full 8-domain layout.

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

*Part 4: Three pixel-layer domain types — pairwise independence.*

With the three pixel-layer seeds generated independently from crypto/rand:

```
I(noiseSeed ; dataSeed) = 0
I(noiseSeed ; startSeed) = 0
I(dataSeed ; startSeed) = 0
```

CCA reveals N (noiseSeed configuration). Since noiseSeed and dataSeed are independent random variables, I(dataSeed ; noiseSeed) = 0 — knowledge of the complete noiseSeed configuration provides zero information about dataSeed. Similarly for startSeed.

Cache reveals S (startSeed → startPixel). Since startSeed is independent of both noiseSeed and dataSeed, the leak is contained.

D has zero software-observable side-channel. Even combined CCA + cache + KPA provides: N configuration (from noiseSeed) + start pixel (from startSeed) + known plaintext. Per-bit XOR (1:1) ensures 7 candidate rotations per pixel remain valid ([Section 2.9 in SCIENCE.md](SCIENCE.md#29-per-bit-xor-and-known-plaintext-resistance)). Without information about dataSeed, the attacker cannot distinguish candidates → security reduces to brute-force over dataSeed key space.

Within the pixel-layer domain types, three independent seeds are therefore minimal: fewer creates cross-domain leakage in every possible pairing.

*Part 5: Lifting to the 8-domain layout.*

The shipped construction instantiates the D and S domain types once per snake and adds the barrier domain L. Merging any two of the 8 domains onto one seed reproduces one of the Part 3 leakage patterns:

- **Observable + unobservable** (N or any S_i merged with L or any D_j): the observable domain's attack surface (CCA for N, cache for S_i) constrains the shared seed, leaking information about the unobservable domain — the pattern of pairings (a) and (c).
- **Observable + observable** (N merged with an S_i, or S_i with S_j): two attack surfaces target one seed, and observations from one surface reduce the search space for the other domain — the pattern of pairing (b). For S_i + S_j the leak is additionally cross-snake: one snake's observed startPixel constrains another snake's offset.
- **Unobservable + unobservable** (L with a D_i, or D_i with D_j): no direct software-observable surface exists, but the merged domains lose statistical independence — under KPA, candidate constraints formulated against one snake's rotation/XOR channel (or against the barrier's mask channel) would constrain the other domain derived from the same seed, defeating the independence that [Proof 3](#proof-3-8-seed-isolation) establishes and that the Full KPA composition ([Proof 4a](#proof-4a-multi-factor-full-kpa-resistance)) and the per-chunk mask-space argument ([Proof 11](#proof-11-48-bit-interlocked-barrier-mask-space)) treat as disjoint entropy sources.

Every layout with at most 7 seeds merges at least two of the 8 domains (pigeonhole) and therefore contains at least one of the three patterns. 8 independent seeds are the minimum: any merge creates cross-domain or cross-snake leakage, while 8 CSPRNG-generated independent keys achieve the pairwise independence of [Proof 3](#proof-3-8-seed-isolation). ∎

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

For P = 196 (the ⌈1024 / log₂(56)⌉-derived container at a 1024-bit key — a looser worked bound below the shipped floor; see the MinPixels unification note in [Proof 5](#proof-5-noise-barrier-bound)): 7^196 ≈ 10^166 ≈ 2^550 — exceeds the Landauer bound on irreversible enumeration cost (~2^306 ≈ 10^92), and each of the 10^166 rotation configurations requires independent ChainHash evaluation to verify. The Landauer bound scopes to the cost of blind enumeration of the configuration space; it does not bound structural attacks that do not enumerate. For P = 400 (the unified shipped floor `MinPixels := MinPixelsAuth`, 1024-bit key): 7^400 ≈ 2^1123. The noise barrier (2^1568 for 196 pixels, [Proof 5](#proof-5-noise-barrier-bound)) independently exceeds the Landauer enumeration-cost bound. ∎

This proof covers one layer (rotation barrier). For the complete multi-factor Full KPA defense, see [Proof 4a](#proof-4a-multi-factor-full-kpa-resistance).

## Proof 4a: Multi-Factor Full KPA Resistance

**Theorem.** Under the PRF assumption, Full KPA brute-force seed recovery requires at least:
- P × 2^(2×keyBits) hash evaluations for Core ITB (joint noiseSeed + dataSeed search)
- P × 2^keyBits hash evaluations for MAC + Reveal (noiseSeed eliminated, dataSeed + startPixel enumeration)

with 7^P (or 56^P without CCA) per-pixel encoding ambiguity as an additional factor that any shortcut attack must also defeat. The attacker must simultaneously succeed on three independent obstacles — (1) PRF inversion, (2) enumeration of P startPixel candidates derived from an independent startSeed, (3) resolution of 7-rotation × 8-noisePos per-pixel ambiguity at signal/noise 1:1 — plus one Partial KPA-specific obstacle, (4) gcd(7,8)=1 byte-splitting non-alignability, effective only under Partial KPA.

**Proof.** Obstacles (1)–(3) correspond to disjoint entropy sources and jointly determine the Full KPA brute-force cost; obstacle (4) is a Partial KPA-specific defense:

**(1) PRF inversion.** Given a verified candidate dataHash h', recovering dataSeed from H(counter||nonce, dataSeed) = h' requires hash inversion ([Definition 2, SCIENCE.md §5](SCIENCE.md#5-formal-definitions)). Under the PRF assumption (which implies one-wayness), this is infeasible.

**(2) startPixel isolation.** startPixel = f(startSeed, nonce) where startSeed ⊥ noiseSeed ⊥ dataSeed ([Proof 3](#proof-3-8-seed-isolation)). startPixel is not transmitted in the cleartext header. An attacker with full known plaintext does not know which pixel of the container corresponds to plaintext byte 0 — there are P candidate offsets with no feedback to narrow them.

**(3) Per-pixel ambiguity at 1:1 signal/noise.** Per [Proof 1](#proof-1-information-theoretic-barrier): P(v | h) = 1/2 for any observed byte v and any hash output h. Per [Proof 4](#proof-4-rotation-barrier): 7 rotation candidates remain indistinguishable after the barrier. Combined: 56 candidates per pixel (8 noisePos × 7 rotation), each equally consistent with the observation. Signal/noise ratio is 1:1 — the observation provides no ranking signal to the attacker. Formally: sup_{c,c'} Pr[c | obs] / Pr[c' | obs] = 1 — all candidates are equiprobable conditional on the observation.

**(4) Byte-splitting non-alignability (Partial KPA defense).** Per [SCIENCE.md §2.9.1](SCIENCE.md#291-byte-splitting-property-78-non-alignment): gcd(7,8)=1 guarantees every plaintext byte is split across exactly 2 channels. Under Partial KPA, where the attacker has incomplete plaintext, per-channel candidate formulation (a potential shortcut attack) is blocked because each channel depends on two bytes — missing one prevents candidate computation. Under Full KPA this shortcut is not available anyway (brute force enumerates seeds directly), so obstacle (4) has no additional defensive effect.

**Composition.** Obstacles (1)–(3) have disjoint entropy sources by [Proof 3](#proof-3-8-seed-isolation) and jointly determine the Full KPA brute-force cost stated in the theorem. Full KPA defense is 3-factor under PRF assumption (PRF non-invertibility, startPixel isolation, per-pixel 1:1 ambiguity); gcd(7,8)=1 byte-splitting is a 4th factor effective only under Partial KPA. The obstacles are not independent sub-problems defeated sequentially but interlocking constraints.

**Composition conjecture.** Hash output bias and collisions are absorbed by the barrier ([Proof 7](#proof-7-bias-neutralization), BHT analysis). Occasional/sporadic PRF inversion events are additionally absorbed by startPixel isolation and per-pixel 1:1 ambiguity (obstacles 2, 3), plus gcd(7,8)=1 byte-splitting under Partial KPA (obstacle 4): recovered candidates become indistinguishable from the false-positive distribution. Systematic partial PRF inversion is a real (non-absorbed) threat that the barrier does not neutralize — the architecture raises cost but does not eliminate the attack — however, no such systematic weakness is currently known to reduce the Full KPA work factor below the theorem bound. Only total PRF inversion circumvents this via algorithmic seed recovery (see Asymmetry note).

**Asymmetry note.** Obstacle (1) (PRF non-invertibility) is asymmetrically privileged: a complete failure of PRF (total hash inversion) allows obstacles (2)–(4) to be resolved algorithmically via recovered seeds, and the always-on Interlocked Barrier's per-chunk mask permutation ([Proof 11](#proof-11-48-bit-interlocked-barrier-mask-space)) similarly collapses via lockSeed recovery (cascade PRF inversion through the mask-derivation chain) or direct Full KPA observation of mask triples from plaintext-chunk to permuted-wire correspondence; whereas a complete failure of any architectural layer leaves PRF non-invertibility intact. The multi-factor property therefore protects against **partial** PRF weakening and **any degree** of architectural weakness, but not against **total** PRF inversion. ∎

**SAT recovery.** SAT-based lockSeed recovery is structurally unmeasurable at attacker-realism. Any formulable SAT instance under the barrier requires granting seven of eight seeds via lab peek to strip the per-pixel stage; a granted-7/8 attacker is not the reuse-realistic attacker (who holds only the ciphertext pair and public nonces). Without stripping the per-pixel stage, the lockSeed → mask path runs through two consecutive live PRF calls (`lockKey = ChainHash(0x04‖interlock_nonce, lockSeed)`, then per-chunk `prf_i = H(0x03‖⟨i⟩, lockKey)`) and the instance reduces to PRF preimage recovery on the primitive, dominated by the primitive's SAT-hardness rather than the interlock's. The measurable instance and the reuse-realistic instance are disjoint by construction; the closure is PRF-conditional by construction.

**Dual-nonce carve-out.** Under the shipped dual-nonce wire format, simultaneous collision of both nonces across two messages is a degeneracy a production caller cannot reach: both nonces are drawn independently from CSPRNG per encryption with no caller-addressable override, so simultaneous collision requires a CSPRNG hardware fault. Under any partial-collision scenario (main-only or interlock-only), the un-collided axis provides fresh-nonce closure and the barrier's plaintext-recovery closure holds a fortiori.

## Proof 5: Noise Barrier Bound

**Note on MinPixels unification.** The shipped construction unifies the container floor: `MinPixels := MinPixelsAuth = ⌈keyBits / log₂(7)⌉` applies to both plain and MAC-authenticated surfaces (the code aliases `MinPixels()` to `MinPixelsAuth()` for every width). One floor for both modes closes an Auth-vs-Non-AEAD distinguisher: the minimum-message container size is mode-independent, so the length envelope does not betray which mode is in use.

**Theorem.** With Channels = 8 and the unified shipped floor `MinPixels = MinPixelsAuth = ⌈keyBits / log₂(7)⌉` (both plain and Auth surfaces), the noise barrier 2^(Channels × P) strictly exceeds the key space 2^keyBits. The looser `⌈keyBits / log₂(56)⌉` quantity — the no-CCA ambiguity-dominance count of [Proof 9](#proof-9-ambiguity-dominance-threshold), which sits below the shipped floor and never ships as a container minimum — gives a second, weaker worked bound and is retained only for illustration.

**Proof.** For keyBits = 1024, the shipped unified floor (both modes):

```
MinPixels = MinPixelsAuth = ⌈1024 / log₂(7)⌉ = ⌈1024 / 2.807⌉ = 365
```

Square container: side = ⌈√365⌉ = 20, P = 400.

Noise barrier:
```
2^(8 × 400) = 2^3200
```

Key space: 2^1024.

```
3200 > 1024  ⟹  2^3200 > 2^1024  ✓
```

The barrier strictly exceeds the key space by a factor of 2^2176.

For keyBits = 1024, the looser no-CCA bound (below the shipped floor, illustrative only):

```
P_noCCA = ⌈1024 / log₂(56)⌉ = ⌈1024 / 5.807⌉ = 177
```

Square container: side = ⌈√177⌉ = 14, P = 196; noise barrier 2^(8 × 196) = 2^1568 > 2^1024, exceeding the key space by 2^544. This bound is weaker than the shipped floor and is never instantiated as a container minimum.

**General:** For the shipped floor (both modes), P ≥ ⌈keyBits / log₂(7)⌉; since 8 / log₂(7) = 8 / 2.807 ≈ 2.850 > 1, we have 8P > keyBits. The looser no-CCA quantity P ≥ ⌈keyBits / log₂(56)⌉ satisfies 8 / log₂(56) = 8 / 5.807 ≈ 1.378 > 1, so 8P > keyBits there too. ∎

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
- XOR mask and rotation from dataSeed (independent of noiseSeed, [Proof 3](#proof-3-8-seed-isolation))
- Per [Proof 2](#proof-2-per-bit-xor-kpa-resistance): any observed value is consistent with any plaintext under some (m, r)

Multi-bit flips yield a single binary response — no amplification beyond single-bit classification.

**Total CCA leak: 3 bits per pixel (noisePos) / 62 total config bits = 4.8%.** ∎

## Proof 7: Bias Neutralization

**Theorem.** The rotation barrier makes dataSeed output bias unobservable regardless of hash function output distribution.

**Proof.** Suppose H has output bias: some bits of ChainHash output are more likely 0 than 1. This affects:
- dataRotation = dataHash % 7 → some rotations more frequent
- channelXOR bits → some XOR values more probable

**Unobservability:** The attacker cannot observe dataSeed's hash output ([Proof 3](#proof-3-8-seed-isolation): 8-seed isolation). The bias manifests only in the encrypted data within the container:

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

**Theorem.** For any container C encrypted with the 8-seed tuple (noiseSeed, lockSeed, dataSeed1..3, startSeed1..3) and any candidate 8-seed tuple that differs on at least one component, the output of `itb.Decrypt3x{128,256,512}Cfg` on C under the candidate tuple is computationally indistinguishable from uniform random bytes.

**Proof.** `Decrypt3x*Cfg` extracts a byte sequence by:
1. Computing each snake's startPixel from its startSeed' (deterministic, different from the true startPixels).
2. Computing noisePos from noiseSeed' for each pixel (deterministic, different from true).
3. Computing rotation and XOR from each dataSeed_i' for each pixel of snake i (deterministic, different from true).
4. Reversing the 48-bit Interlocked Barrier per-chunk mask triple derived from lockSeed' (deterministic, different from the true per-chunk permutation).
5. Extracting, un-rotating, and XOR-decrypting 56 data bits per pixel.
6. Interleaving the three snake outputs back into a byte stream.

Since C was generated from crypto/rand (uniform bytes) and embedded using the true seeds, the bits extracted with wrong seeds correspond to:
- Wrong noise positions → extracting a mix of true noise and true data bits.
- Wrong rotation → un-rotating with incorrect r.
- Wrong XOR → XOR-decrypting with incorrect mask.
- Wrong lockSeed → inverting a wrong per-chunk permutation, so the pre-COBS byte stream is a scrambled reordering of the true post-barrier bits.
- Wrong startPixel_i → reading each snake's data out of a wrong position.

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

For any data volume above these thresholds, encoding ambiguity dominates the key space — the number of indistinguishable configurations exceeds the total number of possible keys. The unified MinPixels formula (`MinPixels := MinPixelsAuth = ⌈keyBits / log₂(7)⌉`) guarantees ambiguity dominance at the minimum container size across both streaming modes: 7^P > 2^keyBits at the unified floor. The 56^P bound remains valid for any container above the plain-mode threshold as an additionally tighter statement in the absence of CCA. ∎

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
| no-CCA bound 1024-bit (illustrative, below shipped floor) | 14 | 203 bytes |
| shipped floor 1024-bit (MinPixels = MinPixelsAuth) | 20 | 287 bytes |
| 16 KB | 49 | 693 bytes |
| 1 MB | 388 | 5,439 bytes |
| 64 MB | 3,103 | 43,449 bytes |

The CSPRNG residue grows with data size: larger containers have proportionally more guaranteed fill. This is a structural property of the `side++` construction and does not depend on the hash function, key size, or plaintext content.

---

## Proof 11: 48-bit Interlocked Barrier Mask Space

**Theorem.** For each 48-bit chunk of the interleaved payload, the Interlocked Barrier draws a mask triple `(m0, m1, m2)` of pairwise-disjoint 16-of-48 lanes from a per-chunk PRF-keyed space of

- A = C(48, 16) = **2,254,848,913,647** (log₂ ≈ 41.04) — choices for `m0`,
- B = C(32, 16) = **601,080,390** (log₂ ≈ 29.16) — choices for `m1` from the remaining 32 bits (`m2` is then determined),

giving a per-chunk mask space of cardinality

```
|Ω_chunk| = A · B = 1,355,345,464,406,015,082,330  ≈  2^70.20 .
```

Under the PRF assumption, the per-chunk mask draws are computationally indistinguishable from independent uniform selections from Ω_chunk. A known-plaintext crib supplying 48 known bits of a chunk does not determine that chunk's mask; the number of preimages per mask triple is `⌊2^128 / (A · B)⌋ ≈ 2^57.80` and every candidate mask remains consistent with the observation.

**Proof.** Balanced-partition counting. A partition of a 48-bit word into three disjoint 16-bit lanes is fully specified by choosing `m0` (`C(48, 16) = A` ways), then `m1` from the remaining 32 bits (`C(32, 16) = B` ways); `m2` is the complement. The product `A · B` is the cardinality of Ω_chunk.

PRF independence. The barrier derives each chunk's mask triple by consuming a domain tag plus the little-endian group index as the PRF input under `deriveInterLockSeed(lockSeed, nonce)`. Distinct chunks receive distinct PRF inputs and therefore distinct, PRF-independent output ranks. Under the PRF assumption these ranks are computationally indistinguishable from independent uniform selections from `[0, 2^128)`.

Preimage count. The unrank map `Ω_rank : [0, 2^128) → Ω_chunk` is the two-step `(idx0, idx1) = (⌊rank / B⌋ mod A, rank mod B)` applied to `rank`. Its preimage counts differ by at most 1: the `2^128 mod (A · B)` lowest-indexed pairs receive `⌈2^128 / (A · B)⌉ = ⌊2^128 / (A · B)⌋ + 1 ≈ 2^57.80` preimages, and the remainder receive `⌊2^128 / (A · B)⌋ ≈ 2^57.80` preimages (the two floors are equal at the 2^57.80 order). Every mask triple therefore has at least `⌊2^128 / (A · B)⌋ ≈ 2^57.80` PRF-output preimages, so any candidate mask triple is consistent with any observation.

**Composition with pixel-layer ambiguity.** Combined with the per-pixel 1:1 signal/noise ambiguity of [Proof 1](#proof-1-information-theoretic-barrier) and the 7-rotation encoding ambiguity of [Proof 4](#proof-4-rotation-barrier), the attacker has no ranking signal among the ≈ 2^70.20 masks per chunk. The barrier's contribution is structural: it adds a hidden per-chunk permutation whose knowledge is required before any per-bit constraint can even be written down.

**Bias — granularity, not distinguisher.** The two-step reduction is deterministic and constant-time; rejection sampling is avoided to preserve constant-time discipline. The reduction carries a fixed, publicly-known per-chunk relative deviation of **≈ 2^-57.8** (the `2^128 mod (A · B)` +1-preimage pairs vs the rest). Accumulated linearly over a maximum-size message of `2^23.42` chunks, the per-message deviation is bounded by **≈ 2^-34.4** (contract value; the tighter iid bound is ≈ 2^-36). Turning this granularity into a confident distinguisher would require on the order of `1 / ε² ≈ 2^115.6` chunk samples — outside any attainable sample budget. The biased event is a property of PRF output (one-way by assumption) and is unobservable beneath the barrier / noise / fill stack, so it exposes no key or plaintext channel in principle.

The empirical statement is bounded: "no distinguisher reachable at attainable sample sizes", not "no bias". ∎

## Proof 12: gcd(A, B) Anti-Collapse Trap

**Theorem.** The rejected same-rank reduction `(rank mod A, rank mod B)` reaches only `1 / gcd(A, B)` of the joint `(m0, m1)` space, where

```
gcd(A, B) = gcd(C(48, 16), C(32, 16)) = 66861 = 3² · 17 · 19 · 23 .
```

The chosen two-step reduction `(⌊rank / B⌋ mod A, rank mod B)` reaches the full `A × B` space near-uniformly.

**Proof.** For any fixed `d = gcd(A, B)`, the pair `(rank mod A, rank mod B)` is a function of `rank mod lcm(A, B) = A · B / d`, so its range is a subset of `[0, A) × [0, B)` of cardinality `A · B / d = A · B / 66861`. The pairs `(a, b)` reached by this reduction are exactly those satisfying `a ≡ b (mod d)`. The remaining `A · B · (d − 1) / d ≈ (A · B) · (1 − 1/66861)` pairs are unreachable.

Concretely, the reachable fraction of `(m0, m1)` pairs under the rejected same-rank double-mod is

```
1 / 66861  ≈  1.5 × 10⁻⁵ ,
```

so ≈ 99.998 % of the `A × B` mask space would be structurally excluded. An attacker exploiting the reduction structure would face a 66861×-restricted mask space through the back door — a substantial `log₂ 66861 ≈ 16.03`-bit erosion of the [Proof 11](#proof-11-48-bit-interlocked-barrier-mask-space) floor.

**Contrast with the chosen reduction.** The two-step map `rank ↦ (⌊rank / B⌋, rank mod B)` is a bijection `[0, 2^128) → [0, ⌊2^128 / B⌋) × [0, B)`. Reducing the first component `mod A` maps each pair `(a, b)` to `≈ ⌊2^128 / (A · B)⌋ = 2^57.80` preimages, differing by at most 1 — the deviation is granularity, not a distinguisher — so every pair in the full `[0, A) × [0, B)` is reached, with the near-uniformity bound of [Proof 11](#proof-11-48-bit-interlocked-barrier-mask-space). Full-space coverage is a deliberate property of the two-step reduction, not an accident.

**Constant-time note.** The qmod accumulator `qmod = (qmod · 2^64 + limb) mod A` computes `⌊rank / B⌋ mod A` incrementally during schoolbook division. Reduction commutes with the Horner form of the quotient, so the two-step reduction introduces no skew beyond the documented ±1 preimage deviation. ∎

---

## Additional Theorems

The following theorems are well-known properties included for completeness. They are not numbered in the scientific paper.

## MAC-Inside-Encrypt Composition

**Theorem.** `itb.EncryptAuthenticated3x{128,256,512}Cfg` (and the streaming counterparts `itb.EncryptStreamAuth3xCfg`) with MAC over full capacity (COBS + null + fill) is designed to prevent CCA spatial patterns and false null-terminator attacks (given a secure MAC function).

**Proof.**

**Part A: No spatial patterns.** The MAC covers the entire capacity: `tag = MAC(payload)` where `payload = [COBS data][0x00][crypto/rand fill]`.

Under CCA, flipping any bit:
- **COBS data bit** → payload changes → MAC(modified) ≠ tag → reject
- **Null terminator bit** → payload changes → MAC(modified) ≠ tag → reject
- **Fill byte bit** → payload changes → MAC(modified) ≠ tag → reject
- **MAC tag bit** → tag changes → tag ≠ MAC(payload) → reject
- **Noise bit** → payload unchanged → MAC(payload) = tag → accept

Every data bit position produces "reject." Only noise bits produce "accept." The response pattern is uniform across all pixels: 87.5% reject, 12.5% accept. No spatial pattern distinguishes COBS from fill regions.

**Part B: False null-terminator prevention.** MAC is verified BEFORE null-terminator search in `itb.DecryptAuthenticated3x{128,256,512}Cfg`:

```
1. Decrypt3x{128,256,512}Cfg entire capacity → decoded[]
2. Verify: MAC(decoded[:payloadLen]) == decoded[payloadLen:]
3. ONLY IF MAC passes: search for null terminator in decoded[:payloadLen]
```

Any bit modification (including creating a false 0x00) fails MAC verification at step 2. Step 3 is never reached with tampered data. ∎

## Nonce Uniqueness

**Theorem.** With nonces drawn from crypto/rand at up to the shipped default 512-bit width, the birthday collision probability at width w reaches ~50 % at 2^(w/2) messages and remains practically safe well below that threshold. A nonce collision affects only the colliding pair.

**Proof.** By the birthday paradox, the probability of at least one collision among n nonces drawn uniformly from {0,1}^w:

```
P(collision) ≈ 1 - e^(-n²/2^(w+1)) ≈ n²/2^(w+1)
```

At w = 512 (the shipped default): P reaches ~1/2 only at n ≈ 2^256, mathematically unreachable on foreseeable hardware. At w = 128 (the shortest supported width): P reaches ~1/2 at n ≈ 2^64.

**Impact of collision:** The wire carries two independent per-message CSPRNG nonces — a main nonce `N_main` (bound to per-pixel noiseSeed / dataSeed_i derivations and per-snake startSeed_i derivations) and an interlock nonce `N_il` (bound to the lockSeed's per-chunk mask draw through the `0x04` domain tag). A collision on one axis leaves the other axis re-parametrised. Under joint collision of both nonces with the same 8-seed tuple:
- Same noiseSeed + `N_main` → identical noise positions for both messages.
- Same lockSeed + `N_il` → identical per-chunk Interlocked Barrier permutations for both messages.
- Same dataSeed_i + `N_main` → identical rotation and XOR masks per snake.
- Same startSeed_i + `N_main` → identical per-snake startPixels.
- Different crypto/rand containers (generated independently).

The attacker with two containers C₁, C₂ sharing the same configuration can extract corresponding data bits and XOR them: `data₁ ⊕ data₂` (two-time-pad structure at the bit level, after per-snake reversal). This affects ONLY the colliding pair — all other messages with unique nonces remain secure.

**Mitigation:** The nonce is mandatory and internally generated from crypto/rand on every `itb.Encrypt3x{128,256,512}Cfg` / `itb.EncryptStream*3xCfg` / `triple.Pipeline.Encrypt*` call. The caller cannot reuse nonces by design. ∎
