# ITB: Scientific Analysis

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

## Abstract

ITB (Information-Theoretic Barrier) is a parameterized symmetric cipher construction that renders the hash output unreconstructible from ciphertext-only observation. **Noise absorption** interposes a CSPRNG-generated random container between the PRF hash output and the observer; each byte retains one random noise bit at an unknown position. Under known-plaintext, chosen-plaintext, and chosen-ciphertext attacks the closure is computational and PRF-conditional; the information-theoretic property scopes to the noise-absorption layer under passive observation (Theorem 1). **Encoding ambiguity** applies a secret rotation (0–6) from an independent per-snake dataSeed to each pixel's data bits, creating 7^P unverifiable configurations across P pixels. A mandatory, always-on **48-bit Interlocked Barrier** forms a second architectural layer: each 48-bit chunk of the payload is partitioned into three disjoint 16-of-48 lane payloads by a PRF-keyed balanced mask triple drawn from a space of cardinality ≈ 2^70.20 per chunk, unobservable without the dedicated lockSeed. Even if the noise mechanism is bypassed via CCA (which reveals noise positions), the rotation barrier, the per-chunk mask permutation, and CSPRNG residue in data positions survive through 8-seed isolation.

The 8-seed architecture (noiseSeed, lockSeed, three per-snake dataSeeds, three per-snake startSeeds) ensures that compromise of any single configuration domain provides zero information about the remaining domains; the lockSeed → per-chunk mask path is bound to the primitive through cascade PRF binding (two consecutive live PRF calls). A dual-nonce wire format carries two independently CSPRNG-drawn nonces per message, producing independent configurations per encryption with no caller-addressable override.

The construction exhibits **ambiguity-based security**: the number of observation-consistent *configurations* grows exponentially with data size. This property is orthogonal to Shannon's key-entropy bound and distinct from Shannon's perfect-secrecy relationship on plaintext entropy. Above a threshold P_th = ⌈k / log₂ C⌉ (C = 56 without CCA, C = 7 under CCA), encoding ambiguity exceeds the 2^k key space. At 64 KB plaintext, ambiguity reaches 2^26,414; its exponent is 25.8× the 1024-bit key-space exponent. An attacker-realistic audit suite in the reference implementation confirms the barrier's absorption across multiple trapdoor mechanism classes at the tested sample sizes (see [REDTEAM.md](REDTEAM.md)).

All operations are elementary: XOR, bitwise AND, modular reduction, and bit shifts. No Galois fields, no S-boxes, no polynomial multiplication. The security architecture composes around a pluggable PRF hash function; the construction's own operations are elementary, while the closures under KPA/CPA/CCA remain computational and PRF-conditional on the primitive.

**Companion documents.** For the accessible-explanation narrative of the construction, see [ITB.md](ITB.md). For the formal proof set (Theorems referenced throughout), see [PROOFS.md](PROOFS.md). For the empirical audit-suite verdicts, see [REDTEAM.md](REDTEAM.md). For the ChainHash trapdoor analysis on non-cryptographic primitives, see [HARNESS.md](HARNESS.md).

## 1. Construction

### 1.1 ChainHash

Let `H : {0,1}* × {0,1}^w → {0,1}^w` be a keyed PRF-grade hash function with output width `w` bits (`w ∈ {128, 256, 512}`). Let `S = (s_0, s_1, …, s_{n-1})` be a seed of `n` independent `w`-bit blocks, where `n = keyBits / w`.

ChainHash is defined as:

```
h_0 = H(data, s_0)
h_i = H(data, s_i ⊕ h_{i-1})   for i = 1, …, n-1
ChainHash(data, S) = h_{n-1}
```

Each round consumes one component and the previous round's output. The XOR mixing of `s_i` with `h_{i-1}` ensures all components influence the final output. Because subsequent seed components are mixed with the prior round's data-dependent hash output, `h_{i-1}` acts as a data-derived effective key from chain depth `i ≥ 2` onward — the property leveraged in trapdoor-absorption analysis (see [HARNESS.md](HARNESS.md) for the per-primitive treatment).

### 1.2 Per-Pixel Configuration

The 8-seed constellation comprises one **noiseSeed**, one **lockSeed**, three per-snake **dataSeeds** (`dataSeed_i`, `i ∈ {1,2,3}`), and three per-snake **startSeeds** (`startSeed_i`, `i ∈ {1,2,3}`). Independent ChainHash calls derive the configuration:

- From **noiseSeed** (3 config bits): `noisePos = noiseHash & 7`, with `noiseHash = ChainHash(counter ‖ N_m, noiseSeed)` — which bit position (0–7) in each channel is the noise bit.
- From **dataSeed_i** (~59 config bits per pixel): `rotation_i = dataHash_i mod 7` (values 0–6, log₂(7) ≈ 2.807 bits of entropy); `xorMask_i = dataHash_i >> 3` (56 independent XOR mask bits, 7 per channel). Each snake's `dataSeed_i` drives its own snake's per-pixel configuration independently.
- From **startSeed_i** (one per snake per message): each snake's starting pixel offset within its payload region, `startPixel_i = ChainHash(0x02 ‖ N_m, startSeed_i) mod P`.
- From **lockSeed**: the per-chunk mask triple of the 48-bit Interlocked Barrier (§1.5).

Total: ~62 config bits per pixel (exact: log₂(8 × 7 × 2^56) = 61.807), plus the per-chunk mask contribution of §1.5.

**Per-pixel encoder consumes only the low 64 bits of the ChainHash output.** Regardless of native primitive width (128 / 256 / 512), the per-pixel encoder reads only `hLo` = `h[0]` — the low 64 bits — of which about 62 are actually used. The narrowing is an encoder-layer choice, not part of ChainHash itself. It has one real side effect: any structural weakness concentrated in the discarded portion of the primitive's output is architecturally invisible to encryption-path observation. FNV-1a's top-bit-isolation case is the canonical example (see [REDTEAM.md § Broken-primitive stress](REDTEAM.md#broken-primitive-stress--fnv-1a-and-crc128)). Under the PRF assumption any consistent subset of a PRF's output is itself a PRF on those bits, so the narrowing preserves PRF-security without strengthening it.

**Interlocked Barrier consumes the full native output pair `(lo, hi)` for the per-chunk PRF.** The barrier's mask-triple draw calls `H` and consumes both 64-bit words of a 128-bit primitive output pair `(lo, hi)` as the 128-bit rank input to the combinadic unrank of §1.5 / §2.15. Both words are load-bearing; this is a barrier-layer choice independent of the pixel encoder's narrowing.

### 1.3 Embedding

The split of the plaintext into the three snake payloads happens in parallel with the per-chunk permutation, not sequentially after a byte round-robin. For each 48-bit chunk, the composite operation `chunk48lock` applies three simultaneous PEXT operations under the PRF-keyed mask triple `(m_0, m_1, m_2)`, producing the three 16-bit lane payloads `(l_0, l_1, l_2)` in one step. There is no intermediate byte round-robin step an attacker can pre-address; each snake's payload is a stream of PRF-permuted 16-bit lane fragments, not plaintext bytes at any offset.

For each channel of each pixel:

1. Extract 7 plaintext data bits from the snake_i payload emitted by `chunk48lock`.
2. XOR with the 7-bit channel mask from `dataSeed_i`.
3. Rotate by `r` positions (from `dataSeed_i`).
4. Insert into the CSPRNG-generated container byte, preserving the noise bit at position `noisePos`.

The dual-nonce wire header carries two nonces, `N_m` (main) and `N_il` (interlock), drawn independently from CSPRNG per encryption. `N_m` feeds the seven per-pixel derivation slots (noisePos, per-snake rotation and channelXOR, per-snake startPixel); `N_il` feeds the eighth — the lockSeed-keyed per-chunk mask draw. Neither slot is caller-addressable.

### 1.4 Message Framing

Plaintext is COBS-encoded (Consistent Overhead Byte Stuffing) before embedding. COBS eliminates 0x00 bytes from the encoded output, enabling a null terminator as the unambiguous message boundary. The null terminator is encrypted inside the container — invisible without the correct seeds.

Output format: `main_nonce (N bytes) ‖ interlock_nonce (N bytes) ‖ width (2 bytes) ‖ height (2 bytes) ‖ W×H×8 raw RGBWYOPA`, where `N` is the primitive's native nonce width in bytes. Header size = `2N + 4` bytes.

No magic bytes, no checksums, no message length header. Wrong seeds produce random-looking output with no verification oracle (oracle-free deniability; see [ITB.md § 16 Oracle-Free Deniability](ITB.md#16-oracle-free-deniability)). The per-message empirical decomposition of nonce collision behaviour under the dual-nonce header is deferred to §2.14.

### 1.5 The 48-bit Interlocked Barrier

The 48-bit Interlocked Barrier is a mandatory, always-on, non-disableable layer sitting between the payload interleave and the per-pixel configuration of §1.2. ChainHash, message framing, and the nonce requirement are unchanged; noise position, rotation, and per-bit XOR apply on the permuted lane payloads.

The interleaved payload is chunked into 48-bit (6-byte) words. For each chunk indexed by `i`, a balanced mask triple `(m_0, m_1, m_2)` is drawn — three 16-of-48-bit partitions of the chunk bits with `popcount(m_j) = 16`, pairwise disjoint, and `m_0 ∪ m_1 ∪ m_2 = 2^48 − 1`.

**Mask space.** The triple is drawn from a space `Ω_chunk` of cardinality `|Ω_chunk| = A · B ≈ 2^70.20` per chunk, with `A = C(48, 16)` and `B = C(32, 16)`; the full statement and cascade constants appear as Theorem 11 (§2.15).

**Cascade PRF binding.** The mask derivation is keyed by the dedicated `lockSeed` through two consecutive live PRF calls:

```
lockKey = ChainHash(0x04 ‖ N_il, lockSeed)
prf_i   = H(0x03 ‖ ⟨i⟩,    lockKey)
```

where `H` is the primitive's hash function, `N_il` is the interlock_nonce component of the dual-nonce header, and `⟨i⟩` is the little-endian byte encoding of the chunk index. The 128-bit output `rank = prf_i` (the full primitive output for a 128-bit primitive, the low 128 bits of wider primitives) is unranked into the mask triple by a two-step combinadic unrank:

```
(idx_0, idx_1) = (⌊rank / B⌋ mod A,   rank mod B)
```

followed by combinadic unrank of `idx_0` (yielding `m_0`) and of `idx_1` over the remaining 32 bits (yielding `m_1`); `m_2` is the complement.

**One composite operation.** `chunk48lock` applies three simultaneous PEXT operations under `(m_0, m_1, m_2)` to the 48-bit chunk word, producing three 16-bit lane payloads in one step (§1.3): split into 3 snakes and per-chunk permutation are one operation, not two. The mapping from a plaintext bit to the lane it lands in is a hidden per-chunk secret. The permutation layer alone is a keyed permutation (it re-orders bits without XOR of key material); the per-pixel stage (channelXOR, rotation, noise-bit insertion at noisePos) applies to each snake's permuted payload independently under its own `dataSeed_i` / `noiseSeed` / `startSeed_i`.

**Indivisibility.** The lockSeed → per-chunk mask path runs through two consecutive live PRF calls before the combinadic unrank produces the mask triple. Consequently, isolating the permutation layer's unrank hardness from the per-pixel configuration hardness requires either (a) granting seven of eight seeds via lab peek (not attacker-realistic under any threat model) or (b) trivializing the PRF (which destroys the cross-chunk coupling the mask hardness rides). The barrier is indivisible by construction at attacker-realism.

## 2. Security Analysis

### 2.1 Information-Theoretic Barrier (Theorem 1)

**Theorem 1 (Barrier).** *For a random container `C` generated from a CSPRNG and any PRF hash function `H`, the distribution of observed pixel values after embedding is independent of the hash output.*

The core observation: `P(C'[p, ch] = v | h) = 1/2` for any observed value `v` and any hash output `h`, because the noise bit at `noisePos` retains the original CSPRNG-generated container bit — Bernoulli(1/2) and independent of everything.

**Compatibility formula:**

```
∀v, ∀h : ∃c : embed(c, h, d) = v
```

For any observed value, any hash output, there exists a container byte that produces this observation. This is the information-theoretic core of the barrier and applies to the noise-absorption layer (Part 2 of the Interlocked Barrier composition) under passive observation. Full derivation: [PROOFS.md § Proof 1](PROOFS.md#proof-1-information-theoretic-barrier).

**Scope.** The IT property scopes to the noise-absorption layer under passive observation (COA / KPA). Under CCA the noise-position channel is revealed via oracle interaction (§2.8, Theorem 6); the closure of KPA / CPA / CCA is computational and PRF-conditional through the multi-factor defense of §2.6 (Theorem 4a). Part 1 of the barrier (the per-chunk permutation) is PRF-conditional throughout — its mask-space cardinality bound is Theorem 11 (§2.15).

### 2.2 Per-Bit XOR KPA Resistance (Theorem 2)

**Theorem 2.** *Under per-bit XOR (1:1), for any observed channel byte `v` and known plaintext data bits `d`, there exists a 7-bit XOR mask `m` such that encoding `d` with mask `m` is consistent with `v`, for any noise position and rotation.*

Given `v`, `noisePos`, and candidate rotation `r'`, a matching `m' = rotate⁻¹(extract(v, noisePos), r') ⊕ d` always exists. All 56 (8 × 7) candidates per pixel are consistent with the observation without CCA; with CCA (noisePos known), 7 rotation candidates remain. Known plaintext does not uniquely determine the per-pixel configuration. Full derivation: [PROOFS.md § Proof 2](PROOFS.md#proof-2-per-bit-xor-kpa-resistance).

Additionally, the per-chunk mask permutation (§2.15, Theorem 11) removes any fixed byte-position anchor a Crib KPA attacker could exploit: the crib bytes are moved to per-chunk PRF-keyed lane positions unobservable without lockSeed.

### 2.3 8-Seed Isolation (Theorems 3, 3a)

**Theorem 3.** *In the 8-seed architecture, compromise of any subset of `{noiseSeed, dataSeed_1, dataSeed_2, dataSeed_3, startSeed_1, startSeed_2, startSeed_3}` provides zero information about `lockSeed`, and symmetrically. Pairwise mutual information between any two of the 8 seeds is zero.*

The 8 seeds are drawn independently from CSPRNG. Each seed's ChainHash uses only its own components (`noiseSeed → noisePos`; `lockSeed → lockKey → per-chunk mask via cascade PRF`; `dataSeed_i → rotation_i, XOR_i`; `startSeed_i → startPixel_i`), so `I(any subset ; complement) = 0` where `I` is mutual information. CCA reveals noise positions (noiseSeed config); cache side-channel reveals a `startPixel_i` (startSeed_i config); neither carries any information about any other seed — in particular, none about lockSeed. The pairwise independence between seeds is information-theoretic (all 8 are CSPRNG-drawn); the individual unrecoverability of lockSeed under Full KPA is *computationally* hidden under the PRF assumption via cascade PRF binding, not information-theoretic — total PRF inversion recovers lockSeed via the Asymmetry note (§2.6). Full derivation: [PROOFS.md § Proof 3](PROOFS.md#proof-3-8-seed-isolation).

The lockSeed → per-chunk mask path is bound to the primitive via two consecutive live PRF calls (`deriveInterLockSeed`, then the per-chunk hash), so any attempt to isolate the permutation layer's unrank hardness from the primitive's PRF hardness reduces the instance to PRF preimage recovery — dominated by the primitive's SAT-hardness, not by the interlock structure.

**Theorem 3a (Minimality).** *Eight seeds are the minimum configuration where every leak in the 3-snake construction is architecturally isolated. Fewer seeds would create cross-domain leakage in at least one snake pair or between the barrier layer and one per-snake role.*

Pigeonhole argument on 8 disjoint derivation domains (N, L, D₁..D₃, S₁..S₃) with distinct attack surfaces: any layout with at most 7 seeds merges at least two domains, and every merger creates at least one cross-domain leakage pattern (observable + unobservable, snake collapse, or noise/mask coupling). 8 CSPRNG-independent seeds achieve the pairwise independence of Theorem 3. Full derivation: [PROOFS.md § Proof 3a](PROOFS.md#proof-3a-8-seed-isolation-minimality).

### 2.4 ChainHash Full Component Utilization (Theorem 3b)

**Theorem 3b.** *For any PRF-grade hash function `H`, `ChainHash(data, S)` depends on all `n` components. No component can be changed without affecting the final output.*

By contradiction plus the PRF property: any component change avalanches through subsequent rounds with overwhelming probability. Full derivation: [PROOFS.md § Proof 3b](PROOFS.md#proof-3b-chainhash-full-component-utilization).

### 2.5 Rotation Barrier (Theorem 4)

**Theorem 4.** *With unknown rotation `r ∈ {0, …, 6}` from `dataSeed_i`, the attacker faces `7^P` indistinguishable configurations for `P` pixels when using a non-invertible hash.*

For `P = 400` (minimum container at a 1024-bit key): `7^400 ≈ 2^1123`, which exceeds the Landauer bound on irreversible enumeration cost (~2^306); this bounds the cost of blind enumeration of the ambiguity space, not resistance to structural attacks. See [PROOFS.md § Proof 4](PROOFS.md#proof-4-rotation-barrier).

### 2.6 Multi-Factor Full KPA Resistance (Theorem 4a)

**Theorem 4a.** *Under the PRF assumption, Full KPA brute-force seed recovery requires: for Core ITB in Silent Drop mode (no verification oracle), at least `P × 2^(2·keyBits)` hash evaluations (joint noiseSeed + dataSeed search); for MAC + Reveal variants where the encrypted MAC tag serves as a local verification oracle, at least `P × 2^keyBits` hash evaluations (noiseSeed eliminated, dataSeed + startPixel enumeration verified locally per §2.13). The `7^P` (or `56^P` without CCA) per-pixel encoding ambiguity is an additional factor over either bound that any shortcut attack must also defeat.*

The attacker must simultaneously succeed on four independent obstacles whose entropy sources are disjoint by Theorem 3, plus one Partial KPA specific obstacle:

1. **PRF inversion.** Recovering a `dataSeed_i` from a verified candidate hash `h' = H(counter ‖ N_m, dataSeed_i)` is infeasible under the PRF assumption (which implies one-wayness).
2. **Per-chunk mask-triple isolation.** Each chunk observation admits ≈ 2^57.80 mask preimages (Theorem 11, §2.15); collapsing that ambiguity requires coupling many chunks through the shared lockSeed chain against the SAT-hostile combinadic unrank arithmetic. The mapping from a plaintext bit to the lane it lands in is unobservable without lockSeed.
3. **startPixel_i isolation.** `startPixel_i = f(startSeed_i, N_m)` is never transmitted; each snake presents its own candidate offset space with no feedback to narrow it, and no snake's recovery reveals another's.
4. **Per-pixel ambiguity at 1:1 signal/noise.** By Theorems 1 and 4, 56 per-pixel candidates (without CCA) or 7 (under CCA) are equally consistent with the observation. Formally, `sup_{c,c'} Pr[c | obs] / Pr[c' | obs] = 1`: all candidates are equiprobable conditional on the observation.
5. **Byte-splitting non-alignability (Partial KPA defense).** `gcd(7, 8) = 1` guarantees every plaintext byte is split across 2 channels. Under Partial KPA, per-channel candidate formulation is blocked because each channel depends on two bytes — missing one prevents candidate computation. Under Full KPA this shortcut is not available anyway (brute force enumerates seeds directly), so obstacle (5) has no additional defensive effect.

Obstacles (1)–(4) jointly determine the Full KPA brute-force cost; `gcd(7,8)=1` byte-splitting is a 5th factor effective only under Partial KPA. The obstacles are not sub-problems defeated sequentially but interlocking constraints. Full derivation: [PROOFS.md § Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance).

**SAT recovery.** SAT-based lockSeed recovery is **structurally unmeasurable at attacker-realism**. Any formulable SAT instance under the barrier requires granting seven of eight seeds via lab peek to strip the per-pixel stage (noiseSeed strips the noise bit, per-snake `dataSeed_i` strips per-pixel rotation and channelXOR, per-snake `startSeed_i` strips the per-snake pixel-to-chunk mapping). A granted-7/8 attacker is not the attacker-realistic attacker (the attacker-realistic attacker holds only the ciphertext pair and public nonces). Without stripping the per-pixel stage, the lockSeed → mask path runs through two live PRF calls and the instance reduces to PRF preimage recovery on the primitive, dominated by the primitive's SAT-hardness rather than the interlock's. The measurable instance and the attacker-realistic instance are disjoint by construction; the closure is PRF-conditional by construction. Empirically confirmed: naive-crib Bitwuzla returns UNSAT on FNV-1a keyed to every one of the 8 seed roles under the maximum-peek attacker regime (see [REDTEAM.md § FNV-1a lo-lane SAT — architecturally foreclosed](REDTEAM.md#fnv-1a-lo-lane-sat--architecturally-foreclosed)).

**Dual-nonce carve-out.** Under the shipped dual-nonce wire format, simultaneous collision of both nonces across two messages is a degeneracy a production caller cannot reach: both nonces are drawn independently from CSPRNG per encryption with no caller-addressable override, so simultaneous collision requires a **CSPRNG hardware fault**. Under any partial-collision scenario (main-only or interlock-only), the un-collided axis provides fresh-nonce closure and the barrier's plaintext-recovery closure holds a fortiori.

**Composition conjecture.** Hash output bias and collisions are absorbed by the barrier (§2.11, Theorem 7 + BHT analysis of §3.4). Occasional/sporadic PRF inversion events are additionally absorbed by per-chunk mask-triple isolation, startPixel isolation, and per-pixel 1:1 ambiguity (obstacles 2–4), plus `gcd(7,8)=1` byte-splitting under Partial KPA (obstacle 5): recovered candidates become indistinguishable from the false-positive distribution. Systematic partial PRF inversion is a real (non-absorbed) threat that the barrier does not neutralize — the architecture raises cost but does not eliminate the attack — however, no such systematic weakness is currently known to reduce the Full KPA work factor below the theorem bound. Only total PRF inversion circumvents this via algorithmic seed recovery (see Asymmetry note).

**Asymmetry note.** Obstacle (1) is asymmetrically privileged: a total PRF inversion algorithmically resolves obstacles (2)–(5) via recovered seeds; the per-chunk mask permutation collapses via lockSeed recovery through cascade PRF inversion of the mask-derivation chain, or via direct Full KPA observation of mask triples from plaintext-chunk to permuted-wire correspondence. Failure of any architectural layer leaves PRF non-invertibility intact. Theorem 4a protects against *partial* PRF weakness and *any degree* of architectural weakness, but not against total PRF inversion.

**Why KPA candidates do not break the barrier.** Under KPA, the attacker can compute 56 candidate dataHash values per pixel — but these are *calculated* from the combination of (known plaintext + observed byte + candidate config), not extracted from the observation. All 56 are equally consistent; the attacker does not learn which is real. Across P pixels, the pixel-layer ambiguity is `56^P` (or `7^P` with CCA); across `C = ⌈(4 + payload_bytes) × 8 / 48⌉` barrier chunks, Part 1 stacks an additional `≈ 2^(70.20 × C)` mask-enumeration multiplier. Without ChainHash inversion the attacker cannot verify any candidate combination; without lockSeed the attacker cannot even write down the per-bit constraint the candidate would satisfy. Under an invertible primitive on the shipped construction the attacker's naive «candidate → invert primitive → verify on another pixel» path is closed one step earlier by Part 1: the second pixel's mapping is a different per-chunk secret drawn from ≈ 2^70.20 balanced partitions — instance-formulation impossibility, not solver-throughput bound.

### 2.7 Noise Barrier Bound (Theorem 5)

**Theorem 5.** *With 8 channels and the unified container floor `MinPixels = ⌈keyBits / log₂(7)⌉` (shared by plain and MAC-authenticated surfaces), the noise barrier `2^(8P)` strictly exceeds the key space `2^keyBits`.*

For `keyBits = 1024`: `MinPixels = 365`, giving `P = 400` after square rounding (20 × 20). Noise barrier = `2^3200 ≫ 2^1024`. The unified floor is mode-independent, so the minimum-message container size does not betray whether the MAC-authenticated or plain surface produced a given wire. See [PROOFS.md § Proof 5](PROOFS.md#proof-5-noise-barrier-bound).

### 2.8 CCA Leak Upper Bound (Theorem 6)

**Theorem 6.** *Under CCA with MAC-reveal, the noise position (3 bits per pixel from noiseSeed) is the maximum information extractable about the configuration under this attack model.*

The CCA oracle classifies each bit as noise (accept) or data (reject). Per pixel: 8 queries suffice (testing each bit position; all channels share the same `noisePos`). After classification, the 7 data-bit positions are known, but their values are protected by per-bit XOR from `dataSeed_i` (independent of noiseSeed by Theorem 3). The per-chunk mask channel is unaffected under this attack model.

CCA leak = 3 / 62 ≈ 4.8 % of per-pixel configuration. CCA reveals no plaintext, no XOR masks, no startPixel, no barrier permutation — but eliminates noiseSeed from brute-force: `P × 2^(2·keyBits) → P × 2^keyBits`. Remaining brute-force enumeration cost far exceeds the Landauer bound (~2^306) at all shipped key sizes; structural attacks that do not enumerate the seed space are not bounded by Landauer.

### 2.9 Guaranteed CSPRNG Residue (Theorem 10)

**Theorem 10 (No Perfect Fill).** *With container dimensions `(s+1) × (s+1)` where `s = ⌈√max(dataPixels, MinPixels)⌉`, the container capacity strictly exceeds the maximum payload. CSPRNG fill bytes are always present in the data bit positions.*

The container capacity gap is `≥ (2s + 1) × 7 > 0` for all `s ≥ 1`; perfect fill is mathematically impossible. Full derivation: [PROOFS.md § Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill).

**Consequence for CCA.** After CCA removes noise bits, the data bit positions contain both encrypted plaintext and encrypted CSPRNG fill — processed identically by `dataSeed_i` (rotation + XOR). The attacker cannot distinguish fill from plaintext. CCA weakens the CSPRNG-residue barrier layer without eliminating it: the residue preserves configuration ambiguity within the data channel independent of the `7^P` rotation barrier (Theorem 4). The Full KPA closure under CCA remains computational and PRF-conditional (Theorem 4a).

### 2.10 Byte-Splitting Property

Since `gcd(7, 8) = 1` (7 data bits per channel, 8 bits per byte), plaintext bytes never align with channel boundaries. Every plaintext byte is split across exactly 2 channels with independent XOR masks.

Byte-splitting is an auxiliary layer under Partial KPA — the second obstacle to candidate formulation after the barrier's per-chunk mask permutation, which is primary, has already moved every plaintext byte to a per-chunk unobservable lane position. Under Partial KPA (attacker knows byte `k` but not `k ± 1`): each channel mixes bits from 2 adjacent bytes. Without the adjacent byte, the attacker cannot compute expected channel bits. Candidates are not formulable.

### 2.11 Bias Neutralization (Theorem 7)

**Theorem 7.** *With a non-invertible PRF hash function, the rotation barrier makes dataSeed output bias unobservable regardless of the primitive's output distribution.*

The attacker cannot observe dataSeed's hash output (Theorem 3, 8-seed isolation), and without knowing rotation `r` the mapping plaintext → observed bits is 7-to-1 ambiguous per pixel (Theorem 4). Any statistical bias in `H` provides a Bayesian prior, but without dataSeed the attacker cannot evaluate `P(observed | r = r')` — the Bayesian update is uninformative. Full derivation: [PROOFS.md § Proof 7](PROOFS.md#proof-7-bias-neutralization).

### 2.12 Oracle-Free Deniability (Theorem 8)

**Theorem 8.** *For any container `C` encrypted with the 8-seed tuple and any wrong 8-seed tuple, decryption produces output computationally indistinguishable from uniform random bytes.*

No magic bytes, no checksums. The COBS null terminator is encrypted inside the container. A wrong lockSeed inverts a wrong per-chunk permutation, so the pre-COBS byte stream is a scrambled reordering of the true post-barrier bits; wrong per-snake seeds extract, un-rotate, and XOR-decrypt with incorrect configurations. Wrong seeds produce random-looking output at a random-length boundary. See [ITB.md § 16 Oracle-Free Deniability](ITB.md#16-oracle-free-deniability) for the accessible property list.

### 2.13 MAC-Inside-Encrypt Composition

For integrity protection, the MAC tag is computed over the entire decrypted capacity (COBS + null + fill) and encrypted inside the container, preserving oracle-free deniability. Flipping any data bit causes MAC failure. Only noise-bit flips produce «accept» — uniform 12.5 % across all pixels, with no spatial pattern. After noise removal, CSPRNG fill bytes persist in data positions (Theorem 10).

If the attacker has insider knowledge that a MAC tag is present (MAC + Silent Drop), the encrypted tag serves as a local verification oracle. The brute-force cost remains identical to Core ITB for both classical and Grover bounds, with additional `O(P)` per candidate for MAC verification. No external oracle is required — the attacker verifies locally by decrypting, computing MAC(payload), and comparing against the embedded tag.

### 2.14 Nonce Uniqueness

The dual-nonce wire header carries two independently drawn CSPRNG nonces. Birthday collision on either single slot reaches ~50 % after `2^(N/2)` messages (`N` = the primitive's nonce width in bits); simultaneous collision on both slots is the product probability, requiring on the order of `2^N` messages. Simultaneous collision is not reachable through the shipped API: both nonces are drawn independently from CSPRNG per encryption, neither slot is caller-addressable, so simultaneous collision requires a **CSPRNG hardware fault**. Under single-slot collision, the un-collided axis provides fresh-nonce closure and the barrier's confidentiality closure holds a fortiori. Each dual-nonce pair creates an independent configuration map; a collision affects only the colliding pair.

**Empirical verdict — plaintext recovery is null under every attacker-realistic dual-slot / main-only / interlock-only collision scenario at the tested sample sizes** (see [REDTEAM.md § Nonce reuse](REDTEAM.md#nonce-reuse-lab-only)). Under the maximum-leverage dual-slot collision the lab can force (both nonces overridden through test-only setters — impossible through the shipped API), the container XOR carries `rotate7(snake_XOR_bits, r)` at every non-noise bit position plus a fresh CSPRNG noise bit, but only up to the barrier's Part 1 permutation of the plaintext bits into three lane-scrambled snake payloads. The lane assignment a two-time-pad demasker would need to anchor on is a per-chunk PRF secret keyed by lockSeed and unobservable without it. Empirical null holds across BLAKE3 as a PRF-grade reference and FNV-1a as a below-spec stress control on every one of the 8 seed roles.

**Nonce-misuse resistance is strictly local.** Even the two lab-forced colliding messages recover zero plaintext bytes under attacker-realistic probes at the tested sample sizes. Seeds remain secret because a single collision provides one ChainHash output for one (pixelIndex, nonce) input — insufficient to invert ChainHash (PRF non-invertibility). All 8 seeds retain full entropy; future messages with fresh nonces are unaffected, so **no key rotation is required** after a collision. A single collision also provides too few observations for Simon's periodicity detection, BHT collision-finding, or quantum structural algebraic attacks. This contrasts with AES-GCM where a single nonce reuse leaks the GHASH authentication key `H`, enabling **permanent forgery** of arbitrary messages under the same key until key rotation — a global catastrophe. ITB achieves nonce-misuse resistance through PRF architecture plus the barrier's per-chunk permutation, rather than dedicated misuse-resistant construction (as in AES-GCM-SIV).

### 2.15 48-bit Interlocked Barrier Mask Space (Theorem 11)

**Theorem 11.** *The per-chunk mask triple `(m_0, m_1, m_2)` is drawn from a space `Ω_chunk` of cardinality `|Ω_chunk| = A · B` where `A = C(48, 16) = 2,254,848,913,647` and `B = C(32, 16) = 601,080,390`, so `|Ω_chunk| ≈ 2^70.20`. Under the PRF assumption on the primitive, the per-chunk mask draw is computationally indistinguishable from an independent uniform selection from `Ω_chunk`. A known-plaintext crib supplying 48 known bits of a chunk does not determine that chunk's mask triple: the number of PRF-output preimages per mask triple is `⌊2^128 / (A · B)⌋ ≈ 2^57.80`.*

Balanced-partition counting: `A` ways to choose `m_0`, then `B` ways for `m_1` from the remaining 32 bits; `m_2` = complement. Under the PRF assumption each chunk's mask draw is computationally indistinguishable from an independent uniform selection from `Ω_chunk`. The two-step unrank `(idx_0, idx_1) = (⌊rank / B⌋ mod A, rank mod B)` has preimage counts differing by at most 1 — the `2^128 mod (A · B)` lowest-indexed pairs receive one extra preimage — with both counts equal to ≈ 2^57.80 at that order. Every mask triple therefore has ≈ 2^57.80 PRF-output preimages, so any candidate mask triple is consistent with any observation. Full derivation: [PROOFS.md § Proof 11](PROOFS.md#proof-11-48-bit-interlocked-barrier-mask-space).

**Cascade constants.** The reduction map `rank ↦ (⌊rank/B⌋, rank mod B)` is a bijection onto `[0, ⌊2^128/B⌋) × [0, B)`; reducing the first component mod `A` gives near-uniform full-space coverage with a fixed, publicly-known per-chunk relative deviation of ≈ 2^-57.8 — granularity, not a distinguisher. The reduction is deterministic and constant-time; rejection sampling is avoided to preserve constant-time discipline. Accumulated linearly over a maximum-size message of 2^23.42 chunks, the per-message deviation is bounded by ≈ 2^-34.4. Turning this granularity into a confident distinguisher would require on the order of `1/ε² ≈ 2^115.6` chunk samples — beyond any attainable sample budget. The biased event is a property of PRF output (one-way by assumption) and is unobservable beneath the barrier / noise / fill stack. The empirical statement is bounded: no distinguisher is reachable at attainable sample sizes, not «no bias exists».

**Gcd anti-collapse.** `gcd(A, B) = 66,861 = 3² · 17 · 19 · 23`. The rejected alternative reduction `(rank mod A, rank mod B)` (using the same rank for both moduli directly) reaches only pairs `(a, b)` with `a ≡ b (mod gcd(A, B))` — `1 / 66,861 ≈ 1.5 × 10⁻⁵` of the pair space, a structured subset that would hand the attacker a `66,861×`-restricted mask space through the back door. The two-step reduction preserves the full ≈ 2^70.20 cardinality by construction.

## 3. Barrier Metrics

**Barrier strength at minimum container (1024-bit key):**

| Metric | Value |
|---|---|
| MinPixels (unified floor, all modes) | 365 → 400 (20 × 20) |
| Noise barrier (P = 400) | 2^3200 |
| Encoding ambiguity `56^P` (P = 400) | 2^2323 |
| Encoding ambiguity `7^P` (P = 400) | 2^1123 |
| CSPRNG residue (P = 400) | ≥ 287 bytes (Theorem 10) |
| Mask-space cardinality per chunk (A · B) | ≈ 2^70.20 |
| PRF-preimage count per mask triple | ≈ 2^57.80 |
| Distinguisher sample budget | ≈ 2^115.6 chunks |
| Landauer bound (blind enumeration cost) | ~2^306 |
| Key space | 2^1024 |

**Attack resistance under normal use:**

| Attack | What happens | Barrier |
|---|---|---|
| COA | Random bytes, hash output unobservable | Intact |
| Crib KPA | Barrier removes fixed byte-position anchor; below-spec primitives absorbed via ChainHash | Closed under PRF* |
| Full KPA | Multi-factor under PRF (Theorem 4a); ≈ 2^57.80 mask preimages per chunk | Closed under PRF* |
| Partial KPA | Superset of Full KPA candidate sets; `gcd(7,8)=1` auxiliary | Closed under PRF, a fortiori |
| CPA | Different dual-nonce → independent maps, fresh mask draws | Intact |
| CCA | No oracle (core ITB without MAC); mask channel unaffected | No oracle |
| Nonce reuse | Simultaneous collision requires CSPRNG fault; single-slot collision closed on un-collided axis | Not reachable via shipped API |

\* All «closed under PRF» verdicts are instance-formulation-bounded and sample-bounded.

### 3.1 Full KPA

Full KPA (the attacker knows the entire plaintext) is analyzed by primitive class under the always-on barrier:

- **PRF-grade primitive**: closed under PRF (Theorem 4a), bounded by instance formulation and sample size per Theorem 11. Each known-plaintext chunk admits ≈ 2^57.80 mask preimages with no ranking signal among the ≈ 2^70.20 masks per chunk.
- **Below-spec primitive** (empirically tested controls): the barrier still provides anchor protection — the crib cannot anchor to a fixed byte position because the barrier's per-chunk mask permutation moves every plaintext byte to a per-chunk PRF-keyed lane position. Anchor-based recovery attacks that succeed on such a primitive in isolation fail through the barrier at the tested sample sizes. The closure remains PRF-conditional in the sense of Theorem 4a's Asymmetry note: total PRF inversion still collapses the barrier via cascade lockSeed recovery.

SAT-based lockSeed recovery is structurally unmeasurable at attacker-realism; the argument is stated in full at §2.6 (Theorem 4a). Partial weakness in any single factor leaves the others intact; total PRF inversion would collapse the architectural layers via recovered seeds — the multi-factor property defends against *partial* PRF weakness, not total failure.

### 3.2 Empirical Corroboration

The reference implementation ships an attacker-realistic audit suite (see [REDTEAM.md](REDTEAM.md)) whose recovery decisions consume only attacker-visible inputs (ciphertext bytes, public cribs, the public dual-nonce and dimension header); ground-truth values appear only in terminal-stage audit printouts.

**Wire distinguisher (Mode B KL matrix).** A construction-level χ² / pairwise-KL distinguisher measures, for the shipping wire under every combination of plaintext size and Barrier Fill margin, whether the ITB body bytes are separable from `/dev/urandom` bytes of matched length. Across an 11-size × 6-BF grid (66 cells) with 25 ITB samples plus 25 `/dev/urandom` samples per cell, **every cell satisfies `|z_ratio| ≤ 1.0`** (indistinguishable at 1σ); peak `z_ratio` = 0.51, peak `z(χ²)` = 0.62. Minimum Barrier Fill margin for indistinguishability = **BF = 1 for every size measured**; the shipped default `DefaultBarrierFill = 1` already suffices across the 1 KB → 4 MB payload envelope.

**Nonce reuse (lab-only, dual-slot decomposition).** Nonce reuse is not reachable through the shipped API. Under lab-forced overrides three collision classes are exercised: Scenario A (both nonces collide), Scenario B (main-only collision), Scenario C (interlock-only collision). **Empirical verdict — plaintext recovery is null across all three scenarios** at the tested sample sizes; the barrier's per-chunk PRF-keyed 48-bit mask permutation removes the demask anchor even under the maximum-leverage dual-slot collision. Verified across BLAKE3 (PRF-grade reference) and FNV-1a (below-spec stress) on every one of the 8 seed roles.

**Related-nonce differential.** Three scenarios × six Δ patterns × two plaintext kinds. Null-plaintext-recovery across all cells; χ² inside the df = 255 uniform band on both slots — main-nonce Δ perturbs 7 of 8 seed-derivation slots, interlock-nonce Δ perturbs the `lockSeed`-keyed per-chunk mask draw.

**COBS-alignment probe.** Container size depends on per-snake COBS-encoded lengths, so a 1-bit flip transitioning the flipped plaintext byte to / from `0x00` shifts the COBS overhead by one byte. The alignment probe sweeps Barrier Fill ∈ {1, 4, 8, 16, 32} × plaintext ∈ {512 B, 4 KB, 16 KB} = 15 cells at N = 200 pairs per cell under Scenario A. **0 / 200 container-body length mismatch at every cell** — the container is pixel-quantized and the ±1-byte COBS overhead perturbation sits below the pixel-boundary step across the full BF range.

**Direct pathological-input recovery.** Per-byte plaintext-recovery probe on pathological low-entropy input under lab-only Scenario A: **0 recoveries** across the tested decoder family at 10⁶+ trial-position pairs.

**Broken-primitive stress (FNV-1a lo-lane SAT — architecturally foreclosed).** Under fresh-nonce Full KPA with FNV-1a on every one of the 8 seed roles, naive-crib Bitwuzla returns **UNSAT** on all 3 snakes at N = 2 crib pixels in ≈ 7–10 s per snake under the maximum-peek attacker regime (true `(np, r)` granted via lab peek — 5 of 8 chains inverted for free — and true `sp_i` disclosed). The full coupled-8-chain SAT (all 8 chains unknown plus the ≈ 2^70.20 per-chunk mask triples symbolic) is trivially harder; the isolated-chain UNSAT is a strict upper bound. Positive control (`TestRedTeamBrokenFNV1aCribKPAControl`) drives the same 8-seed FNV-1a configuration through the low-level `process128Cfg` encoder (Single Ouroboros, barrier off — not reachable through the shipped API) and confirms the anchor logic recovers the true `xor_mask56` at every one of the first 6 crib pixels under true `(sp, np, r)`, matching the archived SAT anchoring premise bit-exact. The barrier null is contrasted against a filter that IS sensitive on the retired configuration. See [REDTEAM.md § FNV-1a lo-lane SAT — architecturally foreclosed](REDTEAM.md#fnv-1a-lo-lane-sat--architecturally-foreclosed).

**Fresh-nonce CPA under FNV-1a on every seed role.** Chosen-plaintext against `Encrypt3x128Cfg` with FNV-1a on all 8 seed roles, N = 2000 queries per (arm, plaintext-kind) cell across 7 chosen-plaintext kinds; reference arm keys with BLAKE3-128. Homogeneity χ² between FNV-1a and BLAKE3 arms per plaintext kind: 214.8 – 265.8 (df = 255, one-sided 3σ uniform band top ≈ 323) — **every cell inside the uniform band**. No plaintext kind surfaces a primitive-attributable channel; the crib-anchored `structured_json` and `structured_html` cells sit at χ² 214.8 and 224.8, comparable to the trivial `zeros` cell at 244.1. Under fresh nonces each Encrypt call redraws every nonce-bound derivation, so no chosen plaintext byte lands at an attacker-predictable wire position.

**Trapdoor absorption via ChainHash (feedforward-depth + input-XOR keying).** The ChainHash construction empirically absorbs multiple trapdoor mechanism classes: **structural partition trapdoors** (BEA-1 class), **chosen-constants collision trapdoors** (Malicious SHA-1 class), **round-reduced primitives**, and **accidentally-weak primitives** (CRC128, FNV-1a). Two absorption mechanisms operate in ChainHash: **feedforward-depth** (the data-dependent effective round key at chain depth ≥ 2 defeats attacks requiring a fixed round key across the input structure) and **input-XOR keying** (the seed-XOR moves engineered collisions out of the collision-engineered input space). For per-primitive analysis on non-cryptographic hash primitives (t1ha1_64le, SeaHash, mx3, SipHash-1-3), see [HARNESS.md](HARNESS.md).

**Audit-surface aggregate verdicts:**

| Probe class | Attacker capability | Observable | Aggregate verdict |
|---|---|---|---|
| Wire distinguisher | Ciphertext only, fresh dual-nonce | Body-byte statistics vs. CSPRNG | Indistinguishable at 1σ over the tested envelope |
| Trapdoor absorption | Public plaintext, chosen trapdoor primitive | Anchor recovery through ChainHash | Absorbed across all four tested classes |
| Recovery under reuse (lab-only) | Ciphertext pair, low-entropy plaintext | Per-byte plaintext recovery | 0 recoveries over 10⁶+ trial pairs |
| SAT-based lockSeed | Attacker-realistic (no seed peek) | Formulable instance | Structurally unmeasurable at attacker-realism |
| SAT-based lockSeed | Maximum-peek (7 of 8 chains granted) | Bitwuzla UNSAT | Architecturally foreclosed |

All verdicts are sample-bounded and, where they invoke primitive strength, PRF-conditional.

### 3.3 Quantum Resistance (Conjectured)

The noise-absorption layer under passive observation is computation-model-independent: a quantum computer cannot extract information absent from the observation (the Theorem 1 property is not conditional on the computation model). Under active seed-recovery attacks the closure is computational and admits Grover speedup; the bounds below assume the standard Grover-oracle model applied to seed-space brute-force.

- **Grover**: no oracle (Core ITB) or expensive oracle (MAC-Inside: full decryption per query). Core ITB: `√P × 2^keyBits` (~2^1028 at 1024-bit). MAC + Reveal: `√P × 2^(keyBits/2)` (~2^516 at 1024-bit, P = 400), with `O(P)` per-query decryption cost.
- **Simon**: needs periodicity; config map is aperiodic (dual-nonce per message).
- **BHT**: needs observable collisions; random container absorbs them.
- **Q2 superposition queries**: MAC oracle is inherently classical.

The barrier's per-chunk mask enumeration (Theorem 11, ≈ 2^70.20 per chunk) is not amenable to Grover — there is no observable anchor to search against. AES-256 with Grover bound 2^128 is widely considered quantum-resistant for practical purposes; ITB's random-container plus barrier architecture may provide an additional architectural layer of resistance to quantum structural algorithms, but this is a conjectured property that has not been independently verified.

## 4. Comparison with Existing Ciphers

The security model sits in the stegosecurity tradition of Cachin (1998) and Hopper, Langford, and von Ahn (2002). ITB is not a steganographic system in the classical sense (it has no natural cover distribution to match); rather, it is a cipher whose ciphertext distribution is computationally indistinguishable from a CSPRNG-generated cover. The novelty is architectural: 8-seed isolation and encoding ambiguity produce a computationally indistinguishable joint distribution without any assumption about a natural cover.

Shannon (1949) established that perfect secrecy requires key entropy ≥ message entropy. ITB does not claim perfect secrecy in Shannon's sense. Instead, ITB exhibits **ambiguity-based security**: the number of observation-consistent configurations grows with data size — a property orthogonal to Shannon's key-entropy bound, not a violation of it (§5).

Unlike AES and ChaCha20, which expose the primitive's output directly to the observer (keystream ⊕ plaintext), ITB absorbs the PRF output into a random container before the observer can see it. This is an architectural difference, not a mathematical one. Beyond that distinction, ITB's mandatory 48-bit Interlocked Barrier introduces a per-chunk PRF-keyed permutation over a space of cardinality ≈ 2^70.20 that removes the fixed byte-position anchor a Crib KPA attacker requires.

At the minimum container size, blind enumeration of the ambiguity space at ITB's parameters already exceeds the Landauer bound on irreversible computation: the 2^3200 noise-barrier at 1024-bit keys (P = 400) is `2^2894×` the ~2^306 Landauer bound. This bounds *blind enumeration cost*, not resistance to structural attacks — structural attacks that do not enumerate (e.g., algebraic recovery through a compromised primitive) are not bounded by Landauer. Reversible-computing adversaries are additionally unbounded on the enumeration axis; the physics-layer argument is therefore a conditional positioning of enumeration cost, not an unconditional security guarantee.

**Maximum key size comparison:**

| Cipher | Maximum key size | Effective security |
|---|---|---|
| AES | 256 bits | 256 bits |
| ChaCha20 | 256 bits | 256 bits |
| Threefish | 1024 bits | 1024 bits |
| ITB + BLAKE3 | 2048 bits | 2048 bits |

**Hash function requirement comparison:**

| Cipher | Minimum primitive requirement |
|---|---|
| AES-CTR | PRP (strong) |
| ChaCha20 | PRF |
| ITB | PRF |

## 5. Ambiguity-Based Security

Traditional symmetric ciphers follow Shannon's model: each additional plaintext bit constrains the key, reducing uncertainty about it. In ITB, a distinct orthogonal property emerges: each additional pixel adds unverifiable *configuration* candidates without contradicting Shannon's plaintext-entropy bound. The property applies to oracle-free observation; under any verification oracle (e.g., MAC-inside, §2.13) configuration ambiguity collapses to the primitive's brute-force bound.

The per-chunk mask permutation (§1.5, §2.15) additionally multiplies the ambiguity by the mask-space cardinality per chunk (≈ 2^70.20); that contribution is orthogonal to the per-pixel encoding ambiguity this section quantifies.

**Definition (Ambiguity-Based Security).** Fix key size `k` bits and a container of `P` pixels. The construction has `(k, P)`-ambiguity-based security if the number of observation-consistent configurations exceeds `2^k` for all `P > P_threshold`.

**Theorem 9 (Ambiguity Dominance).** *For ITB with key size `k` bits:*

- *Without CCA (Core ITB / Silent Drop): `P_threshold = ⌈k / log₂ 56⌉ ≈ ⌈k / 5.807⌉`.*
- *Under CCA (MAC + Reveal): `P_threshold = ⌈k / log₂ 7⌉ ≈ ⌈k / 2.807⌉`.*

*Above `P_threshold`, encoding ambiguity exceeds the key space in the exponent.*

Direct from candidate arithmetic: `56^P > 2^k ⇔ P > k / log₂(56)`; under CCA `7^P > 2^k ⇔ P > k / log₂(7)`. Full derivation: [PROOFS.md § Proof 9](PROOFS.md#proof-9-ambiguity-dominance-threshold).

**Ambiguity dominance thresholds:**

| Key size | No CCA: `56^P > 2^k` | CCA: `7^P > 2^k` |
|---|---|---|
| 512-bit | P > 89 (~0.6 KB) | P > 183 (~1.3 KB) |
| 1024-bit | P > 177 (~1.2 KB) | P > 365 (~2.5 KB) |
| 2048-bit | P > 353 (~2.4 KB) | P > 730 (~5.0 KB) |

The reference implementation sets the unified floor `MinPixels = ⌈k / log₂(7)⌉` for all modes (plain and authenticated), guaranteeing ambiguity dominance in all composition modes at the stricter CCA threshold.

**Encoding ambiguity by data size (1024-bit key, CCA case `7^P`):**

| Data size | P | `7^P` | vs `2^1024` key space |
|---|---|---|---|
| MinPixels (~2.5 KB) | 400 | `2^1,123` | 1.1× |
| 8 KB | 1,225 | `2^3,439` | 3.4× |
| 64 KB | 9,409 | `2^26,414` | 25.8× |
| 1 MB | 150,544 | `2^422,630` | 413× |

**No-CCA scale (56 candidates per pixel):**

| Data size | P | `56^P` | vs `2^1024` |
|---|---|---|---|
| MinPixels | 400 | `2^2,323` | 2.3× |
| 8 KB | 1,225 | `2^7,114` | 6.9× |
| 64 KB | 9,409 | `2^54,641` | 53.4× |
| 1 MB | 150,544 | `2^874,262` | 854× |

At 64 KB, encoding ambiguity alone is `2^26,414`, whose exponent is 25.8× the 1024-bit key-space exponent. No computational model can perform *blind enumeration* of `2^26,414` configurations. This bounds enumeration cost, not resistance to structural attacks; ambiguity dominance is orthogonal to the PRF-conditional multi-factor defense (Theorem 4a). Noise barrier (`2^(8P)`) and key brute-force are independent additional enumeration layers.

**Per-candidate decryption cost.** Each brute-force candidate requires full container decryption: `P × 2R` hash calls (where `R` = ChainHash rounds). This cost applies to all modes and grows linearly with `P`. At 64 MB (`P ≈ 9.6 × 10⁶`), each candidate costs ~154 million hash calls — orders of magnitude more expensive than AES, in which verification costs a single block operation.

**Relationship to Shannon.** Shannon's theorem on unconditional (information-theoretic) key-message equality requires `|key| ≥ |message|`. It applies to models where keystream is XOR'd directly with plaintext — each additional plaintext bit constrains the key. ITB does not meet Shannon's unconditional-secrecy definition: the key is shorter than the message. Instead, ITB exhibits a distinct property orthogonal to Shannon's key-entropy bound: the number of observation-consistent *configurations* grows exponentially with data size. This is a distinct class of security property; the formal relationship to Shannon's framework remains an open research question (see §7).

## 6. Implementation

A reference implementation in Go (`github.com/everanium/itb`) supports three hash width variants:

- 128-bit (SipHash-2-4, AES-CMAC): effective max key 1024 bits.
- 256-bit (BLAKE3, BLAKE2b-256, BLAKE2s): effective max key 2048 bits.
- 512-bit (BLAKE2b-512): effective max key 2048 bits.

Wire format: `main_nonce (N bytes) ‖ interlock_nonce (N bytes) ‖ W (2 bytes) ‖ H (2 bytes) ‖ W × H × 8 raw RGBWYOPA`, header size `2N + 4` bytes (`N` = the primitive's native nonce width in bytes). The 48-bit Interlocked Barrier is mandatory and always-on; no compile-time or runtime flag disables it. The 8-seed constellation is required at every entry point.

Key sizes range from 512 to 2048 bits (minimum 8 components per seed). Zero external dependencies (Go standard library plus user-supplied hash primitives). Hash functions are user-supplied — either registered by name via `hashes.Register(spec hashes.Spec) error` for use through the Triple facade, or plugged directly as `HashFunc{N}` + `BatchHashFunc{N}` closures at the Low-Level `*Cfg` surface (see [ITB.md § 17 Custom Primitives](ITB.md#17-custom-primitives)). All pixel processing uses elementary operations (XOR, AND, shift, modulo) with no secret-dependent memory access — register-only operations for all dataSeed-derived values; the barrier's per-chunk kernels are constant-time.

For per-platform microarchitecture dispatch (AVX-512 / AVX2 / AES-NI / NEON / SVE2 / BMI2 tiers), see [README.md § asm dispatch table](README.md) and [HWTHREATS.md § Category 5](HWTHREATS.md#category-5-instruction-set-side-channel-profile). For the harness / testing surface, see [HARNESS.md](HARNESS.md).

## 7. Research Directions

- Formal simulation-based proof of hash independence in the ideal cipher model.
- Formal analysis of MAC-Inside-Encrypt composition with ITB.
- Formal comparison with Threefish-1024 security margins and performance.
- Precise formalization of ambiguity-based security in Shannon's framework and its relationship to Cachin's steganographic security.

### Scope and Maturity Disclaimer

ITB is a new construction without prior peer review or independent cryptanalysis. The primary contribution is theoretical: demonstrating that Full KPA resistance is 4-factor under the PRF assumption (5-factor under Partial KPA) — PRF non-invertibility closes the candidate-verification step, while architectural layers (the Interlocked Barrier's per-chunk mask permutation of ≈ 2^70.20 balanced partitions, 8-seed isolation with independent startSeeds, and per-pixel 7-rotation × 8-noisePos encoding ambiguity; plus byte-splitting under Partial KPA) deny the point of application. PRF and barrier are complementary, neither sufficient alone (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)). Performance is not a design goal.

The author does not claim that ITB is the most secure symmetric cipher construction, nor that the analysis is exhaustive. As a first publication, the construction may contain overlooked vulnerabilities at two levels:

**1. Fundamental (barrier invalidation).** If the information-theoretic barrier does not hold as claimed — e.g., if the random container does not fully absorb hash outputs under some attack model not considered here — the core security guarantee would be invalidated. This is considered unlikely: the proof that every observed byte value is compatible with every possible hash output (`∀v, ∀h : ∃c : embed(c, h, d) = v`) is a direct consequence of probability theory, independent of the hash function. However, the interaction between the barrier and active attacks (CCA, side-channel, multi-message analysis) may have subtleties not captured by the current analysis.

**2. Implementational (correctable).** Edge cases in COBS framing, off-by-one errors in bit indexing, timing side-channels in constant-time operations, or insufficient secure-wiping coverage. These are correctable without redesigning the construction. The library includes mitigation for known side-channels (constant-iteration null search, `secureWipe` with `runtime.KeepAlive`, register-only dataSeed operations), but the mitigations themselves have not been independently audited.

**Minimum container caveat.** The information-theoretic barrier strength depends on container size: `2^(8P)` for P pixels. At the unified minimum container (400 pixels for 1024-bit; `MinPixels = MinPixelsAuth`), the barrier is `2^3200` — well above the key space. However, for very small payloads where the container is only slightly larger than the minimum, the security margin above the key space is at its lowest. The construction does not provide security guarantees for containers smaller than `MinPixels`.

**Areas for reviewer scrutiny:**

- Whether PRF combined with the architectural layers (Interlocked Barrier per-chunk mask permutation, 8-seed isolation, encoding ambiguity; plus byte-splitting under Partial KPA) is sufficient under the analyzed threat models ([Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)), or whether additional properties are needed for attack models not considered.
- Whether the 8-seed isolation provides the claimed independence under all side-channel combinations.
- Whether the CCA leak analysis correctly bounds the information extractable from the MAC oracle (Theorem 6, Theorem 10).
- Whether the ChainHash construction achieves the claimed effective key sizes through multi-call recovery.
- Whether the barrier's per-chunk mask permutation (Theorem 11) is sufficient to close instance-formulation against a SAT/algebraic solver granted less than 7 of the 8 seeds.
