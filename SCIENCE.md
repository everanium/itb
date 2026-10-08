## ITB Scientific Analysis

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB composes established, standardized primitives rather than introducing new cryptographic designs. Security properties and regulatory status are inherited from the underlying primitives; see [README.md](README.md) for jurisdictional certification details.

## Abstract

ITB (Information-Theoretic Barrier) is a parameterized symmetric cipher construction that renders the hash output unreconstructible from ciphertext-only observation. **Noise insertion** interposes a random container — filled by `internal/drbg` (CSPRNG-seeded noise from the operator-selected DRBG fill primitive, AES-256-CTR by default where hardware AES is present and ChaCha20 otherwise) — between the PRF hash output and the observer; each byte retains one random noise bit at an unknown position. Under known-plaintext, chosen-plaintext, and chosen-ciphertext attacks the closure is computational and PRF-conditional; the information-theoretic property scopes to the noise-insertion layer under passive observation (Theorem 1). **Encoding ambiguity** applies a secret rotation (0–6) from an independent per-region dataSeed to each pixel's data bits, creating 7^P unverifiable configurations across P pixels.

The construction establishes the **Interlocked Barrier** as a mandatory, always-on composite of two indivisible layers: the **Rank Barrier** partitions each 48-bit chunk of the payload into three disjoint 16-of-48 lane payloads via a PRF-keyed balanced mask triple drawn from a space of cardinality ≈ 2^70.20 per chunk (executed in ~3 cycles in constant time via BMI2 PEXTQ/PDEPQ), and the **Pixel Barrier** performs per-pixel channel XOR masking, rotation, and noise insertion. Even if the noise mechanism is bypassed via CCA (which reveals noise positions), the rotation barrier, the per-chunk mask permutation, and DRBG residue in data positions survive through 8-seed isolation.

The 8-seed architecture (noiseSeed, lockSeed, three per-region dataSeeds, three per-region startSeeds) ensures that compromise of any single configuration domain provides zero information about the remaining domains; the lockSeed → per-chunk mask path is bound to the primitive through cascade PRF binding (two consecutive live PRF cascades). A dual-nonce wire format carries two independently CSPRNG-drawn nonces per message, producing independent configurations per encryption with no caller-addressable override.

The construction exhibits **ambiguity-based security**: the number of observation-consistent **configurations** grows exponentially with data size. This property is orthogonal to Shannon's key-entropy bound and distinct from Shannon's perfect-secrecy relationship on plaintext entropy. Above a threshold P_th = ⌈k / log₂ C⌉ (C = 56 without CCA, C = 7 under CCA), encoding ambiguity exceeds the 2^k key space. At 64 KB plaintext, ambiguity reaches 2^27,515; its exponent is 26.9× the 1024-bit key-space exponent. An attacker-realistic audit suite in the reference implementation confirms the barrier's absorption across multiple trapdoor mechanism classes at the tested sample sizes (see [REDTEAM.md](REDTEAM.md)).

All core operations are elementary: XOR, bitwise AND, modular reduction, and bit shifts, executed without secret-dependent table lookups or field inversions. The security architecture composes around a pluggable PRF hash function; the construction's own operations are elementary, while the closures under KPA/CPA/CCA remain computational and PRF-conditional on the primitive.

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

### 1.2 Interlocked Barrier Architecture

The Interlocked Barrier is the mandatory, always-on composite of two indivisible layers: the **Rank Barrier** (per-chunk 48-bit permutation into 3 lanes) and the **Pixel Barrier** (per-pixel channel XOR masking, rotation, and noise insertion). Treating either layer in isolation misstates what the construction resists; both layers operate in series and are non-disableable.

#### 1.2.1 Rank Barrier (48-bit Combinadic Chunk Permutation)

Before COBS framing and pixel encoding, the interleaved payload is partitioned into 48-bit (6-byte) chunks. For each chunk, the Rank Barrier derives a balanced mask triple `(m_0, m_1, m_2)` — three 16-of-48-bit partitions with `popcount(m_j) = 16`, pairwise disjoint, satisfying `m_0 ∪ m_1 ∪ m_2 = 2^48 − 1`.

The mask triple is drawn from a balanced partition space `Ω_chunk` of cardinality:

```
|Ω_chunk| = A · B = 1,355,345,464,406,015,082,330  ≈  2^70.20
```

where `A = C(48, 16) = 2,254,848,913,647` (choices for `m_0`) and `B = C(32, 16) = 601,080,390` (choices for `m_1` from the remaining 32 bits; `m_2` is the complement).

**Two-Stage Cascade Fill (`interlock48_cascade.go`).**
The derivation runs a two-stage cascade:
1. **Stage 1 (Intermediate key derivation):** Setup computes `K = deriveInterLockSeed(N_il)` under dedicated domain tag `0x04` via full `ChainHash` over `[0x04 ‖ N_il]` keyed by `lockSeed`. Intermediate key `K` comprises `w = width / 64` 64-bit words.
2. **Stage 2 (Primer round + session feed-forward):** The builder prepends `K` to the lockSeed's session components:
   ```
   lockComps = [K[0], …, K[w-1], c[0], c[1], …, c[n-1]]
   ```
   Round 1 of the cascade is the **primer round** seeded with intermediate key `K`. Rounds `2 … 1 + keyBits / width` feed the state forward through the session components `c`.
3. **Per-chunk rank evaluation:** Each chunk-group evaluates the 13-byte input block `[0x03 ‖ LE64(groupIdx) ‖ 4×0x00]` through `chainHashWith(lockComps, buf)`, yielding a 128-bit rank `(lo, hi)`.
4. **Round count invariant:**
   - **Pixel Barrier:** depth `r = keyBits / width` (4 / 8 / 16 rounds at width 128 for 512 / 1024 / 2048-bit keys).
   - **Rank Barrier cascade fill:** depth `r = 1 + keyBits / width` (5 / 9 / 17 rounds at width 128; 3 / 5 / 9 at width 256; 2 / 3 / 5 at width 512). The Rank Barrier cascade fill is **exactly 1 round deeper** than the Pixel Barrier cascade.
5. **Divmod anti-collapse:** The 128-bit rank is converted to mask indices via `(q, idx_1) = divmod_128(rank, B)` and `idx_0 = q mod A`. This two-step division defeats the `gcd(A, B) = 66,861` collapse trap that would reduce the reachable space to `1 / 66,861 ≈ 1.5 × 10^-5` under naive double-modulo.
6. **Hardware execution:** On x86-64, `chunk48LockBatch` executes three BMI2 `PEXTQ` instructions to compress each 48-bit chunk into three 16-bit lane payloads in ~3 cycles in constant time; decryption unpacks lanes via three BMI2 `PDEPQ` instructions and pairwise `ORQ`.

#### 1.2.2 Pixel Barrier (Per-Pixel Channel XOR, Rotation, and Noise Injection)

Each pixel packs 56 payload bits into 8 channel bytes (RGBWYOPA) of 7 data bits each. Keyed by `dataSeed_i` and `noiseSeed`, the Pixel Barrier executes per-pixel encoding over each 7-bit field:
- **channelXOR:** 56 PRF-mask bits (7 per channel) derived from `dataSeed_i` (`xorMask_i = dataHash_i >> 3`).
- **rotate7:** cyclic rotation by a per-pixel amount in `[0, 6]` derived from `dataSeed_i` (`rotation_i = dataHash_i mod 7`, providing log₂(7) ≈ 2.807 bits of entropy).
- **Noise injection:** insertion of a DRBG noise bit from the random container at a per-pixel position `noisePos ∈ [0, 7]` derived from `noiseSeed` (`noisePos = noiseHash & 7`).

**Narrowing semantics:** Regardless of native hash width (128 / 256 / 512), the per-pixel encoder consumes only the low 64 bits (`hLo = h[0]`) of the ChainHash output, discarding the rest. In contrast, the Rank Barrier consumes both words of the 128-bit output pair `(lo, hi)` as rank material.

**Entropy accounting:** Each pixel consumes ~62 configuration bits (exact: log₂(8 × 7 × 2^56) = 61.807 bits) across `noisePos`, `rotation`, and `channelXOR`. The decode path inverts exactly (extract noise bit, inverse rotate7, XOR demask).

### 1.3 Message Framing & Dual-Nonce Handling

Plaintext is partitioned across three regions and framed with COBS (Consistent Overhead Byte Stuffing). COBS eliminates `0x00` bytes, establishing the null terminator as an unambiguous message boundary encrypted inside the container.

Output wire format:
```
Offset  Size     Content
0       32       Stream prefix (CSPRNG; the streamID bound into the MAC on authenticated surfaces)
32      N        Main nonce (crypto/rand, public; N = 16/32/64 bytes)
32+N    2        Width (uint16 big-endian)
34+N    2        Height (uint16 big-endian)
36+N    W×H×8    Raw RGBWYOPA pixel container
```

**Dual-nonce mechanism:**
Each encryption draws two nonces independently from `crypto/rand`:
- `N_m` (main nonce): travels in the public header and parametrizes the seven per-pixel and offset derivations (`noisePos`, 3 × `startPixel_i`, 3 × per-region `dataSeed_i` rotation/XOR).
- `N_il` (interlock nonce): keys the Rank Barrier's per-chunk mask derivation via `deriveInterLockSeed(N_il)`. It is split into three lane fragments (`base, rem := N/3, N%3`) and prepended to the lane bytes ahead of COBS framing. It travels encrypted beneath the Pixel Barrier; no length information is exposed.

### 1.4 Pipeline Flow

The end-to-end execution flow strictly preserves the following order:
- **Encryption:** `Plaintext` → **Rank Barrier** (BMI2 `PEXTQ` partitions 48-bit chunks into three 16-bit lane streams) → **Lane COBS framing** (lane prefix prepends interlock-nonce fragment) → **Pixel Barrier** (channelXOR + rotate7 + DRBG noise insertion into RGBWYOPA container) → **Outer cipher** (optional wrapper for format deniability) → `Wire`.
- **Decryption:** `Wire` → **Outer cipher** (if enabled) → **Inverse Pixel Barrier** (noise extraction, inverse rotate7, XOR demask) → **Lane COBS deframing** → **Inverse Rank Barrier** (BMI2 `PDEPQ` + `ORQ` reassembles 16-bit lane fragments into 48-bit plaintext chunks) → `Plaintext`.

## 2. Security Analysis

### 2.1 Information-Theoretic Barrier (Theorem 1)

**Theorem 1 (Barrier).** **For a random container `C` generated from a DRBG and any PRF hash function `H`, under passive ciphertext-only observation (COA), the distribution of observed pixel values after embedding is independent of the hash output.**

The core observation: for any fixed hash configuration `h` and fixed plaintext data bits `d`, the output channel byte `C'[p, ch]` takes one of two possible values (differing only at `noisePos`), each with probability 1/2 because the noise bit retains the original DRBG-generated container bit — Bernoulli(1/2) and independent of everything. Across an unknown uniform plaintext distribution under ciphertext-only attack (COA), every byte value `v ∈ {0, …, 255}` is equiprobable:

```
P(C'[p, ch] = v | h) = 1/256 = P(C'[p, ch] = v)
```

Hence `I(H(K); C') = 0` and `H(H(K) | C') = H(H(K))`.

**Compatibility formula:**

```
∀ v ∈ {0, …, 255}, ∀ h : ∃ (c, d) : embed(c, h, d) = v
```

For any observed byte value `v` and any candidate hash output `h`, there exist a container byte `c` and plaintext data bits `d` producing `v`. Under known plaintext (fixed `d`), a compatible XOR mask `m` exists for every candidate pair `(noisePos, r)` by Theorem 2. This is the information-theoretic core of the barrier and applies to the noise-insertion layer (Pixel Barrier of the Interlocked Barrier composition) under passive observation. Full derivation: [PROOFS.md § Proof 1](PROOFS.md#proof-1-information-theoretic-barrier).

**Scope.** The IT property scopes to the noise-insertion layer under passive observation (COA / KPA). Under CCA the noise-position channel is revealed via oracle interaction (§2.8, Theorem 6); the closure of KPA / CPA / CCA is computational and PRF-conditional through the multi-factor defense of §2.6 (Theorem 4a). The Rank Barrier of the compound (the per-chunk permutation) is PRF-conditional throughout — its mask-space cardinality bound is Theorem 11 (§2.15).

### 2.2 Per-Bit XOR KPA Resistance (Theorem 2)

**Theorem 2.** **Under per-bit XOR (1:1), for any observed channel byte `v` and known plaintext data bits `d`, there exists a unique 7-bit XOR mask `m` such that encoding `d` with mask `m` is consistent with `v`, for any noise position and rotation:**

```
∀ d ∈ {0,1}⁷, ∀ v ∈ {0,…,255}, ∀ noisePos ∈ {0,…,7}, ∀ r ∈ {0,…,6}:
∃! m ∈ {0,1}⁷ : encode(d, m, r, noisePos) is consistent with v
```

Given `v`, `noisePos`, and candidate rotation `r'`, a matching `m' = rotate⁻¹(extract(v, noisePos), r') ⊕ d` always exists and is uniquely determined. All 56 (8 × 7) candidates per pixel are consistent with the observation without CCA; with CCA (noisePos known), 7 rotation candidates remain. Known plaintext does not uniquely determine the per-pixel configuration. Multi-pixel key recovery requires computational search over the key space.

**Corollary (startPixel Indistinguishability).** The attacker cannot determine the start pixel from known plaintext: every pixel position produces a valid `(d, m)` pair, making all `P` positions indistinguishable. Full derivation: [PROOFS.md § Proof 2](PROOFS.md#proof-2-per-bit-xor-kpa-resistance).

Additionally, the Rank Barrier per-chunk mask permutation (§1.2.1, §2.15, Theorem 11) removes any fixed byte-position anchor a Crib KPA attacker could exploit: the crib bytes are moved to per-chunk PRF-keyed lane positions unobservable without lockSeed.

### 2.3 8-Seed Isolation (Theorems 3, 3a)

**Theorem 3.** **In the 8-seed architecture, compromise of any subset of `{noiseSeed, dataSeed_1, dataSeed_2, dataSeed_3, startSeed_1, startSeed_2, startSeed_3}` provides zero information about `lockSeed`, and symmetrically. Pairwise mutual information between any two of the 8 seeds is zero.**

The 8 seeds are drawn independently from CSPRNG. Each seed's ChainHash uses only its own components:
- `noiseSeed → noisePos`: `ChainHash(counter ‖ N_m, noiseSeed) & 7`
- `lockSeed → per-chunk mask triple`: Stage 1 derives intermediate key `K = deriveInterLockSeed(lockSeed, N_il)` under domain tag `0x04`; Stage 2 evaluates `[0x03 ‖ LE64(groupIdx) ‖ 4×0x00]` over `lockComps = [K, session components...]`, unranked per Theorem 11
- `dataSeed_i → rotation_i, XOR_i`: `ChainHash(counter ‖ N_m, dataSeed_i)`
- `startSeed_i → startPixel_i`: `ChainHash(0x02 ‖ N_m, startSeed_i) mod P_region`

Let `U = {noiseSeed, lockSeed, dataSeed_{1..3}, startSeed_{1..3}}` denote the set of eight seeds. For any non-empty proper subset `S ⊊ U`:

```
I(X_{U \ S} ; X_S) = 0
```

where `I` denotes Shannon mutual information and `X_A` denotes the joint distribution of seeds in subset `A`. CCA reveals noise positions (noiseSeed config); cache side-channel reveals a `startPixel_i` (startSeed_i config); neither carries any information about any other seed — in particular, none about lockSeed. The pairwise independence between seeds is information-theoretic (all 8 are CSPRNG-drawn); the individual unrecoverability of lockSeed under Full KPA is **computationally** hidden under the PRF assumption via cascade PRF binding, not information-theoretic — total PRF inversion recovers lockSeed via the Asymmetry note (§2.6). Full derivation: [PROOFS.md § Proof 3](PROOFS.md#proof-3-8-seed-isolation).

The lockSeed → per-chunk mask path is bound to the primitive via the Two-Stage Cascade Fill (`deriveInterLockSeed(N_il)` under tag 0x04, followed by the per-chunk cascade where Round 1 is the dedicated primer round on intermediate key K and subsequent rounds consume session components), so any attempt to isolate the permutation layer's unrank hardness from the primitive's PRF hardness reduces the instance to PRF preimage recovery — dominated by the primitive's SAT-hardness, not by the interlock structure.

**Theorem 3a (Minimality).** **Under the documented attack surfaces — CCA for noise positions, cache side-channel for start pixels — eight seeds are the minimum where compromise of any one domain yields zero information about the rest. Fewer seeds merge domains and create cross-domain or cross-region leakage.**

Pigeonhole argument on 8 disjoint derivation domains (N, L, D₁..D₃, S₁..S₃) with distinct attack surfaces: any layout with at most 7 seeds merges at least two domains, creating at least one of four cross-domain leakage patterns: observable + unobservable (N or S_i merged with L or D_j), observable + observable (cross-region collapse S_i + S_j), unobservable + unobservable (loss of statistical independence between L and D_i under KPA), or noise/mask coupling. 8 CSPRNG-independent seeds achieve the pairwise independence of Theorem 3. Full derivation: [PROOFS.md § Proof 3a](PROOFS.md#proof-3a-8-seed-isolation-minimality).

### 2.4 ChainHash Full Component Utilization (Theorem 3b)

**Theorem 3b.** **For any PRF-grade hash function `H`, `ChainHash(data, S)` depends on all `n` components. No component can be changed without affecting the final output.**

By contradiction plus the PRF property: any component change avalanches through subsequent rounds with overwhelming probability. Full derivation: [PROOFS.md § Proof 3b](PROOFS.md#proof-3b-chainhash-full-component-utilization).

### 2.5 Rotation Barrier (Theorem 4)

**Theorem 4.** **With unknown rotation `r ∈ {0, …, 6}` from `dataSeed_i`, the attacker faces `7^P` indistinguishable configurations for `P` pixels when using a non-invertible hash.**

For `P = 441` (Mode 2 per-container floor at a 1024-bit key — joint floor `MinPixels = 365`, square-rounded to `21 × 21 = 441` with `DefaultBarrierFill = 1`): `7^441 ≈ 2^1238`. For `P = 1225` (Mode 1 per-region floor — `3 × 365 = 1095` total pixels, square-rounded to `35 × 35 = 1225`): `7^1225 ≈ 2^3439` observation-consistent candidate configurations (with `7^400 ≈ 2^1123` at the theoretical single-region baseline).

Both values far exceed the Landauer bound on irreversible enumeration cost (~2^306 ≈ 10^92). Each candidate rotation configuration requires an independent ChainHash evaluation to verify. This bounds the cost of blind enumeration of the ambiguity space, not resistance to structural attacks that do not enumerate. See [PROOFS.md § Proof 4](PROOFS.md#proof-4-rotation-barrier).

### 2.6 Multi-Factor Full KPA Resistance (Theorem 4a)

**Theorem 4a.** **Under the PRF assumption, Full KPA brute-force seed recovery requires: for Core ITB in Silent Drop mode (no verification oracle), at least `P × 2^(2·keyBits)` hash evaluations (joint noiseSeed + dataSeed search); for MAC + Reveal, at least `P × 2^keyBits` hash evaluations (the CCA reveal channel eliminates noiseSeed per Theorem 6, leaving dataSeed + startPixel enumeration). The `7^P` (or `56^P` without CCA) per-pixel encoding ambiguity is an additional factor over either bound that any shortcut attack must also defeat.**

Theorem 4a's bound composes four independent obstacles under Full KPA whose entropy sources are disjoint by Theorem 3, plus one Partial KPA specific obstacle:

1. **PRF inversion.** Recovering a `dataSeed_i` from a verified candidate hash `h' = H(counter ‖ N_m, dataSeed_i)` is infeasible under the PRF assumption (which implies one-wayness).
2. **startPixel_i isolation.** `startPixel_i = f(startSeed_i, N_m)` is never transmitted; each region presents its own candidate offset space with no feedback to narrow it, and no region's recovery reveals another's.
3. **Per-pixel ambiguity at 1:1 signal/noise.** By Theorems 1 and 4, 56 per-pixel candidates (without CCA) or 7 (under CCA) are equally consistent with the observation. Formally, `sup_{c,c'} Pr[c | obs] / Pr[c' | obs] = 1`: all candidates are equiprobable conditional on the observation.
4. **Rank Barrier per-chunk mask-triple isolation.** Each chunk observation admits ≈ 2^57.80 mask preimages (Theorem 11, §2.15); collapsing that ambiguity requires coupling many chunks through the shared lockSeed chain against the SAT-hostile combinadic unrank arithmetic. The mapping from a plaintext bit to the lane it lands in is unobservable without lockSeed.
5. **Byte-splitting non-alignability (Partial KPA defense).** `gcd(7, 8) = 1` guarantees every plaintext byte is split across 2 channels. Under Partial KPA, per-channel candidate formulation is blocked because each channel depends on two bytes — missing one prevents candidate computation. Under Full KPA this shortcut is not available anyway (brute force enumerates seeds directly), so obstacle (5) has no additional defensive effect.

Obstacles (1)–(3) jointly determine the Full KPA brute-force cost stated by Theorem 4a; obstacle (4) is an additional per-chunk multiplier over that cost that any shortcut attack must also defeat, and `gcd(7,8)=1` byte-splitting is a 5th factor effective only under Partial KPA. Full KPA resistance is 4-factor under the PRF assumption; Partial KPA resistance is 5-factor. The obstacles are not sub-problems defeated sequentially but interlocking constraints. Full derivation: [PROOFS.md § Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance).

**SAT recovery.** SAT-based lockSeed recovery is **structurally unmeasurable at attacker-realism**. Any formulable SAT instance under the barrier requires granting seven of eight seeds via lab peek to strip the per-pixel stage (noiseSeed strips the noise bit, per-region `dataSeed_i` strips per-pixel rotation and channelXOR, per-region `startSeed_i` strips the per-region pixel-to-chunk mapping). A granted-7/8 attacker is not the reuse-realistic attacker (who holds only the ciphertext pair and the public main nonce). Without stripping the per-pixel stage, the lockSeed → mask path runs through the Two-Stage Cascade Fill: setup derivation `K = ChainHash(0x04 ‖ N_il, lockSeed)`, then per-chunk rank evaluation over `[0x03 ‖ LE64(groupIdx) ‖ 4×0x00]` under `lockComps = [K, session components...]` with Round 1 primer round on `K` and session feed-forward (`interlock48_cascade.go`), and the instance reduces to PRF preimage recovery on the primitive, dominated by the primitive's SAT-hardness rather than the interlock's. The measurable instance and the reuse-realistic instance are disjoint by construction; the closure is PRF-conditional by construction. Empirically corroborated on the adjacent dataSeed_i target: with FNV-1a keyed to every one of the 8 seed roles, naive-crib Bitwuzla does not recover the true dataSeed_i lo lane under that probe's maximum-peek regime (5 of 8 chains granted, sp_i disclosed) (see [REDTEAM.md § FNV-1a lo-lane SAT — architecturally foreclosed](REDTEAM.md#fnv-1a-lo-lane-sat--architecturally-foreclosed)).

**Dual-nonce carve-out.** Under the shipped dual-nonce wire format, simultaneous collision of both nonces across two messages is a degeneracy an external caller cannot reach: both nonces are drawn independently from CSPRNG per encryption with no caller-addressable override, so simultaneous collision requires a **CSPRNG hardware fault**. Under any partial-collision scenario (main-only or interlock-only), the un-collided axis provides fresh-nonce closure and the barrier's plaintext-recovery closure holds a fortiori.

**Composition conjecture.** Hash output bias and collisions are absorbed by the barrier (§2.11, Theorem 7 + BHT analysis of §3.3). Occasional/sporadic PRF inversion events are additionally absorbed by startPixel isolation, per-pixel 1:1 ambiguity, and Rank Barrier per-chunk mask-triple isolation (obstacles 2–4), plus `gcd(7,8)=1` byte-splitting under Partial KPA (obstacle 5): recovered candidates become indistinguishable from the false-positive distribution. Systematic partial PRF inversion is a real (non-absorbed) threat that the barrier does not neutralize — the architecture raises cost but does not eliminate the attack — however, no such systematic weakness is currently known to reduce the Full KPA work factor below the theorem bound. Only total PRF inversion circumvents this via algorithmic seed recovery (see Asymmetry note).

**Asymmetry note.** Obstacle (1) is asymmetrically privileged: a total PRF inversion algorithmically resolves obstacles (2)–(5) via recovered seeds; the Rank Barrier per-chunk mask permutation collapses via lockSeed recovery through cascade PRF inversion of the mask-derivation chain, or via direct Full KPA observation of mask triples from plaintext-chunk to permuted-wire correspondence. Failure of any architectural layer leaves PRF non-invertibility intact. Theorem 4a protects against **partial** PRF weakness and **any degree** of architectural weakness, but not against total PRF inversion.

**Why KPA candidates do not break the barrier.** Under KPA, the attacker can compute 56 candidate dataHash values per pixel — but these are **calculated** from the combination of (known plaintext + observed byte + candidate config), not extracted from the observation. All 56 are equally consistent; the attacker does not learn which is real. Across P pixels, the pixel-layer ambiguity is `56^P` (or `7^P` with CCA); across `C = ⌈(4 + payload_bytes) × 8 / 48⌉` barrier chunks, the Rank Barrier stacks `≈ 2^(70.20 × C)` observation-consistent mask configurations — an ambiguity count, not a work factor, since every chunk mask descends from the one lockSeed. Without ChainHash inversion the attacker cannot verify any candidate combination; without lockSeed the attacker cannot even write down the per-bit constraint the candidate would satisfy. Under an invertible primitive on the shipped construction the attacker's naive «candidate → invert primitive → verify on another pixel» path is closed one step earlier by the Rank Barrier: the second pixel's mapping is a different per-chunk secret drawn from ≈ 2^70.20 balanced partitions — instance-formulation closure ([Proof 11](PROOFS.md#proof-11-48-bit-rank-barrier-mask-space-interlocked-barrier)), not solver-throughput bound.

### 2.7 Noise Barrier Bound (Theorem 5)

**Theorem 5.** **With 8 channels and the unified floor `MinPixels = ⌈keyBits / log₂(7)⌉` (shared by plain and MAC Authenticated surfaces), the noise barrier `2^(8P)` strictly exceeds the key space `2^keyBits` across all configurations: the theoretical single-region floor, the Mode 2 per-container floor, and the Mode 1 per-region container.**

For `keyBits = 1024`: joint floor `MinPixels = 365`. In Mode 2 (per-container), the joint floor produces a `21 × 21` container (`P = 441`), where the noise barrier is `2^3528 ≫ 2^1024` (a margin of `2^2504`). In Mode 1 (per-region), each region independently enforces `MinPixels = 365`, requiring at least `3 × 365 = 1095` data pixels; square container rounding (`⌈√1095⌉ = 34`) plus `DefaultBarrierFill = 1` yields `35 × 35 = 1225` pixels, expanding the noise barrier to `2^9800` (a margin of `2^8776` over the key space). The unified floor is surface-independent, so the minimum-message container size does not betray whether the MAC Authenticated or plain surface produced a given wire. See [PROOFS.md § Proof 5](PROOFS.md#proof-5-noise-barrier-bound).

### 2.8 CCA Leak Upper Bound (Theorem 6)

**Theorem 6.** **Under CCA with MAC Reveal, the noise position (3 bits per pixel from noiseSeed) is the maximum information extractable about the configuration under this attack model.**

The CCA oracle classifies each bit as noise (accept) or data (reject). Per pixel: 8 queries suffice (testing each bit position; all channels share the same `noisePos`). After classification, the 7 data-bit positions are known, but their values are protected by per-bit XOR from `dataSeed_i` (independent of noiseSeed by Theorem 3). The per-chunk mask channel is unaffected under this attack model.

CCA leak = 3 / 62 ≈ 4.8 % of per-pixel configuration. CCA reveals no plaintext, no XOR masks, no startPixel, no Rank Barrier permutation — but eliminates noiseSeed from brute-force: `P × 2^(2·keyBits) → P × 2^keyBits`. The remaining brute-force enumeration cost `P × 2^keyBits` remains computationally infeasible at all shipped key sizes (≥ 2^512 hash evaluations); structural attacks that do not enumerate the seed space are PRF-conditional. Full derivation: [PROOFS.md § Proof 6](PROOFS.md#proof-6-cca-leak-upper-bound).

### 2.9 Guaranteed DRBG Residue (Theorem 10)

**Theorem 10 (No Perfect Fill).** **With container dimensions `(s+1) × (s+1)` where `s = ⌈√max(dataPixels, MinPixels)⌉`, the container capacity strictly exceeds the maximum payload. DRBG fill bytes are always present in the data bit positions.**

The container capacity gap is `≥ (2s + 1) × 7 > 0` for all `s ≥ 1`; perfect fill is mathematically impossible. Concretely at a 1024-bit key:
- Mode 1 per-region container (`s = 34`, container `35 × 35 = 1225`): `gap ≥ (2 × 34 + 1) × 7 = 483 bytes` (`(1225 − 1095) × 7 = 910 bytes` at the exact floor).
- Mode 2 per-container container (`s = 20`, container `21 × 21 = 441`): `gap ≥ (2 × 20 + 1) × 7 = 287 bytes` (`(441 − 365) × 7 = 532 bytes` at the exact floor).
- Theoretical single-region floor (`s = 19`, container `20 × 20 = 400`): `gap ≥ (2 × 19 + 1) × 7 = 273 bytes` for payloads ≤ 19² = 361 pixels, and `(400 − 365) × 7 = 245 bytes` at the exact 365-pixel floor.

Full derivation: [PROOFS.md § Proof 10](PROOFS.md#proof-10-guaranteed-drbg-residue-no-perfect-fill).

**Consequence for CCA.** After CCA removes noise bits, the data bit positions contain both encrypted plaintext and encrypted DRBG fill — processed identically by `dataSeed_i` (rotation + XOR). The attacker cannot distinguish fill from plaintext. CCA weakens the DRBG-residue barrier layer without eliminating it: the residue preserves configuration ambiguity within the data channel independent of the `7^P` rotation barrier (Theorem 4). The Full KPA closure under CCA remains computational and PRF-conditional (Theorem 4a).

### 2.10 Byte-Splitting Property

Since `gcd(7, 8) = 1` (7 data bits per channel, 8 bits per byte), plaintext bytes never align with channel boundaries. Every plaintext byte is split across exactly 2 channels with independent XOR masks.

Byte-splitting is an auxiliary layer under Partial KPA — the second obstacle to candidate formulation after the Rank Barrier's per-chunk mask permutation, which is primary, has already moved every plaintext byte to a per-chunk unobservable lane position. Under Partial KPA (attacker knows byte `k` but not `k ± 1`): each channel mixes bits from 2 adjacent bytes. Without the adjacent byte, the attacker cannot compute expected channel bits. Candidates are not formulable.

### 2.11 Bias Neutralization (Theorem 7)

**Theorem 7.** **With a non-invertible PRF hash function, the rotation barrier makes dataSeed output bias unobservable regardless of the primitive's output distribution.**

The attacker cannot observe dataSeed's hash output (Theorem 3, 8-seed isolation), and without knowing rotation `r` the mapping plaintext → observed bits is 7-to-1 ambiguous per pixel (Theorem 4). Any statistical bias in `H` provides a Bayesian prior, but without dataSeed the attacker cannot evaluate `P(observed | r = r')` — the Bayesian update is uninformative. Full derivation: [PROOFS.md § Proof 7](PROOFS.md#proof-7-bias-neutralization).

### 2.12 Oracle-Free Deniability (Theorem 8)

**Theorem 8.** **For any container `C` encrypted with the 8-seed tuple and any wrong 8-seed tuple, decryption produces output computationally indistinguishable from uniform random bytes.**

No magic bytes, no checksums. The COBS null terminator is encrypted inside the container. A wrong lockSeed inverts a wrong Rank Barrier chunk permutation, so the pre-COBS byte stream is a scrambled reordering of the true post-barrier bits; wrong per-region seeds extract, un-rotate, and XOR-decrypt with incorrect configurations. Wrong seeds produce random-looking output at a random-length boundary. See [ITB.md § 16 Oracle-Free Deniability](ITB.md#16-oracle-free-deniability) for the accessible property list. Full derivation: [PROOFS.md § Proof 8](PROOFS.md#proof-8-oracle-free-deniability).

### 2.13 MAC-Inside-Encrypt Composition

For integrity protection, the MAC tag is computed over the entire decrypted capacity (COBS + null + fill) together with the stream prefix, stream offset and final flag, and encrypted inside the container, preserving oracle-free deniability. Because the lane fragments of the interlock nonce `N_il` are prepended to the lane payloads prior to COBS framing, they reside within the authenticated lane buffers covered by the MAC tag; any active modification of `N_il` causes immediate MAC verification failure, eliminating unauthenticated context-commitment vulnerabilities. Flipping any data bit causes MAC failure. Only noise-bit flips produce «accept» — uniform 12.5 % across all pixels, with no spatial pattern. After noise removal, DRBG fill bytes persist in data positions (Theorem 10).

If the attacker has insider knowledge that a MAC tag is present (MAC + Silent Drop), the encrypted tag serves as a local verification oracle. The brute-force cost is unchanged from Core ITB for both classical and Grover bounds — without the CCA reveal channel noiseSeed is not eliminated — with an additional `O(P)` per candidate for MAC verification. No external oracle is required: the attacker verifies locally by decrypting, computing MAC(payload), and comparing against the embedded tag. Composition derivation: [PROOFS.md § MAC-Inside-Encrypt Composition](PROOFS.md#mac-inside-encrypt-composition).

### 2.14 Nonce Uniqueness

The construction employs two independent per-message CSPRNG nonces: the public main nonce `N_m` on the wire header (bound to per-pixel noiseSeed / dataSeed_i derivations and per-region startSeed_i derivations) and the interlock nonce `N_il` embedded across the container lanes ahead of COBS under the Pixel Barrier (bound to the lockSeed's per-chunk mask draw through the domain tag `0x04`).

Birthday collision on either single slot reaches ~50 % after `2^(N/2)` messages (`N` = the configured nonce width in bits, default `DefaultNonceBits = 512`); simultaneous collision on both slots is the product probability, requiring on the order of `2^N` messages. Simultaneous collision is not reachable through the shipped API: both nonces are drawn independently from CSPRNG per encryption, neither slot is caller-addressable, so simultaneous collision requires a **CSPRNG hardware fault**. Within one message (64 MB cap, about 2^23.4 chunks of 48 bits) a repeated per-chunk mask is expected with probability ~2^-24. Under single-slot collision, the un-collided axis provides fresh-nonce closure and the barrier's confidentiality closure holds a fortiori. Each nonce pair creates an independent configuration map; a collision affects only the colliding pair.

Under joint collision of both nonces with the same 8-seed tuple:
- Same `noiseSeed` + `N_m` → identical noise positions for both messages.
- Same `lockSeed` + `N_il` → identical per-chunk Interlocked Barrier permutations for both messages.
- Same `dataSeed_i` + `N_m` → identical rotation and XOR masks per region.
- Same `startSeed_i` + `N_m` → identical per-region `startPixels`.
- Different DRBG containers (generated independently).

This creates a two-time-pad structure at the bit level after per-region reversal, affecting strictly the colliding pair. Single-slot derivation: [PROOFS.md § Nonce Uniqueness](PROOFS.md#nonce-uniqueness).

**Empirical verdict — plaintext recovery is null under every attacker-realistic dual-slot / main-only / interlock-only collision scenario at the tested sample sizes** (see [REDTEAM.md § Nonce reuse](REDTEAM.md#nonce-reuse-lab-only)). Under the maximum-leverage dual-slot collision the lab can force (both nonces overridden through test-only setters — impossible through the shipped API), the container XOR carries `rotate7(region_XOR_bits, r)` at every non-noise bit position plus a fresh DRBG noise bit, but only up to the Rank Barrier's permutation of the plaintext bits into three lane-scrambled region payloads. The lane assignment a two-time-pad demasker would need to anchor on is a per-chunk PRF secret keyed by lockSeed and unobservable without it. Empirical null holds across BLAKE3 as a PRF-grade reference and FNV-1a as a below-spec stress control on every one of the 8 seed roles.

**Nonce-misuse resistance is strictly local.** Even the two lab-forced colliding messages recover zero plaintext bytes under attacker-realistic probes at the tested sample sizes. Seeds remain secret because a single collision provides one ChainHash output for one (pixelIndex, nonce) input — insufficient to invert ChainHash (PRF non-invertibility). All 8 seeds retain full entropy; future messages with fresh nonces are unaffected, so **no key rotation is required** after a collision. A single collision also provides too few observations for Simon's periodicity detection, BHT collision-finding, or quantum structural algebraic attacks. This contrasts with AES-GCM where a single nonce reuse leaks the GHASH authentication key `H`, enabling **permanent forgery** of arbitrary messages under the same key until key rotation — a global catastrophe. ITB achieves nonce-misuse resistance through PRF architecture plus the Rank Barrier's per-chunk permutation, rather than dedicated misuse-resistant construction (as in AES-GCM-SIV).

### 2.15 48-bit Rank Barrier Mask Space (Theorem 11)

**Theorem 11.** **The per-chunk mask triple `(m_0, m_1, m_2)` is drawn from a space `Ω_chunk` of cardinality `|Ω_chunk| = A · B` where `A = C(48, 16) = 2,254,848,913,647` and `B = C(32, 16) = 601,080,390`, so `|Ω_chunk| ≈ 2^70.20`. Under the PRF assumption on the primitive, the per-chunk mask draw is computationally indistinguishable from an independent uniform selection from `Ω_chunk`. A known-plaintext crib supplying 48 known bits of a chunk does not determine that chunk's mask triple: the number of PRF-output preimages per mask triple is `⌊2^128 / (A · B)⌋ ≈ 2^57.80`.**

Balanced-partition counting: `A` ways to choose `m_0`, then `B` ways for `m_1` from the remaining 32 bits; `m_2` = complement. Under the PRF assumption each chunk's mask draw is computationally indistinguishable from an independent uniform selection from `Ω_chunk`.

The per-chunk mask is evaluated via the Two-Stage Cascade Fill (`interlock48_cascade.go`):
1. **Stage 1 (Intermediate key derivation):** `deriveInterLockSeed(N_il)` derives intermediate key `K = (lockLo, lockHi)` under dedicated domain tag `0x04` via a full ChainHash cascade over `[0x04 ‖ N_il]`.
2. **Stage 2 (Cascade Fill PRF):** Vector `lockComps = [K, session components...]` is assembled with length `w + n` (where `w = width / 64` and `n = keyBits / 64`). Round 1 is the dedicated **primer round** seeded with intermediate key `K`, and feed-forward rounds `2 … 1 + keyBits / width` consume the session key components. Total cascade depth is `r = 1 + keyBits / width` (exactly one round deeper than Pixel Barrier's `keyBits / width`).
3. **Rank Evaluation & Unranking:** For chunk group `groupIdx`, the 13-byte input `[0x03 ‖ LE64(groupIdx) ‖ 4×0x00]` is evaluated by the cascade fill to yield a 128-bit rank. The two-step divmod unrank `(idx_0, idx_1) = (⌊rank / B⌋ mod A, rank mod B)` maps this rank into the balanced mask triple `(m_0, m_1, m_2)` with popcount 16 per mask, avoiding the `gcd(A, B) = 66,861` anti-collapse trap.
4. **Hardware Execution:** Encryption compresses 48-bit chunks into three 16-bit lane streams via balanced parallel bit extraction (3 BMI2 `PEXTQ` instructions in ~3 cycles per chunk in constant time on amd64); decryption reassembles them via 3 `PDEPQ` instructions and pairwise `ORQ`.

The unrank mapping `(idx_0, idx_1) = (⌊rank / B⌋ mod A, rank mod B)` has preimage counts differing by at most 1 — the `2^128 mod (A · B)` lowest-indexed pairs receive one extra preimage — with both counts equal to ≈ 2^57.80 at that order. Every mask triple therefore has ≈ 2^57.80 PRF-output preimages, so any candidate mask triple is consistent with any observation. Full derivation: [PROOFS.md § Proof 11](PROOFS.md#proof-11-48-bit-rank-barrier-mask-space-interlocked-barrier).

**Cascade constants.** The reduction map `rank ↦ (⌊rank/B⌋, rank mod B)` is a bijection onto `[0, ⌊2^128/B⌋) × [0, B)`; reducing the first component mod `A` gives near-uniform full-space coverage with a fixed, publicly-known per-chunk relative deviation of ≈ 2^-57.8 — granularity, not a distinguisher. The reduction is deterministic and constant-time; rejection sampling is avoided to preserve constant-time discipline. Accumulated linearly over a maximum-size message of 2^23.42 chunks, the per-message deviation is bounded by ≈ 2^-34.4. Turning this granularity into a confident distinguisher would require on the order of `1/ε² ≈ 2^115.6` chunk samples — beyond any attainable sample budget. The biased event is a property of PRF output (one-way by assumption) and is unobservable beneath the barrier / noise / fill stack. The empirical statement is bounded: no distinguisher is reachable at attainable sample sizes, not «no bias exists».

### 2.16 gcd(A, B) Anti-Collapse Trap (Theorem 12)

**Theorem 12 (gcd Anti-Collapse).** **The naive same-rank reduction `(rank mod A, rank mod B)` reaches only `1 / gcd(A, B)` of the joint `(m_0, m_1)` mask space, where:**

```
gcd(A, B) = gcd(C(48, 16), C(32, 16)) = 66,861 = 3² · 17 · 19 · 23
```

**The two-step divmod reduction `(⌊rank / B⌋ mod A, rank mod B)` reaches the full `A × B` Cartesian product near-uniformly.**

For any fixed `d = gcd(A, B)`, the pair `(rank mod A, rank mod B)` is uniquely determined by `rank mod lcm(A, B) = A · B / d`. Its image in `[0, A) × [0, B)` has cardinality `A · B / 66,861`. The reachable pairs `(a, b)` are strictly those satisfying `a ≡ b (mod 66,861)`; the remaining `≈ 99.998 %` of the mask space is structurally excluded. An adversary exploiting this naive reduction would face a `66,861×`-restricted mask space — an erosion of `log₂ 66,861 ≈ 16.03` bits from Theorem 11's floor.

In contrast, the two-step reduction decomposes `rank ∈ [0, 2^128)` bijectively into quotient `q = ⌊rank / B⌋` and remainder `r = rank mod B`. Reducing `q mod A` maps the domain onto the full Cartesian space. The preimage count per pair is `⌊2^128 / (A · B)⌋ ≈ 2^57.80`, differing by at most 1 on the `2^128 mod (A · B)` lowest-indexed pairs. Full derivation: [PROOFS.md § Proof 12](PROOFS.md#proof-12-gcda-b-anti-collapse-trap).

## 3. Barrier Metrics

**Barrier strength at minimum container (1024-bit key):**

| Metric | Mode 2: Per-Container | Mode 1: Per-Region (Default) | Theoretical Floor (Single Region) |
|---|---|---|---|
| Container dimensions | 21 × 21 (P = 441) | 35 × 35 (P = 1,225) | 20 × 20 (P = 400) |
| MinPixels enforcement | 365 joint → 441 | 3 × 365 = 1,095 → 1,225 | 365 → 400 |
| Noise barrier (`2^(8P)`) | 2^3,528 | 2^9,800 | 2^3,200 |
| Encoding ambiguity `56^P` (No CCA) | 2^2,561 | 2^7,114 | 2^2,323 |
| Encoding ambiguity `7^P` (Under CCA) | 2^1,238 | 2^3,439 | 2^1,123 |
| DRBG residue (Theorem 10) | ≥ 287 bytes (s = 20; 532 B at floor) | ≥ 483 bytes (s = 34; 910 B at floor) | ≥ 273 bytes (s = 19; 245 B at floor) |
| Config map space (`2^(62P)`) | 2^27,342 | 2^75,950 | 2^24,800 |
| Mask-space cardinality (`A · B`) | ≈ 2^70.20 | ≈ 2^70.20 | ≈ 2^70.20 |
| PRF-preimages per mask triple | ≈ 2^57.80 | ≈ 2^57.80 | ≈ 2^57.80 |
| Distinguisher sample budget | ≈ 2^115.6 chunks | ≈ 2^115.6 chunks | ≈ 2^115.6 chunks |
| Landauer bound (blind enumeration) | ~2^306 | ~2^306 | ~2^306 |
| Key space | 2^1,024 | 2^1,024 | 2^1,024 |

**Container floor scaling across key sizes (Mode 1 vs Mode 2):**

| Key size | Joint floor `MinPixels` | Mode 2: Per-Container | Mode 1: Per-Region (Default) | Wire footprint (Mode 2 vs Mode 1)* |
|---|---|---|---|---|
| 512-bit | 183 px | 15 × 15 (P = 225) [17 × 17 at 1460 B payload] | 25 × 25 (P = 625) | 1,900 B vs 5,100 B (−62.7%; 2,412 B at 1460 B payload) |
| 1024-bit | 365 px | 21 × 21 (P = 441) | 35 × 35 (P = 1,225) | 3,628 B vs 9,900 B (−63.4%) |
| 2048-bit | 730 px | 29 × 29 (P = 841) | 48 × 48 (P = 2,304) | 6,828 B vs 18,532 B (−63.2%) |

\* Wire sizes measured with DefaultNonceBits = 512 (32-byte stream prefix + 68-byte header), DefaultBarrierFill = 1, wrapper and parallax off.

**Attack resistance under normal use:**

| Attack | What happens | Barrier |
|---|---|---|
| COA | Random bytes, hash output unobservable | Intact |
| Crib KPA | Rank Barrier removes fixed byte-position anchor; below-spec primitives absorbed via ChainHash | Closed under PRF* |
| Full KPA | Multi-factor under PRF (Theorem 4a); ≈ 2^57.80 mask preimages per chunk | Closed under PRF* |
| Partial KPA | Superset of Full KPA candidate sets; `gcd(7,8)=1` auxiliary | Closed under PRF, a fortiori |
| CPA | Different dual-nonce → independent maps, fresh mask draws | Intact |
| CCA | No oracle (Core ITB without MAC); mask channel unaffected | No oracle |
| Nonce reuse | Simultaneous collision requires CSPRNG fault; single-slot collision closed on un-collided axis | Simultaneous collision unreachable; single-slot closed on fresh axis |

\* All «closed under PRF» verdicts are instance-formulation-bounded and sample-bounded.

### 3.1 Full KPA

Full KPA (the attacker knows the entire plaintext) is analyzed by primitive class under the always-on barrier:

- **PRF-grade primitive**: closed under PRF (Theorem 4a), bounded by instance formulation and sample size per Theorem 11. Each known-plaintext chunk admits ≈ 2^57.80 mask preimages with no ranking signal among the ≈ 2^70.20 masks per chunk.
- **Below-spec primitive** (empirically tested controls): the Rank Barrier still provides anchor protection — the crib cannot anchor to a fixed byte position because the Rank Barrier's per-chunk mask permutation moves every plaintext byte to a per-chunk PRF-keyed lane position. Anchor-based recovery attacks that succeed on such a primitive in isolation fail through the barrier at the tested sample sizes. The closure remains PRF-conditional in the sense of Theorem 4a's Asymmetry note: total PRF inversion still collapses the barrier via cascade lockSeed recovery.

SAT-based lockSeed recovery is structurally unmeasurable at attacker-realism; the argument is stated in full at §2.6 (Theorem 4a). Partial weakness in any single factor leaves the others intact; total PRF inversion would collapse the architectural layers via recovered seeds — the multi-factor property defends against **partial** PRF weakness, not total failure.

### 3.2 Empirical Corroboration

The reference implementation ships an attacker-realistic audit suite (see [REDTEAM.md](REDTEAM.md)) whose recovery decisions consume only attacker-visible inputs (ciphertext bytes, public cribs, the public main-nonce and dimension header); ground-truth values appear only in terminal-stage audit printouts.

**Wire distinguisher (Mode B KL matrix).** A construction-level χ² / pairwise-KL distinguisher measures, for the shipping wire under every combination of plaintext size and Barrier Fill margin, whether the ITB body bytes are separable from `/dev/urandom` bytes of matched length. Across an 11-size × 6-BF grid (66 cells) with 25 ITB samples plus 25 `/dev/urandom` samples per cell, **every cell satisfies `|z_ratio| ≤ 1.0`** (indistinguishable at 1σ); peak `z_ratio` = 0.49, peak `z(χ²)` = 0.48. Minimum Barrier Fill margin for indistinguishability = **BF = 1 for every size measured**; the shipped default `DefaultBarrierFill = 1` already suffices across the 1 KB → 4 MB payload envelope.

**Nonce reuse (lab-only, dual-slot decomposition).** Nonce reuse is not reachable through the shipped API. Under lab-forced overrides three collision classes are exercised: Scenario A (both nonces collide), Scenario B (main-only collision), Scenario C (interlock-only collision). **Empirical verdict — plaintext recovery is null across all three scenarios** at the tested sample sizes; the Rank Barrier's per-chunk PRF-keyed 48-bit mask permutation removes the demask anchor even under the maximum-leverage dual-slot collision. Verified across BLAKE3 (PRF-grade reference) and FNV-1a (below-spec stress) on every one of the 8 seed roles.

**Related-nonce differential.** Three scenarios × six Δ patterns × two plaintext kinds. Null-plaintext-recovery across all cells; χ² inside the df = 255 uniform band on both slots — main-nonce Δ perturbs 7 of 8 seed-derivation slots, interlock-nonce Δ perturbs the `lockSeed`-keyed per-chunk mask draw.

**COBS-alignment probe.** Container size depends on per-region COBS-encoded lengths, so a 1-bit flip transitioning the flipped plaintext byte to / from `0x00` shifts the COBS overhead by one byte. The alignment probe sweeps Barrier Fill ∈ {1, 4, 8, 16, 32} × plaintext ∈ {512 B, 4 KB, 16 KB} = 15 cells at N = 200 pairs per cell under Scenario A. **0 / 200 container-body length mismatch at every cell** — the container is pixel-quantized and the ±1-byte COBS overhead perturbation sits below the pixel-boundary step across the full BF range.

**Direct pathological-input recovery.** Per-byte plaintext-recovery probe on pathological low-entropy input under lab-only Scenario A: **0 recoveries** across the tested decoder family at 10⁶+ trial-position pairs.

**Broken-primitive stress (FNV-1a lo-lane SAT — architecturally foreclosed).** Under fresh-nonce Full KPA with FNV-1a on every one of the 8 seed roles, naive-crib Bitwuzla at N = 2 crib pixels under the maximum-peek attacker regime (true `(np, r)` granted via lab peek — 5 of 8 chains inverted for free — and true `sp_i` disclosed) returns **UNSAT** on regions 1 and 2 in ≈ 6–22 s and, on region 0, either unknown at a 300 s cap or a SAT model that cross-validation on a further crib pixel rejects; the true `dataSeed_i` lo lane is not recovered on 5 / 5 corpus bundles. The full coupled-8-chain SAT (all 8 chains unknown plus the ≈ 2^70.20 per-chunk mask triples symbolic) is trivially harder; the isolated-chain null is a strict upper bound. Positive control (`TestRedTeamBrokenFNV1aCribKPAControl`) drives the same 8-seed FNV-1a configuration through the low-level `process128Cfg` encoder (Single Ouroboros, barrier off — not reachable through the shipped API) and confirms the anchor logic recovers the true `xor_mask56` at every one of the first 6 crib pixels under true `(sp, np, r)`, matching the archived SAT anchoring premise bit-exact. The barrier null is contrasted against a filter that **is** sensitive on the retired configuration. See [REDTEAM.md § FNV-1a lo-lane SAT — architecturally foreclosed](REDTEAM.md#fnv-1a-lo-lane-sat--architecturally-foreclosed).

**Fresh-nonce CPA under FNV-1a on every seed role.** Chosen-plaintext against `Encrypt3x128Cfg` with FNV-1a on all 8 seed roles, N = 2000 queries per (arm, plaintext-kind) cell across 7 chosen-plaintext kinds; reference arm keys with BLAKE3-128. Homogeneity χ² between FNV-1a and BLAKE3 arms per plaintext kind: 221.0 – 293.6 (df = 255, one-sided 3σ uniform band top ≈ 323) — **every cell inside the uniform band**. No plaintext kind surfaces a primitive-attributable channel; the crib-anchored `structured_json` and `structured_html` cells sit at χ² 269.5 and 260.7, comparable to the trivial `zeros` cell at 227.4. Under fresh nonces each Encrypt call redraws every nonce-bound derivation, so no chosen plaintext byte lands at an attacker-predictable wire position.

**Trapdoor absorption via ChainHash (feedforward-depth + input-XOR keying).** The ChainHash construction empirically absorbs multiple trapdoor mechanism classes: **structural partition trapdoors** (BEA-1 class), **chosen-constants collision trapdoors** (Malicious SHA-1 class), **round-reduced primitives**, and **accidentally-weak primitives** (CRC128, FNV-1a). Two absorption mechanisms operate in ChainHash: **feedforward-depth** (the data-dependent effective round key at chain depth ≥ 2 defeats attacks requiring a fixed round key across the input structure) and **input-XOR keying** (the seed-XOR moves engineered collisions out of the collision-engineered input space). For per-primitive analysis on non-cryptographic hash primitives (t1ha1_64le, SeaHash, mx3, SipHash-1-3), see [HARNESS.md](HARNESS.md).

**Audit-surface aggregate verdicts:**

| Probe class | Attacker capability | Observable | Aggregate verdict |
|---|---|---|---|
| Wire distinguisher | Ciphertext only, fresh dual-nonce | Body-byte statistics vs. CSPRNG | Indistinguishable at 1σ over the tested envelope |
| Trapdoor absorption | Public plaintext, chosen trapdoor primitive | Anchor recovery through ChainHash | Absorbed across all four tested classes |
| Recovery under reuse (lab-only) | Ciphertext pair, low-entropy plaintext | Per-byte plaintext recovery | 0 recoveries over 10⁶+ trial pairs |
| SAT-based lockSeed | Attacker-realistic (no seed peek) | Formulable instance | Structurally unmeasurable at attacker-realism |
| SAT-based dataSeed_i lo lane (FNV-1a) | Maximum-peek (5 of 8 chains granted, sp_i disclosed) | True seed not recovered on 5 / 5 bundles (UNSAT, or model rejected by cross-validation) | Architecturally foreclosed |

All verdicts are sample-bounded and, where they invoke primitive strength, PRF-conditional.

### 3.3 Quantum Resistance (Conjectured)

The noise-insertion layer under passive observation is computation-model-independent: a quantum computer cannot extract information absent from the observation (the Theorem 1 property is not conditional on the computation model). Under active seed-recovery attacks the closure is computational and admits Grover speedup; the bounds below assume the standard Grover-oracle model applied to seed-space brute-force.

- **Grover**: no oracle (Core ITB) or expensive oracle (MAC-Inside: full decryption per query). Core ITB: `√P × 2^keyBits` (~2^1028 at 1024-bit for Mode 2 P = 441 and theoretical floor P = 400; ~2^1029 at Mode 1 P = 1225). MAC + Reveal: `√P × 2^(keyBits/2)` (~2^516 at 1024-bit for P = 441 and P = 400; ~2^517 at Mode 1 P = 1225), with `O(P)` per-query decryption cost.
- **Simon**: needs periodicity; config map is aperiodic (dual-nonce per message).
- **BHT**: needs observable collisions; random container absorbs them.
- **Q2 superposition queries**: MAC oracle is inherently classical.

The Rank Barrier's per-chunk mask enumeration (Theorem 11, ≈ 2^70.20 per chunk) is not amenable to Grover — there is no observable anchor to search against. AES-256 with Grover bound 2^128 is widely considered quantum-resistant for practical purposes; ITB's random-container plus barrier architecture may provide an additional architectural layer of resistance to quantum structural algorithms, but this is a conjectured property that has not been independently verified.

## 4. Comparison with Existing Ciphers

The security model sits in the stegosecurity tradition of Cachin (1998) and Hopper, Langford, and von Ahn (2002). ITB is not a steganographic system in the classical sense (it has no natural cover distribution to match); rather, it is a cipher whose ciphertext distribution is computationally indistinguishable from a CSPRNG-generated cover. The novelty is architectural: 8-seed isolation and encoding ambiguity produce a computationally indistinguishable joint distribution without any assumption about a natural cover.

Shannon (1949) established that perfect secrecy requires key entropy ≥ message entropy. ITB does not claim perfect secrecy in Shannon's sense. Instead, ITB exhibits **ambiguity-based security**: the number of observation-consistent configurations grows with data size — a property orthogonal to Shannon's key-entropy bound, not a violation of it (§5).

Unlike AES and ChaCha20, which expose the primitive's output directly to the observer (keystream ⊕ plaintext), ITB absorbs the PRF output into a random container before the observer can see it. This is an architectural difference, not a mathematical one. Beyond that distinction, the Interlocked Barrier's Rank Barrier introduces a per-chunk PRF-keyed permutation over a space of cardinality ≈ 2^70.20 that removes the fixed byte-position anchor a Crib KPA attacker requires.

At the minimum container size, blind enumeration of the ambiguity space at ITB's parameters already exceeds the Landauer bound on irreversible computation — at the cosmic microwave background temperature (T ≈ 2.7 K) erasing one bit costs `k_B T ln 2 ≈ 2.6 × 10⁻²³ J`, so a mass-energy budget of ~4 × 10^69 J bounds irreversible operations at ~10^92 ≈ 2^306: the 2^9800 noise-barrier at 1024-bit keys (P = 1225) is `2^9494×` the ~2^306 Landauer bound. This bounds **blind enumeration cost**, not resistance to structural attacks — structural attacks that do not enumerate (e.g., algebraic recovery through a compromised primitive) are not bounded by Landauer. Reversible-computing adversaries are additionally unbounded on the enumeration axis; the physics-layer argument is therefore a conditional positioning of enumeration cost, not an unconditional security guarantee.

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
| ITB | PRF; NPRF permitted subject to strict quality requirements |

## 5. Ambiguity-Based Security

Traditional symmetric ciphers follow Shannon's model: each additional plaintext bit constrains the key, reducing uncertainty about it. In ITB, a distinct orthogonal property emerges: each additional pixel adds unverifiable **configuration** candidates without contradicting Shannon's plaintext-entropy bound. The property applies to oracle-free observation; under any verification oracle (e.g., MAC-inside, §2.13) configuration ambiguity collapses to the primitive's brute-force bound.

The Rank Barrier per-chunk mask permutation (§1.2.1, §2.15) additionally multiplies the ambiguity by the mask-space cardinality per chunk (≈ 2^70.20); that contribution is orthogonal to the per-pixel encoding ambiguity this section quantifies.

**Definition (Ambiguity-Based Security).** Fix key size `k` bits and a container of `P` pixels. The construction has `(k, P)`-ambiguity-based security if the number of observation-consistent configurations exceeds `2^k` for all `P > P_threshold`.

**Theorem 9 (Ambiguity Dominance).** **For ITB with key size `k` bits, the ambiguity threshold is:**

- **Without CCA (Core ITB / Silent Drop): `P_threshold = ⌈k / log₂ 56⌉ ≈ ⌈k / 5.807⌉`.**
- **Under CCA (MAC + Reveal): `P_threshold = ⌈k / log₂ 7⌉ ≈ ⌈k / 2.807⌉`.**

**In Mode 1, when each of three regions independently reaches `P_threshold`, per-region encoding ambiguity exceeds the key space in the exponent; joint 3-region ambiguity is strictly stronger. In Mode 2, the container reaches `P_threshold` jointly; under the PRF assumption plaintext cannot be attributed to an individual region, so joint container ambiguity governs.**

Direct from candidate arithmetic: `56^P_region > 2^k ⇔ P_region > k / log₂(56)`; under CCA `7^P_region > 2^k ⇔ P_region > k / log₂(7)`. Full derivation: [PROOFS.md § Proof 9](PROOFS.md#proof-9-ambiguity-dominance-threshold).

**Per-region ambiguity dominance thresholds:**

| Key size | No CCA: `56^P_region > 2^k` | CCA: `7^P_region > 2^k` |
|---|---|---|
| 512-bit | P_region ≥ 89 (~0.6 KB) | P_region ≥ 183 (~1.3 KB) |
| 1024-bit | P_region ≥ 177 (~1.2 KB) | P_region ≥ 365 (~2.6 KB) |
| 2048-bit | P_region ≥ 353 (~2.5 KB) | P_region ≥ 730 (~5.1 KB) |

The reference implementation sets the unified per-region floor `MinPixels = ⌈k / log₂(7)⌉` on both surfaces (plain and authenticated), applied in Mode 1 to each of three regions by `calcContainerSize3Cfg`, so per-region ambiguity dominance holds in Mode 1 on both surfaces at the stricter CCA threshold.

Both columns below are computed at `DefaultBarrierFill = 1` and `DefaultNonceBits = 512`; a wider `BarrierFill` raises `P` and every ambiguity figure with it.

**Encoding ambiguity by data size (1024-bit key):**

| Data size | Container pixels P | CCA ambiguity (`7^P`) | vs `2^1024` key space | No-CCA ambiguity (`56^P`) | vs `2^1024` key space |
|---|---|---|---|---|---|
| Mode 2 container floor (payload ≤ ~2.6 KB) | 441 | `2^1,238` | 1.2× | `2^2,561` | 2.5× |
| Mode 1 container floor (payload ≤ ~7.9 KB) | 1,225 | `2^3,439` | 3.4× | `2^7,114` | 6.9× |
| Theoretical single-region floor (~2.6 KB) | 400 | `2^1,123` | 1.1× | `2^2,323` | 2.3× |
| 64 KB | 9,801 | `2^27,515` | 26.9× | `2^56,918` | 55.6× |
| 1 MB | 151,321 | `2^424,812` | 415× | `2^878,775` | 858× |

At 64 KB, encoding ambiguity alone is `2^27,515`, whose exponent is 26.9× the 1024-bit key-space exponent. No computational model can perform **blind enumeration** of `2^27,515` configurations. This bounds enumeration cost, not resistance to structural attacks; ambiguity dominance is orthogonal to the PRF-conditional multi-factor defense (Theorem 4a). Noise barrier (`2^(8P)`) and key brute-force are independent additional enumeration layers.

**Per-candidate decryption cost.** Each brute-force candidate requires full container decryption: `P × 2R` hash calls (where `R` = ChainHash rounds). This cost applies to all modes and grows linearly with `P`. At 64 MB (`P ≈ 9.6 × 10⁶`), each candidate costs ~154 million hash calls at width 128 — orders of magnitude more expensive than AES, in which verification costs a single block operation.

**Relationship to Shannon.** Shannon's theorem on unconditional (information-theoretic) key-message equality requires `|key| ≥ |message|`. It applies to models where keystream is XOR'd directly with plaintext — each additional plaintext bit constrains the key. ITB does not meet Shannon's unconditional-secrecy definition: the key is shorter than the message. Instead, ITB exhibits a distinct property orthogonal to Shannon's key-entropy bound: the number of observation-consistent **configurations** grows exponentially with data size. This is a distinct class of security property; the formal relationship to Shannon's framework remains an open research question (see §7).

## 6. Implementation

A reference implementation in Go (`github.com/everanium/itb`) supports three hash width variants:

- 128-bit primitives: effective max key 2048 bits.
- 256-bit primitives: effective max key 2048 bits.
- 512-bit primitives: effective max key 2048 bits.

Wire format: `prefix (32 bytes) ‖ main_nonce (N bytes) ‖ W (2 bytes) ‖ H (2 bytes) ‖ W × H × 8 raw RGBWYOPA` for a Single Message, with one chunk header of `N + 4` bytes (`N` = the configured nonce width in bytes; default `DefaultNonceBits = 512` bits, `N = 64`); the independently drawn interlock nonce travels split across the three interlocked lanes (§1.3, §1.4). The 48-bit Interlocked Barrier is mandatory and always-on; no compile-time or runtime flag disables it. Its Rank Barrier component executes 48-bit chunk permutation in constant time (~3 cycles per chunk) via BMI2 `PEXTQ` on encryption and `PDEPQ` + `ORQ` on decryption (with constant-time portable table and bitslicing fallbacks on architectures without BMI2). Its Pixel Barrier component performs per-pixel channel XOR masking, rotation, and noise insertion. The 8-seed constellation is required at every entry point.

Key sizes range from 512 to 2048 bits (minimum 8 components per seed). Hash functions are user-supplied — either registered by name via `hashes.Register(spec hashes.Spec) error` for use through the Triple facade, or plugged directly as `HashFunc{N}` + `BatchHashFunc{N}` closures at the Low-Level `*Cfg` surface (see [ITB.md § 17 Custom Primitives](ITB.md#17-custom-primitives)). All pixel processing in the Pixel Barrier uses elementary operations (XOR, AND, shift, modulo) with no secret-dependent memory access — register-only operations for all dataSeed-derived values; all Rank Barrier and Pixel Barrier kernels execute in strictly constant time.

For per-platform microarchitecture dispatch (AVX-512 / AVX2 / AES-NI / NEON / SVE2 / BMI2 tiers), see [README.md § asm dispatch table](README.md) and [HWTHREATS.md § Category 5](HWTHREATS.md#category-5-instruction-set-side-channel-profile). For the harness / testing surface, see [HARNESS.md](HARNESS.md).

## 7. Research Directions

- Formal simulation-based proof of hash independence in the ideal cipher model.
- Formal analysis of MAC-Inside-Encrypt composition with ITB.
- Formal comparison with Threefish-1024 security margins and performance.
- Precise formalization of ambiguity-based security in Shannon's framework and its relationship to Cachin's steganographic security.

### Scope and Maturity Disclaimer

ITB is a new construction without prior peer review or independent cryptanalysis. The primary contribution is theoretical: demonstrating that Full KPA resistance is 4-factor under the PRF assumption (5-factor under Partial KPA) — PRF non-invertibility closes the candidate-verification step, while architectural layers (the Rank Barrier's per-chunk mask permutation of ≈ 2^70.20 balanced partitions, 8-seed isolation with independent startSeeds, and per-pixel 7-rotation × 8-noisePos encoding ambiguity; plus byte-splitting under Partial KPA) deny the point of application. PRF and barrier are complementary, neither sufficient alone (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)). Performance is not a design goal.

The ITB construction does not claim to be the most secure symmetric cipher construction, nor that the analysis is exhaustive. As a first publication, the construction may contain overlooked vulnerabilities at two levels:

**1. Fundamental (barrier invalidation).** If the information-theoretic barrier does not hold as claimed — e.g., if the random container does not fully absorb hash outputs under some attack model not considered here — the core security guarantee would be invalidated. This is considered unlikely: the proof that every observed byte value is compatible with every possible hash output (`∀ v ∈ {0, …, 255}, ∀ h : ∃ (c, d) : embed(c, h, d) = v`) is a direct consequence of probability theory, independent of the hash function. However, the interaction between the barrier and active attacks (CCA, side-channel, multi-message analysis) may have subtleties not captured by the current analysis.

**2. Implementational (correctable).** Edge cases in COBS framing, off-by-one errors in bit indexing, timing side-channels in constant-time operations, or insufficient secure-wiping coverage. These are correctable without redesigning the construction. The library includes mitigation for known side-channels (constant-iteration null search, `secureWipe` with `runtime.KeepAlive`, register-only dataSeed operations), but the mitigations themselves have not been independently audited.

**Minimum container caveat.** The information-theoretic barrier strength depends on container size: `2^(8P)` for P pixels. At the minimum container for 1024-bit keys, the barrier strictly exceeds the key space in both sizing modes: Mode 1 enforces the per-region floor `MinPixels = 365` across all three regions (`3 × 365 = 1095` square-rounded to `35 × 35 = 1225` with `DefaultBarrierFill = 1`), yielding barrier `2^9800`; Mode 2 enforces `MinPixels = 365` jointly across the container (`21 × 21 = 441` with `DefaultBarrierFill = 1`), yielding barrier `2^3528`. In Mode 1, for very small payloads the shipped floor over-provisions substantially: each of three regions independently satisfies per-region ambiguity dominance, and square-rounding plus the DRBG barrier margin add further pixels on top, so the margin over the key space is at its **largest** in this floor-dominated regime (`≥ 2^8776` at 1024-bit). For large payloads the payload volume dominates the pixel count and the floor becomes irrelevant; the intrinsic noise-bit overhead settles at `8/56 ≈ 14%` over the data bits. The construction does not provide security guarantees for containers below the floor of the selected mode — this floor is enforced by `calcContainerSize3Cfg` and cannot be lowered through the shipped API.

**Areas for reviewer scrutiny:**

- Whether PRF combined with the architectural layers (Rank Barrier per-chunk mask permutation, 8-seed isolation, encoding ambiguity; plus byte-splitting under Partial KPA) is sufficient under the analyzed threat models ([Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)), or whether additional properties are needed for attack models not considered.
- Whether the 8-seed isolation provides the claimed independence under all side-channel combinations.
- Whether the CCA leak analysis correctly bounds the information extractable from the MAC oracle (Theorem 6) and whether DRBG residue in data positions sufficiently preserves configuration ambiguity under CCA (Theorem 10).
- Whether the ChainHash construction achieves the claimed effective key sizes through multi-call recovery.
- Whether the Rank Barrier's per-chunk mask permutation (Theorem 11) is sufficient to close instance-formulation against a SAT/algebraic solver granted less than 7 of the 8 seeds.
