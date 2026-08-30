# ITB: How the Barrier Works

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

## 1. The Core Idea: Absorption

The shipped barrier composes two mechanisms — a per-chunk 48-bit keyed bit permutation (Part 1) and a per-pixel absorption stage (Part 2), both described together in §12. This section narrates the absorption intuition, which is Part 2's contribution.

The hash output exists — it is computed and determines the pixel configuration. But it is absorbed by a modification of a random container. The observer sees the result: random byte ± modification. The original random byte is unknown → the modification is unknown → the hash output is unobservable.

This is not destruction (the hash output is used), not hiding (there is no encryption on top), but absorption — the random container absorbs the hash output. Like dropping a drop of paint into an ocean of random waves — the paint is there, but the observer sees only waves.

The barrier is computation-model-independent under passive observation: no matter how much computational power the attacker has, the information is not in the observation.

**Formal basis:** ∀v, ∀h : ∃c : embed(c, h, d) = v — for any observed value, any hash output, there exists a container byte that produces this observation (see [SCIENCE.md § 2.1 Theorem 1](SCIENCE.md#21-information-theoretic-barrier-theorem-1), [SECURITY.md § 4 IT Barrier Metrics](SECURITY.md#4-information-theoretic-barrier-metrics)).

## 2. Two Independent Sources of Randomness

The barrier works because of separation of sources:

- **Container**: crypto/rand (CSPRNG) — external, independent of the construction.
- **Config**: ChainHash(seed + nonce) — internal, PRF-based.
- **Nonces**: crypto/rand — two independent per-message draws (`main_nonce` for the per-pixel and per-snake derivations, `interlock_nonce` for the barrier's per-chunk mask draws), each wire-configurable up to 512 bits and enforced pairwise-distinct inside the pair.

Two independent random processes. CSPRNG does not know about PRF, PRF does not know about CSPRNG. Their only point of contact is the moment of embedding, after which the observer sees only the result, not the components.

**Hash output bandwidth.** Each per-pixel ChainHash call produces a wide output — 128, 256, or 512 bits depending on the primitive — but the encoder consumes only the low 64 bits. About 62 of those are actually used (3 noise-position + 56 channelXOR + ~3 rotation); the rest is slack, and the high portion is discarded entirely. This is a coding-bandwidth choice — one `uint64` register fits the per-pixel needs exactly — not a security upgrade. It has one real side effect: any structural weakness of the underlying primitive that lives in the discarded bits is architecturally invisible to encryption-path observation. FNV-1a's top-bit-isolation case is the canonical example (see [REDTEAM.md § Broken-primitive stress](REDTEAM.md#broken-primitive-stress--fnv-1a-and-crc128)). For PRF-grade primitives the narrowing is defense-in-depth against partial weaknesses; under the standard PRF assumption it does not change cryptanalytic resistance at large captured-ciphertext volumes — truncation preserves PRF-security, it does not strengthen it. See [SCIENCE.md § 1.2 Per-Pixel Configuration](SCIENCE.md#12-per-pixel-configuration) for the formal treatment.

## 3. Nonce: A New Universe Per Message

The nonce guarantees that the same message with the same seeds produces each time:

- A different random container (new crypto/rand).
- A different config map (nonce feeds into every ChainHash).
- Three different startPixels (main nonce feeds into each snake's `deriveStartPixel`).
- A fresh per-chunk 48-bit permutation draw (an independent interlock nonce feeds into the barrier's `deriveInterLockSeed`).

Repeated transmissions of the same plaintext under fresh nonces produce independent containers. No observable correlation between them; the classical stream-cipher two-time-pad structure that a single-nonce collision would produce is under-determined by the barrier's per-chunk permutation and empirically null on the shipped construction (§9).

The mandatory internal nonce derivation from crypto/rand at every call is API-side discipline: the shipped API draws both nonces internally on every encrypt and enforces the pair pairwise-distinct, so caller-side reuse cannot occur through the shipped surface. Closure of the CPA / KPA families is PRF-conditional on fresh nonces at the construction level (§9).

## 4. 8-Seed Isolation

The API surface takes 8 mandatory seeds, drawn as independent CSPRNG components and enforced pairwise-distinct by byte-level `Components` comparison in addition to pointer identity — so byte-identical seeds reaching the API through blob import or the Low-Level constructors are rejected on the same gate:

- **noiseSeed** → noise position (which bit in each channel is noise).
- **lockSeed** → the 48-bit Interlocked Barrier per-chunk permutation channel.
- **dataSeed1, dataSeed2, dataSeed3** → per-snake rotation + XOR configurations.
- **startSeed1, startSeed2, startSeed3** → per-snake pixel offsets.

Each seed drives its own ChainHash with its own components. There is no mathematical relationship between them. Full knowledge of any subset of seeds gives zero bits of information about the remaining seeds (see [SCIENCE.md § 2.3 8-Seed Isolation](SCIENCE.md#23-8-seed-isolation-theorems-3-3a), [SECURITY.md Section 1](SECURITY.md#1-itb-composition-modes)).

The lockSeed keys the barrier's permutation channel independently of the noiseSeed that keys the noise-position channel, so a structural shortcut against one channel's primitive cannot leak into another channel's derivation. The three-way per-snake `dataSeed`/`startSeed` split localises any per-snake weakness to that snake alone — recovery of one snake's dataSeed or startSeed reveals nothing about the other two.

## 5. Triple Ouroboros: Three Interleaved Snakes

Plaintext does not reach the snakes as bytes. Every message first passes through the Interlocked Barrier's Part 1 (§12) — a per-chunk PRF-keyed 48-bit permutation — which is also the mechanism that produces the three snake payloads. What each snake actually carries is a stream of PRF-permuted 16-bit lane fragments, not plaintext at any offset.

**How the plaintext becomes three snake payloads.**

1. A 4-byte big-endian length prefix is prepended to the plaintext (`prependTripleLen`), so the recovery side can slice back to the exact original extent after inverse permutation and interleave.
2. The length-prefixed byte stream is walked in 48-bit (6-byte) chunks.
3. For each chunk, `deriveInterLockSeed(lockSeed, interlock_nonce)` seeds a per-chunk PRF call that draws a mask triple `(m0, m1, m2)` — three disjoint 16-of-48 lanes covering all 48 bits — from a space of ≈ 2^70.20 balanced partitions (see §12 for the mask-space accounting).
4. `chunk48lock(x, m0, m1, m2)` compresses the 48-bit chunk into three 16-bit lane values `(l0, l1, l2)` — three PEXT operations on x86 with BMI2, `softPEXT48` fallback elsewhere.
5. Snake 0's payload receives `l0` (2 bytes), Snake 1 receives `l1`, Snake 2 receives `l2`. The three payloads grow in lockstep — one 16-bit lane fragment per 48-bit input chunk.

```
Plaintext + 4-byte BE length prefix
        │
        ▼
  ┌─────────────────────────────────────────────────┐
  │ 48-bit chunk 0 │ 48-bit chunk 1 │ 48-bit ... │
  └─────────────────────────────────────────────────┘
        │                │
        ▼                ▼
   PRF-keyed         PRF-keyed
   mask triple 0     mask triple 1     ...  (each independently keyed;
   (m0, m1, m2)      (m0, m1, m2)           mask of one chunk carries no
        │                │                   information about any other)
        ▼                ▼
   chunk48lock →     chunk48lock →
   (l0, l1, l2)      (l0, l1, l2)
        │                │
        ▼                ▼
   Snake 0 payload:  l0_chunk0 ‖ l0_chunk1 ‖ ...  (16 bits per chunk)
   Snake 1 payload:  l1_chunk0 ‖ l1_chunk1 ‖ ...
   Snake 2 payload:  l2_chunk0 ‖ l2_chunk1 ‖ ...
```

No snake carries a plaintext byte at any position. Without the lockSeed and interlock_nonce, the mapping from plaintext bits to lane positions is a per-chunk secret drawn from ≈ 2^70.20 balanced partitions; a known-plaintext crib fixes no bit-position-to-lane anchor a solver could rest on. The three per-snake payloads are what feeds every stage below; the plaintext byte sequence never appears intact anywhere past this point.

**Three parallel CSPRNG regions.** One container is allocated. Three parallel goroutines fill it with crypto/rand — each writes to its own region:

```
Container (one allocation, three parallel fills):

┌──────────────┬──────────────┬──────────────┐
│  Region 0    │  Region 1    │  Region 2    │
│  crypto/rand │  crypto/rand │  crypto/rand │
│  goroutine 1 │  goroutine 2 │  goroutine 3 │
└──────────────┴──────────────┴──────────────┘
  pixels 0..P/3  pixels P/3..2P/3  pixels 2P/3..P
```

ASIC-ready: three independent DRBGs can fill three regions in parallel.

**Three parallel encrypt pipelines.** Each per-snake lane payload (16-bit fragments from Part 1's chunk permutation, not plaintext bytes) is COBS-encoded, null-terminated, filled with CSPRNG residue, then encrypted into its region with its own seeds:

```
Snake 0 payload (l0 stream) → COBS → [cobs|0x00|fill] → dataSeed1 + startSeed1 + noiseSeed → Region 0
Snake 1 payload (l1 stream) → COBS → [cobs|0x00|fill] → dataSeed2 + startSeed2 + noiseSeed → Region 1
Snake 2 payload (l2 stream) → COBS → [cobs|0x00|fill] → dataSeed3 + startSeed3 + noiseSeed → Region 2
                                                        ─────────────────────────────────
                                                        3 goroutines, each with numCPU/3 workers
```

Each pipeline is the per-pixel absorption stage: per-pixel ChainHash, rotation, XOR mask, noise bit at unknown position, startPixel wrap-around — all within its region. Part 1 of the Interlocked Barrier (§12) already ran before this stage produced the lane payloads; Part 2 (per-pixel absorption, §12) is what these three pipelines apply. The two parts always run together — this is the shipped indivisible barrier composition.

**Per-pixel bit-level processing.** Inside each region, the standard ITB per-pixel processing applies. For a lane byte `b` (part of Snake 0's `l0` stream after COBS framing):

```
b = 01001000 (8 bits of lane data, not plaintext)

Channel 0:  0100100  ← 7 bits extracted from the lane bit stream
            ⊕ XOR mask from dataSeed1 (7 bits per channel)
            = encrypted 7 bits
            rotate(encrypted, rotation1)  ← rotation 0-6 from dataSeed1
            insert into pixel, preserving noise bit at noisePos (from noiseSeed)

Channel 1:  0??????  ← next 7 bits (from b + next lane byte)
            ... same XOR + rotate + insert ...
```

Each lane byte is split across 2 channels (gcd(7,8)=1). Each channel has 7 encrypted data bits + 1 noise bit. The attacker sees 8 random-looking bits per channel.

**What the attacker sees:**

```
Output: [main_nonce][interlock_nonce][W][H][uniform random pixels]

┌──────────────────────────────────────────────────────┐
│ dddddddddddddddddddddddddddddddddddddddddddddddddd  │
│ dddddddddddddddddddddddddddddddddddddddddddddddddd  │
│ dddddddddddddddddddddddddddddddddddddddddddddddddd  │
└──────────────────────────────────────────────────────┘
  ← one continuous block of uniform random bytes →

  No visible boundary between regions.
  No visible startPixel markers (three different, all hidden).
  No visible data/fill boundary (three different, all hidden).
```

**Decrypt.** The three snakes are decoded in parallel: read `[main_nonce][interlock_nonce][W][H]`, split the pixel data into thirds (integer division; last third absorbs remainder), three parallel goroutines run the Part 2 inverse (noise-strip, inverse rotate, XOR-unmask) on each region with the respective seeds, and COBS-decode each snake back to its lane payload. Then Part 1 inverse (`interleaveTriple48LockedBatch`) reassembles the three lane streams into the 48-bit chunks under the same per-chunk mask triples derived from lockSeed + interlock_nonce, and the 4-byte length prefix is stripped to recover the original plaintext at its exact extent.

## 6. Under Normal Use: The Barrier Is Practically Impenetrable

With PRF hash, crypto/rand, and no co-located attacker:

| Attack | What happens | Barrier status |
|---|---|---|
| **COA** (ciphertext only) | Attacker sees random bytes, hash output unobservable | Intact |
| **KPA** (known plaintext) | Even with known plaintext, the original container is unknown and the per-chunk barrier permutation is a hidden per-chunk secret | Intact |
| **CPA** (chosen plaintext) | Different seed → different config, zero correlation | Intact |
| **CCA** (chosen ciphertext) | Core ITB and MAC + Silent Drop have no external oracle (see [SECURITY.md](SECURITY.md) ‡‡ for insider case) | No oracle exists |

Under passive observation (COA, CPA), the barrier alone blocks all analysis. Under Full KPA, PRF non-invertibility is essential — it closes the candidate-verification step, while additional architectural layers deny the attacker a usable reference position. The always-on Interlocked Barrier (§12) contributes two obstacles:

- **Part 1 — per-chunk mask permutation** — a per-chunk PRF-keyed mask triple drawn from ≈ 2^70.20 balanced partitions sits between the plaintext and the pixel layer; without the lockSeed the mapping from plaintext bits to observed lane positions is a per-chunk secret.
- **Part 2 — per-pixel 1:1 signal/noise ambiguity** — 7-rotation × 8-noisePos encoding preserves 56 per-pixel candidates at 1:1 signal/noise from a CSPRNG noise bit at unknown position.

Alongside the barrier, three independent per-snake startPixels — each derived from a separate startSeed and not transmitted on the wire — force the attacker to jointly enumerate (sp0, sp1, sp2) candidate triples without feedback.

Under Partial KPA, gcd(7,8)=1 byte-splitting adds a further factor — per-channel candidate formulation is blocked when adjacent bytes are unknown (each channel depends on two bytes; missing one prevents candidate computation).

An attacker with partial PRF inversion capability still faces three independent startPixel candidates to enumerate, 56-fold per-pixel ambiguity to disambiguate without a verification oracle, and the per-chunk ≈ 2^70.20 permutation to reverse.

See [SECURITY.md § 3 Attack Resistance Summary](SECURITY.md#3-attack-resistance-summary) for the full attack resistance table.

## 7. Byte-Splitting: Why Byte Analysis Does Not Work

Since gcd(7, 8) = 1 (7 data bits per channel, 8 bits per byte), plaintext bytes never align with channel boundaries. Every plaintext byte is split across exactly 2 channels with independent XOR masks.

A known byte like `{` (0x7B) cannot be analyzed per-channel because each channel mixes bits from 2 adjacent plaintext bytes. Without knowing the adjacent byte, the attacker cannot compute the expected channel bits. Candidates are not even formulable.

Under Partial KPA, three layers of protection combine:

1. **Barrier** — hash output unobservable (container is random).
2. **Byte-splitting** — per-channel byte-level analysis blocked (gcd(7, 8) = 1).
3. **PRF** — even if the attacker somehow gets through, inversion is infeasible.

All three layers work together: the barrier denies observation, byte-splitting denies per-channel candidate formulation under Partial KPA, and PRF denies candidate verification. Under Full KPA, byte-splitting does not add defensive benefit (the attacker has all adjacent bytes), but the defense is nonetheless multi-factor under the PRF assumption: PRF non-invertibility + independent startSeeds + 7-rotation × 8-noisePos per-pixel ambiguity at signal/noise 1:1 + the 48-bit Interlocked Barrier. The layers are architecturally independent and combine conjunctively (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)).

See [SCIENCE.md § 2.10 Byte-Splitting Property](SCIENCE.md#210-byte-splitting-property).

## 8. Full KPA (PRF Assumption)

Full KPA (the attacker knows the entire plaintext) is the worst-case adversarial baseline. The barrier composition holds under both regimes below:

| Condition | Result |
|---|---|
| Full KPA + invertible primitive | Part 1's per-chunk mask permutation and multi-seed coupling foreclose SAT-based seed recovery at instance formulation — the mapping from plaintext bits to observed lane positions is a per-chunk PRF secret keyed by lockSeed, and naive-crib SAT returns UNSAT even under a maximum-peek attacker regime (see [REDTEAM.md § FNV-1a lo-lane SAT](REDTEAM.md#fnv-1a-lo-lane-sat--architecturally-foreclosed)) |
| Full KPA + PRF (non-invertible) | Inversion infeasible → residual is brute-force P × 2^(2×keyBits) (Core ITB) or P × 2^keyBits (MAC + Reveal), per snake, plus the per-chunk barrier mask space (≈ 2^70.20 per chunk) |

Without the barrier, a naive attacker path is: take any pixel → 56 candidates (8 noisePos × 7 rotation) → compute candidate dataHash → **invert** ChainHash → get candidate dataSeed → verify on a second pixel (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)). Under PRF this path is closed at the verification step. Under an invertible primitive on the shipped construction the path is closed one step earlier: the "verify on a second pixel" step assumes a stable plaintext-byte-to-observed-lane mapping, and Part 1's per-chunk mask permutation removes that assumption — the second pixel's mapping is a different per-chunk secret drawn from ≈ 2^70.20 balanced partitions.

**Under Full KPA + total PRF inversion** (a hypothetical worst case, not an achievable attack), both barrier mechanisms collapse via algorithmic recovery (see the asymmetry note in [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)) — Part 2 through hash inversion (dataSeeds → per-pixel configuration + startPixels), Part 1 through Full KPA direct observation of mask triples (plaintext-chunk to permuted-wire correspondence) plus cascade PRF inversion for lockSeed to derive mask triples under arbitrary future nonces. The multi-factor property defends against *partial* PRF weakness, not total failure. Within partial PRF weakness, occasional/sporadic inversion events are absorbed — the architectural obstacles generate a false-positive distribution that hides the true candidates. Systematic partial inversion is not absorbed; the architecture raises cost but does not eliminate the attack. No such systematic weakness is currently known (see [Proof 4a Composition conjecture](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)).

**Under Full KPA + non-invertible PRF**, the defense is multi-factor under the PRF assumption: (1) PRF non-invertibility prevents candidate verification; (2) three independent startSeeds require joint enumeration of (sp0, sp1, sp2) triples — none of the startPixels is transmitted; (3) 7-rotation and 8-noisePos per-pixel ambiguity preserved by the barrier at 1:1 signal/noise; (4) the 48-bit Interlocked Barrier's per-chunk permutation multiplies enumeration by ≈ 2^70.20 per chunk without contributing constraints that couple chunks. gcd(7,8)=1 byte-splitting is an additional factor effective only under Partial KPA (when the attacker is missing adjacent bytes). A partial weakening of PRF is not sufficient for a Full KPA break under this stack.

## 9. Nonce Reuse: A Usage Precondition, Not an Absorbed Threat

The shipped wire carries **two independent nonces** side by side — `main_nonce` and `interlock_nonce`. The main nonce feeds the per-pixel and per-snake derivations (noisePos, per-snake rotations and channelXOR, three startPixels); the interlock nonce feeds the barrier's per-chunk mask triple through `deriveInterLockSeed` under the disjoint `0x04` domain tag. Both are drawn internally from crypto/rand on every encrypt through `generateNoncePairCfg`, and the pair is enforced pairwise-distinct inside the wire. The shipped API therefore cannot present a caller with any reuse condition — reaching one requires test-only overrides (`testNonceOverride`, `testInterlockNonceOverride`) that exist solely for the lab.

Because forcing a collision requires the lab, the birthday bounds below apply to a caller who has already deliberately narrowed the nonce width. At the shipped default `DefaultNonceBits = 512` each of the two nonce slots has an independent ~`2^256`-message birthday floor — mathematically unreachable on foreseeable hardware. A user who deliberately drops to 128-bit trades this safety-out-of-box for the ~`2^64` per-slot birthday and takes on the fresh-nonce discipline burden themselves. Joint dual-slot collision requires simultaneous collision on **both** slots — a CSPRNG hardware fault, not a design bound.

Three collision classes surface distinctly in the lab, each mapping to which of the two nonce-driven axes the attacker forces to repeat:

- **Scenario A — dual-slot collision.** Both nonces reused across the pair. Every nonce-bound draw repeats — mask triples, noise positions, rotations, channelXOR, all three startPixels. This is the maximum leverage the lab can grant, and is what a single-nonce stream cipher's classical two-time-pad structure would correspond to.
- **Scenario B — main-only collision.** Main nonce repeats, interlock nonce fresh per encrypt. The seven main-nonce-keyed derivation slots repeat; the barrier's per-chunk mask draw re-parametrises independently.
- **Scenario C — interlock-only collision.** Mirror of B. Interlock nonce repeats, main nonce fresh per encrypt. The barrier permutation repeats; the seven main-nonce-keyed slots re-parametrise.

**Empirical verdict across all three: plaintext recovery is null under attacker-realistic probes at the tested sample sizes** (see [REDTEAM.md § Nonce reuse](REDTEAM.md#nonce-reuse-lab-only)). Under Scenario A — the classical stream-cipher worst case — the container XOR carries `rotate7(snake_XOR_bits, r)` at every non-noise bit position plus a fresh CSPRNG noise bit, but **only up to the barrier's Part 1 permutation of the plaintext bits into three lane-scrambled snake payloads**. The lane assignment a two-time-pad demasker would need to anchor on is a per-chunk PRF secret keyed by the lockSeed and unobservable without it. Zero bytes recovered, both for the `random`-plaintext null-baseline control and for the `near_identical` (`P2 = P1 ⊕ 1_bit`) maximally-adversarial pair shape, across BLAKE3 as a PRF-grade reference and FNV-1a as a below-spec stress control on every one of the 8 seed roles.

**Disclaimer — "demasking" is not plaintext recovery.** A demasker of an ITB nonce-reuse ciphertext pair strips the noise-bit, per-pixel rotation, and channelXOR layers to expose the underlying raw `dataSeed.ChainHash(pixel, nonce)` output stream — a clean PRF signal under a controlled (pixel, nonce) probe, not plaintext. That output is downstream ammunition for a seed-recovery SAT attempt (feasible only under invertible primitives; infeasible under any PRF-grade primitive). Unlike a stream cipher where `C1 ⊕ C2` directly yields `plaintext_1 ⊕ plaintext_2`, ITB's per-encryption fresh-CSPRNG noise bits + per-pixel rotation + per-pixel channelXOR mean that raw ciphertext XOR does NOT reduce to plaintext XOR. A demasker's output is always the hash-output stream, never plaintext bits. On the shipped construction the barrier's per-chunk permutation removes the demasker's entry point entirely — the lane assignment is a per-chunk PRF secret keyed by the lockSeed.

## 10. CCA: Reveals Only Noise, Not Data

Under CCA (bit-flip with MAC reveal), the attacker learns noise positions — which bit in each channel is noise (3 bits per pixel from noiseSeed). Because of 8-seed isolation:

- **noiseSeed config** — revealed via CCA.
- **dataSeed configs** (rotation + 56 XOR bits, per snake) — completely independent, zero leak.
- **startSeed configs** (per-snake pixel offsets) — completely independent, zero leak.
- **lockSeed** (Interlocked Barrier per-chunk permutation channel) — completely independent, zero leak.

With CCA, the candidate count per pixel drops from 56 (8 noisePos × 7 rotation) to 7 (only rotation unknown). But 7 candidates do not help without invertible hash — the attacker cannot verify which of the 7 is correct without inverting ChainHash, and the 48-bit per-chunk barrier permutation remains unobservable.

**What the attacker gets after removing noise bits.** CCA lets the attacker strip noise bits and see 7 data bits per channel. But "clean encrypted data" is a misleading description. These data bits contain a mixture of encrypted plaintext (COBS-encoded) **and** encrypted CSPRNG fill — both encrypted identically by the per-snake dataSeed (rotation + XOR). The container is always over-sized relative to the payload; the `side++` construction guarantees a positive CSPRNG-fill gap. Perfect fill — zero CSPRNG bytes — is mathematically impossible ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

This means CCA does not give the attacker a clean plaintext-only ciphertext. A portion of the data bits carry random CSPRNG fill that is indistinguishable from encrypted plaintext. The attacker does not know where the plaintext ends and the fill begins, does not know the fill content, and cannot separate one from the other without the correct dataSeed. The CSPRNG-residue barrier layer is partially preserved within the data channel itself: ambiguity from CSPRNG residue persists even after noise removal.

CCA leak = 3/62 ≈ 4.8 % of per-pixel configuration. CCA reveals no plaintext bits, no XOR masks, no start pixel, no barrier permutation. However, CCA eliminates noiseSeed from brute-force search: P × 2^(2×keyBits) → P × 2^keyBits (two seeds → one seed). The remaining blind enumeration cost exceeds the Landauer bound on irreversible enumeration (~2^306); this bounds enumeration cost, not structural attack resistance, and the Full KPA closure under CCA remains computational and PRF-conditional (Theorem 4a).

See [SECURITY.md § 2 CCA Oracle Leak Comparison](SECURITY.md#2-cca-oracle-leak-comparison), [SCIENCE.md § 2.8 CCA Leak Upper Bound](SCIENCE.md#28-cca-leak-upper-bound-theorem-6), [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill).

## 11. startPixels: Not Transmitted, Not Recoverable

Each snake's startPixel is computed from its own startSeed + main nonce via ChainHash. None of the three startPixels is transmitted or stored; each is computed in a register once. The only theoretical way to learn a startPixel is a cache side-channel (Flush+Reload, Prime+Probe) by a co-located attacker on the same CPU.

Even in the worst case (Full KPA + CCA + cache side-channel on one snake), the attacker gets: noisePos (from CCA) + one startPixel (from cache) + 7 rotation candidates per pixel of that snake + the per-chunk barrier permutation still unobservable. Without invertible hash — brute-force 2^keyBits on that snake's dataSeed. The other two snakes remain isolated.

See [SCIENCE.md § 2.3 8-Seed Isolation — cache side-channel note](SCIENCE.md#23-8-seed-isolation-theorems-3-3a).

## 12. The Interlocked Barrier

The Interlocked Barrier is a mandatory, always-on, non-disableable layer that sits between the plaintext-interleaved payload and the pixel-embedding pipeline. It composes two mechanisms in series and never runs either in isolation. **Part 1** is a per-chunk 48-bit keyed bit permutation over the interleaved payload, drawn from a ≈ 2^70.20 balanced-partition space keyed by the lockSeed and the interlock nonce. **Part 2** is the per-pixel absorption stage that whitens each channel byte through channelXOR + rotate7 + noise-bit insertion, keyed by the dataSeed and noiseSeed against the main nonce. Part 1 denies the attacker a stable bit-position-to-lane anchor; Part 2 denies a per-byte observation channel. Neither part alone is sufficient — Part 1 alone is invertible once a primitive is inverted, and Part 2 alone leaves a fixed bit-position map. The shipped construction always engages both.

**Part 1 — 48-bit chunk permutation.** Each 48-bit (6-byte) chunk of the interleaved payload is partitioned into three disjoint 16-of-48 lanes by a mask triple `(m0, m1, m2)`, each of popcount 16, with `m0 ∪ m1 ∪ m2` covering all 48 bits. The mask triple is drawn per chunk by a PRF-keyed unrank of the balanced-partition space, keyed by the lockSeed and the nonce, and unobservable without the lockSeed.

**Mask-space cardinality.** The number of such balanced partitions per chunk is

- A = C(48, 16) = **2,254,848,913,647** (log₂ ≈ 41.04) — choices for `m0`,
- B = C(32, 16) = **601,080,390** (log₂ ≈ 29.16) — choices for `m1` from the remaining 32 bits (`m2` is then determined),

giving a per-chunk mask space of

- A · B = **1,355,345,464,406,015,082,330**, i.e. **log₂ ≈ 70.20**.

Every chunk draws its mask triple from this ≈ 2^70.20 space via a per-chunk PRF call keyed by the lockSeed and nonce. Because the draw is per-chunk and PRF-keyed, the mask of one chunk carries no information about the mask of any other. A crib supplies known plaintext bits, but the mapping from those bits to observed lane positions is a fresh ≈ 2^70.20-way secret at each chunk. The solver has no fixed bit-position-to-lane anchor. Every crib chunk therefore multiplies the attacker's enumeration by ≈ 2^70.20 without contributing a constraint that couples across chunks — the instance is under-determined regardless of crib density, and solver throughput cannot make an under-determined instance determined. This is the sense in which the barrier converts a computational-hardness problem into an instance-formulation impossibility, under the PRF assumption.

**Per-chunk PRF independence.** The security of the mask-space cardinality claim rests on the masks being independently keyed per chunk. The derivation consumes a domain tag plus the little-endian group index as the PRF input under the lockSeed (itself bound to the nonce via the internal `deriveInterLockSeed`), so distinct chunks receive distinct, PRF-independent draws. Under the PRF assumption these draws are computationally indistinguishable from independent uniform selections from the mask space. This independence is what prevents any hypothetically recovered mask from constraining any neighbour — the property that makes the per-chunk floor multiply rather than amortize.

**Exact-B reduction and the gcd anti-collapse trap.** The mask triple is produced by unranking a 128-bit uniform PRF value into `(idx0, idx1)` over the full A × B space. The chosen reduction is a two-step divmod: `idx1 = rank mod B`, `idx0 = ⌊rank / B⌋ mod A`. This reaches the **full** [0, A) × [0, B) space near-uniformly.

The rejected alternative — reducing the same rank by both moduli directly, `(rank mod A, rank mod B)` — is unsafe because it only reaches pairs `(a, b)` with `a ≡ b (mod gcd(A, B))`. Here

- gcd(A, B) = **66861 = 3² · 17 · 19 · 23**,

so the same-rank double-mod reaches only `1 / 66861 ≈ 1.5 × 10⁻⁵` of the `(m0, m1)` pairs — a structured subset that would hand the attacker a 66861×-restricted mask space through the back door. Choosing the two-step reduction is what preserves the full 2^70.20 cardinality. Naming the gcd value is a good-faith showing that the full-space coverage is deliberate, not accidental.

**Algebraic under-determination at 48 known bits per chunk.** Even granting an attacker the 48 known plaintext bits of a chunk under Full KPA, the observation does not determine the chunk's mask: the number of preimages per mask triple is `⌊2^128 / (A · B)⌋ ≈ 2^57.80`, and any candidate mask is consistent with the observation. Combined with the per-pixel 1:1 signal/noise ambiguity of Part 2 (Proof 1: P(observed | hash) = 1/2), the attacker has no ranking signal among the ≈ 2^70.20 masks. Part 1's contribution is structural: it adds a hidden per-chunk permutation whose knowledge is required before any per-bit constraint can even be written down.

**Bias distribution — granularity, not a distinguisher.** The two-step reduction is deterministic and constant-time (rejection sampling would introduce a secret-dependent branch and is avoided), so it carries a small, fixed, publicly-known bias: the `2^128 mod (A · B)` lowest-indexed pairs receive one extra preimage, giving a **per-chunk relative deviation of ≈ 2^-57.8**. Because the bias direction is fixed public arithmetic (the nonce and key randomize the draw, not the deviation), chunks across messages are independent samples of one slightly-biased law. Accumulated over a maximum-size message of `2^23.42` chunks, the conservative linear bound is ≈ **2^-34.4** per message (the tighter iid bound is ≈ 2^-36; the linear figure is the contract value). Turning this granularity into a confident distinguisher would require on the order of `1/ε² ≈ 2^115.6` chunk samples, i.e. ≈ `2^92` maximum-size messages — far beyond any attainable sample budget. Crucially, the biased event is a property of PRF output (one-way by assumption) and is unobservable beneath the barrier / noise / fill stack, so it exposes no key or plaintext channel even in principle. The figure is an architectural constant derived from the reduction arithmetic, not an empirical measurement — but the "no distinguisher" consequence is bounded by the attainable sample size and must be phrased as such.

**Part 2 — per-pixel absorption.** Each pixel packs 56 payload bits into 8 channel bytes of 7 data bits each. The 8 channels carry the **RGBWYOPA** mnemonic — Red, Green, Blue, White, Yellow, Orange, Purple, Alpha — labelling the eight positions of the byte-unit; the mnemonic is a naming convention, not a tie to image processing. Per pixel, keyed by the `dataSeed` and `noiseSeed` ChainHash outputs, Part 2 applies per 7-bit field: a **channelXOR** with 7 PRF-mask bits, a **rotate7** by a per-pixel amount in [0, 6], and insertion around a per-pixel **noise bit** taken from the original CSPRNG container byte at a per-pixel `noisePos`. The decode path inverts exactly (noise-strip, inverse rotate, XOR).

**The absorption guarantee** ([Proof 1](PROOFS.md#proof-1-information-theoretic-barrier)): for any observed byte value v and any hash output h, the probability P(v | h) = 1/2. This holds even under Full KPA — because the noise bit comes from the original container (CSPRNG), which is random and independent of everything. The observation does not uniquely determine the hash output. This is information theory, not computational assumption.

### Why KPA candidates do not break the barrier

A common question: if the attacker with known plaintext can compute 56 candidate hash outputs per pixel, doesn't that mean the barrier failed to absorb the hash output?

The 56 candidates are not extracted from the observation. They are **calculated** from the combination of (known plaintext + observed byte + candidate config). This is arithmetic, not a barrier break. All 56 candidates are **equally consistent** with the observation — the attacker does not know which one is real.

**Without hash inversion (PRF):** 56 candidates per pixel × P pixels per snake × 3 snakes = a combinatorial space that no attainable throughput enumerates. The attacker cannot verify any candidate without inverting ChainHash. PRF makes inversion infeasible. Part 2's per-pixel ambiguity is preserved, and Part 1 stacks a per-chunk ≈ 2^70.20 mask-space enumeration on top that must be resolved jointly.

**With hash inversion (invertible hash):** the attacker takes each candidate, inverts ChainHash → gets candidate seed → verifies on another pixel. Inversion **bypasses** Part 2's per-pixel ambiguity. Part 1's per-chunk permutation remains — the mapping from plaintext bits to observed lane positions is a hidden per-chunk secret and no inversion of the primitive produces it — so the instance-formulation under-determination survives. The barrier is not broken; ChainHash is inverted.

The barrier absorbs the hash output through both mechanisms: (1) Part 2's noise absorption — CSPRNG noise bit at unknown position makes the byte ambiguous, and 7 rotation candidates per pixel create 7^P unverifiable combinations; (2) Part 1's permutation — a hidden per-chunk mask triple denies a bit-position-to-lane anchor. CSPRNG residue — guaranteed fill bytes encrypted by dataSeed within the data channel, indistinguishable from encrypted plaintext ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)) — is a structural property of mechanism (1): even after CCA reveals noise bit positions, CSPRNG fill remains in the data channel. CCA (MAC + Reveal) can bypass Part 2's noise-position uncertainty, but Part 2's rotation ambiguity, the CSPRNG residue, and Part 1's per-chunk permutation remain intact through 8-seed isolation. The noise bits are removed, but the data bits still contain CSPRNG fill that the attacker cannot separate from plaintext — the information-theoretic barrier is never fully eliminated. KPA candidates are ambiguity, not leakage. PRF preserves Part 2's ambiguity; Part 1's under-determination survives even an invertible-hash case.

**Map space vs key space.** Direct guessing of the per-pixel configuration map is architecturally more expensive than seed brute-force: 2^(62·P) attempts (62 config bits per pixel — 3 noise-position + 3 data-rotation + 56 per-bit XOR), which at the unified minimum container P = 400 for 1024-bit keys gives ≈ 2^24800, dwarfing the ≤ 2^2048 key space. Brute-forcing the seed remains the attacker's most efficient known path, and even that residual enumeration exceeds the Landauer bound on irreversible enumeration at all shipped key sizes (see §10).

**Why this matters.** The barrier goes further than an information-theoretic denial of observation: it removes the public encoding of chunks entirely. Each crib chunk multiplies attacker enumeration by ≈ 2^70.20 with no shared algebraic structure to couple chunks across, so the joint SAT instance is information-theoretically under-determined regardless of crib coverage. Even an adversary with full plaintext-ciphertext pairs cannot anchor a SAT instance on a stable bit-position-to-lane mapping — the mapping is per-chunk-keyed and unobservable without the lockSeed. Under the PRF assumption, SAT-based cryptanalysis on the barrier is not a computational-hardness problem; it is an instance-formulation impossibility.

**Cost.** The barrier is a security/quality architecture, not a throughput optimisation. On x86 with BMI2 (Rocket Lake / Zen 3 and newer) the apply kernel uses three PEXT (forward) / three PDEP (inverse) instructions per chunk with 2–3-chunk ILP; the batched combinadic unrank runs through an AVX-512F ZMM kernel on top-tier hosts and through an AVX2 4-lane YMM kernel (`rankToMaskTripleUnrank48AVX2`) on AVX2-without-AVX-512 hosts (Zen 3, Cascade Lake, AVX2-only cloud VMs). On other platforms a pure-Go scalar path (`softPEXT48` / `softPDEP48`) covers correctness. End-to-end throughput stays at parity-class with the per-pixel pipeline it wraps; the barrier's contribution is architectural, at parity of speed.

Every entrypoint of the `itb.Encrypt3x{128,256,512}Cfg` / `itb.EncryptAuth3x{128,256,512}Cfg` / `itb.EncryptStream3xCfg` / `itb.EncryptStreamAuth3xCfg` and `Decrypt` families routes through the barrier; there is no runtime knob to bypass it. Every shipped `triple` profile inherits the barrier by construction — both the single-primitive shipped entries and the mixed-primitive counterparts.

## 13. Quantum Resistance

The barrier works strictly by information theory: the observation does not contain information about the hash output. This property is **computation-model-independent** — it does not depend on whether the attacker uses a classical computer, a quantum computer, or any future computational model. A quantum computer cannot extract information that does not exist in the observation.

This is the fundamental difference between ITB and traditional ciphers. AES and ChaCha20 rely on **computational hardness** — their security degrades if the attacker has more computational power (Grover: √ speedup). ITB's barrier relies on **information absence** — no amount of computation helps when the information is not there.

Specific quantum algorithms and why they are conjectured mitigated:

- **Grover** — requires a verification oracle. Core ITB and MAC + Silent Drop have no external oracle; the attacker must jointly search noiseSeed and per-snake dataSeeds (without dataSeed, noiseSeed output is indistinguishable from random), while three independent startSeeds contribute per-snake startPixel candidates (enumerated, not brute-forced), and the per-chunk barrier permutation lifts each Grover iteration by a factor tied to the ≈ 2^70.20 mask space. With MAC + Reveal: CCA reveals noisePos but not startPixels or lockSeed.
- **Simon** — requires periodic function structure. ITB's config map is aperiodic: each message has a unique per-message nonce (up to 512-bit, configurable), creating a completely different configuration.
- **BHT** — requires observable hash collisions. In Core ITB and MAC + Silent Drop the random container absorbs collisions — two identical hash outputs on different pixels produce different observed bytes (different random container values). After CCA (MAC + Reveal), collisions remain unobservable through encoding ambiguity (7 rotation candidates per pixel — attacker cannot identify which candidates collide) and through the barrier's per-chunk permutation.
- **Q2 superposition queries** — requires an oracle that accepts quantum superposition inputs. ITB's MAC oracle is inherently classical: it receives concrete bytes over a network and returns accept/reject. Superposition queries are physically impossible.

At 1024-bit key: Core / Silent Drop and MAC + Reveal both sit at complexities far beyond any foreseeable quantum capability, before crediting the barrier. For comparison, AES-256 with Grover: 2^128 — widely considered quantum-resistant.

See [SCIENCE.md § 3.3 Quantum Resistance](SCIENCE.md#33-quantum-resistance-conjectured), [SCIENCE.md § 2.6 — Why KPA candidates do not break the barrier](SCIENCE.md#26-multi-factor-full-kpa-resistance-theorem-4a).

## 14. Per-Candidate Cost: Why Brute-Force Is Slow

In AES or ChaCha20, testing one candidate key takes on the order of a nanosecond — a single block operation. In ITB, testing one candidate requires decrypting the **entire container** — all P pixels across all three snakes, each with ChainHash evaluation, plus the per-chunk barrier unrank. The larger the message, the more expensive each attempt.

| Data size | P (pixels) | Time per attempt | vs AES |
|---|---|---|---|
| Min container (~2.5 KB) | 400 | ~64 µs | ~64,000× slower |
| 4 MB | 602,176 | ~96 ms | ~96 million× slower |
| 16 MB | 2,408,704 | ~385 ms | ~385 million× slower |
| 64 MB | 9,628,609 | ~1.5 s | ~1.5 billion× slower |

Approximate example: 1024-bit key, ~10 ns/hash (average across PRF functions on a typical modern CPU), 8 ChainHash rounds. Actual times vary by hash function, key size, and hardware. This applies to all modes (Core ITB, MAC + Silent Drop, MAC + Reveal) and stacks additively with the barrier's per-chunk unrank cost.

This is not a tunable parameter — it is a structural consequence of the construction. Every brute-force candidate, classical or quantum (Grover), must pay this cost. ChainHash rounds are sequential and cannot be parallelized.

See [SCIENCE.md § 5 — Per-candidate decryption cost](SCIENCE.md#5-ambiguity-based-security) for detailed analysis.

## 15. Barrier and PRF: Symbiosis

The barrier and PRF hash function protect each other:

- **PRF protects the barrier:** non-invertibility prevents the attacker from resolving the 56-candidate per-pixel ambiguity and the per-chunk ≈ 2^70.20 mask ambiguity under KPA. Without inversion, the barrier's information-theoretic protection holds — the attacker cannot verify which candidate is real.

- **Barrier protects the PRF:** hash collisions are the only theoretical weakness of a non-invertible hash function — two different inputs producing the same output. In a traditional cipher, collisions may be exploitable because the attacker observes the output directly. In ITB, collisions are invisible: two pixels with the same dataHash have different original container bytes (CSPRNG), so the observed bytes are different. The collision is absorbed. The 48-bit Interlocked Barrier compounds this by re-mapping every chunk through a hidden per-chunk permutation — any hypothetical collision in the underlying dataHash lands in a chunk-specific lane assignment the attacker cannot recover.

- **ChainHash architecture resists MITM:** the N independent `uint64` seed components are processed sequentially — each round feeds the previous output XOR'd with the next component — so compromising one component reveals nothing about the others (there are no key-schedule relationships between them). Three independent barriers stack against meet-in-the-middle attacks: unobservable hash output (Part 2 absorption), non-invertibility (PRF assumption), and multi-call key discrimination through the chained output.

Together: non-invertibility blocks inversion, and absorption hides collisions. Each property closes the other's theoretical weakness. In Core ITB and MAC + Silent Drop (no oracle, passive observation only), the barrier makes a non-invertible hash function indistinguishable from an ideal random function — collisions absorbed, statistical patterns absorbed, no known attack surface remains. With MAC + Reveal (CCA): noiseSeed config is leaked via oracle interaction, but per-snake dataSeeds and the lockSeed remain protected by PRF non-invertibility and 8-seed isolation. Even after noise removal, the data channel retains CSPRNG fill bytes encrypted by dataSeed — perfect fill is impossible ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)) — so information-theoretic ambiguity persists within the data bits themselves.

See [SCIENCE.md § 2.1 Information-Theoretic Barrier](SCIENCE.md#21-information-theoretic-barrier-theorem-1).

## 16. Oracle-Free Deniability

The wire and the API surface are designed so that a wrong-seed attempt is indistinguishable from a correct one to any observer without the seeds. The construction carries no verification channel of its own:

- **No magic bytes or file-format signatures.** The wire header carries only `[main_nonce][interlock_nonce][W][H]` — dimensions plus the two per-message nonces — and the container. Nothing on the wire identifies the payload as ITB output.
- **No message length header.** The plaintext length is not transmitted. The 4-byte big-endian length prefix consumed by the Interlocked Barrier (§5) travels inside the encrypted container across the chunk-level split, invisible without the correct seeds.
- **Null terminator encrypted.** The COBS terminator is embedded inside each snake's encrypted payload, so decoding with a wrong seed does not surface a distinguishing boundary.
- **No padding required.** The rotation barrier from the independent `dataSeed` slots provides confidentiality without any padding scheme, so the wire does not carry padding markers or length-recovery hints.
- **Wrong seed produces random-looking output with no verification oracle.** Decryption with any seed always succeeds mechanically and returns bytes; correctness has no on-wire signal.
- **MAC + Silent Drop preserves oracle-free deniability.** When the deployment drops on MAC failure without a response, the attacker receives no verification feedback — the MAC surface itself is deniable.

Under MAC + Reveal the noise-position channel becomes an oracle bounded to 3 bits per pixel from `noiseSeed` (see §10, [Proof 6](PROOFS.md#proof-6-cca-leak-upper-bound)); every other seed and the full plaintext channel remain outside the oracle. Deployments that need full oracle-free deniability run Core ITB or MAC + Silent Drop.

## 17. Custom Primitives

Users plug a custom hash primitive in one of two ways.

**Direct closure at the Low-Level surface.** Construct `itb.HashFunc{N}` + `itb.BatchHashFunc{N}` closures and pass them directly to the `*Cfg` entrypoints. This is the most explicit path — the primitive never touches any registry, and every call passes the closure explicitly.

**Registration by name via `hashes.Register`.** The runtime API `hashes.Register(spec hashes.Spec) error` adds a user-supplied primitive to the runtime registry (a mutex-guarded slice separate from the shipped `hashes.Registry`; the FFI iteration surface stays untouched). The registered name resolves through `hashes.Find` / `hashes.Make{N}` / `hashes.Make{N}Pair` alongside shipped entries. Registration is process-wide, immutable (a second `Register` for the same name returns `hashes.ErrHashExists`), and appended after the shipped Registry in `hashes.AllPrimitives`. The Spec carries `Name` (lowercase letters, digits, underscores; capped at `hashes.MaxNameLen`), `Width` (`W128` / `W256` / `W512`), and exactly one `Make{N}Pair` factory field matching the width. `hashes.Register` is a Go-native API only; bindings are triple-only and do not expose custom-primitive plug.

**Custom primitives in the `triple` facade.** A user-registered primitive is usable through the triple facade via `triple.RegisterProfile`: build a `triple.Profile` whose `InnerHash` (or `MixedHashes` per-slot entries) references the registered name, then register the profile under a new user-chosen name and reference it from `triple.Init` / `triple.Open` like any shipped profile. The shipped profile catalogue itself binds only to shipped registry entries; user profiles pick from any resolvable name (shipped or registered).

For worked examples, see the README's [Advanced — Low-Level `*Cfg` surface](README.md#advanced--low-level-cfg-surface) and [Custom user-supplied primitives](README.md#custom-user-supplied-primitives) sections.
