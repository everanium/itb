# ITB FAQ: Broken Primitives and the Barrier — an Analytical Walkthrough

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

This FAQ is the plain-language companion to [REDTEAM.md](REDTEAM.md), [SCIENCE.md](SCIENCE.md), and [PROOFS.md](PROOFS.md). It walks a cryptanalyst through three concrete scenarios — a trivially invertible three-line `jokeHash`, a GF(2)-linear CRC128, and a T-function FNV-1a — and traces the reasoning arrows from primitive weakness on paper to wire observability in the shipped construction, and precisely which lab-only privileges (unreachable through the shipped API) would be required for each attack vector to engage. The canonical documents give the corresponding conclusions in formal notation; this file gives the reasoning arrows.

**Framing.** This document is an analytical walkthrough of the reasoning that leads to the null-recovery observations recorded in REDTEAM.md — not a security proof, not a certification claim, not a guarantee that no attack exists. The picture presented below is the current architectural understanding as seen from the reasoning steps listed here. Audit findings that contradict any arrow in the reasoning would supersede the corresponding conclusion. The framing is «this is what the analysis currently shows», not «this is what the construction guarantees».

Three questions, three primitives, one shared architectural pattern.

---

## Question 1 — What if I write a three-line `jokeHash`?

**Reader's setup.** «Suppose I plug into all eight ITB seed roles this three-line primitive — initialise the accumulator from `seed0`, mix each data byte via a small odd multiplier plus add, complement for the second lane:

```
jokeHash(data, seed0, seed1):
    lo = seed0
    for b in data: lo = lo*257 + b
    return (lo, ~lo)
```

T-function class (Klimov and Shamir 2002): output bit t depends only on input bits at position ≤ t, so recovery is polynomial per bit-plane. Trivially invertible for any single `(data, seed)` observation pair, catastrophically weak by any cryptographic standard — no round mixing, no diffusion, below spec compared with CRC128 or FNV-1a on the observation-channel-required stress axis. Ship it via `hashes.Register` as a custom primitive and encrypt real messages. Do I compromise the wire?»

### Current analytical picture

Under attacker-realism (0/8 seeds granted, no `main_nonce` collision, no side channel exposing primitive outputs), the reasoning traced below does not appear to yield a viable attack path. The observation the analysis rests on is that the path from the wire to any primitive input appears to be structurally cut, independently of primitive strength — so a three-line invertible primitive, however trivial, seems to have nothing observable to invert. The empirical counterpart lives in `redteam_jokehash_test.go` (Go build tag `redteam`), which encrypts N = 10000 fresh-nonce ciphertexts under a multiply-add-fold jokeHash on all eight seed roles and gates on the wire body region showing zero per-bit fixation (a stricter surface than the shipped FNV-1a-on-8-roles fresh-nonce CPA cell at N = 2000 per REDTEAM.md § Broken-primitive stress). The three sections below trace each arrow in the reasoning.

### The full picture

The attacker's problem, stated in the simplest form:

```
observation on wire  →?→  reach jokeHash output  →?→  invert to seed
```

`jokeHash` invertibility gives the third arrow essentially for free — plane-by-plane T-function recovery in polynomial time. The first two arrows are what the barrier removes.

**Where hash outputs live in the pipeline.** In the shipped construction, hash outputs are consumed opaquely inside the encoder and never surface on the wire in cleartext:

- `noiseSeed.ChainHash(pixel, N_m)` → `& 7` → `noisePos` → used only as an insertion position, then folded into a container byte
- `dataSeed_i.ChainHash(pixel, N_m)` → `hLo` low bits → rotation + `channelXOR` → applied to data bits → lane compression / rotation / XOR / noise-bit merge → wire byte
- `lockSeed.deriveInterLockSeed(N_il)` → `lockKey` → per-chunk `H(0x03 ‖ ⟨i⟩, lockKey)` → 128-bit `rank` → combinadic unrank → mask triple → applied via PEXT inside `chunk48lock` → 3 lane fragments → Part 2 encoding

A wire byte at position `(p, ch)` has the shape:

```
wire[p, ch] = insert( rotate( lane_bits ⊕ channelXOR, r ),  C[p, ch],  noisePos )
```

where `lane_bits`, `r`, `channelXOR`, `noisePos` are all derived from hash outputs — but the hash output itself never appears. Every observable is a composition. Every composition mixes a PRF-derived quantity with an independent CSPRNG-derived quantity (`C[p, ch]`, the random container) via Part 2 absorption.

**The demasker gate.** To extract even one hash output the attacker must «demask» — strip Part 2 encoding. Demasker fundamentally requires a Full KPA anchor to choose among 56 candidates per pixel. Without an anchor, [Proof 1](PROOFS.md#proof-1) says all 56 are equiprobable, and the algorithm does not converge to a decisive answer.

Under **Single Ouroboros**, an attacker with a Crib KPA anchor could sometimes demask successfully — that is the regime where archived scripts recovered `dataSeed` from a strong-primitive target. Under the current shipped construction (**Triple Ouroboros + Interlocked Barrier + dual-nonce**), the demasker fails empirically per [REDTEAM.md](REDTEAM.md), even under lab-forced Scenario A on FNV-1a on every seed role, because three unknown-offset snake streams plus Part 1 lane scrambling give the demasker nothing to anchor on.

So the attacker holding a shipped ciphertext, running `jokeHash` in an arbitrary seed role:

- Cannot demask Part 2 → **no observations of hash outputs** → `jokeHash` invertibility has nothing to invert
- Cannot observe mask triples → Part 1 remains opaque → combinadic unrank is uninformative even at a `jokeHash`-driven `lockSeed`, because a `rank` value never becomes visible
- Cannot exploit `jokeHash` bias for plaintext-content recovery → Part 2 absorption gives `P(v | h) = 1/2` **per pixel** regardless of primitive bias, so no wire byte is ever anchored to a specific plaintext bit (a weaker aggregate-statistics residue — a plaintext-Hamming-weight distinguisher visible under repeat-plaintext CPA when the primitive's output distribution itself carries measurable bias — does surface for the popcount-2 `jokeHash` multiplier specifically; see [§ Residual bias under repeat-plaintext CPA](#residual-bias-under-repeat-plaintext-cpa) below, and note that it does not enable plaintext-content recovery)

### The lab-only scenarios where `jokeHash` bites

Both scenarios are unreachable through the shipped API and require adversary capabilities that the shipped surface does not grant:

1. **7/8 seeds granted via lab peek.** Grant the attacker seven of the eight seeds through instrumentation. Part 2 encoding collapses (all its keying material is known). The attacker now sees clean per-chunk PRF observations, inverts `jokeHash` plane-by-plane in polynomial time per T-function, recovers `lockKey`, decodes mask triples, and reads plaintext. The takeaway is not «`jokeHash` broke ITB» but «once the barrier has been surgically stripped in the lab, whatever remains is `jokeHash`-level trivial to reverse». The shipped API does not expose seven-seed material.

2. **Novel observation channel that exposes hash outputs directly.** A side channel that leaks primitive output bypassing PEXT / mask apply — cache timing on a software AES kernel without AES-NI is the classic example. The register-only ITB kernels (with mandatory hardware AES / GFNI / VAES paths for AES-family primitives) do not create this observation surface. `jokeHash` bias would help if the surface existed; the shipped construction denies the surface.

### Why REDTEAM.md uses CRC128 and FNV-1a as stress controls

Not to «break ITB through them», but to demonstrate empirically that the barrier absorbs primitive weakness across a wide spectrum. If under CRC128 (worst primitive on the algebraic axis, GF(2)-linear compound-key recovery available on paper) the attacker gets null recovery, then any PRF-grade primitive automatically inherits at least the same outcome by a closure argument. The framing is «if the weakest works, all stronger work a fortiori» — a closure scoped to the plaintext-content-recovery axis on which CRC128 is the hardest realistic control. Among realistic below-spec primitives the barrier also absorbs output-distribution bias cleanly: CRC128 and FNV-1a both sit at the noise floor on every measurement in this file. jokeHash is a deliberately pathological stress case (popcount-2 multiplier, more poorly diffused than any real primitive would be), and it is the sole primitive that surfaces the plaintext-Hamming-weight residue documented in [§ Residual bias under repeat-plaintext CPA](#residual-bias-under-repeat-plaintext-cpa) below — a plaintext-structure distinguisher, not plaintext-content recovery, and one that CRC128 and FNV-1a do not exhibit.

### General principle the `jokeHash` thought experiment illustrates

The primitive-strength assumption in [Proof 4a Asymmetry note](PROOFS.md#proof-4a) is load-bearing only in the case where the attacker has an observation channel on hash outputs. The barrier's job is to remove that observation channel independently of primitive strength. Under attacker-realism the observation channel is closed structurally. Primitive strength then matters only for partial-inversion scenarios where a fragment of output leaks — and even there the multi-factor defense (see the closing note below) demands simultaneous breach of every factor.

Even a three-line invertible primitive produces no wire-level plaintext-recovery channel through the shipped barrier under attacker-realism. The gap opens only when primitive-inverted output becomes actually observable, which the shipped API does not permit.

### Empirical corroboration at N = 10 000

`TestRedTeamJokeHashRepeatPlaintextCPA` and `TestRedTeamJokeHashVaryingPlaintextCPA` in `redteam_jokehash_test.go` run 10 000 encryptions under a multiply-add-fold jokeHash on all eight seed roles (fresh nonce per call, no seed peek), at a 5× larger sample than the shipped FNV-1a-on-8-roles cell (N = 2000 per REDTEAM.md). Measurements on the wire:

- **Roundtrip.** All 10 000 ciphertexts unique; every roundtrip recovers plaintext; 18 KB long-plaintext roundtrip confirms `chunk48lock` functionality under jokeHash on `lockSeed`.
- **Byte-value chi² across five sampled wire positions**: 225.5, 235.8, 246.8, 262.0, 266.2 (df = 255, uniform expects 255 ± 22.6). Every position inside the uniform band.
- **Hot-bit-per-byte histogram (`|p(bit=1) - 0.5| > 0.15`)**: 9928 body bytes at 0 fixed bits, 4 metadata bytes (the W and H dimension fields, always fixed for a given plaintext length regardless of primitive) at 8 fixed bits, nothing in between.
- **Delta between repeat-plaintext and varying-plaintext runs**: identical hot-bit histograms and identical 32 catastrophic bits — the plaintext-content-derived wire signal is zero.
- **Body-region monobit on 762 560 000 bits**: p(bit = 1) = 0.499998, |z| = 0.13 (well inside the 5σ gate; the 3σ band width is 5.4 × 10⁻⁵ at this sample size).

### Residual bias under repeat-plaintext CPA

The tests above measure the wire under a fresh CSPRNG plaintext or under the same plaintext repeated with fresh nonces, and gate on plaintext-content recovery. A separate measurement — `TestRedTeamJokeHashHWDistinguisherVsPRF` in the same file — runs a two-arm repeat-plaintext probe (same all-zero plaintext under one arm, same uniform-random 4 KB plaintext under the other, both at N = 2000 fresh-nonce ciphertexts) across four W128 primitives on all eight seed roles: jokeHash, CRC128, FNV-1a, and SipHash-2-4 as the hard-gated PRF control. Representative numbers from one run (specific z-scores drift across runs with the CSPRNG-drawn seed components; the pattern is stable):

| Primitive | zeros arm \|z\| | random arm \|z\| | homogeneity chi² |
|---|---|---|---|
| jokeHash (multiply-add, multiplier 257) | **≈ 30 – 40** | ≈ 1 – 2 | **≈ 3000 – 6000** |
| CRC128 (GF(2)-linear) | ≈ 1 | ≈ 1 | ≈ 250 |
| FNV-1a (T-function, multiplier `0x100000001b3`) | ≈ 1 | ≈ 1 | ≈ 250 |
| SipHash-2-4 (PRF) | ≈ 1 – 3 | ≈ 1 – 3 | ≈ 250 |

Noise floor at N = 2000 pooled over 152 M body bits: per-arm \|z\| under a uniform CSPRNG stays under 3 with overwhelming probability; homogeneity chi² has a df = 255 uniform band top at ≈ 323 (3σ) / ≈ 368 (5σ). CRC128, FNV-1a, and SipHash-2-4 all sit inside that band. Only jokeHash surfaces the signal.

**The finding is jokeHash-specific, not "any broken primitive".** CRC128 (algebraically the friendliest primitive — one Gaussian elimination inverts it) and FNV-1a (T-function class, poly-time recoverable per bit-plane) both stay inside the noise floor on this measurement, matching the PRF-grade control. jokeHash is the outlier.

Mechanism. The encoder mixes primitive output into the wire through `channelXOR` (see the earlier «Where hash outputs live in the pipeline» block). For a plaintext bit `p` and an encoded wire bit `p ⊕ channelXOR`, uniform `channelXOR` symmetrises any `p` distribution to 0.5 on the wire. What matters is whether the primitive's output distribution is close to uniform under random-seed input, not whether the primitive is cryptographically strong. CRC128's dense-table GF(2) diffusion and FNV-1a's popcount-6 prime multiplier both produce output distributions that are indistinguishable from uniform on 152 M pooled bits, so `channelXOR` inherits that uniformity and the wire monobit sits at 0.5 regardless of plaintext HW. jokeHash's multiplier 257 = `0x101` has popcount 2 — `x * 257 = (x << 8) + x`, a shift-add that preserves the low byte of `x` verbatim after the multiply — so its output distribution is measurably biased, `channelXOR` inherits about 1 % of that bias, and the bias couples with plaintext HW to shift the pooled wire monobit by ≈ 10⁻³ on the fixed-plaintext arm.

What this residual means:

- **Plaintext-content recovery — unaffected.** The signal does not localise on a per-pixel bit, does not name a wire byte, and does not read out any plaintext bit. Both `TestRedTeamJokeHashRepeatPlaintextCPA` and `TestRedTeamJokeHashVaryingPlaintextCPA` still show 9928 body bytes at 0 fixed bits and identical delta between the repeat and varying arms.
- **Plaintext-structure distinguisher — present under repeat-plaintext CPA with a poorly-diffused primitive.** An attacker with ~2000 ciphertexts of the same plaintext under jokeHash on all eight seed roles can distinguish «this plaintext was mostly zeros» from «this plaintext was uniform-random» at high confidence. Under CRC128, FNV-1a, or any well-diffused primitive (PRF-grade or not) the distinguisher closes at the tested sample size; the residue is specifically a poorly-diffused-primitive artefact, not a generic broken-primitive property.

Honest phrasing: the shipped barrier absorbs the observation channel that a plaintext-content-recovery attack would need, but the primitive's output-distribution properties still project onto the wire through `channelXOR` diffusion. Under attacker-realism the recovery channel stays closed regardless of primitive choice — that is the load-bearing claim. Under a structured-repeat-plaintext CPA a primitive whose output distribution is measurably non-uniform leaves a weak Hamming-weight distinguisher that a well-diffused primitive does not; jokeHash's popcount-2 multiplier is the tested case where this residual is visible.

The reasoning arrows above and the numbers here point at the same picture: through the shipped barrier under attacker-realism, even a three-line invertible primitive gives the same plaintext-content-recovery surface as a well-designed one — because the barrier's absorption acts before the primitive's output can be observed. A separate weaker channel — a plaintext-Hamming-weight distinguisher visible only under repeat-plaintext CPA with a poorly-diffused primitive — remains open, and closing it is what shipped primitives with adequate output diffusion (all shipped-registry entries qualify, and even CRC128 and FNV-1a as stress controls qualify on this specific measurement) already do.

---

## Question 2 — CRC128 is GF(2)-linear. Can I use compound-key linear algebra to break ITB?

**Reader's setup.** «CRC128 admits full total inversion in polynomial time — one Gaussian elimination on a GF(2) system. The public script `scripts/redteam/itb/theory/crc128/compound_key_crc128.py` recovers a compound key `K` without any crib KPA on Single Ouroboros. Why does that path not carry into the shipped construction?»

### Current analytical picture

Analytically, three shipped-construction factors — **Triple Ouroboros**, the **always-on Interlocked Barrier**, and **dual-nonce separation** — each appear to invalidate one of the assumptions the compound-key linear-algebra recovery relies on, so the attack path that works cleanly against Single Ouroboros does not seem to carry over. Beyond that, the hypothetical transfer of the recovered `K` from Part 2 to Part 1 runs into five orthogonal architectural reasons at the algebra layer, before any observation gap is even considered. The sections below trace each reasoning arrow; countering any of them would supersede the corresponding step in the analysis.

### CRC128 is indeed total inversion — on paper

CRC128 is literally total inversion in polynomial time: given a hash-output observation `h = H(data, seed)` the seed is recovered as

```
seed = M_L^{-1} · (h XOR const(0))
```

by one Gaussian elimination on an `n × n` GF(2) system in `O(n^3)`. This is not a PRF in any cryptographic sense — it is an integrity-check function reused as a stress control precisely because it is the algebra-friendliest possible primitive.

Under **Single Ouroboros**, this translates into the compound-key attack:

```
hLo(p) = K XOR const(data(p))
```

where `K` is a pixel-independent 64-bit compound key and `const(data(p))` is public-computable from the public pixel index and public nonce (ChainHash with `seed = 0`). Linear algebra recovers `K` from observations without plaintext, restores `channelXOR` at any pixel of future messages under the same `(dataSeed, nonce)`, and reads out the encoded data — because ITB reads only 64 bits from the 128-bit CRC128 output and 56 of them are exposed via `xorMask = hLo >> 3`. The script demonstrates this against Single Ouroboros with no Interlocked Barrier and no Triple wrapping. It is real, and it works in that regime.

### Why the shipped construction closes the path

Three architectural factors compose:

**1. Triple Ouroboros — three snakes with independent `startPixel`s.**

Compound-key recovery assumes the pixel-to-observation-position mapping is known (or brute-forceable via period shift). Under Triple, the attacker sees a container with interleaved 3-snake payload where the snake boundaries are not visible on wire. The attacker does not know which observation belongs to which snake without joint enumeration of three independent `startPixel` candidates — three independent compound-key recovery instances with unknown routing between them.

**2. Interlocked Barrier Part 1 — per-chunk PRF-keyed permutation.**

Even if the routing were solved hypothetically, the data in each snake is no longer a direct projection of plaintext bytes to channels. Between the plaintext and the per-pixel encoder sits `chunk48lock`, which via PEXT under a mask triple `(m_0, m_1, m_2)` — drawn from `Ω_chunk ≈ 2^70.20` space keyed by `lockSeed + interlock_nonce` — redistributes the bits into three 16-bit lane fragments per 48-bit chunk. The attacker's `channelXOR(p, ch)` recovery under CRC128 would yield an XOR mask on channel bytes, but those channel bytes now carry PRF-permuted lane fragments, not plaintext bytes directly. The linear system recovers `K` → predicts `channelXOR` → recovers not plaintext, but `PEXT(chunk, m_N)` bits under an unknown mask. To go further requires `lockSeed → mask triple`, which is PRF-opaque under fresh `interlock_nonce`.

**3. Dual-nonce separation.**

Compound-key recovery is pinned to a specific `(dataSeed, main_nonce)` pair. Fresh `main_nonce` → fresh `K` per message. `main_nonce` reuse is possible only through a test-only override, not the shipped API. Even under a lab-forced Scenario B (main-only collision), `K` is identical on the colliding pair, but the barrier's lane assignment depends on `interlock_nonce`, which is fresh → the attacker gets same `K`, same `channelXOR`, but different lane assignments → previously predictable channel bytes now map to unknown 48-bit chunk positions.

Honest phrasing of the verdict: the CRC128 linear-algebra path is closed not because «without KPA it is impossible at all» — that would be an over-claim — but because Triple splits the observation space into three unknown-offset streams, Part 1 injects an unknown PRF-keyed permutation between the recoverable `channelXOR` and plaintext bytes, and dual-nonce guarantees fresh barrier keying even under a single-slot collision.

### But wait — what if CRC128 is also used inside Part 1?

**Reader's setup, continued.** «Suppose `lockSeed` is fed by CRC128 too. Same primitive on both barrier layers. Doesn't the compound-key `K` recovered from Part 2 give me leverage on Part 1?»

**No.** Even under identical primitive, `K` from Part 2 is fundamentally not transferable to Part 1. There are five reasons at the algebra layer alone, before any observation gap:

**Reason 1 — Seed independence ([Theorem 3](PROOFS.md#proof-3)).**
`lockSeed` and `dataSeed` are independent CSPRNG components, `I(lockSeed; dataSeed) = 0`. The compound-key script recovers `K_data = [M_L^1, ..., M_L^8] · [s_14, s_12, ..., s_0]` — a linear projection *inside* `dataSeed`'s ECMA-half components. `K_lock` would be a fundamentally different projection over `lockSeed` components. No overlap can produce a transfer.

**Reason 2 — Different derivation-chain shape.**
The compound-key linear structure depends on the length-`L` CRC64 state-transfer matrix `M_L`:
- `dataSeed → dataHash`: `data(p) = pixel_le_u32 ‖ nonce`, so `L = 4 + nonceBytes` — fixed per session at the caller's nonce size — and `M_L` stays constant at that `L` across all pixels; this is what the compound-key script exploits
- `lockSeed` cascade: `lockKey = ChainHash(0x04 ‖ N_il, lockSeed)` with `L = 1 + nonceBytes`; then `prf_i = H(0x03 ‖ ⟨i⟩, lockKey)` with `L = 9` (1 byte tag + 8-byte LE index). **Different length constants → different matrix products → different compound-key algebra.**

**Reason 3 — Different domain tags.**
`0x04` for `lockKey` derivation, `0x03` for per-chunk PRF, counter for `dataSeed`. Even with identical seed material, different tags yield different `const(data)` in the affine decomposition `hLo(p) = K XOR const(data(p))`. `K_data` cannot be re-used to predict `lockSeed`'s chain output.

**Reason 4 — Different observation path.**
`K_data` is recovered from `channelXOR` observations (post-demask or via KPA). The attacker physically sees container bytes → strips Part 2 (rotation + XOR + noise) → gets lane fragments. Lane fragments are not plaintext — they are `PEXT(chunk_48, m_N)` where `m_N` is a Part 1 mask. To recover Part 1 via linear algebra the attacker needs observations of mask ranks — and **mask ranks never appear on the wire in cleartext.** They are applied opaquely inside `chunk48lock` and compress plaintext bits into 16-bit lanes. The attacker sees the compression result, not the permutation itself.

**Reason 5 — Combinadic unrank is not GF(2)-linear.**
Even if `lockKey` were hypothetically recovered (which already requires observation of hash outputs that are unobservable), unranking it into a mask triple runs through two-step divmod:

```
idx_0 = ⌊rank / B⌋ mod A
idx_1 =  rank        mod B
```

where `A = C(48, 16) = 2,254,848,913,647` and `B = C(32, 16) = 601,080,390`. This is pure arithmetic over `Z`, not GF(2)-linear. CRC128's GF(2)-linearity is useless here — combinadic reduction breaks linearity even if the primitive is linear.

**Bonus reason — cascade PRF binding across two live hash calls.**
Per [Proof 11](PROOFS.md#proof-11): `lockKey → per-chunk PRF chain` is two sequential hash calls. An attacker attacking Part 1 via linear algebra must solve a system running through both chain calls simultaneously. The compound-key script composed an 8-round chain as a single affine XOR (`K = M_L^1·s_0 XOR M_L^2·s_2 XOR ...`) because 8 XOR-composed CRC64 rounds are still GF(2)-linear. A cascade of two chain calls with an intermediate unrank/mask draw is no longer a single-composition path — the attacker needs either a system with symbolic `mask` **and** `K_lock` (two unknowns interleaved), or per-chunk hash outputs as observations (which do not exist on wire).

**Summary.** Primitive is same. Seeds are independent. Chain-input structure differs. Observation path differs. Unrank arithmetic is non-linear. Across these five orthogonal structural differences no linear transfer path from `K_data` to any other seed / channel is apparent — combinadic-unrank non-linearity specifically blocks the GF(2) route that CRC128's linearity exploits on Part 2. A non-linear bridge — a symbolic-SAT setup that carries `K` through unrank arithmetic, or a novel algebraic technique that couples the two layers through structure the walkthrough above did not surface — is not ruled out by the reasoning here, only unaddressed by known technique. What [Theorem 3a](PROOFS.md#proof-3a)'s minimality argues is that the 8 independent seeds oblige the barrier layers to be architecturally separable at the algebra layer, independently of primitive strength or weakness.

### The `2^57.80` preimage math and cross-nonce non-collapsibility

**Reader's setup, continued.** «Fine, but the mask triple has a fixed preimage count `≈ 2^57.80`. Can I collect enough observations across many nonces under a fixed `lockSeed`, using CRC128's linearity across the cascade, to collapse that ambiguity?»

**No.** Let me refine the math first, because «floating range» is a mischaracterisation.

The rank space is `2^128` (from 128-bit PRF output). The mask space is `Ω_chunk = A · B ≈ 2^70.20`. The reduction map `rank → (idx_0, idx_1)` is many-to-one, mapping `2^128` rank values into `2^70.20` mask triples. The preimage count per mask triple is either `⌊2^128 / (A · B)⌋` or `⌊2^128 / (A · B)⌋ + 1`:

- `2^128 mod (A · B)` masks receive `⌊…⌋ + 1` preimages
- The rest receive `⌊…⌋` preimages
- Both are approximately `2^57.80` — the deviation is exactly ±1 per specific mask, **not a range**

What actually «floats» is the per-chunk relative bias magnitude `2^-57.8` (the inverse of the preimage count). If every mask had identical preimages, the distribution would be uniform; the +1 extras produce a bias of magnitude `2^-57.8` per chunk. Accumulated linearly across `2^23.42` chunks in a maximum-length message, the per-message deviation is `≈ 2^-34.4`. The distinguisher budget needed to detect this bias with confidence is `≈ 2^115.6` chunk samples — not attainable.

Now the attack model. Under CRC128 the cascade is fully affine over GF(2):

```
lockKey_msg = M_L · lockSeed XOR const_lock(N_il)                    (linear in lockSeed for fixed N_il)
prf_i_msg   = M_pr · lockKey_msg XOR const_pr(i)
            = M_pr · M_L · lockSeed XOR M_pr · const_lock(N_il) XOR const_pr(i)
```

If the attacker had many `rank_i_msg = prf_i_msg` observations under many `(N_il, i)` pairs at fixed `lockSeed`, this would be a trivial linear system `rank_j = A_j · lockSeed XOR b_j`. `n` unknowns (bits of `lockSeed`), `n` linearly independent observations, Gaussian elimination in `O(n^3)`. Broken in milliseconds.

But the attacker does not observe `rank`. Rank is consumed opaquely inside combinadic unrank → mask triple → applied via PEXT to compress a plaintext chunk into 3 lane fragments → lane fragments pass Part 2 encoding → container byte.

The attacker's observation path to obtain a single `rank` observation is:

1. **Strip Part 2** from the container byte → need demask → need KPA anchor per pixel (56 candidates equiprobable without an anchor). Under Triple + Barrier the demask fails empirically per REDTEAM.md null verdict.
2. **Reassemble lane fragments** from Part 2-stripped snake payload bytes. Works fine if Part 2 is stripped.
3. **Recover the mask triple** from `(known plaintext chunk, observed lane fragments)`. For candidate mask `m`, `PEXT(chunk, m) = lane_N` is under-determined. At 48 known plaintext bits and 48 output bits (16 × 3 lanes) the attacker gets 48 constraints on `≈ 2^70.20` candidate masks — approximately `2^22` masks remain consistent with the observation in the general case.
4. **Recover `rank` from the mask triple** — inverse combinadic unrank. For each mask triple, `≈ 2^57.80` candidate ranks correspond (the preimage count). Even after fixing a candidate mask, `2^57.80` candidate ranks remain per chunk.
5. **Only then** can the attacker use CRC128 linearity through cross-message system solving on recovered ranks.

**The mathematical crux — steps 3–4 do not collapse by adding more observations under different nonces.**

Each message yields its own per-chunk PRF-independent mask draw ([Proof 11](PROOFS.md#proof-11)'s PRF-independence clause). Ambiguity from message `N` does not constrain ambiguity in message `N+1` — they are independent PRF draws. After `N` messages the attacker does not have «`2^57.80` initial ambiguity collapsing to `2^57.80 / N`»; the attacker has `N` independent instances of `2^57.80` ambiguity, none coupling to the others.

Cross-message CRC128 linearity would help for the problem «recover `lockSeed` given multiple `rank` observations under different nonces». But each `rank` observation is itself under-determined with multiplier `2^57.80` (even with granted plaintext and granted Part 2 stripping). Hypothetically:

- For each chunk in each message: `2^57.80` candidate ranks
- For a message with `M` chunks: `2^(57.80 · M)` full-message rank candidates
- Cross-message: even after fixing candidate ranks per chunk, the system's unknowns and observations correlate only through the correct-candidate choice — unknown a priori

This does not collapse via linear algebra because the correct candidate rank per chunk is unknown a priori. The attacker must brute-force enumerate `2^57.80 × M` candidates before CRC128 linearity kicks in. Enumeration explodes exponentially in `M`.

**Summary for the CRC128 fixed-`lockSeed` + variable-nonce attack model:**

- **Attacker-realistic (0/8 peek, shipped API):** structural wall at step 1 (demask fails). CRC128 linearity never engages, because there are no observations.
- **Lab-only maximum peek (Part 2 stripped by lab instrumentation):** structural wall at steps 3–4. Mask/rank per chunk is under-determined with multiplier `2^57.80`. CRC128 linearity is blocked by non-linear combinadic arithmetic. This is what REDTEAM.md Bitwuzla UNSAT under this posture records.

The preimage count `2^57.80` is not a «collectable through more messages» ambiguity — it is information-theoretic under-determination per chunk observation. More messages equal more independent instances of the same structural problem, not a more-determined single instance. That is the fundamental difference between a CRC128 KPA attack (linear system with constraints — more observations, more determined) and a Part 1 barrier attack (per-chunk unknown PRF-drawn mask — observations independent, ambiguity constant per chunk).

Exactly this aspect makes the barrier «structurally unmeasurable at attacker-realism» — not «cost too high» but «instance under-determined regardless of observation count».

---

## Question 3 — FNV-1a has the T-function property. Doesn't that break the barrier?

**Reader's setup.** «FNV-1a's round is `h = (h XOR byte) * FNV_PRIME`. Multiplication modulo `2^64` is not GF(2)-linear (carry chain), but it has the T-function property (Klimov & Shamir 2002) — output bit `t` depends only on input bits `0..t`, invertible plane-by-plane in `O(n^2)`. Under Single Ouroboros the archived Phase 2g SAT recovered `dataSeed` lo-lane in `~8h` single-core on 4 cribs + disclosed `startPixel` at `keyBits = 512`. Does that path carry into the shipped construction?»

### Current analytical picture

The reasoning tracks the CRC128 case, plus one primitive-specific arrow: **combinadic unrank appears to break T-function friendliness.** FNV-1a's T-function property gives the cryptanalyst a poly-time shortcut on direct hash inversion (given `h → seed`), but the analysis suggests there is no `h` to give — hash outputs appear to be consumed opaquely inside the pipeline before they reach the wire, and the pipeline component that would need inverting for the T-function shortcut to reach forward (combinadic unrank) appears to be neither GF(2)-linear nor T-function. The sections below trace each arrow.

### The T-function property, on paper

Multiplication by an odd constant modulo `2^64` is a T-function: carry propagates only LOW → HIGH, so output bit `t` is an affine function of input bits `0..t` with variable coefficients from the multiplier. This lets a solver work plane-by-plane from LSB to MSB via linear algebra on each bit plane, in `O(n^2)` instead of `2^n`.

Under Single Ouroboros, this is exactly what enabled the archived Phase 2g result: Bitwuzla with T-function-aware handling of the multiply recovered `dataSeed` lo-lane at ITB's minimum `keyBits = 512` on 4 cribs plus disclosed `startPixel`. The regime was Single Ouroboros, no Interlocked Barrier, disclosed `startPixel`, Crib KPA — a partial-lab posture that the current shipped surface does not expose.

### What happens when FNV-1a meets combinadic unrank in Part 1

The cascade is:

```
lockKey  = ChainHash(0x04 ‖ N_il, lockSeed)
prf_i    = H(0x03 ‖ ⟨i⟩, lockKey)
rank     = prf_i (128 bits)
(m0,m1,m2) = combinadic_unrank(rank)                 ← breaks T-function here
lane_N   = PEXT(chunk_48, m_N)                       ← 48 → 16 bit compression
wire     = Part_2_encode(lane_N, dataSeed, noiseSeed, startSeed, container)
```

FNV-1a's T-function property covers the first two operations (`ChainHash` and per-chunk hash). Unrank breaks T-function friendliness in three places at once:

**Break 1 — Two-step divmod.**
`idx_0 = ⌊rank / B⌋ mod A`, `idx_1 = rank mod B`, where `A = C(48, 16)` and `B = C(32, 16)`. Division by a non-power-of-2 constant, and modulo of a non-power-of-2, both involve carry propagation in both directions (multiply-by-reciprocal + shifts + subtract). Output bit `t` depends on input bits both above and below `t`. Not a T-function.

**Break 2 — Combinadic cell-selection loop.**
For each position `p ∈ [47, 46, ..., 0]`:

```
if rank >= C(p, k):
    include p
    rank -= C(p, k)
```

Data-dependent comparisons `>=` with variable-magnitude constants. Not a T-function, not GF(2)-linear, not even covered by AND-only polynomial methods.

**Break 3 — Non-adjacency in the bit-plane structure.**
Combinadic decomposition determines mask bit `t` based on the full magnitude of `rank`, not only bits `0..t`. Output bits of the mask triple are correlated across all bit positions of `rank` simultaneously — the exact opposite of T-function structure.

### The reverse direction, which is what the attacker actually needs

The attacker wants:

```
observation  →  mask_triple  →  prf_i (rank)  →  lockKey  →  lockSeed
```

Forward pipeline: `rank → unrank → mask_triple` (polynomially fast — that is what the encoder computes). Reverse: `mask_triple → rank` requires enumerating `C(48, 16) × C(32, 16) ≈ 2^70.20` preimages because unranks are many-to-one (`≈ 2^57.80` preimages per triple per [Proof 11](PROOFS.md#proof-11)). Even given a `mask_triple`, backward inversion of combinadic reduction is essentially guessing rank among `2^57.80` preimages — not amenable to any T-function shortcut.

But the most important point remains: **the attacker never observes `mask_triple` directly.** The mask is applied opaquely inside `chunk48lock` via PEXT to compress a plaintext chunk into 3 lane fragments. The attacker sees on wire only post-Part-2-encoded container bytes. To even start working backward to a mask triple:

1. Strip Part 2 (rotation + `channelXOR` + noise) — requires Part 2 demask, which requires KPA anchor.
2. Recover lane fragments from Part 2-stripped bytes.
3. Compute candidate mask triples from lane fragments + known plaintext chunks.

Each chunk observation gives `lane_N = PEXT(chunk, m_N)` — 16 output bits as a function of 48 input bits and mask `m_N`. Per [Proof 11](PROOFS.md#proof-11), at 48 known plaintext bits per chunk the preimage count per candidate mask triple is `≈ 2^57.80` — an under-determined system regardless of how many chunks accumulate (masks per chunk are independent PRF draws — no coupling).

### Summary

FNV-1a's T-function property protects the cryptanalyst under direct hash inversion, but:

- The attacker does not observe `h` — per-chunk PRF outputs are consumed opaquely inside unrank + PEXT
- The attacker cannot recover mask triples from wire observations — Part 2 encoding + Part 1 lane compression prevent it
- Combinadic unrank is non-linear over GF(2) **and** non-T-function — even a hypothetical T-function attack on the ChainHash cascade that recovered `lockKey` would still break at the unrank arithmetic reverse
- Compound-key linear algebra in the CRC128 style does not transfer to FNV-1a anyway (multiplication carry structure defeats it)

REDTEAM.md § FNV-1a lo-lane SAT records precisely this: Bitwuzla UNSAT under maximum-peek regime — even when the attacker gets a lab peek stripping Part 2 encoding, the full-coupled 8-chain SAT with symbolic mask triples is not formulable — not because the solver is too slow, but because the instance is under-determined without `lockSeed` under combinadic-unrank arithmetic that breaks the primitive's T-function / GF(2)-linear structure.

The only path FNV-1a's T-function still leaves open is a hypothetical case where the attacker gets `prf_i` observations directly, bypassing PEXT compression — which is architecturally impossible in the shipped construction.

So: FNV-1a is technically «total inversion in poly time per T-function» on the bare hash, but unrank arithmetic + Part 2 encoding + the observation gap make this structural shortcut inapplicable to shipped ITB. The tool exists; there is nowhere to apply it.

---

## Closing Note — Why Standard Decomposition Attacks Do Not Apply

The three questions above share a single architectural answer. A cryptanalyst reading REDTEAM.md's null recovery rows and asking «where is the leverage I would normally exploit» typically has one class of technique left: **meet-in-the-middle (MITM), also called divide-and-conquer or layer-peeling cryptanalysis.** The attacker tries to split the joint attack surface into two or more halves that meet at a known intermediate state. If each half is cheaper separately, MITM reduces complexity from `O(2^n)` to `O(2^(n/2))` or better. Classical breaker for composed ciphers.

ITB's «independent but interconnected» architecture blocks this class of attack at the design layer.

**Independence — 8-seed isolation ([Theorem 3](PROOFS.md#proof-3)).** For any `i ≠ j`, `I(seed_i; seed_j) = 0`. Cross-seed algebraic leverage is absent — if the attacker knows some bits of `noiseSeed` via CCA leak, this gives zero bits of information about `dataSeed / lockSeed / startSeed`. This blocks MITM «split by seed»: impossible to split the problem into «recover `noiseSeed` half» + «recover `dataSeed` half» at cheaper cost, because the halves do not share state space that MITM exploits.

**Interconnectedness — compositional forward pipeline.** Layers apply sequentially in the encoder:

```
plaintext
   ↓ Part 1 (chunk48lock under lockSeed)
lane_bits                                    ← never observable
   ↓ Part 2 (channelXOR + rotate + noise under dataSeed / noiseSeed / startSeed)
wire byte
```

On wire the attacker sees only the composed result. This blocks MITM «split by layer»: impossible to observe the intermediate state (lane fragments after Part 1 but before Part 2) separately — they are consumed opaquely inside the next stage.

### Classical MITM setup versus ITB

Classical MITM (e.g. for 2-DES):

```
plain →[K1]→ intermediate →[K2]→ cipher
```

Attacker guesses `K1`, computes forward to `intermediate`; guesses `K2`, computes backward from `cipher` to `intermediate`; matches guesses at the meeting point. `O(2^{2n}) → O(2^{n+1})`.

ITB pipeline:

```
plain →[lockSeed (Part 1 chunk48lock)]→ lane_bits →[dataSeed × noiseSeed × startSeed (Part 2)]→ wire byte
```

Two potential meeting points, both blocked:

- **Between Part 1 and Part 2 (`lane_bits`).** Attacker guesses `lockSeed` → forward-computes `lane_bits` from known plaintext; guesses `(dataSeed × noiseSeed × startSeed)` → backward-computes `lane_bits` from wire byte; matches. Blocked two ways: (a) backward from wire byte requires stripping Part 2 — 56 candidates per pixel equiprobable per [Proof 1](PROOFS.md#proof-1), backward step under-determined without anchor, so the attacker's «backward guess» produces 56 candidate lane fragments per pixel, none verifiable; (b) forward from plaintext through `lockSeed` applies `chunk48lock` per-chunk fresh PRF-keyed mask triple — `≈ 2^70.20` possible masks under the PRF assumption, and per-chunk mask uncertainty from `≈ 2^57.80` preimages per rank, so the attacker gets `2^(57.80 · C)` candidate lane sequences per `lockSeed` guess for `C` chunks.
- **Between PRF chain and unrank (`rank_i` values).** Attacker guesses `lockSeed` → forward via cascade PRF chain → ranks; observes hypothetical rank → backward via combinadic unrank → mask triples → compares with observations. Blocked: mask triples are never observed directly (applied opaquely via PEXT). Forward step gives ranks trivially; backward step from observations to ranks via inverse unrank requires enumerating `≈ 2^57.80` candidates per chunk with no verification anchor.

### Other decomposition attempts

Every standard «peel one layer while holding others» technique the analysis surveyed encounters the same underlying obstacle. The list below is a walkthrough, not a completeness claim over the attack space — a novel technique or a novel composition of the ones tabulated is not on the table by definition; each row states the specific assumption a known technique makes that the shipped architecture removes:

| Technique | What it needs | Why it fails on ITB |
|---|---|---|
| Slide attack | Repeating structure across rounds | ChainHash rounds are independent per component ([Theorem 3b](PROOFS.md#proof-3b)) — no slide equivalence |
| Related-key attack | Algebraic relation between keys | 8 CSPRNG-drawn seeds enforced pairwise-distinct at API — no relation |
| Boomerang | Composable differential paths through intermediate state | No observable intermediate state in the barrier |
| Integral / square | Balanced property preserved across rounds | Random container destroys balance |
| Linear cryptanalysis | Linear approximation input ↔ output | Part 2 absorbs primitive output through CSPRNG noise; per-chunk mask permutation removes fixed bit-position anchor |

Every standard tool assumes exactly one thing (fixed anchor, observation channel, exploitable primitive weakness, table-lookup side channel). The construction removes that thing at its specific layer while remaining layers work independently. A cryptanalyst attempting a standard workflow encounters: «my tool requires X; this layer removes X. Next layer removes Y, which I also need. Third layer removes Z.»

Not defense-in-depth in the sense of «stacking redundant walls» — because each wall protects against a structurally different attack class. They cannot be defeated by a single algebraic breakthrough, because they are not related layers in one algebra — they are orthogonal channels closed by independent seeds under disjoint domain tags through independent hash chains.

Architecturally, three properties compose:

1. **Layers keyed by independent seeds** — no cross-layer algebraic bridge
2. **Layers composed such that only the final composition is observable** — no intermediate leak
3. **Per-composition fresh PRF draws** — barrier mask per-chunk, `dataSeed` hash per-pixel; cross-observation constraints do not accumulate

[Proof 4a](PROOFS.md#proof-4a) codifies this in one sentence:

> «The obstacles are not sub-problems defeated sequentially but interlocking constraints.»

The word «interlocking» is a precise pointer to MITM-block. Sub-problems defeated sequentially = classical decomposition. Interlocking constraints = the attacker must simultaneously breach all obstacles in the same attempt, because none can be «peeled» to reveal another's intermediate state.

### Honest positioning of the residual risk

The construction has one exit that all of the above does not close: **total PRF inversion of a shipped primitive** — an assumption breach on primitive strength, not a decomposition attack. Historically this has never happened to a modern well-designed PRF in the open literature (MD5 collisions ≠ preimage inversion; SHA-1 same; DES key exhaustion ≠ inversion; A5/1 and RC4 are stream ciphers of specific design; reduced-round breaks are not full-round breaks). Should it ever happen to a specific shipped primitive, ITB mitigates via the shipped-primitive registry + custom primitive plug: the caller switches to another primitive via `hashes.Register + triple.RegisterProfile` without changing the construction. No single-point-of-failure.

Everything else is on the table. All theorems have formal derivations in PROOFS.md; all empirical measurements have reproducible harnesses in REDTEAM.md; all code is public. A cryptanalyst's reaction is more likely «this is architecturally different from anything I have analyzed» than «this hides something». Which is exactly the posture required for paper-oriented review.
