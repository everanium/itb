## ITB Broken Primitives Walkthrough

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB composes established, standardized primitives rather than introducing new cryptographic designs. Security properties and regulatory status are inherited from the underlying primitives; see [README.md](README.md) for jurisdictional certification details.

This document provides an analytical walkthrough companion to [REDTEAM.md](REDTEAM.md), [SCIENCE.md](SCIENCE.md), and [PROOFS.md](PROOFS.md). It traces primitive-weakness absorption across a spectrum of broken primitives — from degenerate controls (`nullHash`, `quadHash`, `trainHash`, `jokeHash`) to GF(2)-linear CRC128 and T-function FNV-1a — mapping the boundary between primitive weakness on paper and wire observability in the shipped construction, and identifying the lab-only privileges required for theoretical attack vectors to engage.

**Framing.** This document details the architectural reasoning that produces the null-recovery observations recorded in [REDTEAM.md](REDTEAM.md). It is an analytical specification of current architectural boundaries, not a formal security proof or guarantee. Six questions, six primitives, one shared architectural pattern.

---

## Question 1 — What if the primitive is even more degenerate than `trainHash` and `jokeHash`?

**Reader's setup.** «Suppose a two-line primitive weaker than `jokeHash` is evaluated — one reading only `data[0]` and the low byte of each seed word, discarding everything else. Under the shipped Triple Ouroboros + Interlocked Barrier construction, does the barrier fail?»

```
nullHash(data, seed0, seed1):
    d = data[0] if len(data) > 0 else 0
    return (d ^ (seed0 & 0xFF), d ^ (seed1 & 0xFF))
```

### Current analytical picture

`nullHash` violates the barrier's entropy-floor reduction target. Under `Seed128.ChainHash128`'s four-round cascade at 512-bit key, the `data[0]` byte cancels on every even-numbered round because the XOR-carry between the previous-round state (only the low byte carries information under `nullHash`) and the next-round data byte collapses. Final `(hLo, hHi)` degenerates to a pure per-seed 16-bit constant — independent of pixel index and independent of nonce content. Every per-pixel encoder decision becomes a static function of five collapsed 16-bit constants, identical across every pixel of every message.

### Empirical measurement across four attacker threat-model tiers

Attack code: `redteam_nullhash_attack_test.go`, Go build tag `redteam`. Measured on i7-11700K, 512-byte plaintext, 25×25 = 625-pixel container, one victim-freshly-generated ciphertext per tier.

| Threat model | Wall-clock | Recovery |
|---|---|---|
| Full KPA + startPixels given | ~285 ms | unique |
| Crib KPA (48 bytes) + startPixels given | ~315 ms | unique |
| Crib KPA (48 bytes) + startPixels brute (208³ enumeration) | ~1.25 s | unique |
| COA (2 wires) + content-agnostic COBS gate | ~2.9 s | ~256 candidates, all decrypting to the true plaintext |

Under any Full or Crib KPA the recovery is unique. The 48-byte crib alone gives a 128-bit lane-prefix anchor (8 six-byte Rank Barrier chunks, each with a lockSeed-derived mask) that massively over-constrains the 16-bit collapsed lock. Enumerating the startPixel cube adds only ~4× in wall-clock and does not break uniqueness — the lane-prefix anchor remains decisive.

Under pure ciphertext-only attack the low byte of `lockSeed` remains unresolved, but the residue is a functional don't-care rather than confidentiality. The attack recovers `noisePos`, all three `startPixels`, all three `dataSeed` low bytes and the HIGH byte of `lockSeed`; ~256 candidate `lockSeed` low bytes stay admissible, and **all of them decrypt to the same plaintext** — the true one. Measured directly: across all 65 536 lock constants the Rank Barrier produces exactly one distinct lane per region, so the mask is a universal constant under `nullHash`, independent of both `lockSeed` and the interlock nonce. The enumeration therefore extracts zero bits about the lock, and content-agnostic COA is a complete break rather than a one-in-256 choice. No content-oracle is needed to finish it.

### Reproduction

```
go test -tags redteam -run TestRedTeamNullHashAttack ./ -v -count=1
```

Default output directory is `$HOME/scratch/redteam/nullhash/` per the shared red-team probe layout; override via `REDTEAM_NULLHASH_OUTPUT_DIR`. Per-stage entry points: `TestRedTeamNullHashAttack` (Full KPA), `TestRedTeamNullHashAttackCrib` (Crib + startPixels given), `TestRedTeamNullHashAttackCribNoStartPixels` (Crib + startPixels brute), `TestRedTeamNullHashAttackNoKPA` (ciphertext-only, 2 wires). Each attack test regenerates its own expose files at start, so ordering under `go test -tags redteam ./` is irrelevant.

### Conclusion

`nullHash` violates the entropy-floor reduction target: the barrier absorbs a primitive's algebraic weakness (T-function structure, GF(2)-linearity, poor multiplier diffusion) **when the primitive's cascade output does not collapse to a per-seed constant**. Once the primitive collapses, the barrier's per-chunk mask independence collapses with it and the attack surface reduces to the observable-bit budget on the wire (~42 bits out of 80 nominal for the shipped constellation), which is trivially brute-forceable under any KPA. The collapse is total at this floor: the surviving ~8 bits of `lockSeed` low byte are a functional don't-care, every value decrypting to the same true plaintext, so the barrier contributes nothing measurable once the primitive's cascade output degenerates to a constant. That is the point of the entropy floor — below it the barrier has nothing left to absorb.

The `nullHash` attack path is structurally closed under stronger primitives whose cascade output stays per-pixel varying and whose per-round iteration preserves entropy relative to initial state (bijective per-iteration). See [Question 1a](#question-1a--what-if-the-primitive-is-quadhash-a-squaring-t-function) below for a parallel collapse mechanism — non-bijective iteration `x²` induces an attractor-collapse variant of `nullHash`'s linear identity collapse — and [Question 2](#question-2--what-if-the-primitive-is-trainhash-an-8-bit-per-lane-multiply-add) / [Question 3](#question-3--what-if-a-three-line-jokehash-is-evaluated) for the bijective non-collapsing cases (`trainHash` at 8-bit-per-lane, `jokeHash` at 64-bit-per-lane).

---

## Question 1a — What if the primitive is `quadHash`, a squaring T-function?

**Reader's setup.** «`nullHash` collapses via linear XOR⁴ = identity into a per-seed constant. What if a non-linear squaring fold is evaluated — same 8-bit-per-lane width as `trainHash`, T-function class, but non-bijective per iteration because `x² mod 256` has collisions on `±x`? Two-lane squaring:

```
quadHash(data, seed0, seed1):
    lo = seed0 & 0xFF
    hi = seed1 & 0xFF
    for b in data:
        lo = ((lo + b) * (lo + b))          & 0xFF   # x²
        hi = ((hi + b) * (hi + b) + 1)      & 0xFF   # x² + 1
    return (lo, hi)
```

`x²` is T-function (bit t depends only on bits ≤ t of input), so recovery is polynomial per bit-plane. `x² mod 256` produces only ~44 unique output values from a 256-value domain, versus `trainHash`'s bijective 256 values — one iteration loses ~2.5 bits of entropy on average. Repeated iteration converges to an attractor set (fixed points at `l = 0` and `l = 1`, orbits of length ≤ 8 elsewhere). Does this cascade attractor collapse open the wire the way `nullHash`'s linear collapse does?»

### Current analytical picture

`quadHash`'s cascade collapses through a **buffer-length-dependent attractor mechanism** distinct from `nullHash`'s linear XOR cancellation. Under a 13-byte Rank Barrier chunk buffer `[0x03 | LE64(groupIdx) | 4×0]`, 13 non-bijective iterations of `l = (l + b)² & 0xFF` drive the state fully into the attractor set — `Components[1..7]` effect on cascade output vanishes into the attractor, and the mask triples become effectively a function of the buffer alone. Under the shorter 4-byte Pixel Barrier per-pixel buffer `[LE32(pixel_idx)]`, only 4 iterations run — the attractor is partially reached and `Components[0]` still dominates per-pixel `(rotation, noisePos)` derivation. Both stages give the attacker a foothold: mask triples via `Components[1..7] = 0` synthetic seed, `Components[0]` via a 256-brute per seed under Full KPA byte-match feedback.

### Empirical measurement

Attack code: `redteam_quadhash_leak_test.go`, `TestRedTeamQuadHashLeak7of8` and `TestRedTeamQuadHashFullAttack` (Go build tag `redteam`). Measured on i7-11700K, 512-byte plaintext, 25×25 = 625-pixel container.

| Threat model | Wall-clock | Recovery |
|---|---|---|
| Full KPA + startPixels (via synthetic-seed cascade collapse — no lab peek needed) | ~660 ms, 3984 Decrypt trials | **512 / 512 bytes bit-exact** |
| Step 1 leak measurement (7-of-8 unmask, under lab lockSeed peek for debug) | ~10 ms | 74 / 75 pixels unique |
| Step 2 mask triple recovery (2¹⁶ lockSeed enumeration, no lockSeed peek) | ~3.5 s | **75 / 75 match at synthetic `Components 0` candidates** — Interlock cascade broken |

**Sequential brute converges in 2 greedy passes.** Baseline (`Components[0] = 1..8`, `Components[1..7] = 0`, distinct-to-satisfy-8-seed-isolation): 0 / 512 byte match. Pass 1 (per-slot 256-brute maximising byte-match): 17 / 512 (3.32%). Pass 2: **512 / 512 bit-exact recovery**. Recovered synthetic `Components[0]` per seed: `[3, 2, 7, 4, 0, 5, 12, 1]`, `Components[1..7] = 0` for all 8 slots. Shipped `Decrypt3x128Cfg` with the recovered synthetic constellation reproduces plaintext byte-identical.

### Mechanism — attractor collapse ≠ linear collapse

`nullHash`'s cascade collapses because `nullHash⁴(s, d) = s ⊕ d ⊕ d ⊕ d ⊕ d = s` — the data term algebraically cancels, and ChainHash output degenerates to a per-seed constant independent of buffer. `quadHash`'s cascade collapses because `x² mod 256` is many-to-one — repeated iteration loses entropy relative to initial state, and after enough rounds the state converges to a buffer-only function independent of `Components[1..7]`. The two mechanisms compose the same architectural break — mask triples become predictable — through opposite algebraic properties (`nullHash` cancels the data term keeping the seed term; `quadHash` cancels the seed term keeping the data term).

The **buffer-length asymmetry** between Rank Barrier (13 bytes → full attractor) and Pixel Barrier (4 bytes → partial attractor) is what makes `quadHash` slightly less trivial than `nullHash`: attacker needs 256 sequential brutes per non-lockSeed slot for the residual `Components[0]` dependence, versus `nullHash`'s direct recovery. Both attacks resolve in under a second on commodity hardware.

### Reproduction

```
go test -tags redteam -run TestRedTeamQuadHashLeak7of8 ./ -v -count=1
go test -tags redteam -run TestRedTeamQuadHashFullAttack ./ -v -count=1
```

Default output directory is `$HOME/scratch/redteam/quadhash_leak/`. The two tests run independently — `Leak7of8` characterises Interlock cascade collapse via 2¹⁶ candidate matching; `FullAttack` demonstrates end-to-end plaintext recovery via sequential `Components[0]` brute across 8 seed slots.

### Conclusion

`quadHash` — a squaring T-function — sits alongside `nullHash` as a **cascade-collapsing primitive** that breaks ITB architecturally, through the non-bijective attractor variant of `nullHash`'s linear identity collapse. Any primitive whose per-round iteration loses entropy relative to initial state (non-bijective under fixed data byte) is disqualified for the same architectural reason: the barrier's per-pixel and per-chunk decisions become predictable from buffer content alone, regardless of `Components` state.

The distinction between the cascade-collapsing family (`nullHash`, `quadHash`) and the bijective non-collapsing family (`trainHash`, `jokeHash`, all shipped registry primitives) is the load-bearing invariant. See [Question 2](#question-2--what-if-the-primitive-is-trainhash-an-8-bit-per-lane-multiply-add) for the same attack path under `trainHash` (8-bit-per-lane bijective multiply-add), where the per-round `× 3` bijection over 256 prevents the attractor collapse that the sequential brute exploits here. That bijection is why the cascade does not degenerate to a constant; it does not follow that the cascade carries its declared key width, and under a Crib KPA `trainHash`'s Interlocked Barrier falls to a different attack entirely.

---

## Question 2 — What if the primitive is `trainHash`, an 8-bit-per-lane multiply-add?

**Reader's setup.** «`nullHash` collapses via XOR⁴ = identity into a per-seed 16-bit constant. `jokeHash` retains full 64-bit accumulated state per invocation. What sits between them — an 8-bit-per-lane multiply-add fold that DOES vary the output per pixel but keeps the cascade output narrow enough that Interlock's mask-triple derivation might be tractable? Two independent 8-bit lanes:

```
trainHash(data, seed0, seed1):
    lo = seed0 & 0xFF
    hi = seed1 & 0xFF
    for b in data:
        lo = ((lo + b) * 3 + 1) & 0xFF
        hi = ((hi + b) * 5 + 7) & 0xFF
    return (lo, hi)
```

Non-cancelling multiply-add per lane, so the `nullHash` XOR-cancellation collapse is absent — per-pixel output varies. But 8-bit output width per lane collapses the `splitRank48(prf_lo, prf_hi)` divmod input to 2¹⁶ effective states across all chunks, versus the full C(48,16) × C(32,16) ≈ 2⁷⁰·² mask-triple space at 128-bit hash width. An attacker enumerating 2¹⁶ candidate `(lo, hi)` byte pairs takes under 10 seconds on i7-11700K. Does the 16-bit rank-space collapse empirically break the wire?»

### What the measurement shows

**The Rank Barrier does not hold under a 48-byte Crib KPA.** The 8-bit lane width bounds the cascade's own key material: `trainHash` reduces each seed word to `seed & 0xFF` and carries no more than 8 bits of state per lane, so of the keying list `lockComps` — the `deriveInterLockSeed` pair followed by `Components` — only five bytes per lane reach the output. A meet-in-the-middle over those five, anchored on the lane prefix the crib pins, recovers the rank schedule for every chunk in about a second, with no seed, no `Components`, no interlock nonce and no `startPixel` entering the derivation. Start pixels are recovered rather than granted.

The asymmetric fill design — primer round over `deriveInterLockSeed` output, then component rounds — does not close this path: an 8-bit-per-lane primitive never lets the cascade carry the key material the design assumes. The 2¹⁶ synthetic candidate space (`Components[2..7] = 0`) misses for the same reason, varying two of the five effective bytes and holding three at zero — a failure of parameterisation, not of hardness.

Two consequences. The per-chunk rank space is **2¹⁶, not the construction's 2⁷⁰·²⁰**, and the unrank maps those reachable ranks injectively onto distinct mask triples, so the preimage ambiguity a primitive filling the space would impose does not apply — measured median 8, maximum 256. And the **interlock nonce is not on the critical path**: the attack steps over its lane fragment by the public length `nonceSplit` derives, never recovering it, because the nonce's whole influence is the 16-bit derived pair the meet-in-the-middle already absorbs.

**The Pixel Barrier is what holds.** The value that stays out of reach is the per-region effective `dataSeed` key — four bytes under `trainHash`. The crib yields two fully readable pixels per region, pinning 16 bits against 32; the rest narrows only under a plaintext model, and the mechanism there is per-pixel ambiguity rather than any hardness in the noise bit. Eight noise positions by seven rotations give **56 internally consistent readings of every pixel**, and picking the right one needs something to check against: under Full KPA that is the plaintext, and the noise bit costs nothing; under Crib KPA it costs nothing up to the crib's edge and everything past it, where the only verifier left is the model. That is why the walk halts with several configurations still admissible rather than running out of candidates.

`noiseSeed` is not a second wall beside `dataSeed`: its whole per-pixel output is `noisePos`, three bits, against the 59 `dataSeed` supplies to the same pixel. An attacker never targets it — the walk needs the position, and one of eight is enumerated rather than derived; deriving it would mean inverting a PRF through a three-bit-per-pixel channel observable only once the data bits are already known.

The leak that makes lane bytes observable at all (channels 1..7 receive `channelXOR = 0`, since the 5-bit xorMask fits entirely in channel 0's shift-slot) follows from the same arithmetic: 8 bits supplied where `DataConfigBits` consumes 59. That and the rank-space collapse are both the primitive **starving** the barriers, not an attacker defeating them.

### Empirical measurement

Attack code: `redteam_trainhash_leak_test.go`, `TestRedTeamTrainHashLeak7of8` (Go build tag `redteam`). Measured on i7-11700K, same 512-byte plaintext / 25×25 = 625-pixel container as Question 1 for direct comparability.

| Step | Threat model | Wall-clock | Recovery |
|---|---|---|---|
| **Step 1** — 7-of-8 unmask leak measurement | Full KPA + startPixels given + `lockSeed` peek (debug hint only) | ~10 ms | 74 / 75 pixels unique `(rotation, noisePos)` |
| **Step 2** — 2¹⁶ `lockSeed` enumeration | Full KPA + startPixels given, no `lockSeed` peek | ~5 s | **0 / 75 match at any candidate, including at the real `(lo, hi)`** |

**Step 1** reverse-rotates against expected COBS-encoded lane bytes and pins per-pixel `(rotation, noisePos)` uniquely on 74 of 75 pixels — 98.67 %; the one ambiguity is a collision where two hypotheses both pass the 7-channel match. **Step 2** repeats that measurement for each `lockSeed` synthesised via `trainHashSeedConst(lo, hi)` and matches no pixel at any candidate, the real `(lo, hi)` pair included — the synthetic parameterisation described above.

### Reproduction

```
go test -tags redteam -run TestRedTeamTrainHashLeak7of8 ./ -v -count=1
```

Output goes to `$HOME/scratch/redteam/trainhash_leak/`; the test emits a fresh victim (`ct.bin` + `kpa.bin` + `cell.meta.json`) and runs both steps in sequence.

The Crib KPA experiment is separate. Its six entry points differ only in plaintext distribution, message length and model — the attack is identical across them:

```
go test -tags redteam -run TestRedTeamTrainHashCribKPAAscii       ./ -v -count=1
go test -tags redteam -run TestRedTeamTrainHashCribKPABinary      ./ -v -count=1
go test -tags redteam -run TestRedTeamTrainHashCribKPAJson512Plain ./ -v -count=1
go test -tags redteam -run TestRedTeamTrainHashCribKPAJson512Class ./ -v -count=1
go test -tags redteam -run TestRedTeamTrainHashCribKPAJson4kPlain  ./ -v -count=1
go test -tags redteam -run TestRedTeamTrainHashCribKPAJson4kClass  ./ -v -count=1
```

`Ascii` is uniform printable characters over a 69-character alphabet; `Binary` is uniform random bytes with no model; the `Json512` and `Json4k` pairs hold corpus and length fixed and vary only the model. Output goes to `$HOME/scratch/redteam/trainhash_cribkpa_<corpus>/`.

Stages 1 and 2 behave identically across all six; only the Stage 3 walk differs. A run can legitimately stop at Stage 1 or Stage 2 without recovering anything — a `0x00` inside the crib-anchored barrier prefix puts a COBS code byte where a lane byte is expected, and the cross-region join then finds no common rank. That path logs `attack stops here` and is not a failure.

### Conclusion

How much plaintext comes out past the crib is a property of the model, not of the ciphertext, and three measurements separate the variables. With **no model** — uniform random binary — nothing is recovered: the walk does not advance past the crib at all, and the few correct bytes beyond its edge are the crib bleeding into the chunk it partially covers. With a **byte-wise printable model**, corpus structure alone changes nothing: structured JSON yields a lower median than uniform printable ASCII, because repeated keys and syntax are invisible to a model that scores one byte at a time against a chunk-independent test. What moves the number is the model's **resolving power** — narrowing the licensed alphabet from 95 characters to 75, `+0.34` bits per byte, shifts the median recovery about sevenfold on the same corpus, with the best single run reaching just over four fifths of the unknown region.

A recovery percentage quoted without its plaintext model and its message length carries no information. The distribution is heavy-tailed rather than a plateau — roughly `4%` to `82%` across runs on one corpus and model, according to whether the per-region schedule classes collapse to a single candidate — and it falls by nearly an order of magnitude at eight times the plaintext size, because what comes out is approximately a fixed-length prefix rather than a share of the message.

**Mechanical reach is not information gained**, which cuts against the highest figure: the structured corpus is fully determined by its own format, so the run reaching four fifths recovered content anyone holding that format could write out without the ciphertext at all. A real document sits between the two corpora — an alphabet as narrow as the structured one, content as unpredictable as the uniform one — and where that lands has not been measured.

**The solver question stays open and differs sharply by threat model.** `trainHash`'s combined criterion failures — narrow 8-bit lane output, 2¹⁶ rank-space collapse, T-function class — create a theoretically SAT-attackable surface. Under a 48-byte Crib KPA the Rank Barrier's share of it is closed by direct measurement rather than by a solver, and what remains is the Pixel Barrier: no dedicated SAT / algebraic solver has been run against `trainHash`'s per-region `dataSeed` classes, so whether they break under one is **untested**, not proven closed. Under pure ciphertext-only attack nothing here has been measured at all — the meet-in-the-middle depends on the crib for its anchor, so without one the Rank Barrier is not shown to fall either, and a solver would face both barriers jointly. That is a strictly larger open question which does not inherit the Crib KPA result. Every shipped primitive breaks at least one criterion of this combination (a lo lane populated across all 59 `DataConfigBits` closes 7-of-8, a live 128-bit `(lo, hi)` pair closes 2¹⁶, AES-family / ARX cascades close the T-function bit-plane path), so the untested question does not shift the shipped-security envelope — but it is genuinely open about the primitive, not closed.

---

## Question 3 — What if a three-line `jokeHash` is evaluated?

**Reader's setup.** «Suppose all eight ITB seed roles are configured with a three-line primitive — initializing the accumulator from `seed0`, mixing each data byte via a small odd multiplier plus add, complementing for the second lane:

```
jokeHash(data, seed0, seed1):
    lo = seed0
    for b in data: lo = lo*257 + b
    return (lo, ~lo)
```

T-function class (Klimov and Shamir 2002): output bit t depends only on input bits at position ≤ t, so recovery is polynomial per bit-plane. Trivially invertible for any single `(data, seed)` observation pair, catastrophically weak by any cryptographic standard — no round mixing, no diffusion, below spec compared with CRC128 or FNV-1a on the observation-channel-required stress axis. If registered via `hashes.Register` as a custom primitive and used to encrypt messages, is the wire compromised?»

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
- `lockSeed`: Stage 1 intermediate key `K = deriveInterLockSeed(N_il)` under tag `0x04`; Stage 2 hot-loop cascade over `[0x03 ‖ LE64(groupIdx) ‖ 4×0x00]` under `lockComps = [K, session components...]` with Round 1 primer on `K` and session feedforward → 128-bit `rank` → combinadic unrank → mask triple → applied via BMI2 `PEXTQ` inside `chunk48lock` → 3 lane fragments → Pixel Barrier encoding

A wire byte at position `(p, ch)` has the shape:

```
wire[p, ch] = insert( rotate( lane_bits ⊕ channelXOR, r ),  C[p, ch],  noisePos )
```

where `lane_bits`, `r`, `channelXOR`, `noisePos` are all derived from hash outputs — but the hash output itself never appears. Every observable is a composition. Every composition mixes a PRF-derived quantity with an independent DRBG-derived quantity (`C[p, ch]`, the random container) via Pixel Barrier absorption.

**The demasker gate.** To extract even one hash output the attacker must «demask» — strip Pixel Barrier encoding. Demasker fundamentally requires a Full KPA anchor to choose among 56 candidates per pixel. Without an anchor, [Proof 1](PROOFS.md#proof-1-information-theoretic-barrier) says all 56 are equiprobable, and the algorithm does not converge to a decisive answer.

In an unshielded single-region pipeline without the Rank Barrier, a Crib KPA anchor permits demasking. In the shipped construction (**Triple Ouroboros + Interlocked Barrier + dual-nonce**), the demasker fails empirically per [REDTEAM.md](REDTEAM.md), even under lab-forced Scenario A on FNV-1a on every seed role, because three unknown-offset region streams plus Rank Barrier lane scrambling give the demasker nothing to anchor on.

So the attacker holding a shipped ciphertext, running `jokeHash` in an arbitrary seed role:

- Cannot demask the Pixel Barrier → **no observations of hash outputs** → `jokeHash` invertibility has nothing to invert
- Cannot observe mask triples → the Rank Barrier remains opaque → combinadic unrank is uninformative even at a `jokeHash`-driven `lockSeed`, because a `rank` value never becomes visible
- Cannot exploit `jokeHash` bias for plaintext-content recovery → Pixel Barrier absorption gives `P(v | h) = 1/2` **per pixel** regardless of primitive bias, so no wire byte is ever anchored to a specific plaintext bit (a weaker aggregate-statistics residue — a plaintext-Hamming-weight distinguisher visible under repeat-plaintext CPA when the primitive's output distribution itself carries measurable bias — does surface for the popcount-2 `jokeHash` multiplier specifically; see [§ Residual bias under repeat-plaintext CPA](#residual-bias-under-repeat-plaintext-cpa) below, and note that it does not enable plaintext-content recovery)

### The lab-only scenarios where `jokeHash` bites

Both scenarios are unreachable through the shipped API and require adversary capabilities that the shipped surface does not grant:

1. **7/8 seeds granted via lab peek.** Grant the attacker seven of the eight seeds through instrumentation. Pixel Barrier encoding collapses (all its keying material is known). The attacker now sees clean per-chunk PRF observations, inverts `jokeHash` plane-by-plane in polynomial time per T-function, recovers `lockKey`, decodes mask triples, and reads plaintext. The takeaway is not «`jokeHash` broke ITB» but «once the barrier has been surgically stripped in the lab, whatever remains is `jokeHash`-level trivial to reverse». The shipped API does not expose seven-seed material.

2. **Novel observation channel that exposes hash outputs directly.** A side channel that leaks primitive output bypassing PEXT / mask apply — cache timing on a software AES kernel without AES-NI is the classic example. The register-only ITB kernels (with mandatory hardware AES / GFNI / VAES paths for AES-family primitives) do not create this observation surface. `jokeHash` bias would help if the surface existed; the shipped construction denies the surface.

### Role of CRC128 and FNV-1a as Stress Controls

CRC128 and FNV-1a serve as bounding controls on specific algebraic vulnerability axes:

- **CRC128:** Upper bound on GF(2)-linear exploitability. Total inversion is achievable in O(n³) via Gaussian elimination on paper.
- **FNV-1a:** Upper bound on T-function exploitability. Invertible plane-by-plane in O(n²) via triangular carry propagation.

Demonstrating null recovery under both algebraic bounds establishes closure: PRF-grade primitives with non-linear diffusion inherit at least equivalent resistance a fortiori. Furthermore, both primitives exhibit uniform output distributions (|z| < 3 across 152M bits), verifying that bias absorption operates cleanly. In contrast, jokeHash is a pathological stress control (popcount-2 multiplier, `0x101`) specifically included to measure output-bias leakage when diffusion is completely absent.

### General principle the `jokeHash` thought experiment illustrates

The primitive-strength assumption in [Proof 4a Asymmetry note](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance) is load-bearing only in the case where the attacker has an observation channel on hash outputs. The barrier's job is to remove that observation channel independently of primitive strength. Under attacker-realism the observation channel is closed structurally. Primitive strength then matters only for partial-inversion scenarios where a fragment of output leaks — and even there the multi-factor defense (see the closing note below) demands simultaneous breach of every factor.

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

### Empirical reduction-closure verification

Attack code: `redteam_jokehash_fullkpa_test.go`, `TestRedTeamJokeHashFullKPA` (Go build tag `redteam`). Measured on i7-11700K, same 512-byte plaintext / 25×25 container as Question 1 for direct comparability.

| Threat model | Wall-clock | Recovery |
|---|---|---|
| Full KPA + startPixels given | ~40 ms (reduction-closure analysis) | attack does not converge — every path closed |
| Crib KPA (48 bytes) + startPixels given / brute | not run | pointless — Full KPA already gives no Pixel Barrier foothold |
| COA (2 wires) | not run | pointless — same reasoning |

Empirical result under Full KPA: the four reduction paths the `nullHash` Stage 1 attack ([Question 1](#question-1--what-if-the-primitive-is-even-more-degenerate-than-trainhash-and-jokehash)) exploited are all structurally closed under `jokeHash`. This is **measured absence of the specific reductions the `nullHash` attack used**, not a proven work factor — the same document empirically records `jokeHash`'s poorly-diffused-primitive residual (a plaintext-HW distinguisher under repeat-plaintext CPA, [§ Residual bias under repeat-plaintext CPA](#residual-bias-under-repeat-plaintext-cpa)), so any «~2^X safety» framing would contradict that residue. `TestRedTeamJokeHashFullKPA` empirically confirms four independent reduction paths are all closed under `jokeHash`:

| Reduction path | `nullHash` (cascade collapses) | `jokeHash` (cascade non-collapsing) |
|---|---|---|
| Effective key bits per seed role | 16 (per-seed constant) | 256 (four even components fully engaged) |
| Distinct hash outputs across N = 1000 pixels | 1 (identical every pixel) | 1000 / 1000 |
| Distinct mask triples across 86 chunks | 1 (message-wide constant) | 86 / 86 |
| Pixel Barrier known-plaintext under plaintext-level Full KPA | given (all encoder decisions constant) | closed (locked lanes require unrank via 256-bit lockSeed) |

All four paths closed simultaneously. The attack does not converge because every reduction step the `nullHash` Stage 1 attack (~285 ms unique recovery) exploited is empirically demonstrated closed here.

**Reproduction:**

```
go test -tags redteam -run TestRedTeamJokeHashFullKPA ./ -v -count=1
```

---

## Question 4 — CRC128 is GF(2)-linear: does compound-key linear algebra break ITB?

**Reader's setup.** «CRC128 admits full total inversion in polynomial time — one Gaussian elimination on a GF(2) system. The public script `scripts/redteam/itb/theory/crc128/compound_key_crc128.py` recovers a compound key `K` without any Crib KPA on Single Ouroboros. Why does that path not carry into the shipped construction?»

### Current analytical picture

Analytically, three shipped-construction factors — **Triple Ouroboros**, the **always-on Interlocked Barrier**, and **dual-nonce separation** — each appear to invalidate one of the assumptions the compound-key linear-algebra recovery relies on, so the attack path that works cleanly against Single Ouroboros does not seem to carry over. Beyond that, the hypothetical transfer of the recovered `K` from the Pixel Barrier to the Rank Barrier runs into five orthogonal architectural reasons at the algebra layer, before any observation gap is even considered. The sections below trace each reasoning arrow; countering any of them would supersede the corresponding step in the analysis.

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

**1. Triple Ouroboros — three regions with independent `startPixel`s.**

Compound-key recovery assumes the pixel-to-observation-position mapping is known (or brute-forceable via period shift). Under Triple, the attacker sees a container with interleaved 3-region payload where the region boundaries are not visible on wire. The attacker does not know which observation belongs to which region without joint enumeration of three independent `startPixel` candidates — three independent compound-key recovery instances with unknown routing between them.

**2. Interlocked Barrier's Rank Barrier — per-chunk PRF-keyed permutation.**

Even if the routing were solved hypothetically, the data in each region is no longer a direct projection of plaintext bytes to channels. Between the plaintext and the per-pixel encoder sits `chunk48lock`, which via BMI2 `PEXTQ` under a mask triple `(m_0, m_1, m_2)` — drawn from `Ω_chunk ≈ 2^70.20` space keyed by `lockSeed` + fresh `interlock nonce` — redistributes the bits into three 16-bit lane fragments per 48-bit chunk in ~3 cycles in constant time. The attacker's `channelXOR(p, ch)` recovery under CRC128 would yield an XOR mask on channel bytes, but those channel bytes now carry PRF-permuted lane fragments, not plaintext bytes directly. The linear system recovers `K` → predicts `channelXOR` → recovers not plaintext, but `PEXT(chunk, m_N)` bits under an unknown mask. To go further requires `lockSeed → mask triple`, which is PRF-opaque under fresh `interlock nonce`.

**3. Dual-nonce separation.**

Compound-key recovery is pinned to a specific `(dataSeed, main_nonce)` pair. Fresh `main_nonce` → fresh `K` per message. `main_nonce` reuse is possible only through a test-only override, not the shipped API. Even under a lab-forced Scenario B (main-only collision), `K` is identical on the colliding pair, but the barrier's lane assignment depends on `interlock nonce`, which is fresh → the attacker gets same `K`, same `channelXOR`, but different lane assignments → channel bytes now map to unknown 48-bit chunk positions.

Honest phrasing of the verdict: the CRC128 linear-algebra path is closed not because «without KPA it is impossible at all» — that would be an over-claim — but because Triple splits the observation space into three unknown-offset streams, the Rank Barrier injects an unknown PRF-keyed permutation between the recoverable `channelXOR` and plaintext bytes, and dual-nonce guarantees fresh barrier keying even under a single-slot collision.

### But wait — what if CRC128 is also used inside the Rank Barrier?

**Reader's setup, continued.** «Suppose `lockSeed` is fed by CRC128 too. Same primitive on both barrier layers. Does the compound-key `K` recovered from the Pixel Barrier provide leverage against the Rank Barrier?»

**No.** Even under identical primitive, `K` from the Pixel Barrier is fundamentally not transferable to the Rank Barrier. There are five reasons at the algebra layer alone, before any observation gap:

**Reason 1 — Seed independence ([Theorem 3](PROOFS.md#proof-3-8-seed-isolation)).**
`lockSeed` and `dataSeed` are independent CSPRNG components, `I(lockSeed; dataSeed) = 0`. The compound-key script recovers `K_data = [M_L^1, ..., M_L^8] · [s_14, s_12, ..., s_0]` — a linear projection **inside** `dataSeed`'s ECMA-half components. `K_lock` would be a fundamentally different projection over `lockSeed` components. No overlap can produce a transfer.

**Reason 2 — Different derivation-chain shape and depth.**
The compound-key linear structure depends on the length-`L` CRC64 state-transfer matrix `M_L`:
- `dataSeed → dataHash`: `data(p) = pixel_le_u32 ‖ nonce`, so `L = 4 + nonceBytes` — fixed per session at the caller's nonce size — and `M_L` stays constant at that `L` across all pixels; this is what the compound-key script exploits
- `lockSeed` cascade: Stage 1 intermediate key `K = deriveInterLockSeed(N_il)` under tag `0x04` with `L = 1 + nonceBytes`; Stage 2 hot-loop cascade `prf_i = ChainHash(0x03 ‖ LE64(groupIdx) ‖ 4×0x00, lockComps)` with `L = 13` (1-byte tag + 8-byte LE index + 4 zero bytes), running a cascade of `1 + keyBits / width` calls (primer round 1 on `K` followed by session components; contrast with the Pixel Barrier which runs `keyBits / width` rounds). **Different length constants → different matrix products → different compound-key algebra.**

**Reason 3 — Different domain tags.**
`0x04` for setup key derivation, `0x03` for per-chunk PRF, counter for `dataSeed`. Even with identical seed material, different tags yield different `const(data)` in the affine decomposition `hLo(p) = K XOR const(data(p))`. `K_data` cannot be re-used to predict `lockSeed`'s chain output.

**Reason 4 — Different observation path.**
`K_data` is recovered from `channelXOR` observations (post-demask or via KPA). The attacker physically sees container bytes → strips the Pixel Barrier (rotation + XOR + noise) → gets lane fragments. Lane fragments are not plaintext — they are `PEXT(chunk_48, m_N)` where `m_N` is a Rank Barrier mask. To recover the Rank Barrier via linear algebra the attacker needs observations of mask ranks — and **mask ranks never appear on the wire in cleartext.** They are applied opaquely inside `chunk48lock` and compress plaintext bits into 16-bit lanes. The attacker sees the compression result, not the permutation itself.

**Reason 5 — Combinadic unrank is not GF(2)-linear and avoids the GCD anti-collapse trap.**
Even if `lockKey` were hypothetically recovered (which already requires observation of hash outputs that are unobservable), unranking it into a mask triple runs through two-step native divmod:

```
idx_1 =  rank mod B
idx_0 = ⌊rank / B⌋ mod A
```

where `B = C(32, 16) = 601,080,390` and `A = C(48, 16) = 2,254,848,913,647`. This two-step division by `B` before reducing modulo `A` deliberately avoids the Chinese Remainder Theorem anti-collapse trap: because `gcd(A, B) = 66,861`, evaluating both indices directly as `rank mod A` and `rank mod B` would restrict reachable pairs to a 66861× smaller subspace (~16.03 bits lost). The division step breaks both linearity and the GCD trap over Z, rendering CRC128's GF(2)-linearity useless.

**Bonus reason — cascade PRF binding across two live hash calls.**
Per [Proof 11](PROOFS.md#proof-11-48-bit-rank-barrier-mask-space-interlocked-barrier): `lockKey → per-chunk PRF chain` is two sequential hash calls. An attacker attacking the Rank Barrier via linear algebra must solve a system running through both chain calls simultaneously. The compound-key script composed an 8-round chain as a single affine XOR (`K = M_L^1·s_0 XOR M_L^2·s_2 XOR ...`) because 8 XOR-composed CRC64 rounds are still GF(2)-linear. A cascade of two chain calls with an intermediate unrank/mask draw is no longer a single-composition path — the attacker needs either a system with symbolic `mask` **and** `K_lock` (two unknowns interleaved), or per-chunk hash outputs as observations (which do not exist on wire).

**Summary.** Primitive is same. Seeds are independent. Chain-input structure differs. Observation path differs. Unrank arithmetic is non-linear. Across these five orthogonal structural differences no linear transfer path from `K_data` to any other seed / channel is apparent — combinadic-unrank non-linearity specifically blocks the GF(2) route that CRC128's linearity exploits on the Pixel Barrier. A non-linear bridge — a symbolic-SAT setup that carries `K` through unrank arithmetic, or a novel algebraic technique that couples the two layers through structure the walkthrough above did not surface — is not ruled out by the reasoning here, only unaddressed by known technique. What [Theorem 3a](PROOFS.md#proof-3a-8-seed-isolation-minimality)'s minimality argues is that the 8 independent seeds oblige the barrier layers to be architecturally separable at the algebra layer, independently of primitive strength or weakness.

### The `2^57.80` preimage math and cross-nonce non-collapsibility

**Reader's setup, continued.** «Fine, but the mask triple has a fixed preimage count `≈ 2^57.80`. Can observations collected across many nonces under fixed `lockSeed` collapse that ambiguity?»

**No.** The underlying arithmetic clarifies this directly, as "floating range" mischaracterises the mechanism.

The rank space is `2^128` (from 128-bit PRF output). The mask space is `Ω_chunk = A · B ≈ 2^70.20`. The reduction map `rank → (idx_0, idx_1)` is many-to-one, mapping `2^128` rank values into `2^70.20` mask triples. The preimage count per mask triple is either `⌊2^128 / (A · B)⌋` or `⌊2^128 / (A · B)⌋ + 1`:

- `2^128 mod (A · B)` masks receive `⌊…⌋ + 1` preimages
- The rest receive `⌊…⌋` preimages
- Both are approximately `2^57.80` — the deviation is exactly ±1 per specific mask, **not a range**

What actually «floats» is the per-chunk relative bias magnitude `2^-57.8` (the inverse of the preimage count). If every mask had identical preimages, the distribution would be uniform; the +1 extras produce a bias of magnitude `2^-57.8` per chunk. Accumulated linearly across `2^23.42` chunks in a maximum-length message, the per-message deviation is `≈ 2^-34.4`. The distinguisher budget needed to detect this bias with confidence is `≈ 2^115.6` chunk samples — not attainable.

Attack model: under CRC128 the cascade is fully affine over GF(2):

```
lockKey_msg = M_L · lockSeed XOR const_lock(N_il) (linear in lockSeed for fixed N_il)
prf_i_msg   = M_pr · lockKey_msg XOR const_pr(i)
            = M_pr · M_L · lockSeed XOR M_pr · const_lock(N_il) XOR const_pr(i)
```

If the attacker had many `rank_i_msg = prf_i_msg` observations under many `(N_il, i)` pairs at fixed `lockSeed`, this would be a trivial linear system `rank_j = A_j · lockSeed XOR b_j`. `n` unknowns (bits of `lockSeed`), `n` linearly independent observations, Gaussian elimination in `O(n^3)`. Broken in milliseconds.

But the attacker does not observe `rank`. Rank is consumed opaquely inside combinadic unrank → mask triple → applied via BMI2 `PEXTQ` to compress a plaintext chunk into 3 lane fragments in ~3 cycles in constant time → lane fragments pass Pixel Barrier encoding → container byte.

The attacker's observation path to obtain a single `rank` observation is:

1. **Strip the Pixel Barrier** from the container byte → need demask → need KPA anchor per pixel (56 candidates equiprobable without an anchor). Under Triple Ouroboros + Interlocked Barrier the demask fails empirically per REDTEAM.md null verdict.
2. **Reassemble lane fragments** from Pixel-Barrier-stripped region payload bytes. Works fine if the Pixel Barrier is stripped.
3. **Recover the mask triple** from `(known plaintext chunk, observed lane fragments)`. For candidate mask `m`, `PEXT(chunk, m) = lane_N` is under-determined. At 48 known plaintext bits and 48 output bits (16 × 3 lanes) the attacker gets 48 constraints on `≈ 2^70.20` candidate masks — approximately `2^22` masks remain consistent with the observation in the general case.
4. **Recover `rank` from the mask triple** — inverse combinadic unrank. For each mask triple, `≈ 2^57.80` candidate ranks correspond (the preimage count). Even after fixing a candidate mask, `2^57.80` candidate ranks remain per chunk.
5. **Only then** can the attacker use CRC128 linearity through cross-message system solving on recovered ranks.

**The mathematical crux — steps 3–4 do not collapse by adding more observations under different nonces.**

Each message yields its own per-chunk PRF-independent mask draw ([Proof 11](PROOFS.md#proof-11-48-bit-rank-barrier-mask-space-interlocked-barrier)'s PRF-independence clause). Ambiguity from message `N` does not constrain ambiguity in message `N+1` — they are independent PRF draws. After `N` messages the attacker does not have «`2^57.80` initial ambiguity collapsing to `2^57.80 / N`»; the attacker has `N` independent instances of `2^57.80` ambiguity, none coupling to the others.

Cross-message CRC128 linearity would help for the problem «recover `lockSeed` given multiple `rank` observations under different nonces». But each `rank` observation is itself under-determined with multiplier `2^57.80` (even with granted plaintext and granted Pixel Barrier stripping). Hypothetically:

- For each chunk in each message: `2^57.80` candidate ranks
- For a message with `M` chunks: `2^(57.80 · M)` full-message rank candidates
- Cross-message: even after fixing candidate ranks per chunk, the system's unknowns and observations correlate only through the correct-candidate choice — unknown a priori

This does not collapse via linear algebra because the correct candidate rank per chunk is unknown a priori. The attacker must brute-force enumerate `2^57.80 × M` candidates before CRC128 linearity kicks in. Enumeration explodes exponentially in `M`.

**Summary for the CRC128 fixed-`lockSeed` + variable-nonce attack model:**

- **Attacker-realistic (0/8 peek, shipped API):** structural wall at step 1 (demask fails). CRC128 linearity never engages, because there are no observations.
- **Lab-only maximum peek (Pixel Barrier stripped by lab instrumentation):** structural wall at steps 3–4. Mask/rank per chunk is under-determined with multiplier `2^57.80`. CRC128 linearity is blocked by non-linear combinadic arithmetic. This is what REDTEAM.md Bitwuzla UNSAT under this posture records.

The preimage count `2^57.80` is not a «collectable through more messages» ambiguity — it is information-theoretic under-determination per chunk observation. More messages equal more independent instances of the same structural problem, not a more-determined single instance. That is the fundamental difference between a CRC128 KPA attack (linear system with constraints — more observations, more determined) and a Rank Barrier attack (per-chunk unknown PRF-drawn mask — observations independent, ambiguity constant per chunk).

Exactly this aspect makes the barrier «structurally unmeasurable at attacker-realism» — not «cost too high» but «instance under-determined regardless of observation count».

---

## Question 5 — FNV-1a has the T-function property. Doesn't that break the barrier?

**Reader's setup.** «FNV-1a's round is `h = (h XOR byte) * FNV_PRIME`. Multiplication modulo `2^64` is not GF(2)-linear (carry chain), but it has the T-function property (Klimov & Shamir 2002) — output bit `t` depends only on input bits `0..t`, invertible plane-by-plane in `O(n^2)`. A standalone SAT solver targeting an unshielded single-region pipeline without the Rank Barrier can recover `dataSeed` lo-lane at `keyBits = 512` on 4 cribs plus disclosed `startPixel`. Does that attack path scale against the shipped construction?»

### Current analytical picture

The reasoning tracks the CRC128 case, plus one primitive-specific arrow: **combinadic unrank breaks T-function friendliness.** FNV-1a's T-function property gives the cryptanalyst a poly-time shortcut on direct hash inversion (given `h → seed`), but there is no `h` to give — hash outputs are consumed opaquely inside the pipeline before reaching the wire, and the pipeline component that would need inverting for the T-function shortcut to reach forward (combinadic unrank) is neither GF(2)-linear nor a T-function. The sections below trace each arrow.

### The T-function property, on paper

Multiplication by an odd constant modulo `2^64` is a T-function: carry propagates only LOW → HIGH, so output bit `t` is an affine function of input bits `0..t` with variable coefficients from the multiplier. This lets a solver work plane-by-plane from LSB to MSB via linear algebra on each bit plane, in `O(n^2)` instead of `2^n`.

In an unshielded single-region pipeline lacking the Rank Barrier and dual-nonce separation, Bitwuzla with T-function-aware handling of the multiply could recover `dataSeed` lo-lane at `keyBits = 512` on 4 cribs plus disclosed `startPixel`. That regime was single-region, unshielded, disclosed `startPixel`, Crib KPA — a partial-lab posture that the shipped surface does not expose.

### What happens when FNV-1a meets combinadic unrank in the Rank Barrier

The cascade is:

```
lockKey  = ChainHash(0x04 ‖ N_il, lockSeed)
prf_i    = ChainHash(0x03 ‖ LE64(groupIdx) ‖ 4×0x00, lockComps)   ← Round 1 primer on lockKey, then session components (13 bytes)
rank     = prf_i (128 bits)
(m0,m1,m2) = combinadic_unrank(rank)          ← breaks T-function here
lane_N   = PEXT(chunk_48, m_N)                ← 48 → 16 bit compression via BMI2 PEXTQ (~3 cycles/chunk)
wire     = PixelBarrierEncode(lane_N, dataSeed, noiseSeed, startSeed, container)  ← COBS + Pixel Barrier
```

FNV-1a's T-function property covers the first two operations (the setup `ChainHash` and the per-chunk cascade). Unrank breaks T-function friendliness in three places at once:

**Break 1 — Two-step divmod (Theorem 12).**
`idx_1 = rank mod B`, `idx_0 = ⌊rank / B⌋ mod A`, where `B = C(32, 16)` and `A = C(48, 16)` (avoiding the `gcd(A, B) = 66,861` anti-collapse trap, [Proof 12](PROOFS.md#proof-12-gcda-b-anti-collapse-trap)). Division by a non-power-of-2 constant, and modulo of a non-power-of-2, both involve carry propagation in both directions (multiply-by-reciprocal + shifts + subtract). Output bit `t` depends on input bits both above and below `t`. Not a T-function.

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

Forward pipeline: `rank → unrank → mask_triple` (polynomially fast — that is what the encoder computes). Reverse: `mask_triple → rank` requires enumerating `C(48, 16) × C(32, 16) ≈ 2^70.20` preimages because unranks are many-to-one (`≈ 2^57.80` preimages per triple per [Proof 11](PROOFS.md#proof-11-48-bit-rank-barrier-mask-space-interlocked-barrier)). Even given a `mask_triple`, backward inversion of combinadic reduction is essentially guessing rank among `2^57.80` preimages — not amenable to any T-function shortcut.

But the most important point remains: **the attacker never observes `mask_triple` directly.** The mask is applied opaquely inside `chunk48lock` via hardware BMI2 `PEXTQ` (or constant-time soft fallback) in ~3 cycles to compress a plaintext chunk into 3 lane fragments. The attacker sees on wire only post-Pixel-Barrier-encoded container bytes. To even start working backward to a mask triple:

1. Strip the Pixel Barrier (rotation + `channelXOR` + noise) — requires Pixel Barrier demask, which requires KPA anchor.
2. Recover lane fragments from Pixel-Barrier-stripped bytes.
3. Compute candidate mask triples from lane fragments + known plaintext chunks.

Each chunk observation gives `lane_N = PEXT(chunk, m_N)` — 16 output bits as a function of 48 input bits and mask `m_N`. Per [Proof 11](PROOFS.md#proof-11-48-bit-rank-barrier-mask-space-interlocked-barrier), at 48 known plaintext bits per chunk the preimage count per candidate mask triple is `≈ 2^57.80` — an under-determined system regardless of how many chunks accumulate (masks per chunk are independent PRF draws — no coupling).

### Summary

FNV-1a's T-function property assists direct hash inversion, but:

- Per-chunk PRF outputs are consumed opaquely inside unrank and `PEXTQ`, never surfacing on the wire.
- Pixel Barrier encoding combined with Rank Barrier lane compression prevents mask triple recovery.
- Combinadic unrank is non-linear over GF(2) and non-T-function — reversing it requires resolving an under-determined system with `2^57.80` preimages per chunk.
- Compound-key linear algebra does not transfer across carry chains.

Under the maximum-peek regime ([REDTEAM.md § FNV-1a lo-lane SAT](REDTEAM.md#fnv-1a-lo-lane-sat--architecturally-foreclosed)), Bitwuzla returns UNSAT: the instance is structurally under-determined. The T-function shortcut exists on paper, but the ITB architecture leaves no point of application.

---

## Closing Note — Why Standard Decomposition Attacks Do Not Apply

The questions above share a single architectural answer. A cryptanalyst reading [REDTEAM.md](REDTEAM.md)'s null-recovery results and evaluating conventional cryptanalytic leverage typically considers **meet-in-the-middle (MITM), divide-and-conquer, or layer-peeling cryptanalysis.** If an attack surface splits into two halves meeting at a known intermediate state, MITM reduces complexity from `O(2^n)` to `O(2^(n/2))` or better.

ITB's independent-yet-interconnected architecture blocks decomposition at the structural design layer:

**Independence — 8-seed isolation ([Theorem 3](PROOFS.md#proof-3-8-seed-isolation)).** For any `i ≠ j`, `I(seed_i; seed_j) = 0`. Cross-seed algebraic leverage is absent: partial knowledge of `noiseSeed` via CCA leaks provides zero bits of information about `dataSeed`, `lockSeed`, or `startSeed`. A split-by-seed MITM cannot engage because the halves share zero state space.

**Interconnectedness — compositional forward pipeline.** Layers apply sequentially in the encoder:

```
plaintext
   ↓ Rank Barrier (chunk48lock under lockSeed via BMI2 PEXTQ)
lane_bits  ← never observable on wire
   ↓ Pixel Barrier (channelXOR + rotate + noise under dataSeed / noiseSeed / startSeed)
wire byte
```

On the wire, only the composed result is observable. A split-by-layer MITM cannot engage because intermediate states (`lane_bits`) are consumed opaquely within the pipeline.

### Classical MITM setup versus ITB

Classical MITM (e.g. 2-DES):

```
plain →[K1]→ intermediate →[K2]→ cipher
```

The attacker computes forward from plaintext and backward from ciphertext, matching at the intermediate state in `O(2^{n+1})`.

ITB pipeline:

```
plain →[lockSeed (Rank Barrier chunk48lock)]→ lane_bits →[dataSeed × noiseSeed × startSeed (Pixel Barrier)]→ wire byte
```

Both potential meeting points are structurally blocked:

- **Between the Rank Barrier and the Pixel Barrier (`lane_bits`):** Backward computation from wire requires stripping the Pixel Barrier — 56 equiprobable candidates per pixel under [Proof 1](PROOFS.md#proof-1-information-theoretic-barrier), rendering the step under-determined. Forward computation through `chunk48lock` encounters the per-chunk mask space of `≈ 2^70.20` partitions and `2^57.80` preimages per rank, yielding `2^(57.80 · C)` candidate sequences across `C` chunks.
- **Between PRF chain and unrank (`rank_i` values):** Forward cascade evaluation produces ranks, but backward inversion from wire observations requires inverting PEXT lane compression and combinadic unrank — an under-determined system with `≈ 2^57.80` preimages per chunk and no verification anchor.

### Other decomposition attempts

Standard layer-peeling techniques encounter orthogonal structural obstacles:

| Technique | What it needs | Why it fails on ITB |
|---|---|---|
| Slide attack | Repeating structure across rounds | ChainHash rounds are independent per component ([Theorem 3b](PROOFS.md#proof-3b-chainhash-full-component-utilization)) |
| Related-key attack | Algebraic relation between keys | 8 CSPRNG-drawn seeds enforced pairwise-distinct at API |
| Boomerang | Composable differential paths through intermediate state | No observable intermediate state in the barrier |
| Integral / square | Balanced property preserved across rounds | Random container destroys balance |
| Linear cryptanalysis | Linear approximation input ↔ output | Pixel Barrier absorbs output through DRBG noise; Rank Barrier removes fixed bit-position anchor |

Conventional cryptanalytic tools require a fixed anchor, observable output, or linear relation. ITB's architecture structurally denies these prerequisites:

1. **Independent seeds:** `I(seed_i; seed_j) = 0` eliminates cross-layer algebraic bridges.
2. **Opaque composition:** intermediate states are never emitted on the wire.
3. **Fresh PRF draws per chunk and pixel:** observations remain uncoupled across messages and positions.

As codified in [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance): *«The obstacles are not sub-problems defeated sequentially but interlocking constraints.»* An adversary cannot peel layers sequentially; all obstacles must be breached simultaneously.

### Residual Risk

The construction has one fundamental assumption boundary: **total PRF inversion of a shipped primitive**. Should any shipped primitive suffer total preimage inversion, ITB mitigates through primitive agility: callers can select or register alternative primitives via `hashes.Register` and `triple.Register` without altering the wire format or construction architecture. All theorems have formal derivations in [PROOFS.md](PROOFS.md); all empirical bounds have reproducible harnesses in [REDTEAM.md](REDTEAM.md).
