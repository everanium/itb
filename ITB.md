# ITB: How the Barrier Works

> **Triple Ouroboros** (7-seed variant with 3× security): see [ITB3.md](ITB3.md)

## 1. The Core Idea: Absorption

The hash output exists — it is computed and determines the pixel configuration. But it is absorbed by a modification of a random container. The observer sees the result: random byte ± modification. The original random byte is unknown → the modification is unknown → the hash output is unobservable.

This is not destruction (the hash output is used), not hiding (there is no encryption on top), but absorption — the random container absorbs the hash output. Like dropping a drop of paint into an ocean of random waves — the paint is there, but the observer sees only waves.

This is why the barrier is computation-model-independent under passive observation: no matter how much computational power the attacker has — the information is not in the observation.

**Formal basis:** ∀v, ∀h : ∃c : embed(c, h, d) = v — for any observed value, any hash output, there exists a container byte that produces this observation (see [SCIENCE.md Section 2.4.1](SCIENCE.md#241-the-barrier-passive-observation), [SECURITY.md Section 9](SECURITY.md#9-information-theoretic-barrier-metrics)).

## 2. Two Independent Sources of Randomness

The barrier works because of separation of sources:

- **Container**: crypto/rand (CSPRNG) — external, independent of the construction
- **Config**: ChainHash(seed + nonce) — internal, PRF-based
- **Nonce**: crypto/rand — fresh 128-bit per message

Two independent random processes. CSPRNG does not know about PRF, PRF does not know about CSPRNG. Their only point of contact is the moment of embedding, after which the observer sees only the result, not the components.

## 3. Nonce: A New Universe Per Message

The nonce guarantees that the same message with the same seed produces each time:

- A different random container (new crypto/rand)
- A different config map (nonce feeds into every ChainHash)
- A different startPixel (nonce feeds into deriveStartPixel)

1000 transmissions of the same message — 1000 independent containers (given unique nonces). No observable correlation between them. Two-time pad is impossible until the birthday bound ~2^64 messages.

This is not a cryptographic trick — this is information theory: two independent random processes, the observation result contains no information about either one individually.

## 4. Triple-Seed Isolation

Three seeds, three independent keys from crypto/rand:

- **noiseSeed** → noise position (which bit in each channel is noise)
- **dataSeed** → rotation + XOR masks (how data is arranged and encrypted)
- **startSeed** → pixel offset (where in the container the data begins)

Each seed has its own ChainHash with its own components. There is no mathematical relationship between them. Full knowledge of noiseSeed configuration gives zero bits of information about dataSeed or startSeed (see [SCIENCE.md Section 2.4](SCIENCE.md#24-information-theoretic-barrier-and-hash-requirements), [SECURITY.md Section 1](SECURITY.md#1-itb-composition-modes)).

**Note (five-seed variant).** Splitting dataSeed into rotationSeed + xorEvenSeed + xorOddSeed is architecturally possible and doubles the brute-force space under PRF. With PRF, rotation candidates are unverifiable — the attacker cannot derive XOR masks from candidate rotations, so xorEvenSeed and xorOddSeed remain independently protected. Under CCA, classical brute-force increases from P × 2^keyBits to P × 2^(2×keyBits) for the data domain; Grover from √P × 2^(keyBits/2) to √P × 2^keyBits. However, the three-seed architecture already provides P × 2^keyBits classical resistance under CCA (far beyond the Landauer thermodynamic limit of ~2^306), making the additional key space practically redundant. The five-seed variant adds implementation complexity without meaningful security gain. Three seeds remain the proven optimum: minimum configuration with full domain isolation ([Proof 3a](PROOFS.md#proof-3a-triple-seed-isolation-minimality)), no cross-domain leakage, and brute-force resistance already beyond physical limits.

**Note (Triple Ouroboros — implemented).** Plaintext split into 3 parts at the byte level (every 3rd byte: bytes[0::3], [1::3], [2::3]), each encrypted into 1/3 of the pixel data with independent dataSeed and startSeed, sharing noiseSeed. 7 seeds: 3 × dataSeed + 3 × startSeed + 1 × noiseSeed. Output format identical to standard ITB: `[nonce][W][H][W×H×8 pixels]` — attacker cannot distinguish Single from Triple. Pixel data split into thirds by integer division (last third absorbs remainder). Three independent rings, three startPixels, three rotation/XOR configurations. 3×CSPRNG parallel generation into one buffer (ASIC-ready). 3 parallel goroutines with perThird worker limit (numCPU/3) for optimal CPU utilization. One dataSeed yields every third byte — useless without the other two. Under CCA: P × 2^(3×keyBits) classical, √P × 2^(3×keyBits/2) Grover. API: `Encrypt3x128/256/512`, `Decrypt3x128/256/512`, `EncryptAuthenticated3x128/256/512`, `DecryptAuthenticated3x128/256/512`, `EncryptStream3x128/256/512`, `DecryptStream3x128/256/512`. See [BENCH3.md](BENCH3.md) for performance results.

**General pattern (N-tuple Ouroboros).** N containers within one message = (2N+1) seeds (N × dataSeed + N × startSeed + 1 × noiseSeed). Plaintext split into N parts at the byte level. Under CCA: P × 2^(N×keyBits) classical. Same header, same file size, externally indistinguishable.

## 5. Under Normal Use: The Barrier Is Practically Impenetrable

With PRF hash, crypto/rand, and no co-located attacker:

| Attack | What happens | Barrier status |
|---|---|---|
| **COA** (ciphertext only) | Attacker sees random bytes, hash output unobservable | Intact |
| **KPA** (known plaintext) | Even with known plaintext, the original container is unknown | Intact |
| **CPA** (chosen plaintext) | Different seed → different config, zero correlation | Intact |
| **CCA** (chosen ciphertext) | Core ITB and MAC + Silent Drop have no external oracle (see SECURITY.md ‡‡ for insider case) | No oracle exists |

Under passive observation (COA, CPA), the barrier alone blocks all analysis. Under Full KPA, PRF non-invertibility is essential — it closes the candidate-verification step, while two architectural layers deny the attacker a usable reference pixel:

- **Independent startSeed** — startPixel is not transmitted; derived from a separate ChainHash. The attacker must enumerate P candidates without feedback.
- **7-rotation × 8-noisePos encoding ambiguity** — 56 per-pixel candidates preserved at signal/noise 1:1.

Under Partial KPA, gcd(7,8)=1 byte-splitting adds a 4th factor — per-channel candidate formulation is blocked when adjacent bytes are unknown (each channel depends on two bytes; missing one prevents candidate computation).

An attacker with partial PRF inversion capability still faces P startPixel candidates to enumerate and 56-fold per-pixel ambiguity to disambiguate without a verification oracle.

See [SECURITY.md Section 7](SECURITY.md#7-attack-resistance-summary) for the full attack resistance table.

## 6. Byte-Splitting: Why Byte Analysis Does Not Work

Since gcd(7, 8) = 1 (7 data bits per channel, 8 bits per byte), plaintext bytes never align with channel boundaries. Every plaintext byte is split across exactly 2 channels with independent XOR masks.

A known byte like `{` (0x7B) cannot be analyzed per-channel because each channel mixes bits from 2 adjacent plaintext bytes. Without knowing the adjacent byte, the attacker cannot compute the expected channel bits. Candidates are not even formulable.

Three layers of protection under Partial KPA:

1. **Barrier** — hash output unobservable (container is random)
2. **Byte-splitting** — byte-level analysis impossible (gcd(7,8) = 1)
3. **PRF** — even if the attacker somehow gets through, inversion is impossible

All three layers work together: the barrier denies observation, byte-splitting denies per-channel candidate formulation under Partial KPA, and PRF denies candidate verification. Under Full KPA, byte-splitting does not add defensive benefit (the attacker has all adjacent bytes), but the defense is nonetheless 3-factor under PRF assumption: PRF non-invertibility + independent startSeed + 7-rotation × 8-noisePos per-pixel ambiguity at signal/noise 1:1. The layers are architecturally independent and combine conjunctively (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)).

See [SCIENCE.md Section 2.9.1](SCIENCE.md#291-byte-splitting-property-78-non-alignment), [SECURITY.md Section 8](SECURITY.md#8-byte-splitting-property).

## 7. Full KPA: The Only Theoretical Threat (PRF Assumption)

Full KPA (the attacker knows the entire plaintext) is the only scenario where the barrier can be bypassed — but only with an invertible hash function:

| Condition | Result |
|---|---|
| Full KPA + invertible hash | ~56 × P inversions → **seed recovered** (barrier intact, hash inverted) |
| Full KPA + PRF (non-invertible) | Inversion impossible → brute-force P × 2^(2×keyBits) (Core ITB) or P × 2^keyBits (MAC + Reveal) |

The attack: the attacker takes any pixel → 56 candidates (8 noisePos × 7 rotation) → computes candidate dataHash → **inverts** ChainHash → gets candidate dataSeed → verifies on a second pixel (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)).

With PRF: the same 56 candidates, the same candidate dataHash values. But inverting ChainHash is impossible — PRF by definition. The only path: brute-force all seeds (P × 2^(2×keyBits) for Core ITB, P × 2^keyBits for MAC + Reveal).

**Under Full KPA + total PRF inversion**, the architectural layers collapse via algorithmic seed recovery (see Asymmetry note in [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)): the attacker inverts hashes to recover dataSeed, then re-derives startPixel and the per-pixel configuration. The multi-factor property defends against *partial* PRF weakness, not total failure. Within partial PRF weakness, occasional/sporadic inversion events are absorbed — the architectural obstacles generate a false-positive distribution that hides the true candidates. Systematic partial inversion is not absorbed; the architecture raises cost but does not eliminate the attack. No such systematic weakness is currently known (see [Proof 4a Composition conjecture](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)).

**Under Full KPA + non-invertible PRF**, the defense is 3-factor under PRF assumption: (1) PRF non-invertibility prevents candidate verification; (2) independent startSeed requires enumeration of P startPixel candidates — startPixel is not transmitted; (3) 7-rotation and 8-noisePos per-pixel ambiguity preserved by the barrier at 1:1 signal/noise. gcd(7,8)=1 byte-splitting is a 4th factor effective only under Partial KPA (when the attacker is missing adjacent bytes). A partial weakening of PRF is not sufficient for a Full KPA break: the attacker still faces P startPixel candidates to enumerate + 56-fold per-pixel ambiguity to disambiguate without a verification oracle. PRF non-invertibility is necessary, and together with the architectural layers it constitutes the 3-factor KPA defense under PRF assumption, 4-factor under Partial KPA (see [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance)).

## 8. Nonce Reuse: Only If Every Condition Holds

Nonce reuse is the single edge case where the barrier can leak local information without brute-forcing seeds. But **every** condition below must hold simultaneously — miss any one and the attack collapses:

1. **User downgraded the nonce size from 512-bit to ≤ 128-bit.** ITB supports nonce sizes up to 512 bits → `2^256` queries to birthday-collision → mathematically unreachable on any foreseeable hardware. Shrinking to 128-bit is the gate the attacker cannot force open; only the user can.
2. **Same seeds + same nonce across ≥ 2 messages.** Different nonces → different container + config + startPixel → no cross-message information transfer.
3. **Attacker knows plaintext format at byte-level precision over ≳ 90 % of the plaintext.** Exact field-name lengths, exact value-region offsets, exact structural-punctuation positions. Off by one byte anywhere → every subsequent mask position misaligns → demasker returns nothing useful.
4. **Two DISTINCT template variants, both known to the attacker.** Both messages sharing the same template byte-for-byte → `d1 ⊕ d2 = 0` on all known channels → rotation unrecoverable → degenerate same-plaintext case (attacker effectively sees two copies of the same ciphertext).
5. **Per-record varying sequence numbers at known offsets.** Without per-record variation the `d_xor` pattern is periodic over the record length → Layer 2 locks onto a period-shifted startPixel → reconstruction leaks residual plaintext-XOR, not hash output.

**All five conditions held:**

| Primitive | What the attacker walks away with |
|---|---|
| PRF (BLAKE3, AES-CMAC, SipHash-2-4, ChaCha20, AreionSoEM-256/512, BLAKE2s, BLAKE2b-512, MD5 in PRF-output mode) | Plaintexts of the 2 – 3 colliding messages only. No seeds, no configuration map, nothing reusable on future traffic. |
| Invertible (FNV-1a) | Same plaintexts + a reconstructed `dataSeed.ChainHash(pixel, nonce)` output stream — usable as ammunition for a SAT solver. Seed recovery still requires **three separate research-scale SAT campaigns**, one per seed (dataSeed, startSeed, noiseSeed). Each campaign consumes many independent nonce-reuse sessions (each session requires forcing a fresh birthday-bound nonce collision). Not push-button: `startSeed` yields ONE observation per session; `noiseSeed` requires a separate `noisePos` emit pipeline that the demasker does not even ship by default. |

**Any one condition violated:**

| Violated condition | Result |
|---|---|
| 1 (512-bit nonce in use) | No nonce collision ever occurs. Attack never starts. |
| 2 (nonces differ) | XOR of ciphertexts is pure random noise. Demasker refuses (validated empirically: 0 / 18 766 recovery on nonce-mismatch control corpus). |
| 3 (format misknown by ≥ 10 %) | Known-mask misaligns with actual payload bytes. Layer 1 constraint-matching accepts bogus `(noisePos, rotation)` candidates → WRONG matches flood the output → demasker exits with code 2. Format brute-forcing over the `10^8 – 10^12` hypothesis space is a binary-pass/fail search with no gradient. |
| 4 (single template used by both messages) | Rotation constraint collapses on known channels. Demasker at best recovers noisePos only (ambiguity stays 7× per pixel on rotation). Stream mostly zero bytes. |
| 5 (no per-record variation) | Layer 2 converges onto any of `~N_records` period-shifted startPixel candidates. Reconstruction under a period-shifted sp XORs recovered data with the wrong payload → output is a mix of hash-output bits and plaintext-difference residue, not a clean hash stream. |

→ The security gate is the user's choice of nonce size. At 512-bit nonce the attack is mathematically out of reach.

→ For the 96-cell empirical matrix quantifying Clean Signal % under each (format, coverage, plaintext size, primitive) combination, and for the full 9-effect architectural analysis of why the demasker's yield is always below attacker-known byte coverage, see [REDTEAM.md § Phase 2d — Nonce-Reuse](REDTEAM.md#phase-2d--nonce-reuse).

## 9. CCA: Reveals Only Noise, Not Data

Under CCA (bit-flip with MAC reveal), the attacker learns noise positions — which bit in each channel is noise (3 bits per pixel from noiseSeed). But due to triple-seed isolation:

- **noiseSeed config** — revealed via CCA
- **dataSeed config** (rotation + 56 XOR bits) — completely independent, zero leak
- **startSeed** (pixel offset) — completely independent, zero leak

With CCA, the candidate count drops from 56 (8 noisePos × 7 rotation) to 7 (only rotation unknown). But 7 candidates do not help without invertible hash — the attacker cannot verify which of the 7 is correct without inverting ChainHash.

**What the attacker gets after removing noise bits.** CCA lets the attacker strip noise bits and see 7 data bits per channel. But "clean encrypted data" is a misleading description. These data bits contain a mixture of encrypted plaintext (COBS-encoded) **and** encrypted CSPRNG fill — both encrypted identically by dataSeed (rotation + XOR). The container is always over-sized relative to the payload: the `side += barrierFill` construction (`SetBarrierFill`, default 1) guarantees at least (2s+1)×7 bytes of CSPRNG fill (≥203 bytes at 1024-bit key). Perfect fill — zero CSPRNG bytes — is mathematically impossible ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

This means CCA does not give the attacker a clean plaintext-only ciphertext. A portion of the data bits carry random CSPRNG fill that is indistinguishable from encrypted plaintext. The attacker does not know where the plaintext ends and the fill begins, does not know the fill content, and cannot separate one from the other without the correct dataSeed. The information-theoretic barrier is partially preserved within the data channel itself: ambiguity from CSPRNG residue persists even after noise removal.

CCA leak = 3/62 ≈ 4.8% of per-pixel configuration. CCA reveals no plaintext bits, no XOR masks, no start pixel. However, CCA eliminates noiseSeed from brute-force search: P × 2^(2×keyBits) → P × 2^keyBits (two seeds → one seed). The remaining security (P × 2^keyBits ≈ 2^1033 at 1024-bit, P=400) is still far beyond the Landauer limit (~2^306).

See [SECURITY.md Section 6](SECURITY.md#6-cca-oracle-leak-comparison), [SCIENCE.md Section 4.1–4.5](SCIENCE.md#41-chosen-ciphertext-attack-and-mac-composition), [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill).

## 10. startPixel: Not Transmitted, Not Recoverable

startPixel is computed from startSeed + nonce via ChainHash. It is not transmitted, not stored, computed in a register once. The only theoretical way to learn it is a cache side-channel (Flush+Reload, Prime+Probe) by a co-located attacker on the same CPU.

Even in the worst case (Full KPA + CCA + cache side-channel), the attacker gets: noisePos + startPixel + 7 rotation candidates. Without invertible hash — brute-force 2^keyBits.

See [SCIENCE.md Section 4, startPixel limitation](SCIENCE.md#known-theoretical-threats).

## 11. Why the Barrier Is Not Broken by KPA Candidates

A common question: if the attacker with known plaintext can compute 56 candidate hash outputs per pixel, doesn't that mean the barrier failed to absorb the hash output?

No. The barrier is intact. Here is why:

**What the barrier guarantees ([Proof 1](PROOFS.md#proof-1-information-theoretic-barrier)):** for any observed byte value v and any hash output h, the probability P(v | h) = 1/2. This holds even under Full KPA — because the noise bit comes from the original container (CSPRNG), which is random and independent of everything. The observation does not uniquely determine the hash output. This is information theory, not computational assumption.

**What the attacker computes:** the 56 candidates are not extracted from the observation. They are **calculated** from the combination of (known plaintext + observed byte + candidate config). This is arithmetic, not a barrier break. All 56 candidates are **equally consistent** with the observation — the attacker does not know which one is real.

**Without hash inversion (PRF):** 56 candidates per pixel × P pixels = 56^P total combinations. For P = 196 (1024-bit key, Encrypt/Stream): 56^196 ≈ 2^1138. The attacker cannot verify any candidate without inverting ChainHash. PRF makes inversion impossible. The ambiguity is preserved.

**With hash inversion (invertible hash):** the attacker takes each candidate, inverts ChainHash → gets candidate seed → verifies on another pixel. Inversion **bypasses** the ambiguity. The barrier is not broken — ChainHash is inverted.

The barrier absorbs the hash output through two independent mechanisms: (1) noise absorption — CSPRNG noise bit at unknown position makes the byte ambiguous; (2) encoding ambiguity — 7 rotation candidates per pixel create 7^P unverifiable combinations. CSPRNG residue — guaranteed fill bytes encrypted by dataSeed within the data channel, indistinguishable from encrypted plaintext ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)) — is a structural property of mechanism (1): even after CCA reveals noise bit positions, CSPRNG fill remains in the data channel. CCA (MAC + Reveal) can bypass noise-position uncertainty of mechanism (1), but mechanism (2) and the CSPRNG residue remain intact through triple-seed isolation. The noise bits are removed, but the data bits still contain CSPRNG fill that the attacker cannot separate from plaintext — the information-theoretic barrier is never fully eliminated. KPA candidates are ambiguity, not leakage. PRF preserves this ambiguity. Invertible hash resolves it — but that is a hash function failure, not a barrier failure.

## 12. Quantum Resistance

The barrier works strictly by information theory: the observation does not contain information about the hash output. This property is **computation-model-independent** — it does not depend on whether the attacker uses a classical computer, a quantum computer, or any future computational model. A quantum computer cannot extract information that does not exist in the observation.

This is the fundamental difference between ITB and traditional ciphers. AES and ChaCha20 rely on **computational hardness** — their security degrades if the attacker has more computational power (Grover: √ speedup). ITB's barrier relies on **information absence** — no amount of computation helps when the information is not there.

Specific quantum algorithms and why they are conjectured mitigated:

- **Grover** — requires a verification oracle. Core ITB and MAC + Silent Drop have no external oracle; the attacker must jointly search noiseSeed and dataSeed (without dataSeed, noiseSeed output is indistinguishable from random), while startSeed contributes only P startPixel candidates (enumerated, not brute-forced). Grover complexity: √P × 2^keyBits — at 1024-bit keys (P=196): ~2^1028. With MAC + Reveal: CCA reveals noisePos but not startPixel (independent startSeed). Search: dataSeed (2^keyBits) × P startPixel candidates. Grover: √(P × 2^keyBits) = √P × 2^(keyBits/2), each oracle query costs O(P) — full container decryption. At 1024-bit key (P=400): ~2^516 iterations × O(P) each.
- **Simon** — requires periodic function structure. ITB's config map is aperiodic: each message has a unique per-message nonce (128/256/512-bit, configurable), creating a completely different configuration.
- **BHT** — requires observable hash collisions. In Core ITB and MAC + Silent Drop: the random container absorbs collisions — two identical hash outputs on different pixels produce different observed bytes (different random container values). After CCA (MAC + Reveal): collisions remain unobservable through encoding ambiguity (7 rotation candidates per pixel — attacker cannot identify which candidates collide).
- **Q2 superposition queries** — requires oracle that accepts quantum superposition inputs. ITB's MAC oracle is inherently classical: it receives concrete bytes over a network and returns accept/reject. Superposition queries are physically impossible.

At 1024-bit key: Core/Silent Drop (P=196) ~2^2056 classical, ~2^1028 Grover. MAC + Reveal (P=400): ~2^1033 classical, ~2^516 Grover. Both are far beyond any foreseeable quantum capability. For comparison, AES-256 with Grover: 2^128 — widely considered quantum-resistant.

See [SECURITY.md Section 16](SECURITY.md#16-quantum-resistance-conjectured), [SCIENCE.md Section 2.11](SCIENCE.md#211-quantum-resistance-analysis), [SCIENCE.md Section 2.9.2 — Why KPA candidates do not break the barrier](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier).

## 13. Per-Candidate Cost: Why Brute-Force Is Slow

In AES or ChaCha20, testing one candidate key takes ~1 nanosecond — a single block operation. In ITB, testing one candidate requires decrypting the **entire container** — all P pixels, each with ChainHash evaluation. The larger the message, the more expensive each attempt.

| Data size | P (pixels) | Time per attempt | vs AES |
|---|---|---|---|
| 1 KB | 196 | ~31 µs | ~31,000× slower |
| 4 MB | 602,176 | ~96 ms | ~96 million× slower |
| 16 MB | 2,408,704 | ~385 ms | ~385 million× slower |
| 64 MB | 9,628,609 | ~1.5 s | ~1.5 billion× slower |

Approximate empirical example: 1024-bit key, ~10 ns/hash (average across PRF functions on a typical modern CPU), 8 ChainHash rounds. Actual times vary by hash function, key size, and hardware. This applies to all modes (Core ITB, MAC + Silent Drop, MAC + Reveal).

This is not a tunable parameter — it is a structural consequence of the construction. Every brute-force candidate, classical or quantum (Grover), must pay this cost. ChainHash rounds are sequential and cannot be parallelized.

See [SCIENCE.md §2.12](SCIENCE.md#212-per-candidate-decryption-cost) for detailed analysis.

## 14. Barrier and PRF: Symbiosis

The barrier and PRF hash function protect each other:

- **PRF protects the barrier:** non-invertibility prevents the attacker from resolving the 56-candidate ambiguity under KPA. Without inversion, the barrier's information-theoretic protection holds — the attacker cannot verify which candidate is real.

- **Barrier protects the PRF:** hash collisions are the only theoretical weakness of a non-invertible hash function — two different inputs producing the same output. In a traditional cipher, collisions may be exploitable because the attacker observes the output directly. In ITB, collisions are invisible: two pixels with the same dataHash have different original container bytes (CSPRNG), so the observed bytes are different. The collision is absorbed.

Together: non-invertibility blocks inversion, and absorption hides collisions. Each property closes the other's theoretical weakness. In core ITB and MAC + Silent Drop (no oracle, passive observation only), the barrier makes a non-invertible hash function indistinguishable from an ideal random function — collisions absorbed, statistical patterns absorbed, no known attack surface remains. With MAC + Reveal (CCA): noiseSeed config is leaked via oracle interaction, but dataSeed remains protected by PRF non-invertibility and triple-seed isolation. Additionally, even after noise removal, the data channel retains CSPRNG fill bytes encrypted by dataSeed — perfect fill is impossible ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)), so information-theoretic ambiguity persists within the data bits themselves.

See [SCIENCE.md Section 2.4](SCIENCE.md#24-information-theoretic-barrier-and-hash-requirements).
