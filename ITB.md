# ITB: How the Barrier Works

## 1. The Core Idea: Absorption

The hash output exists — it is computed and determines the pixel configuration. But it is absorbed by a modification of a random container. The observer sees the result: random byte ± modification. The original random byte is unknown → the modification is unknown → the hash output is unrecoverable from observation.

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

## 5. Under Normal Use: The Barrier Is Practically Impenetrable

With PRF hash, crypto/rand, and no co-located attacker:

| Attack | What happens | Barrier status |
|---|---|---|
| **COA** (ciphertext only) | Attacker sees random bytes, hash output unobservable | Intact |
| **KPA** (known plaintext) | Even with known plaintext, the original container is unknown | Intact |
| **CPA** (chosen plaintext) | Different seed → different config, zero correlation | Intact |
| **CCA** (chosen ciphertext) | Core ITB and MAC + Silent Drop have no external oracle (see SECURITY.md ‡‡ for insider case) | No oracle exists |

The PRF is not even reached — the barrier blocks everything at the observation level. PRF is defence-in-depth for active attacks, which under normal conditions are not possible.

See [SECURITY.md Section 7](SECURITY.md#7-attack-resistance-summary) for the full attack resistance table.

## 6. Byte-Splitting: Why Byte Analysis Does Not Work

Since gcd(7, 8) = 1 (7 data bits per channel, 8 bits per byte), plaintext bytes never align with channel boundaries. Every plaintext byte is split across exactly 2 channels with independent XOR masks.

A known byte like `{` (0x7B) cannot be analyzed per-channel because each channel mixes bits from 2 adjacent plaintext bytes. Without knowing the adjacent byte, the attacker cannot compute the expected channel bits. Candidates are not even formulable.

Three layers of protection under Partial KPA:

1. **Barrier** — hash output unobservable (container is random)
2. **Byte-splitting** — byte-level analysis impossible (gcd(7,8) = 1)
3. **PRF** — even if the attacker somehow gets through, inversion is impossible

None of the three is breached. The PRF is not even reached.

See [SCIENCE.md Section 2.9.1](SCIENCE.md#291-byte-splitting-property-78-non-alignment), [SECURITY.md Section 8](SECURITY.md#8-byte-splitting-property).

## 7. Full KPA: The Only Theoretical Threat (Requires Invertible Hash)

Full KPA (the attacker knows the entire plaintext) is the only scenario where the barrier can be bypassed — but only with an invertible hash function:

| Condition | Result |
|---|---|
| Full KPA + invertible hash | ~56 × P inversions → **seed recovered** (barrier intact, hash inverted) |
| Full KPA + PRF (non-invertible) | Inversion impossible → brute-force P × 2^(2×keyBits) (Core ITB) or P × 2^keyBits (MAC + Reveal) |

The attack: the attacker takes any pixel → 56 candidates (8 noisePos × 7 rotation) → computes candidate dataHash → **inverts** ChainHash → gets candidate dataSeed → verifies on a second pixel.

With PRF: the same 56 candidates, the same candidate dataHash values. But inverting ChainHash is impossible — PRF by definition. The only path: brute-force all seeds (P × 2^(2×keyBits) for Core ITB, P × 2^keyBits for MAC + Reveal).

Non-invertibility is the sole wall. The barrier protects against passive observation. Byte-splitting blocks partial KPA. But under Full KPA + invertible hash, none of this helps — the attacker knows all bytes, does not need byte analysis, only needs inversion. PRF forbids this.

## 8. CCA: Reveals Only Noise, Not Data

Under CCA (bit-flip with MAC reveal), the attacker learns noise positions — which bit in each channel is noise (3 bits per pixel from noiseSeed). But due to triple-seed isolation:

- **noiseSeed config** — revealed via CCA
- **dataSeed config** (rotation + 56 XOR bits) — completely independent, zero leak
- **startSeed** (pixel offset) — completely independent, zero leak

With CCA, the candidate count drops from 56 (8 noisePos × 7 rotation) to 7 (only rotation unknown). But 7 candidates do not help without invertible hash — the attacker cannot verify which of the 7 is correct without inverting ChainHash.

**What the attacker gets after removing noise bits.** CCA lets the attacker strip noise bits and see 7 data bits per channel. But "clean encrypted data" is a misleading description. These data bits contain a mixture of encrypted plaintext (COBS-encoded) **and** encrypted CSPRNG fill — both encrypted identically by dataSeed (rotation + XOR). The container is always over-sized relative to the payload: the `side += barrierFill` construction (`SetBarrierFill`, default 1) guarantees at least (2s+1)×7 bytes of CSPRNG fill (≥203 bytes at 1024-bit key). Perfect fill — zero CSPRNG bytes — is mathematically impossible ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)).

This means CCA does not give the attacker a clean plaintext-only ciphertext. A portion of the data bits carry random CSPRNG fill that is indistinguishable from encrypted plaintext. The attacker does not know where the plaintext ends and the fill begins, does not know the fill content, and cannot separate one from the other without the correct dataSeed. The information-theoretic barrier is partially preserved within the data channel itself: ambiguity from CSPRNG residue persists even after noise removal.

CCA leak = 3/62 ≈ 4.8% of per-pixel configuration. CCA reveals no plaintext bits, no XOR masks, no start pixel. However, CCA eliminates noiseSeed from brute-force search: P × 2^(2×keyBits) → P × 2^keyBits (two seeds → one seed). The remaining security (P × 2^keyBits ≈ 2^1033 at 1024-bit, P=400) is still far beyond the Landauer limit (~2^306).

See [SECURITY.md Section 6](SECURITY.md#6-cca-oracle-leak-comparison), [SCIENCE.md Section 4.1–4.5](SCIENCE.md#41-chosen-ciphertext-attack-and-mac-composition), [Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill).

## 9. startPixel: Not Transmitted, Not Recoverable

startPixel is computed from startSeed + nonce via ChainHash. It is not transmitted, not stored, computed in a register once. The only theoretical way to learn it is a cache side-channel (Flush+Reload, Prime+Probe) by a co-located attacker on the same CPU.

Even in the worst case (Full KPA + CCA + cache side-channel), the attacker gets: noisePos + startPixel + 7 rotation candidates. Without invertible hash — brute-force 2^keyBits.

See [SCIENCE.md Section 4, startPixel limitation](SCIENCE.md#known-theoretical-threats).

## 10. Why the Barrier Is Not Broken by KPA Candidates

A common question: if the attacker with known plaintext can compute 56 candidate hash outputs per pixel, doesn't that mean the barrier failed to absorb the hash output?

No. The barrier is intact. Here is why:

**What the barrier guarantees ([Theorem 1](PROOFS.md#proof-1-information-theoretic-barrier)):** for any observed byte value v and any hash output h, the probability P(v | h) = 1/2. This holds even under Full KPA — because the noise bit comes from the original container (CSPRNG), which is random and independent of everything. The observation does not uniquely determine the hash output. This is information theory, not computational assumption.

**What the attacker computes:** the 56 candidates are not extracted from the observation. They are **calculated** from the combination of (known plaintext + observed byte + candidate config). This is arithmetic, not a barrier break. All 56 candidates are **equally consistent** with the observation — the attacker does not know which one is real.

**Without hash inversion (PRF):** 56 candidates per pixel × P pixels = 56^P total combinations. For P = 196 (1024-bit key, Encrypt/Stream): 56^196 ≈ 2^1138. The attacker cannot verify any candidate without inverting ChainHash. PRF makes inversion impossible. The ambiguity is preserved.

**With hash inversion (invertible hash):** the attacker takes each candidate, inverts ChainHash → gets candidate seed → verifies on another pixel. Inversion **bypasses** the ambiguity. The barrier is not broken — ChainHash is inverted.

The barrier absorbs the hash output through two independent mechanisms: (1) noise absorption — CSPRNG noise bit at unknown position makes the byte ambiguous; (2) encoding ambiguity — 7 rotation candidates per pixel create 7^P unverifiable combinations. An additional structural property reinforces the barrier after CCA: (3) CSPRNG residue — guaranteed fill bytes encrypted by dataSeed within the data channel, indistinguishable from encrypted plaintext ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)). CCA (MAC + Reveal) can bypass mechanism (1) by revealing noise positions, but mechanism (2) and property (3) remain intact through triple-seed isolation. The noise bits are removed, but the data bits still contain CSPRNG fill that the attacker cannot separate from plaintext — the information-theoretic barrier is never fully eliminated. KPA candidates are ambiguity, not leakage. PRF preserves this ambiguity. Invertible hash resolves it — but that is a hash function failure, not a barrier failure.

## 11. Quantum Resistance

The barrier works strictly by information theory: the observation does not contain information about the hash output. This property is **computation-model-independent** — it does not depend on whether the attacker uses a classical computer, a quantum computer, or any future computational model. A quantum computer cannot extract information that does not exist in the observation.

This is the fundamental difference between ITB and traditional ciphers. AES and ChaCha20 rely on **computational hardness** — their security degrades if the attacker has more computational power (Grover: √ speedup). ITB's barrier relies on **information absence** — no amount of computation helps when the information is not there.

Specific quantum algorithms and why they are conjectured mitigated:

- **Grover** — requires a verification oracle. Core ITB and MAC + Silent Drop have no external oracle; the attacker must jointly search noiseSeed and dataSeed (without dataSeed, noiseSeed output is indistinguishable from random), while startSeed contributes only P startPixel candidates (enumerated, not brute-forced). Grover complexity: √P × 2^keyBits — at 1024-bit keys (P=196): ~2^1028. With MAC + Reveal: CCA reveals noisePos but not startPixel (independent startSeed). Search: dataSeed (2^keyBits) × P startPixel candidates. Grover: √(P × 2^keyBits) = √P × 2^(keyBits/2), each oracle query costs O(P) — full container decryption. At 1024-bit key (P=400): ~2^516 iterations × O(P) each.
- **Simon** — requires periodic function structure. ITB's config map is aperiodic: each message has a unique 128-bit nonce, creating a completely different configuration.
- **BHT** — requires observable hash collisions. In Core ITB and MAC + Silent Drop: the random container absorbs collisions — two identical hash outputs on different pixels produce different observed bytes (different random container values). After CCA (MAC + Reveal): collisions remain unobservable through encoding ambiguity (7 rotation candidates per pixel — attacker cannot identify which candidates collide).
- **Q2 superposition queries** — requires oracle that accepts quantum superposition inputs. ITB's MAC oracle is inherently classical: it receives concrete bytes over a network and returns accept/reject. Superposition queries are physically impossible.

At 1024-bit key: Core/Silent Drop (P=196) ~2^2056 classical, ~2^1028 Grover. MAC + Reveal (P=400): ~2^1033 classical, ~2^516 Grover. Both are far beyond any foreseeable quantum capability. For comparison, AES-256 with Grover: 2^128 — widely considered quantum-resistant.

See [SECURITY.md Section 16](SECURITY.md#16-quantum-resistance-conjectured), [SCIENCE.md Section 2.11](SCIENCE.md#211-quantum-resistance-analysis), [SCIENCE.md Section 2.9.2 — Why KPA candidates do not break the barrier](SCIENCE.md#292-why-kpa-candidates-do-not-break-the-barrier).

## 12. Per-Candidate Cost: Why Brute-Force Is Slow

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

## 13. Barrier and PRF: Symbiosis

The barrier and PRF hash function protect each other:

- **PRF protects the barrier:** non-invertibility prevents the attacker from resolving the 56-candidate ambiguity under KPA. Without inversion, the barrier's information-theoretic protection holds — the attacker cannot verify which candidate is real.

- **Barrier protects the PRF:** hash collisions are the only theoretical weakness of a non-invertible hash function — two different inputs producing the same output. In a traditional cipher, collisions may be exploitable because the attacker observes the output directly. In ITB, collisions are invisible: two pixels with the same dataHash have different original container bytes (CSPRNG), so the observed bytes are different. The collision is absorbed.

Together: non-invertibility blocks inversion, and absorption hides collisions. Each property closes the other's theoretical weakness. In core ITB and MAC + Silent Drop (no oracle, passive observation only), the barrier makes a non-invertible hash function indistinguishable from an ideal random function — collisions absorbed, statistical patterns absorbed, no known attack surface remains. With MAC + Reveal (CCA): noiseSeed config is leaked via oracle interaction, but dataSeed remains protected by PRF non-invertibility and triple-seed isolation. Additionally, even after noise removal, the data channel retains CSPRNG fill bytes encrypted by dataSeed — perfect fill is impossible ([Proof 10](PROOFS.md#proof-10-guaranteed-csprng-residue-no-perfect-fill)), so information-theoretic ambiguity persists within the data bits themselves.

See [SCIENCE.md Section 2.4](SCIENCE.md#24-information-theoretic-barrier-and-hash-requirements).
