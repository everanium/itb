# ITB: How the Barrier Works

## 1. The Core Idea: Absorption

The hash output exists — it is computed and determines the pixel configuration. But it is absorbed by a modification of a random container. The observer sees the result: random byte ± modification. The original random byte is unknown → the modification is unknown → the hash output is unrecoverable from observation.

This is not destruction (the hash output is used), not hiding (there is no encryption on top), but absorption — the random container absorbs the hash output. Like dropping a drop of paint into an ocean of random waves — the paint is there, but the observer sees only waves.

This is why the barrier is computation-model-independent: no matter how much computational power the attacker has — the information is not in the observation.

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

1000 transmissions of the same message — 1000 completely independent containers. No correlation between them. Two-time pad is impossible until the birthday bound ~2^64 messages.

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
| **CCA** (chosen ciphertext) | Core ITB without MAC has no oracle at all | No oracle exists |

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
| Full KPA + invertible hash | ~56 × P inversions → seed recovered → **breaks** |
| Full KPA + PRF (non-invertible) | Inversion impossible → brute-force 2^keyBits |

The attack: the attacker takes any pixel → 56 candidates (8 noisePos × 7 rotation) → computes candidate dataHash → **inverts** ChainHash → gets candidate dataSeed → verifies on a second pixel.

With PRF: the same 56 candidates, the same candidate dataHash values. But inverting ChainHash is impossible — PRF by definition. The only path: brute-force 2^keyBits.

Non-invertibility is the sole wall. The barrier protects against passive observation. Byte-splitting blocks partial KPA. But under Full KPA + invertible hash, none of this helps — the attacker knows all bytes, does not need byte analysis, only needs inversion. PRF forbids this.

See [SECURITY.md KPA Attack Feasibility table](SECURITY.md#kpa-attack-feasibility-by-knowledge-level).

## 8. CCA: Reveals Only Noise, Not Data

Under CCA (bit-flip with MAC reveal), the attacker learns noise positions — which bit in each channel is noise (3 bits per pixel from noiseSeed). But due to triple-seed isolation:

- **noiseSeed config** — revealed via CCA
- **dataSeed config** (rotation + 56 XOR bits) — completely independent, zero leak
- **startSeed** (pixel offset) — completely independent, zero leak

With CCA, the candidate count drops from 56 (8 noisePos × 7 rotation) to 7 (only rotation unknown). But 7 candidates do not help without invertible hash — the attacker cannot verify which of the 7 is correct without inverting ChainHash.

CCA leak = 3/62 ≈ 4.8% of per-pixel configuration. The practical value of this leak is zero: no plaintext bits, no XOR masks, no start pixel, no key-space reduction.

See [SECURITY.md Section 6](SECURITY.md#6-cca-oracle-leak-comparison), [SCIENCE.md Section 4.1–4.5](SCIENCE.md#41-chosen-ciphertext-attack-and-mac-composition).

## 9. startPixel: Not Transmitted, Not Recoverable

startPixel is computed from startSeed + nonce via ChainHash. It is not transmitted, not stored, computed in a register once. The only theoretical way to learn it is a cache side-channel (Flush+Reload, Prime+Probe) by a co-located attacker on the same CPU.

Even in the worst case (Full KPA + CCA + cache side-channel), the attacker gets: noisePos + startPixel + 7 rotation candidates. Without invertible hash — brute-force 2^keyBits.

See [SCIENCE.md Section 4, startPixel limitation](SCIENCE.md#known-theoretical-threats).

## 10. Why the Barrier Is Not Broken by KPA Candidates

A common question: if the attacker with known plaintext can compute 56 candidate hash outputs per pixel, doesn't that mean the barrier failed to absorb the hash output?

No. The barrier is intact. Here is why:

**What the barrier guarantees (Theorem 1):** for any observed byte value v and any hash output h, the probability P(v | h) = 1/2. This holds even under Full KPA — because the noise bit comes from the original container (CSPRNG), which is random and independent of everything. The observation does not uniquely determine the hash output. This is information theory, not computational assumption.

**What the attacker computes:** the 56 candidates are not extracted from the observation. They are **calculated** from the combination of (known plaintext + observed byte + candidate config). This is arithmetic, not a barrier break. All 56 candidates are **equally consistent** with the observation — the attacker does not know which one is real.

**Without hash inversion (PRF):** 56 candidates per pixel × P pixels = 56^P total combinations. For P = 169 (1024-bit key): 56^169 ≈ 2^987. The attacker cannot verify any candidate without inverting ChainHash. PRF makes inversion impossible. The ambiguity is preserved.

**With hash inversion (invertible hash):** the attacker takes each candidate, inverts ChainHash → gets candidate seed → verifies on another pixel. Inversion **bypasses** the ambiguity. The barrier is not broken — ChainHash is inverted.

The barrier absorbs the hash output. KPA candidates are ambiguity, not leakage. PRF preserves this ambiguity. Invertible hash resolves it — but that is a hash function failure, not a barrier failure.

## 11. Quantum Resistance

The barrier works strictly by information theory: the observation does not contain information about the hash output. This property is **computation-model-independent** — it does not depend on whether the attacker uses a classical computer, a quantum computer, or any future computational model. A quantum computer cannot extract information that does not exist in the observation.

This is the fundamental difference between ITB and traditional ciphers. AES and ChaCha20 rely on **computational hardness** — their security degrades if the attacker has more computational power (Grover: √ speedup). ITB's barrier relies on **information absence** — no amount of computation helps when the information is not there.

Specific quantum algorithms and why they are conjectured mitigated:

- **Grover** — requires a verification oracle. Core ITB (no MAC) has no oracle at all. With MAC-inside: each oracle query costs O(P) — full container decryption. At 1024-bit key: 2^512 iterations × O(P) each.
- **Simon** — requires periodic function structure. ITB's config map is aperiodic: each message has a unique 128-bit nonce, creating a completely different configuration.
- **BHT** — requires observable hash collisions. The random container absorbs collisions — two identical hash outputs on different pixels produce different observed bytes (different random container values).
- **Q2 superposition queries** — requires oracle that accepts quantum superposition inputs. ITB's MAC oracle is inherently classical: it receives concrete bytes over a network and returns accept/reject. Superposition queries are physically impossible.

At 1024-bit key: 2^512 Grover. At 2048-bit key: 2^1024. Both are far beyond any foreseeable quantum capability. For comparison, AES-256 with Grover: 2^128 — widely considered quantum-resistant.

See [SECURITY.md Section 16](SECURITY.md#16-quantum-resistance-conjectured), [SCIENCE.md Section 2.11](SCIENCE.md#211-quantum-resistance-analysis).
