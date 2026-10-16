## ITB Broken Primitives Walkthrough

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB composes established, standardized primitives rather than introducing new cryptographic designs. Security properties and regulatory status are inherited from the underlying primitives; see [README.md](README.md) for jurisdictional certification details.

This document is an analytical and empirical companion to [REDTEAM.md](REDTEAM.md), [SCIENCE.md](SCIENCE.md), and [PROOFS.md](PROOFS.md). It evaluates how the shipped **Triple Ouroboros** and **Interlocked Barrier** architecture behaves when instantiated with deliberately broken, non-cryptographic hash functions across two distinct regimes:

1. **Total PRF Failure and Inversion (`nullHash`, `quadHash`, `trainHash`):** 8-bit-per-lane toy functions whose state width falls below the structural floor required to populate the **Pixel Barrier** (59 `DataConfigBits` per pixel) and the **Rank Barrier** (128-bit rank input). In this regime, both barriers are starved of entropy and total key/plaintext recovery is achieved.
2. **Full-Width Algebraic Stress Controls (`jokeHash`, `CRC128`, `FNV-1a`):** 64-bit-per-lane (128-bit total) functions that populate all barrier bit-fields so the observation channel is closed on the wire, testing whether primitive invertibility (`GF(2)`-linearity in `CRC128`, T-function carry structure in `FNV-1a` and `jokeHash`) can penetrate the barrier without out-of-band leaks.

---

## Total PRF Failure and Inversion (`nullHash`, `quadHash`, `trainHash`)

When a primitive outputs only 8 bits per lane (`lo, hi < 256`) instead of a full 64-bit word per lane, total PRF failure occurs across both barriers simultaneously:

- **Pixel Barrier starvation (7-of-8 channel unmask):** Each pixel consumes 59 bits of `dataHash` (`3` bits for the mod-7 rotation and `8 × 7 = 56` bits for the eight `channelXOR` masks). An 8-bit `dataHash` supplies only the 3-bit rotation and a 5-bit mask on channel 0, leaving **channels 1..7 completely unmasked** (`channelXOR = 0`).
- **Rank Barrier starvation (`2^16` rank collapse):** `splitRank48(lo, hi)` expects a 128-bit PRF output to draw from `C(48, 16) · C(32, 16) ≈ 2^70.20` mask triples. When `lo` and `hi` are 8-bit bytes, at most `2^16 = 65,536` mask triples are reachable.
- **Seed truncation:** Masking each 64-bit seed word with `& 0xFF` discards 56 of every 64 key bits before the first round begins.

The three questions below trace how total PRF failure manifests across linear cancellation (`nullHash`), non-bijective squaring collapse (`quadHash`), and bijective affine iteration (`trainHash`).

---

## Question 1 — What happens under `nullHash` (linear identity collapse)?

```
nullHash(data, seed0, seed1):
    d = data[0] if len(data) > 0 else 0
    return (d ^ (seed0 & 0xFF), d ^ (seed1 & 0xFF))
```

### Analytical mechanism

`nullHash` reads only `data[0]` and the low byte of each seed word. Under `Seed128.ChainHash128`'s four-round cascade at 512-bit key width, `data[0]` is XORed an even number of times and cancels identically. The cascade output `(hLo, hHi)` degenerates to a static per-seed 16-bit constant that is independent of the pixel counter, chunk index, and nonce. Every encoder decision becomes constant across the entire message.

### Empirical measurement

Attack code: `redteam_nullhash_attack_test.go` (`//go:build redteam`), 512-byte plaintext, 25×25 = 625-pixel container, fresh CSPRNG seeds per run.

| Threat model | Wall-clock | Recovery |
|---|---|---|
| Full KPA + `startPixels` given | ~285 ms | 100% unique recovery |
| Crib KPA (48 B) + `startPixels` given | ~315 ms | 100% unique recovery |
| Crib KPA (48 B) + `startPixels` brute (`208^3` enumeration) | ~1.25 s | 100% unique recovery |
| Ciphertext-only (2 wires) + content-agnostic COBS gate | ~2.9 s | 100% plaintext recovery (~256 functionally equivalent `lockSeed` low bytes) |

Under any **Full KPA** or 48-byte **Crib KPA**, recovery is unique. Even under a pure **ciphertext-only attack (COA)** on two wires, the COBS framing gate recovers `noisePos`, all three `startPixels`, all three `dataSeed` low bytes, and the high byte of `lockSeed`. Across all 65,536 candidate lock constants, the **Rank Barrier** produces the exact same lane bytes per region under `nullHash`, so all surviving candidates decrypt to the identical true plaintext without a content oracle.

### Reproduction

```bash
go test -tags redteam -run TestRedTeamNullHashAttack -v -count=1 ./
```

### Conclusion

When a primitive's cascade output collapses to a buffer-independent constant, per-chunk and per-pixel independence vanish completely. Both the **Rank Barrier** and the **Pixel Barrier** degenerate to static permutations that are solvable in under 3 seconds even under ciphertext-only observation.

---

## Question 2 — What happens under `quadHash` (non-bijective squaring T-function)?

```
quadHash(data, seed0, seed1):
    lo = seed0 & 0xFF
    hi = seed1 & 0xFF
    for b in data:
        lo = ((lo + b) * (lo + b))     & 0xFF
        hi = ((hi + b) * (hi + b) + 1) & 0xFF
    return (lo, hi)
```

### Analytical mechanism

Unlike `nullHash`, `quadHash` absorbs every byte of the input buffer nonlinearly. However, squaring modulo 256 is non-bijective (`(x + b)^2` collides on opposite signs) and erases one bit of any even seed difference per input byte: whenever two states share the same low `k` bits (`k >= 1`), adding a byte `b` and squaring modulo 256 shifts their difference up by at least one bit position, so they share at least `k + 1` low bits after the step. After 7 input bytes, bits `1..7` of the initial seed byte are completely erased modulo 256, leaving only bit 0 (`(x + b)^2 == x ^ b mod 2`).

Since every ITB domain buffer is at least 13 bytes long (`13 B` for `lockBuf`, `17 B` for `startBuf` and `ilNonceBuf`, `20 B` for `pixelBuf`), the 4-round `ChainHash128` cascade collapses every 512-bit seed to at most **1 parity bit in `lo`** (`(s0 ^ s2 ^ s4 ^ s6) & 1`) and **1 parity bit in `hi`** (`(s1 ^ s3 ^ s5 ^ s7) & 1`):

- **`lockSeed` has 0 effective bits:** `deriveInterLockSeed` (4 rounds) followed by `fillRanks` (4 component rounds) XORs the `lockSeed` parity bits twice, cancelling both modulo 2. Every 512-bit `lockSeed` behaves identically to the all-zero `lockSeed`.
- **Pixel counters cancel modulo 2:** In `pixelBuf = [LE32(counter) || mainNonce]` (20 bytes), the 4-byte counter is absorbed 4 times before the 16-byte `mainNonce` tail (rounds 1..3 plus the first 4 bytes of round 4), cancelling its parity modulo 2 while the 16-byte `mainNonce` tail erases bits `1..7`. Consequently, `dataHash` and `noisePos` are constant across all pixels of a message.
- **Total session key space is 256 states (`2^8`):** Across all 8 seeds (`noiseSeed`: 2 bits, `lockSeed`: 0 bits, `dataSeed_1..3`: 1 bit each, `startSeed_1..3`: 1 bit each), the entire 4,096-bit (8 × 512-bit) constellation collapses to **8 universal parity bits**.

### Empirical measurement

Attack code: `redteam_quadhash_single_test.go` (`TestRedTeamQuadHashSingleMessage`) and `redteam_quadhash_multimsg_test.go` (`TestRedTeamQuadHashMultiMessage`), 512-byte plaintexts across `ascii`, `json`, and uniform random `binary` corpora (0/8 seeds granted, 0 `startPixels` granted).

| Solver mode | Corpus | Sample size | Mean `Decrypt3x128Cfg` trials | Wall-clock | Recovery (`Decrypt3x128Cfg` + SHA-256) |
|---|---|---|---|---|---|
| **Single-message solver** (fresh 8 seeds per message, 48 B Crib KPA) | `ascii` | 1,000 msgs | 1.02 / msg | ~0.28 s (0.28 ms/msg) | **1,000 / 1,000 (100.00%)** |
| **Single-message solver** (fresh 8 seeds per message, 48 B Crib KPA) | `json` | 1,000 msgs | 1.02 / msg | ~0.31 s (0.31 ms/msg) | **1,000 / 1,000 (100.00%)** |
| **Single-message solver** (fresh 8 seeds per message, 48 B Crib KPA) | `binary` | 1,000 msgs | 1.02 / msg | ~0.29 s (0.29 ms/msg) | **1,000 / 1,000 (100.00%)** |
| **Multi-message `8xEquivSeeds` solver** (20 sessions × 50 msgs, 128 B Crib KPA on anchor msgs) | `ascii` | 1,000 msgs | 8.00 / session | ~0.43 s | **1,000 / 1,000 (100.00%)** |
| **Multi-message `8xEquivSeeds` solver** (20 sessions × 50 msgs, 128 B Crib KPA on anchor msgs) | `json` | 1,000 msgs | 8.00 / session | ~0.45 s | **1,000 / 1,000 (100.00%)** |
| **Multi-message `8xEquivSeeds` solver** (20 sessions × 50 msgs, 128 B Crib KPA on anchor msgs) | `binary` | 1,000 msgs | 8.00 / session | ~0.44 s | **1,000 / 1,000 (100.00%)** |

Walking the per-region COBS pointer chain to the first `0x00` delimiter (accounting for the per-region `interlock nonce` prefix `lens[r]`, the 4-byte length prefix inside chunk 0, and any `0xFF` 254-byte COBS group overhead shifts) and matching the decoded lane length across all three regions filters each region's `(dataSeed_r, startSeed_r)` candidates independently before invoking `Decrypt3x128Cfg`. In the single-message solver, an average of **1.02 `Decrypt3x128Cfg` calls per message** suffices to recover the full 512-byte plaintext across 1,000 freshly keyed messages per corpus. In the multi-message session solver, pinning the 8-bit universal equivalence class yields 8 valid `*Seed128` objects that decrypt every message in the session via `Decrypt3x128Cfg` with 100% SHA-256 verification.

### Reproduction

```bash
go test -tags redteam -run TestRedTeamQuadHashSingleMessage -v -count=1 ./
go test -tags redteam -run TestRedTeamQuadHashMultiMessage -v -count=1 ./
```

### Conclusion

Non-bijective iteration over a narrow state collapses seed entropy exponentially fast with buffer length. Under `quadHash`, squaring modulo 256 erases bits `1..7` of every seed component within 7 bytes, reducing all 8 512-bit seeds to an 8-bit universal equivalence class that is inverted with 100% accuracy in under a millisecond per message.

---

## Question 3 — What happens under `trainHash` (8-bit bijective affine T-function)?

```
trainHash(data, seed0, seed1):
    lo = seed0 & 0xFF
    hi = seed1 & 0xFF
    for b in data:
        lo = ((lo + b) * 3 + 1) & 0xFF
        hi = ((hi + b) * 5 + 7) & 0xFF
    return (lo, hi)
```

### Analytical mechanism

Because 3 and 5 are odd, multiplication modulo 256 is a bijection: `trainHash` does not suffer from `nullHash`'s XOR cancellation or `quadHash`'s squaring collapse, and its output varies across every pixel and chunk. Instead, `trainHash` fails through **8-bit lane starvation combined with end-to-end affine linearity modulo 256**:

1. **Affine per-round structure and MSB gauge symmetry:** Over any buffer of length `n`, a single round of `trainHash` is an affine map `a * s + c (mod 256)` in the low seed byte, where the odd multiplier `a` (`3^n` or `5^n` mod 256) and constant `c` (`trainHash(buf, 0, 0)`) are publicly computable from the buffer. Across the 4-round `ChainHash128` cascade, flipping bit 7 (`0x80`) of round key `k[r]` shifts that round's output by `128 mod 256` (also flipping bit 7), which cancels if bit 7 of `k[r+1]` is flipped at the same time. This 8-fold (`2^3`) MSB gauge symmetry reduces every 4-byte cascade lane key from 32 bits to **29 effective bits**.
2. **Cross-region band joining:** Because `dataHash` is only 8 bits wide, channels 1..7 of every pixel carry `channelXOR = 0`. A 128-byte (25%) **Crib KPA** prefix spans the first 22 48-bit **Rank Barrier** chunks (walk bands `w = 1..6`). Joining candidate pixel readings across all three regions against the 65,536 (`2^16`) reachable rank masks uniquely determines `startPixel_0..2`, per-pixel rotations and noise positions on the crib bands, and the per-chunk 16-bit ranks.
3. **Multi-message recovery of all 8 seeds (including `noiseSeed`):**
   - `startSeed_0..2` (`lo` lanes) are pinned across 3 messages via 2-round meet-in-the-middle (`tcSolveLane4Canonical`).
   - `lockSeed` (`lo` and `hi` lanes) is recovered on the first clean message via parallel differential meet-in-the-middle over the 256 interlock-nonce fold shifts (`tcSolveLaneFoldParallel`), and subsequent messages resolve in milliseconds using the pinned 4-byte `lockSeed` suffixes.
   - `dataSeed_0..2` (`lo` lanes) are pinned across 2–4 messages from channel-0 XOR observations on the crib bands.
   - `noiseSeed` (`lo` and `hi` lanes) is recovered without any plaintext model via **`cHi`-collision correlation** across a 50-message session (`tcSolveNoiseSeedFromBins`): grouping crib-band pixel observations that share the same public `cHi` byte freezes the `hi` lane output within each bin, decoupling the `lo` lane search from the `hi` lane search.

### Empirical measurement

Attack code: `redteam_trainhash_multimsg_test.go` (`TestRedTeamTrainHashMultiMessage`), 50-message session per corpus, 512-byte plaintexts, 128-byte (25%) **Crib KPA** prefix, 0/8 seeds granted, 0 `startPixels` granted, zero plaintext model (`ascii`, `json`, and uniform random `binary` execute the identical code path).

| Corpus | Session size | Crib KPA | Seeds recovered (`SeedFromComponents128`) | Unknown 75% bytes recovered | `Decrypt3x128Cfg` SHA-256 match | Wall-clock (8 cores) |
|---|---|---|---|---|---|---|
| `ascii` | 50 msgs (512 B) | 128 B (25%) | **8 / 8 seeds** (`ns`, `ls`, `d1..d3`, `s1..s3`) | **19,200 / 19,200 (100.00%)** | **50 / 50 (100.00%)** | ~4.0 s |
| `json` | 50 msgs (512 B) | 128 B (25%) | **8 / 8 seeds** (`ns`, `ls`, `d1..d3`, `s1..s3`) | **19,200 / 19,200 (100.00%)** | **50 / 50 (100.00%)** | ~4.5 s |
| `binary` | 50 msgs (512 B) | 128 B (25%) | **8 / 8 seeds** (`ns`, `ls`, `d1..d3`, `s1..s3`) | **19,200 / 19,200 (100.00%)** | **50 / 50 (100.00%)** | ~4.0 s |

Once all 8 truncated `*Seed128` instances are reconstructed via `SeedFromComponents128`, passing them directly to the standard `Decrypt3x128Cfg` decoder decrypts all 50 messages of the session (including uniform random `binary` plaintexts where no byte-level plaintext model exists) with 100% SHA-256 verification.

### Reproduction

```bash
go test -tags redteam -run TestRedTeamTrainHashMultiMessage -v -count=1 ./
```

### Conclusion

Preventing cascade collapse via a bijective step (`× 3 + 1`, `× 5 + 7` mod 256) is insufficient when the primitive's lane width (`8` bits) starves the **Pixel Barrier** and **Rank Barrier**. Because 7 of 8 pixel channels remain unmasked, the rank space collapses to 65,536 states, and each 4-round seed lane carries only 29 effective bits, a 50-message session under 25% **Crib KPA** yields complete recovery of all 8 session seeds and 100% bit-exact decryption across any plaintext distribution.

---

## Full-Width Algebraic Stress Controls (`jokeHash`, `CRC128`, `FNV-1a`)

The remaining three questions evaluate primitives whose output width populates all 64 bits per lane, closing both the 7-of-8 channel leak and the `2^16` rank-space collapse.

---

## Question 4 — What if a three-line 64-bit `jokeHash` is evaluated?

```
jokeHash(data, seed0, seed1):
    lo = seed0
    for b in data: lo = lo*257 + b
    return (lo, ~lo)
```

`jokeHash` belongs to the T-function class (Klimov and Shamir 2002): output bit `t` depends only on input bits at positions `<= t`, so a single `(data, h)` observation pair is invertible plane-by-plane in polynomial time. Unlike `trainHash`, `jokeHash` operates on the full 64-bit word (`uint64`) rather than truncating to `& 0xFF`.

### Why widening from 8 bits to 64 bits closes the direct solver paths

Widening the lane accumulator from 8 bits to 64 bits closes every reduction step that enabled the `nullHash`, `quadHash`, and `trainHash` solvers:

1. **All 8 pixel channels are masked (`channelXOR != 0`):** Because `lo` is 64 bits wide, all 59 `DataConfigBits` (`3` rotation bits + `56` XOR mask bits across channels 0..7) are populated on every pixel. The 7-of-8 unmasked channel leak disappears.
2. **Full 256-bit even-component seed key:** Although `jokeHash` ignores `seed1` (returning `hi = ^lo`), the four even-indexed seed words (`Components[0, 2, 4, 6]`) contribute 256 bits per seed role rather than 29 bits.
3. **No `2^16` rank table:** The **Rank Barrier** draws from 64-bit `(lo, ^lo)` pairs across 86 distinct chunk masks per 512-byte message rather than a 65,536-entry table, and the interlock nonce is no longer reducible to a 1-byte shift.
4. **Opaque composition on the wire:** Every hash output is consumed inside the encoder before reaching the wire:
   - `noiseSeed` drives `noiseFold3(h[0] + rotl64(h[1], 1))` to select `noisePos` (`8/8` positions populated even under `hi = ^lo`, because addition with `rotl64(^lo, 1)` induces data-dependent carries).
   - `dataSeed_i` supplies per-pixel rotation and 56-bit `channelXOR`.
   - `lockSeed` derives per-chunk 128-bit ranks passed through combinadic unrank and `PEXTQ` (`chunk48lock`) into three 16-bit lane fragments before **Pixel Barrier** encoding.

Without a known-lane anchor at the **Pixel Barrier**, all 56 `(noisePos, rotation)` readings per pixel remain equiprobable ([Proof 1](PROOFS.md#proof-1-information-theoretic-barrier)), leaving `jokeHash`'s T-function invertibility with no clean `(input, output)` pair to invert. Only lab-only concessions (such as granting 7 of 8 seeds out-of-band or introducing a side channel that leaks raw `ChainHash` outputs) expose a surface where T-function inversion can engage.

### Empirical corroboration at N = 10,000

`TestRedTeamJokeHashRepeatPlaintextCPA` and `TestRedTeamJokeHashVaryingPlaintextCPA` in `redteam_jokehash_test.go` execute 10,000 fresh-nonce encryptions with `jokeHash` on all eight seed roles (0/8 seeds granted):

- **Roundtrip:** All 10,000 ciphertexts are unique and roundtrip-exact (including an 18 KB multi-chunk message).
- **Byte-value chi² across five sampled wire positions:** `218.4, 246.3, 258.3, 267.5, 297.8` (`df = 255`, uniform band `255 ± 22.6`, 3σ top `≈ 323`).
- **Per-byte bit fixation (`|p(bit=1) - 0.5| > 0.15`):** 9,896 container body bytes have 0 fixed bits; only the 4 public dimension bytes (`W`, `H`) are fixed.
- **Repeat-plaintext vs varying-plaintext delta:** Identical hot-bit histograms across both arms — zero per-byte plaintext fixation.
- **Body-region monobit on 760,000,000 bits:** `p(bit = 1) = 0.500031`, `|z| = 1.69` (well inside the 3σ band).

### Residual bias under repeat-plaintext CPA

While per-pixel plaintext recovery is closed, `jokeHash`'s sparse multiplier (`257 = 0x101`, popcount 2, equivalent to `(x << 8) + x`) leaves the low byte of the state unmixed after each multiply. `TestRedTeamJokeHashHWDistinguisherVsPRF` in `redteam_jokehash_test.go` runs a two-arm repeat-plaintext CPA probe (`N = 2,000` fresh-nonce encryptions of an all-zero 4 KB plaintext vs a fixed random 4 KB plaintext, `152 M` pooled body bits) across `jokeHash`, `CRC128`, `FNV-1a`, and `SipHash-2-4`:

| Primitive | Zeros arm \|z\| | Random arm \|z\| | Homogeneity chi² (`df = 255`) |
|---|---|---|---|
| `jokeHash` (multiplier `257 = 0x101`, popcount 2) | **≈ 3 – 64** | ≈ 0.1 – 2.6 | **≈ 1,200 – 7,500** |
| `CRC128` (GF(2)-linear) | ≈ 0.1 – 3.8 | ≈ 0.1 – 1.7 | ≈ 218 – 316 |
| `FNV-1a` (T-function, prime `0x100000001b3`) | ≈ 0.3 – 10.6 | ≈ 0.1 – 1.8 | ≈ 210 – 358 |
| `SipHash-2-4` (PRF control) | ≈ 0.2 – 1.4 | ≈ 0.1 – 1.8 | ≈ 220 – 313 |

Because `257 = 0x101` has virtually no upward bit diffusion, `jokeHash`'s raw output distribution is measurably biased, `channelXOR` inherits ~1% of that bias, and pooling ~2,000 encryptions of the same low-Hamming-weight plaintext shifts the aggregate wire monobit by `≈ 10^-3`. This aggregate bias does not localize to individual pixels or recover plaintext bytes, but it acts as a repeat-plaintext Hamming-weight distinguisher when avalanche diffusion is absent. Well-diffused primitives (including `CRC128` and all shipped registry primitives) remain inside the uniform band.

### Empirical reduction-closure verification

Attack code: `redteam_jokehash_fullkpa_test.go` (`TestRedTeamJokeHashFullKPA`), 512-byte plaintext, 25×25 container.

| Reduction path | `nullHash` (8-bit collapsing) | `jokeHash` (64-bit non-collapsing) |
|---|---|---|
| Effective key bits per seed role | 16 (per-seed constant) | 256 (four even 64-bit components engaged) |
| Distinct `dataHash` outputs across `N = 1,000` pixels | 1 | 1,000 / 1,000 (`noisePos` spread `8/8`, rotation spread `7/7`) |
| Distinct mask triples across 86 chunks | 1 | 86 / 86 |
| Pixel Barrier known-plaintext under Full KPA | Open (channels 1..7 unmasked, constant lock) | Closed (all 8 channels masked; lanes locked by 256-bit `lockSeed` via combinadic unrank) |

### Reproduction

```bash
go test -tags redteam -run TestRedTeamJokeHash -v -count=1 ./
go test -tags redteam -run TestRedTeamJokeHashFullKPA -v -count=1 ./
```

---

## Question 5 — `CRC128` is GF(2)-linear: does compound-key linear algebra break ITB?

Given a direct hash-output observation `h = H(data, seed)`, `CRC128` (two independent keyed CRC64 lanes, ECMA and ISO) is invertible in polynomial time via Gaussian elimination over GF(2):

```
seed = M_L^{-1} · (h XOR const(0))
```

On a **single-region, barrier-off control encode** (`scripts/redteam/itb/theory/crc128/compound_key_crc128.py`), the `ChainHash128` cascade reduces to a single affine equation per pixel:

```
hLo(p) = K XOR const(data(p))
```

where `K` is a pixel-independent 64-bit compound key and `const(data(p))` is publicly computable from the pixel index and nonce (`ChainHash128` with `seed = 0`). In that unshielded single-region control, linear algebra recovers `K` directly and reconstructs `channelXOR` across future messages. Under an active **MAC + Reveal (Reject)** chosen-ciphertext oracle ([REDTEAM.md — CCA](REDTEAM.md#cca--noise-position-oracle)), where **MAC Authenticated** mode places the MAC inside the container and an exposed accept/reject oracle reveals whether flipping a wire bit hit the per-pixel noise bit (accept) or a data channel (reject), an attacker can observe the physical noise positions `obs_i[j]` of each region. On an unshielded control layout where each region's noise counter starts at `0` or where the 3-bit fold is purely GF(2)-linear, those `obs_i[j]` arrays reveal the unknown per-region `startPixel_i` offsets on a single message. In the shipped construction, `noiseCounterBase` (`i * third + p`) prevents cross-region alignment of `obs_i[j]`, and `noiseMix(word0, word1) = word0 + rotl64(word1, 1)` combines the two 64-bit words via integer addition before `noiseFold3`, breaking the single-message GF(2)-linear split for `CRC128` (`0 / 30` in `TestRedTeamNoisePosCCA`). This also inverts the multi-message problem into a circular dependency: under `CRC128`, the position is `noiseFold3((K_lo ⊕ B_lo) + rotl64(K_hi ⊕ B_hi, 1))`, where the zero-seed term `B = (B_lo, B_hi)` at physical pixel `j` depends on the unknown stream index `p = (j - startPixel_i) mod T_i`. Attempting to recover the 128-bit constant `(K_lo, K_hi)` by linear cryptanalysis of the modular-addition carries across `≈ 2^32–2^34` revealed positions (`≈ 2^22–2^24` messages, `≈ 2^35–2^37` oracle queries) requires an out-of-band lab grant of all three `startPixel_i` offsets on every one of those messages just to compute `B` — whereas recovering `(K_lo, K_hi)` would itself yield only noise positions and `startPixel_i` offsets (leaving `dataSeed_i`, DRBG fill, and the **Rank Barrier** intact).

### Why the shipped construction closes passive linear-algebra recovery

In the shipped **Triple Ouroboros** + **Interlocked Barrier** construction under passive observation (**Crib KPA** / **Full KPA** / COA), three architectural layers compose to block compound-key linear algebra:

1. **Triple Ouroboros — three regions with independent `startPixel`s:** The container is partitioned into three regions (`third = W·H / 3`), each walked from an independent secret offset `startPixel_i`. Without enumerating three independent `startPixel` offsets jointly, pixel observations cannot be aligned to stream positions.
2. **Rank Barrier — per-chunk PRF-keyed bit dispersion (`chunk48lock`):** Even if `channelXOR` were recovered on a region, channel bytes do not carry contiguous plaintext bytes. Each 48-bit framed chunk is dispersed via `PEXTQ` under a per-chunk mask triple `(m_0, m_1, m_2)` drawn from `Ω_chunk ≈ 2^70.20` states into three 16-bit lane fragments. Recovering `channelXOR` yields only `PEXT(chunk, m_N)` bits under an unknown per-chunk mask.
3. **Dual-nonce separation:** While `K` in `CRC128` depends on the seed components alone (with `main_nonce` entering only `const(data(p))`), the **Rank Barrier** is re-keyed on every message by a fresh `interlock nonce` (`N_il`). Even under a forced `main_nonce` collision in the lab, fresh `N_il` produces independent per-chunk lane assignments on each message.

### Why a Pixel Barrier compound key `K_data` does not transfer to the Rank Barrier

Even when `CRC128` keys both `dataSeed` and `lockSeed`, five structural boundaries prevent transferring `K_data` to `lockSeed`:

1. **8-seed isolation ([Proof 3](PROOFS.md#proof-3-8-seed-isolation)):** `lockSeed` and `dataSeed_i` are drawn independently from the CSPRNG (`I(lockSeed; dataSeed_i) = 0`). `K_data` is a linear projection of `dataSeed_i` components and shares zero state with `lockSeed`.
2. **Distinct derivation lengths and cascade depth:** `dataSeed` hashes buffers of length `4 + nonceBytes` over 4 rounds (at 512-bit key width), whereas `lockSeed` first derives `K = deriveInterLockSeed(N_il)` over `1 + nonceBytes` (tag `0x04`) and then runs a 5-round cascade over 13-byte chunk blocks `[0x03 ‖ LE64(groupIdx) ‖ v]` (`v` — the 4-byte interlock-nonce fold of `N_il`). Different buffer lengths induce distinct CRC64 state-transfer matrices `M_L`.
3. **Domain separation tags:** Tags `0x04` (interlock key setup), `0x03` (per-chunk rank fill), and `0x02` (`startPixel`) produce distinct affine constants `const(data)`.
4. **No cleartext rank observation:** Per-chunk 128-bit ranks never appear on the wire; they are consumed inside combinadic unrank and `PEXTQ` compression.
5. **Non-linear combinadic unrank ([Proof 12](PROOFS.md#proof-12-gcda-b-anti-collapse-trap)):** Mapping a 128-bit `(lo, hi)` rank into `(idx_0, idx_1)` uses two-step integer division and modulo (`idx_1 = rank mod B`, `idx_0 = ⌊rank / B⌋ mod A` with `B = C(32, 16) = 601,080,390` and `A = C(48, 16) = 2,254,848,913,647`), followed by threshold comparisons `rank >= C(p, k)`. Both steps destroy GF(2)-linearity and avoid the `gcd(A, B) = 66,861` CRT reduction trap.

### Preimage ambiguity (`2^57.80`) across messages

Because the 128-bit rank space (`2^128`) maps onto `Ω_chunk = A · B ≈ 2^70.20` mask triples, each mask triple has either `⌊2^128 / (A · B)⌋` or `⌊2^128 / (A · B)⌋ + 1` rank preimages (`≈ 2^57.80` preimages per mask triple, with per-chunk modular bias `≈ 2^-57.8`). Even if an attacker were granted both the plaintext chunk and the demasked lane fragments in the lab:

1. **Mask ambiguity per chunk:** A 48-bit chunk and its three 16-bit `PEXT` lane fragments leave `≈ 2^22` compatible mask triples out of `2^70.20`.
2. **Rank preimage ambiguity per mask:** Each candidate mask triple corresponds to `≈ 2^57.80` candidate 128-bit ranks.
3. **Cross-message independence ([Proof 11](PROOFS.md#proof-11-48-bit-rank-barrier-mask-space-interlocked-barrier)):** Every message and chunk draws an independent mask. Adding `N` messages adds `N` independent `2^57.80` preimage sets rather than narrowing a single linear system, because Gaussian elimination over GF(2) cannot be formed until the true rank preimage is selected for each chunk (`2^(57.80 · M)` combinations across `M` chunks).

### Reproduction

```bash
go test -tags redteam -run TestRedTeamBrokenCRC128CribKPA -v -count=1 ./
ITB_REDTEAM_NOISEPOS_HASH=crc128 go test -tags redteam -run 'TestRedTeamNoisePosCCA' -v -count=1 ./
```

---

## Question 6 — `FNV-1a` is a 128-bit T-function: does bit-plane lifting break the barrier?

`FNV-1a` updates its 128-bit state via `h = (h XOR byte) * FNV_PRIME (mod 2^128)`. Because multiplication by an odd prime modulo `2^128` propagates carries strictly from low bits to high bits (Klimov and Shamir 2002), output bit `t` depends only on input bits `0..t`. Given a direct `(data, h)` observation pair — or on an unshielded single-region pipeline without the **Rank Barrier** and with `startPixel` disclosed — a bit-vector SAT solver (such as Bitwuzla) can lift the seed plane-by-plane from LSB to MSB.

### Why combinadic unrank blocks T-function bit-plane lifting

In the shipped pipeline, the **Rank Barrier** sits between `FNV-1a` and the **Pixel Barrier**:

```
lockKey      = ChainHash(0x04 ‖ N_il, lockSeed)
prf_i        = ChainHash(0x03 ‖ LE64(groupIdx) ‖ v, lockComps)
(m0, m1, m2) = combinadic_unrank(prf_i)                     ← breaks T-function structure
lane_N       = PEXT(chunk_48, m_N)                          ← 48 → 16 bit compression
wire         = PixelBarrierEncode(lane_N, dataSeed, ...)
```

While `FNV-1a` preserves T-function triangularity through `ChainHash`, combinadic unrank breaks T-function structure in three ways simultaneously:

1. **Two-step non-power-of-two divmod ([Proof 12](PROOFS.md#proof-12-gcda-b-anti-collapse-trap)):** Computing `rank mod B` and `⌊rank / B⌋ mod A` with non-power-of-two constants `B = C(32, 16)` and `A = C(48, 16)` mixes high bits back into low bits. Output bit `t` depends on input bits both above and below `t`.
2. **Magnitude comparisons in the combinadic loop:** Selecting combination bits via `if rank >= C(p, k) { rank -= C(p, k) }` depends on the full integer magnitude of `rank` (most-significant bit first), which is the opposite of LSB-to-MSB T-function propagation.
3. **Many-to-one preimage fan-out (`2^57.80`):** Reversing `mask_triple → rank` fans out to `≈ 2^57.80` preimages per chunk, and `mask_triple` itself is never exposed on the wire (only post-**Pixel Barrier** container bytes are observable).

Consequently, even under the maximum-peek lab regime in [REDTEAM.md § FNV-1a lo-lane SAT](REDTEAM.md#fnv-1a-lo-lane-sat--architecturally-foreclosed) (5 of 8 chains granted and `startPixel_i` disclosed), Bitwuzla fails to recover the true `dataSeed_i` lo lane because the **Rank Barrier** leaves the instance structurally under-determined.

### Reproduction

```bash
go test -tags redteam -run TestRedTeamBrokenFNV1a -v -count=1 ./
ITB_REDTEAM_NOISEPOS_HASH=fnv1a go test -tags redteam -run 'TestRedTeamNoisePosCCA' -v -count=1 ./
```

---

## Closing Note — Why Standard Decomposition Attacks Do Not Apply

Across the full-width stress controls (`jokeHash`, `CRC128`, `FNV-1a`), conventional divide-and-conquer and meet-in-the-middle (MITM) techniques fail to decompose the cipher into independent single-seed subproblems for two structural reasons:

1. **8-seed isolation ([Proof 3](PROOFS.md#proof-3-8-seed-isolation)):** All eight seeds are drawn independently (`I(seed_i; seed_j) = 0` for `i != j`). Partial information about one seed role provides zero algebraic constraints on any other seed role.
2. **Opaque forward composition:** Intermediate states never appear on the wire:
   ```
   plaintext → [lockSeed: Rank Barrier PEXTQ] → lane_bits → [dataSeed × noiseSeed × startSeed: Pixel Barrier] → wire byte
   ```
   To meet at `lane_bits`, backward computation from the wire must strip the **Pixel Barrier** (56 equiprobable readings per pixel without an anchor, [Proof 1](PROOFS.md#proof-1-information-theoretic-barrier)), while forward computation from the plaintext faces `≈ 2^70.20` mask partitions and `≈ 2^57.80` rank preimages per 48-bit chunk ([Proof 11](PROOFS.md#proof-11-48-bit-rank-barrier-mask-space-interlocked-barrier)).

| Technique | Prerequisite | Structural blocker in ITB |
|---|---|---|
| Meet-in-the-middle (MITM) | Observable or predictable intermediate state | `lane_bits` and `rank_i` are unobservable; `2^57.80` preimages per chunk |
| Slide attack | Identical round keys across rounds | `ChainHash` rounds use distinct seed components ([Proof 3b](PROOFS.md#proof-3b-chainhash-full-component-utilization)) |
| Related-key attack | Algebraic relation between keys | All 8 seeds are enforced pairwise-distinct at the API |
| Boomerang / differential | Composable differential trails through rounds | Combinadic unrank + `PEXTQ` + random container bits break trail composition |
| Linear cryptanalysis | Linear input-to-output approximation | **Pixel Barrier** absorbs output via DRBG noise bit; **Rank Barrier** removes fixed bit positions |

As established in [Proof 4a](PROOFS.md#proof-4a-multi-factor-full-kpa-resistance), **the obstacles are not sub-problems defeated sequentially, but interlocking constraints that must be resolved simultaneously.**

### Residual Risk

The construction has one fundamental assumption boundary: **total PRF failure or starvation of the underlying primitive** (as demonstrated by the 8-bit `nullHash`, `quadHash`, and `trainHash` controls in Questions 1–3). Should any shipped primitive suffer a cryptanalytic break, ITB provides primitive agility via `hashes.Register` and `triple.Register` without altering the wire format or barrier architecture. Formal derivations are provided in [PROOFS.md](PROOFS.md) and empirical harnesses in [REDTEAM.md](REDTEAM.md).

