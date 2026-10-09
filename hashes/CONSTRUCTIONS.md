## ITB Hash Constructions

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB composes established, standardized primitives rather than introducing new cryptographic designs. Security properties and regulatory status are inherited from the underlying primitives; see [README.md](../README.md) for jurisdictional certification details.

This document describes how each PRF-grade primitive in the registry is wrapped before it reaches `itb.HashFunc{128|256|512}`. Several wrappers diverge from the canonical RFC / NIST form of the underlying primitive in deliberate, documented ways. The names in `registry.go` (`aescmac`, `chacha20`, `blake2b256`, etc.) are short identifiers, **not** assertions of conformance with the RFC / NIST specification of the same name.

Audience: external auditors, paper reviewers, downstream integrators reading the code wanting to know what is actually computed when ITB calls into one of these primitives.

For RFC / NIST primitive math conformance, refer to the upstream library tests:

- `third/goaes` (an in-module subset of `github.com/jedisct1/go-aes` v0.1.1 carrying the SoEM22 patch; see its README) — Areion paper vectors and the SoEM22 known answers.
- `golang.org/x/crypto/blake2b` — RFC 7693 vectors.
- `golang.org/x/crypto/blake2s` — RFC 7693 vectors.
- `github.com/zeebo/blake3` — official BLAKE3 reference vectors.
- `crypto/aes` — NIST FIPS-197 AES vectors.
- `github.com/dchest/siphash` — official SipHash test vectors.
- `golang.org/x/crypto/chacha20` — RFC 8439 vectors (the `chacha20` closure carries its own ChaCha20 permutation in `internal/chacha20asm`; the package tests pin it to the upstream `HChaCha20`, to the HChaCha20 vector of draft-irtf-cfrg-xchacha § 2.2.1 and to the upstream block function).

The primitive-math layer is the upstream libraries' responsibility. This document describes the ITB-construction wrapping around those primitives, and `kat_fixed_test.go` (frozen-output vectors) plus `kat_test.go` (Pair-API closure-vs-reference parity across the variable-length matrix) pin that wrapping against regression.

## Table of constructions

Listed in canonical primitive order. Below-spec lab helpers (CRC128, FNV-1a, MD5) are **not** registered as PRF-grade and are absent from this table — they live in the test stress harness, not in `hashes/registry.go`.

`aesitb128` is the sole registry entry classified as **Non-PRF** (inner-role primitive only, `Class = ClassNPRF` in [`registry.go`](registry.go)): a reduced-round AES chain purpose-built for two distinct ITB inner surfaces, each with its own load-bearing two-stage defence composition. **In both compositions the ChainHash cascade is the full shipped construction — not a reduced variant — and only its depth parameter differs by site; the second stage is what differs in kind.** At the **Rank Barrier**, defence = the ChainHash cascade fill **plus** the **divmod-then-combinadic-unrank** absorption of the full `(lo, hi)` output (both lanes, no truncation, into a 16-of-48 mask triple — `[HARNESS.md § 3.10.3](../HARNESS.md#3103-rank-barrier-cascade-fill-consumption-chain-interlocked-barrier)`). At the **Pixel Barrier**, defence = the ChainHash cascade fill **plus** the `lo`-lane-only consumption pattern the byte conveyor enforces (upper 8 bytes discarded — the `lo`-only projection is the second half of the defence, not a downstream artefact; there is no divmod stage at this site). The primitive is deliberately weak standalone and safe only under those two compound stacks; separately, it serves as the `aesitb128` DRBG noise fill, where carrier noise needs uniformity rather than PRF security. External integrators reaching for a general-purpose PRF-grade hash must pick from rows 2–10; row 1 is not appropriate outside the ITB inner-Barrier roles. Standalone breaks and their dissolution through the cascade are measured in [`HARNESS.md` § 3.10](../HARNESS.md#310-aes-itb-128-standalone-breaks-and-cascade-dissolution).

| # | Registry name | Native width | Underlying primitive | Construction shape |
|---|---|---|---|---|
| 1 | `aesitb128` | 128 | AES-ITB-128 (ITB-native reduced-round AES chain, `aesitb.go` + `internal/aesitbasm`) | CBC-MAC-style chain absorption over public AES rounds (one per block + two finalising rounds), keyed through the initial state; NUMS round constants (SHA-2 IVs); intentionally Non-PRF, inner-role only (Rank Barrier + Pixel Barrier) |
| 2 | `areion256` | 256 | AreionSoEM-256 (`third/goaes` building blocks; SoEM22, two Areion permutations) | CBC-MAC with SoEM-256 as keyed round function |
| 3 | `areion512` | 512 | AreionSoEM-512 (`third/goaes` building blocks; SoEM22, two Areion permutations) | CBC-MAC with SoEM-512 as keyed round function |
| 4 | `blake2b256` | 256 | BLAKE2b-256 unkeyed (`x/crypto/blake2b`) | Prepend-key MAC with seed XOR into data prefix |
| 5 | `blake2b512` | 512 | BLAKE2b-512 unkeyed (`x/crypto/blake2b`) | Prepend-key MAC, scaled to 64-byte key + 512-bit output |
| 6 | `blake2s` | 256 | BLAKE2s-256 unkeyed (`x/crypto/blake2s`) | Prepend-key MAC with seed XOR into data prefix |
| 7 | `blake3` | 256 | BLAKE3 keyed (`zeebo/blake3.NewKeyed`) | Native keyed BLAKE3 + seed XOR mix |
| 8 | `aescmac` | 128 | AES-128 (`crypto/aes`) | AES-128-CBC-MAC with length-tag fold into seed prefix |
| 9 | `siphash24` | 128 | SipHash-2-4 (`dchest/siphash`) | Direct call — seed components are the SipHash key |
| 10 | `chacha20` | 256 | ChaCha20 block function in its HChaCha20 form (RFC 8439 § 2.3 permutation, `internal/chacha20asm`) | HChaCha20 chain — 15-byte slot blocks through the counter / nonce words, each output keying the next block |

## Detailed constructions

### AES-ITB-128 (registry: `aesitb128`)

**Underlying primitive.** AES-ITB-128 — an ITB-native reduced-round AES chain over a 128-bit state. One AES round per absorbed 16-byte block plus two finalising rounds; eight public round constants are Nothing-Up-My-Sleeve big-endian packings of FIPS 180-4 initial-hash-value words (BLAKE3 / SHA-256 IV, SHA-512 IV, SHA-384 IV — fractional bits of square roots of small primes). Defined in [`aesitb.go`](../aesitb.go) with the batched cascade kernels in [`internal/aesitbasm`](../internal/aesitbasm).

**Construction.** CBC-MAC-style chain absorption over public AES rounds, keyed through the initial state. The 16-byte fixed key and the per-call seed enter once, XORed together into the initial state; every AES round that follows is public (its round key is a public round constant), so there is no secret per-round key, no rate / capacity split, no feed-forward within a call and no length strengthening (the injective PKCS#7 padding alone separates input lengths). Defined in [`aesitb.go`](../aesitb.go)`::MakeAESITB128Hash` (re-exported via `hashes/aesitb.go::AESITB128Pair`).

**Per-call flow** (data of length `L`):

1. Initialise 16-byte state from the seed pair: `state[0..8) = uint64_le(seed0)`, `state[8..16) = uint64_le(seed1)`. XOR the 16-byte fixed key into `state`.
2. Apply injective PKCS#7 padding to `data` up to a multiple of 16 bytes (always appending 1 to 16 bytes of value `16 - (len(data) % 16)`).
3. For each 16-byte block `i` of padded data: `state = AESRound(state ⊕ block[i], RC[i mod 8])` where `RC[i]` is the round-constant slot for absorb index `i`.
4. Two finalising rounds over fixed SHA-256 IV constants `RC[0]` and `RC[1]`: `state = AESRound(state, RC[0])`; `state = AESRound(state, RC[1])`.
5. Output: `(uint64_le(state[0..8)), uint64_le(state[8..16)))`.

At ITB's three shipped per-pixel buffer widths (20 / 36 / 68 bytes = 20 / 36 / 68-byte shapes), padded lengths are 32 / 48 / 80 bytes (2 / 3 / 5 absorb blocks), so the total primitive round count works out to `T = 4 / 5 / 7` respectively (absorb rounds + 2 finalising).

**Why this is deliberately Non-PRF.** `aesitb128` carries `Class = ClassNPRF` in [`registry.go`](registry.go), the shipped **inner-role-only** tier — the primitive is used at two inner surfaces, each with its own two-stage defence (Rank Barrier: divmod-then-combinadic-unrank of `(lo, hi)` plus ChainHash cascade fill; Pixel Barrier: ChainHash cascade fill plus `lo`-lane-only consumption), but never as a standalone user-visible PRF. HARNESS.md § 3.10 records the standalone breaks measured on the raw primitive:

- **One-pair inversion** — under the lab grant of the full 16-byte primitive output, a single (plaintext, digest) pair recovers `K = fixedKey ⊕ seed` in `≈ 2⁰` work (state is invertible in one direction given the public round constants).
- **Structured lo-lane recovery `≈ 2²⁰`** — under 15 chosen Λ-sets on plaintext bytes 0..14 at the raw-primitive one-block shape, a per-byte `2¹⁶` constancy search over `(k_b, c)` recovers `K` from the lo lane alone (3840 chosen texts, `keyrecover_r1_2p20.py`; 20 / 20 at the one-block lab shape).
- **Probability-1 Square integral** — order-1 Λ-set balances the lo lane 8 / 8 at the one-block lab shape (raw 3-round AES property).

None of these reach the shipped wire. Two closures apply, one per inner-Barrier site:

- **Pixel Barrier site.** Two-stage defence — **ChainHash cascade fill plus `lo`-lane-only consumption**. The byte conveyor reads only `lo(h_r)` (upper 8 bytes discarded outright — this alone closes the one-pair-inversion path), and the shipped per-pixel shapes 20 / 36 / 68 confine the attacker's active bytes to LE32(idx) bytes 0..3 (the ≈ 2²⁰ engine is out of regime at every shipped shape as measured — 0 / 0 score at every position at r = 1 and r = 4, `keyrecover_r1_2p20.py --shape-probe 20 --rounds 1 --positions 0,1,2,3 --trials 3`, likewise at 36 / 68 and `--rounds 4`, 3 trials each). No divmod / unrank stage here; the `lo`-lane restriction is itself the second half of the defence.
- **Rank Barrier site.** Two-stage defence — **divmod-then-combinadic-unrank plus ChainHash cascade fill**. The full `(lo, hi)` output is absorbed monolithically through the 128-bit divmod-then-combinadic-unrank chain (`[§ 3.10.3](../HARNESS.md#3103-rank-barrier-cascade-fill-consumption-chain-interlocked-barrier)`), which maps `(lo, hi)` into a 16-of-48 mask triple with an ≈ 2⁵⁷·⁸ preimage ambiguity per triple even under a full-mask read. Both lanes participate; neither is truncated.

The same cascade also runs in two per-message derivations, neither of which writes its output to the wire: the startSeed's `deriveStartPixel` over `0x02 ‖ main nonce`, of which only `lo mod totalPixels` (the starting pixel) is consumed, and the lockSeed's `deriveInterLockSeed` over `0x04 ‖ interlock nonce`, whose full `(lo, hi)` becomes the key `K` heading the Rank Barrier fill cascade above.

**Why AES-ITB and not one of the PRF-grade primitives.** `aesitb128` is engineered for both inner-Barrier roles. At the 48-bit Rank Barrier fill (`[§ 3.10.3](../HARNESS.md#3103-rank-barrier-cascade-fill-consumption-chain-interlocked-barrier)`), a round-based bijection over 128-bit state gives the near-uniform `(lo, hi)` output distribution the combinadic unrank (Exact-B reduction into `C(48, 16) · C(32, 16)` mask space) consumes optimally. At the Pixel Barrier, the site restricts consumption to the `lo` lane as a load-bearing half of its defence and what it demands of the primitive is a fast keyed 128-bit permutation whose `lo` output the ChainHash cascade fill can drive through the AES silicon path (VAES / GFNI / ARM Crypto Extension) that the shipping cascade kernels — [`internal/aesitbasm/`](../internal/aesitbasm) — exploit. The primitive's public-round-constant, single-seed-XOR shape is what enables the 4-lane fused cascade kernels the pipeline hot-path relies on at both sites; a PRF-grade primitive at the same width (`aescmac`, `siphash24`) does not admit the same fused-kernel fusion at the same throughput, and the two-stage defence composition around each use — divmod-unrank + cascade at the fill site; cascade + `lo`-lane-only consumption at the conveyor site — closes the observation gap the primitive's own standalone weakness would otherwise expose.

**Security claim.** **NOT PRF-grade standalone.** The primitive is safe **only** under the ITB compound defence composition at whichever inner-Barrier site it is used. **The ChainHash cascade is the full shipped construction at both sites — never a reduced variant — differing only in the depth parameter each site drives it at. The second stage of the defence is where the two sites diverge in kind:**

- **Rank Barrier.** Defence = the ChainHash cascade with feed-forward at fill depth `r = 1 + keyBits / width` **plus** the **divmod-then-combinadic-unrank** absorption of the full `(lo, hi)` output into a 16-of-48 mask triple. The extra primer round comes from the fill closure prepending `K = deriveInterLockSeed(interlock nonce)` — itself the output of a full separate `ChainHash128` cascade over `[0x04 ‖ interlock nonce]` under the same lockSeed — to the session-component slice, so round 1 seeds the state with `K` cleanly before rounds 2..1 + keyBits/width mix in the session components. Both stages are load-bearing; neither alone suffices, and the primitive's `(lo, hi)` never surfaces to the wire — it exits only as the mask triple.
- **Pixel Barrier.** Defence = the ChainHash cascade at the shipped conveyor depths (`r ∈ {4, 8, 16}` for 512- / 1024- / 2048-bit key widths) **plus** the `lo`-lane-only consumption pattern of the byte conveyor itself (upper 8 bytes never leave the primitive; the site has no divmod / unrank stage — the `lo`-lane restriction is the second half of the defence, not a downstream artefact). Both stages are load-bearing here too.

Empirical validation of the cascade dissolving every standalone break at `r ≥ 2` on the shipped observable is [`HARNESS.md` § 3.10.2](../HARNESS.md#3102-dissolution-mode--cost-versus-cascade-depth), and the fill-site absorption bound is [§ 3.10.3](../HARNESS.md#3103-rank-barrier-cascade-fill-consumption-chain-interlocked-barrier). Do not use as a general-purpose PRF outside ITB.

### Areion-SoEM-256 (registry: `areion256`)

**Underlying primitive.** AreionSoEM-256: the Sum of Even-Mansour SoEM22 of Chen–Lambooij–Mennink (CRYPTO 2019; ePrint 2019/554, Eq. (4)) over two AES-round-based Areion-256 permutations,

    F(k1, k2, m) = P1(m ⊕ k1) ⊕ P2(m ⊕ k2) ⊕ k1 ⊕ k2

where `P1` is Areion-256 under its published round constants and `P2` is Areion-256 under a second round-constant table (the next words of the hexadecimal digits of π), modelled as a permutation independent of `P1`; built atop the `third/goaes` round building blocks.

**ITB uses a patched in-module copy of go-aes (`third/goaes`), because the upstream `AreionSoEM256` / `AreionSoEM512` evaluate one Areion permutation in both branches, which leaves `F(m) = F(m ⊕ k1 ⊕ k2 ⊕ d)` for every `m` and caps the PRF at the birthday bound; the ~170 / ~341-bit figure quoted upstream is the SoEM22 bound and is not reachable there (<https://github.com/jedisct1/go-aes/issues/1>).**

**Construction.** CBC-MAC with the SoEM-256 keyed function (a PRF, not a permutation) as the round function. Defined in `itb/areion.go::MakeAreionSoEM256HashWithKey` (re-exported via `hashes/areion256.go`).

**Per-call flow** (data of length `L`):

1. Build 64-byte subkey: `subkey[0..32) = fixedKey`, `subkey[32..64) = seed (4 × uint64 LE)`.
2. Initialise 32-byte state: `state[0..8) = uint64_le(L)`, `state[8..32) = 0`.
3. For each 24-byte chunk of data:
   - `state[8..min(32, 8+chunk_len)) ^= chunk`,
   - `state ← AreionSoEM256(subkey, state)`.
   The chain runs at least once even for empty data, so the length-tagged state always passes through SoEM before output.
4. Output: `state[0..32)` re-marshalled as 4 × uint64 LE.

**Why this is not a strict sponge.** A sponge has rate / capacity separation and an unkeyed permutation. This construction has no rate / capacity split (the entire 32-byte state passes through SoEM each round) and uses SoEM as a **keyed** function (the subkey carries the fixed key + per-call seed mix). SoEM is a PRF, not a permutation: its output is the XOR of two Areion permutation outputs and is not invertible. Functionally a chained MAC where SoEM-256 plays the round-function role a block cipher plays in classic CBC-MAC.

**Why SoEM-256 specifically.** SoEM with VAES + AVX-512 applies one AES round to each of four 128-bit lanes per VAESENC instruction, and the two-half independent ILP on x86 SIMD allows interleaving across two SoEM halves per call. ARM64 hosts with the ARM Crypto Extension (Graviton 2+, Apple M1+, Neoverse N1+/V1+/V2+) reach the same architectural shape via 4-lane parallel `AESE`/`AESMC` over NEON registers. This is the structural reason Areion-SoEM-256 / Areion-SoEM-512 outpace the other primitives at large ITB widths in the throughput tables.

**Why CBC-MAC and not a sponge.** A sponge construction over the Areion permutation is a structurally valid alternative — Keccak-like designs use exactly that pattern, and the academic narrative for SoEM-based PRFs commonly invokes the sponge frame. The CBC-MAC variant chosen here is a deliberate trade-off:

- **State efficiency.** A sponge reserves part of its state as capacity (e.g. SHA3-256 reserves 512 of 1600 state bits, leaving rate=1088). CBC-MAC uses the entire 256- / 512-bit state as both working memory and absorb target — no bits reserved as capacity. The whole state fits in 1–2 ZMM registers without bookkeeping for which bits are absorbable.
- **Higher data-per-permutation ratio.** Per round, CBC-MAC absorbs 24 bytes (SoEM-256) or 56 bytes (SoEM-512) — close to the full state minus the 8-byte length-tag region. A sponge with capacity reservation absorbs only `rate < state_size` bytes per round, requiring more permutation calls per data byte.
- **AVX-512 fit.** The 4-pixel-parallel ZMM kernels carry full SoEM state per lane through VAESENC without rate / capacity arithmetic. A sponge would impose extra state-shuffle overhead per absorb to maintain the rate / capacity split across lanes.
- **Single-round fast-path for ITB short inputs.** ITB feeds 20- / 36- / 68-byte buffers per pixel. SoEM-256 with chunkSize=24 single-rounds the 20-byte case; SoEM-512 with chunkSize=56 single-rounds the 20- and 36-byte cases. A sponge with `rate < state_size` would force multi-round absorbs even for these short inputs.

The security argument does not regress relative to a sponge framing. CBC-MAC over prefix-free inputs is PRF-secure under a PRF assumption on the round function (`Adv_PRF(CBC-MAC[F_K]) ≤ Adv_PRF(F_K) + q² · ℓ² / 2^n`; Bellare–Kilian–Rogaway for fixed-length inputs, Petrank–Rackoff for prefix-free inputs); the length tag in the first block makes the absorbed inputs prefix-free. Applying it to SoEM gives `Adv_PRF ≤ Adv_PRF(SoEM22) + q² · ℓ² / 2^n` with `n ∈ {256, 512}`. For `Adv_PRF(SoEM22)`, Theorem 1 of Chen–Lambooij–Mennink (CRYPTO 2019; ePrint 2019/554) bounds the PRF advantage of SoEM22 — two independent permutations, two independent keys, output whitening `k1 ⊕ k2` — by about `q^{3/2} / 2^n` in the random-permutation model, so the round function is a PRF up to about `2^{2n/3}` queries (`≈ 2^170` for `n = 256`, `≈ 2^341` for `n = 512`) under one subkey pair, conditional on modelling `P2` (Areion under its second constant table) as independent of `P1`. The `q² · ℓ² / 2^n` chaining term is then the dominant one; it is birthday-level in `n`. A sponge over the Areion permutation gives `Adv_PRF ≤ q² / 2^c` for capacity `c < n`; in either framing the dominant term is birthday-level in the width that carries the security (`n` for the CBC-MAC chain, `c` for the sponge), so the CBC-MAC framing's birthday-level term is no narrower than that of a sponge over the same state size. The trade-off is purely throughput / state efficiency versus academic narrative cleanliness; this construction takes the throughput side and characterises the framing explicitly here so a reader expecting the sponge framing has it stated rather than implied.

**Security claim.** PRF-secure under the assumption that SoEM22 over Areion-256 (`P1(m ⊕ k1) ⊕ P2(m ⊕ k2) ⊕ k1 ⊕ k2`, two Areion-256 permutations under distinct round-constant tables, two subkeys) is a PRF — CLM19 Theorem 1 gives about `2^{2n/3}` queries, `n = 256`, in the random-permutation model with `P2` modelled as independent of `P1` — with both subkeys secret, composed through the CBC-MAC chaining term `q² · ℓ² / 2^256` above.

### Areion-SoEM-512 (registry: `areion512`)

**Underlying primitive.** AreionSoEM-512: SoEM22 over two Areion-512 permutations (`P1` under the published constants, `P2` under the second table), the same shape as AreionSoEM-256 at `n = 512`.

**Construction.** Identical shape to Areion-SoEM-256 — CBC-MAC with the SoEM-512 keyed function (a PRF, not a permutation) as the round function. Scaled to a 64-byte fixed key, 64-byte state, 56-byte chunks per round (8 bytes reserved for the length tag), and 512-bit output. Defined in `itb/areion.go::MakeAreionSoEM512HashWithKey` (re-exported via `hashes/areion512.go`).

**Per-call flow** (data of length `L`):

1. Build 128-byte subkey: `subkey[0..64) = fixedKey`, `subkey[64..128) = seed (8 × uint64 LE)`.
2. Initialise 64-byte state: `state[0..8) = uint64_le(L)`, `state[8..64) = 0`.
3. For each 56-byte chunk of data: XOR into `state[8..64)`, then `state ← AreionSoEM512(subkey, state)`.
4. ITB's three nonce-bit configurations (buf 20 / 36 / 68): 1 / 1 / 2 rounds.
5. Output: `state[0..64)` re-marshalled as 8 × uint64 LE.

**Why this is not a strict sponge.** Same reasoning as Areion-SoEM-256.

**Security claim.** PRF-secure under the same SoEM22 PRF assumption at `n = 512` (CLM19 Theorem 1, about `2^{2n/3} ≈ 2^341` queries in the random-permutation model, `P2` modelled as independent of `P1`), scaled to 512-bit output width, with the chaining term `q² · ℓ² / 2^512`.

### BLAKE2b-256 (registry: `blake2b256`)

**Underlying primitive.** BLAKE2b-256 (`golang.org/x/crypto/blake2b.Sum256`, **unkeyed** mode).

**Construction.** Identical shape to BLAKE2s — prepend-key MAC with seed XOR into the first 32 bytes of the data region. Defined in `blake2b256.go::BLAKE2b256WithKey`. The only difference between this construction and BLAKE2s is BLAKE2b's larger compression function (selected when ITB widths benefit from BLAKE2b's 128-byte block over BLAKE2s's 64-byte block at high data volumes).

**Why this is not RFC 7693 keyed BLAKE2b.** Same reasoning as BLAKE2s — `H(K || M XOR seed)` rather than `MAC_K(M XOR seed)`.

**Security claim.** Same shape as BLAKE2s, scaled to BLAKE2b's compression function.

### BLAKE2b-512 (registry: `blake2b512`)

**Underlying primitive.** BLAKE2b-512 (`golang.org/x/crypto/blake2b.Sum512`, **unkeyed** mode).

**Construction.** Same prepend-key shape as BLAKE2b-256, scaled to a 64-byte fixed key, 64-byte zero-pad threshold (8 seed components contributing into `buf[64..128)`), and 512-bit output. Defined in `blake2b512.go::BLAKE2b512WithKey`.

**Why this is not RFC 7693 keyed BLAKE2b.** Same reasoning as BLAKE2b-256 / BLAKE2s.

**Security claim.** Same shape as BLAKE2b-256, scaled to 512-bit width; the zero padding runs to 64 bytes, so the fixed-length condition applies below 64 bytes.

### BLAKE2s (registry: `blake2s`)

**Underlying primitive.** BLAKE2s-256 (`golang.org/x/crypto/blake2s.Sum256`, **unkeyed** mode).

**Construction.** Prepend-key MAC with seed XOR into the first 32 bytes of the data region. Defined in `blake2s.go::BLAKE2sWithKey`.

**Per-call flow** (data of length `L`):

1. Build buffer: `buf = fixedKey || data`, where `data` is zero-padded out to 32 bytes when `L < 32` (ensures all 4 seed components contribute regardless of input length).
2. XOR seed (4 × uint64 LE) into `buf[32..64)` (the first 32 bytes of the data region).
3. Output: `blake2s.Sum256(buf)` re-marshalled as 4 × uint64 LE.

**Why this is not RFC 7693 keyed BLAKE2s.** RFC 7693 keyed mode uses the BLAKE2 parameter block's `key length` field, prepending the key as a padded full block with proper domain separation **inside** the compression function. This construction concatenates the key as ordinary data in the input message — `blake2s.Sum256(key || data)` rather than `blake2s.Sum256_keyed(key, data)`. Effect: the construction is `H(K || M XOR seed)` rather than `MAC_K(M XOR seed)`. PRF-secure under collision-resistance and PRF-style assumptions on BLAKE2s, but does **not** inherit the per-block PRF property RFC 7693 keyed mode provides.

**Why `H(K || M)` is safe for BLAKE2 despite the prepend-key shape.** The classic length-extension attack against `H(K || M)` applies when `H` is a Merkle-Damgård construction (SHA-1, SHA-2): given `H(K || M)` and `len(K)`, an adversary can compute `H(K || M || pad || M')` without knowing `K`, because the hash output equals the internal state after absorbing `K || M || pad`. BLAKE2 is **not** Merkle-Damgård — it follows the HAIFA construction, where the final compression call mixes a finalisation flag (`f0 = 0xff..ff` in the parameter block) into the state before output extraction. Without the pre-finalisation internal state — which the digest does not expose — an adversary cannot simulate the finalisation compress, so length-extension is structurally infeasible. RFC 7693 §2.1 explicitly cites this property as the reason BLAKE2 admits the simple `BLAKE2(secret_key || message)` MAC pattern. The prepend-key construction here therefore inherits the same length-extension immunity as RFC 7693 keyed mode; the gap between the two reduces to the formal proof technique (RFC 7693 keyed mode admits a direct PRF reduction from BLAKE2's compression function as a PRF; prepend-key arrives at the same PRF conclusion via indifferentiability + collision-resistance arguments under standard assumptions on the same compression function). Choosing prepend-key over RFC keyed mode is driven by hot-path allocation discipline — the upstream `blake2s.Sum256` / `blake2b.Sum256` / `blake2b.Sum512` function-form path is a single allocation-free call, whereas RFC keyed mode requires a hasher object created via `blake2.New256(key)` whose per-call use is incompatible with the closure-pool pattern ITB's hot path needs.

**Security claim.** PRF-secure under collision-resistance and PRF-style assumptions on BLAKE2s as a hash function, for inputs the zero padding keeps distinct: inputs of one fixed length, or inputs of 32 bytes and above (see **Length-tag fold**).

### BLAKE3 (registry: `blake3`)

**Underlying primitive.** BLAKE3-keyed (`github.com/zeebo/blake3.NewKeyed`).

**Construction.** Native keyed BLAKE3 plus a per-call seed XOR mix into the first 32 bytes of data. Defined in `blake3.go::BLAKE3WithKey`.

**Per-call flow** (data of length `L`):

1. Once at construction: `template = blake3.NewKeyed(fixedKey)` (native keyed BLAKE3).
2. Per call: `h = template.Clone()` (state-copy operation BLAKE3 supports natively; sidesteps the data race that `Reset()` on a shared hasher would create when ITB dispatches multiple goroutines per seed).
3. Build mixed data buffer: `mixed = data` zero-padded to 32 bytes when `L < 32`; XOR seed (4 × uint64 LE) into `mixed[0..32)`.
4. `h.Write(mixed)`; `out = h.Sum(buf[:0])`.
5. Output: 32 bytes re-marshalled as 4 × uint64 LE.

**Why this is native keyed BLAKE3.** BLAKE3 specifies a native keyed mode (§2.3 of the BLAKE3 spec) — when the hasher is initialised via `NewKeyed(key)`, the 32-byte key replaces the IV constants in the chunk chaining values, yielding a per-block PRF property that the spec ships with directly. This construction uses that mode verbatim via `zeebo/blake3.NewKeyed`, which is the upstream library's exposure of the spec keyed mode. The only deviation from spec-bare keyed BLAKE3 is the per-call seed XOR mix into the first 32 bytes of data — defence in depth, not a substitute for keying.

This native-keyed-mode use is enabled by BLAKE3's clone-friendly hasher API: `template = blake3.NewKeyed(key)` once at construction, then `template.Clone()` per call avoids re-keying and stays allocation-free under the closure's `sync.Pool`. The BLAKE2 family's upstream API (`blake2.New256(key)`) does not expose a comparably cheap clone — its hasher object would need to be allocated or pooled per call — so BLAKE2b / BLAKE2s in this registry use the function-form `Sum256` / `Sum512` instead, paying for that allocation discipline with the prepend-key wrapper documented in the BLAKE2s section. BLAKE3 is therefore the only registry primitive whose underlying upstream library exposes a keyed-PRF mode that this wrapper consumes verbatim. (SipHash-2-4 has no separate "keyed mode" concept — it is itself a designed PRF — so its closure is a direct call without a wrapper, but it is not a "native keyed mode" use in the same sense.)

**Security claim.** PRF-secure under the keyed-BLAKE3 PRF assumption shipped with the BLAKE3 spec, with the seed XOR mix providing additional per-call domain separation, for inputs the zero padding keeps distinct: inputs of one fixed length, or inputs of 32 bytes and above (see **Length-tag fold**).

### AES-CMAC (registry: `aescmac`)

**Underlying primitive.** AES-128 (`crypto/aes`).

**Construction.** AES-128-CBC-MAC with a length-tag fold into the seed prefix. Defined in `aescmac.go::AESCMACWithKey`.

**Per-call flow** (data of length `L`):

1. Build the first 16-byte block:
   - `b1[0..8)  = uint64_le(seed0 XOR L)`
   - `b1[8..16) = uint64_le(seed1 XOR L)`
   - `b1[0..min(16, L)) ^= data[0..min(16, L))`
2. `b1 = AES_K(b1)`.
3. For each subsequent 16-byte chunk of data: `b1 ^= chunk; b1 = AES_K(b1)`. Partial trailing chunks XOR only their available bytes (no `10*` padding).
4. Output: `(uint64_le(b1[0..8)), uint64_le(b1[8..16)))`.

**Why this is not NIST SP 800-38B CMAC.** NIST CMAC derives subkeys `K1 = doubling(AES_K(0¹²⁸))` and `K2 = doubling(K1)` and XORs the last block with `K1` (full block) or `K2` (partial block padded with `10*`). This construction does **no** subkey derivation; instead, the message length `L` is folded into the seed prefix as a XOR mask on both 64-bit halves before the first AES round. Effect: the fold separates inputs that differ only in trailing zero bytes (empty input, `0x00`, `0x00 0x00`, …). It does not separate chosen inputs of different lengths, because `L` lands in the same block positions the data occupies: for two lengths `L`, `L'` with the same number of AES calls, where the longer input covers every first-block byte that `L XOR L'` touches in both 64-bit halves (for lengths below 256, a longer length of 9 bytes or more), an input of length `L` and its zero-extended counterpart of length `L'` with `L XOR L'` XOR'd into both 64-bit halves of the first block produce the same first-round input, and therefore the same output, under every key and seed; across different numbers of AES calls the unpadded CBC-MAC chain admits the usual extension once one shorter-length output is read. The fold is therefore not a substitute for NIST's `K1` / `K2` last-block trick.

**Security claim.** PRF-secure for each fixed input length under PRP-assumption on AES-128 (fixed-length CBC-MAC up to its birthday-type bound: for a fixed `L` the seed-and-length fold is a fixed XOR offset on the first block and the trailing zero fill is injective); not a PRF over inputs of varying length under one key and seed. ITB does not rely on cross-length separation: each per-pixel, start-pixel and interlock-derivation call site presents one input length per configured nonce width to its seed, and the one closure that sees two lengths — the lockSeed's, at the interlock-nonce derivation and the Rank Barrier fill — evaluates them with different block counts, domain bytes and seed words in every round.

### SipHash-2-4 (registry: `siphash24`)

**Underlying primitive.** SipHash-2-4 (`github.com/dchest/siphash`).

**Construction.** Direct call to `siphash.Hash128(seed0, seed1, data)`. The (seed0, seed1) pair is the entire 128-bit SipHash key; the closure carries no fixed-key prefix and no construction wrapping. Defined in `siphash24.go::SipHash24`.

This is the only registry primitive whose construction is verbatim its upstream specification — SipHash-2-4 is itself a designed PRF mapping (key, data) → 128-bit tag, and ITB's per-pixel seed components naturally fill the SipHash key slot.

**Security claim.** Inherits SipHash-2-4's PRF security argument verbatim.

### ChaCha20 (registry: `chacha20`)

**Underlying primitive.** The ChaCha20 block function of RFC 8439 § 2.3 in its HChaCha20 form — the twenty-round permutation over `[σ | key | input]` without the feed-forward, returning words 0..3 and 12..15 — implemented in `hashes/internal/chacha20asm` and pinned by the package tests to `golang.org/x/crypto/chacha20.HChaCha20`, to the HChaCha20 vector of draft-irtf-cfrg-xchacha § 2.2.1 and to the upstream block function (keystream words minus the public state words).

**Construction.** HChaCha20 chain with per-call key derivation from fixed key XOR seed. Defined in `chacha20.go::ChaCha20WithKey` over `chacha20asm.HChaCha20Chain`.

**Per-call flow** (data of length `L`):

1. Derive per-call 256-bit key: `k₀ = fixedKey XOR seed (4 × uint64 LE)`.
2. Encode the data as `m = max(1, ⌈L / 15⌉)` slot blocks of 16 bytes: block `j` carries `data[15j .. 15j+15)` zero-padded in bytes 0..14 and a tag in byte 15 — `0x00` on every block but the last, `0x80 | r` on the last block, `r` being the number of data bytes it carries (0..15).
3. For each block in order: `k_{j+1} = HChaCha20(k_j, block_j)` — the block fills the four counter / nonce words 12..15 of the state `[σ | k_j | block_j]`, twenty rounds run, and the permuted words 0..3 and 12..15 are the next key. No feed-forward, no keystream.
4. Output: `k_m` re-marshalled as 4 × uint64 LE.

**Why this is not RFC 8439 ChaCha20-Poly1305.** No Poly1305 anywhere — this is not an AEAD, and no keystream is produced: ChaCha20 is used as the keyed function HChaCha20 of the XChaCha20 construction, with the data in the 128-bit input slot and the output keying the next call, rather than as a stream cipher. The native counter / nonce slot is the absorb point by design: every data byte enters a permutation input, the chaining state between blocks is the full 256-bit subkey, and the final block's tag byte makes the encoding injective and prefix-free, so no fixed-width slot caps the absorbed width.

**Security claim.** PRF-secure under the PRF assumption on the ChaCha20 block function (the assumption under which the ChaCha20 keystream is pseudorandom). HChaCha20 is a PRF in its 128-bit input under that assumption by the XChaCha20 argument — its output words are keystream words of the block function minus public state words — and a chain of PRF calls, each keyed by the previous output, over a prefix-free encoding is a PRF by the cascade construction argument (Bellare–Canetti–Krawczyk). The data never enters a key word and the seed never enters an input word, so within ITB, where the fixed key and the seed components are secret and uniform, no related-key property of ChaCha20 is relied on; a caller of the exported closure who supplies attacker-known seeds under one fixed key places it in a related-key setting.

## Cross-cutting design properties

**Length-tag fold.** The constructions handle the input length in different ways, and not every one of them separates every pair of lengths. AES-ITB-128 applies injective PKCS#7 padding; Areion-SoEM writes `uint64_le(L)` into a state prefix that data never overwrites; SipHash-2-4 encodes the length in its specified final-block padding byte; ChaCha20 carries the data byte count of its final slot block in that block's tag byte. AES-CMAC XORs `uint64_le(L)` into both seed halves of its first block; this separates all-zero inputs of different lengths, but the tag shares those bytes with the data, so it is not injective across lengths for chosen data. The BLAKE family carries no length tag of its own: the data is zero-padded to the seed-injection width (32 bytes; 64 bytes for BLAKE2b-512) before hashing, and the BLAKE length counter counts the padded buffer, so up to and including that width two inputs that differ only in trailing zero bytes — the empty input and a single zero byte among them — produce the same digest under the same key and seed; above that width the natural BLAKE length encoding separates lengths. ITB's own call sites never present such a pair: each seed slot has its own fixed key and its own components, each site feeds one length for a given nonce width (20 / 36 / 68 bytes per pixel, 17 / 33 / 65 bytes for the start-pixel and interlock-seed derivations, 13 bytes for the Rank Barrier fill), and the two lengths the lockSeed sees differ in their leading domain byte. A caller who invokes an exported BLAKE closure directly on inputs of varying length below the seed-injection width needs to fix the input length or encode it in the input.

**Seed mix.** Every construction mixes the per-call seed components into the first absorb / first compression. The exact location varies — subkey region for Areion-SoEM, fixed-key XOR for ChaCha20, data prefix XOR for the BLAKE family, the SipHash key itself for SipHash-2-4 — but the principle is constant: per-pixel seed contributions reach the digest in round one regardless of input length.

**Fixed key vs seed key.** All primitives carry a long-lived fixed key (16 / 32 / 64 bytes) in addition to the per-call seed components. The fixed key is generated once by the factory (or restored from persistence on the decrypt-side) and shared between encrypt / decrypt of the same payload. Only SipHash-2-4 has no fixed key — its 128-bit key slot is filled by the per-call (seed0, seed1) pair.

**Pool-and-clone.** The BLAKE family closures use a `sync.Pool` of scratch buffers, plus a pre-keyed BLAKE3 template + `Clone()` for BLAKE3. The Areion-SoEM, AES-CMAC and ChaCha20 closures inline scratch buffers on the closure's stack frame. No registry primitive allocates per call in steady state — the BLAKE family pool grows on first miss but is allocation-free once warm.

**Bit-exact single ↔ batched parity.** Every primitive shipping a batched `Pair` factory guarantees the batched asm arm produces bit-identical output to the single-arm closure for the same (key, data, seed) triple. The parity invariant is enforced by `kat_test.go`'s variable-length matrix and by the implementation tests under `hashes/internal/<primitive>asm/` (under `internal/aesitbasm/` and `internal/areionasm/` for AES-ITB-128 and Areion-SoEM). The 4-lane batched kernels operate on the **same** construction described in the per-primitive sections above; they do not encode an alternate construction.

**No CCA / AEAD claims.** None of the constructions in this registry claim AEAD security, ciphertext integrity, or any property beyond PRF security on the digest output. ITB's authenticated-encryption surface is built **on top** of these primitives via separate MAC-Inside-Encrypt machinery (see `EncryptAuth*` and `triple.Pipeline.EncryptStream`), not from these PRFs directly.

## Nonce-width preservation across all primitives

ITB advertises configurable nonce widths of 128 / 256 / 512 bits, selected per-instance via `Config.NonceBits` on the Cfg-suffixed entry points (with `itb.DefaultNonceBits` supplying the compile-in default). The per-call buffer presented to each hash closure carries 4 bytes of little-endian pixel index LE32(idx) plus the configured nonce material — 20 / 36 / 68 byte shapes for the three nonce widths respectively. Every primitive in the registry must absorb that full buffer into the digest with **no silent truncation hidden inside the primitive composition**.

**The trap to avoid.** Most modern primitives carry a fixed-width "nonce" or "IV" slot — AES-CMAC standard usage takes a 16-byte IV, ChaCha20 (RFC 8439) takes a 12-byte nonce. A naive composition that routes the ITB nonce into such a slot would silently truncate a 512-bit advertised property into 96 or 128 effective bits, with passing KAT tests, passing uniformity tests, and a still-valid (but reduced) PRF claim. The downgrade would be undetectable from outside the wrapper.

Every closure in this registry sidesteps that trap by adhering to five architectural patterns (see [Table of constructions](#table-of-constructions) for native widths and underlying primitives):

1. **CBC-MAC-style chain** — `aesitb128`, `areion256`, `areion512`, `aescmac`. The ITB nonce never lands in the primitive's native nonce or IV slot; it enters through the `data` parameter and absorbs iteratively. `aesitb128` is the sole Non-PRF entry in this group — it follows the same XOR-then-round chain shape as `aescmac`, but each step is one public AES round rather than AES-128 under the fixed key, the fixed key enters once through the initial state, PKCS#7 padding takes the place of the length fold, and two public finalising rounds close the chain; it ships strictly for the inner-Barrier role, not as a user-selectable PRF.
2. **Prepend-key concatenation buffer** — `blake2b256`, `blake2b512`, `blake2s`. The closure builds `buf = fixedKey ‖ data ‖ zero-pad`, XORs the seed into the data prefix, and submits the whole buffer to BLAKE2's one-shot `Sum256` / `Sum512` path. For a 512-bit nonce: the full 64-byte nonce lives in the buffer's data region (seed XOR overlays the leading 32 bytes for `blake2b256` / `blake2s`; the trailing 32 bytes pass through verbatim into the compression). For `blake2b512` the seed-XOR region covers the entire 64-byte nonce. No primitive-internal slot is consumed by the ITB nonce.
3. **Native keyed mode plus streaming write** — `blake3`. The fixed key is bound via `blake3.NewKeyed(fixedKey)` (native keyed mode); the ITB nonce flows in through `h.Write(mixed)` where `mixed` is the data buffer with seed XOR mixed into the leading 32 bytes. BLAKE3's chunk-tree streams the full 64-byte buffer through the keyed compression — no fixed-width slot intervenes.
4. **Native variable-length absorb** — `siphash24`. SipHash-2-4 by design accepts arbitrary-length data through unlimited 8-byte SipRound blocks; the closure is a direct passthrough to `siphash.Hash128(seed0, seed1, data)`. There is no nonce slot to misuse. A 64-byte ITB nonce absorbs through 8 SipRound blocks; the SipHash spec encodes `len(data)` in the final block's padding byte, so length disambiguation is structural.
5. **Iterated nonce-slot absorption under a chaining key** — `chacha20`. The ITB nonce does enter ChaCha20's native counter / nonce slot, but iteratively: 15 bytes per block, each block's HChaCha20 output replacing the 256-bit key of the next, so the slot is an absorb window rather than a cap — a 64-byte ITB nonce with its pixel index absorbs through five blocks — and the final block's tag byte carries its data byte count, so no fixed-width slot truncates the advertised width.

**Type-level guard against cross-width misuse.** Every shipped primitive's closure is strictly typed to its native width (`itb.HashFunc128`, `itb.HashFunc256`, or `itb.HashFunc512`). Dispatch in `itb.Seed{128,256,512}` is type-discriminated: a `HashFunc128` closure cannot be installed where a `HashFunc512` is expected, nor can a `HashFunc256` be misconfigured into a 128-bit seed. The Go type system rejects cross-width assignments at compile time. Generic cross-width adaptations across `{128,256,512}` are provided separately through the pluggable PRF builders in [`builders.go`](builders.go).

**Verification surface.** The per-primitive `kat_test.go` (variable-length matrix) and `kat_fixed_test.go` (frozen-output vectors) pin every closure against regression at every supported nonce width. Any future change to a closure that silently truncated the nonce would change the digest output and fail the KAT vectors at the 256-bit and 512-bit shapes immediately, regardless of whether the change still passed at the 128-bit default.

## Why the names are not RFC / NIST identifiers

The registry names (`aescmac`, `chacha20`, `blake2b256`, ...) are short identifiers chosen for FFI stability and brevity, not assertions of conformance with the RFC / NIST specification of the same name. Renaming to `aescbcmac` / `chacha20prf` / `blake2bprependkey` would communicate the divergence more aggressively, but at the cost of ABI churn (FFI index reordering, every existing example, every `Make*` call site, every Python binding name). The trade-off taken here: keep the short names, document the divergence in this file, and require external integrators to read the construction sections above before assuming RFC / NIST compatibility.

## Why use builders for custom user primitives

Beyond the shipped primitives, the package exposes builder families in [`builders.go`](builders.go) for safely wrapping user-supplied PRFs:

- `BuildCBCMACChainAbsorb{128,256,512}` — wraps a keyed [`cipher.Block`](https://pkg.go.dev/crypto/cipher#Block) into a CBC-MAC chain-absorb closure.
- `BuildSpongeChainAbsorb{128,256,512}` — wraps an unkeyed permutation function into a keyed-sponge chain-absorb closure.
- `BuildARXChainAbsorb{128,256,512}` — wraps a full hash function (`Hash256Fn` or `Hash512Fn`) into a Merkle-Damgard-style closure.
- `BuildHMACChainAbsorb{128,256,512}` — semantic alias of `BuildARXChainAbsorb` tailored for HMAC-style keyed closures.

The builders exist to close a specific silent-failure mode in pluggable PRF integration. This section documents the failure mode so external integrators understand the security argument for the builders' existence and the cost of bypassing them.

### The trap — silent nonce truncation

ITB supports configurable nonce widths via [`Config.NonceBits`](https://pkg.go.dev/github.com/everanium/itb#Config): 128, 256, or 512 bits, threaded through any Cfg-suffixed entry point (with [`itb.DefaultNonceBits`](https://pkg.go.dev/github.com/everanium/itb#DefaultNonceBits) as the compile-in default). The per-call buffer presented to a `HashFunc{128|256|512}` closure carries the configured nonce material — 20, 36, or 68 bytes for the three widths respectively (4 bytes of pixel index + the configured nonce width).

For ITB's advertised nonce width property to hold, **every byte** of the `data` parameter must reach the digest. Three concrete ways a naive user wrapper can silently break this invariant:

**(1) Output width truncation.** A `HashFunc512` wrapper that produces fewer than 64 bytes of digest output and zero-pads the rest:

```go
// BROKEN — silently drops half of ITB's intermediate state entropy
func myBrokenHash(data []byte, seed [8]uint64) [8]uint64 {
    h := sha256.Sum256(data)        // 32-byte output
    var out [8]uint64
    for i := 0; i < 4; i++ {
        out[i] = binary.LittleEndian.Uint64(h[i*8:])
    }
    // out[4:8] remains zero — intermediate state entropy lost.
    // ChainHash's per-call XOR chain in ITB consumes the full 64-byte
    // intermediate state; a constant upper half across calls destroys
    // half the entropy of the seed-mix chain.
    return out
}
```

**(2) Primitive's native nonce-slot truncation.** A wrapper that routes the ITB nonce into a primitive's fixed-width IV / nonce slot:

```go
// BROKEN — 512-bit ITB nonce silently truncated to 128-bit AES IV
func myBrokenAESCMAC(data []byte, seed0, seed1 uint64) (uint64, uint64) {
    var iv [16]byte
    copy(iv[:], data)           // takes only the first 16 of 68 input bytes
    block, _ := aes.NewCipher(key[:])
    block.Encrypt(iv[:], iv[:])
    // ... return iv as (lo, hi) ...
    // Config.NonceBits=512 → effective 128-bit nonce. PRF property still
    // holds at the reduced width, but the advertised "512-bit nonce"
    // is broken silently.
}
```

The same trap applies to ChaCha20's 12-byte native nonce slot, Poly1305's 16-byte tag slot, AES-GCM's 12-byte nonce slot, and every other primitive that defines a fixed-width "nonce" or "IV" input.

**(3) Seed-component drop.** A wrapper that uses only some of the seed components passed by ITB:

```go
// BROKEN — seed[2..7] never reach the digest
func myBrokenHash(data []byte, seed [8]uint64) [8]uint64 {
    key := [16]byte{}
    binary.LittleEndian.PutUint64(key[0:], seed[0])
    binary.LittleEndian.PutUint64(key[8:], seed[1])
    // seed[2..7] discarded — half of ChainHash's PRF key material
    // never enters the digest. Per-call PRF key entropy halved silently.
    ...
}
```

In every case, the wrapper compiles cleanly, accepts the right type signature, and produces wire-compatible ciphertext. The only symptom is that ITB's advertised cryptographic property (512-bit nonce, full ChainHash entropy) is silently reduced to a smaller effective property. No runtime check catches this — `NewSeed{N}` only verifies the closure is non-nil.

### What the builders do

The builder families above absorb the full `data` parameter — all 20 / 36 / 68 bytes of pixel index + ITB nonce — through their respective chain-absorb patterns:

- **CBC-MAC chain**: data XOR'd into state in `BlockSize()`-byte chunks, then `block.Encrypt(state)` per chunk. State holds seed + length tag in initial bytes; every input byte reaches the final 16-byte digest extraction.
- **Sponge chain**: data XOR'd into rate region in rate-byte chunks, then `permute(state)` per chunk. State holds fixedKey + seed in capacity region; rate region accumulates the full input through repeated permutation.
- **ARX / HMAC absorb**: data appended to a `(fixedKey || lenTag || seed || domain)` prefix in one canonical buffer; the underlying full hash function (`hashFn`) absorbs the whole thing through its native variable-length input path.

In all patterns, **all 8 seed components, the full input data, and a length tag reach the digest by construction**. The user only writes a primitive call (`block.Encrypt`, `permute`, or `hashFn`); the chain-absorb plumbing lives inside the builder. There is no caller-side knowledge of the chain-absorb pattern required, and no caller-side opportunity to drop bytes.

### Performance cost of the builders

The builders dispatch through interface callbacks (`cipher.Block.Encrypt`, the `Permute` function type, `Hash256Fn`/`Hash512Fn`) and operate on `make([]byte, stateSize)` buffers that escape to heap. The built-in primitive closures in this package use stack-allocated fixed-size state arrays (`var state [32]byte`), inlined primitive calls, and `unsafe.Pointer` escape-analysis tricks to keep buffers on the stack and avoid heap allocation in the hot path.

Concrete delta: ~5-15% throughput loss vs the inline implementations for the CBC-MAC and sponge patterns; ~0% delta for ARX and HMAC (where the cost is dominated by the underlying hash function call). Built-in primitives stay primitive-specific for performance; builders target correctness-by-construction for user primitives.

### Position in the chain of defenses

The builders are an **additive** safety layer for the pluggable PRF surface. They do not replace any built-in primitive, do not change any existing API, and do not introduce new wire-format constraints. They exist so that:

- Users who wrap their own primitive without reading every line of `areion256.go` / `aescmac.go` / `chacha20.go` to crib the chain-absorb pattern still get correct nonce-width preservation.
- The built-in primitives keep their hand-tuned inline implementations with all their performance benefits intact.
- The pluggable-primitive use case has a documented reference approach guaranteeing complete input absorption without relying on ad-hoc closure implementations.

The KAT-test surface in `builders_test.go` includes a "full nonce absorption" check that verifies every byte of a 68-byte input affects the digest output, providing automated regression detection if the builders are ever modified in a way that reintroduces silent truncation.
