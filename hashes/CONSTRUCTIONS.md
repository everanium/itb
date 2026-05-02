# `hashes/` — primitive constructions

This document describes how each PRF-grade primitive in the registry is wrapped before it reaches `itb.HashFunc{128|256|512}`. Several wrappers diverge from the canonical RFC / NIST form of the underlying primitive in deliberate, documented ways. The names in `registry.go` (`aescmac`, `chacha20`, `blake2b256`, etc.) are short identifiers, **not** assertions of conformance with the RFC / NIST specification of the same name.

Audience: external auditors, paper reviewers, downstream integrators reading the code wanting to know what is actually computed when ITB calls into one of these primitives.

For RFC / NIST primitive math conformance, refer to the upstream library tests:

- `github.com/jedisct1/go-aes` — Areion paper vectors.
- `golang.org/x/crypto/blake2b` — RFC 7693 vectors.
- `golang.org/x/crypto/blake2s` — RFC 7693 vectors.
- `github.com/zeebo/blake3` — official BLAKE3 reference vectors.
- `crypto/aes` — NIST FIPS-197 AES vectors.
- `github.com/dchest/siphash` — official SipHash test vectors.
- `golang.org/x/crypto/chacha20` — RFC 7539 vectors.

The primitive-math layer is the upstream libraries' responsibility. This document describes the ITB-construction wrapping around those primitives, and `kat_fixed_test.go` (frozen-output vectors) plus `kat_test.go` (Pair-API closure-vs-reference parity across the variable-length matrix) pin that wrapping against regression.

## Table of constructions

Listed in canonical primitive order. Below-spec lab helpers (CRC128, FNV-1a, MD5) are **not** registered as PRF-grade and are absent from this table — they live in the test stress harness, not in `hashes/registry.go`.

| # | Registry name | Native width | Underlying primitive | Construction shape |
|---|---|---|---|---|
| 1 | `areion256` | 256 | AreionSoEM-256 (`jedisct1/go-aes` building blocks) | CBC-MAC with SoEM-256 as keyed round function |
| 2 | `areion512` | 512 | AreionSoEM-512 (`jedisct1/go-aes` building blocks) | CBC-MAC with SoEM-512 as keyed round function |
| 3 | `blake2b256` | 256 | BLAKE2b-256 unkeyed (`x/crypto/blake2b`) | Prepend-key MAC with seed XOR into data prefix |
| 4 | `blake2b512` | 512 | BLAKE2b-512 unkeyed (`x/crypto/blake2b`) | Prepend-key MAC, scaled to 64-byte key + 512-bit output |
| 5 | `blake2s` | 256 | BLAKE2s-256 unkeyed (`x/crypto/blake2s`) | Prepend-key MAC with seed XOR into data prefix |
| 6 | `blake3` | 256 | BLAKE3 keyed (`zeebo/blake3.NewKeyed`) | Native RFC keyed BLAKE3 + seed XOR mix |
| 7 | `aescmac` | 128 | AES-128 (`crypto/aes`) | AES-128-CBC-MAC with length-tag fold into seed prefix |
| 8 | `siphash24` | 128 | SipHash-2-4 (`dchest/siphash`) | Direct call — seed components are the SipHash key |
| 9 | `chacha20` | 256 | ChaCha20 stream (`x/crypto/chacha20`) | Custom keystream-MAC over a 32-byte accumulator state |

## Detailed constructions

### Areion-SoEM-256 (registry: `areion256`)

**Underlying primitive.** AreionSoEM-256 (Sponge-over-Even-Mansour with the Areion AES-round S-box; built atop `github.com/jedisct1/go-aes` round building blocks).

**Construction.** CBC-MAC with the SoEM-256 keyed permutation as the round function. Defined in `itb/areion.go::MakeAreionSoEM256HashWithKey` (re-exported via `hashes/areion256.go`).

**Per-call flow** (data of length `L`):

1. Build 64-byte subkey: `subkey[0..32) = fixedKey`, `subkey[32..64) = seed (4 × uint64 LE)`.
2. Initialise 32-byte state: `state[0..8) = uint64_le(L)`, `state[8..32) = 0`.
3. For each 24-byte chunk of data:
   - `state[8..min(32, 8+chunk_len)) ^= chunk`,
   - `state ← AreionSoEM256(subkey, state)`.
   The chain runs at least once even for empty data, so the length-tagged state is always permuted before output.
4. Output: `state[0..32)` re-marshalled as 4 × uint64 LE.

**Why this is not a strict sponge.** A sponge has rate / capacity separation and an unkeyed permutation. This construction has no rate / capacity split (the entire 32-byte state passes through SoEM each round) and uses SoEM as a **keyed** permutation (the subkey carries the fixed key + per-call seed mix). Functionally a chained block-cipher MAC where SoEM-256 plays the block-cipher role.

**Why SoEM-256 specifically.** SoEM with VAES + AVX-512 retires four AES rounds per VAESENC instruction, and the two-half independent ILP on x86 SIMD allows interleaving across two SoEM halves per call. This is the structural reason Areion-SoEM-256 / Areion-SoEM-512 outpace the other primitives at large ITB widths in the throughput tables.

**Why CBC-MAC and not a sponge.** A sponge construction over the SoEM permutation is a structurally valid alternative — Keccak-like designs use exactly that pattern, and the academic narrative for SoEM-based PRFs commonly invokes the sponge frame. The CBC-MAC variant chosen here is a deliberate trade-off:

- **State efficiency.** A sponge reserves part of its state as capacity (e.g. SHA3-256 reserves 512 of 1600 state bits, leaving rate=1088). CBC-MAC uses the entire 256- / 512-bit state as both working memory and absorb target — no bits reserved as capacity. The whole state fits in 1–2 ZMM registers without bookkeeping for which bits are absorbable.
- **Higher data-per-permutation ratio.** Per round, CBC-MAC absorbs 24 bytes (SoEM-256) or 56 bytes (SoEM-512) — close to the full state minus the 8-byte length-tag region. A sponge with capacity reservation absorbs only `rate < state_size` bytes per round, requiring more permutation calls per data byte.
- **AVX-512 fit.** The 4-pixel-parallel ZMM kernels carry full SoEM state per lane through VAESENC without rate / capacity arithmetic. A sponge would impose extra state-shuffle overhead per absorb to maintain the rate / capacity split across lanes.
- **Single-round fast-path for ITB short inputs.** ITB feeds 20- / 36- / 68-byte buffers per pixel. SoEM-256 with chunkSize=24 single-rounds the 20-byte case; SoEM-512 with chunkSize=56 single-rounds the 20- and 36-byte cases. A sponge with `rate < state_size` would force multi-round absorbs even for these short inputs.

The security argument does not regress relative to a sponge framing. CBC-MAC is PRF-secure under PRP-assumption on the round function (`Adv_PRF(CBC-MAC[E_K]) ≤ Adv_PRP(E_K) + q² · ℓ² / 2^n`); applying the BBB-secure SoEM PRP gives `Adv_PRF ≤ ε_BBB + q² · ℓ² / 2^n` with `n ∈ {256, 512}`, well clear of birthday for any practical query budget. A sponge over the same SoEM permutation gives `Adv_PRF ≤ q² / 2^c` for capacity `c`; in either framing the dominant term scales with `2^{−n_secure}` where `n_secure` is SoEM's security-bits budget, identical between the two frames. The trade-off is purely throughput / state efficiency versus academic narrative cleanliness; this construction takes the throughput side and characterises the framing explicitly here so a reader expecting the sponge framing has it stated rather than implied.

**Security claim.** PRF-secure under the BBB (beyond-birthday-bound) security proof of SoEM (Even-Mansour with two-key construction), conditional on (length, seed) uniqueness.

### Areion-SoEM-512 (registry: `areion512`)

**Underlying primitive.** AreionSoEM-512.

**Construction.** Identical shape to Areion-SoEM-256 — CBC-MAC with the SoEM-512 keyed permutation as the round function. Scaled to a 64-byte fixed key, 64-byte state, 56-byte chunks per round (8 bytes reserved for the length tag), and 512-bit output. Defined in `itb/areion.go::MakeAreionSoEM512HashWithKey` (re-exported via `hashes/areion512.go`).

**Per-call flow** (data of length `L`):

1. Build 128-byte subkey: `subkey[0..64) = fixedKey`, `subkey[64..128) = seed (8 × uint64 LE)`.
2. Initialise 64-byte state: `state[0..8) = uint64_le(L)`, `state[8..64) = 0`.
3. For each 56-byte chunk of data: XOR into `state[8..64)`, then `state ← AreionSoEM512(subkey, state)`.
4. ITB's three nonce-bit configurations (buf 20 / 36 / 68): 1 / 1 / 2 rounds.
5. Output: `state[0..64)` re-marshalled as 8 × uint64 LE.

**Why this is not a strict sponge.** Same reasoning as Areion-SoEM-256.

**Security claim.** PRF-secure under the BBB security proof of SoEM-512, scaled to 512-bit output width.

### BLAKE2b-256 (registry: `blake2b256`)

**Underlying primitive.** BLAKE2b-256 (`golang.org/x/crypto/blake2b.Sum256`, **unkeyed** mode).

**Construction.** Identical shape to BLAKE2s — prepend-key MAC with seed XOR into the first 32 bytes of the data region. Defined in `blake2b256.go::BLAKE2b256WithKey`. The only difference between this construction and BLAKE2s is BLAKE2b's larger compression function (selected when ITB widths benefit from BLAKE2b's 128-byte block over BLAKE2s's 64-byte block at high data volumes).

**Why this is not RFC 7693 keyed BLAKE2b.** Same reasoning as BLAKE2s — `H(K || M XOR seed)` rather than `MAC_K(M XOR seed)`.

**Security claim.** Same shape as BLAKE2s, scaled to BLAKE2b's compression function.

### BLAKE2b-512 (registry: `blake2b512`)

**Underlying primitive.** BLAKE2b-512 (`golang.org/x/crypto/blake2b.Sum512`, **unkeyed** mode).

**Construction.** Same prepend-key shape as BLAKE2b-256, scaled to a 64-byte fixed key, 64-byte zero-pad threshold (8 seed components contributing into `buf[64..128)`), and 512-bit output. Defined in `blake2b512.go::BLAKE2b512WithKey`.

**Why this is not RFC 7693 keyed BLAKE2b.** Same reasoning as BLAKE2b-256 / BLAKE2s.

**Security claim.** Same shape as BLAKE2b-256, scaled to 512-bit width.

### BLAKE2s (registry: `blake2s`)

**Underlying primitive.** BLAKE2s-256 (`golang.org/x/crypto/blake2s.Sum256`, **unkeyed** mode).

**Construction.** Prepend-key MAC with seed XOR into the first 32 bytes of the data region. Defined in `blake2s.go::BLAKE2sWithKey`.

**Per-call flow** (data of length `L`):

1. Build buffer: `buf = fixedKey || data`, where `data` is zero-padded out to 32 bytes when `L < 32` (ensures all 4 seed components contribute regardless of input length).
2. XOR seed (4 × uint64 LE) into `buf[32..64)` (the first 32 bytes of the data region).
3. Output: `blake2s.Sum256(buf)` re-marshalled as 4 × uint64 LE.

**Why this is not RFC 7693 keyed BLAKE2s.** RFC 7693 keyed mode uses the BLAKE2 parameter block's `key length` field, prepending the key as a padded full block with proper domain separation **inside** the compression function. This construction concatenates the key as ordinary data in the input message — `blake2s.Sum256(key || data)` rather than `blake2s.Sum256_keyed(key, data)`. Effect: the construction is `H(K || M XOR seed)` rather than `MAC_K(M XOR seed)`. PRF-secure under collision-resistance and PRF-style assumptions on BLAKE2s, but does **not** inherit the per-block PRF property RFC 7693 keyed mode provides.

**Why `H(K || M)` is safe for BLAKE2 despite the prepend-key shape.** The classic length-extension attack against `H(K || M)` applies when `H` is a Merkle-Damgård construction (SHA-1, SHA-2): given `H(K || M)` and `len(K)`, an adversary can compute `H(K || M || pad || M')` without knowing `K`, because the hash output equals the internal state after absorbing `K || M || pad`. BLAKE2 is **not** Merkle-Damgård — it follows the HAIFA construction, where the final compression call mixes a finalisation flag (`f0 = 0xff..ff` in the parameter block) into the state before output extraction. Without the pre-finalisation internal state — which the digest does not expose — an adversary cannot simulate the finalisation compress, so length-extension is structurally infeasible. RFC 7693 §2.1 explicitly cites this property as the reason BLAKE2 admits the simple `BLAKE2(secret_key || message)` MAC pattern. The prepend-key construction here therefore inherits the same length-extension immunity as RFC 7693 keyed mode; the gap between the two reduces to the formal proof technique (RFC 7693 keyed mode admits a direct PRF reduction from BLAKE2's compression function as a PRF; prepend-key arrives at the same PRF conclusion via indifferentiability + collision-resistance arguments under standard assumptions on the same compression function). Choosing prepend-key over RFC keyed mode is driven by hot-path allocation discipline — the upstream `blake2s.Sum256` / `blake2b.Sum256` / `blake2b.Sum512` function-form path is a single allocation-free call, whereas RFC keyed mode requires a hasher object created via `blake2.New256(key)` whose per-call use is incompatible with the closure-pool pattern ITB's hot path needs.

**Security claim.** PRF-secure under collision-resistance and PRF-style assumptions on BLAKE2s as a hash function, conditional on (length, seed, key) uniqueness across queries.

### BLAKE3 (registry: `blake3`)

**Underlying primitive.** BLAKE3-keyed (`github.com/zeebo/blake3.NewKeyed`).

**Construction.** Native RFC keyed BLAKE3 plus a per-call seed XOR mix into the first 32 bytes of data. Defined in `blake3.go::BLAKE3WithKey`.

**Per-call flow** (data of length `L`):

1. Once at construction: `template = blake3.NewKeyed(fixedKey)` (proper RFC keyed BLAKE3).
2. Per call: `h = template.Clone()` (state-copy operation BLAKE3 supports natively; sidesteps the data race that `Reset()` on a shared hasher would create when ITB dispatches multiple goroutines per seed).
3. Build mixed data buffer: `mixed = data` zero-padded to 32 bytes when `L < 32`; XOR seed (4 × uint64 LE) into `mixed[0..32)`.
4. `h.Write(mixed)`; `out = h.Sum(buf[:0])`.
5. Output: 32 bytes re-marshalled as 4 × uint64 LE.

**Why this IS proper RFC-keyed BLAKE3.** BLAKE3 specifies a native keyed mode (§1.3 of the BLAKE3 spec) — when the hasher is initialised via `NewKeyed(key)`, the 32-byte key replaces the IV constants in the chunk chaining values, yielding a per-block PRF property that the spec ships with directly. This construction uses that mode verbatim via `zeebo/blake3.NewKeyed`, which is the upstream library's exposure of the spec keyed mode. The only deviation from spec-bare keyed BLAKE3 is the per-call seed XOR mix into the first 32 bytes of data — defence in depth, not a substitute for keying.

This native-keyed-mode use is enabled by BLAKE3's clone-friendly hasher API: `template = blake3.NewKeyed(key)` once at construction, then `template.Clone()` per call avoids re-keying and stays allocation-free under the closure's `sync.Pool`. The BLAKE2 family's upstream API (`blake2.New256(key)`) does not expose a comparably cheap clone — its hasher object would need to be allocated or pooled per call — so BLAKE2b / BLAKE2s in this registry use the function-form `Sum256` / `Sum512` instead, paying for that allocation discipline with the prepend-key wrapper documented in the BLAKE2s section. BLAKE3 is therefore the only registry primitive whose underlying upstream library exposes a keyed-PRF mode that this wrapper consumes verbatim. (SipHash-2-4 has no separate "keyed mode" concept — it is itself a designed PRF — so its closure is a direct call without a wrapper, but it is not a "native keyed mode" use in the same sense.)

**Security claim.** PRF-secure under the keyed-BLAKE3 PRF assumption shipped with the BLAKE3 spec, with the seed XOR mix providing additional per-call domain separation.

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

**Why this is not NIST SP 800-38B CMAC.** NIST CMAC derives subkeys `K1 = doubling(AES_K(0¹²⁸))` and `K2 = doubling(K1)` and XORs the last block with `K1` (full block) or `K2` (partial block padded with `10*`). This construction does **no** subkey derivation; instead, the message length `L` is folded into the seed prefix as a XOR mask on both 64-bit halves before the first AES round. Effect: distinct lengths produce distinct first-round inputs, addressing CMAC's length-extension concern through a different mechanism than NIST's `K1` / `K2` last-block trick.

**Security claim.** PRF-secure under PRP-assumption on AES-128, conditional on (length, seed) uniqueness across queries — guaranteed by ITB's per-pixel seed derivation.

### SipHash-2-4 (registry: `siphash24`)

**Underlying primitive.** SipHash-2-4 (`github.com/dchest/siphash`).

**Construction.** Direct call to `siphash.Hash128(seed0, seed1, data)`. The (seed0, seed1) pair is the entire 128-bit SipHash key; the closure carries no fixed-key prefix and no construction wrapping. Defined in `siphash24.go::SipHash24`.

This is the only registry primitive whose construction is verbatim its upstream specification — SipHash-2-4 is itself a designed PRF mapping (key, data) → 128-bit tag, and ITB's per-pixel seed components naturally fill the SipHash key slot.

**Security claim.** Inherits SipHash-2-4's PRF security argument verbatim.

### ChaCha20 (registry: `chacha20`)

**Underlying primitive.** ChaCha20 stream cipher (`golang.org/x/crypto/chacha20.NewUnauthenticatedCipher`).

**Construction.** Custom keystream-MAC with per-call key derivation from fixed key XOR seed. Defined in `chacha20.go::ChaCha20WithKey`.

**Per-call flow** (data of length `L`):

1. Derive per-call 256-bit key: `k = fixedKey XOR seed (4 × uint64 LE)`.
2. Initialise ChaCha20 with `k` and a fixed 12-byte zero nonce. Per-call freshness comes from the per-call key derivation, not the nonce, so a constant nonce is safe at the PRF layer (this is **not** a stream-cipher confidentiality use — there is no `keystream XOR keystream` exposure).
3. Initialise 32-byte state: `state[0..8) = uint64_le(L)` (length tag), `state[8..32) = 0`.
4. Absorb data in 24-byte chunks into `state[8..32)`, running `state ← state XOR ChaCha20_keystream` after each absorb. The keystream block counter advances internally between rounds.
5. Output: `state[0..32)` re-marshalled as 4 × uint64 LE.

**Why this is not RFC 7539 ChaCha20-Poly1305.** No Poly1305 anywhere — this is not an AEAD. ChaCha20 is not used as a stream cipher encrypting plaintext data. Data is absorbed into a 32-byte accumulator state whose only "encryption" is the post-absorb XOR with one keystream block. Structurally this is a chained-keystream MAC: each round XORs the state with a keystream block dependent on (key, advancing counter), serving the role that an unkeyed permutation plays in a sponge.

**Security claim.** PRF-secure under the keystream-as-PRF assumption on ChaCha20 (the same assumption underlying ChaCha20-Poly1305's security argument), conditional on (length, seed, key) uniqueness across queries.

## Cross-cutting design properties

**Length-tag fold.** Every construction folds `uint64_le(L)` into the per-call inputs (state prefix for ChaCha20 / Areion-SoEM, seed-prefix XOR for AES-CMAC, message body for the BLAKE family via the natural BLAKE2 length encoding). Without it, empty input vs single-zero-byte vs multi-zero-byte input would produce identical first-round state. The length tag breaks that collision class without requiring extra rounds.

**Seed mix.** Every construction mixes the per-call seed components into the first absorb / first compression. The exact location varies — subkey region for Areion-SoEM, fixed-key XOR for ChaCha20, data prefix XOR for the BLAKE family, the SipHash key itself for SipHash-2-4 — but the principle is constant: per-pixel seed contributions reach the digest in round one regardless of input length.

**Fixed key vs seed key.** Eight of the nine primitives carry a long-lived fixed key (16 / 32 / 64 bytes) in addition to the per-call seed components. The fixed key is generated once by the factory (or restored from persistence on the decrypt-side) and shared between encrypt / decrypt of the same payload. Only SipHash-2-4 has no fixed key — its 128-bit key slot is filled by the per-call (seed0, seed1) pair.

**Pool-and-clone.** The BLAKE family closures use a `sync.Pool` of scratch buffers, plus a pre-keyed BLAKE3 template + `Clone()` for BLAKE3. The Areion-SoEM and AES-CMAC closures inline scratch buffers on the closure's stack frame. ChaCha20 takes one `chacha20.NewUnauthenticatedCipher` allocation per call (the cipher carries per-call state and cannot be safely shared across goroutines); this is the only non-zero per-call allocation among the registry primitives.

**Bit-exact single ↔ batched parity.** Every primitive shipping a batched `Pair` factory guarantees the batched ZMM-arm produces bit-identical output to the single-arm closure for the same (key, data, seed) triple. The parity invariant is enforced by `kat_test.go`'s variable-length matrix and by the implementation tests under `hashes/internal/<primitive>asm/`. The 4-pixel-parallel ZMM kernels operate on the **same** construction described in the per-primitive sections above; they do not encode an alternate construction.

**No CCA / AEAD claims.** None of the constructions in this registry claim AEAD security, ciphertext integrity, or any property beyond PRF security on the digest output. ITB's authenticated-encryption surface is built **on top** of these primitives via separate KMAC-Inside-Encrypt machinery (see `EncryptAuth*` and the in-design streaming counterpart), not from these PRFs directly.

## Why the names are not RFC / NIST identifiers

The registry names (`aescmac`, `chacha20`, `blake2b256`, ...) are short identifiers chosen for FFI stability and brevity, not assertions of conformance with the RFC / NIST specification of the same name. Renaming to `aescbcmac` / `chacha20prf` / `blake2bprependkey` would communicate the divergence more aggressively, but at the cost of ABI churn (FFI index reordering, every existing example, every `Make*` call site, every Python binding name). The trade-off taken here: keep the short names, document the divergence in this file, and require external integrators to read the construction sections above before assuming RFC / NIST compatibility.
