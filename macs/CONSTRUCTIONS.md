# `macs/` — MAC constructions

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

This document describes how each shipped MAC primitive is keyed and wrapped before it reaches `itb.MACFunc` (`func(data []byte) []byte`). Two of the three names are exact references to a standard; the third, `hmac-blake3`, diverges from its literal name in a deliberate, documented way. The names in `registry.go` (`kmac256`, `hmac-sha256`, `hmac-blake3`) are short FFI-stable identifiers, **not** in every case assertions of conformance with the standard of the same name.

Audience: external auditors, paper reviewers, downstream integrators reading the code wanting to know what is actually computed when ITB calls into one of these MACs.

For the standards' own conformance, refer to the upstream specifications and library tests:

- NIST SP 800-185 §4.3.1 — KMAC256.
- RFC 2104 / FIPS 198-1 — HMAC; RFC 4231 — HMAC-SHA-256 test vectors.
- `golang.org/x/crypto/sha3` — the cSHAKE256 sponge underlying KMAC256.
- `crypto/hmac` + `crypto/sha256` — the stdlib HMAC-SHA-256.
- `github.com/zeebo/blake3` — BLAKE3 native keyed mode (BLAKE3 spec §6).

The primitive-math layer is the upstream libraries' (and the stdlib's) responsibility. This document describes the ITB-construction wrapping around those primitives, and `macs_test.go` pins that wrapping against regression (bit-exact KAT against pycryptodome's KMAC256, the RFC 4231 HMAC-SHA-256 vectors, the upstream BLAKE3 keyed-mode KAT, plus an `EncryptAuth` round-trip integration test).

## Table of constructions

Listed in canonical registry order (the FFI iteration order exposed via `ITB_MACName` / `ITB_MACTagSize`, stable across releases). All three produce a **32-byte tag** and accept a 32-byte key.

| # | Registry name | Underlying primitive | Construction shape | Key (min / recommended) | Tag |
|---|---|---|---|---|---|
| 1 | `kmac256` | cSHAKE256 (`x/crypto/sha3`) | NIST SP 800-185 KMAC256, `L = 256`, empty customization | 16 / 32 bytes | 32 bytes |
| 2 | `hmac-sha256` | SHA-256 (`crypto/sha256`) | RFC 2104 / FIPS 198-1 HMAC | 16 / 32 bytes | 32 bytes |
| 3 | `hmac-blake3` | BLAKE3 keyed (`zeebo/blake3.NewKeyed`) | BLAKE3 **native keyed mode** — **not** RFC 2104 HMAC | 32 / 32 bytes | 32 bytes |

## Detailed constructions

### KMAC256 (registry: `kmac256`)

**Underlying primitive.** cSHAKE256, the customizable SHAKE256 sponge (`golang.org/x/crypto/sha3`).

**Construction.** NIST SP 800-185 §4.3.1 KMAC256 with requested output length `L = 256` bits and an empty customization string `S`. Defined in `kmac256.go::KMAC256` (a thin wrapper over `KMAC256WithCustomization(key, nil)`). This is the standard, conformant KMAC256 — no divergence.

**Per-call flow** (data `X`):

1. Once at construction: build `prefix = bytepad(encode_string(K), 136)` (136 = the cSHAKE256 rate in bytes) and `suffix = right_encode(256)`, then absorb `prefix` into a template `cSHAKE256` initialised with function-name `N = "KMAC"` and customization `S`.
2. Per call: clone the template (sponge-state copy), `Write(X)`, `Write(suffix)`, then `Read` 32 output bytes.

The `left_encode` / `right_encode` / `encode_string` / `bytepad` helpers in `kmac256.go` implement NIST SP 800-185 Algorithms 5 / 6 / 3 / 4 respectively; the bit-exact KAT against pycryptodome's KMAC256 pins their correctness.

**Customization.** The shipped factory uses an empty `S`. `KMAC256WithCustomization` exposes a non-empty `S` for callers needing domain separation across distinct usages of the same key.

**Key length.** NIST SP 800-185 places no hard lower bound; ITB enforces a 16-byte minimum to stay aligned with its own keying discipline.

**Security claim.** Inherits KMAC256's PRF / MAC security argument verbatim (cSHAKE256 modelled as a random oracle / sponge-PRF).

### HMAC-SHA256 (registry: `hmac-sha256`)

**Underlying primitive.** SHA-256 (`crypto/sha256`).

**Construction.** RFC 2104 / FIPS 198-1 HMAC with SHA-256 as the hash, via the stdlib `crypto/hmac.New(sha256.New, key)`. Defined in `hmac_sha256.go::HMACSHA256`. This is the standard, conformant HMAC-SHA-256 — no divergence; bit-exact against the RFC 4231 vectors.

**Per-call flow** (data):

1. Once at construction: copy the key and create a `sync.Pool` whose `New` builds a fresh `hmac.New(sha256.New, key)` (which carries the key-XOR'd ipad SHA-256 state).
2. Per call: take a pre-keyed hasher from the pool, `Reset()` it (restoring the post-ipad state), `Write` the data, finalise to 32 bytes, return it to the pool. No per-call key-derivation cost.

**Key length.** HMAC accepts arbitrary-length keys (RFC 2104 zero-pads short keys to the block size and pre-hashes long ones). The typed factory rejects only an empty key; the package `Make` dispatcher applies a 16-byte minimum on top for ITB keying discipline.

**Security claim.** Inherits HMAC-SHA-256's PRF / MAC security argument verbatim (HMAC is a PRF under the assumption that SHA-256's compression function is a PRF).

### HMAC-BLAKE3 (registry: `hmac-blake3`)

**Underlying primitive.** BLAKE3 in native keyed mode (`github.com/zeebo/blake3.NewKeyed`).

**Construction.** BLAKE3's native keyed mode keyed by the 32-byte key. Defined in `hmac_blake3.go::HMACBLAKE3`.

**Per-call flow** (data):

1. Once at construction: `template = blake3.NewKeyed(key)` (the 32-byte key replaces the IV constants in BLAKE3's chunk chaining values — the spec keyed-PRF mode, §6).
2. Per call: clone the template (internal-state copy), `Write` the data, finalise to 32 bytes. Each clone is independent, so concurrent goroutines may call the closure in parallel.

**Why this is not RFC 2104 HMAC.** The name `hmac-blake3` is a **deliberate misnomer**, not a claim of the nested `H(K ⊕ opad ‖ H(K ⊕ ipad ‖ M))` HMAC construction. BLAKE3-keyed mode is chosen here **precisely because the BLAKE3 authors recommend it instead of HMAC**: BLAKE3's keyed mode is itself a sound keyed PRF (BLAKE3 spec §6), so the nested HMAC wrapper RFC 2104 builds around an unkeyed Merkle-Damgård hash is unnecessary with BLAKE3 — and would only add cost without adding security. Wrapping BLAKE3 in literal RFC 2104 HMAC would be the wrong construction for this primitive, not the right one.

The registry name is nonetheless kept as `hmac-blake3` for two reasons. First, **user familiarity and registry symmetry**: alongside `hmac-sha256`, the `hmac-` prefix marks the MAC role ("a keyed authentication tag") that integrators recognise and scan for, where a bare `blake3-keyed` would read as something unrelated to the MAC slot. Second, **FFI stability**: the name is exposed at a frozen index through `ITB_MACName`, so renaming would churn every binding, example, and test that references it. The standard-conformant name would be `blake3-keyed`; this section is where the divergence is stated rather than implied, so an auditor reads what is actually computed regardless of the label.

**Key length.** Exactly 32 bytes — BLAKE3's keyed mode is defined only for a 256-bit key. Shorter or longer keys are rejected.

**Security claim.** PRF-secure under the keyed-BLAKE3 PRF assumption shipped with the BLAKE3 spec.

## Cross-cutting design properties

**Uniform 32-byte tag.** All three primitives emit exactly 32 bytes regardless of key length, so a consumer does not vary its authenticated-payload layout based on which MAC was selected — a binding-friendly invariant the FFI surface (`ITB_MACTagSize`) relies on.

**Pre-key once, clone / pool per call.** Each factory absorbs its key into a long-lived template once, then reuses it per call with no key-derivation overhead: KMAC256 clones a cSHAKE256 template pre-absorbed up through `bytepad(encode_string(K), 136)`; HMAC-SHA-256 draws a pre-keyed `hmac.Hash` from a `sync.Pool` and `Reset()`s it to the post-ipad state; HMAC-BLAKE3 clones a `blake3.NewKeyed` template. All three closures are safe for concurrent invocation across goroutines.

**No fixed-width-slot truncation.** All three are native variable-length absorb primitives — the full message (the entire encrypted container the MAC authenticates) reaches the tag with no silent truncation hidden in a fixed-width nonce or IV slot. The trap documented for the keyed-hash registry in [`hashes/CONSTRUCTIONS.md`](../hashes/CONSTRUCTIONS.md) does not arise here.

**No AEAD claim from the MAC alone.** None of the three claims AEAD security or ciphertext integrity on its own — each is only a keyed PRF / MAC on its tag output. ITB's authenticated-encryption surface is built **on top** via the MAC-Inside-Encrypt construction (`EncryptAuth*` and its streaming counterpart), not from these MACs directly.

## Why these three, and why a sound keyed PRF suffices

ITB's MAC-Inside-Encrypt construction places the 32-byte tag **inside** the encrypted container, where the barrier dispersal (`process128` / `process256` / `process512`) already destroys any plaintext / tag boundary an attacker could see; under `SetLockSoup(1)` the bit-permutation layer further obscures the payload region. The surrounding ITB construction therefore takes care of placement-hiding, replay-resistance (via the per-message nonce), and CCA-resistance, which means the MAC primitive itself only has to be a sound keyed PRF. All three shipped MACs meet that bar under standard assumptions, and the selection spans three independent primitive families (Keccak-sponge, SHA-2 Merkle-Damgård, BLAKE3 tree) so a structural weakness discovered in one family leaves the other two unaffected.

The set is curated, not pluggable: these three are the built-in factories for the C / FFI / mobile shared-library distribution. Users needing a different MAC supply their own `itb.MACFunc` to the `EncryptAuth*` path directly.
