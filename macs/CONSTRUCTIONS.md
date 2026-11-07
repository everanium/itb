## ITB MAC Constructions

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB composes established, standardized primitives rather than introducing new cryptographic designs. Security properties and regulatory status are inherited from the underlying primitives; see [README.md](../README.md) for jurisdictional certification details.

This document describes how each shipped MAC primitive is keyed and wrapped before it reaches `itb.MACFunc` (`func(data []byte) []byte`). While `kmac256` and `hmac-sha256` are exact references to standards, `hmac-blake3` diverges from its literal name in a deliberate, documented way. The names in `registry.go` (`kmac256`, `hmac-sha256`, `hmac-blake3`) are short FFI-stable identifiers, **not** in every case assertions of conformance with the standard of the same name.

Audience: external auditors, paper reviewers, downstream integrators reading the code wanting to know what is actually computed when ITB calls into one of these MACs.

For the standards' own conformance, refer to the upstream specifications and library tests:

- NIST SP 800-185 §4.3.1 — KMAC256.
- RFC 2104 / FIPS 198-1 — HMAC; RFC 4231 — HMAC-SHA-256 test vectors.
- `macs/internal/keccakasm` — the cSHAKE256 sponge underlying KMAC256 (pinned against `golang.org/x/crypto/sha3` and pycryptodome in tests).
- `crypto/hmac` + `crypto/sha256` — the stdlib HMAC-SHA-256.
- `github.com/zeebo/blake3` — BLAKE3 native keyed mode (BLAKE3 spec §2.3).

The primitive-math layer is the upstream libraries' (and the stdlib's) responsibility. This document describes the ITB-construction wrapping around those primitives, and the `macs/` test suite pins that wrapping (bit-exact KAT against pycryptodome's KMAC256, the RFC 4231 HMAC-SHA-256 vectors, the official BLAKE3 keyed-mode KAT, plus integration testing under `TestRegisterTripleIntegration` and `TestMakeIncrementalParity`).

## Table of constructions

Listed in canonical registry order (referenced by `triple.Profile.MacName` and the per-call `triple.Opts.MacName` override, stable across releases). Every shipped primitive produces a **32-byte tag** and accepts a 32-byte key.

| # | Registry name | Underlying primitive | Construction shape | Key (min / recommended) | Tag |
|---|---|---|---|---|---|
| 1 | `kmac256` | cSHAKE256 (`macs/internal/keccakasm`) | NIST SP 800-185 KMAC256, `L = 256`, empty customization | 16 / 32 bytes | 32 bytes |
| 2 | `hmac-sha256` | SHA-256 (`crypto/sha256`) | RFC 2104 / FIPS 198-1 HMAC | 16 / 32 bytes | 32 bytes |
| 3 | `hmac-blake3` | BLAKE3 keyed (`zeebo/blake3.NewKeyed`) | BLAKE3 **native keyed mode** — **not** RFC 2104 HMAC | 32 / 32 bytes | 32 bytes |

## Detailed constructions

### KMAC256 (registry: `kmac256`)

**Underlying primitive.** cSHAKE256, the customizable SHAKE256 sponge (`macs/internal/keccakasm`, `keccakasm.CShake256`).

**Construction.** NIST SP 800-185 §4.3.1 KMAC256 with requested output length `L = 256` bits and an empty customization string `S`. Defined in `kmac256.go::KMAC256` (a thin wrapper over `KMAC256WithCustomization(key, nil)`). This is the standard, conformant KMAC256 — no divergence.

**Per-call flow** (data `X`):

1. Once at construction: build `prefix = bytepad(encodeString(K), 136)` (136 = the cSHAKE256 rate in bytes) and `suffix = rightEncode(256)`, then absorb `prefix` into a template `keccakasm.CShake256` initialised with function-name `N = "KMAC"` and customization `S`.
2. Per call: copy the template state into a stack-allocated `var h keccakasm.CShake256` via `h.CopyFrom(tmpl)`, `Write(X)`, `Write(suffix)`, extract 32 output bytes via `h.Sum256Into(ret)`, and scrub the stack frame via `wipe.CallStack2K`.

The `leftEncode` / `rightEncode` / `encodeString` / `bytepad` helpers in `kmac256.go` implement NIST SP 800-185 Algorithms 5 / 6 / 3 / 4 respectively; the bit-exact KAT against pycryptodome's KMAC256 pins their correctness.

**Customization.** The shipped factory uses an empty `S`. `KMAC256WithCustomization` exposes a non-empty `S` for callers needing domain separation across distinct usages of the same key.

**Key length.** NIST SP 800-185 places no hard lower bound; ITB enforces a 16-byte minimum to stay aligned with its own keying discipline.

**Security claim.** Inherits KMAC256's PRF / MAC security argument verbatim (cSHAKE256 modelled as a random oracle / sponge-PRF).

**Hardware & portable tiers.** On amd64 hosts with the AVX-512 F/BW/VL/DQ baseline, `macs/internal/keccakasm/` routes through the vendored AVX-512 Keccak-f[1600] kernel (one lane per XMM register, `VPTERNLOGQ` theta/chi folds, `VPROLQ` rho, pi as register renaming, fused rate-block absorb), while all other hosts and `-tags noitbasm` builds execute the zeroizable portable Go permutation `keccakF1600Generic`. The NIST SP 800-185 framing above is tier-independent; the two tiers emit byte-identical tags.

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

1. Once at construction: `template = blake3.NewKeyed(key)` (the 32-byte key replaces the IV constants in BLAKE3's chunk chaining values — the spec keyed-PRF mode, §2.3), backed by a `sync.Pool` of pre-cloned instances (`newBLAKE3MACPool`).
2. Per call: check out an entry from the pool (`template.Clone()` runs only on pool miss), `Write` the data, finalise to 32 bytes, and scrub the entry via `scrubBLAKE3MACEntry` + `wipe.CallStack2K`. Each pooled entry is independent, so concurrent goroutines may call the closure in parallel.

**Why this is not RFC 2104 HMAC.** The name `hmac-blake3` is a **deliberate misnomer**, not a claim of the nested `H(K ⊕ opad ‖ H(K ⊕ ipad ‖ M))` HMAC construction. BLAKE3-keyed mode is chosen here **precisely because the BLAKE3 authors recommend it instead of HMAC**: BLAKE3's keyed mode is itself a sound keyed PRF (BLAKE3 spec §6.1), so the nested HMAC wrapper RFC 2104 builds around an unkeyed Merkle-Damgård hash is unnecessary with BLAKE3 — and would only add cost without adding security. Wrapping BLAKE3 in literal RFC 2104 HMAC is redundant for this primitive and adds cost without cryptographic benefit.

The registry name is nonetheless kept as `hmac-blake3` for two reasons. First, **user familiarity and registry symmetry**: alongside `hmac-sha256`, the `hmac-` prefix marks the MAC role ("a keyed authentication tag") that integrators recognise and scan for, where a bare `blake3-keyed` would read as something unrelated to the MAC slot. Second, **wire-level stability**: the name is embedded in every `triple.Profile` and travels on the wire through `MacName`, so renaming would churn every binding, example, and test that references it. The standard-conformant name would be `blake3-keyed`; this section is where the divergence is stated rather than implied, so an auditor reads what is actually computed regardless of the label.

**Key length.** Exactly 32 bytes — BLAKE3's keyed mode is defined only for a 256-bit key. Shorter or longer keys are rejected.

**Security claim.** PRF-secure under the keyed-BLAKE3 PRF assumption shipped with the BLAKE3 spec.

## Cross-cutting design properties

**Uniform 32-byte tag.** Every shipped primitive emits exactly 32 bytes regardless of key length, so a consumer does not vary its authenticated-payload layout based on which MAC was selected — a binding-friendly invariant every `triple.Profile` fixed-tag consumer relies on.

**Pre-key once, copy / pool per call.** Each factory absorbs its key into a long-lived template once, then reuses it per call with no key-derivation overhead: KMAC256 copies a `keccakasm.CShake256` template (pre-absorbed up through `bytepad(encodeString(K), 136)`) into a stack-allocated sponge via `CopyFrom`; HMAC-SHA-256 draws a pre-keyed `hmac.Hash` from a `sync.Pool`, `Reset()`s it to the post-ipad state, and scrubs block buffers on return via `scrubHMACSHA256Entry`; HMAC-BLAKE3 draws a pre-cloned `blake3.NewKeyed` entry from `newBLAKE3MACPool` and scrubs it via `scrubBLAKE3MACEntry`. Every shipped closure is safe for concurrent invocation across goroutines.

**No fixed-width-slot truncation.** Every shipped primitive is a native variable-length absorb primitive — the full message (the three region payloads plus the stream binding, which is what the MAC authenticates) reaches the tag with no silent truncation hidden in a fixed-width nonce or IV slot. The trap documented for the keyed-hash registry in [`hashes/CONSTRUCTIONS.md`](../hashes/CONSTRUCTIONS.md) does not arise here.

**No AEAD claim from the MAC alone.** No shipped primitive claims AEAD security or ciphertext integrity on its own — each is only a keyed PRF / MAC on its tag output. ITB's authenticated-encryption surface is built **on top** via the MAC-Inside-Encrypt construction (`EncryptAuth*` and its streaming counterpart), not from these MACs directly.

## Design rationale and PRF sufficiency

ITB's MAC-Inside-Encrypt construction places the 32-byte tag **inside** the encrypted container, where the Pixel Barrier dispersal already destroys any lane payload / tag boundary an attacker could see (the tag is appended to the post-Rank-Barrier lane payload before pixel encoding). The surrounding ITB construction therefore takes care of placement-hiding, per-message freshness (a fresh nonce for every message, so no two wires repeat; rejecting a replayed wire needs receiver-side state, which ITB does not keep; within a stream, the MAC binds every chunk to its stream ID, offset and final flag, so a chunk replayed, reordered or spliced from another stream fails verification), and the bounded CCA leak of the MAC Authenticated shapes (at most the per-pixel noise position, [Proof 6](../PROOFS.md#proof-6-cca-leak-upper-bound), under the PRF assumption on the MAC), which means the MAC primitive itself only has to be a sound keyed PRF. Every shipped MAC meets that bar under standard assumptions, and the selection spans independent primitive families (Keccak-sponge, SHA-2 Merkle-Damgård, BLAKE3 tree) so a structural weakness discovered in one family leaves the remaining families unaffected.

The C shared-library ABI exports a curated, non-pluggable set serving the FFI / mobile distribution. In Go-native environments, custom MACs can be plugged via `macs.Register` and `macs.BuildHMAC` / `macs.BuildKeyedHash`, or supplied as a custom `itb.MACFunc` directly.

---

## References

- John Kelsey, Shu-jen Chang, and Ray Perlner, "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash and ParallelHash", NIST Special Publication 800-185, December 2016, DOI: [10.6028/NIST.SP.800-185](https://doi.org/10.6028/NIST.SP.800-185).
- National Institute of Standards and Technology, "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions", FIPS PUB 202, August 2015, DOI: [10.6028/NIST.FIPS.202](https://doi.org/10.6028/NIST.FIPS.202).
- Hugo Krawczyk, Mihir Bellare, and Ran Canetti, "HMAC: Keyed-Hashing for Message Authentication", IETF RFC 2104, February 1997, DOI: [10.17487/RFC2104](https://doi.org/10.17487/RFC2104) ([RFC Editor](https://www.rfc-editor.org/rfc/rfc2104)).
- National Institute of Standards and Technology, "The Keyed-Hash Message Authentication Code (HMAC)", FIPS PUB 198-1, July 2008, DOI: [10.6028/NIST.FIPS.198-1](https://doi.org/10.6028/NIST.FIPS.198-1).
- National Institute of Standards and Technology, "Secure Hash Standard (SHS)", FIPS PUB 180-4, August 2015, DOI: [10.6028/NIST.FIPS.180-4](https://doi.org/10.6028/NIST.FIPS.180-4).
- Magnus Nyström, "Identifiers and Test Vectors for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, and HMAC-SHA-512", IETF RFC 4231, December 2005, DOI: [10.17487/RFC4231](https://doi.org/10.17487/RFC4231) ([RFC Editor](https://www.rfc-editor.org/rfc/rfc4231)).
- Jack O'Connor, Jean-Philippe Aumasson, Samuel Neves, and Zooko Wilcox-O'Hearn, "BLAKE3: one function, fast everywhere", Technical Specification, January 2020 ([PDF](https://github.com/BLAKE3-team/BLAKE3-specs/raw/master/blake3.pdf)).
