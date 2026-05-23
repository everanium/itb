# `ctr/` — Counter-mode keystream constructions

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

This document describes how each supported `New` construction turns a key and a per-stream nonce into a counter-mode keystream. Each registry name maps to a standard, separately analysable construction. The names (`aescmac`, `chacha20`, `siphash24`) are short identifiers; this document states the exact keystream each one computes.

Audience: external auditors, paper reviewers, downstream integrators reading the code wanting to know what is actually computed when `New(...).XORKeyStream` is called.

For the standards' own conformance, refer to the upstream specifications and library tests:

- NIST SP 800-38A — Counter (CTR) block-cipher mode of operation.
- NIST FIPS-197 — the AES block cipher (`crypto/aes`).
- RFC 8439 — ChaCha20 (`golang.org/x/crypto/chacha20`).
- `github.com/dchest/siphash` — SipHash-2-4 test vectors.

## Table of constructions

| Registry name | Underlying primitive | Construction shape | Key size | Nonce size |
|---|---|---|---|---|
| `aescmac` | AES-128 (`crypto/aes`) | AES-128 in CTR mode (`crypto/cipher.NewCTR`) | 16 bytes | 16 bytes |
| `chacha20` | ChaCha20 (RFC8439) (`golang.org/x/crypto/chacha20`) | RFC8439 ChaCha20 keystream | 32 bytes | 12 bytes |
| `siphash24` | SipHash-2-4, 128-bit output (`github.com/dchest/siphash`) | PRF-counter mode, 16-byte keystream blocks | 16 bytes | 16 bytes |

## AES-128-CTR (registry: `aescmac`)

**Underlying primitive.** AES-128 (`crypto/aes`).

**Construction.** AES-128 in NIST SP 800-38A Counter (CTR) mode, via `crypto/cipher.NewCTR` over a `crypto/aes` block cipher.

1. The 16-byte key is the AES-128 key (`aes.NewCipher(key)`).
2. The 16-byte nonce is the CTR initial counter block — the IV passed to `cipher.NewCTR(block, nonce)`.
3. `XORKeyStream` produces the keystream by encrypting successive counter blocks under AES-128 and XORing the result over the input; the standard library advances the 128-bit counter internally.

**Standards posture.** This is the stdlib's CTR mode over the stdlib's AES; it is standard NIST CTR mode end to end. On hosts with the AES instruction set (`crypto/aes` AES-NI on x86, the ARM Crypto Extension on AArch64) the block calls are hardware-accelerated.

**Stream shape.** AES is a pseudorandom permutation, so each counter value yields a distinct 16-byte keystream block; there is no keystream-block collision until the 128-bit counter space is exhausted. This is the standard CTR-mode property.

**Security claim.** PRF-secure keystream under the PRP assumption on AES-128, conditional on the `(key, nonce)` initial counter block not being reused across distinct streams. No security beyond standard CTR mode is claimed.

## ChaCha20 (registry: `chacha20`)

**Underlying primitive.** ChaCha20 stream cipher, RFC 8439 variant (`golang.org/x/crypto/chacha20.NewUnauthenticatedCipher`).

**Construction.** The ChaCha20 (RFC8439) keystream directly.

1. The 32-byte key is the ChaCha20 key.
2. The 12-byte nonce is the RFC 8439 nonce.
3. `XORKeyStream` is the underlying `chacha20.Cipher`'s own `XORKeyStream` — the RFC 8439 keystream XORed over the input, with the 32-bit block counter advancing internally.

**Standards posture.** This is the upstream `x/crypto/chacha20` keystream with no ITB-side wrapping. It is the RFC 8439 ChaCha20 stream as the library ships it.

**Stream shape.** ChaCha20 is a stream-native cipher whose keystream is generated from distinct block-counter values; there is no keystream-block collision until the counter space is exhausted. This is the standard stream-cipher property.

**Security claim.** PRF-secure keystream under the keystream-as-PRF assumption on ChaCha20 (the same assumption underlying ChaCha20-based AEAD), conditional on the `(key, nonce)` pair not being reused across distinct streams. No security beyond the standard ChaCha20 keystream is claimed.

## SipHash-CTR (registry: `siphash24`)

**Underlying primitive.** SipHash-2-4 with 128-bit output (`github.com/dchest/siphash`, `Hash128`).

**Construction.** PRF-counter mode. SipHash-2-4 is a 128-bit-keyed PRF / MAC; its 128-bit-output variant (SipHash-2-4-128) drives the keystream. Building a keystream from a PRF by hashing a counter is the standard counter-mode construction:

```
keystream_block_i = SipHash128(K, nonce_hi || (nonce_lo XOR counter_le))   (16 bytes per block)
```

where:

- **`K`** is the 16-byte key, split into the little-endian halves `(k0, k1)` that form the entire 128-bit SipHash key.
- **`nonce`** is 16 bytes wide, partitioned as `(nonce_hi || nonce_lo)` (little-endian 64-bit halves).
- **`counter_le`** is a 64-bit block counter, starting at 0 and incrementing per 16-byte block.

Each keystream block hashes a 16-byte PRF input formed from `nonce_hi || (nonce_lo XOR counter_le)`. This binds every block to the stream's nonce while injecting unique 64-bit counter material per block. The 16-byte `(lo, hi)` SipHash-128 output is the keystream block; sub-block tails consume the leading bytes of a freshly hashed block.

**Stream shape.** This is PRF-counter mode, **not** a permutation-native CTR. AES-CTR and ChaCha20 above use a permutation / stream-native keystream where each counter value yields a distinct block with no keystream-block collision until the counter space is exhausted. SipHash-CTR instead hashes the counter through a PRF whose output is 128 bits wide, so two distinct counter inputs can in principle produce the same 16-byte keystream block. The keystream-block collision birthday bound is therefore **2^64** — on par with the 128-bit block-cipher CTR paths, since their collision space is likewise 2^128 over 16-byte blocks. The 64-bit counter likewise admits 2^64 blocks (2^68 bytes) per nonce before the counter space is exhausted.

**Security claim.** PRF-secure keystream under the same PRF assumption that justifies AES-CTR — XORing PRF output with plaintext is the canonical PRF-secure stream — conditional on the `(key, nonce)` pair not being reused across distinct streams. The 128-bit SipHash output places the keystream-block collision bound at 2^64. No security beyond a sound PRF-counter construction is claimed.

## Cross-cutting properties

**Key and nonce sizing.** Each construction's key and nonce lengths are fixed and reported by `KeySize` / `NonceSize`: `aescmac` is 16 / 16, `chacha20` is 32 / 12, `siphash24` is 16 / 16. `New` rejects any key or nonce whose length does not match the declared size; the package neither truncates nor pads caller-supplied key or nonce material.

**Determinism.** All three keystreams are deterministic in `(name, key, nonce)`: the byte at a given stream offset is fixed by those three inputs. Chunked and whole-buffer calls produce the same output for the same total offset — `XORKeyStream` maintains a continuous internal counter across calls.

**Nonce-reuse caveat.** As with every counter-mode keystream, reusing a `(key, nonce)` pair across two distinct messages reuses the same keystream and is a confidentiality break (the XOR of the two ciphertexts equals the XOR of the two plaintexts). A distinct per-stream nonce under a fixed key is required for all three constructions.

**Standards posture.** Of the three, `aescmac` (AES-128-CTR) and `chacha20` (RFC8439 ChaCha20) are standard, widely analysed keystreams. `siphash24` is a sound PRF-counter construction over a non-NIST PRF; it inherits SipHash-2-4's PRF security argument and is not a NIST-approved cipher. These distinctions are stated so an integrator selecting a construction for a regulated context knows which keystreams are standard and which is a PRF-counter construction.
