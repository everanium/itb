# `kdf/` — Subkey-derivation constructions

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

This document describes how each supported `Derive` construction turns a key-derivation key (the **master**) and a public **label** into an `outLen`-byte subkey. Each registry name maps to a standard, separately analysable construction. The names (`aescmac`, `siphash24`, `chacha20`) are short identifiers; this document states the exact byte layout each one computes.

Audience: external auditors, paper reviewers, downstream integrators reading the code wanting to know what is actually computed when `Derive` is called.

For the standards' own conformance, refer to the upstream specifications and library tests:

- NIST SP 800-108r1 — KDF in Counter Mode.
- RFC 4493 — the AES-CMAC algorithm (AES-128).
- `github.com/dchest/siphash` — SipHash-2-4 test vectors.
- `golang.org/x/crypto/chacha20` — XChaCha20 (24-byte nonce variant).

## Table of constructions

| Registry name | Underlying primitive | Construction shape | Master key size |
|---|---|---|---|
| `aescmac` | AES-128 CMAC (RFC 4493) | NIST SP 800-108 KDF in Counter Mode (representation r1) | 16 bytes |
| `siphash24` | SipHash-2-4, 128-bit output | NIST SP 800-108 KDF in Counter Mode (representation r1) | 16 bytes |
| `chacha20` | XChaCha20 stream (24-byte nonce) | Keystream KDF — label as nonce, leading `outLen` keystream bytes | 32 bytes |

## SP 800-108 Counter Mode (registry: `aescmac`, `siphash24`)

**Construction.** NIST SP 800-108 KDF in Counter Mode, fixed-input representation **r1**, over a fixed-output-length PRF. The two registry names differ only in which PRF fills the role:

- **`aescmac`** — PRF = AES-CMAC (RFC 4493) over AES-128. The 16-byte master is the AES-128 key; the CMAC subkeys `K1`, `K2` are derived once per RFC 4493 §2.3 via GF(2^128) doubling with the reduction constant `0x87`. Each PRF call returns a 16-byte tag.
- **`siphash24`** — PRF = SipHash-2-4 with 128-bit output. The 16-byte master is the SipHash key, split into the little-endian halves `(k0, k1)`. Each PRF call returns the 16-byte `(lo, hi)` SipHash-128 tag in little-endian order.

**Per-block PRF input.** For each block index `i = 1, 2, ...` the PRF is evaluated over the fixed input

```
[i]_32be || Label || 0x00 || Context || [L]_32be
```

where:

- **`[i]_32be`** is the 32-bit big-endian block counter (starting at 1),
- **`Label`** is the public domain-separation string passed as `label`,
- **`0x00`** is the single-byte separator between Label and Context,
- **`Context`** is **empty** in this package (zero bytes),
- **`[L]_32be`** is the requested output length **in bits** (`outLen * 8`) as a 32-bit big-endian integer.

Only the leading 4 counter bytes change between blocks; the suffix `Label || 0x00 || [L]_32be` is built once and reused per block. The subkey is the leftmost `outLen` bytes of the concatenated PRF outputs `K(1) || K(2) || ...`.

**Key-separation property.** Distinct labels produce distinct PRF inputs at every block index, so subkeys derived under different labels are independent. The label is public; only distinctness is required.

**Output is NOT cross-length prefix-consistent.** Because the output length `L` is bound into **every** block input (the `[L]_32be` suffix), changing `outLen` under the same master and label changes every PRF block input and therefore the entire output. Deriving 64 bytes and then truncating to 32 does **not** equal deriving 32 bytes directly. A consumer that needs a 32-byte key must call `Derive` with `outLen = 32`; slicing a longer derivation yields different bytes.

**Security claim.** SP 800-108 Counter Mode is a NIST-standard KDF; with PRF = AES-CMAC over AES-128 the construction is NIST-standard end to end, PRF-secure under the standard PRP assumption on AES-128. With PRF = SipHash-2-4 the SP 800-108 mode is unchanged, but SipHash-as-PRF is **not** NIST-approved; the construction is sound under SipHash-2-4's own PRF security argument, without claiming NIST conformance.

## XChaCha20 keystream KDF (registry: `chacha20`)

**Underlying primitive.** XChaCha20 stream cipher (`golang.org/x/crypto/chacha20`, 24-byte-nonce variant).

**Construction.** The subkey is the leading `outLen` bytes of the XChaCha20 keystream at counter 0:

1. The 32-byte master is the XChaCha20 **key** (`master[:32]`).
2. The public `label` becomes the XChaCha20 **nonce**: it is right-zero-padded into a 24-byte nonce buffer (`copy(nonce[:], label)`). The label must be **at most 24 bytes**; a longer label is an error.
3. XChaCha20 is initialised with this key and nonce. The keystream at counter 0 is extracted by XORing it into a zeroed `outLen`-byte buffer; the result is the raw keystream prefix.

**Key-separation property.** Distinct labels select distinct XChaCha20 nonces, yielding independent keystreams under the same key. The label is public; only distinctness is required.

**Output IS cross-length prefix-consistent.** The keystream is generated sequentially with no length bound in the input. The leading bytes of a longer derivation equal a shorter derivation under the same key and label: deriving 64 bytes and truncating to 32 **does** equal deriving 32 bytes directly. This is the opposite of the SP 800-108 constructions above — for `chacha20`, slicing a longer derivation is well-defined.

**Security claim.** Deriving keys from XChaCha20 keystream under a per-label nonce is a sound KDF construction under the keystream-as-PRF assumption on XChaCha20 (the same assumption underlying XChaCha20-based AEAD), conditional on label distinctness so that no `(key, nonce)` pair is reused. It is **not** a NIST-approved KDF. No security beyond this construction is claimed.

## Cross-cutting properties

**Master sizing.** Every construction truncates the master **down** to its primitive key size when the master is longer (16 bytes for `aescmac` / `siphash24`, 32 bytes for `chacha20`); a uniform master remains uniform under truncation. A master **shorter** than the required key size is an error — the package does not stretch or pad short masters into key material.

**Determinism.** All three constructions are deterministic in `(name, master, label, outLen)`. The same four inputs always produce the same output bytes; there is no internal randomness.

**Labels are public.** In all three constructions the label is a public domain-separation input. It feeds the SP 800-108 Label field (`aescmac`, `siphash24`) or the XChaCha20 nonce (`chacha20`). Its only requirement is distinctness per intended subkey; it carries no secrecy requirement.

**Standards posture.** Of the three, only `aescmac` is a NIST-standard KDF over a NIST-standard PRF end to end. `siphash24` uses the NIST-standard SP 800-108 mode over a non-NIST PRF; `chacha20` is a sound non-NIST keystream KDF. These distinctions are stated so an integrator selecting a construction for a regulated context knows which one inherits NIST conformance and which do not.
