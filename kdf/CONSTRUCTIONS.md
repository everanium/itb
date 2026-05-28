# `kdf/` — Subkey-derivation constructions

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

This document describes how each supported `Derive` construction turns a key-derivation key (the **master**) and a public **label** into an `outLen`-byte subkey. Each registry name maps to a standard, separately analysable construction. The names (`areion256`, `areion512`, `blake2b256`, `blake2b512`, `blake2s`, `blake3`, `aescmac`, `siphash24`, `chacha20`) are short identifiers; this document states the exact byte layout each one computes.

Audience: external auditors, paper reviewers, downstream integrators reading the code wanting to know what is actually computed when `Derive` is called.

For the standards' own conformance, refer to the upstream specifications and library tests:

- NIST SP 800-108r1 — KDF in Counter Mode.
- RFC 4493 — the AES-CMAC algorithm (AES-128).
- `github.com/dchest/siphash` — SipHash-2-4 test vectors.
- `golang.org/x/crypto/chacha20` — XChaCha20 (24-byte nonce variant).
- RFC 7693 — the BLAKE2 keyed-hash mode (BLAKE2b / BLAKE2s).
- `github.com/zeebo/blake3` — BLAKE3 keyed mode.
- `github.com/everanium/itb/hashes` — the registry Areion-SoEM-256 / Areion-SoEM-512 keyed hashes.

## Table of constructions

| Registry name | Underlying primitive | Construction shape | Master key size |
|---|---|---|---|
| `areion256` | registry Areion-SoEM-256 keyed hash, 32-byte output | NIST SP 800-108 KDF in Counter Mode (representation r1) | 32 bytes |
| `areion512` | registry Areion-SoEM-512 keyed hash, 64-byte output | NIST SP 800-108 KDF in Counter Mode (representation r1); 32 → 64 key stretch via `areion256` | 32 bytes |
| `blake2b256` | native keyed BLAKE2b-256 (RFC 7693), 32-byte output | NIST SP 800-108 KDF in Counter Mode (representation r1) | 32 bytes |
| `blake2b512` | native keyed BLAKE2b-512 (RFC 7693), 64-byte output | NIST SP 800-108 KDF in Counter Mode (representation r1) | 32 bytes |
| `blake2s` | native keyed BLAKE2s-256 (RFC 7693), 32-byte output | NIST SP 800-108 KDF in Counter Mode (representation r1) | 32 bytes |
| `blake3` | native keyed BLAKE3, 32-byte output | NIST SP 800-108 KDF in Counter Mode (representation r1) | 32 bytes |
| `aescmac` | AES-128 CMAC (RFC 4493) | NIST SP 800-108 KDF in Counter Mode (representation r1) | 16 bytes |
| `siphash24` | SipHash-2-4, 128-bit output | NIST SP 800-108 KDF in Counter Mode (representation r1) | 16 bytes |
| `chacha20` | XChaCha20 stream (24-byte nonce) | Keystream KDF — label as nonce, leading `outLen` keystream bytes | 32 bytes |

## SP 800-108 Counter Mode over Areion-SoEM (registry: `areion256`, `areion512`)

**Construction.** NIST SP 800-108 KDF in Counter Mode, fixed-input representation **r1**, with PRF = the registry Areion-SoEM keyed hash. The Areion-SoEM keyed `HashFunc` is a CBC-MAC over the keyed SoEM permutation; the PRF hashes the block input under a zero seed and serialises the resulting uint64 words little-endian.

- **`areion256`** — PRF = registry Areion-SoEM-256 keyed hash. The 32-byte master is the family key; each PRF call returns a 32-byte output.
- **`areion512`** — PRF = registry Areion-SoEM-512 keyed hash, which requires a 64-byte family key. The 32-byte master is first stretched to 64 bytes by an internal key schedule — SP 800-108 Counter Mode over the `areion256` PRF (keyed by `master[:32]`) under a fixed family-internal label, producing 64 bytes — and the stretched key then keys the Areion-SoEM-512 PRF. The fixed internal label keeps the stretch isolated from any caller-chosen label. Each PRF call returns a 64-byte output.

**Per-block PRF input.** Identical to the `aescmac` / `siphash24` layout: `[i]_32be || Label || 0x00 || Context || [L]_32be`, empty Context, `[L]_32be` the output length in bits. The subkey is the leftmost `outLen` bytes of the concatenated PRF outputs.

**Output is NOT cross-length prefix-consistent.** As with every SP 800-108 construction here, the bound `[L]_32be` field makes the output specific to `outLen`; slicing a longer derivation does **not** equal deriving the shorter length directly.

**Security claim.** SP 800-108 Counter Mode is a NIST-standard KDF; the Areion-SoEM keyed hash is a CBC-MAC over the SoEM keyed permutation, beyond-birthday-bound secure under the SoEM PRP assumption. The Areion-SoEM PRF is **not** NIST-approved, so the construction is sound under that PRP assumption without claiming NIST conformance.

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

## SP 800-108 Counter Mode over native keyed BLAKE (registry: `blake2b256`, `blake2b512`, `blake2s`, `blake3`)

**Construction.** NIST SP 800-108 KDF in Counter Mode, fixed-input representation **r1**, identical in shape to the `aescmac` / `siphash24` constructions above. The four registry names differ only in which keyed BLAKE hash fills the PRF role:

- **`blake2b256`** — PRF = native keyed BLAKE2b-256 (RFC 7693). The 32-byte master is the BLAKE2b key; each PRF call returns the 32-byte keyed digest over the block input.
- **`blake2b512`** — PRF = native keyed BLAKE2b-512 (RFC 7693). The 32-byte master is the BLAKE2b key; each PRF call returns the 64-byte keyed digest over the block input.
- **`blake2s`** — PRF = native keyed BLAKE2s-256 (RFC 7693). The 32-byte master is the BLAKE2s key; each PRF call returns the 32-byte keyed digest over the block input.
- **`blake3`** — PRF = native keyed BLAKE3. The 32-byte master is the BLAKE3 key; each PRF call returns the leading 32 bytes of the keyed BLAKE3 output over the block input.

The keyed mode here is the upstream **standard keyed PRF** (RFC 7693 keyed BLAKE2 / BLAKE3 keyed mode); it is **not** the ITB per-pixel registry hash wrapper of the same name, which derives its key differently. The 32-byte master keys the hash directly.

**Per-block PRF input.** Identical to the `aescmac` / `siphash24` layout: for each block index `i = 1, 2, ...` the PRF is evaluated over `[i]_32be || Label || 0x00 || Context || [L]_32be`, with empty Context and `[L]_32be` the requested output length in bits. The subkey is the leftmost `outLen` bytes of `K(1) || K(2) || ...`.

**Output is NOT cross-length prefix-consistent.** As with every SP 800-108 construction here, the output length `L` is bound into every block input, so changing `outLen` under the same master and label changes the entire output. Slicing a longer derivation does **not** equal deriving the shorter length directly.

**Security claim.** SP 800-108 Counter Mode is a NIST-standard KDF; the keyed BLAKE PRF is sound under the standard PRF assumption on keyed BLAKE2 / BLAKE3. The mode is NIST-standard but the BLAKE PRF is **not** NIST-approved, so the construction is sound under the keyed-BLAKE PRF security argument without claiming NIST conformance.

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

**Master sizing.** Every construction truncates the master **down** to its primitive key size when the master is longer (16 bytes for `aescmac` / `siphash24`, 32 bytes for the rest); a uniform master remains uniform under truncation. A master **shorter** than the required key size is an error — the package does not stretch or pad short masters into key material. The sole exception is `areion512`'s internal 32 → 64 key stretch: that is a deterministic expansion of the already-uniform 32-byte master into the wider family key, applied after the master length check, not a way to fabricate entropy from a too-short master.

**Determinism.** All constructions are deterministic in `(name, master, label, outLen)`. The same four inputs always produce the same output bytes; there is no internal randomness.

**Labels are public.** In all constructions the label is a public domain-separation input. It feeds the SP 800-108 Label field (`aescmac`, `siphash24`, the four BLAKE names, `areion256`, `areion512`) or the XChaCha20 nonce (`chacha20`). Its only requirement is distinctness per intended subkey; it carries no secrecy requirement.

**Standards posture.** Only `aescmac` is a NIST-standard KDF over a NIST-standard PRF end to end. The four BLAKE names, `areion256`, `areion512`, and `siphash24` use the NIST-standard SP 800-108 mode over a non-NIST PRF; `chacha20` is a sound non-NIST keystream KDF. These distinctions are stated so an integrator selecting a construction for a regulated context knows which one inherits NIST conformance and which do not.
