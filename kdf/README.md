# kdf — Length-flexible subkey derivation for ITB

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

> **See [CONSTRUCTIONS.md](CONSTRUCTIONS.md) for the per-primitive construction descriptions.**.

This package derives length-flexible subkeys from a **key-derivation key** (the **master**) under a public domain-separation **label**, with one construction per registry cipher name. The intended source of the master is a high-entropy, uniformly distributed secret — for example an ML-KEM shared secret — from which a caller wants several independent, named subkeys of arbitrary length.

Each supported primitive maps to a standard, separately analysable construction. The package neither defines a new KDF nor claims security beyond what the underlying construction provides.

## Public API

```go
func Derive(name string, master []byte, label string, outLen int) ([]byte, error)
```

`Derive` produces an `outLen`-byte subkey from `master` under the public domain-separation `label`, using the construction selected by `name`.

- **`name`** selects the construction. Any unknown value returns an error.
- **`master`** is the key-derivation key. When `master` is longer than the selected primitive's key size it is **truncated down** to that size (a uniform master remains uniform under truncation). When `master` is **shorter** than the required key size `Derive` returns an error rather than fabricate key entropy.
- **`label`** is a **public** domain-separation string. It is not secret; it only needs to be **distinct** per intended subkey. See the notes column below for the per-primitive role and length constraint.
- **`outLen`** is the exact number of subkey bytes returned. It must be non-negative; `outLen == 0` returns an empty slice. Output length is otherwise arbitrary.

Derivations are **deterministic** in `(name, master, label, outLen)`: the same four inputs always yield the same bytes.

## Supported primitives

| Registry name | Construction | Key size | Notes |
|---|---|---|---|
| `areion256` | NIST SP 800-108 KDF in Counter Mode, PRF = registry Areion-SoEM-256 keyed hash | 32 bytes | `label` is the SP 800-108 Label field; any length. Output is **not** cross-length prefix-consistent. |
| `areion512` | NIST SP 800-108 KDF in Counter Mode, PRF = registry Areion-SoEM-512 keyed hash | 32 bytes | `master` is stretched 32 → 64 via the `areion256` PRF to form the 64-byte family key. `label` any length. Output is **not** cross-length prefix-consistent. |
| `blake2b256` | NIST SP 800-108 KDF in Counter Mode, PRF = native keyed BLAKE2b-256 (RFC 7693) | 32 bytes | `label` is the SP 800-108 Label field; any length. Output is **not** cross-length prefix-consistent. |
| `blake2b512` | NIST SP 800-108 KDF in Counter Mode, PRF = native keyed BLAKE2b-512 (RFC 7693) | 32 bytes | `label` is the SP 800-108 Label field; any length. Output is **not** cross-length prefix-consistent. |
| `blake2s` | NIST SP 800-108 KDF in Counter Mode, PRF = native keyed BLAKE2s-256 (RFC 7693) | 32 bytes | `label` is the SP 800-108 Label field; any length. Output is **not** cross-length prefix-consistent. |
| `blake3` | NIST SP 800-108 KDF in Counter Mode, PRF = native keyed BLAKE3 | 32 bytes | `label` is the SP 800-108 Label field; any length. Output is **not** cross-length prefix-consistent. |
| `aescmac` | NIST SP 800-108 KDF in Counter Mode, PRF = AES-CMAC (RFC 4493) over AES-128 | 16 bytes | `label` is the SP 800-108 Label field; any length. Output is **not** cross-length prefix-consistent. |
| `siphash24` | NIST SP 800-108 KDF in Counter Mode, PRF = SipHash-2-4 with 128-bit output | 16 bytes | `master` is the `(k0, k1)` SipHash key (little-endian halves). `label` any length. Output is **not** cross-length prefix-consistent. |
| `chacha20` | XChaCha20 keystream KDF — `label` right-zero-padded to the 24-byte nonce | 32 bytes | `label` must be at most 24 bytes; longer is an error. Output **is** cross-length prefix-consistent. |

All registry primitives are supported; `Derive` returns an error for any unknown name.

**Cross-length prefix-consistency.** The eight SP 800-108 constructions bind the requested output length `L` into every PRF block input, so deriving 64 bytes and truncating to 32 does **not** equal deriving 32 bytes directly — request the exact length needed. The XChaCha20 keystream construction does not bind a length into its input, so its output is prefix-consistent: the leading 32 bytes of a 64-byte derivation equal a 32-byte derivation under the same key and label. CONSTRUCTIONS.md states this distinction in full; do not slice a longer SP 800-108 derivation.

## Key separation via labels

The `label` is the domain-separation mechanism. Two `Derive` calls with the same `(name, master)` but distinct labels produce independent subkeys; reusing a label re-derives the same subkey. Labels carry **no** secrecy requirement — they may be fixed application constants ("enc-key", "mac-key", "nonce-prefix"), public protocol identifiers, or any other distinct strings. Distinctness, not unpredictability, is what separates the derived keys.

## Usage

```go
import (
    "fmt"

    "github.com/everanium/itb/kdf"
)

func main() {
    // master is a high-entropy secret — for example an ML-KEM shared secret.
    master := mlkemSharedSecret() // []byte, at least 32 bytes for chacha20

    // Two independent 32-byte subkeys from the same master, separated by label.
    encKey, err := kdf.Derive("aescmac", master, "session-enc", 32)
    if err != nil {
        panic(err)
    }
    macKey, err := kdf.Derive("aescmac", master, "session-mac", 32)
    if err != nil {
        panic(err)
    }

    // XChaCha20 keystream derivation — label becomes the nonce (<= 24 bytes).
    streamKey, err := kdf.Derive("chacha20", master, "stream-2026", 64)
    if err != nil {
        panic(err)
    }

    fmt.Printf("enc=%x mac=%x stream=%x\n", encKey, macKey, streamKey)
}
```
