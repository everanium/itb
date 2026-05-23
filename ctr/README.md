# ctr — Counter-mode keystream constructions for ITB

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

> **See [CONSTRUCTIONS.md](CONSTRUCTIONS.md) for the per-primitive construction descriptions.** The registry names (`aescmac`, `chacha20`, `siphash24`) are short identifiers shared with the `hashes/` registry; here they select a counter-mode keystream construction, not the per-pixel hash wrapper of the same name. Read CONSTRUCTIONS.md before assuming a particular standard's exact byte layout.

This package builds a counter-mode keystream from a registry primitive and is the **single source of truth for cipher key and nonce sizes**. It is consumed by the `wrapper/` package (the format-deniability outer cipher) and by the planned `parallax/` package; both rely on this package's `KeySize` / `NonceSize` declarations rather than hardcoding cipher dimensions of their own.

Each supported primitive maps to a standard counter-mode keystream. The package neither defines a new cipher nor claims security beyond what the underlying construction provides.

## Public API

```go
func New(name string, key, nonce []byte) (Keystream, error)
func KeySize(name string) (int, error)
func NonceSize(name string) (int, error)
```

- **`New`** constructs a `Keystream` from the named cipher, the caller-provided key, and a per-stream nonce. The key length must equal `KeySize(name)` and the nonce length must equal `NonceSize(name)`; a mismatch is an error. An unknown name is an error.
- **`KeySize`** returns the byte length of the key for the named cipher, or an error for an unknown name.
- **`NonceSize`** returns the nonce byte length for the named cipher, or an error for an unknown name.

The `Keystream` interface is the minimal counter-mode surface:

```go
type Keystream interface {
    XORKeyStream(dst, src []byte)
}
```

`XORKeyStream` xors a keystream segment over `src` into `dst`, advancing the internal counter. The contract matches [`crypto/cipher.Stream`](https://pkg.go.dev/crypto/cipher#Stream); `dst` must be at least as long as `src`. The interface stays decoupled from `crypto/cipher.Stream` so the SipHash construction does not have to present itself as a stdlib type. As with any counter-mode stream, decryption is the same operation as encryption: XORing a fresh keystream built from the same `(name, key, nonce)` over the ciphertext recovers the plaintext.

## Supported primitives

| Registry name | Construction | Key size | Nonce size | Notes |
|---|---|---|---|---|
| `aescmac` | AES-128 in CTR mode (`crypto/cipher.NewCTR` over `crypto/aes`) | 16 bytes | 16 bytes | Standard NIST CTR mode; AES-NI accelerated on supported hosts. The 16-byte nonce is the CTR initial counter block. |
| `chacha20` | ChaCha20 (RFC8439) keystream (`golang.org/x/crypto/chacha20`) | 32 bytes | 12 bytes | Standard RFC8439 ChaCha20 keystream. |
| `siphash24` | SipHash-2-4 PRF in counter mode, 128-bit output | 16 bytes | 16 bytes | PRF-counter construction; keystream-block collision bound is 2^64. See CONSTRUCTIONS.md. |

The other six registry primitives (`areion256`, `areion512`, `blake2b256`, `blake2b512`, `blake2s`, `blake3`) are **not** supported by this package version; every entry point (`New`, `KeySize`, `NonceSize`) returns an error for any name outside the three above.

## Usage

```go
import (
    "crypto/rand"

    "github.com/everanium/itb/ctr"
)

func main() {
    name := "chacha20"

    keySize, _ := ctr.KeySize(name)     // 32
    nonceSize, _ := ctr.NonceSize(name) // 12

    key := make([]byte, keySize)
    nonce := make([]byte, nonceSize)
    if _, err := rand.Read(key); err != nil {
        panic(err)
    }
    if _, err := rand.Read(nonce); err != nil {
        panic(err)
    }

    plaintext := []byte("any text or binary data - including 0x00 bytes")

    // Encrypt: XOR the keystream over the plaintext.
    enc, err := ctr.New(name, key, nonce)
    if err != nil {
        panic(err)
    }
    ciphertext := make([]byte, len(plaintext))
    enc.XORKeyStream(ciphertext, plaintext)

    // Decrypt: a fresh keystream from the same (name, key, nonce) recovers
    // the plaintext — counter-mode decryption is the same XOR operation.
    dec, err := ctr.New(name, key, nonce)
    if err != nil {
        panic(err)
    }
    recovered := make([]byte, len(ciphertext))
    dec.XORKeyStream(recovered, ciphertext)

    _ = recovered // bit-exact recovery of plaintext.
}
```
