## ITB Keystream Factories

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB composes established, standardized primitives rather than introducing new cryptographic designs. Security properties and regulatory status are inherited from the underlying primitives; see [README.md](../README.md) for jurisdictional certification details.

> **See [CONSTRUCTIONS.md](CONSTRUCTIONS.md) for the per-primitive construction descriptions.** The registry names are short identifiers shared with the `hashes/` registry; here they select a counter-mode keystream construction, not the per-pixel hash wrapper of the same name. Read CONSTRUCTIONS.md before assuming a particular standard's exact byte layout.

This package builds a counter-mode keystream from a registry primitive and is the **single source of truth for cipher key and nonce sizes**. It is consumed by the `wrapper/` package (the format-deniability outer cipher) and by the `parallax/` package; both rely on this package's `KeySize` / `NonceSize` declarations rather than hardcoding cipher dimensions of their own.

Each supported primitive maps to a standard counter-mode keystream. The package neither defines a new cipher nor claims security beyond what the underlying construction provides.

## Public API

```go
func New(name string, key, nonce []byte) (Keystream, error)
func NewAt(name string, key, nonce []byte, byteOffset int) (Keystream, error)
func NewResettable(name string, key, nonce []byte) (ResettableKeystream, error)
func NewResettableAt(name string, key, nonce []byte, byteOffset int) (ResettableKeystream, error)
func KeySize(name string) (int, error)
func NonceSize(name string) (int, error)
```

- **`New`** constructs a `Keystream` from the named cipher, the caller-provided key, and a per-stream nonce. The key length must equal `KeySize(name)` and the nonce length must equal `NonceSize(name)`; a mismatch is an error. An unknown name is an error.
- **`NewAt`** constructs a `Keystream` positioned at `byteOffset` within the logical stream. Sub-block positioning is handled in O(1) time by setting the block counter and pre-discarding intra-block residual bytes.
- **`NewResettable` / `NewResettableAt`** construct a `ResettableKeystream` that can rewind or realign its counter to any byte offset without re-keying.
- **`KeySize`** returns the byte length of the key for the named cipher, or an error for an unknown name.
- **`NonceSize`** returns the nonce byte length for the named cipher, or an error for an unknown name.

The `Keystream` interface is the minimal counter-mode surface:

```go
type Keystream interface {
    XORKeyStream(dst, src []byte)
}

type ResettableKeystream interface {
    Keystream
    ResetCounter(byteOffset int) error
}
```

`XORKeyStream` xors a keystream segment over `src` into `dst`, advancing the internal counter. The contract matches [`crypto/cipher.Stream`](https://pkg.go.dev/crypto/cipher#Stream); `dst` must be at least as long as `src`. The interface stays decoupled from `crypto/cipher.Stream` so the SipHash construction does not have to present itself as a stdlib type. `ResetCounter` on `ResettableKeystream` realigns the stream to `byteOffset` in place, avoiding buffer reallocations in worker pools. As with any counter-mode stream, decryption is the same operation as encryption: XORing a fresh keystream built from the same `(name, key, nonce)` over the ciphertext recovers the plaintext.

## Supported primitives

Every PRF-grade primitive in the registry is supported in counter mode. For the complete matrix of construction shapes, block sizes, key/nonce sizes, and collision bounds, see [CONSTRUCTIONS.md § Table of constructions](CONSTRUCTIONS.md#table-of-constructions).

Every outer-cipher-eligible / PRF-grade registry primitive is supported; every entry point (`New`, `NewAt`, `KeySize`, `NonceSize`) returns an error for any name outside of supported primitives. `NewAt(name, key, nonce, byteOffset)` returns a keystream positioned at `byteOffset` of the `New` stream, so one logical stream can be XORed in parallel — each worker seeks to its chunk offset and emits a byte-identical disjoint range.

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
