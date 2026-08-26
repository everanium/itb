# ITB Format-Deniability Wrapper

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Companion code for the ITB Quick Start. The examples below layer a thin outer cipher envelope over ITB's Triple 8-seed ciphertext so the on-wire bytes look like generic stream cipher output rather than ITB format pixel containers + per-chunk prefix.

## Threat model

ITB encrypts content into RGBWYOPA pixel containers. The construction provides **content-deniability** unconditionally — no plaintext bit can be extracted from the wire. The wire pattern itself, however, is parseable by an observer who knows the ITB format:

- Non-AEAD path: per-chunk header carries width / height / container layout.
- Streaming AEAD path: a once per-stream 32-byte streamID prefix plus per-chunk `nonce || W || H || container || flag_byte`.

A passive observer who knows ITB ships with an 8-channel pixel container and a 32-byte streamID prefix can pattern-match the bytes. The format-deniability wrap hides that surface under a generic outer cipher — any of the PRF-grade ITB registry primitives (Areion-SoEM-256/512, BLAKE2b-256/512, BLAKE2s, BLAKE3, AES-128-CTR, SipHash-2-4 in CTR mode, ChaCha20 (RFC 8439)). After wrapping, the wire is `nonce || keystream-XOR(bytestream)` — the same shape used by countless other protocols. An observer sees a small leading nonce followed by pseudorandom-looking bytes; pattern-matching does not distinguish ITB from any other stream cipher payload.

This is **not** a random-oracle indistinguishability claim. It is a "looks like a different well-known cipher" claim. The wrap exists for format-deniability ONLY; ITB already provides confidentiality (content-deniability) and the AEAD path already provides per-stream and per-chunk integrity. The Non-AEAD streaming path has no integrity by design and the wrap does not add any.

## Public API

```go
type Keystream = ctr.Keystream

const (
    CipherAreion256  = "areion256"
    CipherAreion512  = "areion512"
    CipherBLAKE2b256 = "blake2b256"
    CipherBLAKE2b512 = "blake2b512"
    CipherBLAKE2s    = "blake2s"
    CipherBLAKE3     = "blake3"
    CipherAES128CTR  = "aescmac"
    CipherSipHash24  = "siphash24"
    CipherChaCha20   = "chacha20"

    ParallelThreshold = 256 * 1024
)

var CipherNames []string

func KeySize(name string) (int, error)
func NonceSize(name string) (int, error)
func GenerateKey(name string) ([]byte, error)
func DeriveKey(name string, master []byte) ([]byte, error)
func MakeKeystream(name string, key, nonce []byte) (Keystream, error)
func MakeKeystreamAt(name string, key, nonce []byte, offset int) (Keystream, error)

func Wrap(name string, key, blob []byte) ([]byte, error)
func Unwrap(name string, key, wire []byte) ([]byte, error)
func WrapInPlace(name string, key, blob []byte) ([]byte, error)
func UnwrapInPlace(name string, key, wire []byte) ([]byte, error)

func NewWrapWriter(name string, key []byte, dst io.Writer) (io.Writer, error)
func NewUnwrapReader(name string, key []byte, src io.Reader) (io.Reader, error)

func XORParallel(name string, key, nonce, dst, src []byte) error
func XORParallelAt(name string, key, nonce []byte, base int, dst, src []byte) error
```

- **`Keystream`** is the outer cipher's CTR-mode keystream interface, aliased directly from `ctr.Keystream`. The contract matches `crypto/cipher.Stream`: `XORKeyStream(dst, src)` xors one keystream segment over `src` into `dst` and advances the internal counter.
- **Cipher constants** (`CipherAreion256` ... `CipherChaCha20`) name every outer cipher the wrapper accepts. `CipherAES128CTR = "aescmac"` is the registry alias for AES-128 in CTR mode (identical to the underlying cipher behind the `aescmac` MAC entry). `CipherNames` enumerates the outer cipher palette in canonical primitive order; it is the iteration source for cross-cipher tests and benchmarks.
- **`ParallelThreshold`** is the byte cap below which `Wrap` / `Unwrap` / `WrapInPlace` / `UnwrapInPlace` keep the body XOR in the caller's goroutine. Above it the work is split across up to `min(32, GOMAXPROCS, chunks)` worker goroutines, each seeking its own keystream to the chunk's byte offset via `ctr.NewAt`. Exposed as a read-only constant for out-of-package tests and benchmarks.
- **`KeySize` / `NonceSize`** report the per-cipher key and nonce widths in bytes; both delegate to [`ctr`](../ctr/), which is the single source of truth for the registered cipher sizing.
- **`GenerateKey`** draws a fresh CSPRNG outer cipher key of the appropriate width. Use this in self-test contexts or when no out-of-band key material is available.
- **`DeriveKey`** derives a deterministic outer cipher key from a high-entropy master via [`kdf.Derive`](../kdf/) under a wrapper-specific label. Use this when the application already holds a shared secret (an ML-KEM encapsulated key, an HKDF output, an out-of-band negotiated key) and wants the outer cipher key to be reproducible without re-distribution. The caller wipes the master after this returns.
- **`MakeKeystream` / `MakeKeystreamAt`** construct a `Keystream` ready to XOR data. `MakeKeystreamAt(name, key, nonce, offset)` is the byte-offset positioned variant; it returns a keystream as if `MakeKeystream` had been called and then advanced by `offset` bytes — used by the worker pool to split one logical keystream into disjoint parallel chunks that re-concatenate byte-identical to a serial pass.
- **`Wrap` / `Unwrap`** are the blob (Single Message) round-trip pair. `Wrap` allocates a fresh `nonce(NonceSize(name)) || keystream-XOR(blob)` wire, drawing the nonce from `crypto/rand`. `Unwrap` reverses it.
- **`WrapInPlace` / `UnwrapInPlace`** are the zero-body-allocation counterparts. `WrapInPlace` mutates `blob` to its ciphertext form and returns the assembled wire; on error `blob` is left unchanged.
- **`NewWrapWriter` / `NewUnwrapReader`** are the streaming wrap surface. The wrap writer emits the nonce on its first underlying `dst.Write` then XORs every subsequent byte through the keystream; the unwrap reader is symmetric. One stream session uses one nonce and the keystream counter advances monotonically across every byte written.
- **`XORParallel` / `XORParallelAt`** are the low-level parallel XOR helpers exposed for callers that want the wrap-style worker-pool split without the surrounding wrap envelope. `XORParallelAt(name, key, nonce, base, dst, src)` accepts a `base` byte offset so the leading chunk is positioned at the caller's intended starting point and the result stays byte-identical to a serial XOR over the same `(key, nonce, base, src)` tuple.

### Wire format

The blob wire is `nonce(NonceSize(name)) || keystream-XOR(blob)`; total length is `NonceSize(name) + len(blob)`. The streaming wire is `nonce(NonceSize(name)) || keystream-XOR(continuous bytestream)` where the continuous bytestream is the concatenation of every byte the caller writes through the wrap writer. The single keystream advances monotonically across all bytes within one wrap session; a fresh CSPRNG nonce is generated per session, emitted once at stream start, and never reused across sessions. This is standard CTR mode usage — within one stream, one nonce plus counter is correct.

No length-prefix or other framing byte appears in cleartext on the wire in any wrap shape. The User-Driven Loop variant emits per-chunk length prefixes through the wrap writer so the framing bytes also pass through the keystream XOR alongside the chunk bodies.

## Outer ciphers

The keystream for each outer cipher is built by the [`ctr`](../ctr/) package,
which is the single source of truth for cipher key / nonce sizes. The wrapper
delegates `MakeKeystream` / `KeySize` / `NonceSize` to it.

| Cipher | Key | Nonce |
|---|---|---|
| Areion-SoEM-256 | 32 B | 16 B |
| Areion-SoEM-512 | 64 B | 16 B |
| BLAKE2b-256 | 32 B | 16 B |
| BLAKE2b-512 | 32 B | 16 B |
| BLAKE2s | 32 B | 16 B |
| BLAKE3 | 32 B | 16 B |
| AES-128-CTR | 16 B | 16 B |
| SipHash-2-4 in CTR mode | 16 B | 16 B |
| ChaCha20 (RFC 8439) | 32 B | 12 B |

For the per-cipher construction detail (including the SipHash-CTR PRF-counter
keystream), see [`ctr/CONSTRUCTIONS.md`](../ctr/CONSTRUCTIONS.md).

## Quick Start

The wrapper composes on top of ITB's Triple 8-seed surface. Two canonical wrap shapes cover the surface:

- **Blob wrap** (`Wrap` / `Unwrap`) — the Single Message pair. Wraps one ITB blob returned from `triple.Pipeline.EncryptMessage` (or the Low-Level `Encrypt3xNNNCfg`) with `nonce || keystream-XOR(blob)`.
- **Stream wrap** (`NewWrapWriter` / `NewUnwrapReader`) — the streaming pair. Sits between the caller and the ITB Streaming AEAD / Streaming Non-AEAD reader / writer so every byte of the ITB wire passes through the outer keystream.

Full end-to-end examples covering the canonical 4-triple / 2-Low-Level example set live in the [top-level ITB README](https://github.com/everanium/itb#readme); the two shapes below are the wrap-side snippets those examples plug in.

### Blob wrap — Single Message

```go
import (
    "github.com/everanium/itb/triple"
    "github.com/everanium/itb/wrapper"
)

sender, blob, _ := triple.Init(triple.ProfileSingleMsgTripleMACV1, triple.Opts{})
defer sender.Close()

encrypted, _ := sender.EncryptMessage(plaintext)

// Fresh outer cipher key per test; in a real deployment derive from a
// shared master via wrapper.DeriveKey(cipherName, master).
outerKey, _ := wrapper.GenerateKey(cipherName)
wire, _ := wrapper.Wrap(cipherName, outerKey, encrypted)

// Receiver
receiver, _ := triple.Open(triple.ProfileSingleMsgTripleMACV1, blob, triple.Opts{})
defer receiver.Close()

recovered, _ := wrapper.Unwrap(cipherName, outerKey, wire)
pt, _ := receiver.DecryptMessage(recovered)
```

### Stream wrap — Streaming AEAD IO-Driven

```go
import (
    "bytes"

    "github.com/everanium/itb/triple"
    "github.com/everanium/itb/wrapper"
)

sender, blob, _ := triple.Init(triple.ProfileStreamingAEADTripleMACV1, triple.Opts{})
defer sender.Close()

outerKey, _ := wrapper.GenerateKey(cipherName)

var wireBuf bytes.Buffer
wrapWriter, _ := wrapper.NewWrapWriter(cipherName, outerKey, &wireBuf)
_ = sender.EncryptStream(plaintextReader, wrapWriter)

// Receiver
receiver, _ := triple.Open(triple.ProfileStreamingAEADTripleMACV1, blob, triple.Opts{})
defer receiver.Close()

unwrapReader, _ := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wireBuf.Bytes()))
var dst bytes.Buffer
_ = receiver.DecryptStream(unwrapReader, &dst)
```

Non-AEAD streaming picks `triple.ProfileStreamingNoAEADTripleV1` at `triple.Init`. Both cipher shapes accept the same wrap shape — the outer cipher is oblivious to whether ITB is producing AEAD or Non-AEAD wire underneath.

### Low-Level wrap

Callers driving the Low-Level `EncryptStreamAuth3xNNNCfg` / `Encrypt3xNNNCfg` entry points directly compose the same wrap shapes above around the caller-produced byte slice or `io.Reader` / `io.Writer` — the wrapper sees only bytes and does not care whether the source is the facade or the Low-Level entry points. The eight-seed constellation (`noiseSeed, lockSeed, dataSeed1..3, startSeed1..3`) is threaded through the Low-Level call in the usual way.

## Verification matrix

Every wrap shape × cipher combination round-trips against random plaintext (1 KiB for Single Message, 64 KiB for streaming) with sha256 byte-equality inside the wrapper's test suite. The wire-byte delta between cipher columns is exactly the per-stream nonce-size delta (16 vs 12 vs 16 bytes); the User-Driven Loop variants additionally include 4 bytes of keystream-XORed length prefix per chunk.

## Performance

Bench numbers across the wrapper only round-trip and the Full ITB + wrapper (Single Message and Streaming, encrypt / decrypt split sub-benches) are tracked in [BENCH.md](BENCH.md).

## Notes on outer cipher key management

The wrapper itself does not address outer key distribution; the examples generate a fresh CSPRNG outer key per run for self-test purposes. In a real deployment the outer key is shared out-of-band (or derived via a separate key-exchange step) and is independent of the ITB seed material. The ITB state blob already carries the inner cipher's keying material; the outer key is the additional piece both endpoints need.

The outer key MAY be reused across many streams provided each stream uses a fresh CSPRNG nonce — this is the standard CTR mode safety contract. The wrapper helpers always generate a fresh nonce internally, so caller-side discipline is reduced to "do not reuse the same `(key, nonce)` across distinct streams" — a contract the helper enforces by construction.

## What this is not

- Not an integrity layer. The outer cipher is unauthenticated by design — adding a MAC at this layer would defeat the format-deniability goal (the resulting wire would pattern-match an AEAD construction's tag-bearing format, not a generic stream cipher). Use the ITB AEAD path when integrity is required.
- Not a substitute for ITB's content-deniability. ITB still provides the unconditional content-deniability; the wrap adds format-deniability on top.
