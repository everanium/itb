## ITB Format-Deniability Wrapper

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB composes established, standardized primitives rather than introducing new cryptographic designs. Security properties and regulatory status are inherited from the underlying primitives; see [README.md](../README.md) for jurisdictional certification details.

Companion code for the ITB Quick Start. The examples below layer a thin outer cipher envelope over ITB ciphertext so the on-wire bytes look like generic stream cipher output rather than recognizable wire framing.

## Threat model

ITB provides **content-deniability** unconditionally — no plaintext bit can be extracted from the wire. The raw wire pattern itself, however, carries structural framing and headers parseable by an observer who knows the ITB specification:

- Non-AEAD path: a 32-byte CSPRNG prefix ahead of every chunk plus structural dimension and layout framing headers.
- AEAD path: a 32-byte prefix ahead of every chunk (the streamID ahead of the first) plus per-chunk framing and deniable termination indicators.

A passive observer searching for ITB signatures could identify these wire structures. The format-deniability wrap hides that surface under a generic outer cipher — any PRF-grade ITB registry primitive. After wrapping, the wire is `nonce || keystream-XOR(bytestream)` — the same shape used by standard stream ciphers. An observer sees a leading nonce followed by pseudorandom-looking bytes; pattern-matching does not distinguish ITB from any other stream cipher payload.

This is **not** a random-oracle indistinguishability claim. It is a "looks like a different well-known cipher" claim. The wrap exists for format-deniability **only**; ITB already provides confidentiality (content-deniability) and the AEAD path already provides per-stream and per-chunk integrity. The Non-AEAD streaming path has no integrity by design and the wrap does not add any.

## Public API

```go
type Keystream = ctr.Keystream

const (
    ParallelThreshold = 256 * 1024
    MaxMasterKeySize  = 128
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
func FinishWrapStream(w io.Writer) error

func XORParallel(name string, key, nonce, dst, src []byte) error
func XORParallelAt(name string, key, nonce []byte, base int, dst, src []byte) error
```

- **`Keystream`** is the outer cipher's CTR-mode keystream interface, aliased directly from `ctr.Keystream`. The contract matches `crypto/cipher.Stream`: `XORKeyStream(dst, src)` xors one keystream segment over `src` into `dst` and advances the internal counter.
- **`CipherNames`** enumerates the outer cipher palette in canonical primitive order as a snapshot of the shipped `hashes.Registry` names (`hashes.KeystreamNames()`); it is the iteration source for cross-cipher tests and benchmarks. Each entry is named by a `hashes.Cipher*` constant; `hashes.CipherAES128CTR = "aescmac"` is the registry alias for AES-128 in CTR mode (identical to the underlying cipher behind the `aescmac` MAC entry).
- **`ParallelThreshold`** is the byte cap below which `Wrap` / `Unwrap` / `WrapInPlace` / `UnwrapInPlace` keep the body XOR in the caller's goroutine. Above it the work is split across up to `min(32, GOMAXPROCS, chunks)` worker goroutines, each seeking its own keystream to the chunk's byte offset via `ctr.NewAt`. Exposed as a read-only constant for out-of-package tests and benchmarks.
- **`KeySize` / `NonceSize`** report the per-cipher key and nonce widths in bytes; both delegate to [`ctr`](../ctr/), which is the single source of truth for the registered cipher sizing.
- **`GenerateKey`** draws a fresh CSPRNG outer cipher key of the appropriate width. Use this in self-test contexts or when no out-of-band key material is available.
- **`DeriveKey`** derives a deterministic outer cipher key from a high-entropy master (`32 <= len(master) <= MaxMasterKeySize`) via [`kdf.Derive`](../kdf/) under a wrapper-specific label. Use this when the application already holds a shared secret (an ML-KEM encapsulated key, an HKDF output, an out-of-band negotiated key) and wants the outer cipher key to be reproducible without re-distribution. The caller wipes the master after this returns.
- **`MakeKeystream` / `MakeKeystreamAt`** construct a `Keystream` ready to XOR data. `MakeKeystreamAt(name, key, nonce, offset)` is the byte-offset positioned variant; it returns a keystream as if `MakeKeystream` had been called and then advanced by `offset` bytes — used by the worker pool to split one logical keystream into disjoint parallel chunks that re-concatenate byte-identical to a serial pass.
- **`Wrap` / `Unwrap`** are the blob (Single Message) round-trip pair. `Wrap` allocates a fresh `nonce(NonceSize(name)) || keystream-XOR(blob)` wire, drawing the nonce from `crypto/rand`. `Unwrap` reverses it.
- **`WrapInPlace` / `UnwrapInPlace`** are the zero-body-allocation counterparts. `WrapInPlace` mutates `blob` to its ciphertext form in place and returns the per-stream nonce; the caller emits `nonce` followed by `blob` to the wire without allocating an intermediate wire buffer. `UnwrapInPlace` strips the leading nonce from `wire`, XOR-decrypts the body in place, and returns an aliased slice `wire[NonceSize(name):]` to the decrypted data.
- **`NewWrapWriter` / `NewUnwrapReader`** are the streaming wrap surface. The wrap writer emits the nonce on its first underlying `dst.Write` then XORs every subsequent byte through the keystream; the unwrap reader is symmetric. One stream session uses one nonce and the keystream counter advances monotonically across every byte written.
- **`FinishWrapStream`** flushes and finalises a stream created with `NewWrapWriter`, ensuring any pending nonce is emitted even if zero payload bytes were written.
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

**Per-stream length cap under ChaCha20 outer cipher — 256 GiB per `(key, nonce)`.** RFC 8439 fixes the ChaCha20 block counter at 32 bits, so one logical outer cipher stream under a single `(key, nonce)` covers at most `2^32 × 64 B = 256 GiB` before the counter would wrap. `ctr.NewAt` returns an explicit error at the first seek at or above that offset rather than silently reusing keystream. The impact of a hypothetical wrap is scoped to the outer format-deniability layer — inner ITB confidentiality is not carried by the outer cipher and stays intact regardless — but the wrapper still refuses the wrap because reused outer keystream weakens format deniability at the wire (an attacker XORing two wire positions exactly 256 GiB apart would cancel the outer whitener and expose the inner ITB-encrypted body pattern to traffic analysis, though not the plaintext). For streaming a single logical outer stream past this cap, choose an outer cipher whose counter is wider than 32 bits — **AES-128-CTR** uses a 128-bit big-endian counter and is practically unlimited for random nonces; SipHash-CTR and the PRF-counter ciphers (Areion, BLAKE2, BLAKE3) all use 64-bit counters.

For the per-cipher construction detail (including the SipHash-CTR PRF-counter
keystream), see [`ctr/CONSTRUCTIONS.md`](../ctr/CONSTRUCTIONS.md).

## Quick Start

The wrapper composes on top of ITB's Triple surface. Standard Triple profiles (`ProfileSingleMsgTripleMACV1`, `ProfileStreamingAEADTripleMACV1`) already engage the format-deniability wrapper automatically. Manual composition via `wrapper.Wrap` or `wrapper.NewWrapWriter` is intended for custom pipelines where the built-in wrapper is disengaged (`triple.Opts{WithWrapper: &noWrap}`), for Low-Level ITB entry points (`Encrypt3xNNNCfg`), or for external ciphertext streams. In the examples below, the pipeline's internal wrapper is explicitly disengaged (`withWrap := false`) to prevent double wrapping.

Two canonical wrap shapes cover the surface:

- **Blob wrap** (`Wrap` / `Unwrap`) — the Single Message pair. Wraps one ITB blob returned from `triple.Pipeline.EncryptMessage` (or the Low-Level `Encrypt3xNNNCfg`) with `nonce || keystream-XOR(blob)`.
- **Stream wrap** (`NewWrapWriter` / `NewUnwrapReader`) — the streaming pair. Sits between the caller and the ITB Streaming AEAD / Streaming Non-AEAD reader / writer so every byte of the ITB wire passes through the outer keystream.

Full end-to-end examples covering the canonical four-Triple / two-Low-Level example set live in the [top-level ITB README](https://github.com/everanium/itb#readme); the two shapes below are the wrap-side snippets those examples plug in.

### Blob wrap — Single Message

```go
import (
    "github.com/everanium/itb/triple"
    "github.com/everanium/itb/wrapper"
)

// Disengage internal wrapper to avoid double wrapping when wrapping manually:
withWrap := false
sender, blob, _ := triple.Init(triple.ProfileSingleMsgTripleMACV1, triple.Opts{
    WithWrapper: &withWrap,
})
defer sender.Close()
// Persist the session bundle for a receiver:
//   _ = sender.SaveF("session.json")
// The receiver reopens with:
//   receiver, _ := triple.LoadF("session.json")

encrypted, _ := sender.EncryptMessage(plaintext)

// Fresh outer cipher key per test; in a real deployment derive from a
// shared master via wrapper.DeriveKey(cipherName, master).
outerKey, _ := wrapper.GenerateKey(cipherName)
wire, _ := wrapper.Wrap(cipherName, outerKey, encrypted)

// Receiver — the blob carries the resolved recipe; no profile
// registration and no Opts are needed on the receiving side.
receiver, _ := triple.Load(blob)
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

withWrap := false
sender, blob, _ := triple.Init(triple.ProfileStreamingAEADTripleMACV1, triple.Opts{
    WithWrapper: &withWrap,
})
defer sender.Close()
// Persist the session bundle for a receiver:
//   _ = sender.SaveF("session.json")
// The receiver reopens with:
//   receiver, _ := triple.LoadF("session.json")

outerKey, _ := wrapper.GenerateKey(cipherName)

var wireBuf bytes.Buffer
wrapWriter, _ := wrapper.NewWrapWriter(cipherName, outerKey, &wireBuf)
_ = sender.EncryptStream(plaintextReader, wrapWriter)

// Receiver — the blob carries the resolved recipe; no profile
// registration and no Opts are needed on the receiving side.
receiver, _ := triple.Load(blob)
defer receiver.Close()

unwrapReader, _ := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wireBuf.Bytes()))
var dst bytes.Buffer
_ = receiver.DecryptStream(unwrapReader, &dst)
```

Non-AEAD streaming picks `triple.ProfileStreamingNoAEADTripleV1` at `triple.Init`. Both cipher shapes accept the same wrap shape — the outer cipher is oblivious to whether ITB is producing AEAD or Non-AEAD wire underneath.

### Low-Level wrap

Callers driving the Low-Level `EncryptStreamAuth3xNNNCfg` / `Encrypt3xNNNCfg` entry points directly compose the same wrap shapes above around the caller-produced byte slice or `io.Reader` / `io.Writer` — the wrapper sees only bytes and does not care whether the source is the facade or the Low-Level entry points. Session seed material is threaded through the Low-Level call in the usual way.

## Verification matrix

Every wrap shape × cipher combination round-trips against random plaintext (1 KiB for Single Message, 64 KiB for streaming) with sha256 byte-equality inside the wrapper's test suite. The wire-byte delta between cipher columns is exactly the per-stream nonce-size delta (16 bytes for PRF-counter / AES-CTR vs 12 bytes for ChaCha20); the User-Driven Loop variants additionally include 4 bytes of keystream-XORed length prefix per chunk.

## Performance

Bench numbers across the wrapper only round-trip and the Full ITB + wrapper (Single Message and Streaming, encrypt / decrypt split sub-benches) are tracked in [BENCH.md](BENCH.md).

## Notes on outer cipher key management

The wrapper itself does not address outer key distribution; the examples generate a fresh CSPRNG outer key per run for self-test purposes. In a real deployment the outer key is shared out-of-band (or derived via a separate key-exchange step) and is independent of the ITB seed material. The ITB state blob already carries the inner cipher's keying material; the outer key is the additional piece both endpoints need.

The outer key MAY be reused across many streams provided each stream uses a fresh CSPRNG nonce — this is the standard CTR mode safety contract. The wrapper helpers always generate a fresh nonce internally, so caller-side discipline is reduced to "do not reuse the same `(key, nonce)` across distinct streams" — a contract the helper enforces by construction.

## What this is not

- Not an integrity layer. The outer cipher is unauthenticated by design — adding a MAC at this layer would defeat the format-deniability goal (the resulting wire would pattern-match an AEAD construction's tag-bearing format, not a generic stream cipher). Use the ITB AEAD path when integrity is required.
- Not a substitute for ITB's content-deniability. ITB still provides the unconditional content-deniability; the wrap adds format-deniability on top.
