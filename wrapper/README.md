# ITB Format-Deniability Wrapper

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Companion code for the ITB Quick Start. Every example mirrors one configuration from the [ITB README](https://github.com/everanium/itb#readme) and adds a thin user-side outer cipher envelope so the on-wire bytes look like generic stream cipher output rather than ITB format pixel containers + per-chunk prefix.

## Threat model

ITB encrypts content into RGBWYOPA pixel containers. The construction provides **content-deniability** unconditionally — no plaintext bit can be extracted from the wire. The wire pattern itself, however, is parseable by an observer who knows the ITB format:

- Non-AEAD path: per-chunk header carries width / height / container layout.
- Streaming AEAD path: a once per-stream 32-byte streamID prefix plus per-chunk `nonce || W || H || container || flag_byte`.

A passive observer who knows ITB ships with an 8-channel pixel container and a 32-byte streamID prefix can pattern-match the bytes. The format-deniability wrap hides that surface under a generic outer cipher — any of PRF-grade ITB registry primitives (Areion-SoEM-256/512, BLAKE2b-256/512, BLAKE2s, BLAKE3, AES-128-CTR, SipHash-2-4 in CTR mode, ChaCha20 (RFC 8439)). After wrapping, the wire is `nonce || keystream-XOR(bytestream)` — the same shape used by countless other protocols. An observer sees a small leading nonce followed by pseudorandom-looking bytes; pattern-matching does not distinguish ITB from any other stream cipher payload.

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
- **Cipher constants** (`CipherAreion256` ... `CipherChaCha20`) name every outer cipher the wrapper accepts. `CipherAES128CTR = "aescmac"` is the registry alias for AES-128 in CTR mode (identical to the underlying cipher behind the `aescmac` MAC entry). `CipherNames` enumerates all of them in canonical primitive order; it is the iteration source for cross-cipher tests and benchmarks.
- **`ParallelThreshold`** is the byte cap below which `Wrap` / `Unwrap` / `WrapInPlace` / `UnwrapInPlace` keep the body XOR in the caller's goroutine. Above it the work is split across up to `min(32, GOMAXPROCS, chunks)` worker goroutines, each seeking its own keystream to the chunk's byte offset via `ctr.NewAt`. Exposed as a read-only constant for out-of-package tests and benchmarks.
- **`KeySize` / `NonceSize`** report the per-cipher key and nonce widths in bytes; both delegate to [`ctr`](../ctr/), which is the single source of truth for the registered cipher sizing.
- **`GenerateKey`** draws a fresh CSPRNG outer-cipher key of the appropriate width. Use this in self-test contexts or when no out-of-band key material is available.
- **`DeriveKey`** derives a deterministic outer-cipher key from a high-entropy master via [`kdf.Derive`](../kdf/) under a wrapper-specific label. Use this when the application already holds a shared secret (an ML-KEM encapsulated key, an HKDF output, an out-of-band negotiated key) and wants the outer-cipher key to be reproducible without re-distribution. The caller wipes the master after this returns.
- **`MakeKeystream` / `MakeKeystreamAt`** construct a `Keystream` ready to XOR data. `MakeKeystreamAt(name, key, nonce, offset)` is the byte-offset positioned variant; it returns a keystream as if `MakeKeystream` had been called and then advanced by `offset` bytes — used by the worker pool to split one logical keystream into disjoint parallel chunks that re-concatenate byte-identical to a serial pass.
- **`Wrap` / `Unwrap`** are the blob (Single Message) round-trip pair. `Wrap` allocates a fresh `nonce(NonceSize(name)) || keystream-XOR(blob)` wire, drawing the nonce from `crypto/rand`. `Unwrap` reverses it.
- **`WrapInPlace` / `UnwrapInPlace`** are the zero-body-allocation counterparts. `WrapInPlace` mutates `blob` to its ciphertext form and returns the assembled wire; on error `blob` is left unchanged.
- **`NewWrapWriter` / `NewUnwrapReader`** are the streaming wrap surface. The wrap writer emits the nonce on its first underlying `dst.Write` then XORs every subsequent byte through the keystream; the unwrap reader is symmetric. One stream session uses one nonce and the keystream counter advances monotonically across every byte written.
- **`XORParallel` / `XORParallelAt`** are the low-level parallel XOR helpers exposed for callers that want the wrap-style worker-pool split without the surrounding wrap envelope. `XORParallelAt(name, key, nonce, base, dst, src)` accepts a `base` byte offset so the leading chunk is positioned at the caller's intended starting point and the result stays byte-identical to a serial XOR over the same `(key, nonce, base, src)` tuple.

### Wire format

The blob wire is `nonce(NonceSize(name)) || keystream-XOR(blob)`; total length is `NonceSize(name) + len(blob)`. The streaming wire is `nonce(NonceSize(name)) || keystream-XOR(continuous bytestream)` where the continuous bytestream is the concatenation of every byte the caller writes through the wrap writer. The single keystream advances monotonically across all bytes within one wrap session; a fresh CSPRNG nonce is generated per session, emitted once at stream start, and never reused across sessions. This is standard CTR mode usage — within one stream, one nonce plus counter is correct.

No length-prefix or other framing byte appears in cleartext on the wire in any wrap shape. The User-Driven Loop variant emits per-chunk length prefixes through the wrap writer so the framing bytes also pass through the keystream XOR alongside the chunk bodies.

### Wrap-shape pairs

| Helper pair | Wire format | Use case |
|---|---|---|
| `Wrap` / `Unwrap` (+ `WrapInPlace` / `UnwrapInPlace`) | `nonce || keystream-XOR(blob)` | Single Message Encrypt / EncryptAuth output |
| `NewWrapWriter` / `NewUnwrapReader` | `nonce || keystream-XOR(continuous bytestream)` | streaming — IO-Driven, or User-Driven Loop where caller-side framing (e.g. per-chunk `u32_LE` length prefixes) is written through the wrap writer so the framing bytes also pass through the keystream XOR |

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

Code paths under `tools/eitb/main.go`. Run the matrix:

```sh
go run ./tools/eitb       # run every example × every cipher
go run ./tools/eitb -help # print help
```

### 1. Streaming AEAD Easy (MAC Authenticated, IO-Driven)

ITB Call: `easy.Encryptor.EncryptStreamAuthIO` / `DecryptStreamAuthIO`. Wrap shape: `NewWrapWriter` / `NewUnwrapReader` over the continuous bytestream ITB emits.

```go
enc := easy.New("areion512", 1024, "hmac-blake3")
defer enc.Close()
enc.SetNonceBits(512); enc.SetBarrierFill(4); enc.SetBitSoup(1); enc.SetLockSoup(1)

// Alternative — derive deterministically from an external master (e.g. an ML-KEM shared secret):
// outerKey, _ := wrapper.DeriveKey(cipherName, master); clear(master)
outerKey, _ := wrapper.GenerateKey(cipherName)

// Sender
var wireBuf bytes.Buffer
wrapWriter, _ := wrapper.NewWrapWriter(cipherName, outerKey, &wireBuf)
_ = enc.EncryptStreamAuthIO(plaintextReader, wrapWriter, chunkSize)

// Receiver
unwrapReader, _ := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wireBuf.Bytes()))
var dst bytes.Buffer
_ = enc.DecryptStreamAuthIO(unwrapReader, &dst)
```

### 2. Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)

ITB Call: `itb.EncryptStreamAuth` / `itb.DecryptStreamAuth` with three explicit `*Seed512` handles plus `macs.Make("hmac-blake3", key)`. Wrap shape: `NewWrapWriter` / `NewUnwrapReader`.

```go
hashFn, _, _ := hashes.Make512("areion512")
noise, _ := itb.NewSeed512(1024, hashFn)
data,  _ := itb.NewSeed512(1024, hashFn)
start, _ := itb.NewSeed512(1024, hashFn)

macKey := make([]byte, 32); rand.Read(macKey)
macFunc, _ := macs.Make("hmac-blake3", macKey)

// Alternative — derive deterministically from an external master (e.g. an ML-KEM shared secret):
// outerKey, _ := wrapper.DeriveKey(cipherName, master); clear(master)
outerKey, _ := wrapper.GenerateKey(cipherName)
wrapWriter, _ := wrapper.NewWrapWriter(cipherName, outerKey, &wireBuf)
_ = itb.EncryptStreamAuth(noise, data, start, plaintextReader, wrapWriter, macFunc, chunkSize)

// receiver
unwrapReader, _ := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wireBuf.Bytes()))
_ = itb.DecryptStreamAuth(noise, data, start, unwrapReader, &dst, macFunc)
```

### 3. Streaming Easy (No MAC, IO-Driven)

ITB Call: `easy.Encryptor.EncryptStreamIO` / `DecryptStreamIO`. Wrap shape: `NewWrapWriter` / `NewUnwrapReader`. The outer cipher contributes format-deniability only — does not retro-fit integrity onto the No MAC ITB path.

```go
enc := easy.New("areion512", 1024)
// Set* configuration unchanged from authenticated variant.
wrapWriter, _ := wrapper.NewWrapWriter(cipherName, outerKey, &wireBuf)
_ = enc.EncryptStreamIO(plaintextReader, wrapWriter, chunkSize)

unwrapReader, _ := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wireBuf.Bytes()))
_ = enc.DecryptStreamIO(unwrapReader, &dst)
```

### 4. Streaming Easy (No MAC, User-Driven Loop)

The README's "Alternative — User-Driven Loop" pattern: each chunk is one independent `enc.Encrypt(buf[:n])` call. Wrap shape: `NewWrapWriter` / `NewUnwrapReader` driven by a caller loop that emits `u32_LE_len || ct` per chunk through the wrapped writer. Length prefix and chunk body both pass through the keystream XOR — no length appears in cleartext on the wire.

```go
// Alternative — derive deterministically from an external master (e.g. an ML-KEM shared secret):
// outerKey, _ := wrapper.DeriveKey(cipherName, master); clear(master)
outerKey, _ := wrapper.GenerateKey(cipherName)

// Sender
var wireBuf bytes.Buffer
wrapWriter, _ := wrapper.NewWrapWriter(cipherName, outerKey, &wireBuf)

buf := make([]byte, chunkSize)
for {
    n, rerr := io.ReadFull(plaintextReader, buf)
    if rerr == io.EOF { break }
    ct, _ := enc.Encrypt(buf[:n])
    _ = binary.Write(wrapWriter, binary.LittleEndian, uint32(len(ct)))
    _, _ = wrapWriter.Write(ct)
    if rerr == io.ErrUnexpectedEOF { break }
}

// Receiver — read u32_LE length then body through the unwrap-reader, looping until EOF.
unwrapReader, _ := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wireBuf.Bytes()))
for {
    var ctLen uint32
    if err := binary.Read(unwrapReader, binary.LittleEndian, &ctLen); err == io.EOF {
        break
    } else if err != nil {
        panic(err)
    }
    ctBuf := make([]byte, ctLen)
    _, _ = io.ReadFull(unwrapReader, ctBuf)
    pt, _ := enc.Decrypt(ctBuf)
    out.Write(pt)
}
```

### 5. Streaming Low-Level (No MAC, IO-Driven)

ITB Call: `itb.EncryptStream` / `itb.DecryptStream`. Wrap shape: `NewWrapWriter` / `NewUnwrapReader`.

```go
hashFn, _, _ := hashes.Make512("areion512")
noise, _ := itb.NewSeed512(1024, hashFn)
data,  _ := itb.NewSeed512(1024, hashFn)
start, _ := itb.NewSeed512(1024, hashFn)

wrapWriter, _ := wrapper.NewWrapWriter(cipherName, outerKey, &wireBuf)
_ = itb.EncryptStream(noise, data, start, plaintextReader, wrapWriter, chunkSize)

unwrapReader, _ := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wireBuf.Bytes()))
_ = itb.DecryptStream(noise, data, start, unwrapReader, &dst)
```

### 6. Streaming Low-Level (No MAC, User-Driven Loop)

Per-chunk `itb.Encrypt` / `itb.Decrypt` with caller-side framing. Wrap shape: `NewWrapWriter` / `NewUnwrapReader`. Each chunk is emitted as `u32_LE_len || ct` through the wrap-writer; the length and the body both pass through the keystream XOR.

```go
// Alternative — derive deterministically from an external master (e.g. an ML-KEM shared secret):
// outerKey, _ := wrapper.DeriveKey(cipherName, master); clear(master)
outerKey, _ := wrapper.GenerateKey(cipherName)

var wireBuf bytes.Buffer
wrapWriter, _ := wrapper.NewWrapWriter(cipherName, outerKey, &wireBuf)

buf := make([]byte, chunkSize)
for {
    n, rerr := io.ReadFull(plaintextReader, buf)
    if rerr == io.EOF { break }
    ct, _ := itb.Encrypt(noise, data, start, buf[:n])
    _ = binary.Write(wrapWriter, binary.LittleEndian, uint32(len(ct)))
    _, _ = wrapWriter.Write(ct)
    if rerr == io.ErrUnexpectedEOF { break }
}

// Receiver
unwrapReader, _ := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wireBuf.Bytes()))
for {
    var ctLen uint32
    if err := binary.Read(unwrapReader, binary.LittleEndian, &ctLen); err == io.EOF {
        break
    } else if err != nil {
        panic(err)
    }
    ctBuf := make([]byte, ctLen)
    _, _ = io.ReadFull(unwrapReader, ctBuf)
    pt, _ := itb.Decrypt(noise, data, start, ctBuf)
    out.Write(pt)
}
```

### 7. Easy: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: `enc.Encrypt(plaintext)` returns one ITB blob. Wrap shape: `Wrap` — `nonce || ks-XOR(blob)`. Wire shape mirrors any "outer cipher with a fresh nonce and an opaque payload" pattern.

```go
enc := easy.New("areion512", 2048)
defer enc.Close()
enc.SetNonceBits(512); enc.SetBarrierFill(4); enc.SetBitSoup(1); enc.SetLockSoup(1)

encrypted, _ := enc.Encrypt(plaintext)

// Alternative — derive deterministically from an external master (e.g. an ML-KEM shared secret):
// outerKey, _ := wrapper.DeriveKey(cipherName, master); clear(master)
outerKey, _ := wrapper.GenerateKey(cipherName)
wire, _ := wrapper.Wrap(cipherName, outerKey, encrypted)

// receiver
recovered, _ := wrapper.Unwrap(cipherName, outerKey, wire)
pt, _ := enc.Decrypt(recovered)
```

### 8. Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: `enc.EncryptAuth` / `enc.DecryptAuth`. Wrap shape: `Wrap`. The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

```go
enc := easy.New("areion512", 2048, "hmac-blake3")
defer enc.Close()
enc.SetNonceBits(512); enc.SetBarrierFill(4); enc.SetBitSoup(1); enc.SetLockSoup(1)

encrypted, _ := enc.EncryptAuth(plaintext)

// Alternative — derive deterministically from an external master (e.g. an ML-KEM shared secret):
// outerKey, _ := wrapper.DeriveKey(cipherName, master); clear(master)
outerKey, _ := wrapper.GenerateKey(cipherName)
wire, _ := wrapper.Wrap(cipherName, outerKey, encrypted)

// receiver
recovered, _ := wrapper.Unwrap(cipherName, outerKey, wire)
pt, _ := enc.DecryptAuth(recovered)
```

### 9. Low-Level: Areion-SoEM-512 (No MAC, Single Message)

ITB Call: width-less `itb.Encrypt(noise, data, start, plaintext)` / `itb.Decrypt(...)` with three explicit `*Seed512` handles built from `hashes.Make512("areion512")`. Wrap shape: `Wrap` — `nonce || ks-XOR(blob)`. Wire shape matches example 7; the difference is that the seed material is held by caller-side handles rather than by an `easy.Encryptor` instance.

```go
itb.SetNonceBits(512); itb.SetBarrierFill(4); itb.SetBitSoup(1); itb.SetLockSoup(1)

hashFn, _, _ := hashes.Make512("areion512")
noise, _ := itb.NewSeed512(2048, hashFn)
data,  _ := itb.NewSeed512(2048, hashFn)
start, _ := itb.NewSeed512(2048, hashFn)

encrypted, _ := itb.Encrypt(noise, data, start, plaintext)

// Alternative — derive deterministically from an external master (e.g. an ML-KEM shared secret):
// outerKey, _ := wrapper.DeriveKey(cipherName, master); clear(master)
outerKey, _ := wrapper.GenerateKey(cipherName)
wire, _ := wrapper.Wrap(cipherName, outerKey, encrypted)

// receiver
recovered, _ := wrapper.Unwrap(cipherName, outerKey, wire)
pt, _ := itb.Decrypt(noise, data, start, recovered)
```

### 10. Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)

ITB Call: width-less `itb.EncryptAuth(noise, data, start, plaintext, macFunc)` / `itb.DecryptAuth(...)` with the MAC closure constructed via `macs.Make("hmac-blake3", macKey)`. Wrap shape: `Wrap`. The ITB-internal 32-byte MAC tag remains inside the RGBWYOPA container; outer cipher is format-deniability only.

```go
itb.SetNonceBits(512); itb.SetBarrierFill(4); itb.SetBitSoup(1); itb.SetLockSoup(1)

hashFn, _, _ := hashes.Make512("areion512")
noise, _ := itb.NewSeed512(2048, hashFn)
data,  _ := itb.NewSeed512(2048, hashFn)
start, _ := itb.NewSeed512(2048, hashFn)

macKey := make([]byte, 32); rand.Read(macKey)
macFunc, _ := macs.Make("hmac-blake3", macKey)

encrypted, _ := itb.EncryptAuth(noise, data, start, plaintext, macFunc)

// Alternative — derive deterministically from an external master (e.g. an ML-KEM shared secret):
// outerKey, _ := wrapper.DeriveKey(cipherName, master); clear(master)
outerKey, _ := wrapper.GenerateKey(cipherName)
wire, _ := wrapper.Wrap(cipherName, outerKey, encrypted)

// receiver
recovered, _ := wrapper.Unwrap(cipherName, outerKey, wire)
pt, _ := itb.DecryptAuth(noise, data, start, recovered, macFunc)
```

## Verification matrix

Every example × cipher combination round-trips against random plaintext (1 KiB for Single Message, 64 KiB for streaming) with sha256 byte-equality. Sample run:

```
[PASS] aead-easy-io               + areion256   pt=65536 wire=90208
[PASS] aead-easy-io               + areion512   pt=65536 wire=90208
[PASS] aead-easy-io               + blake2b256   pt=65536 wire=90208
[PASS] aead-easy-io               + blake2b512   pt=65536 wire=90208
[PASS] aead-easy-io               + blake2s    pt=65536 wire=90208
[PASS] aead-easy-io               + blake3     pt=65536 wire=90208
[PASS] aead-easy-io               + aescmac    pt=65536 wire=90208
[PASS] aead-easy-io               + siphash24   pt=65536 wire=90208
[PASS] aead-easy-io               + chacha20   pt=65536 wire=90204
...
[PASS] message-lowlevel-auth      + areion256   pt=1024 wire=8276
[PASS] message-lowlevel-auth      + areion512   pt=1024 wire=8276
[PASS] message-lowlevel-auth      + blake2b256   pt=1024 wire=8276
[PASS] message-lowlevel-auth      + blake2b512   pt=1024 wire=8276
[PASS] message-lowlevel-auth      + blake2s    pt=1024 wire=8276
[PASS] message-lowlevel-auth      + blake3     pt=1024 wire=8276
[PASS] message-lowlevel-auth      + aescmac    pt=1024 wire=8276
[PASS] message-lowlevel-auth      + siphash24   pt=1024 wire=8276
[PASS] message-lowlevel-auth      + chacha20   pt=1024 wire=8272
```

The wire-byte difference between cipher columns is exactly the per-stream nonce-size delta (16 vs 12 vs 16 bytes); the User-Driven Loop variants additionally include 4 bytes of keystream-XORed length prefix per chunk.

## Performance

Bench numbers across Single Ouroboros and Triple Ouroboros, message and streaming, encrypt and decrypt (split sub-benches) are tracked in [BENCH.md](BENCH.md).

## Notes on outer cipher key management

The wrapper itself does not address outer key distribution; the examples generate a fresh CSPRNG outer key per run for self-test purposes. In a real deployment the outer key is shared out-of-band (or derived via a separate key-exchange step) and is independent of the ITB seed material. The ITB state blob already carries the inner cipher's keying material; the outer key is the additional piece both endpoints need.

The outer key MAY be reused across many streams provided each stream uses a fresh CSPRNG nonce — this is the standard CTR mode safety contract. The wrapper helpers always generate a fresh nonce internally, so caller-side discipline is reduced to "do not reuse the same `(key, nonce)` across distinct streams" — a contract the helper enforces by construction.

## What this is not

- Not an integrity layer. The outer cipher is unauthenticated by design — adding a MAC at this layer would defeat the format-deniability goal (the resulting wire would pattern-match an AEAD construction's tag-bearing format, not a generic stream cipher). Use the ITB AEAD path when integrity is required.
- Not a substitute for ITB's content-deniability. ITB still provides the unconditional content-deniability; the wrap adds format-deniability on top.
