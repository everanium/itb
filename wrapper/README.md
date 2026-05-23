# ITB Examples Code

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Companion code for the ITB Quick Start. Every example mirrors one configuration from the [ITB README](https://github.com/everanium/itb#readme) and adds a thin user-side outer cipher envelope so the on-wire bytes look like generic stream cipher output rather than ITB format pixel containers + per-chunk prefix.

## Threat model

ITB encrypts content into RGBWYOPA pixel containers. The construction provides **content-deniability** unconditionally — no plaintext bit can be extracted from the wire. The wire pattern itself, however, is parseable by an observer who knows the ITB format:

- Non-AEAD path: per-chunk header carries width / height / container layout.
- Streaming AEAD path: a once per-stream 32-byte streamID prefix plus per-chunk `nonce || W || H || container || flag_byte`.

A passive observer who knows ITB ships with an 8-channel pixel container and a 32-byte streamID prefix can pattern-match the bytes. The format-deniability wrap hides that surface under a generic outer cipher: AES-128-CTR, ChaCha20 (RFC8439), or SipHash-2-4 in CTR mode. After wrapping, the wire is `nonce || keystream-XOR(bytestream)` — the same shape used by countless other protocols. An observer sees a small leading nonce followed by pseudorandom-looking bytes; pattern-matching does not distinguish ITB from any other stream cipher payload.

This is **not** a random-oracle indistinguishability claim. It is a "looks like a different well-known cipher" claim. The wrap exists for format-deniability ONLY; ITB already provides confidentiality (content-deniability) and the AEAD path already provides per-stream and per-chunk integrity. The Non-AEAD streaming path has no integrity by design and the wrap does not add any.

## Wrapper API

The wrapper package exposes one `Keystream` interface satisfied by all three outer ciphers, plus two wrap-shape helpers:

| Helper | Wire format | Use case |
|---|---|---|
| `Wrap` / `Unwrap` | `nonce` + keystream-XOR(blob) | Single Message Encrypt / EncryptAuth output |
| `NewWrapWriter` / `NewUnwrapReader` | `nonce` + keystream-XOR(continuous bytestream) | streaming use — IO-Driven, or User-Driven Loop where caller-side framing (e.g. per-chunk `u32_LE` length prefixes) is written through the wrap-writer so the framing bytes also pass through the keystream XOR |

The single keystream advances monotonically across all bytes within one wrap session. A fresh CSPRNG nonce is generated per session; emitted once at stream start; never reused across sessions. This is standard CTR mode usage — within one stream, one nonce + counter is correct.

No length-prefix or other framing byte appears in cleartext on the wire in any wrap shape. The User-Driven Loop emits length prefixes through the wrap-writer so they get XORed into the keystream alongside the chunk bodies.

## Outer ciphers

The keystream for each outer cipher is built by the [`ctr`](../ctr/) package,
which is the single source of truth for cipher key / nonce sizes. The wrapper
delegates `MakeKeystream` / `KeySize` / `NonceSize` to it.

| Cipher | Key | Nonce |
|---|---|---|
| AES-128-CTR | 16 B | 16 B |
| ChaCha20 (RFC 8439) | 32 B | 12 B |
| SipHash-2-4 in CTR mode | 16 B | 16 B |

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
// outerKey, _ := wrapper.DeriveKey(cipherName, master)
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
// outerKey, _ := wrapper.DeriveKey(cipherName, master)
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
// outerKey, _ := wrapper.DeriveKey(cipherName, master)
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
// outerKey, _ := wrapper.DeriveKey(cipherName, master)
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
// outerKey, _ := wrapper.DeriveKey(cipherName, master)
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
// outerKey, _ := wrapper.DeriveKey(cipherName, master)
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
// outerKey, _ := wrapper.DeriveKey(cipherName, master)
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
// outerKey, _ := wrapper.DeriveKey(cipherName, master)
outerKey, _ := wrapper.GenerateKey(cipherName)
wire, _ := wrapper.Wrap(cipherName, outerKey, encrypted)

// receiver
recovered, _ := wrapper.Unwrap(cipherName, outerKey, wire)
pt, _ := itb.DecryptAuth(noise, data, start, recovered, macFunc)
```

## Verification matrix

Every example × cipher combination round-trips against random plaintext (1 KiB for Single Message, 64 KiB for streaming) with sha256 byte-equality. Sample run:

```
[PASS] aead-easy-io                + aescmac    pt=65536 wire=90208
[PASS] aead-easy-io                + chacha20   pt=65536 wire=90204
[PASS] aead-easy-io                + siphash24  pt=65536 wire=90208
[PASS] aead-lowlevel-io            + aescmac    pt=65536 wire=90208
[PASS] aead-lowlevel-io            + chacha20   pt=65536 wire=90204
[PASS] aead-lowlevel-io            + siphash24  pt=65536 wire=90208
[PASS] noaead-easy-io              + aescmac    pt=65536 wire=90176
[PASS] noaead-easy-io              + chacha20   pt=65536 wire=90172
[PASS] noaead-easy-io              + siphash24  pt=65536 wire=90176
[PASS] noaead-easy-userloop        + aescmac    pt=65536 wire=90192
[PASS] noaead-easy-userloop        + chacha20   pt=65536 wire=90188
[PASS] noaead-easy-userloop        + siphash24  pt=65536 wire=90192
[PASS] noaead-lowlevel-io          + aescmac    pt=65536 wire=90176
[PASS] noaead-lowlevel-io          + chacha20   pt=65536 wire=90172
[PASS] noaead-lowlevel-io          + siphash24  pt=65536 wire=90176
[PASS] noaead-lowlevel-userloop    + aescmac    pt=65536 wire=90192
[PASS] noaead-lowlevel-userloop    + chacha20   pt=65536 wire=90188
[PASS] noaead-lowlevel-userloop    + siphash24  pt=65536 wire=90192
[PASS] message-easy-nomac          + aescmac    pt=1024 wire=4316
[PASS] message-easy-nomac          + chacha20   pt=1024 wire=4312
[PASS] message-easy-nomac          + siphash24  pt=1024 wire=4316
[PASS] message-easy-auth           + aescmac    pt=1024 wire=8276
[PASS] message-easy-auth           + chacha20   pt=1024 wire=8272
[PASS] message-easy-auth           + siphash24  pt=1024 wire=8276
[PASS] message-lowlevel-nomac      + aescmac    pt=1024 wire=4316
[PASS] message-lowlevel-nomac      + chacha20   pt=1024 wire=4312
[PASS] message-lowlevel-nomac      + siphash24  pt=1024 wire=4316
[PASS] message-lowlevel-auth       + aescmac    pt=1024 wire=8276
[PASS] message-lowlevel-auth       + chacha20   pt=1024 wire=8272
[PASS] message-lowlevel-auth       + siphash24  pt=1024 wire=8276

=== Summary: 30 PASS, 0 FAIL ===
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
