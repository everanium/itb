package wrapper

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/everanium/itb/ctr"
	"github.com/everanium/itb/kdf"
)

// Cipher names accepted by the Make* helpers and the cmd/-flag parsing.
const (
	CipherSipHash24 = "siphash24"
	CipherAES128CTR = "aescmac"
	CipherChaCha20  = "chacha20"
)

// CipherNames lists every supported outer cipher in iteration order.
var CipherNames = []string{CipherSipHash24, CipherAES128CTR, CipherChaCha20}

// Keystream is the outer cipher keystream the wrap helpers consume. It
// aliases ctr.Keystream; the contract matches crypto/cipher.Stream —
// XORKeyStream xors a keystream segment over src into dst, advancing the
// internal counter.
type Keystream = ctr.Keystream

// KeySize returns the byte length of the key for the named outer cipher.
func KeySize(name string) (int, error) {
	return ctr.KeySize(name)
}

// NonceSize returns the on-wire nonce length for the named outer cipher.
func NonceSize(name string) (int, error) {
	return ctr.NonceSize(name)
}

// MakeKeystream constructs an outer cipher Keystream from the named cipher,
// the caller-provided key, and a per-stream nonce. The key length must equal
// KeySize(name); the nonce length must equal NonceSize(name).
func MakeKeystream(name string, key, nonce []byte) (Keystream, error) {
	return ctr.New(name, key, nonce)
}

// GenerateKey returns a fresh CSPRNG key sized for the named outer cipher.
func GenerateKey(name string) ([]byte, error) {
	n, err := KeySize(name)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

// generateNonce returns a fresh CSPRNG nonce sized for the named cipher.
func generateNonce(name string) ([]byte, error) {
	n, err := NonceSize(name)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

// Wrap helpers.
//
// Two flavours, picked per use case:
//
//   1. Wrap / Unwrap — Single Message. The whole ITB ciphertext is treated as
//      one opaque blob. Wire = nonce || keystream-XORed blob. Suitable for
//      any Single Message Encrypt / EncryptAuth example output, plus the Streaming
//      AEAD case where the entire wire output (32-byte streamID + every
//      chunk) is sealed as one blob — the receiver unwraps to recover the
//      raw ITB stream then feeds it to ITB's stream decoder.
//
//      WrapInPlace / UnwrapInPlace are zero-allocation variants that XOR the
//      caller's blob / wire buffer in place. Use when the caller has just
//      produced an ITB ciphertext and will not re-read it, e.g. on the hot
//      write-to-wire path where the allocation cost of a fresh output buffer
//      dominates over the keystream XOR itself.
//
//   2. NewWrapWriter / NewUnwrapReader — io.Writer / io.Reader pipeline.
//      Emits the nonce once at stream start, then XORs the entire bytestream
//      verbatim. Suitable for IO-Driven streaming and for User-Driven Loops
//      where caller-side framing (e.g. per-chunk u32_LE length prefixes) is
//      written through the wrapped writer so the lengths themselves go
//      through the keystream XOR rather than appearing in cleartext on the
//      wire.

// Wrap seals one ITB ciphertext blob under the named outer cipher, emitting
// the wire form `nonce || keystream-XOR(blob)`. The returned wire bytes are
// the format-deniability envelope.
func Wrap(name string, key, blob []byte) ([]byte, error) {
	nonce, err := generateNonce(name)
	if err != nil {
		return nil, err
	}
	ks, err := MakeKeystream(name, key, nonce)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(nonce)+len(blob))
	copy(out, nonce)
	ks.XORKeyStream(out[len(nonce):], blob)
	return out, nil
}

// Unwrap reverses Wrap. The leading nonce is read from wire; the remaining
// bytes are XOR-decrypted under (key, nonce) and returned.
func Unwrap(name string, key, wire []byte) ([]byte, error) {
	nlen, err := NonceSize(name)
	if err != nil {
		return nil, err
	}
	if len(wire) < nlen {
		return nil, fmt.Errorf("wrapper: wire shorter than nonce (%d < %d)", len(wire), nlen)
	}
	nonce := wire[:nlen]
	body := wire[nlen:]
	ks, err := MakeKeystream(name, key, nonce)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(body))
	ks.XORKeyStream(out, body)
	return out, nil
}

// WrapInPlace XORs blob in place under a fresh outer cipher keystream and
// returns the per-stream nonce. The caller is expected to emit nonce
// followed by blob to the wire, or compose a single buffer themselves.
//
// blob is MUTATED. Do not pass plaintext that must be preserved beyond
// the call. Suitable for hot paths where the caller has just produced an
// ITB ciphertext and will not re-read it (the typical case for buffered
// write-to-wire).
func WrapInPlace(name string, key, blob []byte) ([]byte, error) {
	nonce, err := generateNonce(name)
	if err != nil {
		return nil, err
	}
	ks, err := MakeKeystream(name, key, nonce)
	if err != nil {
		return nil, err
	}
	ks.XORKeyStream(blob, blob)
	return nonce, nil
}

// UnwrapInPlace strips the leading nonce from wire and XORs the remainder
// in place. Returns an aliased slice equal to wire[NonceSize(name):],
// fully decrypted. wire is MUTATED.
func UnwrapInPlace(name string, key, wire []byte) ([]byte, error) {
	nlen, err := NonceSize(name)
	if err != nil {
		return nil, err
	}
	if len(wire) < nlen {
		return nil, fmt.Errorf("wrapper: wire shorter than nonce (%d < %d)", len(wire), nlen)
	}
	nonce := wire[:nlen]
	body := wire[nlen:]
	ks, err := MakeKeystream(name, key, nonce)
	if err != nil {
		return nil, err
	}
	ks.XORKeyStream(body, body)
	return body, nil
}

// keystreamReader and keystreamWriter wrap a Keystream to satisfy
// io.Reader / io.Writer for the streaming-mode helpers below.
//
// Why not crypto/cipher.StreamReader / StreamWriter directly? The Keystream
// interface is strictly looser than crypto/cipher.Stream (it has no
// implementation of crypto/cipher.Stream's requirement that XORKeyStream
// panics on a misuse pattern). Wrapping by hand keeps the one-method
// contract explicit and works equally for the SipHash-CTR construction.

type keystreamWriter struct {
	w       io.Writer
	ks      Keystream
	scratch []byte // reused across Writes; grows to the largest p seen
}

func (kw *keystreamWriter) Write(p []byte) (int, error) {
	if cap(kw.scratch) < len(p) {
		kw.scratch = make([]byte, len(p))
	}
	out := kw.scratch[:len(p)]
	kw.ks.XORKeyStream(out, p)
	return kw.w.Write(out)
}

type keystreamReader struct {
	r  io.Reader
	ks Keystream
}

func (kr *keystreamReader) Read(p []byte) (int, error) {
	n, err := kr.r.Read(p)
	if n > 0 {
		kr.ks.XORKeyStream(p[:n], p[:n])
	}
	return n, err
}

// NewWrapWriter returns an io.Writer that emits the per-stream nonce on
// construction, then XOR-encrypts every subsequent byte through to dst. The
// matching reader is NewUnwrapReader. Useful when the caller needs an
// io.Writer to pass to ITB's EncryptStreamIO / EncryptStreamAuthIO, or to
// drive a user-side loop that emits caller-framed chunks (e.g. a u32_LE
// length prefix followed by the chunk body) through a single keystream so
// the framing bytes also pass through the XOR.
func NewWrapWriter(name string, key []byte, dst io.Writer) (io.Writer, error) {
	nonce, err := generateNonce(name)
	if err != nil {
		return nil, err
	}
	if _, err := dst.Write(nonce); err != nil {
		return nil, err
	}
	ks, err := MakeKeystream(name, key, nonce)
	if err != nil {
		return nil, err
	}
	return &keystreamWriter{w: dst, ks: ks}, nil
}

// NewUnwrapReader returns an io.Reader that consumes the per-stream nonce
// from src on construction, then XOR-decrypts every subsequent byte read.
// Useful when the caller needs an io.Reader to pass to ITB's
// DecryptStreamIO / DecryptStreamAuthIO, or to read caller-framed chunks
// emitted through NewWrapWriter back out of the keystream XOR.
func NewUnwrapReader(name string, key []byte, src io.Reader) (io.Reader, error) {
	nlen, err := NonceSize(name)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nlen)
	if _, err := io.ReadFull(src, nonce); err != nil {
		return nil, err
	}
	ks, err := MakeKeystream(name, key, nonce)
	if err != nil {
		return nil, err
	}
	return &keystreamReader{r: src, ks: ks}, nil
}

// DeriveKey deterministically derives an outer cipher key from a caller-
// supplied master secret, sized for the named outer cipher, via the kdf
// package's per-primitive construction.
//
// Where GenerateKey draws a fresh random key, DeriveKey is deterministic in
// (name, master): the same inputs always yield the same key. This is the
// preferred path when the master comes from a key-agreement step — e.g. an
// ML-KEM (crypto/mlkem) shared secret — or any external high-entropy keying
// material, so a rotated master re-derives the per-cipher key with no separate
// key storage. The derivation routes through the named primitive itself, so
// the key material is bound to that primitive and no fixed hash is imposed.
// The cipher name doubles as the derivation label, so one master yields
// independent keys for different outer ciphers. The returned key has length
// KeySize(name); master must be at least that primitive's key size.
func DeriveKey(name string, master []byte) ([]byte, error) {
	n, err := KeySize(name)
	if err != nil {
		return nil, err
	}
	return kdf.Derive(name, master, name, n)
}
