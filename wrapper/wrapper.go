package wrapper

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/dchest/siphash"
	"golang.org/x/crypto/chacha20"
)

// Cipher names accepted by the Make* helpers and the cmd/-flag parsing.
const (
	CipherAES128CTR = "aes"
	CipherChaCha20  = "chacha"
	CipherSipHash24 = "siphash"
)

// CipherNames lists every supported outer cipher in iteration order.
var CipherNames = []string{CipherAES128CTR, CipherChaCha20, CipherSipHash24}

// Keystream is the minimal interface the wrap helpers consume from an outer
// cipher. The contract matches crypto/cipher.Stream — XORKeyStream xors a
// keystream segment over src into dst, advancing the internal counter.
//
// All three concrete implementations (AES-128-CTR, ChaCha20, SipHash-CTR)
// satisfy this signature. The interface stays decoupled from cipher. Stream so
// the SipHash wrapper does not have to pretend to be a stdlib type.
type Keystream interface {
	XORKeyStream(dst, src []byte)
}

// KeySize returns the byte length of the key for the named outer cipher.
func KeySize(name string) (int, error) {
	switch name {
	case CipherAES128CTR:
		return 16, nil
	case CipherChaCha20:
		return chacha20.KeySize, nil // 32
	case CipherSipHash24:
		return 16, nil
	default:
		return 0, fmt.Errorf("wrapper: unknown cipher %q", name)
	}
}

// NonceSize returns the on-wire nonce length for the named outer cipher.
//
// The nonce is emitted as a single prefix per Wrap entry point. AES-CTR uses
// a 16-byte block-sized IV; ChaCha20 (RFC8439) uses a 12-byte nonce; SipHash-CTR
// uses a 16-byte construction-defined nonce (the SipHash key is the wrapper
// key; the nonce gets concatenated with the 64-bit counter under the PRF).
func NonceSize(name string) (int, error) {
	switch name {
	case CipherAES128CTR:
		return aes.BlockSize, nil // 16
	case CipherChaCha20:
		return chacha20.NonceSize, nil // 12
	case CipherSipHash24:
		return 16, nil
	default:
		return 0, fmt.Errorf("wrapper: unknown cipher %q", name)
	}
}

// MakeKeystream constructs an outer cipher Keystream from the named cipher,
// the caller-provided key, and a per-stream nonce. The key length must equal
// KeySize(name); the nonce length must equal NonceSize(name).
func MakeKeystream(name string, key, nonce []byte) (Keystream, error) {
	switch name {
	case CipherAES128CTR:
		if len(key) != 16 {
			return nil, fmt.Errorf("wrapper: aes-128-ctr key must be 16 bytes, got %d", len(key))
		}
		if len(nonce) != aes.BlockSize {
			return nil, fmt.Errorf("wrapper: aes-128-ctr nonce must be %d bytes, got %d", aes.BlockSize, len(nonce))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewCTR(block, nonce), nil
	case CipherChaCha20:
		c, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			return nil, err
		}
		return c, nil
	case CipherSipHash24:
		return newSipHashCTR(key, nonce)
	default:
		return nil, fmt.Errorf("wrapper: unknown cipher %q", name)
	}
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

// SipHash-2-4 in CTR mode.
//
// SipHash-2-4 is a 128-bit-keyed PRF / MAC with 64-bit output. Building a
// keystream from a PRF is the standard CTR construction:
//
//	keystream_block_i = SipHash(K, nonce || counter_i)   (8 bytes per call)
//
// The combined PRF input is 16 bytes (8-byte nonce-half + 8-byte counter, or
// in this construction a 16-byte nonce broken into two 8-byte halves and
// counter increments folded into the lower half). The construction is sound
// under the same PRF assumption that justifies AES-CTR — XORing PRF output
// with plaintext is the canonical PRF-secure stream.
//
// The nonce is 16 bytes wide, partitioned as (nonce_hi||nonce_lo). Each
// keystream block hashes a 16-byte input formed from
// (nonce_hi || nonce_lo XOR counter_le). This binds every block to the
// stream's nonce while injecting unique 64-bit counter material per block.

type sipCTR struct {
	k0, k1   uint64
	nonceHi  uint64
	nonceLo  uint64
	counter  uint64
	keystrm  [8]byte
	keystrmN int // number of unconsumed bytes in keystrm[8-keystrmN:]
}

func newSipHashCTR(key, nonce []byte) (Keystream, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("wrapper: siphash key must be 16 bytes, got %d", len(key))
	}
	if len(nonce) != 16 {
		return nil, fmt.Errorf("wrapper: siphash nonce must be 16 bytes, got %d", len(nonce))
	}
	c := &sipCTR{
		k0:      binary.LittleEndian.Uint64(key[:8]),
		k1:      binary.LittleEndian.Uint64(key[8:]),
		nonceHi: binary.LittleEndian.Uint64(nonce[:8]),
		nonceLo: binary.LittleEndian.Uint64(nonce[8:]),
	}
	return c, nil
}

func (c *sipCTR) refill() {
	var buf [16]byte
	binary.LittleEndian.PutUint64(buf[:8], c.nonceHi)
	binary.LittleEndian.PutUint64(buf[8:], c.nonceLo^c.counter)
	out := siphash.Hash(c.k0, c.k1, buf[:])
	binary.LittleEndian.PutUint64(c.keystrm[:], out)
	c.counter++
	c.keystrmN = 8
}

func (c *sipCTR) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("wrapper/siphash: short dst")
	}
	n := len(src)
	i := 0

	// Drain leftover bytes from a previous partial refill, byte by byte.
	if c.keystrmN > 0 {
		off := 8 - c.keystrmN
		take := c.keystrmN
		if take > n {
			take = n
		}
		for j := 0; j < take; j++ {
			dst[i+j] = src[i+j] ^ c.keystrm[off+j]
		}
		i += take
		c.keystrmN -= take
	}

	// Bulk path: hash one 16-byte input per 8-byte keystream block, XOR
	// directly via uint64 — skips the keystrm[8]byte buffer entirely.
	var nonceBuf [16]byte
	binary.LittleEndian.PutUint64(nonceBuf[:8], c.nonceHi)
	for n-i >= 8 {
		binary.LittleEndian.PutUint64(nonceBuf[8:], c.nonceLo^c.counter)
		ksU64 := siphash.Hash(c.k0, c.k1, nonceBuf[:])
		srcU64 := binary.LittleEndian.Uint64(src[i:])
		binary.LittleEndian.PutUint64(dst[i:], srcU64^ksU64)
		c.counter++
		i += 8
	}

	// Tail (<8 bytes): refill keystrm buffer and consume the leading bytes.
	if i < n {
		c.refill()
		rem := n - i
		for j := 0; j < rem; j++ {
			dst[i+j] = src[i+j] ^ c.keystrm[j]
		}
		c.keystrmN -= rem
	}
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
