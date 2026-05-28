package wrapper

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/everanium/itb/ctr"
	"github.com/everanium/itb/kdf"
)

// Cipher names accepted by the Make* helpers and the cmd/-flag parsing.
// The string values mirror the ctr/ package's primitive identifiers; every
// name routes through ctr.New / kdf.Derive, so all PRF-grade ITB
// registry primitives are supported as outer ciphers.
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
)

// CipherNames lists every supported outer cipher in iteration order, in the
// project's canonical primitive order.
var CipherNames = []string{
	CipherAreion256, CipherAreion512,
	CipherBLAKE2b256, CipherBLAKE2b512, CipherBLAKE2s, CipherBLAKE3,
	CipherAES128CTR, CipherSipHash24,
	CipherChaCha20,
}

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

// MakeKeystreamAt is MakeKeystream positioned at an arbitrary byte offset: the
// returned keystream's first XORKeyStream byte is keystream byte offset of the
// (name, key, nonce) stream. The streaming helpers use it to re-seat their
// serial keystream after a chunk was XORed in parallel, so the next chunk
// continues the one logical stream the matching reader expects.
func MakeKeystreamAt(name string, key, nonce []byte, offset int) (Keystream, error) {
	return ctr.NewAt(name, key, nonce, offset)
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
//      WrapInPlace / UnwrapInPlace are no-output-buffer-allocation variants that XOR the
//      caller's blob / wire buffer in place. Use when the caller has just
//      produced an ITB ciphertext and will not re-read it, e.g. on the hot
//      write-to-wire path where the output-buffer allocation cost of the non-in-place helpers dominates
//      over the keystream XOR itself.
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
	out := make([]byte, len(nonce)+len(blob))
	copy(out, nonce)
	if err := xorParallel(name, key, nonce, out[len(nonce):], blob); err != nil {
		return nil, err
	}
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
	out := make([]byte, len(body))
	if err := xorParallel(name, key, nonce, out, body); err != nil {
		return nil, err
	}
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
	if err := xorParallel(name, key, nonce, blob, blob); err != nil {
		return nil, err
	}
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
	if err := xorParallel(name, key, nonce, body, body); err != nil {
		return nil, err
	}
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

// keystreamWriter / keystreamReader carry the cipher name, key, nonce and a
// running byte offset so each Write / Read can XOR its chunk under one logical
// keystream. A chunk at or above ParallelThreshold is XORed across workers via
// xorParallelAt seeking to the running offset, after which the serial keystream
// ks is re-seated to the new offset; a smaller chunk advances ks directly so
// the common small-write path pays no per-chunk reseed keying.

type keystreamWriter struct {
	w       io.Writer
	name    string
	key     []byte
	nonce   []byte
	ks      Keystream // serial keystream, positioned at byte offset off
	off     int       // cumulative bytes XORed so far
	scratch []byte    // reused across Writes; grows to the largest p seen
}

func (kw *keystreamWriter) Write(p []byte) (int, error) {
	if cap(kw.scratch) < len(p) {
		kw.scratch = make([]byte, len(p))
	}
	out := kw.scratch[:len(p)]
	if len(p) >= parallelThreshold {
		if err := xorParallelAt(kw.name, kw.key, kw.nonce, kw.off, out, p); err != nil {
			return 0, err
		}
		ks, err := MakeKeystreamAt(kw.name, kw.key, kw.nonce, kw.off+len(p))
		if err != nil {
			return 0, err
		}
		kw.ks = ks
	} else {
		kw.ks.XORKeyStream(out, p)
	}
	kw.off += len(p)
	return kw.w.Write(out)
}

type keystreamReader struct {
	r     io.Reader
	name  string
	key   []byte
	nonce []byte
	ks    Keystream
	off   int
}

func (kr *keystreamReader) Read(p []byte) (int, error) {
	n, err := kr.r.Read(p)
	if n > 0 {
		if n >= parallelThreshold {
			if e := xorParallelAt(kr.name, kr.key, kr.nonce, kr.off, p[:n], p[:n]); e != nil {
				return 0, e
			}
			ks, e := MakeKeystreamAt(kr.name, kr.key, kr.nonce, kr.off+n)
			if e != nil {
				return 0, e
			}
			kr.ks = ks
		} else {
			kr.ks.XORKeyStream(p[:n], p[:n])
		}
		kr.off += n
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
	return &keystreamWriter{
		w:     dst,
		name:  name,
		key:   append([]byte(nil), key...),
		nonce: append([]byte(nil), nonce...),
		ks:    ks,
	}, nil
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
	return &keystreamReader{
		r:     src,
		name:  name,
		key:   append([]byte(nil), key...),
		nonce: nonce,
		ks:    ks,
	}, nil
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
// KeySize(name).
//
// master must be at least 32 bytes — the wrapper's uniform security floor, a
// 256-bit master matching an ML-KEM shared secret. A single 32-byte master
// keys every supported cipher: the kdf package takes the leading 16 bytes for
// 128-bit primitives, the leading 32 bytes for 256-bit primitives and for
// 512-bit primitives like BLAKE2b-512, and deterministically stretches the
// leading 32 bytes to the 64 bytes for 512-bit primitives like Areion-SoEM-512.
// A longer master is accepted and truncated the same way, so both endpoints
// derive an identical key from any master of 32 bytes or more.
func DeriveKey(name string, master []byte) ([]byte, error) {
	if len(master) < 32 {
		return nil, fmt.Errorf("wrapper: DeriveKey master must be at least 32 bytes, got %d", len(master))
	}
	n, err := KeySize(name)
	if err != nil {
		return nil, err
	}
	return kdf.Derive(name, master, name, n)
}
