// Benchmarks for the format-deniability wrapper.
package wrapper_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/wrapper"
)

const (
	benchPrimitive   = "areion512"
	benchSeedWidth   = 1024
	benchMACName     = "hmac-blake3"
	benchSingleSize  = 16 * 1024 * 1024
	benchStreamSize  = 64 * 1024 * 1024
	benchStreamChunk = 16 * 1024 * 1024

	benchNonceBits   = 128
	benchBarrierFill = 1
)

func init() {
	itb.SetMaxWorkers(0)
	itb.SetNonceBits(benchNonceBits)
	itb.SetBarrierFill(benchBarrierFill)
}

func benchRandom(b *testing.B, n int) []byte {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		b.Fatalf("rand.Read: %v", err)
	}
	return out
}

func benchMACFunc(b *testing.B) itb.MACFunc {
	macKey := make([]byte, 32)
	if _, err := rand.Read(macKey); err != nil {
		b.Fatalf("rand.Read: %v", err)
	}
	mf, err := macs.Make(benchMACName, macKey)
	if err != nil {
		b.Fatalf("macs.Make: %v", err)
	}
	return mf
}

func benchOuterKey(b *testing.B, cn string) []byte {
	k, err := wrapper.GenerateKey(cn)
	if err != nil {
		b.Fatalf("wrapper.GenerateKey: %v", err)
	}
	return k
}

// composeWire concatenates nonce || body into *buf, growing it only when
// the existing capacity is insufficient. The returned slice aliases *buf.
func composeWire(buf *[]byte, nonce, body []byte) []byte {
	need := len(nonce) + len(body)
	if cap(*buf) < need {
		*buf = make([]byte, 0, need)
	}
	out := append((*buf)[:0], nonce...)
	out = append(out, body...)
	*buf = out
	return out
}

// benchLowLevelMakeSeed512 builds one fresh *itb.Seed512 with both the
// single-arm hash and the 4-way batched arm wired in. The batched arm
// (assigned to Seed512.BatchHash) is what the per-pixel inner loop in
// processChunk512 dispatches through when both noiseSeed.BatchHash and
// dataSeed.BatchHash are non-nil — that path runs four pixels at a time
// and is the canonical Low-Level fast-path setup used by every shipped
// binding's bench harness.
//
// Each seed receives an independently-keyed PRF instance (one
// Make512Pair call per seed) so every slot uses a distinct PRF key;
// sharing one (single, batched) closure pair across all slots would
// couple their key channels.
func benchLowLevelMakeSeed512(b *testing.B) *itb.Seed512 {
	b.Helper()
	single, batched, _, err := hashes.Make512Pair(benchPrimitive)
	if err != nil {
		b.Fatalf("hashes.Make512Pair: %v", err)
	}
	seed, err := itb.NewSeed512(benchSeedWidth, single)
	if err != nil {
		b.Fatalf("NewSeed512: %v", err)
	}
	seed.BatchHash = batched
	return seed
}

func benchLowLevelTripleSeeds(b *testing.B) (noise, lock, d1, d2, d3, s1, s2, s3 *itb.Seed512) {
	return benchLowLevelMakeSeed512(b), benchLowLevelMakeSeed512(b), benchLowLevelMakeSeed512(b), benchLowLevelMakeSeed512(b),
		benchLowLevelMakeSeed512(b), benchLowLevelMakeSeed512(b), benchLowLevelMakeSeed512(b), benchLowLevelMakeSeed512(b)
}

// ---------------------------------------------------------------------------
// Wrapper Only baseline (round-trip — wrapper-cost-isolation case).
// ---------------------------------------------------------------------------

func BenchmarkWrapperOnly(b *testing.B) {
	plaintext := benchRandom(b, benchSingleSize)
	for _, cn := range wrapper.CipherNames {
		b.Run(cn, func(b *testing.B) {
			outerKey := benchOuterKey(b, cn)
			b.SetBytes(int64(len(plaintext)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				wire, err := wrapper.Wrap(cn, outerKey, plaintext)
				if err != nil {
					b.Fatalf("Wrap: %v", err)
				}
				got, err := wrapper.Unwrap(cn, outerKey, wire)
				if err != nil {
					b.Fatalf("Unwrap: %v", err)
				}
				if len(got) != len(plaintext) {
					b.Fatalf("len mismatch: got %d want %d", len(got), len(plaintext))
				}
			}
		})
	}
}

func BenchmarkWrapperOnlyInPlace(b *testing.B) {
	plaintext := benchRandom(b, benchSingleSize)
	for _, cn := range wrapper.CipherNames {
		b.Run(cn, func(b *testing.B) {
			outerKey := benchOuterKey(b, cn)
			nlen, err := wrapper.NonceSize(cn)
			if err != nil {
				b.Fatalf("NonceSize: %v", err)
			}
			// Pre-encrypt plaintext into wire once (untimed) so the timed
			// loop alternates UnwrapInPlace → WrapInPlace on the same buffer
			// with no per-iteration memcpy.
			wire := make([]byte, nlen+len(plaintext))
			copy(wire[nlen:], plaintext)
			nonce, err := wrapper.WrapInPlace(cn, outerKey, wire[nlen:])
			if err != nil {
				b.Fatalf("WrapInPlace setup: %v", err)
			}
			copy(wire[:nlen], nonce)
			b.SetBytes(int64(len(plaintext)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				body, err := wrapper.UnwrapInPlace(cn, outerKey, wire)
				if err != nil {
					b.Fatalf("UnwrapInPlace: %v", err)
				}
				if len(body) != len(plaintext) {
					b.Fatalf("len mismatch: got %d want %d", len(body), len(plaintext))
				}
				newNonce, err := wrapper.WrapInPlace(cn, outerKey, wire[nlen:])
				if err != nil {
					b.Fatalf("WrapInPlace: %v", err)
				}
				copy(wire[:nlen], newNonce)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Single Message — Triple Ouroboros (4 modes × outer-cipher palette × 2 dirs).
// ---------------------------------------------------------------------------

func BenchmarkMessageTriple(b *testing.B) {
	plaintext := benchRandom(b, benchSingleSize)
	for _, cn := range wrapper.CipherNames {
		b.Run("lowlevel-nomac/"+cn+"/encrypt", func(b *testing.B) {
			runMessageLowLevelTripleNoMACEncrypt(b, plaintext, cn)
		})
		b.Run("lowlevel-nomac/"+cn+"/decrypt", func(b *testing.B) {
			runMessageLowLevelTripleNoMACDecrypt(b, plaintext, cn)
		})
		b.Run("lowlevel-auth/"+cn+"/encrypt", func(b *testing.B) {
			runMessageLowLevelTripleAuthEncrypt(b, plaintext, cn)
		})
		b.Run("lowlevel-auth/"+cn+"/decrypt", func(b *testing.B) {
			runMessageLowLevelTripleAuthDecrypt(b, plaintext, cn)
		})
	}
}

// --- Low-Level Triple Ouroboros Message helpers ---

func runMessageLowLevelTripleNoMACEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, lock, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	outerKey := benchOuterKey(b, cn)
	var wireBuf []byte
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := itb.Encrypt3x(noise, lock, d1, d2, d3, s1, s2, s3, plaintext)
		if err != nil {
			b.Fatalf("Encrypt3x: %v", err)
		}
		nonce, err := wrapper.WrapInPlace(cn, outerKey, encrypted)
		if err != nil {
			b.Fatalf("WrapInPlace: %v", err)
		}
		_ = composeWire(&wireBuf, nonce, encrypted)
	}
}

func runMessageLowLevelTripleNoMACDecrypt(b *testing.B, plaintext []byte, cn string) {
	noise, lock, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	outerKey := benchOuterKey(b, cn)

	encrypted, err := itb.Encrypt3x(noise, lock, d1, d2, d3, s1, s2, s3, plaintext)
	if err != nil {
		b.Fatalf("Encrypt3x setup: %v", err)
	}
	nonce, err := wrapper.WrapInPlace(cn, outerKey, encrypted)
	if err != nil {
		b.Fatalf("WrapInPlace setup: %v", err)
	}
	pristineWire := append(append([]byte{}, nonce...), encrypted...)
	workWire := make([]byte, len(pristineWire))

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(workWire, pristineWire)
		body, err := wrapper.UnwrapInPlace(cn, outerKey, workWire)
		if err != nil {
			b.Fatalf("UnwrapInPlace: %v", err)
		}
		pt, err := itb.Decrypt3x(noise, lock, d1, d2, d3, s1, s2, s3, body)
		if err != nil {
			b.Fatalf("Decrypt3x: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
	}
}

func runMessageLowLevelTripleAuthEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, lock, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)
	var wireBuf []byte
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := itb.EncryptAuth3x(noise, lock, d1, d2, d3, s1, s2, s3, plaintext, macFunc)
		if err != nil {
			b.Fatalf("EncryptAuth3x: %v", err)
		}
		nonce, err := wrapper.WrapInPlace(cn, outerKey, encrypted)
		if err != nil {
			b.Fatalf("WrapInPlace: %v", err)
		}
		_ = composeWire(&wireBuf, nonce, encrypted)
	}
}

func runMessageLowLevelTripleAuthDecrypt(b *testing.B, plaintext []byte, cn string) {
	noise, lock, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)

	encrypted, err := itb.EncryptAuth3x(noise, lock, d1, d2, d3, s1, s2, s3, plaintext, macFunc)
	if err != nil {
		b.Fatalf("EncryptAuth3x setup: %v", err)
	}
	nonce, err := wrapper.WrapInPlace(cn, outerKey, encrypted)
	if err != nil {
		b.Fatalf("WrapInPlace setup: %v", err)
	}
	pristineWire := append(append([]byte{}, nonce...), encrypted...)
	workWire := make([]byte, len(pristineWire))

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		copy(workWire, pristineWire)
		body, err := wrapper.UnwrapInPlace(cn, outerKey, workWire)
		if err != nil {
			b.Fatalf("UnwrapInPlace: %v", err)
		}
		pt, err := itb.DecryptAuth3x(noise, lock, d1, d2, d3, s1, s2, s3, body, macFunc)
		if err != nil {
			b.Fatalf("DecryptAuth3x: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
	}
}

// ---------------------------------------------------------------------------
// Streaming — Triple Ouroboros (6 modes × outer-cipher palette × 2 dirs).
// ---------------------------------------------------------------------------

func BenchmarkStreamingTriple(b *testing.B) {
	plaintext := benchRandom(b, benchStreamSize)
	for _, cn := range wrapper.CipherNames {
		b.Run("aead-lowlevel-io/"+cn+"/encrypt", func(b *testing.B) {
			runAEADLowLevelIOTripleEncrypt(b, plaintext, cn)
		})
		b.Run("aead-lowlevel-io/"+cn+"/decrypt", func(b *testing.B) {
			runAEADLowLevelIOTripleDecrypt(b, plaintext, cn)
		})
		b.Run("noaead-lowlevel-io/"+cn+"/encrypt", func(b *testing.B) {
			runNoAEADLowLevelIOTripleEncrypt(b, plaintext, cn)
		})
		b.Run("noaead-lowlevel-io/"+cn+"/decrypt", func(b *testing.B) {
			runNoAEADLowLevelIOTripleDecrypt(b, plaintext, cn)
		})
		b.Run("noaead-lowlevel-userloop/"+cn+"/encrypt", func(b *testing.B) {
			runNoAEADLowLevelUserLoopTripleEncrypt(b, plaintext, cn)
		})
		b.Run("noaead-lowlevel-userloop/"+cn+"/decrypt", func(b *testing.B) {
			runNoAEADLowLevelUserLoopTripleDecrypt(b, plaintext, cn)
		})
	}
}

// --- Streaming AEAD Low-Level — Triple (Encrypt / Decrypt) ---

func runAEADLowLevelIOTripleEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, lock, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)
	var wireBuf bytes.Buffer
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wireBuf.Reset()
		wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &wireBuf)
		if err != nil {
			b.Fatalf("NewWrapWriter: %v", err)
		}
		if err := itb.EncryptStreamAuth3x(noise, lock, d1, d2, d3, s1, s2, s3, bytes.NewReader(plaintext), wrapWriter, macFunc, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStreamAuth3x: %v", err)
		}
	}
}

func runAEADLowLevelIOTripleDecrypt(b *testing.B, plaintext []byte, cn string) {
	noise, lock, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)

	var pristineBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &pristineBuf)
	if err != nil {
		b.Fatalf("NewWrapWriter setup: %v", err)
	}
	if err := itb.EncryptStreamAuth3x(noise, lock, d1, d2, d3, s1, s2, s3, bytes.NewReader(plaintext), wrapWriter, macFunc, benchStreamChunk); err != nil {
		b.Fatalf("EncryptStreamAuth3x setup: %v", err)
	}
	pristineWire := pristineBuf.Bytes()

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		unwrapReader, err := wrapper.NewUnwrapReader(cn, outerKey, bytes.NewReader(pristineWire))
		if err != nil {
			b.Fatalf("NewUnwrapReader: %v", err)
		}
		var dst bytes.Buffer
		if err := itb.DecryptStreamAuth3x(noise, lock, d1, d2, d3, s1, s2, s3, unwrapReader, &dst, macFunc); err != nil {
			b.Fatalf("DecryptStreamAuth3x: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
	}
}

// --- Streaming No MAC Low-Level (IO-Driven) — Triple (Encrypt / Decrypt) ---

func runNoAEADLowLevelIOTripleEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, lock, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	outerKey := benchOuterKey(b, cn)
	var wireBuf bytes.Buffer
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wireBuf.Reset()
		wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &wireBuf)
		if err != nil {
			b.Fatalf("NewWrapWriter: %v", err)
		}
		if err := itb.EncryptStream3x(noise, lock, d1, d2, d3, s1, s2, s3, bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStream3x: %v", err)
		}
	}
}

func runNoAEADLowLevelIOTripleDecrypt(b *testing.B, plaintext []byte, cn string) {
	noise, lock, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	outerKey := benchOuterKey(b, cn)

	var pristineBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &pristineBuf)
	if err != nil {
		b.Fatalf("NewWrapWriter setup: %v", err)
	}
	if err := itb.EncryptStream3x(noise, lock, d1, d2, d3, s1, s2, s3, bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
		b.Fatalf("EncryptStream3x setup: %v", err)
	}
	pristineWire := pristineBuf.Bytes()

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		unwrapReader, err := wrapper.NewUnwrapReader(cn, outerKey, bytes.NewReader(pristineWire))
		if err != nil {
			b.Fatalf("NewUnwrapReader: %v", err)
		}
		var dst bytes.Buffer
		if err := itb.DecryptStream3x(noise, lock, d1, d2, d3, s1, s2, s3, unwrapReader, &dst); err != nil {
			b.Fatalf("DecryptStream3x: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
	}
}

// --- Streaming No MAC Low-Level (User-Driven Loop) — Triple (Encrypt / Decrypt) ---

func runNoAEADLowLevelUserLoopTripleEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, lock, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	outerKey := benchOuterKey(b, cn)
	var wireBuf bytes.Buffer
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		wireBuf.Reset()
		wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &wireBuf)
		if err != nil {
			b.Fatalf("NewWrapWriter: %v", err)
		}
		if err := encryptUserLoop(plaintext, wrapWriter, func(buf []byte) ([]byte, error) {
			return itb.Encrypt3x(noise, lock, d1, d2, d3, s1, s2, s3, buf)
		}); err != nil {
			b.Fatalf("encryptUserLoop: %v", err)
		}
	}
}

func runNoAEADLowLevelUserLoopTripleDecrypt(b *testing.B, plaintext []byte, cn string) {
	noise, lock, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	outerKey := benchOuterKey(b, cn)

	var pristineBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &pristineBuf)
	if err != nil {
		b.Fatalf("NewWrapWriter setup: %v", err)
	}
	if err := encryptUserLoop(plaintext, wrapWriter, func(buf []byte) ([]byte, error) {
		return itb.Encrypt3x(noise, lock, d1, d2, d3, s1, s2, s3, buf)
	}); err != nil {
		b.Fatalf("encryptUserLoop setup: %v", err)
	}
	pristineWire := pristineBuf.Bytes()

	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		unwrapReader, err := wrapper.NewUnwrapReader(cn, outerKey, bytes.NewReader(pristineWire))
		if err != nil {
			b.Fatalf("NewUnwrapReader: %v", err)
		}
		got, err := decryptUserLoop(unwrapReader, func(ct []byte) ([]byte, error) {
			return itb.Decrypt3x(noise, lock, d1, d2, d3, s1, s2, s3, ct)
		})
		if err != nil {
			b.Fatalf("decryptUserLoop: %v", err)
		}
		if len(got) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(got), len(plaintext))
		}
	}
}

// encryptUserLoop drives the User-Driven Loop encrypt-side framing pattern
// shared by every No MAC variant. Each chunk is emitted as
// `u32_LE_len || ct` through the wrapped writer.
func encryptUserLoop(plaintext []byte, wrapWriter io.Writer, encryptChunk func([]byte) ([]byte, error)) error {
	src := bytes.NewReader(plaintext)
	buf := make([]byte, benchStreamChunk)
	for {
		n, rerr := io.ReadFull(src, buf)
		if rerr == io.EOF {
			break
		}
		if rerr != nil && rerr != io.ErrUnexpectedEOF {
			return rerr
		}
		ct, err := encryptChunk(buf[:n])
		if err != nil {
			return err
		}
		if err := binary.Write(wrapWriter, binary.LittleEndian, uint32(len(ct))); err != nil {
			return err
		}
		if _, err := wrapWriter.Write(ct); err != nil {
			return err
		}
		if rerr == io.ErrUnexpectedEOF {
			break
		}
	}
	return nil
}

// decryptUserLoop drives the User-Driven Loop decrypt-side framing pattern.
func decryptUserLoop(unwrapReader io.Reader, decryptChunk func([]byte) ([]byte, error)) ([]byte, error) {
	var pt bytes.Buffer
	for {
		var ctLen uint32
		if err := binary.Read(unwrapReader, binary.LittleEndian, &ctLen); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		ctBuf := make([]byte, ctLen)
		if _, err := io.ReadFull(unwrapReader, ctBuf); err != nil {
			return nil, err
		}
		dec, err := decryptChunk(ctBuf)
		if err != nil {
			return nil, err
		}
		pt.Write(dec)
	}
	return pt.Bytes(), nil
}
