// Benchmarks for the format-deniability wrapper.
package wrapper_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/easy"
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
	benchBitSoup     = 0
	benchLockSoup    = 0
)

func init() {
	itb.SetMaxWorkers(0)
	itb.SetNonceBits(benchNonceBits)
	itb.SetBarrierFill(benchBarrierFill)
	itb.SetBitSoup(benchBitSoup)
	itb.SetLockSoup(benchLockSoup)
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

func benchEasySingle(b *testing.B, withMAC bool) *easy.Encryptor {
	if withMAC {
		return easy.New(benchPrimitive, benchSeedWidth, benchMACName)
	}
	return easy.New(benchPrimitive, benchSeedWidth)
}

func benchEasyTriple(b *testing.B, withMAC bool) *easy.Encryptor {
	if withMAC {
		return easy.New3(benchPrimitive, benchSeedWidth, benchMACName)
	}
	return easy.New3(benchPrimitive, benchSeedWidth)
}

func configureEasy(e *easy.Encryptor) {
	e.SetNonceBits(benchNonceBits)
	e.SetBarrierFill(benchBarrierFill)
	e.SetBitSoup(benchBitSoup)
	e.SetLockSoup(benchLockSoup)
}

func benchLowLevelSingleSeeds(b *testing.B) (noise, data, start *itb.Seed512) {
	hashFn, _, err := hashes.Make512(benchPrimitive)
	if err != nil {
		b.Fatalf("hashes.Make512: %v", err)
	}
	if noise, err = itb.NewSeed512(benchSeedWidth, hashFn); err != nil {
		b.Fatalf("NewSeed512 noise: %v", err)
	}
	if data, err = itb.NewSeed512(benchSeedWidth, hashFn); err != nil {
		b.Fatalf("NewSeed512 data: %v", err)
	}
	if start, err = itb.NewSeed512(benchSeedWidth, hashFn); err != nil {
		b.Fatalf("NewSeed512 start: %v", err)
	}
	return
}

func benchLowLevelTripleSeeds(b *testing.B) (noise, d1, d2, d3, s1, s2, s3 *itb.Seed512) {
	hashFn, _, err := hashes.Make512(benchPrimitive)
	if err != nil {
		b.Fatalf("hashes.Make512: %v", err)
	}
	mk := func(name string) *itb.Seed512 {
		s, err := itb.NewSeed512(benchSeedWidth, hashFn)
		if err != nil {
			b.Fatalf("NewSeed512 %s: %v", name, err)
		}
		return s
	}
	return mk("noise"), mk("data1"), mk("data2"), mk("data3"), mk("start1"), mk("start2"), mk("start3")
}

// ---------------------------------------------------------------------------
// Wrapper-only baseline.
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
// Single message — Single Ouroboros (12 sub-benches).
// ---------------------------------------------------------------------------

func BenchmarkMessageSingle(b *testing.B) {
	plaintext := benchRandom(b, benchSingleSize)
	for _, cn := range wrapper.CipherNames {
		b.Run("easy-nomac/"+cn, func(b *testing.B) {
			runMessageEasy(b, plaintext, cn, false, benchEasySingle)
		})
		b.Run("easy-auth/"+cn, func(b *testing.B) {
			runMessageEasy(b, plaintext, cn, true, benchEasySingle)
		})
		b.Run("lowlevel-nomac/"+cn, func(b *testing.B) {
			runMessageLowLevelSingleNoMAC(b, plaintext, cn)
		})
		b.Run("lowlevel-auth/"+cn, func(b *testing.B) {
			runMessageLowLevelSingleAuth(b, plaintext, cn)
		})
	}
}

// ---------------------------------------------------------------------------
// Single message — Triple Ouroboros (12 sub-benches).
// ---------------------------------------------------------------------------

func BenchmarkMessageTriple(b *testing.B) {
	plaintext := benchRandom(b, benchSingleSize)
	for _, cn := range wrapper.CipherNames {
		b.Run("easy-nomac/"+cn, func(b *testing.B) {
			runMessageEasy(b, plaintext, cn, false, benchEasyTriple)
		})
		b.Run("easy-auth/"+cn, func(b *testing.B) {
			runMessageEasy(b, plaintext, cn, true, benchEasyTriple)
		})
		b.Run("lowlevel-nomac/"+cn, func(b *testing.B) {
			runMessageLowLevelTripleNoMAC(b, plaintext, cn)
		})
		b.Run("lowlevel-auth/"+cn, func(b *testing.B) {
			runMessageLowLevelTripleAuth(b, plaintext, cn)
		})
	}
}

func runMessageEasy(
	b *testing.B,
	plaintext []byte,
	cn string,
	withMAC bool,
	mkEnc func(b *testing.B, withMAC bool) *easy.Encryptor,
) {
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc := mkEnc(b, withMAC)
		configureEasy(enc)
		var encrypted []byte
		var err error
		if withMAC {
			encrypted, err = enc.EncryptAuth(plaintext)
		} else {
			encrypted, err = enc.Encrypt(plaintext)
		}
		if err != nil {
			b.Fatalf("Encrypt: %v", err)
		}
		wire, err := wrapper.Wrap(cn, outerKey, encrypted)
		if err != nil {
			b.Fatalf("Wrap: %v", err)
		}
		recovered, err := wrapper.Unwrap(cn, outerKey, wire)
		if err != nil {
			b.Fatalf("Unwrap: %v", err)
		}
		var pt []byte
		if withMAC {
			pt, err = enc.DecryptAuth(recovered)
		} else {
			pt, err = enc.Decrypt(recovered)
		}
		if err != nil {
			b.Fatalf("Decrypt: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
		enc.Close()
	}
}

func runMessageLowLevelSingleNoMAC(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := itb.Encrypt(noise, data, start, plaintext)
		if err != nil {
			b.Fatalf("Encrypt: %v", err)
		}
		wire, err := wrapper.Wrap(cn, outerKey, encrypted)
		if err != nil {
			b.Fatalf("Wrap: %v", err)
		}
		recovered, err := wrapper.Unwrap(cn, outerKey, wire)
		if err != nil {
			b.Fatalf("Unwrap: %v", err)
		}
		pt, err := itb.Decrypt(noise, data, start, recovered)
		if err != nil {
			b.Fatalf("Decrypt: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
	}
}

func runMessageLowLevelSingleAuth(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := itb.EncryptAuth(noise, data, start, plaintext, macFunc)
		if err != nil {
			b.Fatalf("EncryptAuth: %v", err)
		}
		wire, err := wrapper.Wrap(cn, outerKey, encrypted)
		if err != nil {
			b.Fatalf("Wrap: %v", err)
		}
		recovered, err := wrapper.Unwrap(cn, outerKey, wire)
		if err != nil {
			b.Fatalf("Unwrap: %v", err)
		}
		pt, err := itb.DecryptAuth(noise, data, start, recovered, macFunc)
		if err != nil {
			b.Fatalf("DecryptAuth: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
	}
}

func runMessageLowLevelTripleNoMAC(b *testing.B, plaintext []byte, cn string) {
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := itb.Encrypt3x(noise, d1, d2, d3, s1, s2, s3, plaintext)
		if err != nil {
			b.Fatalf("Encrypt3x: %v", err)
		}
		wire, err := wrapper.Wrap(cn, outerKey, encrypted)
		if err != nil {
			b.Fatalf("Wrap: %v", err)
		}
		recovered, err := wrapper.Unwrap(cn, outerKey, wire)
		if err != nil {
			b.Fatalf("Unwrap: %v", err)
		}
		pt, err := itb.Decrypt3x(noise, d1, d2, d3, s1, s2, s3, recovered)
		if err != nil {
			b.Fatalf("Decrypt3x: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
	}
}

func runMessageLowLevelTripleAuth(b *testing.B, plaintext []byte, cn string) {
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := itb.EncryptAuth3x(noise, d1, d2, d3, s1, s2, s3, plaintext, macFunc)
		if err != nil {
			b.Fatalf("EncryptAuth3x: %v", err)
		}
		wire, err := wrapper.Wrap(cn, outerKey, encrypted)
		if err != nil {
			b.Fatalf("Wrap: %v", err)
		}
		recovered, err := wrapper.Unwrap(cn, outerKey, wire)
		if err != nil {
			b.Fatalf("Unwrap: %v", err)
		}
		pt, err := itb.DecryptAuth3x(noise, d1, d2, d3, s1, s2, s3, recovered, macFunc)
		if err != nil {
			b.Fatalf("DecryptAuth3x: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
	}
}

// ---------------------------------------------------------------------------
// Streaming — Single Ouroboros (18 sub-benches).
// ---------------------------------------------------------------------------

func BenchmarkStreamingSingle(b *testing.B) {
	plaintext := benchRandom(b, benchStreamSize)
	for _, cn := range wrapper.CipherNames {
		b.Run("aead-easy-io/"+cn, func(b *testing.B) {
			runAEADEasyIO(b, plaintext, cn, benchEasySingle)
		})
		b.Run("aead-lowlevel-io/"+cn, func(b *testing.B) {
			runAEADLowLevelIOSingle(b, plaintext, cn)
		})
		b.Run("noaead-easy-io/"+cn, func(b *testing.B) {
			runNoAEADEasyIO(b, plaintext, cn, benchEasySingle)
		})
		b.Run("noaead-easy-userloop/"+cn, func(b *testing.B) {
			runNoAEADEasyUserLoop(b, plaintext, cn, benchEasySingle)
		})
		b.Run("noaead-lowlevel-io/"+cn, func(b *testing.B) {
			runNoAEADLowLevelIOSingle(b, plaintext, cn)
		})
		b.Run("noaead-lowlevel-userloop/"+cn, func(b *testing.B) {
			runNoAEADLowLevelUserLoopSingle(b, plaintext, cn)
		})
	}
}

// ---------------------------------------------------------------------------
// Streaming — Triple Ouroboros (18 sub-benches).
// ---------------------------------------------------------------------------

func BenchmarkStreamingTriple(b *testing.B) {
	plaintext := benchRandom(b, benchStreamSize)
	for _, cn := range wrapper.CipherNames {
		b.Run("aead-easy-io/"+cn, func(b *testing.B) {
			runAEADEasyIO(b, plaintext, cn, benchEasyTriple)
		})
		b.Run("aead-lowlevel-io/"+cn, func(b *testing.B) {
			runAEADLowLevelIOTriple(b, plaintext, cn)
		})
		b.Run("noaead-easy-io/"+cn, func(b *testing.B) {
			runNoAEADEasyIO(b, plaintext, cn, benchEasyTriple)
		})
		b.Run("noaead-easy-userloop/"+cn, func(b *testing.B) {
			runNoAEADEasyUserLoop(b, plaintext, cn, benchEasyTriple)
		})
		b.Run("noaead-lowlevel-io/"+cn, func(b *testing.B) {
			runNoAEADLowLevelIOTriple(b, plaintext, cn)
		})
		b.Run("noaead-lowlevel-userloop/"+cn, func(b *testing.B) {
			runNoAEADLowLevelUserLoopTriple(b, plaintext, cn)
		})
	}
}

// --- Streaming AEAD Easy (IO-Driven) — shared between Single and Triple ---

func runAEADEasyIO(
	b *testing.B,
	plaintext []byte,
	cn string,
	mkEnc func(b *testing.B, withMAC bool) *easy.Encryptor,
) {
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc := mkEnc(b, true)
		configureEasy(enc)

		var wireBuf bytes.Buffer
		wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &wireBuf)
		if err != nil {
			b.Fatalf("NewWrapWriter: %v", err)
		}
		if err := enc.EncryptStreamAuthIO(bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStreamAuthIO: %v", err)
		}

		unwrapReader, err := wrapper.NewUnwrapReader(cn, outerKey, bytes.NewReader(wireBuf.Bytes()))
		if err != nil {
			b.Fatalf("NewUnwrapReader: %v", err)
		}
		var dst bytes.Buffer
		if err := enc.DecryptStreamAuthIO(unwrapReader, &dst); err != nil {
			b.Fatalf("DecryptStreamAuthIO: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
		enc.Close()
	}
}

// --- Streaming Easy (No MAC, IO-Driven) — shared between Single and Triple ---

func runNoAEADEasyIO(
	b *testing.B,
	plaintext []byte,
	cn string,
	mkEnc func(b *testing.B, withMAC bool) *easy.Encryptor,
) {
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc := mkEnc(b, false)
		configureEasy(enc)

		var wireBuf bytes.Buffer
		wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &wireBuf)
		if err != nil {
			b.Fatalf("NewWrapWriter: %v", err)
		}
		if err := enc.EncryptStreamIO(bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStreamIO: %v", err)
		}

		unwrapReader, err := wrapper.NewUnwrapReader(cn, outerKey, bytes.NewReader(wireBuf.Bytes()))
		if err != nil {
			b.Fatalf("NewUnwrapReader: %v", err)
		}
		var dst bytes.Buffer
		if err := enc.DecryptStreamIO(unwrapReader, &dst); err != nil {
			b.Fatalf("DecryptStreamIO: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
		enc.Close()
	}
}

// --- Streaming Easy (No MAC, User-Driven Loop) — shared between Single and Triple ---

func runNoAEADEasyUserLoop(
	b *testing.B,
	plaintext []byte,
	cn string,
	mkEnc func(b *testing.B, withMAC bool) *easy.Encryptor,
) {
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		enc := mkEnc(b, false)
		configureEasy(enc)

		var wireBuf bytes.Buffer
		wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &wireBuf)
		if err != nil {
			b.Fatalf("NewWrapWriter: %v", err)
		}
		if err := encryptUserLoop(plaintext, wrapWriter, func(buf []byte) ([]byte, error) {
			return enc.Encrypt(buf)
		}); err != nil {
			b.Fatalf("encryptUserLoop: %v", err)
		}

		unwrapReader, err := wrapper.NewUnwrapReader(cn, outerKey, bytes.NewReader(wireBuf.Bytes()))
		if err != nil {
			b.Fatalf("NewUnwrapReader: %v", err)
		}
		got, err := decryptUserLoop(unwrapReader, func(ct []byte) ([]byte, error) {
			return enc.Decrypt(ct)
		})
		if err != nil {
			b.Fatalf("decryptUserLoop: %v", err)
		}
		if len(got) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(got), len(plaintext))
		}
		enc.Close()
	}
}

// --- Streaming AEAD Low-Level — Single ---

func runAEADLowLevelIOSingle(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wireBuf bytes.Buffer
		wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &wireBuf)
		if err != nil {
			b.Fatalf("NewWrapWriter: %v", err)
		}
		if err := itb.EncryptStreamAuth(noise, data, start, bytes.NewReader(plaintext), wrapWriter, macFunc, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStreamAuth: %v", err)
		}

		unwrapReader, err := wrapper.NewUnwrapReader(cn, outerKey, bytes.NewReader(wireBuf.Bytes()))
		if err != nil {
			b.Fatalf("NewUnwrapReader: %v", err)
		}
		var dst bytes.Buffer
		if err := itb.DecryptStreamAuth(noise, data, start, unwrapReader, &dst, macFunc); err != nil {
			b.Fatalf("DecryptStreamAuth: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
	}
}

// --- Streaming AEAD Low-Level — Triple ---

func runAEADLowLevelIOTriple(b *testing.B, plaintext []byte, cn string) {
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wireBuf bytes.Buffer
		wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &wireBuf)
		if err != nil {
			b.Fatalf("NewWrapWriter: %v", err)
		}
		if err := itb.EncryptStreamAuth3x(noise, d1, d2, d3, s1, s2, s3, bytes.NewReader(plaintext), wrapWriter, macFunc, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStreamAuth3x: %v", err)
		}

		unwrapReader, err := wrapper.NewUnwrapReader(cn, outerKey, bytes.NewReader(wireBuf.Bytes()))
		if err != nil {
			b.Fatalf("NewUnwrapReader: %v", err)
		}
		var dst bytes.Buffer
		if err := itb.DecryptStreamAuth3x(noise, d1, d2, d3, s1, s2, s3, unwrapReader, &dst, macFunc); err != nil {
			b.Fatalf("DecryptStreamAuth3x: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
	}
}

// --- Streaming No MAC Low-Level (IO-Driven) — Single ---

func runNoAEADLowLevelIOSingle(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wireBuf bytes.Buffer
		wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &wireBuf)
		if err != nil {
			b.Fatalf("NewWrapWriter: %v", err)
		}
		if err := itb.EncryptStream(noise, data, start, bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStream: %v", err)
		}

		unwrapReader, err := wrapper.NewUnwrapReader(cn, outerKey, bytes.NewReader(wireBuf.Bytes()))
		if err != nil {
			b.Fatalf("NewUnwrapReader: %v", err)
		}
		var dst bytes.Buffer
		if err := itb.DecryptStream(noise, data, start, unwrapReader, &dst); err != nil {
			b.Fatalf("DecryptStream: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
	}
}

// --- Streaming No MAC Low-Level (IO-Driven) — Triple ---

func runNoAEADLowLevelIOTriple(b *testing.B, plaintext []byte, cn string) {
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wireBuf bytes.Buffer
		wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &wireBuf)
		if err != nil {
			b.Fatalf("NewWrapWriter: %v", err)
		}
		if err := itb.EncryptStream3x(noise, d1, d2, d3, s1, s2, s3, bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStream3x: %v", err)
		}

		unwrapReader, err := wrapper.NewUnwrapReader(cn, outerKey, bytes.NewReader(wireBuf.Bytes()))
		if err != nil {
			b.Fatalf("NewUnwrapReader: %v", err)
		}
		var dst bytes.Buffer
		if err := itb.DecryptStream3x(noise, d1, d2, d3, s1, s2, s3, unwrapReader, &dst); err != nil {
			b.Fatalf("DecryptStream3x: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
	}
}

// --- Streaming No MAC Low-Level (User-Driven Loop) — Single ---

func runNoAEADLowLevelUserLoopSingle(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wireBuf bytes.Buffer
		wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &wireBuf)
		if err != nil {
			b.Fatalf("NewWrapWriter: %v", err)
		}
		if err := encryptUserLoop(plaintext, wrapWriter, func(buf []byte) ([]byte, error) {
			return itb.Encrypt(noise, data, start, buf)
		}); err != nil {
			b.Fatalf("encryptUserLoop: %v", err)
		}

		unwrapReader, err := wrapper.NewUnwrapReader(cn, outerKey, bytes.NewReader(wireBuf.Bytes()))
		if err != nil {
			b.Fatalf("NewUnwrapReader: %v", err)
		}
		got, err := decryptUserLoop(unwrapReader, func(ct []byte) ([]byte, error) {
			return itb.Decrypt(noise, data, start, ct)
		})
		if err != nil {
			b.Fatalf("decryptUserLoop: %v", err)
		}
		if len(got) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(got), len(plaintext))
		}
	}
}

// --- Streaming No MAC Low-Level (User-Driven Loop) — Triple ---

func runNoAEADLowLevelUserLoopTriple(b *testing.B, plaintext []byte, cn string) {
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	outerKey := benchOuterKey(b, cn)
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var wireBuf bytes.Buffer
		wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &wireBuf)
		if err != nil {
			b.Fatalf("NewWrapWriter: %v", err)
		}
		if err := encryptUserLoop(plaintext, wrapWriter, func(buf []byte) ([]byte, error) {
			return itb.Encrypt3x(noise, d1, d2, d3, s1, s2, s3, buf)
		}); err != nil {
			b.Fatalf("encryptUserLoop: %v", err)
		}

		unwrapReader, err := wrapper.NewUnwrapReader(cn, outerKey, bytes.NewReader(wireBuf.Bytes()))
		if err != nil {
			b.Fatalf("NewUnwrapReader: %v", err)
		}
		got, err := decryptUserLoop(unwrapReader, func(ct []byte) ([]byte, error) {
			return itb.Decrypt3x(noise, d1, d2, d3, s1, s2, s3, ct)
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
