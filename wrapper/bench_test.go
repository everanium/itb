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

// benchLowLevelMakeSeed512 builds one fresh *itb.Seed512 with both the
// single-arm hash and the 4-way batched arm wired in. The batched arm
// (assigned to Seed512.BatchHash) is what the per-pixel inner loop in
// processChunk512 dispatches through when both noiseSeed.BatchHash and
// dataSeed.BatchHash are non-nil — that path runs four pixels at a time
// and is the canonical Low-Level fast-path setup used by every shipped
// binding's bench harness and by easy.allocSeed in easy/easy.go:425+.
//
// Each seed receives an independently-keyed PRF instance (one
// Make512Pair call per seed) so that the noise / data / start seed
// slots use distinct PRF keys, mirroring what easy.New does at
// easy.go:316-322 — sharing one (single, batched) closure pair across
// all three slots would couple their key channels.
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

func benchLowLevelSingleSeeds(b *testing.B) (noise, data, start *itb.Seed512) {
	return benchLowLevelMakeSeed512(b), benchLowLevelMakeSeed512(b), benchLowLevelMakeSeed512(b)
}

func benchLowLevelTripleSeeds(b *testing.B) (noise, d1, d2, d3, s1, s2, s3 *itb.Seed512) {
	return benchLowLevelMakeSeed512(b), benchLowLevelMakeSeed512(b), benchLowLevelMakeSeed512(b), benchLowLevelMakeSeed512(b),
		benchLowLevelMakeSeed512(b), benchLowLevelMakeSeed512(b), benchLowLevelMakeSeed512(b)
}

// ---------------------------------------------------------------------------
// Wrapper-only baseline (round-trip — wrapper-cost-isolation case).
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
// Single message — Single Ouroboros (24 sub-benches: 4 modes × 3 ciphers × 2 directions).
// ---------------------------------------------------------------------------

func BenchmarkMessageSingle(b *testing.B) {
	plaintext := benchRandom(b, benchSingleSize)
	for _, cn := range wrapper.CipherNames {
		b.Run("easy-nomac/"+cn+"/encrypt", func(b *testing.B) {
			runMessageEasyEncrypt(b, plaintext, cn, false, benchEasySingle)
		})
		b.Run("easy-nomac/"+cn+"/decrypt", func(b *testing.B) {
			runMessageEasyDecrypt(b, plaintext, cn, false, benchEasySingle)
		})
		b.Run("easy-auth/"+cn+"/encrypt", func(b *testing.B) {
			runMessageEasyEncrypt(b, plaintext, cn, true, benchEasySingle)
		})
		b.Run("easy-auth/"+cn+"/decrypt", func(b *testing.B) {
			runMessageEasyDecrypt(b, plaintext, cn, true, benchEasySingle)
		})
		b.Run("lowlevel-nomac/"+cn+"/encrypt", func(b *testing.B) {
			runMessageLowLevelSingleNoMACEncrypt(b, plaintext, cn)
		})
		b.Run("lowlevel-nomac/"+cn+"/decrypt", func(b *testing.B) {
			runMessageLowLevelSingleNoMACDecrypt(b, plaintext, cn)
		})
		b.Run("lowlevel-auth/"+cn+"/encrypt", func(b *testing.B) {
			runMessageLowLevelSingleAuthEncrypt(b, plaintext, cn)
		})
		b.Run("lowlevel-auth/"+cn+"/decrypt", func(b *testing.B) {
			runMessageLowLevelSingleAuthDecrypt(b, plaintext, cn)
		})
	}
}

// ---------------------------------------------------------------------------
// Single message — Triple Ouroboros (24 sub-benches).
// ---------------------------------------------------------------------------

func BenchmarkMessageTriple(b *testing.B) {
	plaintext := benchRandom(b, benchSingleSize)
	for _, cn := range wrapper.CipherNames {
		b.Run("easy-nomac/"+cn+"/encrypt", func(b *testing.B) {
			runMessageEasyEncrypt(b, plaintext, cn, false, benchEasyTriple)
		})
		b.Run("easy-nomac/"+cn+"/decrypt", func(b *testing.B) {
			runMessageEasyDecrypt(b, plaintext, cn, false, benchEasyTriple)
		})
		b.Run("easy-auth/"+cn+"/encrypt", func(b *testing.B) {
			runMessageEasyEncrypt(b, plaintext, cn, true, benchEasyTriple)
		})
		b.Run("easy-auth/"+cn+"/decrypt", func(b *testing.B) {
			runMessageEasyDecrypt(b, plaintext, cn, true, benchEasyTriple)
		})
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

// --- Easy Mode Message helpers ---

func runMessageEasyEncrypt(
	b *testing.B,
	plaintext []byte,
	cn string,
	withMAC bool,
	mkEnc func(b *testing.B, withMAC bool) *easy.Encryptor,
) {
	enc := mkEnc(b, withMAC)
	configureEasy(enc)
	defer enc.Close()
	outerKey := benchOuterKey(b, cn)
	var wireBuf []byte
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
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
		nonce, err := wrapper.WrapInPlace(cn, outerKey, encrypted)
		if err != nil {
			b.Fatalf("WrapInPlace: %v", err)
		}
		_ = composeWire(&wireBuf, nonce, encrypted)
	}
}

func runMessageEasyDecrypt(
	b *testing.B,
	plaintext []byte,
	cn string,
	withMAC bool,
	mkEnc func(b *testing.B, withMAC bool) *easy.Encryptor,
) {
	enc := mkEnc(b, withMAC)
	configureEasy(enc)
	defer enc.Close()
	outerKey := benchOuterKey(b, cn)

	// Build one pristine wire (untimed). The timed loop refreshes a working
	// copy each iteration because UnwrapInPlace mutates the buffer.
	var encrypted []byte
	var err error
	if withMAC {
		encrypted, err = enc.EncryptAuth(plaintext)
	} else {
		encrypted, err = enc.Encrypt(plaintext)
	}
	if err != nil {
		b.Fatalf("Encrypt setup: %v", err)
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
		// Refresh the working wire from the pristine copy. The memcpy is
		// inside the timed total — small relative to ITB Decrypt cost.
		copy(workWire, pristineWire)
		body, err := wrapper.UnwrapInPlace(cn, outerKey, workWire)
		if err != nil {
			b.Fatalf("UnwrapInPlace: %v", err)
		}
		var pt []byte
		if withMAC {
			pt, err = enc.DecryptAuth(body)
		} else {
			pt, err = enc.Decrypt(body)
		}
		if err != nil {
			b.Fatalf("Decrypt: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
	}
}

// --- Low-Level Single Ouroboros Message helpers ---

func runMessageLowLevelSingleNoMACEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
	outerKey := benchOuterKey(b, cn)
	var wireBuf []byte
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := itb.Encrypt(noise, data, start, plaintext)
		if err != nil {
			b.Fatalf("Encrypt: %v", err)
		}
		nonce, err := wrapper.WrapInPlace(cn, outerKey, encrypted)
		if err != nil {
			b.Fatalf("WrapInPlace: %v", err)
		}
		_ = composeWire(&wireBuf, nonce, encrypted)
	}
}

func runMessageLowLevelSingleNoMACDecrypt(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
	outerKey := benchOuterKey(b, cn)

	encrypted, err := itb.Encrypt(noise, data, start, plaintext)
	if err != nil {
		b.Fatalf("Encrypt setup: %v", err)
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
		pt, err := itb.Decrypt(noise, data, start, body)
		if err != nil {
			b.Fatalf("Decrypt: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
	}
}

func runMessageLowLevelSingleAuthEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)
	var wireBuf []byte
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := itb.EncryptAuth(noise, data, start, plaintext, macFunc)
		if err != nil {
			b.Fatalf("EncryptAuth: %v", err)
		}
		nonce, err := wrapper.WrapInPlace(cn, outerKey, encrypted)
		if err != nil {
			b.Fatalf("WrapInPlace: %v", err)
		}
		_ = composeWire(&wireBuf, nonce, encrypted)
	}
}

func runMessageLowLevelSingleAuthDecrypt(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)

	encrypted, err := itb.EncryptAuth(noise, data, start, plaintext, macFunc)
	if err != nil {
		b.Fatalf("EncryptAuth setup: %v", err)
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
		pt, err := itb.DecryptAuth(noise, data, start, body, macFunc)
		if err != nil {
			b.Fatalf("DecryptAuth: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
	}
}

// --- Low-Level Triple Ouroboros Message helpers ---

func runMessageLowLevelTripleNoMACEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	outerKey := benchOuterKey(b, cn)
	var wireBuf []byte
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := itb.Encrypt3x(noise, d1, d2, d3, s1, s2, s3, plaintext)
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
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	outerKey := benchOuterKey(b, cn)

	encrypted, err := itb.Encrypt3x(noise, d1, d2, d3, s1, s2, s3, plaintext)
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
		pt, err := itb.Decrypt3x(noise, d1, d2, d3, s1, s2, s3, body)
		if err != nil {
			b.Fatalf("Decrypt3x: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
	}
}

func runMessageLowLevelTripleAuthEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)
	var wireBuf []byte
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := itb.EncryptAuth3x(noise, d1, d2, d3, s1, s2, s3, plaintext, macFunc)
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
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)

	encrypted, err := itb.EncryptAuth3x(noise, d1, d2, d3, s1, s2, s3, plaintext, macFunc)
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
		pt, err := itb.DecryptAuth3x(noise, d1, d2, d3, s1, s2, s3, body, macFunc)
		if err != nil {
			b.Fatalf("DecryptAuth3x: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
	}
}

// ---------------------------------------------------------------------------
// Streaming — Single Ouroboros (36 sub-benches: 6 modes × 3 ciphers × 2 directions).
// ---------------------------------------------------------------------------

func BenchmarkStreamingSingle(b *testing.B) {
	plaintext := benchRandom(b, benchStreamSize)
	for _, cn := range wrapper.CipherNames {
		b.Run("aead-easy-io/"+cn+"/encrypt", func(b *testing.B) {
			runAEADEasyIOEncrypt(b, plaintext, cn, benchEasySingle)
		})
		b.Run("aead-easy-io/"+cn+"/decrypt", func(b *testing.B) {
			runAEADEasyIODecrypt(b, plaintext, cn, benchEasySingle)
		})
		b.Run("aead-lowlevel-io/"+cn+"/encrypt", func(b *testing.B) {
			runAEADLowLevelIOSingleEncrypt(b, plaintext, cn)
		})
		b.Run("aead-lowlevel-io/"+cn+"/decrypt", func(b *testing.B) {
			runAEADLowLevelIOSingleDecrypt(b, plaintext, cn)
		})
		b.Run("noaead-easy-io/"+cn+"/encrypt", func(b *testing.B) {
			runNoAEADEasyIOEncrypt(b, plaintext, cn, benchEasySingle)
		})
		b.Run("noaead-easy-io/"+cn+"/decrypt", func(b *testing.B) {
			runNoAEADEasyIODecrypt(b, plaintext, cn, benchEasySingle)
		})
		b.Run("noaead-easy-userloop/"+cn+"/encrypt", func(b *testing.B) {
			runNoAEADEasyUserLoopEncrypt(b, plaintext, cn, benchEasySingle)
		})
		b.Run("noaead-easy-userloop/"+cn+"/decrypt", func(b *testing.B) {
			runNoAEADEasyUserLoopDecrypt(b, plaintext, cn, benchEasySingle)
		})
		b.Run("noaead-lowlevel-io/"+cn+"/encrypt", func(b *testing.B) {
			runNoAEADLowLevelIOSingleEncrypt(b, plaintext, cn)
		})
		b.Run("noaead-lowlevel-io/"+cn+"/decrypt", func(b *testing.B) {
			runNoAEADLowLevelIOSingleDecrypt(b, plaintext, cn)
		})
		b.Run("noaead-lowlevel-userloop/"+cn+"/encrypt", func(b *testing.B) {
			runNoAEADLowLevelUserLoopSingleEncrypt(b, plaintext, cn)
		})
		b.Run("noaead-lowlevel-userloop/"+cn+"/decrypt", func(b *testing.B) {
			runNoAEADLowLevelUserLoopSingleDecrypt(b, plaintext, cn)
		})
	}
}

// ---------------------------------------------------------------------------
// Streaming — Triple Ouroboros (36 sub-benches).
// ---------------------------------------------------------------------------

func BenchmarkStreamingTriple(b *testing.B) {
	plaintext := benchRandom(b, benchStreamSize)
	for _, cn := range wrapper.CipherNames {
		b.Run("aead-easy-io/"+cn+"/encrypt", func(b *testing.B) {
			runAEADEasyIOEncrypt(b, plaintext, cn, benchEasyTriple)
		})
		b.Run("aead-easy-io/"+cn+"/decrypt", func(b *testing.B) {
			runAEADEasyIODecrypt(b, plaintext, cn, benchEasyTriple)
		})
		b.Run("aead-lowlevel-io/"+cn+"/encrypt", func(b *testing.B) {
			runAEADLowLevelIOTripleEncrypt(b, plaintext, cn)
		})
		b.Run("aead-lowlevel-io/"+cn+"/decrypt", func(b *testing.B) {
			runAEADLowLevelIOTripleDecrypt(b, plaintext, cn)
		})
		b.Run("noaead-easy-io/"+cn+"/encrypt", func(b *testing.B) {
			runNoAEADEasyIOEncrypt(b, plaintext, cn, benchEasyTriple)
		})
		b.Run("noaead-easy-io/"+cn+"/decrypt", func(b *testing.B) {
			runNoAEADEasyIODecrypt(b, plaintext, cn, benchEasyTriple)
		})
		b.Run("noaead-easy-userloop/"+cn+"/encrypt", func(b *testing.B) {
			runNoAEADEasyUserLoopEncrypt(b, plaintext, cn, benchEasyTriple)
		})
		b.Run("noaead-easy-userloop/"+cn+"/decrypt", func(b *testing.B) {
			runNoAEADEasyUserLoopDecrypt(b, plaintext, cn, benchEasyTriple)
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

// --- Streaming AEAD Easy (IO-Driven) — Encrypt / Decrypt ---

func runAEADEasyIOEncrypt(
	b *testing.B,
	plaintext []byte,
	cn string,
	mkEnc func(b *testing.B, withMAC bool) *easy.Encryptor,
) {
	enc := mkEnc(b, true)
	configureEasy(enc)
	defer enc.Close()
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
		if err := enc.EncryptStreamAuthIO(bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStreamAuthIO: %v", err)
		}
	}
}

func runAEADEasyIODecrypt(
	b *testing.B,
	plaintext []byte,
	cn string,
	mkEnc func(b *testing.B, withMAC bool) *easy.Encryptor,
) {
	enc := mkEnc(b, true)
	configureEasy(enc)
	defer enc.Close()
	outerKey := benchOuterKey(b, cn)

	// Build one pristine wire (untimed). The decrypt loop reads from a fresh
	// bytes.Reader over the same backing slice each iteration.
	var pristineBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &pristineBuf)
	if err != nil {
		b.Fatalf("NewWrapWriter setup: %v", err)
	}
	if err := enc.EncryptStreamAuthIO(bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
		b.Fatalf("EncryptStreamAuthIO setup: %v", err)
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
		if err := enc.DecryptStreamAuthIO(unwrapReader, &dst); err != nil {
			b.Fatalf("DecryptStreamAuthIO: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
	}
}

// --- Streaming Easy (No MAC, IO-Driven) — Encrypt / Decrypt ---

func runNoAEADEasyIOEncrypt(
	b *testing.B,
	plaintext []byte,
	cn string,
	mkEnc func(b *testing.B, withMAC bool) *easy.Encryptor,
) {
	enc := mkEnc(b, false)
	configureEasy(enc)
	defer enc.Close()
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
		if err := enc.EncryptStreamIO(bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStreamIO: %v", err)
		}
	}
}

func runNoAEADEasyIODecrypt(
	b *testing.B,
	plaintext []byte,
	cn string,
	mkEnc func(b *testing.B, withMAC bool) *easy.Encryptor,
) {
	enc := mkEnc(b, false)
	configureEasy(enc)
	defer enc.Close()
	outerKey := benchOuterKey(b, cn)

	var pristineBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &pristineBuf)
	if err != nil {
		b.Fatalf("NewWrapWriter setup: %v", err)
	}
	if err := enc.EncryptStreamIO(bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
		b.Fatalf("EncryptStreamIO setup: %v", err)
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
		if err := enc.DecryptStreamIO(unwrapReader, &dst); err != nil {
			b.Fatalf("DecryptStreamIO: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
	}
}

// --- Streaming Easy (No MAC, User-Driven Loop) — Encrypt / Decrypt ---

func runNoAEADEasyUserLoopEncrypt(
	b *testing.B,
	plaintext []byte,
	cn string,
	mkEnc func(b *testing.B, withMAC bool) *easy.Encryptor,
) {
	enc := mkEnc(b, false)
	configureEasy(enc)
	defer enc.Close()
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
			return enc.Encrypt(buf)
		}); err != nil {
			b.Fatalf("encryptUserLoop: %v", err)
		}
	}
}

func runNoAEADEasyUserLoopDecrypt(
	b *testing.B,
	plaintext []byte,
	cn string,
	mkEnc func(b *testing.B, withMAC bool) *easy.Encryptor,
) {
	enc := mkEnc(b, false)
	configureEasy(enc)
	defer enc.Close()
	outerKey := benchOuterKey(b, cn)

	var pristineBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &pristineBuf)
	if err != nil {
		b.Fatalf("NewWrapWriter setup: %v", err)
	}
	if err := encryptUserLoop(plaintext, wrapWriter, func(buf []byte) ([]byte, error) {
		return enc.Encrypt(buf)
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
			return enc.Decrypt(ct)
		})
		if err != nil {
			b.Fatalf("decryptUserLoop: %v", err)
		}
		if len(got) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(got), len(plaintext))
		}
	}
}

// --- Streaming AEAD Low-Level — Single (Encrypt / Decrypt) ---

func runAEADLowLevelIOSingleEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
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
		if err := itb.EncryptStreamAuth(noise, data, start, bytes.NewReader(plaintext), wrapWriter, macFunc, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStreamAuth: %v", err)
		}
	}
}

func runAEADLowLevelIOSingleDecrypt(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)

	var pristineBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &pristineBuf)
	if err != nil {
		b.Fatalf("NewWrapWriter setup: %v", err)
	}
	if err := itb.EncryptStreamAuth(noise, data, start, bytes.NewReader(plaintext), wrapWriter, macFunc, benchStreamChunk); err != nil {
		b.Fatalf("EncryptStreamAuth setup: %v", err)
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
		if err := itb.DecryptStreamAuth(noise, data, start, unwrapReader, &dst, macFunc); err != nil {
			b.Fatalf("DecryptStreamAuth: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
	}
}

// --- Streaming AEAD Low-Level — Triple (Encrypt / Decrypt) ---

func runAEADLowLevelIOTripleEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
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
		if err := itb.EncryptStreamAuth3x(noise, d1, d2, d3, s1, s2, s3, bytes.NewReader(plaintext), wrapWriter, macFunc, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStreamAuth3x: %v", err)
		}
	}
}

func runAEADLowLevelIOTripleDecrypt(b *testing.B, plaintext []byte, cn string) {
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	macFunc := benchMACFunc(b)
	outerKey := benchOuterKey(b, cn)

	var pristineBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &pristineBuf)
	if err != nil {
		b.Fatalf("NewWrapWriter setup: %v", err)
	}
	if err := itb.EncryptStreamAuth3x(noise, d1, d2, d3, s1, s2, s3, bytes.NewReader(plaintext), wrapWriter, macFunc, benchStreamChunk); err != nil {
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
		if err := itb.DecryptStreamAuth3x(noise, d1, d2, d3, s1, s2, s3, unwrapReader, &dst, macFunc); err != nil {
			b.Fatalf("DecryptStreamAuth3x: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
	}
}

// --- Streaming No MAC Low-Level (IO-Driven) — Single (Encrypt / Decrypt) ---

func runNoAEADLowLevelIOSingleEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
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
		if err := itb.EncryptStream(noise, data, start, bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStream: %v", err)
		}
	}
}

func runNoAEADLowLevelIOSingleDecrypt(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
	outerKey := benchOuterKey(b, cn)

	var pristineBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &pristineBuf)
	if err != nil {
		b.Fatalf("NewWrapWriter setup: %v", err)
	}
	if err := itb.EncryptStream(noise, data, start, bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
		b.Fatalf("EncryptStream setup: %v", err)
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
		if err := itb.DecryptStream(noise, data, start, unwrapReader, &dst); err != nil {
			b.Fatalf("DecryptStream: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
	}
}

// --- Streaming No MAC Low-Level (IO-Driven) — Triple (Encrypt / Decrypt) ---

func runNoAEADLowLevelIOTripleEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
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
		if err := itb.EncryptStream3x(noise, d1, d2, d3, s1, s2, s3, bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
			b.Fatalf("EncryptStream3x: %v", err)
		}
	}
}

func runNoAEADLowLevelIOTripleDecrypt(b *testing.B, plaintext []byte, cn string) {
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	outerKey := benchOuterKey(b, cn)

	var pristineBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &pristineBuf)
	if err != nil {
		b.Fatalf("NewWrapWriter setup: %v", err)
	}
	if err := itb.EncryptStream3x(noise, d1, d2, d3, s1, s2, s3, bytes.NewReader(plaintext), wrapWriter, benchStreamChunk); err != nil {
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
		if err := itb.DecryptStream3x(noise, d1, d2, d3, s1, s2, s3, unwrapReader, &dst); err != nil {
			b.Fatalf("DecryptStream3x: %v", err)
		}
		if dst.Len() != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", dst.Len(), len(plaintext))
		}
	}
}

// --- Streaming No MAC Low-Level (User-Driven Loop) — Single (Encrypt / Decrypt) ---

func runNoAEADLowLevelUserLoopSingleEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
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
			return itb.Encrypt(noise, data, start, buf)
		}); err != nil {
			b.Fatalf("encryptUserLoop: %v", err)
		}
	}
}

func runNoAEADLowLevelUserLoopSingleDecrypt(b *testing.B, plaintext []byte, cn string) {
	noise, data, start := benchLowLevelSingleSeeds(b)
	outerKey := benchOuterKey(b, cn)

	var pristineBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &pristineBuf)
	if err != nil {
		b.Fatalf("NewWrapWriter setup: %v", err)
	}
	if err := encryptUserLoop(plaintext, wrapWriter, func(buf []byte) ([]byte, error) {
		return itb.Encrypt(noise, data, start, buf)
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

// --- Streaming No MAC Low-Level (User-Driven Loop) — Triple (Encrypt / Decrypt) ---

func runNoAEADLowLevelUserLoopTripleEncrypt(b *testing.B, plaintext []byte, cn string) {
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
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
			return itb.Encrypt3x(noise, d1, d2, d3, s1, s2, s3, buf)
		}); err != nil {
			b.Fatalf("encryptUserLoop: %v", err)
		}
	}
}

func runNoAEADLowLevelUserLoopTripleDecrypt(b *testing.B, plaintext []byte, cn string) {
	noise, d1, d2, d3, s1, s2, s3 := benchLowLevelTripleSeeds(b)
	outerKey := benchOuterKey(b, cn)

	var pristineBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cn, outerKey, &pristineBuf)
	if err != nil {
		b.Fatalf("NewWrapWriter setup: %v", err)
	}
	if err := encryptUserLoop(plaintext, wrapWriter, func(buf []byte) ([]byte, error) {
		return itb.Encrypt3x(noise, d1, d2, d3, s1, s2, s3, buf)
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
