// Benchmarks for the format-deniability wrapper.
package wrapper_test

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/triple"
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

// benchCfg is the per-encryptor Config the benchmark suite pins every
// low-level call to. Bench harness invariant: NonceBits / BarrierFill
// / MaxWorkers pinned at the same values across every entry point so
// throughput comparisons are apples-to-apples.
var benchCfg = &itb.Config{
	NonceBits:   benchNonceBits,
	BarrierFill: benchBarrierFill,
	MaxWorkers:  0,
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

// benchTripleOnce guards the bench-only profile registrations so
// concurrent b.Run invocations converge on a single register pass.
var benchTripleOnce sync.Once

// benchTripleProfileName returns the deterministic name for a
// bench-only triple profile keyed by (mode, outer cipher).
func benchTripleProfileName(mode, cn string) string {
	return "bench-" + mode + "-" + benchPrimitive + "-" + cn
}

// registerBenchTripleProfiles installs one Profile per (mode, outer
// cipher) combination the Pipeline-based benches consume. Runs once;
// re-registration of an already-installed name is tolerated.
func registerBenchTripleProfiles() {
	benchTripleOnce.Do(func() {
		modes := []struct {
			mode string
			mac  string
			chsz int
		}{
			{"singlemsg-nomac", "", 0},
			{"singlemsg-mac", benchMACName, 0},
			{"streaming-noaead", "", benchStreamChunk},
			{"streaming-aead", benchMACName, benchStreamChunk},
		}
		for _, m := range modes {
			for _, cn := range wrapper.CipherNames {
				name := benchTripleProfileName(m.mode, cn)
				prof := triple.Profile{
					Name:        name,
					Mode:        m.mode,
					Width:       512,
					ChunkSize:   m.chsz,
					InnerHash:   benchPrimitive,
					KeyBits:     benchSeedWidth,
					MacName:     m.mac,
					OuterCipher: cn,
					Wrapper:     true,
					Parallax:    false,
				}
				if err := triple.Register(name, prof); err != nil && !errors.Is(err, triple.ErrProfileExists) {
					panic("triple.Register: " + err.Error())
				}
			}
		}
	})
}

// benchTripleInit opens a fresh Pipeline for the (mode, outer cipher)
// bench cell. The Opts pin NonceBits / BarrierFill to the same values
// the low-level wrapper benches use so throughput is comparable.
func benchTripleInit(b *testing.B, mode, cn string) *triple.Pipeline {
	b.Helper()
	registerBenchTripleProfiles()
	pipeline, _, err := triple.Init(benchTripleProfileName(mode, cn), triple.Opts{
		NonceBits:   benchNonceBits,
		BarrierFill: benchBarrierFill,
	})
	if err != nil {
		b.Fatalf("triple.Init(%s/%s): %v", mode, cn, err)
	}
	return pipeline
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
// Single Message — Triple Ouroboros (4 modes × outer cipher palette × 2 dirs).
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

// --- Triple Pipeline Message helpers ---
//
// The full ITB + wrapper Single Message benches route through the
// triple.Pipeline facade rather than composing itb.Encrypt3x512Cfg +
// wrapper.WrapInPlace by hand. Pipeline owns the buffer lifecycle, so
// the throughput reflects real user-facing composition cost — no
// per-iteration heap allocation of a fresh 18 MiB wire and no memcpy
// artefact.

func runMessageLowLevelTripleNoMACEncrypt(b *testing.B, plaintext []byte, cn string) {
	pipeline := benchTripleInit(b, "singlemsg-nomac", cn)
	defer pipeline.Close()
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pipeline.EncryptMessage(plaintext); err != nil {
			b.Fatalf("EncryptMessage: %v", err)
		}
	}
}

func runMessageLowLevelTripleNoMACDecrypt(b *testing.B, plaintext []byte, cn string) {
	pipeline := benchTripleInit(b, "singlemsg-nomac", cn)
	defer pipeline.Close()
	wire, err := pipeline.EncryptMessage(plaintext)
	if err != nil {
		b.Fatalf("EncryptMessage setup: %v", err)
	}
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pt, err := pipeline.DecryptMessage(wire)
		if err != nil {
			b.Fatalf("DecryptMessage: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
	}
}

func runMessageLowLevelTripleAuthEncrypt(b *testing.B, plaintext []byte, cn string) {
	pipeline := benchTripleInit(b, "singlemsg-mac", cn)
	defer pipeline.Close()
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := pipeline.EncryptMessage(plaintext); err != nil {
			b.Fatalf("EncryptMessage: %v", err)
		}
	}
}

func runMessageLowLevelTripleAuthDecrypt(b *testing.B, plaintext []byte, cn string) {
	pipeline := benchTripleInit(b, "singlemsg-mac", cn)
	defer pipeline.Close()
	wire, err := pipeline.EncryptMessage(plaintext)
	if err != nil {
		b.Fatalf("EncryptMessage setup: %v", err)
	}
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pt, err := pipeline.DecryptMessage(wire)
		if err != nil {
			b.Fatalf("DecryptMessage: %v", err)
		}
		if len(pt) != len(plaintext) {
			b.Fatalf("len mismatch: got %d want %d", len(pt), len(plaintext))
		}
	}
}

// ---------------------------------------------------------------------------
// Streaming — Triple Ouroboros (6 modes × outer cipher palette × 2 dirs).
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

// --- Streaming AEAD (IO-Driven) — Triple Pipeline (Encrypt / Decrypt) ---
//
// The IO-Driven streaming benches route the plaintext through
// bytes.NewReader → Pipeline.EncryptStream → io.Discard so the timed
// path is exactly what a real caller runs (plaintext bytes.Reader
// piped straight into the Pipeline, wire discarded to isolate encrypt
// cost). Decrypt caches the wire once and pipes it through
// Pipeline.DecryptStream on every iteration.

func runAEADLowLevelIOTripleEncrypt(b *testing.B, plaintext []byte, cn string) {
	pipeline := benchTripleInit(b, "streaming-aead", cn)
	defer pipeline.Close()
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pipeline.EncryptStream(bytes.NewReader(plaintext), io.Discard); err != nil {
			b.Fatalf("EncryptStream: %v", err)
		}
	}
}

func runAEADLowLevelIOTripleDecrypt(b *testing.B, plaintext []byte, cn string) {
	pipeline := benchTripleInit(b, "streaming-aead", cn)
	defer pipeline.Close()
	var wireBuf bytes.Buffer
	if err := pipeline.EncryptStream(bytes.NewReader(plaintext), &wireBuf); err != nil {
		b.Fatalf("EncryptStream setup: %v", err)
	}
	wire := wireBuf.Bytes()
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pipeline.DecryptStream(bytes.NewReader(wire), io.Discard); err != nil {
			b.Fatalf("DecryptStream: %v", err)
		}
	}
}

// --- Streaming Non-AEAD (IO-Driven) — Triple Pipeline (Encrypt / Decrypt) ---

func runNoAEADLowLevelIOTripleEncrypt(b *testing.B, plaintext []byte, cn string) {
	pipeline := benchTripleInit(b, "streaming-noaead", cn)
	defer pipeline.Close()
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pipeline.EncryptStream(bytes.NewReader(plaintext), io.Discard); err != nil {
			b.Fatalf("EncryptStream: %v", err)
		}
	}
}

func runNoAEADLowLevelIOTripleDecrypt(b *testing.B, plaintext []byte, cn string) {
	pipeline := benchTripleInit(b, "streaming-noaead", cn)
	defer pipeline.Close()
	var wireBuf bytes.Buffer
	if err := pipeline.EncryptStream(bytes.NewReader(plaintext), &wireBuf); err != nil {
		b.Fatalf("EncryptStream setup: %v", err)
	}
	wire := wireBuf.Bytes()
	b.SetBytes(int64(len(plaintext)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := pipeline.DecryptStream(bytes.NewReader(wire), io.Discard); err != nil {
			b.Fatalf("DecryptStream: %v", err)
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
			return itb.Encrypt3x512Cfg(benchCfg, noise, lock, d1, d2, d3, s1, s2, s3, buf)
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
		return itb.Encrypt3x512Cfg(benchCfg, noise, lock, d1, d2, d3, s1, s2, s3, buf)
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
			return itb.Decrypt3x512Cfg(benchCfg, noise, lock, d1, d2, d3, s1, s2, s3, ct)
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
