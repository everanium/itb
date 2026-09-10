// Benchmarks for the format-deniability wrapper.
package wrapper_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"testing"

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

func benchRandom(b *testing.B, n int) []byte {
	out := make([]byte, n)
	if _, err := rand.Read(out); err != nil {
		b.Fatalf("rand.Read: %v", err)
	}
	return out
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
		b.Run("nomac/"+cn+"/encrypt", func(b *testing.B) {
			runMessageTripleNoMACEncrypt(b, plaintext, cn)
		})
		b.Run("nomac/"+cn+"/decrypt", func(b *testing.B) {
			runMessageTripleNoMACDecrypt(b, plaintext, cn)
		})
		b.Run("auth/"+cn+"/encrypt", func(b *testing.B) {
			runMessageTripleAuthEncrypt(b, plaintext, cn)
		})
		b.Run("auth/"+cn+"/decrypt", func(b *testing.B) {
			runMessageTripleAuthDecrypt(b, plaintext, cn)
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

func runMessageTripleNoMACEncrypt(b *testing.B, plaintext []byte, cn string) {
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

func runMessageTripleNoMACDecrypt(b *testing.B, plaintext []byte, cn string) {
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

func runMessageTripleAuthEncrypt(b *testing.B, plaintext []byte, cn string) {
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

func runMessageTripleAuthDecrypt(b *testing.B, plaintext []byte, cn string) {
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
// Streaming — Triple Ouroboros (2 modes × outer cipher palette × 2 dirs).
// ---------------------------------------------------------------------------

func BenchmarkStreamingTriple(b *testing.B) {
	plaintext := benchRandom(b, benchStreamSize)
	for _, cn := range wrapper.CipherNames {
		b.Run("aead-io/"+cn+"/encrypt", func(b *testing.B) {
			runAEADIOTripleEncrypt(b, plaintext, cn)
		})
		b.Run("aead-io/"+cn+"/decrypt", func(b *testing.B) {
			runAEADIOTripleDecrypt(b, plaintext, cn)
		})
		b.Run("noaead-io/"+cn+"/encrypt", func(b *testing.B) {
			runNoAEADIOTripleEncrypt(b, plaintext, cn)
		})
		b.Run("noaead-io/"+cn+"/decrypt", func(b *testing.B) {
			runNoAEADIOTripleDecrypt(b, plaintext, cn)
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

func runAEADIOTripleEncrypt(b *testing.B, plaintext []byte, cn string) {
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

func runAEADIOTripleDecrypt(b *testing.B, plaintext []byte, cn string) {
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

func runNoAEADIOTripleEncrypt(b *testing.B, plaintext []byte, cn string) {
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

func runNoAEADIOTripleDecrypt(b *testing.B, plaintext []byte, cn string) {
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

