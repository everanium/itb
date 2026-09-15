package itb_test

import (
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/everanium/itb/internal/interlock"
	"github.com/everanium/itb/triple"
)

// benchMaxWorkers returns the ITB_MAX_WORKERS override for bench cells
// that pin the pipeline's worker cap. Zero (the return when the env
// var is unset, empty, non-numeric, or negative) leaves the pipeline
// at the [runtime.NumCPU] default; a positive integer clamps every
// cell to that worker count, so cross-host bench cells can be timed
// under an identical worker cap.
func benchMaxWorkers() int {
	v := os.Getenv("ITB_MAX_WORKERS")
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// benchInterlockGeometry applies ITB_BENCH_UNRANK8X2=1: the 16-chunk
// interlock superblock runs as two 8-lane kernel passes instead of the
// 16-lane kernel, so both geometries can be timed from one binary.
func benchInterlockGeometry(b *testing.B) {
	if os.Getenv("ITB_BENCH_UNRANK8X2") == "1" {
		saved := interlock.UseUnrank16
		interlock.UseUnrank16 = false
		b.Cleanup(func() { interlock.UseUnrank16 = saved })
	}
}

// BenchmarkExtWorkersAESITB128 drives every shipped AES-ITB profile
// (InnerHash aesitb128, wrapper and parallax off) through its mode's
// encrypt / decrypt surface at 64 MB, at 512-, 1024- and 2048-bit
// keys (5 / 9 / 17 cascade rounds in the batch-16 Interlocked Barrier
// fill hot loop), once through the fused ChainHash cascade kernel and
// once through the sequential per-round loop
// (ITB_FORCE_CHAINHASH_SEQ=1 at Init time). Every cell shares the same
// worker cap: ITB_MAX_WORKERS pins the pipeline to a specific worker
// count when set, and leaves the pipeline at the [runtime.NumCPU]
// default when unset — cross-host cells can be compared under an
// identical cap by exporting the same value on every host. The
// standard 1 / 16 / 64 MB message-size sweep for aesitb128 lives in
// aesitb_ext_bench_test.go.
func BenchmarkExtWorkersAESITB128(b *testing.B) {
	benchInterlockGeometry(b)
	workers := benchMaxWorkers()
	const size = 64 << 20
	plain := make([]byte, size)
	rand.Read(plain)
	profiles := []struct {
		name      string
		profile   string
		streaming bool
	}{
		{"singlemsg-mac", triple.ProfileSingleMsgAESITBMACV1, false},
		{"singlemsg-nomac", triple.ProfileSingleMsgAESITBNoMACV1, false},
		{"streaming-aead-mac", triple.ProfileStreamingAEADAESITBMACV1, true},
		{"streaming-noaead", triple.ProfileStreamingNoAEADAESITBV1, true},
	}
	for _, keyBits := range []int{512, 1024, 2048} {
		for _, path := range []string{"fused", "seq"} {
			for _, tc := range profiles {
				if path == "seq" {
					os.Setenv("ITB_FORCE_CHAINHASH_SEQ", "1")
				}
				p, _, err := triple.Init(tc.profile, triple.Opts{KeyBits: keyBits})
				os.Unsetenv("ITB_FORCE_CHAINHASH_SEQ")
				if err != nil {
					b.Fatal(err)
				}
				p.MaxWorkers(workers)
				enc := p.EncryptMessage
				dec := p.DecryptMessage
				if tc.streaming {
					enc = p.EncryptStreamBytes
					dec = p.DecryptStreamBytes
				}
				wire, err := enc(plain)
				if err != nil {
					b.Fatal(err)
				}
				label := fmt.Sprintf("%s/%dbit/%s", tc.name, keyBits, path)
				b.Run(fmt.Sprintf("%s/Encrypt_64MB", label), func(b *testing.B) {
					b.SetBytes(size)
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						if _, err := enc(plain); err != nil {
							b.Fatal(err)
						}
					}
				})
				b.Run(fmt.Sprintf("%s/Decrypt_64MB", label), func(b *testing.B) {
					b.SetBytes(size)
					b.ReportAllocs()
					for i := 0; i < b.N; i++ {
						if _, err := dec(wire); err != nil {
							b.Fatal(err)
						}
					}
				})
				p.Close()
			}
		}
	}
}

// BenchmarkAESITBProfileCell builds exactly one AES-ITB pipeline — chosen
// through ITB_BENCH_PROFILE (singlemsg-mac | singlemsg-nomac |
// streaming-aead-mac | streaming-noaead, default singlemsg-nomac),
// ITB_BENCH_KEYBITS (default 512) and ITB_BENCH_PATH (fused | seq,
// default fused) — and times its Encrypt / Decrypt at 64 MB. The worker
// cap follows ITB_MAX_WORKERS when set and defaults to [runtime.NumCPU]
// otherwise. Intended for -cpuprofile runs: nothing but the selected
// cell's pipeline exists in the process, so the profile carries no
// setup work from other cells.
func BenchmarkAESITBProfileCell(b *testing.B) {
	benchInterlockGeometry(b)
	const size = 64 << 20
	profiles := map[string]struct {
		profile   string
		streaming bool
	}{
		"singlemsg-mac":      {triple.ProfileSingleMsgAESITBMACV1, false},
		"singlemsg-nomac":    {triple.ProfileSingleMsgAESITBNoMACV1, false},
		"streaming-aead-mac": {triple.ProfileStreamingAEADAESITBMACV1, true},
		"streaming-noaead":   {triple.ProfileStreamingNoAEADAESITBV1, true},
	}
	name := os.Getenv("ITB_BENCH_PROFILE")
	if name == "" {
		name = "singlemsg-nomac"
	}
	tc, ok := profiles[name]
	if !ok {
		b.Fatalf("ITB_BENCH_PROFILE=%q unknown", name)
	}
	keyBits := 512
	if v := os.Getenv("ITB_BENCH_KEYBITS"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &keyBits); err != nil {
			b.Fatal(err)
		}
	}
	if os.Getenv("ITB_BENCH_PATH") == "seq" {
		os.Setenv("ITB_FORCE_CHAINHASH_SEQ", "1")
	}
	p, _, err := triple.Init(tc.profile, triple.Opts{KeyBits: keyBits})
	os.Unsetenv("ITB_FORCE_CHAINHASH_SEQ")
	if err != nil {
		b.Fatal(err)
	}
	p.MaxWorkers(benchMaxWorkers())
	defer p.Close()
	plain := make([]byte, size)
	rand.Read(plain)
	enc := p.EncryptMessage
	dec := p.DecryptMessage
	if tc.streaming {
		enc = p.EncryptStreamBytes
		dec = p.DecryptStreamBytes
	}
	wire, err := enc(plain)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("Encrypt", func(b *testing.B) {
		b.SetBytes(size)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := enc(plain); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Decrypt", func(b *testing.B) {
		b.SetBytes(size)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := dec(wire); err != nil {
				b.Fatal(err)
			}
		}
	})
}
