package itb_test

import (
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/everanium/itb/internal/interlock"
	"github.com/everanium/itb/triple"
)

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
// fill hot loop), with the worker cap at auto (0), 4 and 8, once
// through the fused ChainHash cascade kernel and once through the
// sequential per-round loop (ITB_FORCE_CHAINHASH_SEQ=1 at Init time).
// This is a MaxWorkers sweep (every cell carries a W<n> suffix), not
// the message-size sweep the ExtTriple harness runs — the standard
// 1 / 16 / 64 MB cells for aesitb128 live in aesitb_ext_bench_test.go.
func BenchmarkExtWorkersAESITB128(b *testing.B) {
	benchInterlockGeometry(b)
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
	for _, workers := range []int{0, 4, 8} {
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
					b.Run(fmt.Sprintf("%s/Encrypt_64MB_W%d", label, workers), func(b *testing.B) {
						b.SetBytes(size)
						b.ReportAllocs()
						for i := 0; i < b.N; i++ {
							if _, err := enc(plain); err != nil {
								b.Fatal(err)
							}
						}
					})
					b.Run(fmt.Sprintf("%s/Decrypt_64MB_W%d", label, workers), func(b *testing.B) {
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
}

// BenchmarkAESITBProfileCell builds exactly one AES-ITB pipeline — chosen
// through ITB_BENCH_PROFILE (singlemsg-mac | singlemsg-nomac |
// streaming-aead-mac | streaming-noaead, default singlemsg-nomac),
// ITB_BENCH_KEYBITS (default 512) and ITB_BENCH_PATH (fused | seq,
// default fused) — and times its Encrypt / Decrypt at 64 MB with the
// worker cap at auto. Intended for -cpuprofile runs: nothing but the
// selected cell's pipeline exists in the process, so the profile carries
// no setup work from other cells.
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
