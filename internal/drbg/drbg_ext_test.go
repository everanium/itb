package drbg_test

import (
	"bytes"
	"sync"
	"testing"

	"github.com/everanium/itb/ctr"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/drbg"
)

// The tests in this file link package ctr, which installs the
// keystream arms at init; an in-package test cannot import it (ctr
// depends on this package through the hashes registry).

// TestNamesCanonicalOrder pins the token set and its order: aesitb128,
// every keystream-eligible registry primitive in registry order, then
// csprng.
func TestNamesCanonicalOrder(t *testing.T) {
	want := append([]string{drbg.NameAESITB128}, hashes.KeystreamNames()...)
	want = append(want, drbg.NameCSPRNG)
	got := drbg.Names()
	// A test-installed arm (drbg_test.go) may follow the ctr arms;
	// compare the canonical prefix and the closing token.
	if len(got) < len(want) || got[len(got)-1] != drbg.NameCSPRNG {
		t.Fatalf("Names() = %v, want prefix %v closed by csprng", got, want)
	}
	for i, name := range want[:len(want)-1] {
		if got[i] != name {
			t.Fatalf("Names()[%d] = %q, want %q (%v)", i, got[i], name, got)
		}
	}
	for _, name := range got {
		if !drbg.Known(name) {
			t.Fatalf("Known(%q) false for a listed name", name)
		}
	}
}

// TestEveryArmFills runs every arm Names reports over the length
// classes: non-zero output, fresh seed per call.
func TestEveryArmFills(t *testing.T) {
	for _, name := range drbg.Names() {
		for _, n := range []int{0, 1, 15, 16, 17, 64 << 10} {
			a := make([]byte, n)
			b := make([]byte, n)
			if err := drbg.FillWith(name, a); err != nil {
				t.Fatalf("FillWith(%q, %d): %v", name, n, err)
			}
			if err := drbg.FillWith(name, b); err != nil {
				t.Fatalf("FillWith(%q, %d): %v", name, n, err)
			}
			if n >= 16 && (bytes.Equal(a, make([]byte, n)) || bytes.Equal(a, b)) {
				t.Fatalf("FillWith(%q, %d): output all-zero or repeated", name, n)
			}
		}
	}
}

// TestAESITB128ArmBypassesCTR pins the structural isolation: the ctr
// constructor keeps refusing aesitb128 while the DRBG arm serves it.
func TestAESITB128ArmBypassesCTR(t *testing.T) {
	if _, err := ctr.New(hashes.CipherAESITB128, make([]byte, 16), make([]byte, 16)); err == nil {
		t.Fatal("ctr.New(aesitb128) accepted the Non-PRF primitive")
	}
	buf := make([]byte, 4096)
	if err := drbg.FillWith(drbg.NameAESITB128, buf); err != nil {
		t.Fatalf("FillWith(aesitb128): %v", err)
	}
	if bytes.Equal(buf, make([]byte, len(buf))) {
		t.Fatal("aesitb128 arm left the buffer all-zero")
	}
}

// TestKeystreamArmsStatisticalSmoke runs the coarse bit-balance and
// byte-histogram smoke over every installed keystream arm at 1 MiB.
func TestKeystreamArmsStatisticalSmoke(t *testing.T) {
	const size = 1 << 20
	const halfBits = size * 8 / 2
	tol := halfBits / 200
	for _, name := range hashes.KeystreamNames() {
		buf := make([]byte, size)
		if err := drbg.FillWith(name, buf); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var popcount int
		var hist [256]int
		for _, b := range buf {
			hist[b]++
			for x := b; x != 0; x >>= 1 {
				popcount += int(x & 1)
			}
		}
		diff := popcount - halfBits
		if diff < 0 {
			diff = -diff
		}
		if diff > tol {
			t.Errorf("%s: population count %d off half=%d by %d (tol %d)", name, popcount, halfBits, diff, tol)
		}
		for v, c := range hist {
			if c > 2*(size/256) {
				t.Errorf("%s: byte value %d occurs %d times (expected ~%d)", name, v, c, size/256)
			}
		}
	}
}

// BenchmarkArmsParallel3 times every arm under the container-fill
// three-goroutine shape with the keystream arms installed; reports
// aggregate MB/s.
func BenchmarkArmsParallel3(b *testing.B) {
	for _, name := range append([]string{""}, drbg.Names()...) {
		label := name
		if label == "" {
			label = "auto"
		}
		for _, size := range []int{3 << 20, 18 << 20} {
			size := size
			buf := make([]byte, size)
			b.Run(label+"/"+itoaMB(size), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(size))
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					third := size / 3
					var wg sync.WaitGroup
					wg.Add(3)
					go func() { _ = drbg.FillWith(name, buf[0:third]); wg.Done() }()
					go func() { _ = drbg.FillWith(name, buf[third:2*third]); wg.Done() }()
					go func() { _ = drbg.FillWith(name, buf[2*third:size]); wg.Done() }()
					wg.Wait()
				}
			})
		}
	}
}

func itoaMB(n int) string {
	mb := n >> 20
	if mb == 0 {
		return "0MB"
	}
	var d [8]byte
	i := len(d)
	for mb > 0 {
		i--
		d[i] = byte('0' + mb%10)
		mb /= 10
	}
	return string(d[i:]) + "MB"
}
