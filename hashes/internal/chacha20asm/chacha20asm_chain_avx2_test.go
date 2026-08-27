//go:build amd64 && !purego && !noitbasm

package chacha20asm

import (
	"crypto/rand"
	"testing"

	"golang.org/x/sys/cpu"
)

// The AVX2 chain-absorb kernels are called DIRECTLY here (bypassing
// dispatch) so they are exercised even on the maintainer's AVX-512
// hosts where the dispatcher would select the AVX-512 tier. The only
// host requirement is AVX2; every campaign-fleet CPU satisfies it.

func runChaCha20Avx2Parity(
	t *testing.T,
	dataLen, trials int,
	kernel func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64),
) {
	t.Helper()
	if !cpu.X86.HasAVX2 {
		t.Skip("requires AVX2")
	}
	for trial := 0; trial < trials; trial++ {
		var fixedKey [32]byte
		if _, err := rand.Read(fixedKey[:]); err != nil {
			t.Fatal(err)
		}
		var seeds [4][4]uint64
		var sb [128]byte
		if _, err := rand.Read(sb[:]); err != nil {
			t.Fatal(err)
		}
		for lane := 0; lane < 4; lane++ {
			for i := 0; i < 4; i++ {
				seeds[lane][i] = leU64(sb[lane*32+i*8:])
			}
		}
		laneData := make([][]byte, 4)
		var ptrs [4]*byte
		for lane := 0; lane < 4; lane++ {
			laneData[lane] = make([]byte, dataLen)
			if _, err := rand.Read(laneData[lane]); err != nil {
				t.Fatal(err)
			}
			ptrs[lane] = &laneData[lane][0]
		}
		var want [4][4]uint64
		for lane := 0; lane < 4; lane++ {
			want[lane] = runReferenceClosure256(fixedKey, laneData[lane], seeds[lane])
		}
		var got [4][4]uint64
		kernel(&fixedKey, &seeds, &ptrs, &got)
		if got != want {
			t.Fatalf("dataLen=%d trial=%d mismatch\n got:  %v\n want: %v", dataLen, trial, got, want)
		}
	}
}

func TestChaCha20256ChainAbsorb13x4Avx2_Parity(t *testing.T) {
	runChaCha20Avx2Parity(t, 13, 200, chaCha20256ChainAbsorb13x4Avx2Asm)
}
func TestChaCha20256ChainAbsorb20x4Avx2_Parity(t *testing.T) {
	runChaCha20Avx2Parity(t, 20, 200, chaCha20256ChainAbsorb20x4Avx2Asm)
}
func TestChaCha20256ChainAbsorb36x4Avx2_Parity(t *testing.T) {
	runChaCha20Avx2Parity(t, 36, 200, chaCha20256ChainAbsorb36x4Avx2Asm)
}
func TestChaCha20256ChainAbsorb68x4Avx2_Parity(t *testing.T) {
	runChaCha20Avx2Parity(t, 68, 200, chaCha20256ChainAbsorb68x4Avx2Asm)
}

// TestChaCha20ChainAbsorbAvx2_MatchesAVX512 cross-checks the AVX2
// kernels against the AVX-512 kernels on hosts carrying both.
func TestChaCha20ChainAbsorbAvx2_MatchesAVX512(t *testing.T) {
	if !cpu.X86.HasAVX2 || !HasAVX512Fused {
		t.Skip("requires AVX2 and AVX-512F")
	}
	widths := []struct {
		n     int
		avx2  func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64)
		av512 func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64)
	}{
		{13, chaCha20256ChainAbsorb13x4Avx2Asm, chaCha20256ChainAbsorb13x4Asm},
		{20, chaCha20256ChainAbsorb20x4Avx2Asm, chaCha20256ChainAbsorb20x4Asm},
		{36, chaCha20256ChainAbsorb36x4Avx2Asm, chaCha20256ChainAbsorb36x4Asm},
		{68, chaCha20256ChainAbsorb68x4Avx2Asm, chaCha20256ChainAbsorb68x4Asm},
	}
	for _, w := range widths {
		for trial := 0; trial < 64; trial++ {
			var fixedKey [32]byte
			if _, err := rand.Read(fixedKey[:]); err != nil {
				t.Fatal(err)
			}
			var seeds [4][4]uint64
			var sb [128]byte
			if _, err := rand.Read(sb[:]); err != nil {
				t.Fatal(err)
			}
			for lane := 0; lane < 4; lane++ {
				for i := 0; i < 4; i++ {
					seeds[lane][i] = leU64(sb[lane*32+i*8:])
				}
			}
			laneData := make([][]byte, 4)
			var ptrs [4]*byte
			for lane := 0; lane < 4; lane++ {
				laneData[lane] = make([]byte, w.n)
				if _, err := rand.Read(laneData[lane]); err != nil {
					t.Fatal(err)
				}
				ptrs[lane] = &laneData[lane][0]
			}
			var g2, g5 [4][4]uint64
			w.avx2(&fixedKey, &seeds, &ptrs, &g2)
			w.av512(&fixedKey, &seeds, &ptrs, &g5)
			if g2 != g5 {
				t.Fatalf("width %d trial %d: AVX2 %v != AVX-512 %v", w.n, trial, g2, g5)
			}
		}
	}
}

func leU64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

// TestDispatcher_ChaChaAvx2PathSelected is the dispatch-selection guard
// (playbook §10.6): with HasAVX512Fused forced false and HasAVX2Fused
// forced true, the public dispatcher must route to the AVX2 kernel.
func TestDispatcher_ChaChaAvx2PathSelected(t *testing.T) {
	if !cpu.X86.HasAVX2 {
		t.Skip("requires AVX2")
	}
	sv, sa := HasAVX512Fused, HasAVX2Fused
	HasAVX512Fused, HasAVX2Fused = false, true
	t.Cleanup(func() { HasAVX512Fused, HasAVX2Fused = sv, sa })

	cases := []struct {
		n        int
		dispatch func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64)
		direct   func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64)
	}{
		{13, ChaCha20256ChainAbsorb13x4, chaCha20256ChainAbsorb13x4Avx2Asm},
		{20, ChaCha20256ChainAbsorb20x4, chaCha20256ChainAbsorb20x4Avx2Asm},
		{36, ChaCha20256ChainAbsorb36x4, chaCha20256ChainAbsorb36x4Avx2Asm},
		{68, ChaCha20256ChainAbsorb68x4, chaCha20256ChainAbsorb68x4Avx2Asm},
	}
	var fixedKey [32]byte
	var seeds [4][4]uint64
	for _, c := range cases {
		bufs := make([][]byte, 4)
		var ptrs [4]*byte
		for lane := 0; lane < 4; lane++ {
			bufs[lane] = make([]byte, c.n)
			for i := range bufs[lane] {
				bufs[lane][i] = byte(i + lane*7 + 1)
			}
			ptrs[lane] = &bufs[lane][0]
		}
		var viaDispatch, viaDirect [4][4]uint64
		c.dispatch(&fixedKey, &seeds, &ptrs, &viaDispatch)
		c.direct(&fixedKey, &seeds, &ptrs, &viaDirect)
		if viaDispatch != viaDirect {
			t.Fatalf("len=%d: dispatcher %v != direct AVX2 %v", c.n, viaDispatch, viaDirect)
		}
	}
}

// Kernel-level throughput: AVX2 vs AVX-512 vs scalar batch, per
// 4-pixel-batch at the 20-byte default width.
func benchChaChaKernel(b *testing.B, k func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64)) {
	var fixedKey [32]byte
	var seeds [4][4]uint64
	bufs := make([][]byte, 4)
	var ptrs [4]*byte
	for lane := 0; lane < 4; lane++ {
		bufs[lane] = make([]byte, 20)
		ptrs[lane] = &bufs[lane][0]
	}
	var out [4][4]uint64
	b.SetBytes(4 * 20)
	for i := 0; i < b.N; i++ {
		k(&fixedKey, &seeds, &ptrs, &out)
	}
}
func BenchmarkChaCha20_20x4_Scalar(b *testing.B) {
	benchChaChaKernel(b, func(fk *[32]byte, s *[4][4]uint64, d *[4]*byte, o *[4][4]uint64) {
		scalarBatch256ChainAbsorb20(fk, s, d, o)
	})
}
func BenchmarkChaCha20_20x4_Avx2(b *testing.B) {
	if !cpu.X86.HasAVX2 {
		b.Skip()
	}
	benchChaChaKernel(b, chaCha20256ChainAbsorb20x4Avx2Asm)
}
func BenchmarkChaCha20_20x4_Avx512(b *testing.B) {
	if !HasAVX512Fused {
		b.Skip()
	}
	benchChaChaKernel(b, chaCha20256ChainAbsorb20x4Asm)
}
func BenchmarkChaCha20_68x4_Avx2(b *testing.B) {
	if !cpu.X86.HasAVX2 {
		b.Skip()
	}
	var fixedKey [32]byte
	var seeds [4][4]uint64
	bufs := make([][]byte, 4)
	var ptrs [4]*byte
	for lane := 0; lane < 4; lane++ {
		bufs[lane] = make([]byte, 68)
		ptrs[lane] = &bufs[lane][0]
	}
	var out [4][4]uint64
	b.SetBytes(4 * 68)
	for i := 0; i < b.N; i++ {
		chaCha20256ChainAbsorb68x4Avx2Asm(&fixedKey, &seeds, &ptrs, &out)
	}
}
func BenchmarkChaCha20_68x4_Scalar(b *testing.B) {
	var fixedKey [32]byte
	var seeds [4][4]uint64
	bufs := make([][]byte, 4)
	var ptrs [4]*byte
	for lane := 0; lane < 4; lane++ {
		bufs[lane] = make([]byte, 68)
		ptrs[lane] = &bufs[lane][0]
	}
	var out [4][4]uint64
	b.SetBytes(4 * 68)
	for i := 0; i < b.N; i++ {
		scalarBatch256ChainAbsorb68(&fixedKey, &seeds, &ptrs, &out)
	}
}
