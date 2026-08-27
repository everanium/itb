//go:build amd64 && !purego && !noitbasm

package siphashasm

import (
	"crypto/rand"
	"testing"

	"golang.org/x/sys/cpu"
)

// The AVX2 chain-absorb kernels are called DIRECTLY (bypassing dispatch)
// so they run even on the maintainer's AVX-512 hosts. Only AVX2 is
// required.

func runSipAvx2Parity(
	t *testing.T,
	dataLen, trials int,
	kernel func(*[4][2]uint64, *[4]*byte, *[4][2]uint64),
) {
	t.Helper()
	if !cpu.X86.HasAVX2 {
		t.Skip("requires AVX2")
	}
	for trial := 0; trial < trials; trial++ {
		var seeds [4][2]uint64
		var sb [64]byte
		if _, err := rand.Read(sb[:]); err != nil {
			t.Fatal(err)
		}
		for lane := 0; lane < 4; lane++ {
			seeds[lane][0] = leU64(sb[lane*16:])
			seeds[lane][1] = leU64(sb[lane*16+8:])
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
		var want [4][2]uint64
		for lane := 0; lane < 4; lane++ {
			lo, hi := runReferenceClosure128(laneData[lane], seeds[lane][0], seeds[lane][1])
			want[lane][0], want[lane][1] = lo, hi
		}
		var got [4][2]uint64
		kernel(&seeds, &ptrs, &got)
		if got != want {
			t.Fatalf("dataLen=%d trial=%d mismatch\n got:  %v\n want: %v", dataLen, trial, got, want)
		}
	}
}

func TestSipHash24Chain128Absorb13x4Avx2_Parity(t *testing.T) {
	runSipAvx2Parity(t, 13, 200, sipHash24Chain128Absorb13x4Avx2Asm)
}
func TestSipHash24Chain128Absorb20x4Avx2_Parity(t *testing.T) {
	runSipAvx2Parity(t, 20, 200, sipHash24Chain128Absorb20x4Avx2Asm)
}
func TestSipHash24Chain128Absorb36x4Avx2_Parity(t *testing.T) {
	runSipAvx2Parity(t, 36, 200, sipHash24Chain128Absorb36x4Avx2Asm)
}
func TestSipHash24Chain128Absorb68x4Avx2_Parity(t *testing.T) {
	runSipAvx2Parity(t, 68, 200, sipHash24Chain128Absorb68x4Avx2Asm)
}

// TestSipHashChainAbsorbAvx2_MatchesAVX512 cross-checks against the
// AVX-512 kernels on dual-capable hosts.
func TestSipHashChainAbsorbAvx2_MatchesAVX512(t *testing.T) {
	if !cpu.X86.HasAVX2 || !HasAVX512Fused {
		t.Skip("requires AVX2 and AVX-512F")
	}
	widths := []struct {
		n     int
		avx2  func(*[4][2]uint64, *[4]*byte, *[4][2]uint64)
		av512 func(*[4][2]uint64, *[4]*byte, *[4][2]uint64)
	}{
		{13, sipHash24Chain128Absorb13x4Avx2Asm, sipHash24Chain128Absorb13x4Asm},
		{20, sipHash24Chain128Absorb20x4Avx2Asm, sipHash24Chain128Absorb20x4Asm},
		{36, sipHash24Chain128Absorb36x4Avx2Asm, sipHash24Chain128Absorb36x4Asm},
		{68, sipHash24Chain128Absorb68x4Avx2Asm, sipHash24Chain128Absorb68x4Asm},
	}
	for _, w := range widths {
		for trial := 0; trial < 64; trial++ {
			var seeds [4][2]uint64
			var sb [64]byte
			if _, err := rand.Read(sb[:]); err != nil {
				t.Fatal(err)
			}
			for lane := 0; lane < 4; lane++ {
				seeds[lane][0] = leU64(sb[lane*16:])
				seeds[lane][1] = leU64(sb[lane*16+8:])
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
			var g2, g5 [4][2]uint64
			w.avx2(&seeds, &ptrs, &g2)
			w.av512(&seeds, &ptrs, &g5)
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

// TestDispatcher_SipAvx2PathSelected — dispatch-selection guard.
func TestDispatcher_SipAvx2PathSelected(t *testing.T) {
	if !cpu.X86.HasAVX2 {
		t.Skip("requires AVX2")
	}
	sv, sa := HasAVX512Fused, HasAVX2Fused
	HasAVX512Fused, HasAVX2Fused = false, true
	t.Cleanup(func() { HasAVX512Fused, HasAVX2Fused = sv, sa })

	cases := []struct {
		n        int
		dispatch func(*[4][2]uint64, *[4]*byte, *[4][2]uint64)
		direct   func(*[4][2]uint64, *[4]*byte, *[4][2]uint64)
	}{
		{13, SipHash24Chain128Absorb13x4, sipHash24Chain128Absorb13x4Avx2Asm},
		{20, SipHash24Chain128Absorb20x4, sipHash24Chain128Absorb20x4Avx2Asm},
		{36, SipHash24Chain128Absorb36x4, sipHash24Chain128Absorb36x4Avx2Asm},
		{68, SipHash24Chain128Absorb68x4, sipHash24Chain128Absorb68x4Avx2Asm},
	}
	var seeds [4][2]uint64
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
		var viaDispatch, viaDirect [4][2]uint64
		c.dispatch(&seeds, &ptrs, &viaDispatch)
		c.direct(&seeds, &ptrs, &viaDirect)
		if viaDispatch != viaDirect {
			t.Fatalf("len=%d: dispatcher %v != direct AVX2 %v", c.n, viaDispatch, viaDirect)
		}
	}
}

func benchSipKernel(b *testing.B, k func(*[4][2]uint64, *[4]*byte, *[4][2]uint64)) {
	var seeds [4][2]uint64
	bufs := make([][]byte, 4)
	var ptrs [4]*byte
	for lane := 0; lane < 4; lane++ {
		bufs[lane] = make([]byte, 20)
		ptrs[lane] = &bufs[lane][0]
	}
	var out [4][2]uint64
	b.SetBytes(4 * 20)
	for i := 0; i < b.N; i++ {
		k(&seeds, &ptrs, &out)
	}
}
func BenchmarkSipHash_20x4_Scalar(b *testing.B) { benchSipKernel(b, scalarBatch128ChainAbsorb20) }
func BenchmarkSipHash_20x4_Avx2(b *testing.B) {
	if !cpu.X86.HasAVX2 {
		b.Skip()
	}
	benchSipKernel(b, sipHash24Chain128Absorb20x4Avx2Asm)
}
func BenchmarkSipHash_20x4_Avx512(b *testing.B) {
	if !HasAVX512Fused {
		b.Skip()
	}
	benchSipKernel(b, sipHash24Chain128Absorb20x4Asm)
}
