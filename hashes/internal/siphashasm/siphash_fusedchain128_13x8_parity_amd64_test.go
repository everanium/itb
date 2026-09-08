//go:build amd64 && !purego && !noitbasm

package siphashasm

import (
	"fmt"
	"testing"

	"golang.org/x/sys/cpu"
)

// siphash_fusedchain128_13x8_parity_amd64_test.go — the eight-lane fill
// kernel of the AVX2 tier: each half of a batch-16 call must equal the
// four-lane AVX2 kernels run over the Go-synthesised blocks of the same
// lanes (the previous batch-16 arm of the tier), and the two arms are
// timed against each other so the emit-and-bench record of the tier
// ladder is reproducible.

// fillX16ViaX4Avx2 is the batch-16 fill as four four-lane AVX2 kernel
// calls over Go-synthesised blocks.
func fillX16ViaX4Avx2(comps []uint64, base uint64, out *[16][2]uint64) {
	blocks := fillBlocks16(base)
	for q := 0; q < 4; q++ {
		ptrs := x16Quarter(&blocks, q)
		sipHash24FusedChain13x4Avx2Asm(&comps[0], len(comps)/2, &ptrs, x16Out(out, q))
	}
}

// fillX16ViaX8Avx2 is the batch-16 fill as two eight-lane AVX2 kernel
// calls with in-register block synthesis.
func fillX16ViaX8Avx2(comps []uint64, base uint64, out *[16][2]uint64) {
	sipHash24FusedChain13x8Avx2Asm(&comps[0], len(comps)/2, base, x16Half(out, 0))
	sipHash24FusedChain13x8Avx2Asm(&comps[0], len(comps)/2, base+8, x16Half(out, 1))
}

// TestFusedChain13x8Avx2MatchesX4 pins the eight-lane AVX2 fill kernel
// lane for lane to the four-lane AVX2 kernels at every pair count and
// probe base, including the lane-offset carries of the in-register
// synthesis.
func TestFusedChain13x8Avx2MatchesX4(t *testing.T) {
	if !cpu.X86.HasAVX2 {
		t.Skip("AVX2 not available")
	}
	for _, pairs := range fusedX16PairCounts {
		for _, tc := range fusedX16FixedCases {
			comps := fusedX16Components(tc.seed0, tc.seed1, pairs)
			for _, base := range append(tc.bases, 0xFFFFFFFFFFFFFFF8, 0x00000000FFFFFFFC) {
				var viaX4, viaX8 [16][2]uint64
				fillX16ViaX4Avx2(comps, base, &viaX4)
				fillX16ViaX8Avx2(comps, base, &viaX8)
				if viaX4 != viaX8 {
					t.Fatalf("%s pairs=%d base=%#x: eight-lane kernel %v != four-lane kernels %v", tc.name, pairs, base, viaX8, viaX4)
				}
			}
		}
	}
}

// BenchmarkFill13x8VsX4Avx2 times the batch-16 fill of the AVX2 tier
// through its eight-lane kernel (two calls) against the four-lane kernels
// (four calls over Go-synthesised blocks) at the cascade lengths of the
// 512 / 1024 / 2048-bit lockSeeds.
func BenchmarkFill13x8VsX4Avx2(b *testing.B) {
	if !cpu.X86.HasAVX2 {
		b.Skip("AVX2 not available")
	}
	for _, arm := range []struct {
		name string
		fn   fusedX16Fn
	}{{"x4", fillX16ViaX4Avx2}, {"x8", fillX16ViaX8Avx2}} {
		for _, pairs := range fusedX16PairCounts {
			b.Run(fmt.Sprintf("%s/pairs%d", arm.name, pairs), func(b *testing.B) {
				comps := fusedX16Components(0x0102030405060708, 0x090a0b0c0d0e0f00, pairs)
				var out [16][2]uint64
				b.SetBytes(16 * 13)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					arm.fn(comps, uint64(i*16), &out)
				}
			})
		}
	}
}
