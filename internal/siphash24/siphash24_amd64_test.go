//go:build amd64 && !purego && !noitbasm

package siphash24

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"testing"

	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

//go:noescape
func dumpSIMDRegs(dst *[88]uint64, avx512 bool)

//go:noescape
func dirtySIMDRegForTest(masked uint64)

func init() {
	dumpSIMDRegsHook = func(dst *[88]uint64) {
		dumpSIMDRegs(dst, cpuid.AVX512F && cpuid.AVX512VL)
	}
	dirtySIMDRegHook = dirtySIMDRegForTest
}

func TestSipHash24AsmTiersDirectAmd64(t *testing.T) {
	k0 := uint64(0x0706050403020100)
	k1 := uint64(0x0f0e0d0c0b0a0908)
	nonceHi := uint64(0x2122232425262728)
	nonceLo := uint64(0x3132333435363738)
	var vInit [4]uint64
	InitCTRState(&vInit, k0, k1, nonceHi)

	counters := []uint64{0, 1, 7, 42, 0xfffffffffffffffe, 0xffffffffffffffff}
	for _, ctr := range counters {
		for nBlocks := 1; nBlocks <= 35; nBlocks++ {
			n := nBlocks * Size128
			src := make([]byte, n+8)[3 : 3+n]
			for i := range src {
				src[i] = byte(i*31 + 7)
			}
			want := make([]byte, n)
			scalarXORKeyStreamBlocksWithState(want, src, &vInit, nonceLo, ctr)

			if cpuid.AVX2 {
				gotAVX2 := make([]byte, n+8)[1 : 1+n]
				siphashXORBlocksAvx2Asm(&vInit, nonceLo, ctr, &gotAVX2[0], &src[0], nBlocks)
				if !bytes.Equal(gotAVX2, want) {
					t.Fatalf("AVX2 CTR mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
				}
				// In-place test.
				inPlaceAVX2 := append([]byte(nil), src...)
				siphashXORBlocksAvx2Asm(&vInit, nonceLo, ctr, &inPlaceAVX2[0], &inPlaceAVX2[0], nBlocks)
				if !bytes.Equal(inPlaceAVX2, want) {
					t.Fatalf("AVX2 in-place CTR mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
				}
			}
			if cpuid.AVX512F && cpuid.AVX512VL {
				gotAVX512 := make([]byte, n+8)[5 : 5+n]
				siphashXORBlocksAvx512Asm(&vInit, nonceLo, ctr, &gotAVX512[0], &src[0], nBlocks)
				if !bytes.Equal(gotAVX512, want) {
					t.Fatalf("AVX512 CTR mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
				}
				// In-place test.
				inPlaceAVX512 := append([]byte(nil), src...)
				siphashXORBlocksAvx512Asm(&vInit, nonceLo, ctr, &inPlaceAVX512[0], &inPlaceAVX512[0], nBlocks)
				if !bytes.Equal(inPlaceAVX512, want) {
					t.Fatalf("AVX512 in-place CTR mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
				}
			}
		}
	}

	// Direct Sum128x4 tier tests across lengths 0..68.
	for msgLen := 0; msgLen <= 68; msgLen++ {
		var in [4][]byte
		var want [4][16]byte
		for lane := 0; lane < 4; lane++ {
			buf := make([]byte, msgLen+8)[lane+1 : lane+1+msgLen]
			for i := range buf {
				buf[i] = byte(i*23 + lane*41 + msgLen)
			}
			in[lane] = buf
			Sum128Into(want[lane][:], k0, k1, buf)
		}

		if cpuid.AVX2 {
			var gotBuf [4][16]byte
			dst := [4][]byte{gotBuf[0][:], gotBuf[1][:], gotBuf[2][:], gotBuf[3][:]}
			siphashSum128x4Avx2Asm(&dst, &in, k0, k1, msgLen)
			for lane := 0; lane < 4; lane++ {
				if gotBuf[lane] != want[lane] {
					t.Fatalf("AVX2 Sum128x4 mismatch at len=%d lane=%d: got %x, want %x",
						msgLen, lane, gotBuf[lane], want[lane])
				}
			}
		}
		if cpuid.AVX512F && cpuid.AVX512VL {
			var gotBuf [4][16]byte
			dst := [4][]byte{gotBuf[0][:], gotBuf[1][:], gotBuf[2][:], gotBuf[3][:]}
			siphashSum128x4Avx512Asm(&dst, &in, k0, k1, msgLen)
			for lane := 0; lane < 4; lane++ {
				if gotBuf[lane] != want[lane] {
					t.Fatalf("AVX512 Sum128x4 mismatch at len=%d lane=%d: got %x, want %x",
						msgLen, lane, gotBuf[lane], want[lane])
				}
			}
		}
	}
}

func TestForceHashTierAppliedAmd64(t *testing.T) {
	tier := forcetier.HashTier()
	switch tier {
	case "":
		t.Skip("ITB_FORCE_HASH_TIER unset; auto-dispatch")
	case "avx512":
		if !cpuid.AVX512F || !cpuid.AVX512VL {
			t.Skip("avx512 tier not executable on this host")
		}
		if !HasAVX512 || HasAVX2 {
			t.Fatalf("avx512: HasAVX512=%v HasAVX2=%v, want true/false", HasAVX512, HasAVX2)
		}
	case "avx2", "vex":
		if !cpuid.AVX2 {
			t.Skipf("%s tier not executable on this host", tier)
		}
		if HasAVX512 || !HasAVX2 {
			t.Fatalf("%s: HasAVX512=%v HasAVX2=%v, want false/true", tier, HasAVX512, HasAVX2)
		}
	case "gpr", "scalar":
		if HasAVX512 || HasAVX2 {
			t.Fatalf("%s: HasAVX512=%v HasAVX2=%v, want false/false", tier, HasAVX512, HasAVX2)
		}
	}
}

func TestKernelsLeaveNoSecretInFrameAndRegsAmd64(t *testing.T) {
	checkResidueNegativeControls(t)
	const (
		k0      = uint64(0xdeadbeefcafebabe)
		k1      = uint64(0x0123456789abcdef)
		nonceHi = uint64(0xfedcba9876543210)
		nonceLo = uint64(0x4b5a69780f1e2d3c)
	)
	var vInit [4]uint64
	InitCTRState(&vInit, k0, k1, nonceHi)
	secrets := makeSipHashSecrets(k0, k1, nonceHi, nonceLo, &vInit)

	src := make([]byte, 15*Size128)
	dst := make([]byte, 15*Size128)
	var batchInBuf [4][24]byte
	var batchDstBuf [4][16]byte
	for lane := 0; lane < 4; lane++ {
		binary.LittleEndian.PutUint64(batchInBuf[lane][0:8], nonceHi)
		binary.LittleEndian.PutUint64(batchInBuf[lane][8:16], nonceLo)
		binary.LittleEndian.PutUint64(batchInBuf[lane][16:24], uint64(lane+1))
	}
	batchIn := [4][]byte{batchInBuf[0][:], batchInBuf[1][:], batchInBuf[2][:], batchInBuf[3][:]}
	batchDst := [4][]byte{batchDstBuf[0][:], batchDstBuf[1][:], batchDstBuf[2][:], batchDstBuf[3][:]}

	if cpuid.AVX2 {
		for _, blks := range []int{1, 3, 4, 7, 8, 15} {
			b := blks
			res := stackResidue(func() {
				siphashXORBlocksAvx2Asm(&vInit, nonceLo, 1, &dst[0], &src[0], b)
			})
			assertNoSecretResidue(t, fmt.Sprintf("siphashXORBlocksAvx2Asm(blocks=%d)", b), res, secrets)
		}
		resSum4 := stackResidue(func() {
			siphashSum128x4Avx2Asm(&batchDst, &batchIn, k0, k1, 24)
		})
		assertNoSecretResidue(t, "siphashSum128x4Avx2Asm(24)", resSum4, secrets)
	}
	if cpuid.AVX512F && cpuid.AVX512VL {
		for _, blks := range []int{1, 3, 4, 7, 8, 15} {
			b := blks
			res := stackResidue(func() {
				siphashXORBlocksAvx512Asm(&vInit, nonceLo, 1, &dst[0], &src[0], b)
			})
			assertNoSecretResidue(t, fmt.Sprintf("siphashXORBlocksAvx512Asm(blocks=%d)", b), res, secrets)
		}
		resSum4 := stackResidue(func() {
			siphashSum128x4Avx512Asm(&batchDst, &batchIn, k0, k1, 24)
		})
		assertNoSecretResidue(t, "siphashSum128x4Avx512Asm(24)", resSum4, secrets)
	}
	runtime.KeepAlive(&vInit)
	runtime.KeepAlive(&batchIn)
	runtime.KeepAlive(&batchDst)
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
}
