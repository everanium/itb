//go:build arm64 && !purego && !noitbasm

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
		dumpSIMDRegs(dst, false)
	}
	dirtySIMDRegHook = dirtySIMDRegForTest
}

func TestSipHash24AsmTiersDirectArm64(t *testing.T) {
	if !cpuid.ASIMD {
		t.Skip("ASIMD not available")
	}
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

			gotNEON := make([]byte, n+8)[1 : 1+n]
			siphashXORBlocksNEONAsm(&vInit, nonceLo, ctr, &gotNEON[0], &src[0], nBlocks)
			if !bytes.Equal(gotNEON, want) {
				t.Fatalf("NEON CTR mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}
			inPlaceNEON := append([]byte(nil), src...)
			siphashXORBlocksNEONAsm(&vInit, nonceLo, ctr, &inPlaceNEON[0], &inPlaceNEON[0], nBlocks)
			if !bytes.Equal(inPlaceNEON, want) {
				t.Fatalf("NEON in-place CTR mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}
		}
	}

	// Direct Sum128x4 NEON tests across lengths 0..68.
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

		var gotBuf [4][16]byte
		dst := [4][]byte{gotBuf[0][:], gotBuf[1][:], gotBuf[2][:], gotBuf[3][:]}
		siphashSum128x4NEONAsm(&dst, &in, k0, k1, msgLen)
		for lane := 0; lane < 4; lane++ {
			if gotBuf[lane] != want[lane] {
				t.Fatalf("NEON Sum128x4 mismatch at len=%d lane=%d: got %x, want %x",
					msgLen, lane, gotBuf[lane], want[lane])
			}
		}
	}
}

func TestForceHashTierAppliedArm64(t *testing.T) {
	tier := forcetier.HashTier()
	switch tier {
	case "":
		t.Skip("ITB_FORCE_HASH_TIER unset; auto-dispatch")
	case "neon", "sve2", "sve":
		if !cpuid.ASIMD {
			t.Skipf("%s tier not executable on this host", tier)
		}
		if !HasNEON {
			t.Fatalf("%s: HasNEON=false, want true", tier)
		}
	case "gpr", "scalar":
		if HasNEON {
			t.Fatalf("%s: HasNEON=true, want false", tier)
		}
	}
}

func TestKernelsLeaveNoSecretInFrameAndRegsArm64(t *testing.T) {
	if !cpuid.ASIMD {
		t.Skip("ASIMD not available")
	}
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

	for _, blks := range []int{1, 2, 3, 4, 7, 8, 15} {
		b := blks
		res := stackResidue(func() {
			siphashXORBlocksNEONAsm(&vInit, nonceLo, 1, &dst[0], &src[0], b)
		})
		assertNoSecretResidue(t, fmt.Sprintf("siphashXORBlocksNEONAsm(blocks=%d)", b), res, secrets)
	}
	resSum4 := stackResidue(func() {
		siphashSum128x4NEONAsm(&batchDst, &batchIn, k0, k1, 24)
	})
	assertNoSecretResidue(t, "siphashSum128x4NEONAsm(24)", resSum4, secrets)

	runtime.KeepAlive(&vInit)
	runtime.KeepAlive(&batchIn)
	runtime.KeepAlive(&batchDst)
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
}
