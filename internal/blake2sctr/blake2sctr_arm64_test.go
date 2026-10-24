//go:build arm64 && !purego && !noitbasm

package blake2sctr

import (
	"bytes"
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

func TestBlake2sAsmTiersDirectArm64(t *testing.T) {
	if !cpuid.ASIMD {
		t.Skip("ASIMD not available")
	}
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(0x03 + i*5)
	}
	var hKey, keyWords [8]uint32
	InitKey(key, &hKey, &keyWords)
	nonce := [4]uint32{0x09000000, 0x4a000000, 0x11223344, 0x55667788}

	counters := []uint64{0, 1, 19, 1000, 0xfffffffe, 0xffffffff, 0xfffffffffffffffe}
	for _, ctr := range counters {
		for nBlocks := 1; nBlocks <= 25; nBlocks++ {
			n := nBlocks * BlockSize
			src := make([]byte, n)
			for i := range src {
				src[i] = byte(i*31 + 7)
			}
			want := make([]byte, n)
			scalarXORKeyStreamBlocks(want, src, &hKey, &nonce, ctr)

			gotNEON := make([]byte, n)
			blake2sXORBlocksNeonAsm(&hKey, &nonce, ctr, &gotNEON[0], &src[0], nBlocks)
			if !bytes.Equal(gotNEON, want) {
				t.Fatalf("NEON XOR mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
			}
		}
	}

	for _, commonLen := range []int{1, 13, 16, 20, 24, 32, 36, 48, 63, 64} {
		var in, wantDst [4][]byte
		var inStore [4][64]byte
		var wantStore [4][32]byte
		for lane := 0; lane < 4; lane++ {
			for i := 0; i < commonLen; i++ {
				inStore[lane][i] = byte(i*23 + lane*41 + commonLen)
			}
			in[lane] = inStore[lane][:commonLen]
			wantDst[lane] = wantStore[lane][:]
		}
		scalarBatchPRFx4(&wantDst, &in, &hKey, &keyWords)

		var gotStore [4][32]byte
		outPtrs := [4]*byte{&gotStore[0][0], &gotStore[1][0], &gotStore[2][0], &gotStore[3][0]}
		if commonLen == 24 {
			ptrs := [8]*byte{
				&in[0][0], &in[1][0], &in[2][0], &in[3][0],
				&gotStore[0][0], &gotStore[1][0], &gotStore[2][0], &gotStore[3][0],
			}
			blake2sBatch24x4NeonAsm(&hKey, &ptrs)
			for lane := 0; lane < 4; lane++ {
				if gotStore[lane] != wantStore[lane] {
					t.Fatalf("NEON Batch24x4 lane %d mismatch", lane)
				}
			}
		}
		var m [16][4]uint32
		transposeMsg4x(&m, &in, commonLen)
		blake2sCompress4xNeonAsm(&hKey, &m, uint32(64+commonLen), &outPtrs)
		for lane := 0; lane < 4; lane++ {
			if gotStore[lane] != wantStore[lane] {
				t.Fatalf("NEON Compress4x len=%d lane=%d mismatch", commonLen, lane)
			}
		}
	}
}

func TestForceHashTierApplied(t *testing.T) {
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
	keyBytes := [32]byte{
		0xef, 0xbe, 0xad, 0xde, 0xbe, 0xba, 0xfe, 0xca,
		0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89,
		0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76,
		0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
	}
	var hKey, keyWords [8]uint32
	InitKey(keyBytes[:], &hKey, &keyWords)
	nonce := [4]uint32{0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff11}
	secrets := makeTestSecrets(&hKey, &keyWords, &nonce)
	src := make([]byte, 15*BlockSize)
	dst := make([]byte, 15*BlockSize)

	for _, blks := range []int{1, 2, 3, 4, 7, 8, 15} {
		b := blks
		res := stackResidue(func() {
			blake2sXORBlocksNeonAsm(&hKey, &nonce, 1, &dst[0], &src[0], b)
		})
		assertNoSecretResidue(t, fmt.Sprintf("blake2sXORBlocksNeonAsm(blocks=%d)", b), res, secrets)
	}

	var in24 [4][24]byte
	var out24 [4][32]byte
	ptrs24 := [8]*byte{
		&in24[0][0], &in24[1][0], &in24[2][0], &in24[3][0],
		&out24[0][0], &out24[1][0], &out24[2][0], &out24[3][0],
	}
	resBatch24 := stackResidue(func() {
		blake2sBatch24x4NeonAsm(&hKey, &ptrs24)
	})
	assertNoSecretResidue(t, "blake2sBatch24x4NeonAsm", resBatch24, secrets)

	outPtrs := [4]*byte{&out24[0][0], &out24[1][0], &out24[2][0], &out24[3][0]}
	var m [16][4]uint32
	resComp := stackResidue(func() {
		m[0][0] = nonce[0]
		blake2sCompress4xNeonAsm(&hKey, &m, 64+32, &outPtrs)
	})
	assertNoSecretResidue(t, "blake2sCompress4xNeonAsm", resComp, secrets)

	runtime.KeepAlive(&hKey)
	runtime.KeepAlive(&keyWords)
	runtime.KeepAlive(&nonce)
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
	runtime.KeepAlive(&ptrs24)
	runtime.KeepAlive(&outPtrs)
}
