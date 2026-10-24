//go:build amd64 && !purego && !noitbasm

package blake2bctr

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

func TestBlake2bAsmTiersDirectAmd64(t *testing.T) {
	var keyBytes [KeySize]byte
	for i := range keyBytes {
		keyBytes[i] = byte(0x11 + i*7)
	}
	var hKey256, hKey512 [8]uint64
	var keyBlock256, keyBlock512 [4]uint64
	InitKey256(keyBytes[:], &hKey256, &keyBlock256)
	InitKey512(keyBytes[:], &hKey512, &keyBlock512)

	nonce := [2]uint64{0x0706050403020100, 0x0f0e0d0c0b0a0908}
	counters := []uint64{0, 1, 19, 1000, 0xfffffffffffffffe, 0xffffffffffffffff}

	for _, ctr := range counters {
		for nBlocks := 1; nBlocks <= 17; nBlocks++ {
			// BLAKE2b-256 XORKeyStreamBlocks
			n256 := nBlocks * BlockSize256
			src256 := make([]byte, n256)
			for i := range src256 {
				src256[i] = byte(i*31 + 7)
			}
			want256 := make([]byte, n256)
			scalarXORKeyStreamBlocks256(want256, src256, &hKey256, &nonce, ctr)

			if cpuid.AVX2 {
				gotAVX2 := make([]byte, n256)
				blake2bXORBlocks256Avx2Asm(&hKey256, &nonce, ctr, &gotAVX2[0], &src256[0], nBlocks)
				if !bytes.Equal(gotAVX2, want256) {
					t.Fatalf("AVX2 256 XOR mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
				}
			}
			if cpuid.AVX512F && cpuid.AVX512VL {
				gotAVX512 := make([]byte, n256)
				blake2bXORBlocks256Avx512Asm(&hKey256, &nonce, ctr, &gotAVX512[0], &src256[0], nBlocks)
				if !bytes.Equal(gotAVX512, want256) {
					t.Fatalf("AVX512 256 XOR mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
				}
			}

			// BLAKE2b-512 XORKeyStreamBlocks
			n512 := nBlocks * BlockSize512
			src512 := make([]byte, n512)
			for i := range src512 {
				src512[i] = byte(i*29 + 3)
			}
			want512 := make([]byte, n512)
			scalarXORKeyStreamBlocks512(want512, src512, &hKey512, &nonce, ctr)

			if cpuid.AVX2 {
				gotAVX2 := make([]byte, n512)
				blake2bXORBlocks512Avx2Asm(&hKey512, &nonce, ctr, &gotAVX2[0], &src512[0], nBlocks)
				if !bytes.Equal(gotAVX2, want512) {
					t.Fatalf("AVX2 512 XOR mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
				}
			}
			if cpuid.AVX512F && cpuid.AVX512VL {
				gotAVX512 := make([]byte, n512)
				blake2bXORBlocks512Avx512Asm(&hKey512, &nonce, ctr, &gotAVX512[0], &src512[0], nBlocks)
				if !bytes.Equal(gotAVX512, want512) {
					t.Fatalf("AVX512 512 XOR mismatch at ctr=%#x nBlocks=%d", ctr, nBlocks)
				}
			}
		}
	}

	// Direct 24-byte BatchPRF asm comparison.
	var in24 [4][24]byte
	var in24Slices [4][]byte
	var m012 [3][4]uint64
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 24; i++ {
			in24[lane][i] = byte(lane*41 + i*13 + 5)
		}
		in24Slices[lane] = in24[lane][:]
		m012[0][lane] = binary.LittleEndian.Uint64(in24[lane][0:8])
		m012[1][lane] = binary.LittleEndian.Uint64(in24[lane][8:16])
		m012[2][lane] = binary.LittleEndian.Uint64(in24[lane][16:24])
	}
	var wantBatch256 [4][32]byte
	var wantBatch512 [4][64]byte
	var wantSlices256, wantSlices512 [4][]byte
	for lane := 0; lane < 4; lane++ {
		wantSlices256[lane] = wantBatch256[lane][:]
		wantSlices512[lane] = wantBatch512[lane][:]
	}
	scalarBatchPRF256x4(&wantSlices256, &in24Slices, &hKey256, &keyBlock256)
	scalarBatchPRF512x4(&wantSlices512, &in24Slices, &hKey512, &keyBlock512)

	if cpuid.AVX2 {
		var got256 [4][32]byte
		dstPtrs256 := [4]*byte{&got256[0][0], &got256[1][0], &got256[2][0], &got256[3][0]}
		blake2bBatch24_256Avx2Asm(&hKey256, &m012, &dstPtrs256)
		for lane := 0; lane < 4; lane++ {
			if got256[lane] != wantBatch256[lane] {
				t.Fatalf("AVX2 Batch24_256 mismatch on lane %d", lane)
			}
		}
		var got512 [4][64]byte
		dstPtrs512 := [4]*byte{&got512[0][0], &got512[1][0], &got512[2][0], &got512[3][0]}
		blake2bBatch24_512Avx2Asm(&hKey512, &m012, &dstPtrs512)
		for lane := 0; lane < 4; lane++ {
			if got512[lane] != wantBatch512[lane] {
				t.Fatalf("AVX2 Batch24_512 mismatch on lane %d", lane)
			}
		}
	}
	if cpuid.AVX512F && cpuid.AVX512VL {
		var got256 [4][32]byte
		dstPtrs256 := [4]*byte{&got256[0][0], &got256[1][0], &got256[2][0], &got256[3][0]}
		blake2bBatch24_256Avx512Asm(&hKey256, &m012, &dstPtrs256)
		for lane := 0; lane < 4; lane++ {
			if got256[lane] != wantBatch256[lane] {
				t.Fatalf("AVX512 Batch24_256 mismatch on lane %d", lane)
			}
		}
		var got512 [4][64]byte
		dstPtrs512 := [4]*byte{&got512[0][0], &got512[1][0], &got512[2][0], &got512[3][0]}
		blake2bBatch24_512Avx512Asm(&hKey512, &m012, &dstPtrs512)
		for lane := 0; lane < 4; lane++ {
			if got512[lane] != wantBatch512[lane] {
				t.Fatalf("AVX512 Batch24_512 mismatch on lane %d", lane)
			}
		}
	}
}

func TestForceHashTierApplied(t *testing.T) {
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

func TestAsmKernelsLeaveNoSecretInFrameAndRegsAmd64(t *testing.T) {
	checkResidueNegativeControls(t)
	var keyBytes [KeySize]byte
	keyWords := [4]uint64{
		0xdeadbeefcafebabe,
		0x0123456789abcdef,
		0xfedcba9876543210,
		0x4b5a69780f1e2d3c,
	}
	for i, w := range keyWords {
		binary.LittleEndian.PutUint64(keyBytes[i*8:], w)
	}
	var hKey256, hKey512 [8]uint64
	var keyBlock256, keyBlock512 [4]uint64
	InitKey256(keyBytes[:], &hKey256, &keyBlock256)
	InitKey512(keyBytes[:], &hKey512, &keyBlock512)
	nonce := [2]uint64{0x1122334455667788, 0x99aabbccddeeff00}
	secrets := makeTestSecrets(&keyBlock256, &hKey256, &hKey512, &nonce)

	src256 := make([]byte, 8*BlockSize256)
	dst256 := make([]byte, 8*BlockSize256)
	src512 := make([]byte, 8*BlockSize512)
	dst512 := make([]byte, 8*BlockSize512)

	var m012 [3][4]uint64
	for lane := 0; lane < 4; lane++ {
		m012[0][lane] = nonce[0]
		m012[1][lane] = nonce[1]
		m012[2][lane] = uint64(lane)
	}
	var out256 [4][32]byte
	var out512 [4][64]byte
	dstPtrs256 := [4]*byte{&out256[0][0], &out256[1][0], &out256[2][0], &out256[3][0]}
	dstPtrs512 := [4]*byte{&out512[0][0], &out512[1][0], &out512[2][0], &out512[3][0]}
	var hSoA [8][4]uint64
	var mSoA [16][4]uint64

	if cpuid.AVX2 {
		for _, blks := range []int{1, 3, 4, 7} {
			b := blks
			res256 := stackResidue(func() {
				blake2bXORBlocks256Avx2Asm(&hKey256, &nonce, 1, &dst256[0], &src256[0], b)
			})
			assertNoSecretResidue(t, fmt.Sprintf("blake2bXORBlocks256Avx2Asm(blocks=%d)", b), res256, secrets)

			res512 := stackResidue(func() {
				blake2bXORBlocks512Avx2Asm(&hKey512, &nonce, 1, &dst512[0], &src512[0], b)
			})
			assertNoSecretResidue(t, fmt.Sprintf("blake2bXORBlocks512Avx2Asm(blocks=%d)", b), res512, secrets)
		}
		resB256 := stackResidue(func() {
			blake2bBatch24_256Avx2Asm(&hKey256, &m012, &dstPtrs256)
		})
		assertNoSecretResidue(t, "blake2bBatch24_256Avx2Asm", resB256, secrets)

		resB512 := stackResidue(func() {
			blake2bBatch24_512Avx2Asm(&hKey512, &m012, &dstPtrs512)
		})
		assertNoSecretResidue(t, "blake2bBatch24_512Avx2Asm", resB512, secrets)

		for i := 0; i < 8; i++ {
			w := hKey256[i]
			hSoA[i] = [4]uint64{w, w, w, w}
		}
		resC4 := stackResidue(func() {
			blake2bCompress4Avx2Asm(&hSoA, &mSoA, 192, ^uint64(0))
		})
		assertNoSecretResidue(t, "blake2bCompress4Avx2Asm", resC4, secrets)
		clear(hSoA[:])
	}

	if cpuid.AVX512F && cpuid.AVX512VL {
		for _, blks := range []int{1, 3, 4, 7} {
			b := blks
			res256 := stackResidue(func() {
				blake2bXORBlocks256Avx512Asm(&hKey256, &nonce, 1, &dst256[0], &src256[0], b)
			})
			assertNoSecretResidue(t, fmt.Sprintf("blake2bXORBlocks256Avx512Asm(blocks=%d)", b), res256, secrets)

			res512 := stackResidue(func() {
				blake2bXORBlocks512Avx512Asm(&hKey512, &nonce, 1, &dst512[0], &src512[0], b)
			})
			assertNoSecretResidue(t, fmt.Sprintf("blake2bXORBlocks512Avx512Asm(blocks=%d)", b), res512, secrets)
		}
		resB256 := stackResidue(func() {
			blake2bBatch24_256Avx512Asm(&hKey256, &m012, &dstPtrs256)
		})
		assertNoSecretResidue(t, "blake2bBatch24_256Avx512Asm", resB256, secrets)

		resB512 := stackResidue(func() {
			blake2bBatch24_512Avx512Asm(&hKey512, &m012, &dstPtrs512)
		})
		assertNoSecretResidue(t, "blake2bBatch24_512Avx512Asm", resB512, secrets)

		for i := 0; i < 8; i++ {
			w := hKey512[i]
			hSoA[i] = [4]uint64{w, w, w, w}
		}
		resC4 := stackResidue(func() {
			blake2bCompress4Avx512Asm(&hSoA, &mSoA, 192, ^uint64(0))
		})
		assertNoSecretResidue(t, "blake2bCompress4Avx512Asm", resC4, secrets)
		clear(hSoA[:])
	}

	runtime.KeepAlive(&hKey256)
	runtime.KeepAlive(&hKey512)
	runtime.KeepAlive(&nonce)
	runtime.KeepAlive(src256)
	runtime.KeepAlive(dst256)
	runtime.KeepAlive(src512)
	runtime.KeepAlive(dst512)
	runtime.KeepAlive(&m012)
	runtime.KeepAlive(&out256)
	runtime.KeepAlive(&out512)
	runtime.KeepAlive(&hSoA)
	runtime.KeepAlive(&mSoA)
}
