//go:build amd64 && !purego && !noitbasm

package chacha20ctr

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
		dumpSIMDRegs(dst, cpuid.AVX512F && cpuid.AVX512VL)
	}
	dirtySIMDRegHook = dirtySIMDRegForTest
}

func TestChaCha20XORAsmTiersDirect(t *testing.T) {
	key := [8]uint32{
		0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
		0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
	}
	nonce := [3]uint32{0x09000000, 0x4a000000, 0x00000000}

	for _, ctr := range []uint32{0, 1, 19, 1000} {
		for nBlocks := 1; nBlocks <= 25; nBlocks++ {
			n := nBlocks * 64
			src := make([]byte, n)
			for i := range src {
				src[i] = byte(i*31 + 7)
			}
			want := make([]byte, n)
			scalarXORKeyStreamBlocks(want, src, &key, &nonce, ctr)

			if cpuid.AVX2 {
				gotAVX2 := make([]byte, n)
				chacha20XORBlocksAvx2Asm(&key, &nonce, ctr, &gotAVX2[0], &src[0], nBlocks)
				if !bytes.Equal(gotAVX2, want) {
					t.Fatalf("AVX2 mismatch at ctr=%d nBlocks=%d", ctr, nBlocks)
				}
			}
			if cpuid.AVX512F && cpuid.AVX512VL {
				gotAVX512 := make([]byte, n)
				chacha20XORBlocksAvx512Asm(&key, &nonce, ctr, &gotAVX512[0], &src[0], nBlocks)
				if !bytes.Equal(gotAVX512, want) {
					t.Fatalf("AVX512 mismatch at ctr=%d nBlocks=%d", ctr, nBlocks)
				}
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

func TestXORKernelsLeaveNoSecretInFrameAndRegsAmd64(t *testing.T) {
	checkResidueNegativeControls(t)
	key := [8]uint32{
		0xdeadbeef, 0xcafebabe, 0x01234567, 0x89abcdef,
		0xfedcba98, 0x76543210, 0x4b5a6978, 0x0f1e2d3c,
	}
	nonce := [3]uint32{0x11223344, 0x55667788, 0x99aabbcc}
	secrets := makeTestSecrets(&key, &nonce)
	src := make([]byte, 15*64)
	dst := make([]byte, 15*64)

	if cpuid.AVX2 {
		for _, blks := range []int{1, 3, 4, 7} {
			b := blks
			res := stackResidue(func() {
				chacha20XORBlocksAvx2Asm(&key, &nonce, 1, &dst[0], &src[0], b)
			})
			assertNoSecretResidue(t, fmt.Sprintf("chacha20XORBlocksAvx2Asm(blocks=%d)", b), res, secrets)
		}
	}
	if cpuid.AVX512F && cpuid.AVX512VL {
		for _, blks := range []int{1, 3, 4, 7, 8, 15} {
			b := blks
			res := stackResidue(func() {
				chacha20XORBlocksAvx512Asm(&key, &nonce, 1, &dst[0], &src[0], b)
			})
			assertNoSecretResidue(t, fmt.Sprintf("chacha20XORBlocksAvx512Asm(blocks=%d)", b), res, secrets)
		}
	}
	runtime.KeepAlive(&key)
	runtime.KeepAlive(&nonce)
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
}
