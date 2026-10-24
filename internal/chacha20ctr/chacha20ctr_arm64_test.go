//go:build arm64 && !purego && !noitbasm

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
		dumpSIMDRegs(dst, false)
	}
	dirtySIMDRegHook = dirtySIMDRegForTest
}

func TestChaCha20XORAsmTiersDirectArm64(t *testing.T) {
	if !cpuid.ASIMD {
		t.Skip("ASIMD not available")
	}
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

			gotNEON := make([]byte, n)
			c := ctr
			xorKeyStreamVX(gotNEON, src, &key, &nonce, &c)
			if !bytes.Equal(gotNEON, want) {
				t.Fatalf("NEON mismatch at ctr=%d nBlocks=%d", ctr, nBlocks)
			}
			if c != ctr+uint32(nBlocks) {
				t.Fatalf("NEON counter=%d, want %d", c, ctr+uint32(nBlocks))
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

func TestXORKernelsLeaveNoSecretInFrameAndRegsArm64(t *testing.T) {
	if !cpuid.ASIMD {
		t.Skip("ASIMD not available")
	}
	checkResidueNegativeControls(t)
	key := [8]uint32{
		0xdeadbeef, 0xcafebabe, 0x01234567, 0x89abcdef,
		0xfedcba98, 0x76543210, 0x4b5a6978, 0x0f1e2d3c,
	}
	nonce := [3]uint32{0x11223344, 0x55667788, 0x99aabbcc}
	secrets := makeTestSecrets(&key, &nonce)
	src := make([]byte, 15*64)
	dst := make([]byte, 15*64)

	for _, blks := range []int{1, 2, 3, 4, 7, 8, 15} {
		b := blks
		res := stackResidue(func() {
			ctr := uint32(1)
			xorKeyStreamVX(dst[:b*64], src[:b*64], &key, &nonce, &ctr)
		})
		assertNoSecretResidue(t, fmt.Sprintf("xorKeyStreamVX(blocks=%d)", b), res, secrets)
	}
	runtime.KeepAlive(&key)
	runtime.KeepAlive(&nonce)
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
}
