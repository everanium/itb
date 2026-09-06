//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
	"testing"

	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// Every kernel is called directly — bypassing the dispatcher — so each
// tier is exercised on any host whose silicon can execute it, not only
// on the host where auto-dispatch would pick it.

type tierKernels struct {
	name    string
	ok      bool
	skipMsg string
	k       map[int]kernelFn
}

func amd64Tiers() []tierKernels {
	return []tierKernels{
		{
			name: "aesni", ok: aes.CPU.HasAESNI, skipMsg: "requires AES-NI",
			k: map[int]kernelFn{
				13: aesITB128ChainAbsorb13x4AesNiAsm,
				20: aesITB128ChainAbsorb20x4AesNiAsm,
				36: aesITB128ChainAbsorb36x4AesNiAsm,
				68: aesITB128ChainAbsorb68x4AesNiAsm,
			},
		},
		{
			name: "vex", ok: aes.CPU.HasAESNI && aes.CPU.HasAVX2, skipMsg: "requires AES-NI + AVX",
			k: map[int]kernelFn{
				13: aesITB128ChainAbsorb13x4VexAsm,
				20: aesITB128ChainAbsorb20x4VexAsm,
				36: aesITB128ChainAbsorb36x4VexAsm,
				68: aesITB128ChainAbsorb68x4VexAsm,
			},
		},
		{
			name: "vaesavx2", ok: aes.CPU.HasVAES && aes.CPU.HasAVX2, skipMsg: "requires VAES + AVX2",
			k: map[int]kernelFn{
				13: aesITB128ChainAbsorb13x4VaesAvx2Asm,
				20: aesITB128ChainAbsorb20x4VaesAvx2Asm,
				36: aesITB128ChainAbsorb36x4VaesAvx2Asm,
				68: aesITB128ChainAbsorb68x4VaesAvx2Asm,
			},
		},
		{
			name: "avx512", ok: aes.CPU.HasVAES && aes.CPU.HasAVX512, skipMsg: "requires VAES + AVX-512",
			k: map[int]kernelFn{
				13: aesITB128ChainAbsorb13x4Avx512Asm,
				20: aesITB128ChainAbsorb20x4Avx512Asm,
				36: aesITB128ChainAbsorb36x4Avx512Asm,
				68: aesITB128ChainAbsorb68x4Avx512Asm,
			},
		},
	}
}

func TestKernelParityAmd64(t *testing.T) {
	for _, tier := range amd64Tiers() {
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			for _, n := range shapes {
				kernel, ok := tier.k[n]
				if !ok {
					continue
				}
				t.Run(shapeName(n), func(t *testing.T) {
					runKernelParity(t, tier.name, n, kernel)
				})
			}
		})
	}
}

// TestDispatchFlagsExclusive pins the auto-selected flag set to at most
// one active tier.
func TestDispatchFlagsExclusive(t *testing.T) {
	active := 0
	for _, f := range []bool{HasVAESAVX512, HasVAESAVX2NoAVX512, HasAVXAESNIBatched, HasAESNIBatched} {
		if f {
			active++
		}
	}
	if active > 1 {
		t.Fatalf("%d tier flags active, want at most 1", active)
	}
	if aes.CPU.HasAESNI && active == 0 && forcetier.HashTier() == "" {
		t.Fatal("AES-NI host with no batched tier selected under auto-dispatch")
	}
}
