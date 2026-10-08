//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
	"bytes"
	"fmt"
	"testing"

	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

type noiseTier struct {
	name    string
	ok      bool
	skipMsg string
	fn      func(sched *NoiseSchedule, dst *byte, nblk int, lo, hi uint64)
	gran    int
}

func amd64NoiseTiers() []noiseTier {
	return []noiseTier{
		{name: "aesni", ok: aes.CPU.HasAESNI, skipMsg: "requires AES-NI", fn: noiseFillX8AesNiAsm, gran: 8},
		{name: "vex", ok: aes.CPU.HasAESNI && aes.CPU.HasAVX2, skipMsg: "requires AES-NI + AVX2", fn: noiseFillX8VexAsm, gran: 8},
		{name: "vaesavx2", ok: aes.CPU.HasVAES && aes.CPU.HasAVX2, skipMsg: "requires VAES + AVX2", fn: noiseFillX16VaesAvx2Asm, gran: 16},
	}
}

// TestNoiseFillTiersParity drives every amd64 kernel the host can
// execute directly, at block counts from one group up to several
// groups plus every residue, from every start, and pins each output to
// the pure-Go reference — including a dst at every alignment offset
// 0 .. 15 so unaligned stores are covered.
func TestNoiseFillTiersParity(t *testing.T) {
	for _, tier := range amd64NoiseTiers() {
		tier := tier
		t.Run(tier.name, func(t *testing.T) {
			if !tier.ok {
				t.Skip(tier.skipMsg)
			}
			for trial := 0; trial < 200; trial++ {
				key, nonce := randomNoiseKeyNonce(t)
				s := NewNoiseSchedule(key, nonce)
				nblk := tier.gran * (1 + trial%5)
				c := noiseStarts[trial%len(noiseStarts)]
				lo, hi := c[0], c[1]
				if room := ^lo; uint64(nblk-1) > room {
					lo = ^uint64(0) - uint64(nblk) // keep the run clear of the wrap
				}
				want := make([]byte, 16*nblk)
				noiseRefFill(key, nonce, want, lo, hi)
				off := trial % 16
				got := make([]byte, 16*nblk+32)
				tier.fn(&s, &got[off], nblk, lo, hi)
				if !bytes.Equal(got[off:off+16*nblk], want) {
					t.Fatalf("%s trial %d nblk=%d off=%d: kernel differs from reference", tier.name, trial, nblk, off)
				}
				for i := 16*nblk + off; i < len(got); i++ {
					if got[i] != 0 {
						t.Fatalf("%s trial %d: kernel wrote past nblk blocks at %d", tier.name, trial, i)
					}
				}
			}
		})
	}
}

// TestNoiseFillTierSelectedOnCapableHost guards against a silent
// fall-through to the Go path: on a host with AES-NI and no forced
// tier, a kernel must be selected.
func TestNoiseFillTierSelectedOnCapableHost(t *testing.T) {
	if forcetier.HashTier() != "" {
		t.Skip("ITB_FORCE_HASH_TIER set; selection asserted by TestForceHashTierAppliedNoiseFill")
	}
	if !aes.CPU.HasAESNI {
		t.Skip("host has no AES-NI")
	}
	if gran := noiseFillGran(); gran == 0 {
		t.Fatal("AES-NI host selected no noise-filler kernel")
	}
}

// TestNoiseFillForcedTierParity runs the full NoiseFill driver under
// every tier flag assignment the host can execute, so the carry split
// and the tail hand-off are covered on each kernel, then restores the
// flags.
func TestNoiseFillForcedTierParity(t *testing.T) {
	saved := [4]bool{FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI}
	defer func() {
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = saved[0], saved[1], saved[2], saved[3]
	}()
	cases := []struct {
		name  string
		ok    bool
		flags [4]bool
	}{
		{"vaesavx2", aes.CPU.HasVAES && aes.CPU.HasAVX2, [4]bool{false, true, false, false}},
		{"vex", aes.CPU.HasAESNI && aes.CPU.HasAVX2, [4]bool{false, false, true, false}},
		{"aesni", aes.CPU.HasAESNI, [4]bool{false, false, false, true}},
		{"scalar", true, [4]bool{false, false, false, false}},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if !c.ok {
				t.Skip("tier not executable on this host")
			}
			FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = c.flags[0], c.flags[1], c.flags[2], c.flags[3]
			gran := noiseFillGran()
			if c.name == "scalar" && gran != 0 || c.name != "scalar" && gran == 0 {
				t.Fatalf("%s: tier selection gran=%d", c.name, gran)
			}
			for _, n := range noiseLengths {
				for _, st := range noiseStarts {
					key, nonce := randomNoiseKeyNonce(t)
					s := NewNoiseSchedule(key, nonce)
					want := make([]byte, n)
					noiseRefFill(key, nonce, want, st[0], st[1])
					got := make([]byte, n)
					NoiseFill(&s, got, st[0], st[1])
					if !bytes.Equal(got, want) {
						t.Fatalf("%s n=%d ctr=%v: fill differs from reference", c.name, n, st)
					}
				}
			}
		})
	}
}

// TestForceHashTierAppliedNoiseFill asserts the kernel NoiseFill
// selects follows ITB_FORCE_HASH_TIER: the ZMM token lands on the YMM
// kernel (the filler ships no ZMM tier), every other token on its own
// kernel, scalar on none. Skips when the variable is unset or the host
// cannot honour the token, mirroring TestForceHashTierApplied.
func TestForceHashTierAppliedNoiseFill(t *testing.T) {
	tier := forcetier.HashTier()
	gran := noiseFillGran()
	want := func(g int) {
		t.Helper()
		if gran != g {
			t.Fatalf("%s: noise filler group width %d, want %d", tier, gran, g)
		}
	}
	switch tier {
	case "":
		t.Skip("ITB_FORCE_HASH_TIER unset; auto-dispatch")
	case "avx512":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX512) {
			t.Skip("avx512 tier not executable on this host")
		}
		want(16)
	case "vaesavx2", "avx2":
		if !(aes.CPU.HasVAES && aes.CPU.HasAVX2) {
			t.Skip("vaesavx2 tier not executable on this host")
		}
		want(16)
	case "vex":
		if !(aes.CPU.HasAESNI && aes.CPU.HasAVX2) {
			t.Skip("vex tier not executable on this host")
		}
		want(8)
	case "aesni":
		if !aes.CPU.HasAESNI {
			t.Skip("aesni tier not executable on this host")
		}
		want(8)
	case "scalar":
		want(0)
	case "gpr", "sve2", "sve", "neon":
		t.Skipf("%s: no arm in this family on amd64; auto-dispatch kept", tier)
	default:
		t.Fatalf("unexpected validated tier %q", tier)
	}
}

// BenchmarkNoiseFillTiers reports the per-goroutine fill rate of every
// executable kernel and of the Go single-block path at an in-cache and
// a production-shaped size.
func BenchmarkNoiseFillTiers(b *testing.B) {
	key := new([16]byte)
	nonce := new([32]byte)
	s := NewNoiseSchedule(key, nonce)
	sizes := []int{64 << 10, 1 << 20, 6 << 20}
	for _, tier := range amd64NoiseTiers() {
		if !tier.ok {
			continue
		}
		for _, size := range sizes {
			dst := make([]byte, size)
			nblk := size / 16
			nblk -= nblk % tier.gran
			b.Run(fmt.Sprintf("%s/%dKiB", tier.name, size>>10), func(b *testing.B) {
				b.SetBytes(int64(16 * nblk))
				for i := 0; i < b.N; i++ {
					tier.fn(&s, &dst[0], nblk, 0, 0)
				}
			})
		}
	}
	for _, size := range sizes[:2] {
		dst := make([]byte, size)
		b.Run(fmt.Sprintf("generic/%dKiB", size>>10), func(b *testing.B) {
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				noiseFillGeneric(&s, dst, 0, 0)
			}
		})
	}
}
