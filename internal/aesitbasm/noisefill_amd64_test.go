//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/everanium/itb/internal/cpuid"
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
		{name: "aesni", ok: cpuid.AESNI, skipMsg: "requires AES-NI", fn: noiseFillX8AesNiAsm, gran: 8},
		{name: "vex", ok: cpuid.AESNI && cpuid.AVX2, skipMsg: "requires AES-NI + AVX2", fn: noiseFillX8VexAsm, gran: 8},
		{name: "vaesavx2", ok: cpuid.VAESYMM, skipMsg: "requires VAES + AVX2", fn: noiseFillX16VaesAvx2Asm, gran: 16},
		{name: "avx512", ok: cpuid.VAESZMM, skipMsg: "requires VAES + AVX-512", fn: noiseFillX16Avx512Asm, gran: 16},
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
	if !cpuid.AESNI {
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
	savedZMM := noiseFillZMM
	defer func() {
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = saved[0], saved[1], saved[2], saved[3]
		noiseFillZMM = savedZMM
	}()
	cases := []struct {
		name  string
		ok    bool
		flags [4]bool
		zmm   bool
	}{
		{"avx512", cpuid.VAESZMM, [4]bool{true, false, false, false}, true},
		{"vaesavx2", cpuid.VAESYMM, [4]bool{false, true, false, false}, false},
		{"vex", cpuid.AESNI && cpuid.AVX2, [4]bool{false, false, true, false}, false},
		{"aesni", cpuid.AESNI, [4]bool{false, false, false, true}, false},
		{"scalar", true, [4]bool{false, false, false, false}, false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if !c.ok {
				t.Skip("tier not executable on this host")
			}
			FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = c.flags[0], c.flags[1], c.flags[2], c.flags[3]
			noiseFillZMM = c.zmm
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
// selects follows ITB_FORCE_HASH_TIER: the ZMM token arms the VAES ZMM
// kernel, every other token selects its own kernel with the ZMM kernel
// disarmed, scalar selects none. Skips when the variable is unset or the
// host cannot honour the token, mirroring TestForceHashTierApplied.
func TestForceHashTierAppliedNoiseFill(t *testing.T) {
	tier := forcetier.HashTier()
	gran := noiseFillGran()
	wantZMM := false
	want := func(g int) {
		t.Helper()
		if gran != g {
			t.Fatalf("%s: noise filler group width %d, want %d", tier, gran, g)
		}
		if got := noiseFillZMM && FusedHasVAESAVX512; got != wantZMM {
			t.Fatalf("%s: noise filler ZMM kernel selected=%v, want %v", tier, got, wantZMM)
		}
	}
	switch tier {
	case "":
		t.Skip("ITB_FORCE_HASH_TIER unset; auto-dispatch")
	case "avx512":
		if !cpuid.VAESZMM {
			t.Skip("avx512 tier not executable on this host")
		}
		wantZMM = true
		want(16)
	case "vaesavx2", "avx2":
		if !cpuid.VAESYMM {
			t.Skip("vaesavx2 tier not executable on this host")
		}
		want(16)
	case "vex":
		if !(cpuid.AESNI && cpuid.AVX2) {
			t.Skip("vex tier not executable on this host")
		}
		want(8)
	case "aesni":
		if !cpuid.AESNI {
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

// TestNoiseFillZMMParity pins the VAES ZMM kernel, called directly, to
// the pure-Go reference at one to eight groups, from every start (a run
// that would reach the 64-bit wrap of lo is placed so it ends on
// lo == 2^64 - 1, the last block before the carry), into a dst at every
// alignment offset 0 .. 15, and checks no byte past the run is written.
// It then runs the NoiseFill driver with the ZMM kernel armed over every
// length, start and alignment, so the carry split and the tail hand-off
// are covered on this kernel too.
func TestNoiseFillZMMParity(t *testing.T) {
	if !cpuid.VAESZMM {
		t.Skip("requires VAES + AVX-512")
	}
	key, nonce := randomNoiseKeyNonce(t)
	s := NewNoiseSchedule(key, nonce)
	for groups := 1; groups <= 8; groups++ {
		nblk := 16 * groups
		for _, st := range noiseStarts {
			lo, hi := st[0], st[1]
			if room := ^lo; uint64(nblk-1) > room {
				lo = ^uint64(0) - uint64(nblk-1)
			}
			want := make([]byte, 16*nblk)
			noiseRefFill(key, nonce, want, lo, hi)
			for off := 0; off < 16; off++ {
				got := make([]byte, 16*nblk+32)
				noiseFillX16Avx512Asm(&s, &got[off], nblk, lo, hi)
				if !bytes.Equal(got[off:off+16*nblk], want) {
					t.Fatalf("nblk=%d ctr=(%d,%d) off=%d: ZMM kernel differs from reference", nblk, lo, hi, off)
				}
				for i := range got {
					if (i < off || i >= off+16*nblk) && got[i] != 0 {
						t.Fatalf("nblk=%d ctr=(%d,%d) off=%d: ZMM kernel wrote outside the run at %d", nblk, lo, hi, off, i)
					}
				}
			}
		}
	}

	saved := [4]bool{FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI}
	savedZMM := noiseFillZMM
	defer func() {
		FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = saved[0], saved[1], saved[2], saved[3]
		noiseFillZMM = savedZMM
	}()
	FusedHasVAESAVX512, FusedHasVAESAVX2, FusedHasAVXAESNI, FusedHasAESNI = true, false, false, false
	noiseFillZMM = true
	for _, n := range noiseLengths {
		for _, st := range noiseStarts {
			want := make([]byte, n)
			noiseRefFill(key, nonce, want, st[0], st[1])
			for off := 0; off < 16; off++ {
				got := make([]byte, n+32)
				for i := range got {
					got[i] = 0xA5
				}
				NoiseFill(&s, got[off:off+n], st[0], st[1])
				if !bytes.Equal(got[off:off+n], want) {
					t.Fatalf("n=%d ctr=%v off=%d: ZMM-armed fill differs from reference", n, st, off)
				}
				for i := range got {
					if (i < off || i >= off+n) && got[i] != 0xA5 {
						t.Fatalf("n=%d ctr=%v off=%d: byte outside dst at %d overwritten", n, st, off, i)
					}
				}
			}
		}
	}
}

// noiseZMMChildEnv marks the child half of TestNoiseFillZMMSelection.
const noiseZMMChildEnv = "ITB_NOISEFILL_ZMM_CHILD"

// TestNoiseFillZMMSelectionChild is the child half: it prints whether
// the process it runs in selects the VAES ZMM noise-filler kernel and
// the group width the filler runs at. It is a no-op unless the parent
// set the child marker.
func TestNoiseFillZMMSelectionChild(t *testing.T) {
	if os.Getenv(noiseZMMChildEnv) == "" {
		t.Skip("child half of TestNoiseFillZMMSelection")
	}
	fmt.Printf("NOISEFILL zmm=%v gran=%d\n", noiseFillZMM && FusedHasVAESAVX512, noiseFillGran())
}

// TestNoiseFillZMMSelection asserts the VAES ZMM noise filler is never
// auto-selected and is selected under ITB_FORCE_HASH_TIER=avx512. The
// variable is read once at init, so each case re-executes the test
// binary with every ITB_FORCE_* variable of the parent environment
// removed and the case's own set, and reads back the child's selection.
func TestNoiseFillZMMSelection(t *testing.T) {
	if os.Getenv(noiseZMMChildEnv) != "" {
		t.Skip("parent half; running as child")
	}
	zmmHost := cpuid.VAESZMM
	cases := []struct {
		name    string
		tier    string
		wantZMM bool
	}{
		{"auto", "", false},
		{"avx512", "avx512", zmmHost},
		{"vaesavx2", "vaesavx2", false},
		{"vex", "vex", false},
		{"aesni", "aesni", false},
		{"scalar", "scalar", false},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestNoiseFillZMMSelectionChild$", "-test.v")
			env := []string{noiseZMMChildEnv + "=1"}
			for _, kv := range os.Environ() {
				if strings.HasPrefix(kv, "ITB_FORCE_") || strings.HasPrefix(kv, noiseZMMChildEnv+"=") {
					continue
				}
				env = append(env, kv)
			}
			if c.tier != "" {
				env = append(env, "ITB_FORCE_HASH_TIER="+c.tier)
			}
			cmd.Env = env
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child: %v\n%s", err, out)
			}
			var line string
			for _, l := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(l, "NOISEFILL ") {
					line = l
				}
			}
			if line == "" {
				t.Fatalf("child printed no selection line:\n%s", out)
			}
			if want := fmt.Sprintf("zmm=%v", c.wantZMM); !strings.Contains(line, want) {
				t.Fatalf("%s: child reports %q, want %s", c.name, line, want)
			}
			if c.name == "auto" && cpuid.VAESYMM && !strings.Contains(line, "gran=16") {
				t.Fatalf("auto on a VAES host: child reports %q, want the sixteen-block YMM kernel", line)
			}
		})
	}
}
