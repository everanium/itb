//go:build amd64 && !purego && !noitbasm

package keccakasm

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"runtime/debug"
	"testing"
	"unsafe"
)

const (
	residueGap      = 1 << 10
	residuePad      = 2 << 10
	residueWindow   = 16 << 10
	residueSentinel = 0x5A5A5A5A5A5A5A5A
)

func dumpSIMDRegs(dst *[80]uint64, avx512 bool)
func dirtySIMDRegForTest(masked uint64)

func stackResidue(fn func()) []uint64 {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	res := make([]uint64, residueWindow/8+80)
	done := make(chan struct{})
	go func() {
		defer close(done)
		residueGrow(0)
		var regs [80]uint64
		residueProbe(fn, res[:residueWindow/8], &regs)
		copy(res[residueWindow/8:], regs[:])
	}()
	<-done
	return res
}

//go:noinline
func residueGrow(i int) byte {
	var pad [4 * residueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
func residueProbe(fn func(), res []uint64, regs *[80]uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -residueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = residueSentinel
	}
	residueDeep(fn, 0, regs)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func residueDeep(fn func(), i int, regs *[80]uint64) byte {
	var pad [residuePad]byte
	pad[i] = 1
	fn()
	dumpSIMDRegs(regs, HasAVX512Fused)
	return pad[(i+7)%len(pad)]
}

var residueSink uint64

//go:noinline
func leakyKeccakFrame(s *[25]uint64, i int) {
	var frame [25]uint64
	for j := range frame {
		frame[j] = s[j]
	}
	residueSink = frame[(i+1)%len(frame)]
}

// TestFusedKernelsLeaveNoSecretInFrame verifies that keccakF1600AVX512,
// keccakAbsorb136AVX512, and CShake256 leave no sponge state word or
// absorbed rate-block word in either the stack frame or post-RET
// XMM/GPR registers across both AVX-512 and generic dispatch tiers.
func TestFusedKernelsLeaveNoSecretInFrame(t *testing.T) {
	var secret [25]uint64
	var raw [200]byte
	rand.Read(raw[:])
	for i := range secret {
		secret[i] = binary.LittleEndian.Uint64(raw[8*i:])
		if secret[i] == 0 {
			secret[i] = 1
		}
	}
	secrets := make(map[uint64]string, len(secret))
	for i, w := range secret {
		secrets[w] = fmt.Sprintf("sponge word %d", i)
	}

	// Negative control 1: stack residue probe sees leaked sponge frame.
	negStack := stackResidue(func() { leakyKeccakFrame(&secret, 0) })
	hits := 0
	for _, w := range negStack[:residueWindow/8] {
		if _, ok := secrets[w]; ok {
			hits++
		}
	}
	if hits == 0 {
		t.Fatal("negative control: stack-residue probe did not see sponge words stored by leakyKeccakFrame")
	}

	// Negative control 2: post-RET register snapshot sees leaked XMM and GPR.
	regSecret := secret[0]
	negReg := stackResidue(func() { dirtySIMDRegForTest(regSecret ^ 0x5555555555555555) })
	regHits := 0
	for _, w := range negReg[residueWindow/8:] {
		if w == regSecret {
			regHits++
		}
	}
	if regHits < 2 {
		t.Fatalf("negative control: register snapshot saw %d hits of leaked register word, want >= 2 (X2 + R12)", regHits)
	}

	checkNoResidue := func(label string, res []uint64, sec map[uint64]string, checkRegs bool) {
		t.Helper()
		written := 0
		stackWords := residueWindow / 8
		limit := len(res)
		if !checkRegs {
			limit = stackWords
		}
		for i := 0; i < limit; i++ {
			w := res[i]
			if i < stackWords && w != residueSentinel {
				written++
			}
			if w == 0 {
				continue
			}
			if what, ok := sec[w]; ok {
				where := "register snapshot"
				if i < stackWords {
					where = fmt.Sprintf("stack %d bytes below window top", 8*(i+1))
				}
				t.Errorf("%s: %s left in %s", label, what, where)
			}
		}
		if written == 0 {
			t.Fatalf("%s: no word of the stack window was written", label)
		}
	}

	if HasAVX512Fused {
		st := secret
		res := stackResidue(func() {
			keccakF1600AVX512(&st)
		})
		outSec := make(map[uint64]string, 50)
		for k, v := range secrets {
			outSec[k] = v
		}
		for i, w := range st {
			if w != 0 {
				outSec[w] = fmt.Sprintf("permuted state word %d", i)
			}
		}
		checkNoResidue("keccakF1600AVX512", res, outSec, true)

		st2 := secret
		var blk [Rate]byte
		rand.Read(blk[:])
		res2 := stackResidue(func() {
			keccakAbsorb136AVX512(&st2, &blk[0])
		})
		absSec := make(map[uint64]string, 70)
		for k, v := range secrets {
			absSec[k] = v
		}
		for i := 0; i < Rate/8; i++ {
			bw := binary.LittleEndian.Uint64(blk[8*i:])
			if bw != 0 {
				absSec[bw] = fmt.Sprintf("rate block word %d", i)
			}
			if (bw ^ secret[i]) != 0 {
				absSec[bw^secret[i]] = fmt.Sprintf("absorbed lane %d", i)
			}
		}
		for i, w := range st2 {
			if w != 0 {
				absSec[w] = fmt.Sprintf("post-absorb state word %d", i)
			}
		}
		checkNoResidue("keccakAbsorb136AVX512", res2, absSec, true)
	}

	// Verify CShake256 sponge across both AVX-512 (if available) and generic tiers.
	saved := HasAVX512Fused
	defer func() { HasAVX512Fused = saved }()
	for _, tier := range []struct {
		name   string
		avx512 bool
	}{
		{"avx512", true},
		{"generic", false},
	} {
		if tier.avx512 && !saved {
			continue
		}
		HasAVX512Fused = tier.avx512
		var keyBlock [Rate]byte
		rand.Read(keyBlock[:])
		var msg [200]byte
		rand.Read(msg[:])
		var dig [32]byte
		res := stackResidue(func() {
			h := NewCShake256()
			h.Write(keyBlock[:])
			h.Write(msg[:])
			h.Sum256Into(dig[:])
		})
		spSec := make(map[uint64]string, 50)
		for i := 0; i < Rate/8; i++ {
			w := binary.LittleEndian.Uint64(keyBlock[8*i:])
			if w != 0 {
				spSec[w] = fmt.Sprintf("sponge key block word %d", i)
			}
		}
		for i := 0; i < len(msg)/8; i++ {
			w := binary.LittleEndian.Uint64(msg[8*i:])
			if w != 0 {
				spSec[w] = fmt.Sprintf("sponge message word %d", i)
			}
		}
		checkNoResidue("CShake256/"+tier.name, res, spSec, true)
	}
}
