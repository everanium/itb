// Stack-residue and source-level zeroization verification for Mode 3
// Gauss-Posit sub-region scheduling (positDeriveSecretPi, quire512,
// buildSubregionSchedulePosit, and deriveSubregionSchedulePosit across
// 128/256/512-bit seeds).

package itb

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"math/rand"
	"os"
	"strings"
	"testing"
)

// leakyPositSchedule512 is the negative control for stack-residue probing:
// it computes the 0x05 folded words w[0..7], secret Posit pi_{K,r}, radius,
// and quire512 chord intermediates on the stack without clearing them or
// calling wipePixelCallStack512.
//
//go:noinline
func leakyPositSchedule512(s *Seed512, nonce []byte, totalPixels int) {
	var stackBuf [1 + maxDesyncNonceBytes]byte
	buf := stackBuf[:1+len(nonce)]
	buf[0] = 0x05
	copy(buf[1:], nonce)
	h := s.ChainHash512(buf)
	var w [8]uint64
	for i := 0; i < 4; i++ {
		w[2*i], w[2*i+1] = fullWidthFold(h[2*i], h[2*i+1])
	}
	es := 1 + uint((w[0]>>40)%3)
	q := quirePi
	topMix := ((w[2] >> 16) << 8) ^
		((w[3] >> 16) << 9) ^
		((w[4] >> 16) << 10) ^
		((w[5] >> 16) << 11) ^
		((w[6] >> 16) << 12) ^
		((w[7] >> 16) << 12) ^
		(positPiDeepFrac[3] >> 4)
	var carry uint64
	q[3], carry = bits.Add64(q[3], topMix&0x0fffffffffffffff, 0)
	_ = carry
	piK := positEncode64(false, 1, (uint64(3)<<62)|(q[3]>>2), q[2], es)
	radius := positMul(positFromUint64(uint64(totalPixels), es), piK, es)
	pxResidueSink = h[0] ^ w[0] ^ w[7] ^ uint64(piK) ^ uint64(radius) ^ q[3]
}

func TestPositScheduleStackZeroization(t *testing.T) {
	rng := rand.New(rand.NewSource(0x505317))
	nonce := make([]byte, NonceSize)
	rng.Read(nonce)
	const totalPixels = 408

	// 1. Build 128-bit, 256-bit, and 512-bit seeds whose closures also spill onto deep stack frames.
	c128 := make([]uint64, 16)
	c256 := make([]uint64, 16)
	c512 := make([]uint64, 16)
	for i := 0; i < 16; i++ {
		c128[i] = rng.Uint64() | 1
		c256[i] = rng.Uint64() | 1
		c512[i] = rng.Uint64() | 1
	}

	s128 := &Seed128{
		Components: c128,
		Hash: func(data []byte, s0, s1 uint64) (uint64, uint64) {
			d := binary.LittleEndian.Uint64(data[:8]) ^ uint64(data[len(data)-1])*0x9E3779B97F4A7C15
			r0 := (s0 ^ d ^ 0x1122334455667788) * 0xBF58476D1CE4E5B9
			r1 := (s1 ^ d ^ 0x8877665544332211) * 0x94D049BB133111EB
			return simHash128Stack(r0, r1)
		},
	}
	s256 := &Seed256{
		Components: c256,
		Hash: func(data []byte, s [4]uint64) [4]uint64 {
			d := binary.LittleEndian.Uint64(data[:8]) ^ uint64(data[len(data)-1])*0x9E3779B97F4A7C15
			var r [4]uint64
			for i := 0; i < 4; i++ {
				r[i] = (s[i] ^ d ^ uint64(i+1)*0x517CC1B727220A95) * 0x94D049BB133111EB
			}
			return simHash256Stack(r)
		},
	}
	s512 := &Seed512{
		Components: c512,
		Hash: func(data []byte, s [8]uint64) [8]uint64 {
			d := binary.LittleEndian.Uint64(data[:8]) ^ uint64(data[len(data)-1])*0x9E3779B97F4A7C15
			var r [8]uint64
			for i := 0; i < 8; i++ {
				r[i] = (s[i] ^ d ^ uint64(i+1)*0x517CC1B727220A95) * 0xBF58476D1CE4E5B9
			}
			return simHash512Stack(r)
		},
	}

	// Collect all secret words that deriveSubregionSchedulePosit computes across 128/256/512.
	secrets := make(map[uint64]string)
	collectPositSecrets := func(label string, w [8]uint64) {
		for i, v := range w {
			if v != 0 {
				secrets[v] = fmt.Sprintf("%s.w[%d]", label, i)
			}
		}
		piK, es := positDeriveSecretPi(w)
		if piK != 0 {
			secrets[uint64(piK)] = label + ".piK"
		}
		pTotal := positFromUint64(uint64(totalPixels), es)
		radius := positMul(pTotal, piK, es)
		if radius != 0 {
			secrets[uint64(radius)] = label + ".radius"
		}
		k := 8 + int(w[0]%9)
		phase := uint64((w[0] >> 44) & 63)
		flip := ((w[0] >> 52) & 1) != 0
		denPosit := positFromUint64(uint64(64*k+32), es)
		var chordDigest uint64
		for j := 0; j < k; j++ {
			idx := j
			if flip {
				idx = k - 1 - j
			}
			num := uint64(64*idx+16) + phase
			y := positDiv(positMul(radius, positFromUint64(num, es), es), denPosit, es)
			var q quire512
			q.addProduct(radius, radius, es)
			q.subProduct(y, y, es)
			r2MinusY2 := q.toPosit(es)
			cPosit := positSqrt(r2MinusY2, es)
			if r2MinusY2 != 0 {
				secrets[uint64(r2MinusY2)] = fmt.Sprintf("%s.r2MinusY2[%d]", label, j)
			}
			if cPosit != 0 {
				secrets[uint64(cPosit)] = fmt.Sprintf("%s.cPosit[%d]", label, j)
			}
			chordDigest = bits.RotateLeft64(chordDigest, 19) ^ (uint64(cPosit) * desyncGoldenGamma) ^ uint64(r2MinusY2)
			if chordDigest != 0 {
				secrets[chordDigest] = fmt.Sprintf("%s.chordDigest[%d]", label, j)
			}
		}
	}

	// 128-bit secrets
	{
		buf := make([]byte, 1+len(nonce))
		buf[0] = 0x05
		copy(buf[1:], nonce)
		last := len(buf) - 1
		baseByte := nonce[len(nonce)-1]
		var w [8]uint64
		for j := 0; j < 4; j++ {
			buf[last] = baseByte ^ byte(j)
			lo, hi := s128.ChainHash128(buf)
			secrets[lo] = fmt.Sprintf("128.hLo[%d]", j)
			secrets[hi] = fmt.Sprintf("128.hHi[%d]", j)
			w[2*j], w[2*j+1] = fullWidthFold(lo, hi)
		}
		collectPositSecrets("128", w)
	}
	// 256-bit secrets
	{
		buf := make([]byte, 1+len(nonce))
		buf[0] = 0x05
		copy(buf[1:], nonce)
		last := len(buf) - 1
		baseByte := nonce[len(nonce)-1]
		var w [8]uint64
		for j := 0; j < 2; j++ {
			buf[last] = baseByte ^ byte(j)
			h := s256.ChainHash256(buf)
			for i, v := range h {
				secrets[v] = fmt.Sprintf("256.h[%d,%d]", j, i)
			}
			w[4*j], w[4*j+1] = fullWidthFold(h[0], h[1])
			w[4*j+2], w[4*j+3] = fullWidthFold(h[2], h[3])
		}
		collectPositSecrets("256", w)
	}
	// 512-bit secrets
	{
		buf := make([]byte, 1+len(nonce))
		buf[0] = 0x05
		copy(buf[1:], nonce)
		h := s512.ChainHash512(buf)
		var w [8]uint64
		for i := 0; i < 4; i++ {
			secrets[h[2*i]] = fmt.Sprintf("512.h[%d]", 2*i)
			secrets[h[2*i+1]] = fmt.Sprintf("512.h[%d]", 2*i+1)
			w[2*i], w[2*i+1] = fullWidthFold(h[2*i], h[2*i+1])
		}
		collectPositSecrets("512", w)
	}

	// Negative control: verify pxStackResidue detects unwiped Posit secrets.
	resNeg := pxStackResidue(func() {
		pxResidueMark()
		leakyPositSchedule512(s512, nonce, totalPixels)
	})
	if pxResidueHits(resNeg, secrets) == 0 {
		t.Fatal("negative control failed: pxStackResidue did not detect unwiped Posit secrets in leakyPositSchedule512")
	}

	// Verify deriveSubregionSchedulePosit leaves zero secret residue across 128/256/512.
	for _, tc := range []struct {
		name string
		fn   func()
	}{
		{"Seed128.deriveSubregionSchedulePosit", func() {
			pxResidueMark()
			sched := s128.deriveSubregionSchedulePosit(nonce, 17, totalPixels)
			pxResidueSink = uint64(sched.k)
		}},
		{"Seed256.deriveSubregionSchedulePosit", func() {
			pxResidueMark()
			sched := s256.deriveSubregionSchedulePosit(nonce, 17, totalPixels)
			pxResidueSink = uint64(sched.k)
		}},
		{"Seed512.deriveSubregionSchedulePosit", func() {
			pxResidueMark()
			sched := s512.deriveSubregionSchedulePosit(nonce, 17, totalPixels)
			pxResidueSink = uint64(sched.k)
		}},
	} {
		res := pxStackResidue(tc.fn)
		assertNoPixelSecretResidue(t, tc.name, res, secrets)
	}
}

func TestPositSourceZeroizationInvariants(t *testing.T) {
	positSrc, err := os.ReadFile("posit.go")
	if err != nil {
		t.Fatalf("ReadFile(posit.go): %v", err)
	}
	src := string(positSrc)
	requiredSnippets := []string{
		"clear(mag[:])",
		"clear(words[:])",
		"clear(delta[:])",
		"clear(q[:])",
		"clear(w[:])",
		"clear(chords[:])",
		"clear(physOff[:])",
		"clear(physSize[:])",
		"clear(tau[:])",
		"runtime.KeepAlive(&piK)",
		"runtime.KeepAlive(&radius)",
		"runtime.KeepAlive(&chordDigest)",
	}
	for _, snip := range requiredSnippets {
		if !strings.Contains(src, snip) {
			t.Fatalf("posit.go missing required zeroization statement %q", snip)
		}
	}
}
