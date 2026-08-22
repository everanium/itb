//go:build amd64 && !purego && !noitbasm

package interlock

import (
	"math/rand"
	"testing"
)

// softPEXT48Ref / softPDEP48Ref are local pure-Go references for the
// asm entry points. Structurally identical to the parent package's
// softPEXT48 / softPDEP48, duplicated here so the asm-package tests
// stay self-contained (no import cycle with the parent).
func softPEXT48Ref(x, mask uint64) uint16 {
	var result, outBit uint64
	for i := uint64(0); i < 48; i++ {
		bit := (mask >> i) & 1
		xb := (x >> i) & 1
		result |= (bit & xb) << outBit
		outBit += bit
	}
	return uint16(result)
}

func softPDEP48Ref(v uint16, mask uint64) uint64 {
	var result, inBit uint64
	for i := uint64(0); i < 48; i++ {
		bit := (mask >> i) & 1
		vb := uint64(v>>inBit) & 1
		result |= (bit & vb) << i
		inBit += bit
	}
	return result
}

// randomTripleMask returns a valid (m0, m1, m2) mask triple: popcount
// 16 each, pairwise-disjoint, union = 2^48 - 1. Derived from the same
// combinatorial unrank + remap as the parent package; duplicated here
// to keep this test self-contained.
func randomTripleMask(rng *rand.Rand) (m0, m1, m2 uint64) {
	// Local Pascal table just big enough for k <= 16, n <= 48.
	var c [49][17]uint64
	for n := 0; n <= 48; n++ {
		c[n][0] = 1
		for k := 1; k <= 16 && k <= n; k++ {
			c[n][k] = c[n-1][k-1] + c[n-1][k]
		}
	}
	unrank := func(rank uint64, k, n int) uint64 {
		var mask uint64
		for k > 0 {
			cc := k - 1
			for cc+1 <= n-1 && c[cc+1][k] <= rank {
				cc++
			}
			mask |= uint64(1) << uint(cc)
			rank -= c[cc][k]
			k--
		}
		return mask
	}

	const A = 2254848913647
	const B = 601080390
	idx0 := rng.Uint64() % A
	idx1 := rng.Uint64() % B
	m0 = unrank(idx0, 16, 48)
	m1Local := unrank(idx1, 16, 32)
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	remaining := domain & ^m0
	var posIdx uint
	for bit := uint(0); bit < 48; bit++ {
		if (remaining>>bit)&1 == 1 {
			if (m1Local>>posIdx)&1 == 1 {
				m1 |= uint64(1) << bit
			}
			posIdx++
		}
	}
	m2 = remaining & ^m1
	return
}

// TestChunk48LockAsmVsSoft compares the BMI2 kernel output byte-for-byte
// against the pure-Go softPEXT48 reference on random 48-bit inputs and
// PRF-derived mask triples. Byte-level rather than value-level: the
// parent-package driver serialises lane outputs as little-endian uint16
// into three per-lane byte buffers; a byte-level assert catches any
// endianness / truncation surprise a value-level compare would miss.
func TestChunk48LockAsmVsSoft(t *testing.T) {
	if !HasBMI2 {
		t.Skip("BMI2 not available")
	}
	rng := rand.New(rand.NewSource(1))
	const N = 20000
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	for iter := 0; iter < N; iter++ {
		x := rng.Uint64() & domain
		m0, m1, m2 := randomTripleMask(rng)

		l0a, l1a, l2a := Chunk48Lock(x, m0, m1, m2)
		l0s := softPEXT48Ref(x, m0)
		l1s := softPEXT48Ref(x, m1)
		l2s := softPEXT48Ref(x, m2)

		// Value-level.
		if uint16(l0a) != l0s || uint16(l1a) != l1s || uint16(l2a) != l2s {
			t.Fatalf("iter=%d x=%012x masks=(%012x,%012x,%012x): asm=(%04x,%04x,%04x) soft=(%04x,%04x,%04x)",
				iter, x, m0, m1, m2, uint16(l0a), uint16(l1a), uint16(l2a), l0s, l1s, l2s)
		}
		// Byte-level: serialise both lane triples as little-endian uint16 and compare.
		var asmBytes, softBytes [6]byte
		asmBytes[0] = byte(l0a)
		asmBytes[1] = byte(l0a >> 8)
		asmBytes[2] = byte(l1a)
		asmBytes[3] = byte(l1a >> 8)
		asmBytes[4] = byte(l2a)
		asmBytes[5] = byte(l2a >> 8)
		softBytes[0] = byte(l0s)
		softBytes[1] = byte(l0s >> 8)
		softBytes[2] = byte(l1s)
		softBytes[3] = byte(l1s >> 8)
		softBytes[4] = byte(l2s)
		softBytes[5] = byte(l2s >> 8)
		if asmBytes != softBytes {
			t.Fatalf("iter=%d: byte-level lane serialisation differs: asm=%x soft=%x",
				iter, asmBytes, softBytes)
		}
		// Upper bits above the low 16 of each returned uint64 must be zero.
		if l0a>>16 != 0 || l1a>>16 != 0 || l2a>>16 != 0 {
			t.Fatalf("iter=%d: Chunk48Lock leaked bits above position 15: (%016x, %016x, %016x)",
				iter, l0a, l1a, l2a)
		}
	}
}

// TestUnchunk48LockAsmVsSoft compares the BMI2 kernel output against
// the pure-Go softPDEP48 reference. Random 16-bit lane values under
// valid mask triples reconstruct the 48-bit chunk word; both paths
// must produce identical results.
func TestUnchunk48LockAsmVsSoft(t *testing.T) {
	if !HasBMI2 {
		t.Skip("BMI2 not available")
	}
	rng := rand.New(rand.NewSource(2))
	const N = 20000
	for iter := 0; iter < N; iter++ {
		l0 := uint16(rng.Uint32())
		l1 := uint16(rng.Uint32())
		l2 := uint16(rng.Uint32())
		m0, m1, m2 := randomTripleMask(rng)

		xAsm := Unchunk48Lock(uint64(l0), uint64(l1), uint64(l2), m0, m1, m2)
		xSoft := softPDEP48Ref(l0, m0) | softPDEP48Ref(l1, m1) | softPDEP48Ref(l2, m2)

		if xAsm != xSoft {
			t.Fatalf("iter=%d lanes=(%04x,%04x,%04x) masks=(%012x,%012x,%012x): asm=%012x soft=%012x",
				iter, l0, l1, l2, m0, m1, m2, xAsm, xSoft)
		}
		if xAsm>>48 != 0 {
			t.Fatalf("iter=%d: Unchunk48Lock wrote outside 48-bit domain: %016x", iter, xAsm)
		}
	}
}

// TestChunk48LockAsmRoundTrip is the self-consistency check: apply the
// forward asm kernel to a random 48-bit chunk then the inverse asm
// kernel; the recovered value must equal the input.
func TestChunk48LockAsmRoundTrip(t *testing.T) {
	if !HasBMI2 {
		t.Skip("BMI2 not available")
	}
	rng := rand.New(rand.NewSource(3))
	const N = 20000
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	for iter := 0; iter < N; iter++ {
		x := rng.Uint64() & domain
		m0, m1, m2 := randomTripleMask(rng)
		l0, l1, l2 := Chunk48Lock(x, m0, m1, m2)
		back := Unchunk48Lock(l0, l1, l2, m0, m1, m2)
		if back != x {
			t.Fatalf("iter=%d x=%012x: round-trip yielded %012x", iter, x, back)
		}
	}
}
