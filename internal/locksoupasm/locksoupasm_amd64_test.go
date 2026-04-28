//go:build amd64 && !purego

package locksoupasm

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// softPEXT24 is a copy of the parent package's pure-Go reference
// implementation, used here as the parity oracle for the assembly
// PEXT24 path. Bit-by-bit compress of x's bits selected by mask.
func softPEXT24(x, mask uint32) uint32 {
	var result uint32
	var outBit uint
	for i := uint(0); i < 24; i++ {
		if (mask>>i)&1 == 1 {
			if (x>>i)&1 == 1 {
				result |= 1 << outBit
			}
			outBit++
		}
	}
	return result
}

// softPDEP24 mirror of the parent package's pure-Go reference. Inverse
// of softPEXT24 under matching mask.
func softPDEP24(v, mask uint32) uint32 {
	var result uint32
	var inBit uint
	for i := uint(0); i < 24; i++ {
		if (mask>>i)&1 == 1 {
			if (v>>inBit)&1 == 1 {
				result |= 1 << i
			}
			inBit++
		}
	}
	return result
}

// makeBalancedMaskTriple produces a balanced (m0, m1, m2) 24-bit mask
// triple from a 64-bit seed via the same combinadic ranking the parent
// package uses. Self-contained reproduction so the test does not depend
// on parent-package internals.
func makeBalancedMaskTriple(seed uint64) (m0, m1, m2 uint32) {
	var binC [25][9]uint64
	for n := 0; n <= 24; n++ {
		binC[n][0] = 1
		for k := 1; k <= 8 && k <= n; k++ {
			binC[n][k] = binC[n-1][k-1] + binC[n-1][k]
		}
	}

	unrank := func(rank uint64, k, n int) uint32 {
		var mask uint32
		for k > 0 {
			c := k - 1
			for c+1 <= n-1 && binC[c+1][k] <= rank {
				c++
			}
			mask |= uint32(1) << uint(c)
			rank -= binC[c][k]
			k--
		}
		return mask
	}

	const product uint64 = 735471 * 12870
	const c168 uint64 = 12870

	idx := seed % product
	idx0 := idx / c168
	idx1 := idx % c168

	m0 = unrank(idx0, 8, 24)
	m1Local := unrank(idx1, 8, 16)

	remaining := uint32(0xFFFFFF) & ^m0
	var posIdx uint
	for bit := uint(0); bit < 24; bit++ {
		if (remaining>>bit)&1 == 1 {
			if (m1Local>>posIdx)&1 == 1 {
				m1 |= uint32(1) << bit
			}
			posIdx++
		}
	}
	m2 = remaining & ^m1
	return
}

// TestChunk24Lock_ParityWithSoftReference verifies that the assembly
// Chunk24Lock matches the pure-Go softPEXT24-based reference across a
// random sample of (x, m0, m1, m2) inputs spanning the mask space.
func TestChunk24Lock_ParityWithSoftReference(t *testing.T) {
	if !HasBMI2 {
		t.Skip("BMI2 not available on this CPU")
	}

	seedBuf := make([]byte, 8)
	for trial := 0; trial < 10000; trial++ {
		if _, err := rand.Read(seedBuf); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		seed := binary.LittleEndian.Uint64(seedBuf)
		m0, m1, m2 := makeBalancedMaskTriple(seed)

		// 24-bit input from the same seed mixed with trial counter.
		x := uint32((seed ^ uint64(trial)*0x9E3779B97F4A7C15) & 0xFFFFFF)

		asmL0, asmL1, asmL2 := Chunk24Lock(x, m0, m1, m2)
		refL0 := softPEXT24(x, m0)
		refL1 := softPEXT24(x, m1)
		refL2 := softPEXT24(x, m2)

		if asmL0 != refL0 || asmL1 != refL1 || asmL2 != refL2 {
			t.Fatalf("trial %d: parity mismatch x=%06x m0=%06x m1=%06x m2=%06x asm=(%02x,%02x,%02x) ref=(%02x,%02x,%02x)",
				trial, x, m0, m1, m2, asmL0, asmL1, asmL2, refL0, refL1, refL2)
		}
	}
}

// TestUnchunk24Lock_ParityWithSoftReference verifies that the assembly
// Unchunk24Lock matches the pure-Go softPDEP24-based reference across
// a random sample of (l0, l1, l2, m0, m1, m2) inputs.
func TestUnchunk24Lock_ParityWithSoftReference(t *testing.T) {
	if !HasBMI2 {
		t.Skip("BMI2 not available on this CPU")
	}

	seedBuf := make([]byte, 8)
	for trial := 0; trial < 10000; trial++ {
		if _, err := rand.Read(seedBuf); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		seed := binary.LittleEndian.Uint64(seedBuf)
		m0, m1, m2 := makeBalancedMaskTriple(seed)

		// Sample lane bytes (8-bit each in low byte of uint32).
		l0 := uint32((seed >> 8) & 0xFF)
		l1 := uint32((seed >> 16) & 0xFF)
		l2 := uint32((seed >> 24) & 0xFF)

		asmX := Unchunk24Lock(l0, l1, l2, m0, m1, m2)
		refX := softPDEP24(l0, m0) | softPDEP24(l1, m1) | softPDEP24(l2, m2)

		if asmX != refX {
			t.Fatalf("trial %d: parity mismatch l=(%02x,%02x,%02x) m=(%06x,%06x,%06x) asm=%06x ref=%06x",
				trial, l0, l1, l2, m0, m1, m2, asmX, refX)
		}
	}
}

// TestChunk24Lock_RoundTrip verifies Chunk24Lock followed by
// Unchunk24Lock recovers the original 24-bit input under the same mask
// triple. End-to-end inverse property of the assembly path.
func TestChunk24Lock_RoundTrip(t *testing.T) {
	if !HasBMI2 {
		t.Skip("BMI2 not available on this CPU")
	}

	seedBuf := make([]byte, 8)
	for trial := 0; trial < 10000; trial++ {
		if _, err := rand.Read(seedBuf); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		seed := binary.LittleEndian.Uint64(seedBuf)
		m0, m1, m2 := makeBalancedMaskTriple(seed)
		x := uint32((seed ^ uint64(trial)*0x9E3779B97F4A7C15) & 0xFFFFFF)

		l0, l1, l2 := Chunk24Lock(x, m0, m1, m2)
		got := Unchunk24Lock(l0, l1, l2, m0, m1, m2)
		if got != x {
			t.Fatalf("trial %d: round-trip failed x=%06x got=%06x", trial, x, got)
		}
	}
}
