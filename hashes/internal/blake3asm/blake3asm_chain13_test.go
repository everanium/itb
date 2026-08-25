//go:build amd64 && !purego && !noitbasm

package blake3asm

import (
	"crypto/rand"
	"testing"
)

// TestBlake3256ChainAbsorb13x4 verifies the Interlocked Barrier PRF
// fill kernel matches the real BLAKE3 keyed-hash reference across the
// standard case matrix at the 13-byte shape.
func TestBlake3256ChainAbsorb13x4(t *testing.T) {
	runChainAbsorb256Test(t, "Blake3256ChainAbsorb13x4", 13, Blake3256ChainAbsorb13x4)
}

// TestScalarBatch256ChainAbsorb13_Parity verifies the scalar 4-lane
// fallback at the 13-byte shape.
func TestScalarBatch256ChainAbsorb13_Parity(t *testing.T) {
	runScalarBatch256Test(t, "scalarBatch256ChainAbsorb13", 13, scalarBatch256ChainAbsorb13)
}

// TestBlake3256ChainAbsorb13x4_BitSensitivity flips each of the 104
// bits of the 13-byte input (per lane) and requires that lane's
// digest to change — confirming all 13 fill bytes reach the output.
func TestBlake3256ChainAbsorb13x4_BitSensitivity(t *testing.T) {
	if !HasAVX512Fused {
		t.Skip("requires AVX-512 fused path")
	}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	var seeds [4][4]uint64
	for lane := 0; lane < 4; lane++ {
		var sb [32]byte
		if _, err := rand.Read(sb[:]); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 4; i++ {
			for b := 0; b < 8; b++ {
				seeds[lane][i] |= uint64(sb[i*8+b]) << (8 * b)
			}
		}
	}
	base := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		base[i] = make([]byte, 13)
		if _, err := rand.Read(base[i]); err != nil {
			t.Fatal(err)
		}
	}
	run := func(d [][]byte) [4][8]uint32 {
		var dp [4]*byte
		for i := 0; i < 4; i++ {
			dp[i] = &d[i][0]
		}
		var out [4][8]uint32
		Blake3256ChainAbsorb13x4(&key, &seeds, &dp, &out)
		return out
	}
	baseOut := run(base)
	for lane := 0; lane < 4; lane++ {
		for bit := 0; bit < 13*8; bit++ {
			flipped := make([][]byte, 4)
			for i := 0; i < 4; i++ {
				flipped[i] = append([]byte(nil), base[i]...)
			}
			flipped[lane][bit/8] ^= 1 << (bit % 8)
			out := run(flipped)
			if out[lane] == baseOut[lane] {
				t.Fatalf("lane %d bit %d flip produced identical digest", lane, bit)
			}
		}
	}
}

func benchChain13(b *testing.B, fused bool) {
	if !HasAVX512Fused {
		b.Skip("requires AVX-512 fused path")
	}
	var key [32]byte
	var seeds [4][4]uint64
	for i := range key {
		key[i] = byte(i)
	}
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 4; i++ {
			seeds[lane][i] = uint64(lane*4+i) + 0xCAFEBABE
		}
	}
	bufs, ptrs := makeLaneData256(13)
	var out [4][8]uint32
	b.ResetTimer()
	if fused {
		for i := 0; i < b.N; i++ {
			Blake3256ChainAbsorb13x4(&key, &seeds, &ptrs, &out)
		}
	} else {
		for i := 0; i < b.N; i++ {
			for lane := 0; lane < 4; lane++ {
				_ = runReferenceClosure256(key, bufs[lane], seeds[lane])
			}
		}
	}
}

func BenchmarkBlake3256ChainAbsorb13x4_Reference(b *testing.B) { benchChain13(b, false) }
func BenchmarkBlake3256ChainAbsorb13x4_Fused(b *testing.B)     { benchChain13(b, true) }
