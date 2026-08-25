//go:build amd64 && !purego && !noitbasm

package aescmacasm

import (
	"crypto/rand"
	"testing"
)

// TestAESCMAC128ChainAbsorb13x4 verifies the Interlocked Barrier PRF
// fill kernel matches the AES-CMAC reference at the 13-byte shape.
func TestAESCMAC128ChainAbsorb13x4(t *testing.T) {
	runChainAbsorb128Test(t, "AESCMAC128ChainAbsorb13x4", 13, AESCMAC128ChainAbsorb13x4)
}

// TestScalarBatch128ChainAbsorb13_Parity verifies the scalar 4-lane
// fallback at the 13-byte shape.
func TestScalarBatch128ChainAbsorb13_Parity(t *testing.T) {
	runScalarBatchChainAbsorb128Test(t, "scalarBatch128ChainAbsorb13", 13, scalarBatch128ChainAbsorb13)
}

// TestAESCMAC128ChainAbsorb13x4_BitSensitivity flips each of the 104
// bits of the 13-byte input (per lane) and requires that lane's
// digest to change.
func TestAESCMAC128ChainAbsorb13x4_BitSensitivity(t *testing.T) {
	if !HasVAESAVX512 {
		t.Skip("requires VAES + AVX-512")
	}
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	roundKeys := ExpandKeyAES128(key)
	var seeds [4][2]uint64
	for lane := 0; lane < 4; lane++ {
		var sb [16]byte
		if _, err := rand.Read(sb[:]); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
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
	run := func(d [][]byte) [4][2]uint64 {
		var dp [4]*byte
		for i := 0; i < 4; i++ {
			dp[i] = &d[i][0]
		}
		var out [4][2]uint64
		AESCMAC128ChainAbsorb13x4(&roundKeys, &key, &seeds, &dp, &out)
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

func benchAescmac13(b *testing.B, fused bool) {
	if !HasVAESAVX512 {
		b.Skip("requires VAES + AVX-512")
	}
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}
	roundKeys := ExpandKeyAES128(key)
	var seeds [4][2]uint64
	for lane := 0; lane < 4; lane++ {
		seeds[lane][0] = uint64(lane) + 0xCAFEBABE
		seeds[lane][1] = uint64(lane) + 0xDEADBEEF
	}
	bufs, ptrs := makeLaneData128(13)
	var out [4][2]uint64
	b.ResetTimer()
	if fused {
		for i := 0; i < b.N; i++ {
			AESCMAC128ChainAbsorb13x4(&roundKeys, &key, &seeds, &ptrs, &out)
		}
	} else {
		for i := 0; i < b.N; i++ {
			for lane := 0; lane < 4; lane++ {
				_, _ = runReferenceClosure128(key, bufs[lane], seeds[lane][0], seeds[lane][1])
			}
		}
	}
}

func BenchmarkAESCMAC128ChainAbsorb13x4_Reference(b *testing.B) { benchAescmac13(b, false) }
func BenchmarkAESCMAC128ChainAbsorb13x4_Fused(b *testing.B)     { benchAescmac13(b, true) }
