//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/jedisct1/go-aes"
)

// referenceAreionSoEM256ChainAbsorb computes the Areion-SoEM-256 4-way
// CBC-MAC chained-absorb digest by replicating the Go closure shape
// from `makeAreionSoEM256HashWithKey`. Used as the reference for
// fused chained-absorb parity tests.
func referenceAreionSoEM256ChainAbsorb(
	fixedKey *[32]byte,
	seeds *[4][4]uint64,
	data [4][]byte,
) [4][4]uint64 {
	const chunkSize = 24
	var keys [4][64]byte
	var states [4][32]byte
	for lane := 0; lane < 4; lane++ {
		copy(keys[lane][:32], fixedKey[:])
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint64(keys[lane][32+i*8:], seeds[lane][i])
		}
		binary.LittleEndian.PutUint64(states[lane][:8], uint64(len(data[lane])))
	}
	commonLen := len(data[0])
	if commonLen <= chunkSize {
		for lane := 0; lane < 4; lane++ {
			copy(states[lane][8:8+len(data[lane])], data[lane])
		}
		runReferenceSoEM256x4(&keys, &states)
	} else {
		for lane := 0; lane < 4; lane++ {
			laneN := chunkSize
			if laneN > len(data[lane]) {
				laneN = len(data[lane])
			}
			copy(states[lane][8:8+laneN], data[lane][0:laneN])
		}
		runReferenceSoEM256x4(&keys, &states)
		off := chunkSize
		for off < commonLen {
			end := off + chunkSize
			if end > commonLen {
				end = commonLen
			}
			for lane := 0; lane < 4; lane++ {
				laneEnd := end
				if laneEnd > len(data[lane]) {
					laneEnd = len(data[lane])
				}
				for i := 0; i < laneEnd-off; i++ {
					states[lane][8+i] ^= data[lane][off+i]
				}
			}
			runReferenceSoEM256x4(&keys, &states)
			off = end
		}
	}
	var out [4][4]uint64
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 4; i++ {
			out[lane][i] = binary.LittleEndian.Uint64(states[lane][i*8:])
		}
	}
	return out
}

// runReferenceSoEM256x4 mirrors the AreionSoEM256 SoEM construction in
// terms of the existing per-half kernels. Computes
// `state = state1' ⊕ state2'` with state1 = state ⊕ key[0..32] and
// state2 = state ⊕ key[32..64] ⊕ d. Writes result back into states.
func runReferenceSoEM256x4(keys *[4][64]byte, states *[4][32]byte) {
	domainSep := [32]byte{0x01}
	var s1b0, s1b1, s2b0, s2b1 aes.Block4
	for lane := 0; lane < 4; lane++ {
		var s1, s2 [32]byte
		for i := 0; i < 32; i++ {
			s1[i] = states[lane][i] ^ keys[lane][i]
			s2[i] = states[lane][i] ^ keys[lane][32+i] ^ domainSep[i]
		}
		copy(s1b0[lane*16:lane*16+16], s1[0:16])
		copy(s1b1[lane*16:lane*16+16], s1[16:32])
		copy(s2b0[lane*16:lane*16+16], s2[0:16])
		copy(s2b1[lane*16:lane*16+16], s2[16:32])
	}
	Areion256Permutex4(&s1b0, &s1b1)
	Areion256Permutex4(&s2b0, &s2b1)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 16; i++ {
			states[lane][i] = s1b0[lane*16+i] ^ s2b0[lane*16+i]
			states[lane][16+i] = s1b1[lane*16+i] ^ s2b1[lane*16+i]
		}
	}
}

// BenchmarkAreion256ChainAbsorb20x4_Reference / _Fused — same shape
// as the 36x4 benchmarks below, scaled to the 20-byte single-round case.
func BenchmarkAreion256ChainAbsorb20x4_Reference(b *testing.B) {
	benchChainAbsorbReference(b, 20, nil)
}

func BenchmarkAreion256ChainAbsorb20x4_Fused(b *testing.B) {
	benchChainAbsorbReference(b, 20, Areion256ChainAbsorb20x4)
}

func BenchmarkAreion256ChainAbsorb68x4_Reference(b *testing.B) {
	benchChainAbsorbReference(b, 68, nil)
}

func BenchmarkAreion256ChainAbsorb68x4_Fused(b *testing.B) {
	benchChainAbsorbReference(b, 68, Areion256ChainAbsorb68x4)
}

// benchChainAbsorbReference runs either the reference Go-closure path
// (kernelFn == nil) or the fused ASM kernel for chained-absorb perf
// comparisons. Identical input synthesis to keep the comparison fair.
func benchChainAbsorbReference(
	b *testing.B,
	dataLen int,
	kernelFn func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64),
) {
	if !HasVAESAVX512 {
		b.Skip("requires VAES + AVX-512")
	}
	var fixedKey [32]byte
	var seeds [4][4]uint64
	for i := 0; i < 32; i++ {
		fixedKey[i] = byte(i)
	}
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 4; i++ {
			seeds[lane][i] = uint64(lane*4+i) + 0xCAFEBABE
		}
	}
	laneData := make([][]byte, 4)
	for i := 0; i < 4; i++ {
		laneData[i] = make([]byte, dataLen)
		for j := 0; j < dataLen; j++ {
			laneData[i][j] = byte(i*dataLen + j)
		}
	}
	if kernelFn == nil {
		var dataSlice [4][]byte
		copy(dataSlice[:], laneData)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = referenceAreionSoEM256ChainAbsorb(&fixedKey, &seeds, dataSlice)
		}
	} else {
		var dataPtrs [4]*byte
		for i := 0; i < 4; i++ {
			dataPtrs[i] = &laneData[i][0]
		}
		var out [4][4]uint64
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			kernelFn(&fixedKey, &seeds, &dataPtrs, &out)
		}
	}
}

// BenchmarkAreion256ChainAbsorb36x4_Reference measures the reference
// Go-closure path (key/state setup + 2× AreionSoEM256x4 + unpack).
func BenchmarkAreion256ChainAbsorb36x4_Reference(b *testing.B) {
	if !HasVAESAVX512 {
		b.Skip("requires VAES + AVX-512")
	}
	var fixedKey [32]byte
	var seeds [4][4]uint64
	var dataBuf [4][36]byte
	for i := 0; i < 32; i++ {
		fixedKey[i] = byte(i)
	}
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 4; i++ {
			seeds[lane][i] = uint64(lane*4+i) + 0xCAFEBABE
		}
		for i := 0; i < 36; i++ {
			dataBuf[lane][i] = byte(lane*36 + i)
		}
	}
	dataSlice := [4][]byte{dataBuf[0][:], dataBuf[1][:], dataBuf[2][:], dataBuf[3][:]}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = referenceAreionSoEM256ChainAbsorb(&fixedKey, &seeds, dataSlice)
	}
}

// BenchmarkAreion256ChainAbsorb36x4_Fused measures the fused chained-
// absorb VAES kernel.
func BenchmarkAreion256ChainAbsorb36x4_Fused(b *testing.B) {
	if !HasVAESAVX512 {
		b.Skip("requires VAES + AVX-512")
	}
	var fixedKey [32]byte
	var seeds [4][4]uint64
	var dataBuf [4][36]byte
	for i := 0; i < 32; i++ {
		fixedKey[i] = byte(i)
	}
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 4; i++ {
			seeds[lane][i] = uint64(lane*4+i) + 0xCAFEBABE
		}
		for i := 0; i < 36; i++ {
			dataBuf[lane][i] = byte(lane*36 + i)
		}
	}
	dataPtrs := [4]*byte{&dataBuf[0][0], &dataBuf[1][0], &dataBuf[2][0], &dataBuf[3][0]}
	var out [4][4]uint64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Areion256ChainAbsorb36x4(&fixedKey, &seeds, &dataPtrs, &out)
	}
}

// TestAreion256ChainAbsorb36x4_Parity verifies the fused 36-byte
// chained-absorb kernel matches the reference Go-closure output across
// 64 random trials.
func TestAreion256ChainAbsorb36x4_Parity(t *testing.T) {
	testChainAbsorbParity(t, 36, Areion256ChainAbsorb36x4)
}

// TestAreion256ChainAbsorb20x4_Parity verifies the fused 20-byte
// (single-round) kernel.
func TestAreion256ChainAbsorb20x4_Parity(t *testing.T) {
	testChainAbsorbParity(t, 20, Areion256ChainAbsorb20x4)
}

// TestAreion256ChainAbsorb68x4_Parity verifies the fused 68-byte
// (3-round) kernel.
func TestAreion256ChainAbsorb68x4_Parity(t *testing.T) {
	testChainAbsorbParity(t, 68, Areion256ChainAbsorb68x4)
}

// testChainAbsorbParity is the shared body for the three chained-
// absorb parity tests. dataLen ∈ {20, 36, 68}; kernelFn is the
// matching specialised ASM kernel.
func testChainAbsorbParity(
	t *testing.T,
	dataLen int,
	kernelFn func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64),
) {
	if !HasVAESAVX512 {
		t.Skip("requires VAES + AVX-512")
	}
	for trial := 0; trial < 64; trial++ {
		var fixedKey [32]byte
		if _, err := rand.Read(fixedKey[:]); err != nil {
			t.Fatal(err)
		}
		var seeds [4][4]uint64
		var seedBytes [128]byte
		if _, err := rand.Read(seedBytes[:]); err != nil {
			t.Fatal(err)
		}
		seedsBytes := (*[128]byte)(unsafe.Pointer(&seeds))
		copy(seedsBytes[:], seedBytes[:])

		// Allocate per-lane data slices of the requested length.
		laneData := make([][]byte, 4)
		for i := 0; i < 4; i++ {
			laneData[i] = make([]byte, dataLen)
			if _, err := rand.Read(laneData[i]); err != nil {
				t.Fatal(err)
			}
		}

		// Reference path (Go closure shape).
		var dataSlice [4][]byte
		copy(dataSlice[:], laneData)
		want := referenceAreionSoEM256ChainAbsorb(&fixedKey, &seeds, dataSlice)

		// Fused kernel path.
		var dataPtrs [4]*byte
		for i := 0; i < 4; i++ {
			dataPtrs[i] = &laneData[i][0]
		}
		var got [4][4]uint64
		kernelFn(&fixedKey, &seeds, &dataPtrs, &got)

		if got != want {
			t.Fatalf("trial %d (dataLen=%d) mismatch\n  got:  %v\n  want: %v",
				trial, dataLen, got, want)
		}
	}
}
