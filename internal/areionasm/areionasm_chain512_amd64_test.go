//go:build amd64 && !purego

package areionasm

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
	"unsafe"

	"github.com/jedisct1/go-aes"
)

// referenceAreionSoEM512ChainAbsorb computes the Areion-SoEM-512 4-way
// CBC-MAC chained-absorb digest by replicating the Go closure shape
// from `makeAreionSoEM512HashWithKey`. Reference for fused
// chained-absorb 512 parity tests.
func referenceAreionSoEM512ChainAbsorb(
	fixedKey *[64]byte,
	seeds *[4][8]uint64,
	data [4][]byte,
) [4][8]uint64 {
	const chunkSize = 56
	var keys [4][128]byte
	var states [4][64]byte
	for lane := 0; lane < 4; lane++ {
		copy(keys[lane][:64], fixedKey[:])
		for i := 0; i < 8; i++ {
			binary.LittleEndian.PutUint64(keys[lane][64+i*8:], seeds[lane][i])
		}
		binary.LittleEndian.PutUint64(states[lane][:8], uint64(len(data[lane])))
	}
	commonLen := len(data[0])
	if commonLen <= chunkSize {
		for lane := 0; lane < 4; lane++ {
			copy(states[lane][8:8+len(data[lane])], data[lane])
		}
		runReferenceSoEM512x4(&keys, &states)
	} else {
		for lane := 0; lane < 4; lane++ {
			laneN := chunkSize
			if laneN > len(data[lane]) {
				laneN = len(data[lane])
			}
			copy(states[lane][8:8+laneN], data[lane][0:laneN])
		}
		runReferenceSoEM512x4(&keys, &states)
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
			runReferenceSoEM512x4(&keys, &states)
			off = end
		}
	}
	var out [4][8]uint64
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 8; i++ {
			out[lane][i] = binary.LittleEndian.Uint64(states[lane][i*8:])
		}
	}
	return out
}

// runReferenceSoEM512x4 mirrors the AreionSoEM512 SoEM construction
// against the existing per-half kernels.
func runReferenceSoEM512x4(keys *[4][128]byte, states *[4][64]byte) {
	domainSep := [64]byte{0x01}
	var s1a, s1b, s1c, s1d, s2a, s2b, s2c, s2d aes.Block4
	for lane := 0; lane < 4; lane++ {
		var s1, s2 [64]byte
		for i := 0; i < 64; i++ {
			s1[i] = states[lane][i] ^ keys[lane][i]
			s2[i] = states[lane][i] ^ keys[lane][64+i] ^ domainSep[i]
		}
		copy(s1a[lane*16:lane*16+16], s1[0:16])
		copy(s1b[lane*16:lane*16+16], s1[16:32])
		copy(s1c[lane*16:lane*16+16], s1[32:48])
		copy(s1d[lane*16:lane*16+16], s1[48:64])
		copy(s2a[lane*16:lane*16+16], s2[0:16])
		copy(s2b[lane*16:lane*16+16], s2[16:32])
		copy(s2c[lane*16:lane*16+16], s2[32:48])
		copy(s2d[lane*16:lane*16+16], s2[48:64])
	}
	Areion512Permutex4(&s1a, &s1b, &s1c, &s1d)
	Areion512Permutex4(&s2a, &s2b, &s2c, &s2d)
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 16; i++ {
			states[lane][i] = s1a[lane*16+i] ^ s2a[lane*16+i]
			states[lane][16+i] = s1b[lane*16+i] ^ s2b[lane*16+i]
			states[lane][32+i] = s1c[lane*16+i] ^ s2c[lane*16+i]
			states[lane][48+i] = s1d[lane*16+i] ^ s2d[lane*16+i]
		}
	}
}

// testChainAbsorb512Parity is the shared parity-test body for the
// three Areion512 chained-absorb specialised kernels.
func testChainAbsorb512Parity(
	t *testing.T,
	dataLen int,
	kernelFn func(*[64]byte, *[4][8]uint64, *[4]*byte, *[4][8]uint64),
) {
	if !HasVAESAVX512 {
		t.Skip("requires VAES + AVX-512")
	}
	for trial := 0; trial < 64; trial++ {
		var fixedKey [64]byte
		if _, err := rand.Read(fixedKey[:]); err != nil {
			t.Fatal(err)
		}
		var seeds [4][8]uint64
		var seedBytes [256]byte
		if _, err := rand.Read(seedBytes[:]); err != nil {
			t.Fatal(err)
		}
		seedsBytes := (*[256]byte)(unsafe.Pointer(&seeds))
		copy(seedsBytes[:], seedBytes[:])

		laneData := make([][]byte, 4)
		for i := 0; i < 4; i++ {
			laneData[i] = make([]byte, dataLen)
			if _, err := rand.Read(laneData[i]); err != nil {
				t.Fatal(err)
			}
		}

		var dataSlice [4][]byte
		copy(dataSlice[:], laneData)
		want := referenceAreionSoEM512ChainAbsorb(&fixedKey, &seeds, dataSlice)

		var dataPtrs [4]*byte
		for i := 0; i < 4; i++ {
			dataPtrs[i] = &laneData[i][0]
		}
		var got [4][8]uint64
		kernelFn(&fixedKey, &seeds, &dataPtrs, &got)

		if got != want {
			t.Fatalf("trial %d (dataLen=%d) mismatch\n  got:  %v\n  want: %v",
				trial, dataLen, got, want)
		}
	}
}

func TestAreion512ChainAbsorb20x4_Parity(t *testing.T) {
	testChainAbsorb512Parity(t, 20, Areion512ChainAbsorb20x4)
}

func TestAreion512ChainAbsorb36x4_Parity(t *testing.T) {
	testChainAbsorb512Parity(t, 36, Areion512ChainAbsorb36x4)
}

func TestAreion512ChainAbsorb68x4_Parity(t *testing.T) {
	testChainAbsorb512Parity(t, 68, Areion512ChainAbsorb68x4)
}

// benchChainAbsorb512Reference runs either the reference Go-closure
// path (kernelFn == nil) or the fused ASM kernel for chained-absorb
// 512-bit perf comparisons.
func benchChainAbsorb512Reference(
	b *testing.B,
	dataLen int,
	kernelFn func(*[64]byte, *[4][8]uint64, *[4]*byte, *[4][8]uint64),
) {
	if !HasVAESAVX512 {
		b.Skip("requires VAES + AVX-512")
	}
	var fixedKey [64]byte
	var seeds [4][8]uint64
	for i := 0; i < 64; i++ {
		fixedKey[i] = byte(i)
	}
	for lane := 0; lane < 4; lane++ {
		for i := 0; i < 8; i++ {
			seeds[lane][i] = uint64(lane*8+i) + 0xCAFEBABE
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
			_ = referenceAreionSoEM512ChainAbsorb(&fixedKey, &seeds, dataSlice)
		}
	} else {
		var dataPtrs [4]*byte
		for i := 0; i < 4; i++ {
			dataPtrs[i] = &laneData[i][0]
		}
		var out [4][8]uint64
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			kernelFn(&fixedKey, &seeds, &dataPtrs, &out)
		}
	}
}

func BenchmarkAreion512ChainAbsorb20x4_Reference(b *testing.B) {
	benchChainAbsorb512Reference(b, 20, nil)
}
func BenchmarkAreion512ChainAbsorb20x4_Fused(b *testing.B) {
	benchChainAbsorb512Reference(b, 20, Areion512ChainAbsorb20x4)
}
func BenchmarkAreion512ChainAbsorb36x4_Reference(b *testing.B) {
	benchChainAbsorb512Reference(b, 36, nil)
}
func BenchmarkAreion512ChainAbsorb36x4_Fused(b *testing.B) {
	benchChainAbsorb512Reference(b, 36, Areion512ChainAbsorb36x4)
}
func BenchmarkAreion512ChainAbsorb68x4_Reference(b *testing.B) {
	benchChainAbsorb512Reference(b, 68, nil)
}
func BenchmarkAreion512ChainAbsorb68x4_Fused(b *testing.B) {
	benchChainAbsorb512Reference(b, 68, Areion512ChainAbsorb68x4)
}
