//go:build amd64 && !purego && !noitbasm

package blake2basm

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"golang.org/x/sys/cpu"
)

// mkAvx2Fixture256 builds a random 4-lane fixture for the BLAKE2b-256
// AVX2 kernels at the given data length.
func mkAvx2Fixture256(n int) (key [32]byte, seeds [4][4]uint64, data [4][]byte, ptrs [4]*byte) {
	rand.Read(key[:])
	var b [8]byte
	for l := 0; l < 4; l++ {
		for i := 0; i < 4; i++ {
			rand.Read(b[:])
			seeds[l][i] = binary.LittleEndian.Uint64(b[:])
		}
		data[l] = make([]byte, n)
		rand.Read(data[l])
		ptrs[l] = &data[l][0]
	}
	return
}

type kern256 func(*[8]uint64, *[32]byte, *[4][4]uint64, *[4]*byte, *[4][8]uint64)

func TestBlake2b256Avx2Parity(t *testing.T) {
	if !cpu.X86.HasAVX2 {
		t.Skip("no AVX2")
	}
	cases := []struct {
		name string
		n    int
		asm  kern256
		ref  kern256
	}{
		{"13", 13, blake2b256ChainAbsorb13x4Avx2Asm, scalarBatch256ChainAbsorb13},
		{"20", 20, blake2b256ChainAbsorb20x4Avx2Asm, scalarBatch256ChainAbsorb20},
		{"36", 36, blake2b256ChainAbsorb36x4Avx2Asm, scalarBatch256ChainAbsorb36},
		{"68", 68, blake2b256ChainAbsorb68x4Avx2Asm, scalarBatch256ChainAbsorb68},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for iter := 0; iter < 200; iter++ {
				key, seeds, _, ptrs := mkAvx2Fixture256(c.n)
				var got, want [4][8]uint64
				c.asm(&Blake2bIV256Param, &key, &seeds, &ptrs, &got)
				c.ref(&Blake2bIV256Param, &key, &seeds, &ptrs, &want)
				for l := 0; l < 4; l++ {
					for k := 0; k < 4; k++ {
						if got[l][k] != want[l][k] {
							t.Fatalf("lane %d word %d iter %d: got %016x want %016x",
								l, k, iter, got[l][k], want[l][k])
						}
					}
				}
			}
		})
	}
}

func mkAvx2Fixture512(n int) (key [64]byte, seeds [4][8]uint64, ptrs [4]*byte) {
	rand.Read(key[:])
	data := make([][]byte, 4)
	var b [8]byte
	for l := 0; l < 4; l++ {
		for i := 0; i < 8; i++ {
			rand.Read(b[:])
			seeds[l][i] = binary.LittleEndian.Uint64(b[:])
		}
		data[l] = make([]byte, n)
		rand.Read(data[l])
		ptrs[l] = &data[l][0]
	}
	return
}

type kern512 func(*[8]uint64, *[64]byte, *[4][8]uint64, *[4]*byte, *[4][8]uint64)

func TestBlake2b512Avx2Parity(t *testing.T) {
	if !cpu.X86.HasAVX2 {
		t.Skip("no AVX2")
	}
	cases := []struct {
		name string
		n    int
		asm  kern512
		ref  kern512
	}{
		{"13", 13, blake2b512ChainAbsorb13x4Avx2Asm, scalarBatch512ChainAbsorb13},
		{"20", 20, blake2b512ChainAbsorb20x4Avx2Asm, scalarBatch512ChainAbsorb20},
		{"36", 36, blake2b512ChainAbsorb36x4Avx2Asm, scalarBatch512ChainAbsorb36},
		{"68", 68, blake2b512ChainAbsorb68x4Avx2Asm, scalarBatch512ChainAbsorb68},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for iter := 0; iter < 200; iter++ {
				key, seeds, ptrs := mkAvx2Fixture512(c.n)
				var got, want [4][8]uint64
				c.asm(&Blake2bIV512Param, &key, &seeds, &ptrs, &got)
				c.ref(&Blake2bIV512Param, &key, &seeds, &ptrs, &want)
				if got != want {
					t.Fatalf("iter %d: got %016x want %016x", iter, got, want)
				}
			}
		})
	}
}

// TestBlake2bAvx2Dispatch forces HasAVX512Fused off / HasAVX2Fused on
// and drives the public dispatchers, confirming they route to the AVX2
// arm and produce scalar-identical output.
func TestBlake2bAvx2Dispatch(t *testing.T) {
	if !cpu.X86.HasAVX2 {
		t.Skip("no AVX2")
	}
	s512, s2 := HasAVX512Fused, HasAVX2Fused
	defer func() { HasAVX512Fused, HasAVX2Fused = s512, s2 }()
	HasAVX512Fused, HasAVX2Fused = false, true
	for _, n := range []int{13, 20, 36, 68} {
		key, seeds, _, ptrs := mkAvx2Fixture256(n)
		var got, want [4][8]uint64
		switch n {
		case 13:
			Blake2b256ChainAbsorb13x4(&Blake2bIV256Param, &key, &seeds, &ptrs, &got)
		case 20:
			Blake2b256ChainAbsorb20x4(&Blake2bIV256Param, &key, &seeds, &ptrs, &got)
		case 36:
			Blake2b256ChainAbsorb36x4(&Blake2bIV256Param, &key, &seeds, &ptrs, &got)
		case 68:
			Blake2b256ChainAbsorb68x4(&Blake2bIV256Param, &key, &seeds, &ptrs, &got)
		}
		HasAVX2Fused = false
		switch n {
		case 13:
			Blake2b256ChainAbsorb13x4(&Blake2bIV256Param, &key, &seeds, &ptrs, &want)
		case 20:
			Blake2b256ChainAbsorb20x4(&Blake2bIV256Param, &key, &seeds, &ptrs, &want)
		case 36:
			Blake2b256ChainAbsorb36x4(&Blake2bIV256Param, &key, &seeds, &ptrs, &want)
		case 68:
			Blake2b256ChainAbsorb68x4(&Blake2bIV256Param, &key, &seeds, &ptrs, &want)
		}
		HasAVX2Fused = true
		for l := 0; l < 4; l++ {
			for k := 0; k < 4; k++ {
				if got[l][k] != want[l][k] {
					t.Fatalf("n=%d lane %d word %d: avx2 %016x scalar %016x", n, l, k, got[l][k], want[l][k])
				}
			}
		}
	}
}

func BenchmarkBlake2b256Avx220(b *testing.B) {
	key, seeds, _, ptrs := mkAvx2Fixture256(20)
	var out [4][8]uint64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blake2b256ChainAbsorb20x4Avx2Asm(&Blake2bIV256Param, &key, &seeds, &ptrs, &out)
	}
}
func BenchmarkBlake2b256Avx51220(b *testing.B) {
	if !HasAVX512Fused {
		b.Skip("no AVX-512")
	}
	key, seeds, _, ptrs := mkAvx2Fixture256(20)
	var out [4][8]uint64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blake2b256ChainAbsorb20x4Asm(&Blake2bIV256Param, &key, &seeds, &ptrs, &out)
	}
}
