//go:build amd64 && !purego && !noitbasm

package blake3asm

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"golang.org/x/sys/cpu"
)

func mkAvx2Fixture3(n int) (key [32]byte, seeds [4][4]uint64, ptrs [4]*byte) {
	rand.Read(key[:])
	data := make([][]byte, 4)
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

type kern3 func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][8]uint32)

func TestBlake3256Avx2Parity(t *testing.T) {
	if !cpu.X86.HasAVX2 {
		t.Skip("no AVX2")
	}
	cases := []struct {
		name string
		n    int
		asm  kern3
		ref  kern3
	}{
		{"13", 13, blake3256ChainAbsorb13x4Avx2Asm, scalarBatch256ChainAbsorb13},
		{"20", 20, blake3256ChainAbsorb20x4Avx2Asm, scalarBatch256ChainAbsorb20},
		{"36", 36, blake3256ChainAbsorb36x4Avx2Asm, scalarBatch256ChainAbsorb36},
		{"68", 68, blake3256ChainAbsorb68x4Avx2Asm, scalarBatch256ChainAbsorb68},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for iter := 0; iter < 200; iter++ {
				key, seeds, ptrs := mkAvx2Fixture3(c.n)
				var got, want [4][8]uint32
				c.asm(&key, &seeds, &ptrs, &got)
				c.ref(&key, &seeds, &ptrs, &want)
				if got != want {
					t.Fatalf("iter %d: got %08x want %08x", iter, got, want)
				}
			}
		})
	}
}

func BenchmarkBlake3256Avx220(b *testing.B) {
	key, seeds, ptrs := mkAvx2Fixture3(20)
	var out [4][8]uint32
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blake3256ChainAbsorb20x4Avx2Asm(&key, &seeds, &ptrs, &out)
	}
}
func BenchmarkBlake3256Avx51220(b *testing.B) {
	if !HasAVX512Fused {
		b.Skip("no AVX-512")
	}
	key, seeds, ptrs := mkAvx2Fixture3(20)
	var out [4][8]uint32
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blake3256ChainAbsorb20x4Asm(&key, &seeds, &ptrs, &out)
	}
}
