package itb_test

import (
	"fmt"
	"testing"

	"github.com/everanium/itb/hashes"
)

// BenchmarkAESITBBatchedArm compares the aesitb128 batched arm (4-lane
// chain-absorb kernel) against four calls of the single arm on the same
// inputs, per per-pixel shape. Bytes/op = 4 × shape.
func BenchmarkAESITBBatchedArm(b *testing.B) {
	single, batched, _, err := hashes.Make128Pair(hashes.CipherAESITB128, aesitbParityKey[:])
	if err != nil {
		b.Fatal(err)
	}
	for _, n := range []int{13, 20, 36, 68} {
		var lanes [4][]byte
		for i := range lanes {
			lanes[i] = aesitbParityData(n)
		}
		seeds := [4][2]uint64{{1, 2}, {3, 4}, {5, 6}, {7, 8}}
		b.Run(fmt.Sprintf("single4/shape%d", n), func(b *testing.B) {
			b.SetBytes(int64(4 * n))
			b.ReportAllocs()
			var sink uint64
			for i := 0; i < b.N; i++ {
				for l := 0; l < 4; l++ {
					lo, _ := single(lanes[l], seeds[l][0]^uint64(i), seeds[l][1])
					sink ^= lo
				}
			}
			_ = sink
		})
		b.Run(fmt.Sprintf("batched/shape%d", n), func(b *testing.B) {
			b.SetBytes(int64(4 * n))
			b.ReportAllocs()
			var sink uint64
			for i := 0; i < b.N; i++ {
				seeds[0][0] = uint64(i)
				out := batched(&lanes, seeds)
				sink ^= out[0][0]
			}
			_ = sink
		})
	}
}
