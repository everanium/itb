package aesitbasm

import (
	"fmt"
	"testing"
)

// benchKernel times one (kernel, shape) pair. Bytes/op = 4 lanes × shape
// so MB/s reports absorbed input bandwidth, comparable across shapes.
func benchKernel(b *testing.B, n int, kernel kernelFn) {
	key := ascendingKey()
	seeds := [4][2]uint64{{1, 2}, {3, 4}, {5, 6}, {7, 8}}
	_, ptrs := makeLaneData(n)
	var out [4][2]uint64
	b.SetBytes(int64(4 * n))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seeds[0][0] = uint64(i)
		kernel(&key, &seeds, &ptrs, &out)
	}
}

func BenchmarkScalar(b *testing.B) {
	for _, n := range shapes {
		n := n
		b.Run(fmt.Sprintf("shape%d", n), func(b *testing.B) {
			benchKernel(b, n, func(key *[16]byte, seeds *[4][2]uint64, ptrs *[4]*byte, out *[4][2]uint64) {
				scalarBatch(key, seeds, ptrs, n, out)
			})
		})
	}
}

func BenchmarkDispatch(b *testing.B) {
	dispatch := map[int]kernelFn{
		13: AESITB128ChainAbsorb13x4,
		20: AESITB128ChainAbsorb20x4,
		36: AESITB128ChainAbsorb36x4,
		68: AESITB128ChainAbsorb68x4,
	}
	for _, n := range shapes {
		b.Run(fmt.Sprintf("shape%d", n), func(b *testing.B) {
			benchKernel(b, n, dispatch[n])
		})
	}
}
