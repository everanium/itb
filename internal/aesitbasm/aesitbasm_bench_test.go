package aesitbasm

import (
	"fmt"
	"testing"
)

// benchKernel times one (kernel, shape) pair. Bytes/op = 4 lanes × shape
// so MB/s reports absorbed input bandwidth, comparable across shapes.
//
// The seeds vary per call by rotating through a pre-filled ring of seed
// arrays rather than by a store into one array immediately before the
// call: a narrow store directly ahead of the kernel's wide seeds load
// defeats store-to-load forwarding and serialises consecutive calls,
// which measures the harness rather than the kernel. The kernel-level
// figure this benchmark reports is therefore free of that artefact; the
// production call patterns are measured by the *Pix / *Fill benchmarks.
func benchKernel(b *testing.B, n int, kernel kernelFn) {
	key := ascendingKey()
	var ring [8][4][2]uint64
	for i := range ring {
		for lane := range ring[i] {
			ring[i][lane] = [2]uint64{uint64(8*i + 2*lane + 1), uint64(8*i + 2*lane + 2)}
		}
	}
	_, ptrs := makeLaneData(n)
	var out [4][2]uint64
	b.SetBytes(int64(4 * n))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		kernel(&key, &ring[i&7], &ptrs, &out)
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
