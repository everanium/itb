//go:build arm64 && !purego && !noitbasm

package aesitbasm

import (
	"fmt"
	"testing"

	aes "github.com/jedisct1/go-aes"
)

func neonKernels() map[int]kernelFn {
	return map[int]kernelFn{
		13: aesITB128ChainAbsorb13x4NeonAsm,
		20: aesITB128ChainAbsorb20x4NeonAsm,
		36: aesITB128ChainAbsorb36x4NeonAsm,
		68: aesITB128ChainAbsorb68x4NeonAsm,
	}
}

// TestKernelParityNeon calls the NEON kernels directly against the
// pure-Go reference on every shape.
func TestKernelParityNeon(t *testing.T) {
	if !aes.CPU.HasARMCrypto {
		t.Skip("requires the ARM crypto extension")
	}
	for n, kernel := range neonKernels() {
		t.Run(shapeName(n), func(t *testing.T) {
			runKernelParity(t, "neon", n, kernel)
		})
	}
}

// BenchmarkTier times the NEON kernels per shape by direct call.
func BenchmarkTier(b *testing.B) {
	if !aes.CPU.HasARMCrypto {
		b.Skip("requires the ARM crypto extension")
	}
	for _, n := range shapes {
		kernel := neonKernels()[n]
		b.Run(fmt.Sprintf("neon/shape%d", n), func(b *testing.B) {
			benchKernel(b, n, kernel)
		})
	}
}
