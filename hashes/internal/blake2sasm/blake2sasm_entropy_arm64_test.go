//go:build arm64 && !purego && !noitbasm

package blake2sasm

import "testing"

// blake2sasm_entropy_arm64_test.go — the input-entropy differential
// audit of every arm64 kernel by direct call: the four-lane NEON
// kernels and the single-lane GPR kernels.
func TestInputEntropyKernelsArm64(t *testing.T) {
	if !FusedHasNEON {
		t.Skip("requires Advanced SIMD")
	}
	for _, n := range Shapes {
		audit256X4(t, "neon", n, neon256x4[n])
		audit256X1(t, "gpr", n, kernels256x1[n])
	}
}
