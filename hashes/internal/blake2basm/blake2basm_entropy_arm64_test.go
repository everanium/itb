//go:build arm64 && !purego && !noitbasm

package blake2basm

import "testing"

// blake2basm_entropy_arm64_test.go — the input-entropy differential
// audit of every arm64 kernel by direct call, independent of the
// dispatch flag.

// TestInputEntropyKernelsArm64 audits the four-lane NEON kernels and the
// single-lane GPR kernels of every shape at both widths.
func TestInputEntropyKernelsArm64(t *testing.T) {
	if !FusedHasNEON {
		t.Skip("NEON not available")
	}
	for _, n := range Shapes {
		audit256X4(t, "neon", n, neon256x4[n])
		audit256X1(t, "gpr", n, kernels256x1[n])
		audit512X4(t, "neon", n, neon512x4[n])
		audit512X1(t, "gpr", n, kernels512x1[n])
	}
}
