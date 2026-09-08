//go:build arm64 && !purego && !noitbasm

package areionasm

import "testing"

// areionasm_entropy_arm64_test.go — the input-entropy differential audit
// of every NEON kernel by direct call, independent of the dispatch
// flag.

// TestInputEntropyKernelsArm64 audits the four-lane and single-lane NEON
// kernels of every shape at both widths and the eight-lane NEON fill
// kernels of both widths.
func TestInputEntropyKernelsArm64(t *testing.T) {
	if !FusedHasARMAES {
		t.Skip("ARM crypto extension not available")
	}
	for _, n := range Shapes {
		audit256X4(t, "neon", n, neon256x4[n])
		audit256X1(t, "neon", n, neon256x1[n])
		audit512X4(t, "neon", n, neon512x4[n])
		audit512X1(t, "neon", n, neon512x1[n])
	}
	audit256Fill8(t, "neon", neonFill256x8)
	audit512Fill8(t, "neon", neonFill512x8)
}
