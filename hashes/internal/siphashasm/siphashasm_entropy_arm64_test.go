//go:build arm64 && !purego && !noitbasm

package siphashasm

import "testing"

// siphashasm_entropy_arm64_test.go — the input-entropy differential
// audit of every arm64 kernel by direct call, independent of the
// dispatch flag.

// TestInputEntropyKernelsArm64 audits the four-lane NEON kernels and the
// single-lane GPR kernels of every shape and the NEON eight-lane fill
// kernel (two calls per batch).
func TestInputEntropyKernelsArm64(t *testing.T) {
	x4, x1 := neonFusedX4(), gprFusedX1()
	for _, n := range shapes {
		auditX4(t, "neon", n, x4[n])
		auditX1(t, "gpr", n, x1[n])
	}
	auditX16(t, "neon-x8", fillX16ViaX8Neon)
}
