package siphashasm

import (
	"fmt"
	"testing"

	"github.com/everanium/itb/internal/kernelaudit"
)

// siphashasm_entropy_test.go — the input-entropy differential audit
// (internal/kernelaudit) of the fused cascade: every bit of every lane
// buffer, component word and group index base must reach the output,
// lane for lane (the SipHash-2-4 key is the first component pair, so
// the component sweep covers it), and the kernel must agree with the
// pure-Go cascade (ScalarFusedChain / scalarFusedX16) at the baseline
// and after every flip. The helpers drive the single-, four-, eight- and
// sixteen-lane evaluators through the audit; the per-architecture files
// apply them to every kernel by direct call, and this file applies them
// to the public dispatchers under the current dispatch state.

// auditPairCounts are the cascade lengths audited: the one- and two-pair
// floor and the five-pair fill cascade of a 512-bit lockSeed.
var auditPairCounts = []int{1, 2, 5}

// refLanes evaluates the pure-Go cascade on every lane.
func refLanes(in *kernelaudit.Inputs) [][2]uint64 {
	out := make([][2]uint64, len(in.Lanes))
	for l := range in.Lanes {
		out[l][0], out[l][1] = ScalarFusedChain(in.Comps, in.Lanes[l])
	}
	return out
}

// refFill evaluates the pure-Go batch-16 fill cascade.
func refFill(in *kernelaudit.Inputs) [][2]uint64 {
	var out [16][2]uint64
	scalarFusedX16(in.Comps, in.Base, &out)
	return out[:]
}

func reportAudit(t *testing.T, lines []string) {
	t.Helper()
	for _, l := range lines {
		t.Error(l)
	}
}

func auditX4(t *testing.T, label string, n int, f fusedX4Fn) {
	t.Helper()
	for _, pairs := range auditPairCounts {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s x4 %s pairs=%d", label, shapeName(n), pairs), Words: 2 * pairs, Lanes: 4, N: n}
		reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][2]uint64 {
			var ptrs [4]*byte
			for l := range ptrs {
				ptrs[l] = &in.Lanes[l][0]
			}
			var out [4][2]uint64
			f(in.Comps, &ptrs, &out)
			return out[:]
		}, refLanes))
	}
}

func auditX1(t *testing.T, label string, n int, f fusedX1Fn) {
	t.Helper()
	for _, pairs := range auditPairCounts {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s x1 %s pairs=%d", label, shapeName(n), pairs), Words: 2 * pairs, Lanes: 1, N: n}
		reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][2]uint64 {
			var out [2]uint64
			f(in.Comps, &in.Lanes[0][0], &out)
			return [][2]uint64{out}
		}, refLanes))
	}
}

func auditX8(t *testing.T, label string, n int, f fusedX8Fn) {
	t.Helper()
	for _, pairs := range auditPairCounts {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s x8 %s pairs=%d", label, shapeName(n), pairs), Words: 2 * pairs, Lanes: 8, N: n}
		reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][2]uint64 {
			var ptrs [8]*byte
			for l := range ptrs {
				ptrs[l] = &in.Lanes[l][0]
			}
			var out [8][2]uint64
			f(in.Comps, &ptrs, &out)
			return out[:]
		}, refLanes))
	}
}

func auditX16(t *testing.T, label string, f fusedX16Fn) {
	t.Helper()
	for _, pairs := range auditPairCounts {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s x16 pairs=%d", label, pairs), Words: 2 * pairs, Lanes: 16, Base: true}
		reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][2]uint64 {
			var out [16][2]uint64
			f(in.Comps, in.Base, &out)
			return out[:]
		}, refFill))
	}
}

// auditDispatchers runs the audit over every public dispatcher under the
// current dispatch state.
func auditDispatchers(t *testing.T, label string) {
	t.Helper()
	x4 := map[int]fusedX4Fn{13: FusedChain13x4, 20: FusedChain20x4, 36: FusedChain36x4, 68: FusedChain68x4}
	x1 := map[int]fusedX1Fn{13: FusedChain13x1, 20: FusedChain20x1, 36: FusedChain36x1, 68: FusedChain68x1}
	x8 := map[int]fusedX8Fn{20: FusedChain20x8, 36: FusedChain36x8, 68: FusedChain68x8}
	for _, n := range shapes {
		auditX4(t, label, n, x4[n])
		auditX1(t, label, n, x1[n])
	}
	for _, n := range x8Shapes {
		auditX8(t, label, n, x8[n])
	}
	auditX16(t, label, FusedChain13x16)
}

// TestInputEntropyDispatchersAuto audits the dispatchers under the
// build's auto-selected dispatch state.
func TestInputEntropyDispatchersAuto(t *testing.T) {
	auditDispatchers(t, "dispatch-auto")
}
