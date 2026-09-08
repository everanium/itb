package blake2basm

import (
	"fmt"
	"testing"

	"github.com/everanium/itb/internal/kernelaudit"
)

// blake2basm_entropy_test.go — the input-entropy differential audit
// (internal/kernelaudit) of the fused cascade: every bit of every lane
// buffer, component word, key byte and group index base must reach the
// output, lane for lane, and the kernel must agree with the pure-Go
// cascade (ScalarFusedChain256 / 512 and the scalar fill references) at
// the baseline and after every flip. The helpers drive the single-,
// four- and eight-lane evaluators and the fill hooks of both widths
// through the audit; the per-architecture files apply them to every
// kernel by direct call, and this file applies them to the public
// dispatchers under the current dispatch state.

// auditGroupCounts are the cascade lengths audited: the one-group floor
// and the two- and three-group cascades that exercise the re-seeded
// group path.
var auditGroupCounts = []int{1, 2, 3}

func reportAudit(t *testing.T, lines []string) {
	t.Helper()
	for _, l := range lines {
		t.Error(l)
	}
}

func auditKey256(in *kernelaudit.Inputs) *[32]byte {
	var k [32]byte
	copy(k[:], in.Key)
	return &k
}

func auditKey512(in *kernelaudit.Inputs) *[64]byte {
	var k [64]byte
	copy(k[:], in.Key)
	return &k
}

// ref256 / ref512 evaluate the pure-Go cascade on every lane.
func ref256(in *kernelaudit.Inputs) [][4]uint64 {
	key := auditKey256(in)
	out := make([][4]uint64, len(in.Lanes))
	for l := range in.Lanes {
		out[l] = ScalarFusedChain256(key, in.Comps, in.Lanes[l])
	}
	return out
}

func ref512(in *kernelaudit.Inputs) [][8]uint64 {
	key := auditKey512(in)
	out := make([][8]uint64, len(in.Lanes))
	for l := range in.Lanes {
		out[l] = ScalarFusedChain512(key, in.Comps, in.Lanes[l])
	}
	return out
}

// refFill256x8 / refFill512x4 / refFill512x8 evaluate the pure-Go fill
// cascades.
func refFill256x8(in *kernelaudit.Inputs) [][4]uint64 {
	var out [8][4]uint64
	scalarFill256X8(auditKey256(in), in.Comps, in.Base, &out)
	return out[:]
}

func refFill512x4(in *kernelaudit.Inputs) [][8]uint64 {
	var out [4][8]uint64
	scalarFill512X4(auditKey512(in), in.Comps, in.Base, &out)
	return out[:]
}

func refFill512x8(in *kernelaudit.Inputs) [][8]uint64 {
	var out [8][8]uint64
	scalarFill512X8(auditKey512(in), in.Comps, in.Base, &out)
	return out[:]
}

func audit256X4(t *testing.T, label string, n int, f x4fn256) {
	t.Helper()
	for _, g := range auditGroupCounts {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s 256x4 %s groups=%d", label, shapeName(n), g), KeyBytes: 32, Words: 4 * g, Lanes: 4, N: n}
		reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][4]uint64 {
			var ptrs [4]*byte
			for l := range ptrs {
				ptrs[l] = &in.Lanes[l][0]
			}
			var out [4][4]uint64
			f(auditKey256(in), in.Comps, &ptrs, &out)
			return out[:]
		}, ref256))
	}
}

func audit256X1(t *testing.T, label string, n int, f x1fn256) {
	t.Helper()
	for _, g := range auditGroupCounts {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s 256x1 %s groups=%d", label, shapeName(n), g), KeyBytes: 32, Words: 4 * g, Lanes: 1, N: n}
		reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][4]uint64 {
			var out [4]uint64
			f(auditKey256(in), in.Comps, &in.Lanes[0][0], &out)
			return [][4]uint64{out}
		}, ref256))
	}
}

func audit256X8(t *testing.T, label string, n int, f x8fn256) {
	t.Helper()
	for _, g := range auditGroupCounts {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s 256x8 %s groups=%d", label, shapeName(n), g), KeyBytes: 32, Words: 4 * g, Lanes: 8, N: n}
		reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][4]uint64 {
			var ptrs [8]*byte
			for l := range ptrs {
				ptrs[l] = &in.Lanes[l][0]
			}
			var out [8][4]uint64
			f(auditKey256(in), in.Comps, &ptrs, &out)
			return out[:]
		}, ref256))
	}
}

func audit256Fill8(t *testing.T, label string, f func(*[32]byte, []uint64, uint64, *[8][4]uint64)) {
	t.Helper()
	for _, g := range auditGroupCounts {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s fill256x8 groups=%d", label, g), KeyBytes: 32, Words: 4 * g, Lanes: 8, Base: true}
		reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][4]uint64 {
			var out [8][4]uint64
			f(auditKey256(in), in.Comps, in.Base, &out)
			return out[:]
		}, refFill256x8))
	}
}

func audit512X4(t *testing.T, label string, n int, f x4fn512) {
	t.Helper()
	for _, g := range auditGroupCounts {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s 512x4 %s groups=%d", label, shapeName(n), g), KeyBytes: 64, Words: 8 * g, Lanes: 4, N: n}
		reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][8]uint64 {
			var ptrs [4]*byte
			for l := range ptrs {
				ptrs[l] = &in.Lanes[l][0]
			}
			var out [4][8]uint64
			f(auditKey512(in), in.Comps, &ptrs, &out)
			return out[:]
		}, ref512))
	}
}

func audit512X1(t *testing.T, label string, n int, f x1fn512) {
	t.Helper()
	for _, g := range auditGroupCounts {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s 512x1 %s groups=%d", label, shapeName(n), g), KeyBytes: 64, Words: 8 * g, Lanes: 1, N: n}
		reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][8]uint64 {
			var out [8]uint64
			f(auditKey512(in), in.Comps, &in.Lanes[0][0], &out)
			return [][8]uint64{out}
		}, ref512))
	}
}

func audit512X8(t *testing.T, label string, n int, f x8fn512) {
	t.Helper()
	for _, g := range auditGroupCounts {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s 512x8 %s groups=%d", label, shapeName(n), g), KeyBytes: 64, Words: 8 * g, Lanes: 8, N: n}
		reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][8]uint64 {
			var ptrs [8]*byte
			for l := range ptrs {
				ptrs[l] = &in.Lanes[l][0]
			}
			var out [8][8]uint64
			f(auditKey512(in), in.Comps, &ptrs, &out)
			return out[:]
		}, ref512))
	}
}

func audit512Fill4(t *testing.T, label string, f func(*[64]byte, []uint64, uint64, *[4][8]uint64)) {
	t.Helper()
	for _, g := range auditGroupCounts {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s fill512x4 groups=%d", label, g), KeyBytes: 64, Words: 8 * g, Lanes: 4, Base: true}
		reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][8]uint64 {
			var out [4][8]uint64
			f(auditKey512(in), in.Comps, in.Base, &out)
			return out[:]
		}, refFill512x4))
	}
}

func audit512Fill8(t *testing.T, label string, f fill8fn512) {
	t.Helper()
	for _, g := range auditGroupCounts {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s fill512x8 groups=%d", label, g), KeyBytes: 64, Words: 8 * g, Lanes: 8, Base: true}
		reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][8]uint64 {
			var out [8][8]uint64
			f(auditKey512(in), in.Comps, in.Base, &out)
			return out[:]
		}, refFill512x8))
	}
}

// auditDispatchers runs the audit over every public dispatcher and fill
// hook under the current dispatch state.
func auditDispatchers(t *testing.T, label string) {
	t.Helper()
	for _, n := range Shapes {
		audit256X4(t, label, n, dispatchers256x4()[n])
		audit256X1(t, label, n, dispatchers256x1()[n])
		audit512X4(t, label, n, dispatchers512x4()[n])
		audit512X1(t, label, n, dispatchers512x1()[n])
	}
	for _, n := range []int{20, 36, 68} {
		audit256X8(t, label, n, dispatchers256x8()[n])
		audit512X8(t, label, n, dispatchers512x8()[n])
	}
	audit256Fill8(t, label, Fused256Fill13x8)
	audit512Fill4(t, label, Fused512Fill13x4)
	audit512Fill8(t, label, Fused512Fill13x8)
}

// TestInputEntropyDispatchersAuto audits the dispatchers under the
// build's auto-selected dispatch state.
func TestInputEntropyDispatchersAuto(t *testing.T) {
	auditDispatchers(t, "dispatch-auto")
}
