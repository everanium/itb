// Package kernelaudit is the input-entropy differential audit of the
// fused ChainHash cascade kernels: a kernel is driven through a caller-
// supplied evaluator, every bit of every input the kernel absorbs is
// flipped in turn, and the output must react the way the cascade
// structure dictates. The audit does not consult a reference
// implementation — it establishes that every input bit reaches the
// output, which a parity test against a reference that shares a defect
// (a lane input read at a narrower width than the buffer, a component
// word skipped, a key byte ignored) cannot.
//
// The checks, per evaluation case:
//
//   - every bit of every lane's data buffer flipped alone changes that
//     lane's output and no other lane's (lane isolation);
//   - every bit of every component word, of the key and — for the
//     Interlocked Barrier fill kernels that synthesise their blocks from
//     a group index — of the group index base changes every lane;
//   - the lanes are pairwise distinct on distinct inputs;
//   - rotating the lane buffers by one position rotates the outputs the
//     same way (a kernel reading a lane through the wrong pointer), and
//     for the synthesising fill kernels advancing the base by one shifts
//     the outputs by one lane.
//
// The evaluator receives the inputs by pointer and returns one output
// value per lane; it must declare its output storage fresh on every call
// so a lane the kernel fails to write cannot carry a stale value.
//
// [DifferentialRef] adds a reference evaluator: the kernel must agree
// with it at the baseline and after every flip. The structural checks
// stand on their own — a reference that shares the kernel's defect
// leaves them untouched — and the reference check adds the parity of
// the two under every single-bit perturbation.
package kernelaudit

import (
	"fmt"
	"hash/fnv"
	"math/rand/v2"
)

// Config describes one evaluation case.
type Config struct {
	// Label names the case in failure messages and seeds the input
	// generator, so a failure reproduces run to run.
	Label string
	// KeyBytes is the length of the key buffer (0 when the kernel carries
	// the key inside the component words).
	KeyBytes int
	// Words is the number of component words of the cascade.
	Words int
	// Lanes is the number of output lanes the evaluator returns.
	Lanes int
	// N is the length in bytes of every lane's data buffer; 0 for the
	// fill kernels that synthesise their blocks from the group index.
	N int
	// Base reports whether the kernel takes a group index base.
	Base bool
}

// Inputs is the evaluator's argument set.
type Inputs struct {
	Key   []byte
	Comps []uint64
	Lanes [][]byte
	Base  uint64
}

// Eval evaluates the kernel on the inputs and returns one output per
// lane.
type Eval[O comparable] func(in *Inputs) []O

// report accumulates failures per category: the first few coordinates
// verbatim, the rest as a count.
type report struct {
	label string
	lines []string
	count map[string]int
	shown map[string]int
}

const shownPerCategory = 4

func (r *report) add(category, coordinate string) {
	if r.count == nil {
		r.count = map[string]int{}
		r.shown = map[string]int{}
	}
	r.count[category]++
	if r.shown[category] < shownPerCategory {
		r.shown[category]++
		r.lines = append(r.lines, fmt.Sprintf("%s: %s: %s", r.label, category, coordinate))
	}
}

func (r *report) finish() []string {
	for category, n := range r.count {
		if n > r.shown[category] {
			r.lines = append(r.lines, fmt.Sprintf("%s: %s: %d failures in total", r.label, category, n))
		}
	}
	return r.lines
}

func seedFor(label string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(label))
	return h.Sum64()
}

// Differential runs the audit for one case and returns the failure
// lines (empty when every check holds).
func Differential[O comparable](cfg Config, eval Eval[O]) []string {
	return differential(cfg, eval, nil)
}

// DifferentialRef runs the audit with a reference evaluator alongside:
// at the baseline and after every flip the kernel's output must equal
// the reference's, lane for lane, so a kernel and a reference that
// disagree on any single-bit perturbation are reported as a reference
// divergence in addition to whatever the structural checks find. The
// structural checks run on the kernel's output alone; the reference is
// never consulted for them.
func DifferentialRef[O comparable](cfg Config, eval, ref Eval[O]) []string {
	return differential(cfg, eval, ref)
}

func differential[O comparable](cfg Config, kernel, ref Eval[O]) []string {
	rng := rand.New(rand.NewPCG(seedFor(cfg.Label), 0x9E3779B97F4A7C15))
	r := &report{label: cfg.Label}
	// where names the perturbation in force for the reference check.
	where := "baseline"
	eval := func(in *Inputs) []O {
		out := kernel(in)
		if ref != nil {
			want := ref(in)
			for l := range out {
				if l >= len(want) || out[l] != want[l] {
					r.add("reference divergence", fmt.Sprintf("%s: lane %d differs from the reference", where, l))
				}
			}
		}
		return out
	}
	in := &Inputs{Key: make([]byte, cfg.KeyBytes), Comps: make([]uint64, cfg.Words), Lanes: make([][]byte, cfg.Lanes)}
	for i := range in.Key {
		in.Key[i] = byte(rng.Uint32())
	}
	for i := range in.Comps {
		in.Comps[i] = rng.Uint64()
	}
	for l := range in.Lanes {
		in.Lanes[l] = make([]byte, cfg.N)
		for i := range in.Lanes[l] {
			in.Lanes[l][i] = byte(rng.Uint32())
		}
	}
	in.Base = rng.Uint64()

	baseline := eval(in)
	if len(baseline) != cfg.Lanes {
		return []string{fmt.Sprintf("%s: evaluator returned %d lanes, want %d", cfg.Label, len(baseline), cfg.Lanes)}
	}
	// Distinct inputs, distinct lanes.
	if cfg.N > 0 || cfg.Base {
		for a := 0; a < cfg.Lanes; a++ {
			for b := a + 1; b < cfg.Lanes; b++ {
				if baseline[a] == baseline[b] {
					r.add("lane collision", fmt.Sprintf("lanes %d and %d agree on distinct inputs", a, b))
				}
			}
		}
	}
	// A flip of one shared input must move every lane.
	allMove := func(category, coordinate string) {
		where = category + " " + coordinate
		out := eval(in)
		for l := range out {
			if out[l] == baseline[l] {
				r.add(category, fmt.Sprintf("%s leaves lane %d unchanged", coordinate, l))
			}
		}
	}
	// Data: the flipped lane moves, the others hold.
	for l := 0; l < cfg.Lanes; l++ {
		for i := 0; i < cfg.N; i++ {
			for b := 0; b < 8; b++ {
				in.Lanes[l][i] ^= 1 << b
				where = fmt.Sprintf("data lane %d byte %d bit %d", l, i, b)
				out := eval(in)
				if out[l] == baseline[l] {
					r.add("data bit ignored", fmt.Sprintf("lane %d byte %d bit %d leaves the lane unchanged", l, i, b))
				}
				for m := range out {
					if m != l && out[m] != baseline[m] {
						r.add("lane isolation", fmt.Sprintf("lane %d byte %d bit %d moves lane %d", l, i, b, m))
					}
				}
				in.Lanes[l][i] ^= 1 << b
			}
		}
	}
	for w := range in.Comps {
		for b := 0; b < 64; b++ {
			in.Comps[w] ^= 1 << b
			allMove("component bit ignored", fmt.Sprintf("word %d bit %d", w, b))
			in.Comps[w] ^= 1 << b
		}
	}
	for i := range in.Key {
		for b := 0; b < 8; b++ {
			in.Key[i] ^= 1 << b
			allMove("key bit ignored", fmt.Sprintf("byte %d bit %d", i, b))
			in.Key[i] ^= 1 << b
		}
	}
	if cfg.Base {
		for b := 0; b < 64; b++ {
			in.Base ^= 1 << b
			allMove("base bit ignored", fmt.Sprintf("bit %d", b))
			in.Base ^= 1 << b
		}
	}
	// Restored inputs reproduce the baseline.
	where = "restored inputs"
	if out := eval(in); !equalLanes(out, baseline) {
		r.add("determinism", "the restored inputs do not reproduce the baseline")
	}
	// Lane rotation.
	if cfg.N > 0 && cfg.Lanes > 1 {
		rotated := make([][]byte, cfg.Lanes)
		for l := range rotated {
			rotated[l] = in.Lanes[(l+1)%cfg.Lanes]
		}
		saved := in.Lanes
		in.Lanes = rotated
		where = "rotated lanes"
		out := eval(in)
		in.Lanes = saved
		for l := range out {
			if out[l] != baseline[(l+1)%cfg.Lanes] {
				r.add("lane rotation", fmt.Sprintf("rotated lane %d does not carry the output of lane %d", l, (l+1)%cfg.Lanes))
			}
		}
	}
	if cfg.Base && cfg.N == 0 && cfg.Lanes > 1 {
		in.Base++
		where = "base+1"
		out := eval(in)
		in.Base--
		for l := 0; l+1 < cfg.Lanes; l++ {
			if out[l] != baseline[l+1] {
				r.add("base shift", fmt.Sprintf("base+1 lane %d does not carry the output of lane %d", l, l+1))
			}
		}
	}
	return r.finish()
}

func equalLanes[O comparable](a, b []O) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
