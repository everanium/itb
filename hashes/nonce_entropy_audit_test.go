package hashes

import (
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/kernelaudit"
)

// nonce_entropy_audit_test.go — the input-entropy differential audit
// (internal/kernelaudit) of every shipped registry entry as the pipeline
// reaches it: the single and batched hash arms of the entry, and every
// fused cascade hook its factories install — the single- and four-lane
// per-pixel evaluators, the eight-lane evaluators and the batch-16 /
// batch-32 Interlocked Barrier fill hooks — at every per-pixel shape
// (the 13-byte fill block and the 20 / 36 / 68-byte nonce-buf shapes of
// the 128 / 256 / 512-bit nonces). Every bit of every lane buffer,
// component word and group index base must reach the output, lane for
// lane, through the closure the pipeline calls — the composition of the
// factory, the kernel dispatcher and the kernel under the dispatch
// state the process runs with (auto, or the ITB_FORCE_* state of the
// environment) — and every hook must agree, at the baseline and after
// every flip, with the sequential cascade over the entry's single arm,
// the reference the seed's sequential loop evaluates. The kernel
// packages audit every kernel by direct call under every tier; this
// file audits the shipped plumbing.

// auditShapes are the per-pixel input lengths every arm and hook is
// audited at.
var auditShapes = []int{13, 20, 36, 68}

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

// refCascade128 / 256 / 512 evaluate the sequential ChainHash cascade
// over a single arm — the loop of Seed128.ChainHash128 and the wider
// counterparts.
func refCascade128(single itb.HashFunc128, comps []uint64, data []byte) [2]uint64 {
	lo, hi := single(data, comps[0], comps[1])
	for i := 2; i+1 < len(comps); i += 2 {
		lo, hi = single(data, comps[i]^lo, comps[i+1]^hi)
	}
	return [2]uint64{lo, hi}
}

func refCascade256(single itb.HashFunc256, comps []uint64, data []byte) [4]uint64 {
	var seed [4]uint64
	copy(seed[:], comps[:4])
	h := single(data, seed)
	for i := 4; i+3 < len(comps); i += 4 {
		for j := range seed {
			seed[j] = comps[i+j] ^ h[j]
		}
		h = single(data, seed)
	}
	return h
}

func refCascade512(single itb.HashFunc512, comps []uint64, data []byte) [8]uint64 {
	var seed [8]uint64
	copy(seed[:], comps[:8])
	h := single(data, seed)
	for i := 8; i+7 < len(comps); i += 8 {
		for j := range seed {
			seed[j] = comps[i+j] ^ h[j]
		}
		h = single(data, seed)
	}
	return h
}

// fillBlockAt is the 13-byte Interlocked Barrier fill block of group
// base+i: [0x03 | LE64(groupIdx) | 4×0x00].
func fillBlockAt(base uint64, i int) []byte {
	blk := make([]byte, 13)
	blk[0] = 0x03
	binary.LittleEndian.PutUint64(blk[1:9], base+uint64(i))
	return blk
}

func lanes4(in *kernelaudit.Inputs) *[4][]byte {
	var l [4][]byte
	copy(l[:], in.Lanes)
	return &l
}

func lanes8(in *kernelaudit.Inputs) *[8][]byte {
	var l [8][]byte
	copy(l[:], in.Lanes)
	return &l
}

// auditEntry128 audits the arms and hooks of a width-128 entry.
func auditEntry128(t *testing.T, spec Spec) {
	t.Helper()
	single, batched, key, err := Make128Pair(spec.Name)
	if err != nil {
		t.Fatal(err)
	}
	ref := func(in *kernelaudit.Inputs) [][2]uint64 {
		out := make([][2]uint64, len(in.Lanes))
		for l := range in.Lanes {
			out[l] = refCascade128(single, in.Comps, in.Lanes[l])
		}
		return out
	}
	refFill := func(in *kernelaudit.Inputs) [][2]uint64 {
		out := make([][2]uint64, 16)
		for i := range out {
			out[i] = refCascade128(single, in.Comps, fillBlockAt(in.Base, i))
		}
		return out
	}
	// The arms: the single arm on its own, the batched arm against four
	// single calls.
	for _, n := range auditShapes {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s single-arm shape%d", spec.Name, n), Words: 2, Lanes: 1, N: n}
		reportAudit(t, kernelaudit.Differential(cfg, func(in *kernelaudit.Inputs) [][2]uint64 {
			lo, hi := single(in.Lanes[0], in.Comps[0], in.Comps[1])
			return [][2]uint64{{lo, hi}}
		}))
		if batched != nil {
			cfg := kernelaudit.Config{Label: fmt.Sprintf("%s batched-arm shape%d", spec.Name, n), Words: 2, Lanes: 4, N: n}
			reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][2]uint64 {
				var seeds [4][2]uint64
				for l := range seeds {
					seeds[l] = [2]uint64{in.Comps[0], in.Comps[1]}
				}
				out := batched(lanes4(in), seeds)
				return out[:]
			}, ref))
		}
	}
	// The hooks.
	var fsingle itb.FusedChainHashFunc128
	var fbatched itb.BatchFusedChainHashFunc128
	if spec.FusedChainHash128 != nil {
		if fsingle, fbatched, err = spec.FusedChainHash128(key); err != nil {
			t.Fatalf("%s: FusedChainHash128: %v", spec.Name, err)
		}
	}
	for _, n := range auditShapes {
		for _, g := range auditGroupCounts {
			if fsingle != nil {
				if _, _, ok := fsingle(make([]uint64, 2*g), make([]byte, n)); ok {
					cfg := kernelaudit.Config{Label: fmt.Sprintf("%s single128 shape%d groups=%d", spec.Name, n, g), Words: 2 * g, Lanes: 1, N: n}
					reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][2]uint64 {
						lo, hi, ok := fsingle(in.Comps, in.Lanes[0])
						if !ok {
							t.Fatalf("%s: single128 declined shape %d", spec.Name, n)
						}
						return [][2]uint64{{lo, hi}}
					}, ref))
				} else {
					t.Logf("%s: single128 declines shape %d", spec.Name, n)
				}
			}
			if fbatched != nil {
				var probe [4][]byte
				for l := range probe {
					probe[l] = make([]byte, n)
				}
				if _, ok := fbatched(make([]uint64, 2*g), &probe); ok {
					cfg := kernelaudit.Config{Label: fmt.Sprintf("%s batched128 shape%d groups=%d", spec.Name, n, g), Words: 2 * g, Lanes: 4, N: n}
					reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][2]uint64 {
						out, ok := fbatched(in.Comps, lanes4(in))
						if !ok {
							t.Fatalf("%s: batched128 declined shape %d", spec.Name, n)
						}
						return out[:]
					}, ref))
				} else {
					t.Logf("%s: batched128 declines shape %d", spec.Name, n)
				}
			}
		}
	}
	if spec.InterlockFillBatch16 != nil {
		fill, err := spec.InterlockFillBatch16(key)
		if err != nil {
			t.Fatalf("%s: InterlockFillBatch16: %v", spec.Name, err)
		}
		if fill != nil {
			for _, g := range auditGroupCounts {
				cfg := kernelaudit.Config{Label: fmt.Sprintf("%s fill16x128 groups=%d", spec.Name, g), Words: 2 * g, Lanes: 16, Base: true}
				reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][2]uint64 {
					var out [16][2]uint64
					fill(in.Comps, in.Base, &out)
					return out[:]
				}, refFill))
			}
		} else {
			t.Logf("%s: no batch-16 fill hook under this dispatch state", spec.Name)
		}
	}
}

// auditEntry256 audits the arms and hooks of a width-256 entry.
func auditEntry256(t *testing.T, spec Spec) {
	t.Helper()
	single, batched, key, err := Make256Pair(spec.Name)
	if err != nil {
		t.Fatal(err)
	}
	ref := func(in *kernelaudit.Inputs) [][4]uint64 {
		out := make([][4]uint64, len(in.Lanes))
		for l := range in.Lanes {
			out[l] = refCascade256(single, in.Comps, in.Lanes[l])
		}
		return out
	}
	refFillN := func(lanes int) kernelaudit.Eval[[4]uint64] {
		return func(in *kernelaudit.Inputs) [][4]uint64 {
			out := make([][4]uint64, lanes)
			for i := range out {
				out[i] = refCascade256(single, in.Comps, fillBlockAt(in.Base, i))
			}
			return out
		}
	}
	for _, n := range auditShapes {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s single-arm shape%d", spec.Name, n), Words: 4, Lanes: 1, N: n}
		reportAudit(t, kernelaudit.Differential(cfg, func(in *kernelaudit.Inputs) [][4]uint64 {
			var seed [4]uint64
			copy(seed[:], in.Comps)
			return [][4]uint64{single(in.Lanes[0], seed)}
		}))
		if batched != nil {
			cfg := kernelaudit.Config{Label: fmt.Sprintf("%s batched-arm shape%d", spec.Name, n), Words: 4, Lanes: 4, N: n}
			reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][4]uint64 {
				var seeds [4][4]uint64
				for l := range seeds {
					copy(seeds[l][:], in.Comps)
				}
				out := batched(lanes4(in), seeds)
				return out[:]
			}, ref))
		}
	}
	var fsingle itb.FusedChainHashFunc256
	var fbatched itb.BatchFusedChainHashFunc256
	var wide itb.BatchFusedChainHashFunc256x8
	if spec.FusedChainHash256 != nil {
		if fsingle, fbatched, err = spec.FusedChainHash256(key); err != nil {
			t.Fatalf("%s: FusedChainHash256: %v", spec.Name, err)
		}
	}
	if spec.FusedChainHash256x8 != nil {
		if wide, err = spec.FusedChainHash256x8(key); err != nil {
			t.Fatalf("%s: FusedChainHash256x8: %v", spec.Name, err)
		}
	}
	for _, n := range auditShapes {
		for _, g := range auditGroupCounts {
			if fsingle != nil {
				if _, ok := fsingle(make([]uint64, 4*g), make([]byte, n)); ok {
					cfg := kernelaudit.Config{Label: fmt.Sprintf("%s single256 shape%d groups=%d", spec.Name, n, g), Words: 4 * g, Lanes: 1, N: n}
					reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][4]uint64 {
						out, ok := fsingle(in.Comps, in.Lanes[0])
						if !ok {
							t.Fatalf("%s: single256 declined shape %d", spec.Name, n)
						}
						return [][4]uint64{out}
					}, ref))
				} else {
					t.Logf("%s: single256 declines shape %d", spec.Name, n)
				}
			}
			if fbatched != nil {
				var probe [4][]byte
				for l := range probe {
					probe[l] = make([]byte, n)
				}
				if _, ok := fbatched(make([]uint64, 4*g), &probe); ok {
					cfg := kernelaudit.Config{Label: fmt.Sprintf("%s batched256 shape%d groups=%d", spec.Name, n, g), Words: 4 * g, Lanes: 4, N: n}
					reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][4]uint64 {
						out, ok := fbatched(in.Comps, lanes4(in))
						if !ok {
							t.Fatalf("%s: batched256 declined shape %d", spec.Name, n)
						}
						return out[:]
					}, ref))
				} else {
					t.Logf("%s: batched256 declines shape %d", spec.Name, n)
				}
			}
			if wide != nil {
				var probe [8][]byte
				for l := range probe {
					probe[l] = make([]byte, n)
				}
				if _, ok := wide(make([]uint64, 4*g), &probe); ok {
					cfg := kernelaudit.Config{Label: fmt.Sprintf("%s wide256 shape%d groups=%d", spec.Name, n, g), Words: 4 * g, Lanes: 8, N: n}
					reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][4]uint64 {
						out, ok := wide(in.Comps, lanes8(in))
						if !ok {
							t.Fatalf("%s: wide256 declined shape %d", spec.Name, n)
						}
						return out[:]
					}, ref))
				} else {
					t.Logf("%s: wide256 declines shape %d", spec.Name, n)
				}
			}
		}
	}
	if spec.InterlockFillBatch16x256 != nil {
		fill, err := spec.InterlockFillBatch16x256(key)
		if err != nil {
			t.Fatalf("%s: InterlockFillBatch16x256: %v", spec.Name, err)
		}
		if fill != nil {
			for _, g := range auditGroupCounts {
				cfg := kernelaudit.Config{Label: fmt.Sprintf("%s fill16x256 groups=%d", spec.Name, g), Words: 4 * g, Lanes: 8, Base: true}
				reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][4]uint64 {
					var out [8][4]uint64
					fill(in.Comps, in.Base, &out)
					return out[:]
				}, refFillN(8)))
			}
		} else {
			t.Logf("%s: no batch-16 fill hook under this dispatch state", spec.Name)
		}
	}
	if spec.InterlockFillBatch32x256 != nil {
		fill, err := spec.InterlockFillBatch32x256(key)
		if err != nil {
			t.Fatalf("%s: InterlockFillBatch32x256: %v", spec.Name, err)
		}
		if fill != nil {
			for _, g := range auditGroupCounts {
				cfg := kernelaudit.Config{Label: fmt.Sprintf("%s fill32x256 groups=%d", spec.Name, g), Words: 4 * g, Lanes: 16, Base: true}
				reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][4]uint64 {
					var out [16][4]uint64
					fill(in.Comps, in.Base, &out)
					return out[:]
				}, refFillN(16)))
			}
		} else {
			t.Logf("%s: no batch-32 fill hook under this dispatch state", spec.Name)
		}
	}
}

// auditEntry512 audits the arms and hooks of a width-512 entry.
func auditEntry512(t *testing.T, spec Spec) {
	t.Helper()
	single, batched, key, err := Make512Pair(spec.Name)
	if err != nil {
		t.Fatal(err)
	}
	ref := func(in *kernelaudit.Inputs) [][8]uint64 {
		out := make([][8]uint64, len(in.Lanes))
		for l := range in.Lanes {
			out[l] = refCascade512(single, in.Comps, in.Lanes[l])
		}
		return out
	}
	refFillN := func(lanes int) kernelaudit.Eval[[8]uint64] {
		return func(in *kernelaudit.Inputs) [][8]uint64 {
			out := make([][8]uint64, lanes)
			for i := range out {
				out[i] = refCascade512(single, in.Comps, fillBlockAt(in.Base, i))
			}
			return out
		}
	}
	for _, n := range auditShapes {
		cfg := kernelaudit.Config{Label: fmt.Sprintf("%s single-arm shape%d", spec.Name, n), Words: 8, Lanes: 1, N: n}
		reportAudit(t, kernelaudit.Differential(cfg, func(in *kernelaudit.Inputs) [][8]uint64 {
			var seed [8]uint64
			copy(seed[:], in.Comps)
			return [][8]uint64{single(in.Lanes[0], seed)}
		}))
		if batched != nil {
			cfg := kernelaudit.Config{Label: fmt.Sprintf("%s batched-arm shape%d", spec.Name, n), Words: 8, Lanes: 4, N: n}
			reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][8]uint64 {
				var seeds [4][8]uint64
				for l := range seeds {
					copy(seeds[l][:], in.Comps)
				}
				out := batched(lanes4(in), seeds)
				return out[:]
			}, ref))
		}
	}
	var fsingle itb.FusedChainHashFunc512
	var fbatched itb.BatchFusedChainHashFunc512
	var wide itb.BatchFusedChainHashFunc512x8
	if spec.FusedChainHash512 != nil {
		if fsingle, fbatched, err = spec.FusedChainHash512(key); err != nil {
			t.Fatalf("%s: FusedChainHash512: %v", spec.Name, err)
		}
	}
	if spec.FusedChainHash512x8 != nil {
		if wide, err = spec.FusedChainHash512x8(key); err != nil {
			t.Fatalf("%s: FusedChainHash512x8: %v", spec.Name, err)
		}
	}
	for _, n := range auditShapes {
		for _, g := range auditGroupCounts {
			if fsingle != nil {
				if _, ok := fsingle(make([]uint64, 8*g), make([]byte, n)); ok {
					cfg := kernelaudit.Config{Label: fmt.Sprintf("%s single512 shape%d groups=%d", spec.Name, n, g), Words: 8 * g, Lanes: 1, N: n}
					reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][8]uint64 {
						out, ok := fsingle(in.Comps, in.Lanes[0])
						if !ok {
							t.Fatalf("%s: single512 declined shape %d", spec.Name, n)
						}
						return [][8]uint64{out}
					}, ref))
				} else {
					t.Logf("%s: single512 declines shape %d", spec.Name, n)
				}
			}
			if fbatched != nil {
				var probe [4][]byte
				for l := range probe {
					probe[l] = make([]byte, n)
				}
				if _, ok := fbatched(make([]uint64, 8*g), &probe); ok {
					cfg := kernelaudit.Config{Label: fmt.Sprintf("%s batched512 shape%d groups=%d", spec.Name, n, g), Words: 8 * g, Lanes: 4, N: n}
					reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][8]uint64 {
						out, ok := fbatched(in.Comps, lanes4(in))
						if !ok {
							t.Fatalf("%s: batched512 declined shape %d", spec.Name, n)
						}
						return out[:]
					}, ref))
				} else {
					t.Logf("%s: batched512 declines shape %d", spec.Name, n)
				}
			}
			if wide != nil {
				var probe [8][]byte
				for l := range probe {
					probe[l] = make([]byte, n)
				}
				if _, ok := wide(make([]uint64, 8*g), &probe); ok {
					cfg := kernelaudit.Config{Label: fmt.Sprintf("%s wide512 shape%d groups=%d", spec.Name, n, g), Words: 8 * g, Lanes: 8, N: n}
					reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][8]uint64 {
						out, ok := wide(in.Comps, lanes8(in))
						if !ok {
							t.Fatalf("%s: wide512 declined shape %d", spec.Name, n)
						}
						return out[:]
					}, ref))
				} else {
					t.Logf("%s: wide512 declines shape %d", spec.Name, n)
				}
			}
		}
	}
	if spec.InterlockFillBatch16x512 != nil {
		fill, err := spec.InterlockFillBatch16x512(key)
		if err != nil {
			t.Fatalf("%s: InterlockFillBatch16x512: %v", spec.Name, err)
		}
		if fill != nil {
			for _, g := range auditGroupCounts {
				cfg := kernelaudit.Config{Label: fmt.Sprintf("%s fill16x512 groups=%d", spec.Name, g), Words: 8 * g, Lanes: 4, Base: true}
				reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][8]uint64 {
					var out [4][8]uint64
					fill(in.Comps, in.Base, &out)
					return out[:]
				}, refFillN(4)))
			}
		} else {
			t.Logf("%s: no batch-16 fill hook under this dispatch state", spec.Name)
		}
	}
	if spec.InterlockFillBatch32x512 != nil {
		fill, err := spec.InterlockFillBatch32x512(key)
		if err != nil {
			t.Fatalf("%s: InterlockFillBatch32x512: %v", spec.Name, err)
		}
		if fill != nil {
			for _, g := range auditGroupCounts {
				cfg := kernelaudit.Config{Label: fmt.Sprintf("%s fill32x512 groups=%d", spec.Name, g), Words: 8 * g, Lanes: 8, Base: true}
				reportAudit(t, kernelaudit.DifferentialRef(cfg, func(in *kernelaudit.Inputs) [][8]uint64 {
					var out [8][8]uint64
					fill(in.Comps, in.Base, &out)
					return out[:]
				}, refFillN(8)))
			}
		} else {
			t.Logf("%s: no batch-32 fill hook under this dispatch state", spec.Name)
		}
	}
}

// TestRegistryHooksInputEntropy runs the audit over the arms and every
// fused hook of every shipped registry entry under the process's
// dispatch state.
func TestRegistryHooksInputEntropy(t *testing.T) {
	for _, spec := range Registry {
		spec := spec
		t.Run(spec.Name, func(t *testing.T) {
			switch spec.Width {
			case W128:
				auditEntry128(t, spec)
			case W256:
				auditEntry256(t, spec)
			case W512:
				auditEntry512(t, spec)
			}
		})
	}
}
