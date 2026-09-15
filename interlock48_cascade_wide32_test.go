package itb

import (
	"bytes"
	"sync/atomic"
	"testing"
)

// interlock48_cascade_wide32_test.go — the batch-32 rung of the
// Interlocked Barrier fill ladder at width 256 (16 groups per call) and
// width 512 (8 groups per call), under synthetic batch-32 hooks: the
// builder arms fillRanksSuper32 exactly when the lockSeed carries the
// hook and neither disarm knob is set, the armed closure reproduces the
// reference cascade on every group, and the worker split / interleave
// with the rung armed produce lanes bit-identical to the batch-16 rung
// and to the sequential arms, round-tripping each other's wire.

// cascadeWide32Case is one width of the batch-32 surface.
type cascadeWide32Case struct {
	label  string
	factor int
	words  int
	groups int // groups per batch-32 call
	// build returns the builder over a lockSeed carrying the batch-16
	// hook and, when wide is set, the batch-32 hook; calls counts the
	// batch-32 hook's invocations.
	build func(t *testing.T, comps []uint64, nonce []byte, wide bool, calls *atomic.Int64) lockBatchPRF48
	ref   func(comps []uint64, nonce []byte, g uint64) []uint64
}

func cascadeWide32Cases() []cascadeWide32Case {
	return []cascadeWide32Case{
		{
			label: "256", factor: 2, words: 4, groups: 16,
			build: func(t *testing.T, comps []uint64, nonce []byte, wide bool, calls *atomic.Int64) lockBatchPRF48 {
				seed, err := SeedFromComponents256(testHash256, comps...)
				if err != nil {
					t.Fatal(err)
				}
				seed.BatchHash = synthBatch256(testHash256)
				seed.SetInterlockBatch16(func(c []uint64, base uint64, out *[8][4]uint64) {
					for i := range out {
						b := cascadeFillBlock(base + uint64(i))
						out[i] = refCascade256(c, b[:])
					}
				})
				if wide {
					seed.SetInterlockBatch32(func(c []uint64, base uint64, out *[16][4]uint64) {
						calls.Add(1)
						for i := range out {
							b := cascadeFillBlock(base + uint64(i))
							out[i] = refCascade256(c, b[:])
						}
					})
				}
				if (seed.InterlockFillX32() != nil) != wide {
					t.Fatalf("InterlockFillX32 attached=%v, want %v", seed.InterlockFillX32() != nil, wide)
				}
				return buildLockBatchPRF48_256(seed, nonce)
			},
			ref: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g)
				out := refCascade256(refLockComps256(comps, nonce), b[:])
				return out[:]
			},
		},
		{
			label: "512", factor: 4, words: 8, groups: 8,
			build: func(t *testing.T, comps []uint64, nonce []byte, wide bool, calls *atomic.Int64) lockBatchPRF48 {
				seed, err := SeedFromComponents512(testHash512, comps...)
				if err != nil {
					t.Fatal(err)
				}
				seed.BatchHash = synthBatch512(testHash512)
				seed.SetInterlockBatch16(func(c []uint64, base uint64, out *[4][8]uint64) {
					for i := range out {
						b := cascadeFillBlock(base + uint64(i))
						out[i] = refCascade512(c, b[:])
					}
				})
				if wide {
					seed.SetInterlockBatch32(func(c []uint64, base uint64, out *[8][8]uint64) {
						calls.Add(1)
						for i := range out {
							b := cascadeFillBlock(base + uint64(i))
							out[i] = refCascade512(c, b[:])
						}
					})
				}
				if (seed.InterlockFillX32() != nil) != wide {
					t.Fatalf("InterlockFillX32 attached=%v, want %v", seed.InterlockFillX32() != nil, wide)
				}
				return buildLockBatchPRF48_512(seed, nonce)
			},
			ref: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g)
				out := refCascade512(refLockComps512(comps, nonce), b[:])
				return out[:]
			},
		},
	}
}

// TestCascadeFillWide32ReferenceParity pins the batch-32 closure of the
// builder: armed exactly when the hook is attached, it reproduces the
// reference cascade on every group of every probe base, and it agrees
// with the batch-16 closure over the same groups.
func TestCascadeFillWide32ReferenceParity(t *testing.T) {
	if fillBatch32Disarmed() {
		t.Skip("a fill-ladder knob disarms the batch-32 hooks")
	}
	nonce := interlock48Nonce()
	for _, wc := range cascadeWide32Cases() {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			for ci, comps := range cascadeLockSeedComponents {
				for _, wide := range []bool{false, true} {
					var calls atomic.Int64
					bp := wc.build(t, comps, nonce, wide, &calls)
					if bp.fillRanksSuper == nil {
						t.Fatal("fillRanksSuper not armed")
					}
					if (bp.fillRanksSuper32 != nil) != wide {
						t.Fatalf("wide=%v: fillRanksSuper32 armed=%v", wide, bp.fillRanksSuper32 != nil)
					}
					if !wide {
						continue
					}
					var scratch lockFillScratch48
					for _, base := range cascadeWideGroups {
						prf := make([]uint64, 2*8*lockBatchFactor48Max)
						bp.fillRanksSuper32(&scratch, base, prf[0:4*superGroups48])
						super := make([]uint64, 8*lockBatchFactor48Max)
						for j := 0; j < wc.groups; j++ {
							got := prf[j*wc.words : (j+1)*wc.words]
							if want := wc.ref(comps, nonce, base+uint64(j)); !wordsEqual(got, want) {
								t.Fatalf("comps %d base=%#x lane %d: fillRanksSuper32 %x != reference %x", ci, base, j, got, want)
							}
						}
						half := wc.groups / 2
						for h := 0; h < 2; h++ {
							bp.fillRanksSuper(&scratch, base+uint64(h*half), super[0:2*superGroups48])
							if !wordsEqual(super[:half*wc.words], prf[h*half*wc.words:(h+1)*half*wc.words]) {
								t.Fatalf("comps %d base=%#x half %d: fillRanksSuper32 and fillRanksSuper disagree", ci, base, h)
							}
						}
					}
					if calls.Load() == 0 {
						t.Fatalf("comps %d: wide build never consulted the batch-32 hook", ci)
					}
				}
			}
		})
	}
}

// TestFillRanksSuper32WideSplitParity is the wiring layer of the
// batch-32 rung: the worker split with fillRanksSuper32 armed must
// produce lane bytes bit-identical to the batch-16 rung and to the
// sequential arms, the armed path must actually run, and every pair of
// encoders and decoders must round-trip each other's lanes.
func TestFillRanksSuper32WideSplitParity(t *testing.T) {
	if fillBatch32Disarmed() {
		t.Skip("a fill-ladder knob disarms the batch-32 hooks")
	}
	nonce := interlock48Nonce()
	for _, wc := range cascadeWide32Cases() {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			var calls atomic.Int64
			wide := wc.build(t, cascadeLockSeedComponents[1], nonce, true, &calls)
			if wide.fillRanksSuper32 == nil {
				t.Fatal("fillRanksSuper32 not armed")
			}
			var wideCalls atomic.Int64
			orig := wide.fillRanksSuper32
			wide.fillRanksSuper32 = func(s *lockFillScratch48, base uint64, prf []uint64) {
				wideCalls.Add(1)
				orig(s, base, prf)
			}
			narrow := wide
			narrow.fillRanksSuper32 = nil
			seq := narrow
			seq.fillRanksSuper = nil
			variants := []struct {
				label string
				bp    lockBatchPRF48
			}{{"batch-32", wide}, {"batch-16", narrow}, {"sequential", seq}}
			for _, sz := range cascadeWideSplitSizes {
				framed := interlock48RandomBytes(sz)
				src := framedSrc48{body: framed}
				M := src.chunkCount()
				wideCalls.Store(0)
				var lanes [3][3][]byte
				for v := range variants {
					for l := range lanes[v] {
						lanes[v][l] = make([]byte, 2*M)
					}
					splitTriple48LockedBatchInto(src, lanes[v][0], lanes[v][1], lanes[v][2], variants[v].bp, nil)
				}
				for v := 1; v < len(variants); v++ {
					for l := 0; l < 3; l++ {
						if !bytes.Equal(lanes[0][l], lanes[v][l]) {
							t.Fatalf("size %d: %s lane %d diverges from %s", sz, variants[0].label, l, variants[v].label)
						}
					}
				}
				// A single-worker range of at least 32 chunks must enter the
				// batch-32 path at least once.
				if M >= 2*superGroups48 && configuredWorkerCount(nil) == 1 && wideCalls.Load() == 0 {
					t.Fatalf("size %d: split never entered the batch-32 path", sz)
				}
				for ei, enc := range variants {
					for _, dec := range variants {
						got := interleaveTriple48LockedBatch(lanes[ei][0], lanes[ei][1], lanes[ei][2], dec.bp, nil)
						if len(got) < len(framed) || !bytes.Equal(got[:len(framed)], framed) {
							t.Fatalf("size %d %s→%s: round-trip mismatch", sz, enc.label, dec.label)
						}
						for i := len(framed); i < len(got); i++ {
							if got[i] != 0 {
								t.Fatalf("size %d %s→%s: non-zero padding byte at %d", sz, enc.label, dec.label, i)
							}
						}
					}
				}
			}
			// The batch-32 path must run on a large input under a single
			// worker regardless of the host's core count, in both directions.
			cfg := &Config{MaxWorkers: 1}
			framed := interlock48RandomBytes(6 * 1024)
			src := framedSrc48{body: framed}
			M := src.chunkCount()
			wideCalls.Store(0)
			p0, p1, p2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
			splitTriple48LockedBatchInto(src, p0, p1, p2, wide, cfg)
			if wideCalls.Load() == 0 {
				t.Fatal("single-worker split never entered the batch-32 path")
			}
			wideCalls.Store(0)
			got := interleaveTriple48LockedBatch(p0, p1, p2, wide, cfg)
			if wideCalls.Load() == 0 {
				t.Fatal("single-worker interleave never entered the batch-32 path")
			}
			if !bytes.Equal(got[:len(framed)], framed) {
				t.Fatal("single-worker round-trip mismatch")
			}
		})
	}
}

// TestCascadeFillWide32DisarmKnobs pins the fill-ladder knobs on the
// wide widths: ITB_FORCE_INTERLOCK_PRF_FILL_X16 leaves the batch-16 rung
// armed and the batch-32 rung off, _X4 leaves the four-lane arm as the
// top rung, _X1 and _SEQ disarm every batched rung, and with no knob set
// every rung is armed.
func TestCascadeFillWide32DisarmKnobs(t *testing.T) {
	nonce := interlock48Nonce()
	knobs := []string{"ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", "ITB_FORCE_INTERLOCK_PRF_FILL_X1", "ITB_FORCE_INTERLOCK_PRF_FILL_X4", "ITB_FORCE_INTERLOCK_PRF_FILL_X16"}
	for _, wc := range cascadeWide32Cases() {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			var calls atomic.Int64
			check := func(set string, x4, b16, b32 bool) {
				t.Helper()
				for _, k := range knobs {
					if k == set {
						t.Setenv(k, "1")
					} else {
						t.Setenv(k, "")
					}
				}
				bp := wc.build(t, cascadeLockSeedComponents[0], nonce, true, &calls)
				if (bp.fillRanksX4 != nil) != x4 || (bp.fillRanksSuper != nil) != b16 || (bp.fillRanksSuper32 != nil) != b32 {
					t.Fatalf("%s: four-lane armed=%v batch-16 armed=%v batch-32 armed=%v, want %v/%v/%v", set,
						bp.fillRanksX4 != nil, bp.fillRanksSuper != nil, bp.fillRanksSuper32 != nil, x4, b16, b32)
				}
			}
			check("ITB_FORCE_INTERLOCK_PRF_FILL_X16", true, true, false)
			check("ITB_FORCE_INTERLOCK_PRF_FILL_X4", true, false, false)
			check("ITB_FORCE_INTERLOCK_PRF_FILL_X1", false, false, false)
			check("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", false, false, false)
			check("", true, true, true)
		})
	}
}
