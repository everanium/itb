//go:build amd64 && !purego && !noitbasm

package itb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/bits"
	"math/rand"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/everanium/itb/internal/interlock"
)

// interlockArm is one dispatch configuration of the 48-bit interlock
// rank-mask derivation.
type interlockArm struct {
	name                       string
	avx512, avx2, bmi2, use16  bool
	needsAVX512, needsAVX2BMI2 bool
}

func interlockArms() []interlockArm {
	return []interlockArm{
		{"avx512-x16", true, false, true, true, true, false},
		{"avx512-x8x2", true, false, true, false, true, false},
		{"avx2", false, true, true, false, false, true},
		{"scalar", false, false, false, false, false, false},
	}
}

// withInterlockArm installs one arm for the remainder of the test and
// restores the flags the test started with.
func withInterlockArm(t *testing.T, a interlockArm) {
	t.Helper()
	sAVX512, sAVX2, sBMI2, sUse16 := interlock.HasAVX512RankMask, interlock.HasAVX2RankMask, interlock.HasBMI2, interlock.UseUnrank16
	t.Cleanup(func() {
		interlock.HasAVX512RankMask, interlock.HasAVX2RankMask, interlock.HasBMI2, interlock.UseUnrank16 = sAVX512, sAVX2, sBMI2, sUse16
	})
	interlock.HasAVX512RankMask, interlock.HasAVX2RankMask, interlock.HasBMI2, interlock.UseUnrank16 = a.avx512, a.avx2, a.bmi2, a.use16
}

func armRunnable(a interlockArm, hostAVX512, hostAVX2BMI2 bool) bool {
	if a.needsAVX512 && !hostAVX512 {
		return false
	}
	if a.needsAVX2BMI2 && !hostAVX2BMI2 {
		return false
	}
	return true
}

// TestInterlock48ArmsAgree runs the superblock split and interleave
// under every rank-mask arm the host can execute — 16-lane AVX-512,
// two-pass 8-lane AVX-512, AVX2 and scalar — and pins every arm's lane
// bytes to the scalar arm and to the golden digests of
// TestInterlock48LockedLaneGolden, at every width factor and across
// sizes straddling the 16-chunk superblock boundary.
func TestInterlock48ArmsAgree(t *testing.T) {
	hostAVX512 := interlock.HasAVX512RankMask
	hostAVX2BMI2 := interlock.HasAVX2RankMask || (interlock.HasAVX512RankMask && interlock.HasBMI2)
	golden := map[string]map[int]string{
		"128-factor1": {
			144:  "ae946fabd42e89159d4f28d390c098d33f0dfef920d78b9a15ce22f681356c50",
			1000: "8bb7458ad7ca9ad4ad7243277cc5366b8f797c7faa6db476793d0b49d1d98198",
		},
		"256-factor2": {
			144:  "2c835b87ec8835716f7578f542c01c7d93ebc437389e21684ac174170c592e15",
			1000: "8bd1a32af335e88e1e1e3800b3f0159c5bc7099369f3c326b5804548d5cdf83f",
		},
		"512-factor4": {
			144:  "70a7463fd8fdf4ea415247e0eb3f3f55b544e2ba659d2c485088e9f93d4bafe1",
			1000: "df6a2f64090e2d5b9e6cf2a8dfee97f9377f04e03ccff584118d6c14c43ed300",
		},
	}
	sizes := []int{1, 6, 47, 48, 90, 96, 97, 102, 144, 186, 192, 198, 384, 390, 1000, 6 * 257}
	for _, wc := range superTestBuilders(t) {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			// Scalar arm reference per size.
			ref := map[int][3][]byte{}
			func() {
				withInterlockArm(t, interlockArms()[3])
				for _, sz := range sizes {
					src := framedSrc48{body: superTestFixedData(sz)}
					M := src.chunkCount()
					p0, p1, p2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
					splitTriple48LockedBatchInto(src, p0, p1, p2, wc.bp, nil)
					ref[sz] = [3][]byte{p0, p1, p2}
				}
			}()
			for _, a := range interlockArms() {
				a := a
				t.Run(a.name, func(t *testing.T) {
					if !armRunnable(a, hostAVX512, hostAVX2BMI2) {
						t.Skip("arm not executable on this host")
					}
					withInterlockArm(t, a)
					for _, sz := range sizes {
						framed := superTestFixedData(sz)
						src := framedSrc48{body: framed}
						M := src.chunkCount()
						p0, p1, p2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
						splitTriple48LockedBatchInto(src, p0, p1, p2, wc.bp, nil)
						r := ref[sz]
						if !bytes.Equal(p0, r[0]) || !bytes.Equal(p1, r[1]) || !bytes.Equal(p2, r[2]) {
							t.Fatalf("size=%d: arm %s lane bytes diverge from the scalar arm", sz, a.name)
						}
						if want, ok := golden[wc.label][sz]; ok {
							h := sha256.New()
							h.Write(p0)
							h.Write(p1)
							h.Write(p2)
							if got := hex.EncodeToString(h.Sum(nil)); got != want {
								t.Fatalf("size=%d: arm %s golden digest %s, want %s", sz, a.name, got, want)
							}
						}
						out := interleaveTriple48LockedBatch(p0, p1, p2, wc.bp, nil)
						if !bytes.Equal(out[:sz], framed) {
							t.Fatalf("size=%d: arm %s does not round-trip", sz, a.name)
						}
					}
				})
			}
		})
	}
}

// composeRank48 packs (idx0, idx1) into the 128-bit rank pair the
// superblock derivation divides back apart (rank = idx0 · B + idx1 with
// idx0 < A, idx1 < B), so a root-level fixture can land a chunk exactly
// on a combinadic boundary through the production divmod path.
func composeRank48(idx0 uint64, idx1 uint32) (lo, hi uint64) {
	hi, lo = bits.Mul64(idx0, interlockB48)
	var carry uint64
	lo, carry = bits.Add64(lo, uint64(idx1), 0)
	hi += carry
	return lo, hi
}

// unrank16PinFixtures returns the rank fixtures for the superblock
// geometry test: the tier fixture of the tier-parity tests, a
// boundary fixture whose chunks sit on C(p, 16) − 1 / C(p, 16) /
// C(p, 16) + 1 ranks of both unrank loops (the rows where krem = 16
// and krem = 0 share a table slot), and a random 128-bit fixture that
// exercises the full-width divmod.
func unrank16PinFixtures() (out []struct {
	label string
	prf   [2 * superChunks48]uint64
}) {
	var tier [2 * superChunks48]uint64
	for i := range tier {
		lo, hi := tierTestRank(i / 2)
		if i%2 == 0 {
			tier[i] = lo
		} else {
			tier[i] = hi
		}
	}
	out = append(out, struct {
		label string
		prf   [2 * superChunks48]uint64
	}{"tier", tier})

	c := func(p int) uint64 { return binomialC48[p][16] }
	idx0 := [superChunks48]uint64{
		0, c(47) - 1, c(47), c(47) + 1, c(40) - 1, c(40), c(32) - 1, c(32) + 1,
	}
	idx1 := [superChunks48]uint32{
		uint32(c(31) - 1), uint32(c(31)), uint32(c(31) + 1), 0, uint32(c(24) - 1), uint32(c(24)), uint32(c(20) - 1), uint32(c(20) + 1),
	}
	var boundary [2 * superChunks48]uint64
	for j := 0; j < superChunks48; j++ {
		boundary[2*j], boundary[2*j+1] = composeRank48(idx0[j], idx1[j])
	}
	out = append(out, struct {
		label string
		prf   [2 * superChunks48]uint64
	}{"boundary", boundary})

	rng := rand.New(rand.NewSource(0x16))
	var random [2 * superChunks48]uint64
	for i := range random {
		random[i] = rng.Uint64()
	}
	out = append(out, struct {
		label string
		prf   [2 * superChunks48]uint64
	}{"random128", random})
	return out
}

// TestFillLockMasksTriple48SuperUnrank16Pin pins the superblock-wide
// mask derivation at every chunk count 1..superChunks48 under every
// rank-mask arm with the superblock geometry held explicitly: the
// 16-lane kernel (UseUnrank16 on) and the two-pass 8-lane kernel
// (UseUnrank16 off, including the count <= 8 second-pass skip) run as
// separate arms rather than at whichever geometry the host defaults
// to. Every arm is compared to the scalar arm, and the two AVX-512
// geometries are additionally compared to each other lane by lane.
func TestFillLockMasksTriple48SuperUnrank16Pin(t *testing.T) {
	hostAVX512 := interlock.HasAVX512RankMask
	hostAVX2BMI2 := interlock.HasAVX2RankMask || (interlock.HasAVX512RankMask && interlock.HasBMI2)
	for _, fx := range unrank16PinFixtures() {
		fx := fx
		t.Run(fx.label, func(t *testing.T) {
			// Scalar arm reference at every count, checked against the
			// per-rank derivation.
			var want [superChunks48 + 1][superChunks48][3]uint64
			func() {
				withInterlockArm(t, interlockArms()[3])
				for count := 1; count <= superChunks48; count++ {
					prf := fx.prf
					fillLockMasksTriple48Super(&prf, count, &want[count])
					for j := 0; j < count; j++ {
						m0, m1, m2 := rankToMaskTriple48(prf[2*j], prf[2*j+1])
						if want[count][j] != [3]uint64{m0, m1, m2} {
							t.Fatalf("count %d chunk %d: scalar super batch diverges from rankToMaskTriple48", count, j)
						}
					}
				}
			}()
			got := map[string]*[superChunks48 + 1][superChunks48][3]uint64{}
			for _, a := range interlockArms() {
				a := a
				t.Run(a.name, func(t *testing.T) {
					if !armRunnable(a, hostAVX512, hostAVX2BMI2) {
						t.Skip("arm not executable on this host")
					}
					withInterlockArm(t, a)
					if a.avx512 && interlock.UseUnrank16 != a.use16 {
						t.Fatalf("arm %s: UseUnrank16=%v not pinned to %v", a.name, interlock.UseUnrank16, a.use16)
					}
					res := new([superChunks48 + 1][superChunks48][3]uint64)
					for count := 1; count <= superChunks48; count++ {
						prf := fx.prf
						fillLockMasksTriple48Super(&prf, count, &res[count])
						if res[count] != want[count] {
							t.Fatalf("count %d: arm %s diverges from the scalar arm:\n got %#x\nwant %#x",
								count, a.name, res[count], want[count])
						}
					}
					got[a.name] = res
				})
			}
			if x16, x8 := got["avx512-x16"], got["avx512-x8x2"]; x16 != nil && x8 != nil {
				for count := 1; count <= superChunks48; count++ {
					if x16[count] != x8[count] {
						t.Fatalf("count %d: 16-lane and two-pass 8-lane AVX-512 geometries disagree", count)
					}
				}
			}
		})
	}
}

// x4BlockChunkCounts returns chunk counts M at which every worker of
// the superblock split receives at least one full x4 block of groups
// on this host (the block fires only when a worker range spans
// x4Groups groups), including shapes with a block-then-tail worker
// range and — at factors above 1 — a short final group inside a block.
// Sizes are derived from runtime.NumCPU() because the worker split is.
func x4BlockChunkCounts(t *testing.T, factor int) []int {
	t.Helper()
	x4Groups := superChunks48 / factor
	if x4Groups < 4 {
		x4Groups = 4
	}
	base := runtime.NumCPU() * x4Groups * factor
	ms := []int{2 * base, 2*base + 1, 2*base - 1, 3*base + x4Groups*factor/2 + 1, 5*base + 7, 16*base - 1}
	for _, m := range ms {
		numGroups := (m + factor - 1) / factor
		g := runtime.NumCPU()
		if g > numGroups {
			g = numGroups
		}
		groupsPerWorker := (numGroups + g - 1) / g
		if groupsPerWorker < x4Groups {
			t.Fatalf("factor %d M=%d: worker range %d groups < x4 block %d groups; block loop not exercised",
				factor, m, groupsPerWorker, x4Groups)
		}
	}
	return ms
}

// TestInterlock48ArmsAgreeX4Block runs the x4 block path of the
// superblock split and interleave — fillRanksX4 blocks of
// max(superChunks48 / factor, 4) groups, each unranked in
// superChunks48-chunk passes with every lane carrying payload — under
// every rank-mask arm the host can execute, with real batched hash
// arms at 256 / 512 bits and the synthetic 4-lane wrapper at 128 bits.
// Every arm's lane bytes are pinned to the scalar arm with the x4 fill
// disarmed (the per-group fillRanks flush path) and to the sequential
// per-group bp.fill reference, and each arm round-trips its own split.
// The x4 fill is wrapped in a call counter so the block loop is proven
// to have run under every arm rather than inferred from the sizes.
func TestInterlock48ArmsAgreeX4Block(t *testing.T) {
	hostAVX512 := interlock.HasAVX512RankMask
	hostAVX2BMI2 := interlock.HasAVX2RankMask || (interlock.HasAVX512RankMask && interlock.HasBMI2)
	for _, tc := range interlock48X4Cases(t) {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			if tc.bp.fillRanksX4 == nil {
				t.Skip("BatchHash arm unavailable on this host/build — fillRanksX4 not armed")
			}
			type lanes [3][]byte
			var sizes []int
			for _, m := range x4BlockChunkCounts(t, tc.bp.factor) {
				sizes = append(sizes, 6*m, 6*m-3)
			}
			// Fixed inputs, built once, shared by every arm.
			framed := map[int][]byte{}
			for _, sz := range sizes {
				framed[sz] = interlock48RandomBytes(sz)
			}
			// Reference: scalar arm, x4 fill disarmed, cross-checked
			// against the sequential per-group bp.fill reference.
			ref := map[int]lanes{}
			func() {
				withInterlockArm(t, interlockArms()[3])
				scalar := tc.bp
				scalar.fillRanksX4 = nil
				for _, sz := range sizes {
					src := framedSrc48{body: framed[sz]}
					M := src.chunkCount()
					p0, p1, p2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
					splitTriple48LockedBatchInto(src, p0, p1, p2, scalar, nil)
					q0, q1, q2 := refSplitPerGroup48(framed[sz], tc.bp)
					if !bytes.Equal(p0, q0) || !bytes.Equal(p1, q1) || !bytes.Equal(p2, q2) {
						t.Fatalf("size=%d: scalar flush path diverges from the per-group reference", sz)
					}
					ref[sz] = lanes{p0, p1, p2}
				}
			}()
			// Counted x4 fill: the block loop must actually run.
			var x4Calls atomic.Int64
			armed := tc.bp
			origX4 := armed.fillRanksX4
			armed.fillRanksX4 = func(s *lockFillScratch48, groupIdx uint64, prf []uint64) {
				x4Calls.Add(1)
				origX4(s, groupIdx, prf)
			}
			for _, a := range interlockArms() {
				a := a
				t.Run(a.name, func(t *testing.T) {
					if !armRunnable(a, hostAVX512, hostAVX2BMI2) {
						t.Skip("arm not executable on this host")
					}
					withInterlockArm(t, a)
					for _, sz := range sizes {
						x4Calls.Store(0)
						src := framedSrc48{body: framed[sz]}
						M := src.chunkCount()
						p0, p1, p2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
						splitTriple48LockedBatchInto(src, p0, p1, p2, armed, nil)
						if x4Calls.Load() == 0 {
							t.Fatalf("size=%d: arm %s split never entered the x4 block loop", sz, a.name)
						}
						r := ref[sz]
						if !bytes.Equal(p0, r[0]) || !bytes.Equal(p1, r[1]) || !bytes.Equal(p2, r[2]) {
							t.Fatalf("size=%d: arm %s x4-block lane bytes diverge from the scalar flush path", sz, a.name)
						}
						x4Calls.Store(0)
						out := interleaveTriple48LockedBatch(p0, p1, p2, armed, nil)
						if x4Calls.Load() == 0 {
							t.Fatalf("size=%d: arm %s interleave never entered the x4 block loop", sz, a.name)
						}
						if !bytes.Equal(out[:sz], framed[sz]) {
							t.Fatalf("size=%d: arm %s x4-block split does not round-trip", sz, a.name)
						}
						for i := sz; i < len(out); i++ {
							if out[i] != 0 {
								t.Fatalf("size=%d: arm %s non-zero padding byte at %d", sz, a.name, i)
							}
						}
					}
				})
			}
		})
	}
}
