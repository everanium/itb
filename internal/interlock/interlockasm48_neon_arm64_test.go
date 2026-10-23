//go:build arm64 && !purego && !noitbasm

package interlock

import (
	"math/rand"
	"runtime"
	"runtime/debug"
	"testing"
	"unsafe"
)

const (
	neonA = uint64(2254848913647) // C(48, 16)
	neonB = uint64(601080390)     // C(32, 16)
)

// refUnrank48 — pure-Go combinatorial unrank restricted to the ranges
// consumed by the kernel (k <= 16, n <= 48), reading the canonical
// crow48Table rather than the kernel's repacked rows. Independent
// oracle for this file's parity tests.
func refUnrank48(rank uint64, k, n int) uint64 {
	var mask uint64
	for k > 0 {
		c := k - 1
		for c+1 <= n-1 && crow48Table[c+1][k] <= rank {
			c++
		}
		mask |= uint64(1) << uint(c)
		rank -= crow48Table[c][k]
		k--
	}
	return mask
}

// refTriple48 — bit-exact scalar reference for RankToMaskTripleUnrank48NEON:
// the two unranks plus the bit-serial remap onto the positions m0
// leaves free.
func refTriple48(idx0 uint64, idx1 uint32) (m0, m1, m2 uint64) {
	m0 = refUnrank48(idx0, 16, 48)
	m1Local := refUnrank48(uint64(idx1), 16, 32)
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	remaining := domain & ^m0
	var posIdx uint
	for bit := uint(0); bit < 48; bit++ {
		if (remaining>>bit)&1 == 1 {
			if (m1Local>>posIdx)&1 == 1 {
				m1 |= uint64(1) << bit
			}
			posIdx++
		}
	}
	m2 = remaining & ^m1
	return
}

func checkTripleLanes(t *testing.T, tag string, idx0 *[8]uint64, idx1 *[8]uint32, out *[3][8]uint64) {
	t.Helper()
	const domain uint64 = 0x0000_FFFF_FFFF_FFFF
	for j := 0; j < 8; j++ {
		e0, e1, e2 := refTriple48(idx0[j], idx1[j])
		if out[0][j] != e0 || out[1][j] != e1 || out[2][j] != e2 {
			t.Fatalf("%s lane=%d idx0=%d idx1=%d:\n got (%012x, %012x, %012x)\nwant (%012x, %012x, %012x)",
				tag, j, idx0[j], idx1[j], out[0][j], out[1][j], out[2][j], e0, e1, e2)
		}
		if out[0][j]|out[1][j]|out[2][j] != domain || out[0][j]&out[1][j] != 0 || out[0][j]&out[2][j] != 0 || out[1][j]&out[2][j] != 0 {
			t.Fatalf("%s lane=%d: triple is not a balanced partition of the domain", tag, j)
		}
		var gotBytes, wantBytes [24]byte
		for i, v := range []uint64{out[0][j], out[1][j], out[2][j]} {
			for b := 0; b < 8; b++ {
				gotBytes[i*8+b] = byte(v >> (8 * b))
			}
		}
		for i, v := range []uint64{e0, e1, e2} {
			for b := 0; b < 8; b++ {
				wantBytes[i*8+b] = byte(v >> (8 * b))
			}
		}
		if gotBytes != wantBytes {
			t.Fatalf("%s lane=%d: byte-level triple divergence", tag, j)
		}
	}
}

// TestRankToMaskTripleUnrank48NEONFixedVectors pins eight lanes covering
// the rank extremes: idx0 = 0 (the bottom combination, which keeps the
// pick count at 0 down to row 15 and exercises the C(15, 16) = 0 pick),
// A-1 (the top combination), B-1, and mid-range values.
func TestRankToMaskTripleUnrank48NEONFixedVectors(t *testing.T) {
	idx0 := [8]uint64{0, 1, neonA / 7, neonA / 3, neonA / 2, 2 * neonA / 3, neonA - 2, neonA - 1}
	idx1 := [8]uint32{uint32(neonB - 1), uint32(neonB / 2), 0, 1, uint32(neonB / 5), uint32(2 * neonB / 3), uint32(neonB - 2), uint32(neonB / 9)}
	var out [3][8]uint64
	RankToMaskTripleUnrank48NEON(&idx0, &idx1, &out)
	checkTripleLanes(t, "fixed", &idx0, &idx1, &out)
	if out[0][0] != 0xFFFF {
		t.Fatalf("lane 0 (idx0 = 0): m0 = %012x, want the bottom 16 positions 0xFFFF", out[0][0])
	}
	if out[0][7] != 0xFFFF_0000_0000 {
		t.Fatalf("lane 7 (idx0 = A-1): m0 = %012x, want the top 16 positions", out[0][7])
	}
}

// TestRankToMaskTripleUnrank48NEONVsScalar sweeps random 8-lane index
// batches through the NEON kernel and compares every lane's triple
// against the scalar refTriple48 reference, value- and byte-level.
func TestRankToMaskTripleUnrank48NEONVsScalar(t *testing.T) {
	rng := rand.New(rand.NewSource(8))
	const N = 10000
	for iter := 0; iter < N; iter++ {
		var idx0 [8]uint64
		var idx1 [8]uint32
		for j := 0; j < 8; j++ {
			idx0[j] = rng.Uint64() % neonA
			idx1[j] = uint32(rng.Uint64() % neonB)
		}
		var out [3][8]uint64
		RankToMaskTripleUnrank48NEON(&idx0, &idx1, &out)
		checkTripleLanes(t, "random", &idx0, &idx1, &out)
	}
}

// TestRankToMaskTripleUnrank48NEONEdgeRanks concentrates on ranks near
// the row boundaries C(p, k), where the pick predicate flips.
func TestRankToMaskTripleUnrank48NEONEdgeRanks(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	var pool []uint64
	for p := 16; p <= 48; p++ {
		c := crow48Table[p][16]
		for _, d := range []int64{-2, -1, 0, 1, 2} {
			v := int64(c) + d
			if v >= 0 && uint64(v) < neonA {
				pool = append(pool, uint64(v))
			}
		}
	}
	for iter := 0; iter < 2000; iter++ {
		var idx0 [8]uint64
		var idx1 [8]uint32
		for j := 0; j < 8; j++ {
			idx0[j] = pool[rng.Intn(len(pool))]
			idx1[j] = uint32(rng.Uint64() % neonB)
		}
		var out [3][8]uint64
		RankToMaskTripleUnrank48NEON(&idx0, &idx1, &out)
		checkTripleLanes(t, "edge", &idx0, &idx1, &out)
	}
}

// BenchmarkRankToMaskTripleUnrank48NEON measures the NEON 8-lane kernel
// against the scalar reference over the same eight lanes (the divmod
// split is caller-side on both paths and excluded here). Reported per
// 8-lane batch.
func BenchmarkRankToMaskTripleUnrank48NEON(b *testing.B) {
	rng := rand.New(rand.NewSource(1))
	var idx0 [8]uint64
	var idx1 [8]uint32
	for j := 0; j < 8; j++ {
		idx0[j] = rng.Uint64() % neonA
		idx1[j] = uint32(rng.Uint64() % neonB)
	}
	var out [3][8]uint64
	b.Run("neon", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			RankToMaskTripleUnrank48NEON(&idx0, &idx1, &out)
		}
	})
	b.Run("scalar", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for j := 0; j < 8; j++ {
				out[0][j], out[1][j], out[2][j] = refTriple48(idx0[j], idx1[j])
			}
		}
	})
}

//go:noescape
func dumpSIMDRegs(dst *[96]uint64, hasAVX512 bool)

//go:noescape
func dirtySIMDRegForTest(masked uint64)

const (
	interlockResidueGap      = 1 << 10
	interlockResiduePad      = 2 << 10
	interlockResidueWindow   = 16 << 10
	interlockResidueSentinel = uint64(0x5A5A5A5A5A5A5A5A)
	interlockSIMDWords       = 96
	interlockStackWords      = interlockResidueWindow / 8
	interlockTotalWords      = interlockStackWords + interlockSIMDWords
)

//go:noinline
func interlockResidueGrow(i int) byte {
	var pad [4 * interlockResidueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
//go:nocheckptr
func interlockResidueProbe(fn func(), res []uint64, regs *[interlockSIMDWords]uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -interlockResidueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = interlockResidueSentinel
	}
	interlockResidueDeep(fn, 0, regs)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func interlockResidueDeep(fn func(), i int, regs *[interlockSIMDWords]uint64) byte {
	var pad [interlockResiduePad]byte
	pad[i] = 1
	dumpSIMDRegs(regs, false)
	fn()
	dumpSIMDRegs(regs, false)
	return pad[(i+7)%len(pad)]
}

//go:noinline
func captureInterlockFrameAndRegResidue(call func(), dst *[interlockTotalWords]uint64) int {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	done := make(chan struct{})
	go func() {
		defer close(done)
		interlockResidueGrow(0)
		var simd [interlockSIMDWords]uint64
		interlockResidueProbe(call, dst[:interlockStackWords], &simd)
		copy(dst[interlockStackWords:], simd[:])
	}()
	<-done
	written := 0
	for i := 0; i < interlockStackWords; i++ {
		if dst[i] != interlockResidueSentinel {
			written++
		}
	}
	return written
}

var interlockSink uint64

//go:noinline
func leakyInterlockFrame(secret uint64, i int) {
	var frame [64]uint64
	for j := range frame {
		frame[j] = secret
	}
	interlockSink = frame[(i+1)%len(frame)]
}

func scanForInterlockWords(window *[interlockTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	for i, w := range window {
		if w == 0 || (i < interlockStackWords && w == interlockResidueSentinel) {
			continue
		}
		for _, t := range targets {
			if t != 0 && w == t {
				return t, i * 8, true
			}
		}
	}
	return 0, 0, false
}

func scanForInterlockWordsInStack(window *[interlockTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	for i := 0; i < interlockStackWords; i++ {
		w := window[i]
		if w == 0 || w == interlockResidueSentinel {
			continue
		}
		for _, t := range targets {
			if t != 0 && w == t {
				return t, i * 8, true
			}
		}
	}
	return 0, 0, false
}

func scanForInterlockWordsInRegs(window *[interlockTotalWords]uint64, targets []uint64) (uint64, int, bool) {
	for i := interlockStackWords; i < len(window); i++ {
		w := window[i]
		if w == 0 {
			continue
		}
		for _, t := range targets {
			if t != 0 && w == t {
				return t, i * 8, true
			}
		}
	}
	return 0, 0, false
}

func TestFusedKernelsLeaveNoSecretInFrame(t *testing.T) {
	res := new([interlockTotalWords]uint64)

	t.Run("NegativeControl_Stack", func(t *testing.T) {
		const canary = uint64(0xCAFEBABE13579BDF)
		idx := 3
		written := captureInterlockFrameAndRegResidue(func() {
			leakyInterlockFrame(canary, idx)
		}, res)
		runtime.KeepAlive(interlockSink)
		if written == 0 {
			t.Fatal("negative control failed: no stack words were written inside the probe window")
		}
		if _, _, found := scanForInterlockWordsInStack(res, []uint64{canary}); !found {
			t.Fatal("negative control failed: stack canary written to callee frame was not observed in stack window")
		}
	})

	t.Run("NegativeControl_SIMDAndGPR", func(t *testing.T) {
		const mask = uint64(0x5555555555555555)
		const secret = uint64(0xFEEDFACECAFEBEEF)
		masked := secret ^ mask
		written := captureInterlockFrameAndRegResidue(func() {
			dirtySIMDRegForTest(masked)
		}, res)
		if written == 0 {
			t.Fatal("negative control failed: no stack words were written inside the probe window")
		}
		if _, _, found := scanForInterlockWordsInRegs(res, []uint64{secret}); !found {
			t.Fatal("negative control failed: register canary left in V2/R12 was not observed by post-RET register dump")
		}
	})

	t.Run("RankToMaskTripleUnrank48NEON", func(t *testing.T) {
		rng := rand.New(rand.NewSource(105))
		idx0 := new([8]uint64)
		idx1 := new([8]uint32)
		out := new([3][8]uint64)
		for j := 0; j < 8; j++ {
			idx0[j] = (rng.Uint64() % (neonA - 256)) + 256
			idx1[j] = uint32((rng.Uint64() % (neonB - 256)) + 256)
		}
		if w := captureInterlockFrameAndRegResidue(func() {
			RankToMaskTripleUnrank48NEON(idx0, idx1, out)
		}, res); w == 0 {
			t.Fatal("RankToMaskTripleUnrank48NEON: probe missed stack window")
		}
		var targets []uint64
		for j := 0; j < 8; j++ {
			targets = append(targets, idx0[j], out[0][j], out[1][j], out[2][j])
		}
		if word, off, found := scanForInterlockWords(res, targets); found {
			t.Fatalf("RankToMaskTripleUnrank48NEON leaked word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
		}
	})

	if HasSVE2Interlock {
		t.Run("Chunk48LockBatchSVE2_And_Unchunk48LockBatchSVE2", func(t *testing.T) {
			rng := rand.New(rand.NewSource(106))
			const n = 8
			src := make([]byte, 6*n)
			dst := make([]byte, 6*n)
			p0 := make([]byte, 2*n)
			p1 := make([]byte, 2*n)
			p2 := make([]byte, 2*n)
			masks := make([][3]uint64, n)
			var targets []uint64
			for j := 0; j < n; j++ {
				for b := 0; b < 6; b++ {
					src[6*j+b] = byte(rng.Uint32() | 1)
				}
				xw := uint64(src[6*j]) | uint64(src[6*j+1])<<8 | uint64(src[6*j+2])<<16 |
					uint64(src[6*j+3])<<24 | uint64(src[6*j+4])<<32 | uint64(src[6*j+5])<<40
				i0 := (rng.Uint64() % (neonA - 256)) + 256
				i1 := uint32((rng.Uint64() % (neonB - 256)) + 256)
				m0, m1, m2 := refTriple48(i0, i1)
				masks[j] = [3]uint64{m0, m1, m2}
				targets = append(targets, xw, m0, m1, m2)
			}
			if w := captureInterlockFrameAndRegResidue(func() {
				chunk48LockBatchSVE2(n, &src[0], &masks[0], &p0[0], &p1[0], &p2[0])
			}, res); w == 0 {
				t.Fatal("chunk48LockBatchSVE2: probe missed stack window")
			}
			if word, off, found := scanForInterlockWords(res, targets); found {
				t.Fatalf("chunk48LockBatchSVE2 leaked word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
			}
			if w := captureInterlockFrameAndRegResidue(func() {
				unchunk48LockBatchSVE2(n, &masks[0], &p0[0], &p1[0], &p2[0], &dst[0])
			}, res); w == 0 {
				t.Fatal("unchunk48LockBatchSVE2: probe missed stack window")
			}
			if word, off, found := scanForInterlockWords(res, targets); found {
				t.Fatalf("unchunk48LockBatchSVE2 leaked word %#016x at offset %d (window=%d)", word, off, interlockResidueWindow)
			}
		})
	}
}
