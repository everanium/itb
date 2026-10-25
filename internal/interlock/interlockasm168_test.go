package interlock

import (
	"bytes"
	"math/bits"
	"math/rand"
	"testing"

	"github.com/everanium/itb/internal/cpuid"
)

var (
	testA168 = [3]uint64{0xb93f03fb9f9a2ad8, 0x053d5b033cbb2e27, 0x000000000050afaf}
	testB168 = [2]uint64{0x5bc2bbe1b5e02c78, 0x00001341f080963d}
)

var refCrow168 [169][57][3]uint64

func init() {
	for n := 0; n <= 168; n++ {
		refCrow168[n][0] = [3]uint64{1, 0, 0}
		for k := 1; k <= 56 && k <= n; k++ {
			a := refCrow168[n-1][k-1]
			b := refCrow168[n-1][k]
			s0, c0 := bits.Add64(a[0], b[0], 0)
			s1, c1 := bits.Add64(a[1], b[1], c0)
			s2, _ := bits.Add64(a[2], b[2], c1)
			refCrow168[n][k] = [3]uint64{s0, s1, s2}
		}
	}
}

func u192Gte(a, b [3]uint64) bool {
	if a[2] != b[2] {
		return a[2] > b[2]
	}
	if a[1] != b[1] {
		return a[1] > b[1]
	}
	return a[0] >= b[0]
}

func u192Sub(a, b [3]uint64) [3]uint64 {
	d0, br0 := bits.Sub64(a[0], b[0], 0)
	d1, br1 := bits.Sub64(a[1], b[1], br0)
	d2, _ := bits.Sub64(a[2], b[2], br1)
	return [3]uint64{d0, d1, d2}
}

func u192Add(a, b [3]uint64) [3]uint64 {
	s0, c0 := bits.Add64(a[0], b[0], 0)
	s1, c1 := bits.Add64(a[1], b[1], c0)
	s2, _ := bits.Add64(a[2], b[2], c1)
	return [3]uint64{s0, s1, s2}
}

func refUnrank168(rank [3]uint64, k, n int) [3]uint64 {
	var mask [3]uint64
	krem := k
	for p := n - 1; p >= 0; p-- {
		if krem > 0 && u192Gte(rank, refCrow168[p][krem]) {
			rank = u192Sub(rank, refCrow168[p][krem])
			krem--
			mask[p/64] |= uint64(1) << uint(p%64)
		}
	}
	return mask
}

func refTriple168(idx0 [3]uint64, idx1 [2]uint64) (m0, m1, m2 [3]uint64) {
	m0 = refUnrank168(idx0, 56, 168)
	m1Local := refUnrank168([3]uint64{idx1[0], idx1[1], 0}, 56, 112)
	const dom2 = (uint64(1) << 40) - 1
	u := [3]uint64{^m0[0], ^m0[1], ^m0[2] & dom2}
	var posIdx uint
	for bit := uint(0); bit < 168; bit++ {
		w := bit / 64
		b := bit % 64
		if (u[w]>>b)&1 == 1 {
			mw := posIdx / 64
			mb := posIdx % 64
			if (m1Local[mw]>>mb)&1 == 1 {
				m1[w] |= uint64(1) << b
			}
			posIdx++
		}
	}
	m2[0] = u[0] & ^m1[0]
	m2[1] = u[1] & ^m1[1]
	m2[2] = u[2] & ^m1[2]
	return
}

func softPEXT168Ref(src *[21]byte, m [3]uint64) [7]byte {
	var x [3]uint64
	for i := 0; i < 8; i++ {
		x[0] |= uint64(src[i]) << (8 * i)
		x[1] |= uint64(src[8+i]) << (8 * i)
	}
	for i := 0; i < 5; i++ {
		x[2] |= uint64(src[16+i]) << (8 * i)
	}
	var out, outBit uint64
	for bit := uint(0); bit < 168; bit++ {
		w := bit / 64
		b := bit % 64
		mb := (m[w] >> b) & 1
		xb := (x[w] >> b) & 1
		out |= (mb & xb) << outBit
		outBit += mb
	}
	var lane [7]byte
	for i := 0; i < 7; i++ {
		lane[i] = byte(out >> (8 * i))
	}
	return lane
}

func softPDEP168Ref(lane [7]byte, m [3]uint64) [3]uint64 {
	var v uint64
	for i := 0; i < 7; i++ {
		v |= uint64(lane[i]) << (8 * i)
	}
	var res [3]uint64
	var inBit uint64
	for bit := uint(0); bit < 168; bit++ {
		w := bit / 64
		b := bit % 64
		mb := (m[w] >> b) & 1
		vb := (v >> inBit) & 1
		res[w] |= (mb & vb) << b
		inBit += mb
	}
	return res
}

func softUnchunk168Ref(p0, p1, p2 [7]byte, m0, m1, m2 [3]uint64) [21]byte {
	w0 := softPDEP168Ref(p0, m0)
	w1 := softPDEP168Ref(p1, m1)
	w2 := softPDEP168Ref(p2, m2)
	x0 := w0[0] | w1[0] | w2[0]
	x1 := w0[1] | w1[1] | w2[1]
	x2 := w0[2] | w1[2] | w2[2]
	var dst [21]byte
	for i := 0; i < 8; i++ {
		dst[i] = byte(x0 >> (8 * i))
		dst[8+i] = byte(x1 >> (8 * i))
	}
	for i := 0; i < 5; i++ {
		dst[16+i] = byte(x2 >> (8 * i))
	}
	return dst
}

func randomIdx0_168(rng *rand.Rand) [3]uint64 {
	for {
		w2 := (rng.Uint64() & 0x0000_0000_007F_FFFF) | 1
		w1 := rng.Uint64() | 1
		w0 := rng.Uint64() | 1
		v := [3]uint64{w0, w1, w2}
		if !u192Gte(v, testA168) {
			return v
		}
	}
}

func randomIdx1_168(rng *rand.Rand) [2]uint64 {
	for {
		w1 := (rng.Uint64() & 0x0000_1FFF_FFFF_FFFF) | 1
		w0 := rng.Uint64() | 1
		if w1 < testB168[1] || (w1 == testB168[1] && w0 < testB168[0]) {
			return [2]uint64{w0, w1}
		}
	}
}

func randomTripleMask168(rng *rand.Rand) (m0, m1, m2 [3]uint64) {
	return refTriple168(randomIdx0_168(rng), randomIdx1_168(rng))
}

func TestRefCrow168Constants(t *testing.T) {
	if refCrow168[168][56] != testA168 {
		t.Fatalf("C(168,56) = %x, want %x", refCrow168[168][56], testA168)
	}
	wantB := [3]uint64{testB168[0], testB168[1], 0}
	if refCrow168[112][56] != wantB {
		t.Fatalf("C(112,56) = %x, want %x", refCrow168[112][56], wantB)
	}
}

func checkMaskTriple168Valid(t *testing.T, tag string, lane int, m0, m1, m2 [3]uint64) {
	t.Helper()
	const dom2 = (uint64(1) << 40) - 1
	for i, m := range [3][3]uint64{m0, m1, m2} {
		pop := bits.OnesCount64(m[0]) + bits.OnesCount64(m[1]) + bits.OnesCount64(m[2])
		if pop != 56 {
			t.Fatalf("%s lane=%d mask %d popcount=%d, want 56", tag, lane, i, pop)
		}
		if m[2]&^dom2 != 0 {
			t.Fatalf("%s lane=%d mask %d leaked above bit 167: m[2]=%#x", tag, lane, i, m[2])
		}
	}
	if (m0[0]&m1[0])|(m0[0]&m2[0])|(m1[0]&m2[0]) != 0 ||
		(m0[1]&m1[1])|(m0[1]&m2[1])|(m1[1]&m2[1]) != 0 ||
		(m0[2]&m1[2])|(m0[2]&m2[2])|(m1[2]&m2[2]) != 0 {
		t.Fatalf("%s lane=%d masks are not pairwise disjoint", tag, lane)
	}
	if m0[0]|m1[0]|m2[0] != ^uint64(0) ||
		m0[1]|m1[1]|m2[1] != ^uint64(0) ||
		m0[2]|m1[2]|m2[2] != dom2 {
		t.Fatalf("%s lane=%d masks do not partition the 168-bit domain", tag, lane)
	}
}

// boundaryIdx0Vectors returns the boundary idx0 values covering:
//   - 0 and A168 - 1
//   - Transition p = 134 (3-limb to 2-limb): C(135,56)-1 (rem[2]==1 on entry to p=134),
//     C(135,56), C(134,56)-1, C(134,56)
//   - Transition p = 67 (2-limb to 1-limb): sum_{i=0}^{21} C(68+i, 35+i) + C(68,34) - 1
//     (rem[1]==1 on entry to p=67 with krem=34)
//   - All extreme (z0, z1, z2) popcount distributions:
//     * z0 = 64 (m0_0 == 0): A168 - 1 and C(128,56) - 1
//     * z0 = 8  (m0_0 has 56 bits set): 0
//     * z2 = 0  (m0_2 == 0xFFFFFFFFFF): A168 - 1 and sum_{i=0}^{39} C(128+i, 17+i)
//     * z2 = 40 (m0_2 == 0): 0 and C(128,56) - 1
func boundaryIdx0Vectors() [][3]uint64 {
	one := [3]uint64{1, 0, 0}
	aMinus1 := u192Sub(testA168, one)

	// Transition p = 134 boundaries:
	c135_56 := refCrow168[135][56]
	c135_56_m1 := u192Sub(c135_56, one)
	c134_56 := refCrow168[134][56]
	c134_56_m1 := u192Sub(c134_56, one)

	// Transition p = 67 with krem = 34 and rem[1] == 1:
	var p67Base [3]uint64
	for i := 0; i <= 21; i++ {
		p67Base = u192Add(p67Base, refCrow168[68+i][35+i])
	}
	p67Rem1 := u192Sub(u192Add(p67Base, refCrow168[68][34]), one)
	p67Exact := u192Add(p67Base, refCrow168[68][34])

	// Extreme (z0, z1, z2) = (64, 8, 40): C(128, 56) - 1 (picks bits 127..72).
	c128_56_m1 := u192Sub(refCrow168[128][56], one)

	// Extreme (z0, z1, z2) = (48, 64, 0): sum_{i=0}^{39} C(128+i, 17+i) (picks bits 167..128 and 15..0).
	var z2ZeroMid [3]uint64
	for i := 0; i <= 39; i++ {
		z2ZeroMid = u192Add(z2ZeroMid, refCrow168[128+i][17+i])
	}

	return [][3]uint64{
		{0, 0, 0},
		one,
		aMinus1,
		c135_56_m1,
		c135_56,
		c134_56_m1,
		c134_56,
		p67Rem1,
		p67Exact,
		c128_56_m1,
		z2ZeroMid,
	}
}

func boundaryIdx1Vectors() [][2]uint64 {
	bMinus1 := u192Sub([3]uint64{testB168[0], testB168[1], 0}, [3]uint64{1, 0, 0})
	c68_56 := refCrow168[68][56]
	c68_56_m1 := u192Sub(c68_56, [3]uint64{1, 0, 0})
	c67_56 := refCrow168[67][56]
	c67_56_m1 := u192Sub(c67_56, [3]uint64{1, 0, 0})
	return [][2]uint64{
		{0, 0},
		{1, 0},
		{bMinus1[0], bMinus1[1]},
		{c68_56_m1[0], c68_56_m1[1]},
		{c68_56[0], c68_56[1]},
		{c67_56_m1[0], c67_56_m1[1]},
		{c67_56[0], c67_56[1]},
	}
}

func TestBoundaryVectorsProperties(t *testing.T) {
	i0s := boundaryIdx0Vectors()
	// Verify p=134 transition vector has rem[2] == 1 at entry to p=134 (which is c135_56 - 1).
	if i0s[3][2] != 1 {
		t.Fatalf("C(135,56)-1 limb 2 = %d, want 1", i0s[3][2])
	}
	// Verify p=67 transition vector leaves rem[1] == 1 at entry to p=67.
	rank := i0s[7]
	krem := 56
	for p := 167; p >= 68; p-- {
		if krem > 0 && u192Gte(rank, refCrow168[p][krem]) {
			rank = u192Sub(rank, refCrow168[p][krem])
			krem--
		}
	}
	if krem != 34 || rank[1] != 1 || rank[2] != 0 {
		t.Fatalf("at entry to p=67: krem=%d rank=%x, want krem=34 rank[1]=1", krem, rank)
	}
	// Verify extreme (z0, z1, z2) popcount distributions are all covered.
	var sawZ0_64, sawZ0_8, sawZ2_0, sawZ2_40 bool
	const dom2 = (uint64(1) << 40) - 1
	for _, idx0 := range i0s {
		m0 := refUnrank168(idx0, 56, 168)
		z0 := bits.OnesCount64(^m0[0])
		z2 := bits.OnesCount64(^m0[2] & dom2)
		if z0 == 64 {
			sawZ0_64 = true
		}
		if z0 == 8 {
			sawZ0_8 = true
		}
		if z2 == 0 {
			sawZ2_0 = true
		}
		if z2 == 40 {
			sawZ2_40 = true
		}
	}
	if !sawZ0_64 || !sawZ0_8 || !sawZ2_0 || !sawZ2_40 {
		t.Fatalf("missing extreme z coverage: z0=64:%v z0=8:%v z2=0:%v z2=40:%v",
			sawZ0_64, sawZ0_8, sawZ2_0, sawZ2_40)
	}
}

type rankUnrank168Fn func(idx0 *[3][8]uint64, idx1 *[2][8]uint64, out *[3][3][8]uint64)

func runRankToMaskTripleUnrank168Suite(t *testing.T, name string, fn rankUnrank168Fn) {
	t.Helper()

	t.Run(name+"_Boundaries", func(t *testing.T) {
		i0s := boundaryIdx0Vectors()
		i1s := boundaryIdx1Vectors()
		var pairs [][2]int
		for a := range i0s {
			for b := range i1s {
				pairs = append(pairs, [2]int{a, b})
			}
		}
		for base := 0; base < len(pairs); base += 8 {
			var idx0 [3][8]uint64
			var idx1 [2][8]uint64
			for j := 0; j < 8; j++ {
				p := pairs[(base+j)%len(pairs)]
				v0 := i0s[p[0]]
				v1 := i1s[p[1]]
				idx0[0][j] = v0[0]
				idx0[1][j] = v0[1]
				idx0[2][j] = v0[2]
				idx1[0][j] = v1[0]
				idx1[1][j] = v1[1]
			}
			var out [3][3][8]uint64
			fn(&idx0, &idx1, &out)
			for j := 0; j < 8; j++ {
				v0 := [3]uint64{idx0[0][j], idx0[1][j], idx0[2][j]}
				v1 := [2]uint64{idx1[0][j], idx1[1][j]}
				e0, e1, e2 := refTriple168(v0, v1)
				g0 := [3]uint64{out[0][0][j], out[0][1][j], out[0][2][j]}
				g1 := [3]uint64{out[1][0][j], out[1][1][j], out[1][2][j]}
				g2 := [3]uint64{out[2][0][j], out[2][1][j], out[2][2][j]}
				if g0 != e0 || g1 != e1 || g2 != e2 {
					t.Fatalf("%s boundary base=%d lane=%d idx0=%x idx1=%x:\n got m0=%x m1=%x m2=%x\nwant m0=%x m1=%x m2=%x",
						name, base, j, v0, v1, g0, g1, g2, e0, e1, e2)
				}
				checkMaskTriple168Valid(t, name, j, g0, g1, g2)
			}
		}
	})

	t.Run(name+"_Random10000", func(t *testing.T) {
		rng := rand.New(rand.NewSource(16801))
		const batches = 1250 // 1250 * 8 = 10,000 random lane vectors
		for iter := 0; iter < batches; iter++ {
			var idx0 [3][8]uint64
			var idx1 [2][8]uint64
			for j := 0; j < 8; j++ {
				v0 := randomIdx0_168(rng)
				v1 := randomIdx1_168(rng)
				idx0[0][j] = v0[0]
				idx0[1][j] = v0[1]
				idx0[2][j] = v0[2]
				idx1[0][j] = v1[0]
				idx1[1][j] = v1[1]
			}
			var out [3][3][8]uint64
			fn(&idx0, &idx1, &out)
			for j := 0; j < 8; j++ {
				v0 := [3]uint64{idx0[0][j], idx0[1][j], idx0[2][j]}
				v1 := [2]uint64{idx1[0][j], idx1[1][j]}
				e0, e1, e2 := refTriple168(v0, v1)
				g0 := [3]uint64{out[0][0][j], out[0][1][j], out[0][2][j]}
				g1 := [3]uint64{out[1][0][j], out[1][1][j], out[1][2][j]}
				g2 := [3]uint64{out[2][0][j], out[2][1][j], out[2][2][j]}
				if g0 != e0 || g1 != e1 || g2 != e2 {
					t.Fatalf("%s iter=%d lane=%d idx0=%x idx1=%x:\n got m0=%x m1=%x m2=%x\nwant m0=%x m1=%x m2=%x",
						name, iter, j, v0, v1, g0, g1, g2, e0, e1, e2)
				}
				checkMaskTriple168Valid(t, name, j, g0, g1, g2)
			}
		}
	})
}

func TestRankToMaskTripleUnrank168AVX512(t *testing.T) {
	if !HasAVX512RankMask {
		t.Skip("AVX-512F+BMI2 rank-mask kernel not available")
	}
	runRankToMaskTripleUnrank168Suite(t, "AVX512", RankToMaskTripleUnrank168)
}

func TestRankToMaskTripleUnrank168AVX2(t *testing.T) {
	if !HasBMI2 || !cpuid.AVX2 {
		t.Skip("AVX2+BMI2 rank-mask kernel not available")
	}
	runRankToMaskTripleUnrank168Suite(t, "AVX2", RankToMaskTripleUnrank168AVX2)
}

func TestRankToMaskTripleUnrank168NEON(t *testing.T) {
	if !HasNEONInterlock {
		t.Skip("NEON rank-mask kernel not available")
	}
	runRankToMaskTripleUnrank168Suite(t, "NEON", RankToMaskTripleUnrank168NEON)
}

func TestChunk168LockAndUnchunk168LockVsSoft(t *testing.T) {
	if !HasBMI2 {
		t.Skip("BMI2 per-chunk kernel not available")
	}
	rng := rand.New(rand.NewSource(16802))

	// First test all boundary masks with extreme (z0, z1, z2) popcounts.
	i0s := boundaryIdx0Vectors()
	i1s := boundaryIdx1Vectors()
	for _, v0 := range i0s {
		for _, v1 := range i1s {
			m0, m1, m2 := refTriple168(v0, v1)
			var src [21]byte
			rng.Read(src[:])
			var gotOut [3][7]byte
			Chunk168Lock(&src, m0, m1, m2, &gotOut)
			w0 := softPEXT168Ref(&src, m0)
			w1 := softPEXT168Ref(&src, m1)
			w2 := softPEXT168Ref(&src, m2)
			if gotOut[0] != w0 || gotOut[1] != w1 || gotOut[2] != w2 {
				t.Fatalf("boundary idx0=%x idx1=%x: Chunk168Lock got (%x,%x,%x) want (%x,%x,%x)",
					v0, v1, gotOut[0], gotOut[1], gotOut[2], w0, w1, w2)
			}
			var back [21]byte
			Unchunk168Lock(&gotOut[0], &gotOut[1], &gotOut[2], m0, m1, m2, &back)
			if back != src {
				t.Fatalf("boundary idx0=%x idx1=%x: Unchunk168Lock round-trip got %x want %x",
					v0, v1, back, src)
			}
		}
	}

	// Random 10,000 chunks for forward, inverse on arbitrary lane bytes, and round-trip.
	const N = 10000
	for iter := 0; iter < N; iter++ {
		m0, m1, m2 := randomTripleMask168(rng)
		var src [21]byte
		rng.Read(src[:])
		var gotOut [3][7]byte
		Chunk168Lock(&src, m0, m1, m2, &gotOut)
		w0 := softPEXT168Ref(&src, m0)
		w1 := softPEXT168Ref(&src, m1)
		w2 := softPEXT168Ref(&src, m2)
		if gotOut[0] != w0 || gotOut[1] != w1 || gotOut[2] != w2 {
			t.Fatalf("iter=%d: Chunk168Lock got (%x,%x,%x) want (%x,%x,%x)",
				iter, gotOut[0], gotOut[1], gotOut[2], w0, w1, w2)
		}
		var back [21]byte
		Unchunk168Lock(&gotOut[0], &gotOut[1], &gotOut[2], m0, m1, m2, &back)
		if back != src {
			t.Fatalf("iter=%d: round-trip got %x want %x", iter, back, src)
		}

		// Inverse on independent random 7-byte lanes.
		var r0, r1, r2 [7]byte
		rng.Read(r0[:])
		rng.Read(r1[:])
		rng.Read(r2[:])
		var gotDst [21]byte
		Unchunk168Lock(&r0, &r1, &r2, m0, m1, m2, &gotDst)
		wantDst := softUnchunk168Ref(r0, r1, r2, m0, m1, m2)
		if gotDst != wantDst {
			t.Fatalf("iter=%d: Unchunk168Lock got %x want %x", iter, gotDst, wantDst)
		}
	}
}

func TestChunk168LockBatchAndUnchunk168LockBatch(t *testing.T) {
	if !HasChunk168Batch {
		t.Skip("Chunk168LockBatch not available on this build")
	}
	// Empty batch (n = 0) must be a no-op.
	Chunk168LockBatch(nil, nil, nil, nil, nil)
	Unchunk168LockBatch(nil, nil, nil, nil, nil)

	// Short slices (len < required even if cap >= required) must panic.
	t.Run("ShortSlicePanics", func(t *testing.T) {
		masks := make([][3][3]uint64, 2)
		full21 := make([]byte, 0, 42)
		ok21 := make([]byte, 42)
		full7 := make([]byte, 0, 14)
		ok7 := make([]byte, 14)
		mustPanic := func(name string, fn func()) {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s did not panic on short slice", name)
				}
			}()
			fn()
		}
		mustPanic("Chunk168LockBatch_shortSrc", func() {
			Chunk168LockBatch(full21[:41], masks, ok7, ok7, ok7)
		})
		mustPanic("Chunk168LockBatch_shortP0", func() {
			Chunk168LockBatch(ok21, masks, full7[:13], ok7, ok7)
		})
		mustPanic("Chunk168LockBatch_shortP1", func() {
			Chunk168LockBatch(ok21, masks, ok7, full7[:13], ok7)
		})
		mustPanic("Chunk168LockBatch_shortP2", func() {
			Chunk168LockBatch(ok21, masks, ok7, ok7, full7[:13])
		})
		mustPanic("Unchunk168LockBatch_shortDst", func() {
			Unchunk168LockBatch(ok7, ok7, ok7, masks, full21[:41])
		})
		mustPanic("Unchunk168LockBatch_shortP0", func() {
			Unchunk168LockBatch(full7[:13], ok7, ok7, masks, ok21)
		})
		mustPanic("Unchunk168LockBatch_shortP1", func() {
			Unchunk168LockBatch(ok7, full7[:13], ok7, masks, ok21)
		})
		mustPanic("Unchunk168LockBatch_shortP2", func() {
			Unchunk168LockBatch(ok7, ok7, full7[:13], masks, ok21)
		})
	})

	rng := rand.New(rand.NewSource(16803))
	// Sweep batch widths n = 1..16 across 2,000 random batches.
	const iters = 2000
	for iter := 0; iter < iters; iter++ {
		n := 1 + iter%16
		src := make([]byte, 21*n)
		rng.Read(src)
		masks := make([][3][3]uint64, n)
		wantP0 := make([]byte, 7*n)
		wantP1 := make([]byte, 7*n)
		wantP2 := make([]byte, 7*n)
		for j := 0; j < n; j++ {
			m0, m1, m2 := randomTripleMask168(rng)
			masks[j] = [3][3]uint64{m0, m1, m2}
			var chunk [21]byte
			copy(chunk[:], src[21*j:21*(j+1)])
			l0 := softPEXT168Ref(&chunk, m0)
			l1 := softPEXT168Ref(&chunk, m1)
			l2 := softPEXT168Ref(&chunk, m2)
			copy(wantP0[7*j:7*(j+1)], l0[:])
			copy(wantP1[7*j:7*(j+1)], l1[:])
			copy(wantP2[7*j:7*(j+1)], l2[:])
		}
		gotP0 := make([]byte, 7*n)
		gotP1 := make([]byte, 7*n)
		gotP2 := make([]byte, 7*n)
		Chunk168LockBatch(src, masks, gotP0, gotP1, gotP2)
		if !bytes.Equal(gotP0, wantP0) || !bytes.Equal(gotP1, wantP1) || !bytes.Equal(gotP2, wantP2) {
			t.Fatalf("iter=%d n=%d: Chunk168LockBatch mismatch:\n got (%x, %x, %x)\nwant (%x, %x, %x)",
				iter, n, gotP0, gotP1, gotP2, wantP0, wantP1, wantP2)
		}

		gotBack := make([]byte, 21*n)
		Unchunk168LockBatch(gotP0, gotP1, gotP2, masks, gotBack)
		if !bytes.Equal(gotBack, src) {
			t.Fatalf("iter=%d n=%d: Unchunk168LockBatch round-trip mismatch:\n got %x\nwant %x",
				iter, n, gotBack, src)
		}

		// Also verify Unchunk168LockBatch on independent random lane bytes.
		randP0 := make([]byte, 7*n)
		randP1 := make([]byte, 7*n)
		randP2 := make([]byte, 7*n)
		rng.Read(randP0)
		rng.Read(randP1)
		rng.Read(randP2)
		wantDst := make([]byte, 21*n)
		for j := 0; j < n; j++ {
			var r0, r1, r2 [7]byte
			copy(r0[:], randP0[7*j:7*(j+1)])
			copy(r1[:], randP1[7*j:7*(j+1)])
			copy(r2[:], randP2[7*j:7*(j+1)])
			d := softUnchunk168Ref(r0, r1, r2, masks[j][0], masks[j][1], masks[j][2])
			copy(wantDst[21*j:21*(j+1)], d[:])
		}
		gotDst := make([]byte, 21*n)
		Unchunk168LockBatch(randP0, randP1, randP2, masks, gotDst)
		if !bytes.Equal(gotDst, wantDst) {
			t.Fatalf("iter=%d n=%d: Unchunk168LockBatch random mismatch:\n got %x\nwant %x",
				iter, n, gotDst, wantDst)
		}
	}
}

func benchRankIndexBatch168() ([3][8]uint64, [2][8]uint64) {
	rng := rand.New(rand.NewSource(7))
	var idx0 [3][8]uint64
	var idx1 [2][8]uint64
	for j := 0; j < 8; j++ {
		v0 := randomIdx0_168(rng)
		v1 := randomIdx1_168(rng)
		idx0[0][j] = v0[0]
		idx0[1][j] = v0[1]
		idx0[2][j] = v0[2]
		idx1[0][j] = v1[0]
		idx1[1][j] = v1[1]
	}
	return idx0, idx1
}

// BenchmarkRankToMaskTripleUnrank168AVX512 times the 8-lane ZMM kernel
// per 8-triple batch.
func BenchmarkRankToMaskTripleUnrank168AVX512(b *testing.B) {
	if !HasAVX512RankMask {
		b.Skip("AVX-512F+BMI2 rank-mask kernel not available")
	}
	idx0, idx1 := benchRankIndexBatch168()
	var out [3][3][8]uint64
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RankToMaskTripleUnrank168(&idx0, &idx1, &out)
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*8), "ns/triple")
}

// BenchmarkRankToMaskTripleUnrank168AVX2 times the 4-lane YMM kernel
// (two halves per invocation) per 8-triple batch.
func BenchmarkRankToMaskTripleUnrank168AVX2(b *testing.B) {
	if !HasBMI2 || !cpuid.AVX2 {
		b.Skip("AVX2+BMI2 rank-mask kernel not available")
	}
	idx0, idx1 := benchRankIndexBatch168()
	var out [3][3][8]uint64
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RankToMaskTripleUnrank168AVX2(&idx0, &idx1, &out)
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*8), "ns/triple")
}

// BenchmarkRankToMaskTripleUnrank168Scalar8x times the 8x scalar
// refTriple168 walk — the fallback the batched kernels replace.
func BenchmarkRankToMaskTripleUnrank168Scalar8x(b *testing.B) {
	idx0, idx1 := benchRankIndexBatch168()
	var out [3][3][8]uint64
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 8; j++ {
			v0 := [3]uint64{idx0[0][j], idx0[1][j], idx0[2][j]}
			v1 := [2]uint64{idx1[0][j], idx1[1][j]}
			m0, m1, m2 := refTriple168(v0, v1)
			out[0][0][j], out[0][1][j], out[0][2][j] = m0[0], m0[1], m0[2]
			out[1][0][j], out[1][1][j], out[1][2][j] = m1[0], m1[1], m1[2]
			out[2][0][j], out[2][1][j], out[2][2][j] = m2[0], m2[1], m2[2]
		}
	}
	b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*8), "ns/triple")
	_ = out
}

// BenchmarkRankToMaskTripleUnrank168NEON measures the NEON 8-lane kernel
// against the scalar reference over the same eight lanes. Reported per
// 8-lane batch and in ns/triple.
func BenchmarkRankToMaskTripleUnrank168NEON(b *testing.B) {
	if !HasNEONInterlock {
		b.Skip("NEON rank-mask kernel not available")
	}
	idx0, idx1 := benchRankIndexBatch168()
	var out [3][3][8]uint64
	b.Run("neon", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			RankToMaskTripleUnrank168NEON(&idx0, &idx1, &out)
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*8), "ns/triple")
	})
	b.Run("scalar", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j := 0; j < 8; j++ {
				v0 := [3]uint64{idx0[0][j], idx0[1][j], idx0[2][j]}
				v1 := [2]uint64{idx1[0][j], idx1[1][j]}
				m0, m1, m2 := refTriple168(v0, v1)
				out[0][0][j], out[0][1][j], out[0][2][j] = m0[0], m0[1], m0[2]
				out[1][0][j], out[1][1][j], out[1][2][j] = m1[0], m1[1], m1[2]
				out[2][0][j], out[2][1][j], out[2][2][j] = m2[0], m2[1], m2[2]
			}
		}
		b.ReportMetric(float64(b.Elapsed().Nanoseconds())/float64(b.N*8), "ns/triple")
	})
	_ = out
}
