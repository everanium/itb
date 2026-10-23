package blake2sasm

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"runtime/debug"
	"testing"
	"unsafe"
)

// Parity scaffolding of the fused cascade shared by every architecture:
// random inputs, the dispatcher-level parity checks against
// ScalarFusedChain256, and the zero-allocation guard.

var groupCounts = []int{1, 2, 4, 8}

func shapeName(n int) string { return fmt.Sprintf("shape%d", n) }

func randomWords(k int) []uint64 {
	raw := make([]byte, 8*k)
	rand.Read(raw)
	w := make([]uint64, k)
	for i := range w {
		w[i] = binary.LittleEndian.Uint64(raw[8*i:])
	}
	return w
}

func randomKey256() *[32]byte {
	var k [32]byte
	rand.Read(k[:])
	return &k
}

func laneData(n int) ([4][]byte, [4]*byte) {
	var bufs [4][]byte
	var ptrs [4]*byte
	for l := range bufs {
		bufs[l] = make([]byte, n)
		rand.Read(bufs[l])
		ptrs[l] = &bufs[l][0]
	}
	return bufs, ptrs
}

type x4fn256 func(*[32]byte, []uint64, *[4]*byte, *[4][4]uint64)
type x1fn256 func(*[32]byte, []uint64, *byte, *[4]uint64)

// checkX4_256 pins a four-lane kernel to the reference on random inputs
// at every group count.
func checkX4_256(t *testing.T, label string, n int, f x4fn256) {
	t.Helper()
	for _, g := range groupCounts {
		for iter := 0; iter < 16; iter++ {
			key := randomKey256()
			comps := randomWords(4 * g)
			bufs, ptrs := laneData(n)
			var got [4][4]uint64
			f(key, comps, &ptrs, &got)
			for l := 0; l < 4; l++ {
				if want := ScalarFusedChain256(key, comps, bufs[l]); got[l] != want {
					t.Fatalf("%s n=%d groups=%d iter=%d lane %d: got %x want %x", label, n, g, iter, l, got[l], want)
				}
			}
		}
	}
}

func checkX1_256(t *testing.T, label string, n int, f x1fn256) {
	t.Helper()
	for _, g := range groupCounts {
		for iter := 0; iter < 16; iter++ {
			key := randomKey256()
			comps := randomWords(4 * g)
			buf := make([]byte, n)
			rand.Read(buf)
			var got [4]uint64
			f(key, comps, &buf[0], &got)
			if want := ScalarFusedChain256(key, comps, buf); got != want {
				t.Fatalf("%s n=%d groups=%d iter=%d: got %x want %x", label, n, g, iter, got, want)
			}
		}
	}
}

var fillBases = []uint64{0, 1, 0xFF, 0x00FFFFFFFFFFFFF8, 0xFFFFFFFFFFFFFFFC, 0x0123456789ABCDEF}

// fillFolds are the fixed interlock-nonce folds every fill evaluator is
// checked on beside a random one: the all-zero and all-one words and a
// word with the top and bottom bits set, so an evaluator that narrows,
// shifts or drops the fold misses at least one vector.
var fillFolds = []uint32{0, 0xFFFFFFFF, 0x80000001}

// randomFold draws one interlock-nonce fold.
func randomFold() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint32(b[:])
}

// explicitFill256 is the reference of the fill shape built independently
// of fillBlock: lane i runs ScalarFusedChain256 over the explicit
// 13-byte block [0x03 | LE64(base+i) | LE32(v)].
func explicitFill256(key *[32]byte, comps []uint64, base uint64, v uint32, out *[8][4]uint64) {
	for i := range out {
		var blk [13]byte
		blk[0] = 0x03
		binary.LittleEndian.PutUint64(blk[1:9], base+uint64(i))
		binary.LittleEndian.PutUint32(blk[9:13], v)
		out[i] = ScalarFusedChain256(key, comps, blk[:])
	}
}

// checkFill256 pins the batch-16 fill hook to the reference at group
// index bases that carry through every byte of the index, under the
// fixed folds and a random one: against scalarFill256X8 and against the
// explicit-block reference. Every check also flips one bit of the fold
// and requires every lane to move, so an evaluator that leaves bytes
// 9..12 at zero cannot pass by agreeing with a reference under a zero
// fold.
func checkFill256(t *testing.T, label string, f func(*[32]byte, []uint64, uint64, uint32, *[8][4]uint64)) {
	t.Helper()
	for _, g := range groupCounts {
		for _, base := range fillBases {
			for _, v := range append([]uint32{randomFold()}, fillFolds...) {
				key := randomKey256()
				comps := randomWords(4 * g)
				var got, want, explicit, flipped [8][4]uint64
				f(key, comps, base, v, &got)
				scalarFill256X8(key, comps, base, v, &want)
				if got != want {
					t.Fatalf("%s groups=%d base=%#x v=%#x: got %x want %x", label, g, base, v, got, want)
				}
				explicitFill256(key, comps, base, v, &explicit)
				if got != explicit {
					t.Fatalf("%s groups=%d base=%#x v=%#x: got %x, explicit-block reference %x", label, g, base, v, got, explicit)
				}
				bit := uint32(1) << (uint(base) & 31)
				f(key, comps, base, v^bit, &flipped)
				for i := range flipped {
					if flipped[i] == got[i] {
						t.Fatalf("%s groups=%d base=%#x v=%#x lane %d: flipping fold bit %#x leaves the lane unchanged", label, g, base, v, i, bit)
					}
				}
			}
		}
	}
}

func dispatchers256x4() map[int]x4fn256 {
	return map[int]x4fn256{13: Fused256Chain13x4, 20: Fused256Chain20x4, 36: Fused256Chain36x4, 68: Fused256Chain68x4}
}
func dispatchers256x1() map[int]x1fn256 {
	return map[int]x1fn256{13: Fused256Chain13x1, 20: Fused256Chain20x1, 36: Fused256Chain36x1, 68: Fused256Chain68x1}
}

// checkDispatchers pins every dispatcher to the reference under the
// current flag state.
func checkDispatchers(t *testing.T, label string) {
	t.Helper()
	for _, n := range Shapes {
		checkX4_256(t, label+"-256x4", n, dispatchers256x4()[n])
		checkX1_256(t, label+"-256x1", n, dispatchers256x1()[n])
	}
	checkFill256(t, label+"-fill256", Fused256Fill13x8)
}

// TestFusedDispatchersAuto pins the dispatchers under the build's
// auto-selected dispatch state.
func TestFusedDispatchersAuto(t *testing.T) {
	checkDispatchers(t, "auto")
}

// TestFusedReferenceCascade pins the pure-Go reference's cascade
// structure: one group is the prefix-MAC under fixedKey and the
// components as the seed, and each further group re-seeds with the
// previous output XOR the group.
func TestFusedReferenceCascade(t *testing.T) {
	key := randomKey256()
	comps := randomWords(8)
	data := make([]byte, 36)
	rand.Read(data)
	var seed [4]uint64
	copy(seed[:], comps[:4])
	h := absorb256(key, &seed, data)
	if got := ScalarFusedChain256(key, comps[:4], data); got != h {
		t.Fatalf("one group: got %x want %x", got, h)
	}
	for i := range seed {
		seed[i] = comps[4+i] ^ h[i]
	}
	h = absorb256(key, &seed, data)
	if got := ScalarFusedChain256(key, comps, data); got != h {
		t.Fatalf("two groups: got %x want %x", got, h)
	}
}

// checkZeroAlloc asserts that every dispatcher runs without a heap
// allocation under the current dispatch state.
func checkZeroAlloc(t *testing.T, label string) {
	t.Helper()
	check := func(what string, f func()) {
		t.Helper()
		if n := testing.AllocsPerRun(50, f); n != 0 {
			t.Errorf("%s: %s allocates %.0f objects per call", label, what, n)
		}
	}
	k256 := randomKey256()
	c256 := randomWords(8)
	for _, n := range Shapes {
		bufs, ptrs := laneData(n)
		var o4 [4][4]uint64
		var o1 [4]uint64
		f4, f1 := dispatchers256x4()[n], dispatchers256x1()[n]
		check("Fused256Chain"+shapeName(n)+"x4", func() { f4(k256, c256, &ptrs, &o4) })
		check("Fused256Chain"+shapeName(n)+"x1", func() { f1(k256, c256, &bufs[0][0], &o1) })
	}
	var f8 [8][4]uint64
	check("Fused256Fill13x8", func() { Fused256Fill13x8(k256, c256, 0x00FFFFFFFFFFFFF8, 0xA5C33C5A, &f8) })
}

func TestFusedDispatchersZeroAlloc(t *testing.T) {
	checkZeroAlloc(t, "auto")
}

// Stack-residue probe. A kernel's frame lives below its caller's stack
// pointer and Go does not clear it on return, so whatever the kernel
// stored there stays readable until the goroutine reuses that depth.
// stackResidue runs fn at a known depth below a probing frame and
// returns the 8-byte words fn and the kernel it calls left in a window
// that spans every kernel frame of the package.
const (
	// residueGap separates the probing frame from the window: it exceeds
	// the probing frame itself, so filling the window never touches a
	// live local of the probe.
	residueGap = 1 << 10
	// residuePad is the frame of residueDeep; it pushes fn and the
	// kernel below the top of the window.
	residuePad = 2 << 10
	// residueWindow is the span inspected below residueGap.
	residueWindow = 16 << 10
	// residueSentinel marks window words nothing wrote.
	residueSentinel = 0x5A5A5A5A5A5A5A5A
)

// stackResidue calls fn on a fresh goroutine and returns the window
// words below the probing frame once fn has returned. The goroutine
// stack is grown past the window first and the collector is held off
// for the duration, so the stack is neither grown nor shrunk (and so
// never moved) between the sentinel fill, the call and the read-back.
var dumpSIMDRegsHook func(dst *[88]uint64)
var dirtySIMDRegHook func(masked uint64)
var genericResidueSink uint64

//go:noinline
func leakyGenericFrame(secret uint64, i int) {
	var frame [8]uint64
	for j := range frame {
		frame[j] = secret
	}
	genericResidueSink = frame[(i+1)%len(frame)]
}

func checkResidueNegativeControls(t *testing.T) {
	t.Helper()
	secret := uint64(0xA5C35A3CF00DCAFE)
	resStack := stackResidue(func() { leakyGenericFrame(secret, 0) })
	stackHits := 0
	for _, w := range resStack[:residueWindow/8] {
		if w == secret {
			stackHits++
		}
	}
	if stackHits == 0 {
		t.Fatal("negative control: stack-residue probe did not see secret stored by leakyGenericFrame")
	}
	if dirtySIMDRegHook != nil {
		resReg := stackResidue(func() { dirtySIMDRegHook(secret ^ 0x5555555555555555) })
		regHits := 0
		for _, w := range resReg[residueWindow/8:] {
			if w == secret {
				regHits++
			}
		}
		if regHits < 2 {
			t.Fatalf("negative control: register snapshot saw %d hits of leaked register word, want >= 2", regHits)
		}
	}
}

func stackResidue(fn func()) []uint64 {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	res := make([]uint64, residueWindow/8+88)
	done := make(chan struct{})
	go func() {
		defer close(done)
		residueGrow(0)
		var regs [88]uint64
		residueProbe(fn, res[:residueWindow/8], &regs)
		copy(res[residueWindow/8:], regs[:])
	}()
	<-done
	return res
}

// residueGrow forces the goroutine stack well past the probe's depth.
//
//go:noinline
func residueGrow(i int) byte {
	var pad [4 * residueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

// residueProbe fills the window with the sentinel, calls fn through
// residueDeep and copies the window back into res. It calls nothing
// between the fill and the read-back except fn's chain, and the window
// lies below its own stack pointer.
//
//go:noinline
func residueProbe(fn func(), res []uint64, regs *[88]uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -residueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = residueSentinel
	}
	residueDeep(fn, 0, regs)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

// residueDeep calls fn below a residuePad-byte frame, so fn's frame and
// the kernel's frame below it fall inside the window.
//
//go:noinline
func residueDeep(fn func(), i int, regs *[88]uint64) byte {
	var pad [residuePad]byte
	pad[i] = 1
	fn()
	if dumpSIMDRegsHook != nil {
		dumpSIMDRegsHook(regs)
	}
	return pad[(i+7)%len(pad)]
}

// assertNoSecretResidue fails if any window word, or any aligned
// 4-byte half of one, equals a secret (secrets64 / secrets32), and fails
// if the probe saw no write at all (a window that missed the kernel
// frame would otherwise pass vacuously).
func assertNoSecretResidue(t *testing.T, name string, res []uint64, secrets64 map[uint64]string, secrets32 map[uint32]string) {
	t.Helper()
	written := 0
	stackWords := residueWindow / 8
	for i, w := range res {
		if i < stackWords && w != residueSentinel {
			written++
		}
		if i >= stackWords && w == 0 {
			continue
		}
		if what, ok := secrets64[w]; ok {
			if i < stackWords {
				t.Errorf("%s: %s left in the stack %d bytes below the window top", name, what, 8*(i+1))
			} else {
				t.Errorf("%s: %s left in post-RET register snapshot (word %d)", name, what, i-stackWords)
			}
		}
		for h, d := range [2]uint32{uint32(w), uint32(w >> 32)} {
			if i >= stackWords && d == 0 {
				continue
			}
			if what, ok := secrets32[d]; ok {
				if i < stackWords {
					t.Errorf("%s: %s left in the stack %d bytes below the window top", name, what, 8*(i+1)-4*h)
				} else {
					t.Errorf("%s: %s left in post-RET register snapshot (word %d half %d)", name, what, i-stackWords, h)
				}
			}
		}
	}
	if written == 0 {
		t.Fatalf("%s: no word of the window was written; the probe missed the kernel frame", name)
	}
}

// blake2sSecrets lists the secret dwords a one-group cascade could leave
// in a kernel frame: every key dword and, for every lane, every
// seed-injected dword data ⊕ component dword (h = 0 in the only round).
func blake2sSecrets(key []byte, comps []uint64, lanes [][]byte) map[uint32]string {
	m := make(map[uint32]string)
	for k := 0; 4*k < len(key); k++ {
		m[binary.LittleEndian.Uint32(key[4*k:])] = fmt.Sprintf("key dword %d", k)
	}
	for l, data := range lanes {
		for k := 0; k < 2*len(comps); k++ {
			var d [4]byte
			if 4*k < len(data) {
				copy(d[:], data[4*k:])
			}
			c := uint32(comps[k/2] >> (32 * (k % 2)))
			m[binary.LittleEndian.Uint32(d[:])^c] = fmt.Sprintf("lane %d seed-injected dword %d", l, k)
		}
	}
	return m
}

// fillLanes returns the eight 13-byte fill blocks of groupIdxBase under
// the interlock-nonce fold v.
func fillLanes(base uint64, v uint32) [][]byte {
	lanes := make([][]byte, 8)
	for i := range lanes {
		lanes[i] = make([]byte, 13)
		lanes[i][0] = 0x03
		binary.LittleEndian.PutUint64(lanes[i][1:], base+uint64(i))
		binary.LittleEndian.PutUint32(lanes[i][9:], v)
	}
	return lanes
}

// checkBlake2sResidue runs every given kernel at one component group
// under the stack-residue probe and requires that no key dword and no
// seed-injected dword is left in the stack once the kernel has returned.
func checkBlake2sResidue(t *testing.T, label string, x4 map[int]x4fn256, x1 map[int]x1fn256, x8 map[int]x8fn256) {
	t.Helper()
	key, comps := randomKey256(), randomWords(4)
	for _, n := range Shapes {
		bufs, ptrs := laneData(n)
		if f, ok := x4[n]; ok {
			var out [4][4]uint64
			res := stackResidue(func() { f(key, comps, &ptrs, &out) })
			assertNoSecretResidue(t, fmt.Sprintf("%s x4 n=%d", label, n), res, nil, blake2sSecrets(key[:], comps, bufs[:]))
		}
		if f, ok := x1[n]; ok {
			var out [4]uint64
			res := stackResidue(func() { f(key, comps, ptrs[0], &out) })
			assertNoSecretResidue(t, fmt.Sprintf("%s x1 n=%d", label, n), res, nil, blake2sSecrets(key[:], comps, bufs[:1]))
		}
		if f, ok := x8[n]; ok {
			bufs8, ptrs8 := laneData8(n)
			var out [8][4]uint64
			res := stackResidue(func() { f(key, comps, &ptrs8, &out) })
			assertNoSecretResidue(t, fmt.Sprintf("%s x8 n=%d", label, n), res, nil, blake2sSecrets(key[:], comps, bufs8[:]))
		}
	}
}
