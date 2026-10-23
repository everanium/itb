package blake2basm

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
// ScalarFusedChain256 / ScalarFusedChain512, and the zero-allocation guard.

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

func randomKey512() *[64]byte {
	var k [64]byte
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
type x4fn512 func(*[64]byte, []uint64, *[4]*byte, *[4][8]uint64)
type x1fn512 func(*[64]byte, []uint64, *byte, *[8]uint64)

// checkX4_256 pins a four-lane width-256 kernel to the reference on
// random inputs at every group count.
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

func checkX4_512(t *testing.T, label string, n int, f x4fn512) {
	t.Helper()
	for _, g := range groupCounts {
		for iter := 0; iter < 16; iter++ {
			key := randomKey512()
			comps := randomWords(8 * g)
			bufs, ptrs := laneData(n)
			var got [4][8]uint64
			f(key, comps, &ptrs, &got)
			for l := 0; l < 4; l++ {
				if want := ScalarFusedChain512(key, comps, bufs[l]); got[l] != want {
					t.Fatalf("%s n=%d groups=%d iter=%d lane %d: got %x want %x", label, n, g, iter, l, got[l], want)
				}
			}
		}
	}
}

func checkX1_512(t *testing.T, label string, n int, f x1fn512) {
	t.Helper()
	for _, g := range groupCounts {
		for iter := 0; iter < 16; iter++ {
			key := randomKey512()
			comps := randomWords(8 * g)
			buf := make([]byte, n)
			rand.Read(buf)
			var got [8]uint64
			f(key, comps, &buf[0], &got)
			if want := ScalarFusedChain512(key, comps, buf); got != want {
				t.Fatalf("%s n=%d groups=%d iter=%d: got %x want %x", label, n, g, iter, got, want)
			}
		}
	}
}

// fillBases are the group index bases every fill check runs: they carry
// through every byte of the index, cross the byte-7 → byte-8 boundary
// of the in-register synthesis and wrap the uint64 inside a batch.
var fillBases = []uint64{0, 1, 0xFF, 0x00FFFFFFFFFFFFF8, 0xFFFFFFFFFFFFFFFC, 0x0123456789ABCDEF}

// fillFolds are the fixed interlock-nonce folds every fill check runs
// beside one random word (fillFoldSet): the all-zero and all-one words
// and two words with the top and bottom bits set, so a kernel that
// narrows, shifts or drops the fold misses at least one vector.
var fillFolds = []uint32{0, 0xFFFFFFFF, 0x80000001, 0x7F000080}

// fillFoldSet returns fillFolds followed by one random fold.
func fillFoldSet() []uint32 {
	var b [4]byte
	rand.Read(b[:])
	return append(append([]uint32(nil), fillFolds...), binary.LittleEndian.Uint32(b[:]))
}

// fillBlocks returns the explicit 13-byte fill blocks
// [0x03 | LE64(base+i) | LE32(v)] of lanes base .. base+n-1, built
// independently of fillBlock as the second reference of the fill checks.
func fillBlocks(base uint64, v uint32, n int) [][]byte {
	lanes := make([][]byte, n)
	for i := range lanes {
		lanes[i] = make([]byte, 13)
		lanes[i][0] = 0x03
		binary.LittleEndian.PutUint64(lanes[i][1:9], base+uint64(i))
		binary.LittleEndian.PutUint32(lanes[i][9:13], v)
	}
	return lanes
}

// fillFlipBit returns the fold bit a fill check flips for its negative
// control; it varies with the base and the group count so the controls
// spread across the word (the kernelaudit differential flips every fold
// bit; this control pins the kernel under test independently of that harness).
func fillFlipBit(base uint64, g int) uint32 {
	return uint32(1) << (uint(base+uint64(7*g)) & 31)
}

type fill8fn256 func(*[32]byte, []uint64, uint64, uint32, *[8][4]uint64)
type fill4fn512 func(*[64]byte, []uint64, uint64, uint32, *[4][8]uint64)

// checkFill256 pins the width-256 batch-16 fill hook at every (base,
// fold) pair to the scalar fill reference and, lane by lane, to the
// cascade over the explicit 13-byte block, then flips one bit of the
// fold and requires every lane to move — so an arm that leaves bytes
// 9..12 of its blocks untouched cannot pass by agreeing with a reference
// that happens to use a zero fold.
func checkFill256(t *testing.T, label string, f fill8fn256) {
	t.Helper()
	for _, g := range groupCounts {
		for _, base := range fillBases {
			for _, v := range fillFoldSet() {
				key := randomKey256()
				comps := randomWords(4 * g)
				var got, want [8][4]uint64
				f(key, comps, base, v, &got)
				scalarFill256X8(key, comps, base, v, &want)
				if got != want {
					t.Fatalf("%s groups=%d base=%#x v=%#x: got %x want %x", label, g, base, v, got, want)
				}
				for i, blk := range fillBlocks(base, v, 8) {
					if want := ScalarFusedChain256(key, comps, blk); got[i] != want {
						t.Fatalf("%s groups=%d base=%#x v=%#x lane %d: got %x, the explicit block gives %x", label, g, base, v, i, got[i], want)
					}
				}
				bit := fillFlipBit(base, g)
				var flipped [8][4]uint64
				f(key, comps, base, v^bit, &flipped)
				for i := range got {
					if flipped[i] == got[i] {
						t.Errorf("%s groups=%d base=%#x v=%#x lane %d: flipping fold bit %#x leaves the lane unchanged", label, g, base, v, i, bit)
					}
				}
			}
		}
	}
}

// checkFill512 is the width-512 batch-16 form of checkFill256.
func checkFill512(t *testing.T, label string, f fill4fn512) {
	t.Helper()
	for _, g := range groupCounts {
		for _, base := range fillBases {
			for _, v := range fillFoldSet() {
				key := randomKey512()
				comps := randomWords(8 * g)
				var got, want [4][8]uint64
				f(key, comps, base, v, &got)
				scalarFill512X4(key, comps, base, v, &want)
				if got != want {
					t.Fatalf("%s groups=%d base=%#x v=%#x: got %x want %x", label, g, base, v, got, want)
				}
				for i, blk := range fillBlocks(base, v, 4) {
					if want := ScalarFusedChain512(key, comps, blk); got[i] != want {
						t.Fatalf("%s groups=%d base=%#x v=%#x lane %d: got %x, the explicit block gives %x", label, g, base, v, i, got[i], want)
					}
				}
				bit := fillFlipBit(base, g)
				var flipped [4][8]uint64
				f(key, comps, base, v^bit, &flipped)
				for i := range got {
					if flipped[i] == got[i] {
						t.Errorf("%s groups=%d base=%#x v=%#x lane %d: flipping fold bit %#x leaves the lane unchanged", label, g, base, v, i, bit)
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
func dispatchers512x4() map[int]x4fn512 {
	return map[int]x4fn512{13: Fused512Chain13x4, 20: Fused512Chain20x4, 36: Fused512Chain36x4, 68: Fused512Chain68x4}
}
func dispatchers512x1() map[int]x1fn512 {
	return map[int]x1fn512{13: Fused512Chain13x1, 20: Fused512Chain20x1, 36: Fused512Chain36x1, 68: Fused512Chain68x1}
}

// checkDispatchers pins every dispatcher to the reference under the
// current flag state.
func checkDispatchers(t *testing.T, label string) {
	t.Helper()
	for _, n := range Shapes {
		checkX4_256(t, label+"-256x4", n, dispatchers256x4()[n])
		checkX1_256(t, label+"-256x1", n, dispatchers256x1()[n])
		checkX4_512(t, label+"-512x4", n, dispatchers512x4()[n])
		checkX1_512(t, label+"-512x1", n, dispatchers512x1()[n])
	}
	checkFill256(t, label+"-fill256", Fused256Fill13x8)
	checkFill512(t, label+"-fill512", Fused512Fill13x4)
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
	key512 := randomKey512()
	comps512 := randomWords(16)
	var seed512 [8]uint64
	copy(seed512[:], comps512[:8])
	h512 := absorb512(key512, &seed512, data)
	for i := range seed512 {
		seed512[i] = comps512[8+i] ^ h512[i]
	}
	h512 = absorb512(key512, &seed512, data)
	if got := ScalarFusedChain512(key512, comps512, data); got != h512 {
		t.Fatalf("512 two groups: got %x want %x", got, h512)
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
	k256, k512 := randomKey256(), randomKey512()
	c256, c512 := randomWords(8), randomWords(16)
	for _, n := range Shapes {
		bufs, ptrs := laneData(n)
		var o4 [4][4]uint64
		var o1 [4]uint64
		var p4 [4][8]uint64
		var p1 [8]uint64
		f4, f1 := dispatchers256x4()[n], dispatchers256x1()[n]
		g4, g1 := dispatchers512x4()[n], dispatchers512x1()[n]
		check("Fused256Chain"+shapeName(n)+"x4", func() { f4(k256, c256, &ptrs, &o4) })
		check("Fused256Chain"+shapeName(n)+"x1", func() { f1(k256, c256, &bufs[0][0], &o1) })
		check("Fused512Chain"+shapeName(n)+"x4", func() { g4(k512, c512, &ptrs, &p4) })
		check("Fused512Chain"+shapeName(n)+"x1", func() { g1(k512, c512, &bufs[0][0], &p1) })
	}
	var f8 [8][4]uint64
	var f4 [4][8]uint64
	check("Fused256Fill13x8", func() { Fused256Fill13x8(k256, c256, 0x00FFFFFFFFFFFFF8, 0xA5C33C5A, &f8) })
	check("Fused512Fill13x4", func() { Fused512Fill13x4(k512, c512, 0x00FFFFFFFFFFFFF8, 0xA5C33C5A, &f4) })
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

// blake2bSecrets lists the secret 64-bit words a one-group cascade could
// leave in a kernel frame: every key word and, for every lane, every
// seed-injected word data ⊕ component (h = 0 in the only round).
func blake2bSecrets(key []byte, comps []uint64, lanes [][]byte) map[uint64]string {
	m := make(map[uint64]string)
	for k := 0; 8*k < len(key); k++ {
		m[binary.LittleEndian.Uint64(key[8*k:])] = fmt.Sprintf("key word %d", k)
	}
	for l, data := range lanes {
		for i := range comps {
			var d [8]byte
			if 8*i < len(data) {
				copy(d[:], data[8*i:])
			}
			m[binary.LittleEndian.Uint64(d[:])^comps[i]] = fmt.Sprintf("lane %d seed-injected word %d", l, i)
		}
	}
	return m
}

// checkBlake2bResidue runs every given kernel at one component group
// under the stack-residue probe and requires that no key word and no
// seed-injected word is left in the stack once the kernel has returned.
func checkBlake2bResidue(t *testing.T, label string, k256x4 map[int]x4fn256, k512x4 map[int]x4fn512,
	k256x1 map[int]x1fn256, k512x1 map[int]x1fn512) {
	t.Helper()
	key256, key512 := randomKey256(), randomKey512()
	c256, c512 := randomWords(4), randomWords(8)
	for _, n := range Shapes {
		bufs, ptrs := laneData(n)
		if f, ok := k256x4[n]; ok {
			var out [4][4]uint64
			res := stackResidue(func() { f(key256, c256, &ptrs, &out) })
			assertNoSecretResidue(t, fmt.Sprintf("%s 256x4 n=%d", label, n), res, blake2bSecrets(key256[:], c256, bufs[:]), nil)
		}
		if f, ok := k512x4[n]; ok {
			var out [4][8]uint64
			res := stackResidue(func() { f(key512, c512, &ptrs, &out) })
			assertNoSecretResidue(t, fmt.Sprintf("%s 512x4 n=%d", label, n), res, blake2bSecrets(key512[:], c512, bufs[:]), nil)
		}
		if f, ok := k256x1[n]; ok {
			var out [4]uint64
			res := stackResidue(func() { f(key256, c256, ptrs[0], &out) })
			assertNoSecretResidue(t, fmt.Sprintf("%s 256x1 n=%d", label, n), res, blake2bSecrets(key256[:], c256, bufs[:1]), nil)
		}
		if f, ok := k512x1[n]; ok {
			var out [8]uint64
			res := stackResidue(func() { f(key512, c512, ptrs[0], &out) })
			assertNoSecretResidue(t, fmt.Sprintf("%s 512x1 n=%d", label, n), res, blake2bSecrets(key512[:], c512, bufs[:1]), nil)
		}
	}
}
