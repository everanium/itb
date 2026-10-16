package aescmacasm

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"runtime/debug"
	"testing"
	"unsafe"
)

var pairCounts = []int{1, 2, 4, 8}

type fusedX4Fn func(*Schedule, []uint64, *[4]*byte, *[4][2]uint64)
type fusedX1Fn func(*Schedule, []uint64, *byte, *[2]uint64)

func randomComponents(pairs int) []uint64 {
	comps := make([]uint64, 2*pairs)
	var raw [16 * 8]byte
	rand.Read(raw[:])
	for i := range comps {
		comps[i] = binary.LittleEndian.Uint64(raw[8*i:])
	}
	return comps
}

// runFusedX4Parity checks a four-lane fused kernel against the pure-Go
// cascade on every fixed lane case and a random sweep, for every
// component-pair count.
func runFusedX4Parity(t *testing.T, name string, n int, kernel fusedX4Fn) {
	t.Helper()
	for _, pairs := range pairCounts {
		for _, tc := range laneCases {
			bufs, ptrs := makeLaneData(n)
			comps := make([]uint64, 2*pairs)
			for i := range comps {
				comps[i] = tc.seeds[i%4][i%2] ^ uint64(i)*0x9E3779B97F4A7C15
			}
			s := NewSchedule(tc.key)
			var want, got [4][2]uint64
			for lane := 0; lane < 4; lane++ {
				want[lane][0], want[lane][1] = ScalarFusedChain(s, comps, bufs[lane])
			}
			kernel(s, comps, &ptrs, &got)
			if got != want {
				t.Fatalf("%s n=%d pairs=%d case %q: got %x want %x", name, n, pairs, tc.name, got, want)
			}
		}
		for iter := 0; iter < 64; iter++ {
			var key [16]byte
			rand.Read(key[:])
			s := NewSchedule(key)
			comps := randomComponents(pairs)
			bufs, ptrs := makeLaneData(n)
			for lane := 0; lane < 4; lane++ {
				rand.Read(bufs[lane])
			}
			var want, got [4][2]uint64
			for lane := 0; lane < 4; lane++ {
				want[lane][0], want[lane][1] = ScalarFusedChain(s, comps, bufs[lane])
			}
			kernel(s, comps, &ptrs, &got)
			if got != want {
				t.Fatalf("%s n=%d pairs=%d random iter %d: got %x want %x", name, n, pairs, iter, got, want)
			}
		}
	}
}

// runFusedX1Parity checks a single-lane fused kernel the same way.
func runFusedX1Parity(t *testing.T, name string, n int, kernel fusedX1Fn) {
	t.Helper()
	for _, pairs := range pairCounts {
		for iter := 0; iter < 96; iter++ {
			var key [16]byte
			rand.Read(key[:])
			s := NewSchedule(key)
			comps := randomComponents(pairs)
			bufs, ptrs := makeLaneData(n)
			rand.Read(bufs[0])
			wantLo, wantHi := ScalarFusedChain(s, comps, bufs[0])
			var got [2]uint64
			kernel(s, comps, ptrs[0], &got)
			if got[0] != wantLo || got[1] != wantHi {
				t.Fatalf("%s n=%d pairs=%d iter %d: got %x want (%x,%x)", name, n, pairs, iter, got, wantLo, wantHi)
			}
		}
	}
}

// TestScalarFusedChainMatchesSequential pins the fused reference to the
// literal sequential composition of ChainAbsorb.
func TestScalarFusedChainMatchesSequential(t *testing.T) {
	for _, n := range append([]int{0, 1, 17, 33, 65}, shapes...) {
		for _, pairs := range pairCounts {
			var key [16]byte
			rand.Read(key[:])
			s := NewSchedule(key)
			comps := randomComponents(pairs)
			data := make([]byte, n)
			rand.Read(data)
			lo, hi := ChainAbsorb(s, data, comps[0], comps[1])
			for i := 2; i < len(comps); i += 2 {
				lo, hi = ChainAbsorb(s, data, comps[i]^lo, comps[i+1]^hi)
			}
			gLo, gHi := ScalarFusedChain(s, comps, data)
			if gLo != lo || gHi != hi {
				t.Fatalf("n=%d pairs=%d: fused reference diverges", n, pairs)
			}
		}
	}
}

// TestFusedDispatchParity runs the public fused dispatchers (auto tier).
func TestFusedDispatchParity(t *testing.T) {
	x4 := map[int]fusedX4Fn{13: FusedChain13x4, 20: FusedChain20x4, 36: FusedChain36x4, 68: FusedChain68x4}
	x1 := map[int]fusedX1Fn{13: FusedChain13x1, 20: FusedChain20x1, 36: FusedChain36x1, 68: FusedChain68x1}
	for _, n := range shapes {
		t.Run("x4/"+shapeName(n), func(t *testing.T) { runFusedX4Parity(t, "dispatch-x4", n, x4[n]) })
		t.Run("x1/"+shapeName(n), func(t *testing.T) { runFusedX1Parity(t, "dispatch-x1", n, x1[n]) })
	}
}

// TestFusedRejectsShortComponents pins the guard path: fewer than two or
// an odd number of components routes to the scalar cascade without
// touching the kernels.
func TestFusedRejectsShortComponents(t *testing.T) {
	s := NewSchedule(ascendingKey())
	bufs, ptrs := makeLaneData(20)
	var out [4][2]uint64
	comps := []uint64{1, 2, 3}
	FusedChain20x4(s, comps, &ptrs, &out)
	var want [4][2]uint64
	for lane := 0; lane < 4; lane++ {
		want[lane][0], want[lane][1] = ScalarFusedChain(s, comps, bufs[lane])
	}
	if out != want {
		t.Fatal("odd component count did not route to the scalar cascade")
	}
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
func stackResidue(fn func()) []uint64 {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	res := make([]uint64, residueWindow/8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		residueGrow(0)
		residueProbe(fn, res)
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
func residueProbe(fn func(), res []uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -residueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = residueSentinel
	}
	residueDeep(fn, 0)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

// residueDeep calls fn below a residuePad-byte frame, so fn's frame and
// the kernel's frame below it fall inside the window.
//
//go:noinline
func residueDeep(fn func(), i int) byte {
	var pad [residuePad]byte
	pad[i] = 1
	fn()
	return pad[(i+7)%len(pad)]
}

// secretWords splits each 16-byte secret into its two little-endian
// words.
func secretWords(secrets [][16]byte) map[uint64]string {
	m := make(map[uint64]string)
	for i, s := range secrets {
		m[binary.LittleEndian.Uint64(s[0:])] = fmt.Sprintf("secret %d low word", i)
		m[binary.LittleEndian.Uint64(s[8:])] = fmt.Sprintf("secret %d high word", i)
	}
	return m
}

// assertNoSecretResidue fails if any window word, or any aligned
// 4-byte half of one, equals a secret (secrets64 / secrets32), and fails
// if the probe saw no write at all (a window that missed the kernel
// frame would otherwise pass vacuously).
func assertNoSecretResidue(t *testing.T, name string, res []uint64, secrets64 map[uint64]string, secrets32 map[uint32]string) {
	t.Helper()
	written := 0
	for i, w := range res {
		if w != residueSentinel {
			written++
		}
		if what, ok := secrets64[w]; ok {
			t.Errorf("%s: %s left in the stack %d bytes below the window top", name, what, 8*(i+1))
		}
		for h, d := range [2]uint32{uint32(w), uint32(w >> 32)} {
			if what, ok := secrets32[d]; ok {
				t.Errorf("%s: %s left in the stack %d bytes below the window top", name, what, 8*(i+1)-4*h)
			}
		}
	}
	if written == 0 {
		t.Fatalf("%s: no word of the window was written; the probe missed the kernel frame", name)
	}
}

// cmacSecrets lists the key-derived 16-byte values a fused AES-CMAC
// kernel could stage: every round key, K10 ^ K0, K0 ^ the length tag of
// shape n, and K0 ^ every zero-padded block of every lane (block 0 also
// with the length tag).
func cmacSecrets(s *Schedule, n int, lanes [][]byte) [][16]byte {
	var out [][16]byte
	var k [11][16]byte
	for r := range k {
		copy(k[r][:], s.roundKeys[16*r:])
		out = append(out, k[r])
	}
	var tag [16]byte
	binary.LittleEndian.PutUint64(tag[0:], uint64(n))
	binary.LittleEndian.PutUint64(tag[8:], uint64(n))
	x := func(a, b [16]byte) (c [16]byte) {
		for i := range c {
			c[i] = a[i] ^ b[i]
		}
		return c
	}
	out = append(out, x(k[10], k[0]), x(k[0], tag))
	for _, lane := range lanes {
		for b := 0; 16*b < len(lane); b++ {
			var blk [16]byte
			copy(blk[:], lane[16*b:])
			v := x(k[0], blk)
			out = append(out, v)
			if b == 0 {
				out = append(out, x(v, tag))
			}
		}
	}
	return out
}
