package aesitbasm

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	aes "github.com/jedisct1/go-aes"
)

// Shapes lists every per-lane input length the kernels are specialised for.
var shapes = []int{13, 20, 36, 68}

type laneCase struct {
	name  string
	key   [16]byte
	seeds [4][2]uint64
}

func ascendingKey() [16]byte {
	var k [16]byte
	for i := range k {
		k[i] = byte(i * 0x11)
	}
	return k
}

func highBitKey() [16]byte {
	var k [16]byte
	for i := range k {
		k[i] = 0x80 | byte(i)
	}
	return k
}

var laneCases = []laneCase{
	{name: "zero key, zero seeds"},
	{
		name:  "ascending key, distinct lane seeds",
		key:   ascendingKey(),
		seeds: [4][2]uint64{{1, 2}, {3, 4}, {5, 6}, {7, 8}},
	},
	{
		name: "high-bit key, high-bit seeds",
		key:  highBitKey(),
		seeds: [4][2]uint64{
			{0x8000000000000001, 0x8000000000000002},
			{0x8000000000000003, 0x8000000000000004},
			{0x8000000000000005, 0x8000000000000006},
			{0x8000000000000007, 0x8000000000000008},
		},
	},
	{
		name: "zero key, all-ones seeds",
		seeds: [4][2]uint64{
			{^uint64(0), ^uint64(0)}, {^uint64(0), ^uint64(0)},
			{^uint64(0), ^uint64(0)}, {^uint64(0), ^uint64(0)},
		},
	},
}

// makeLaneData returns four distinct per-lane inputs of exactly n bytes.
// Each slice is carved out of a longer backing array whose bytes past n
// are non-zero, so a kernel that reads beyond the shape mismatches the
// reference.
func makeLaneData(n int) ([4][]byte, [4]*byte) {
	var bufs [4][]byte
	var ptrs [4]*byte
	for lane := 0; lane < 4; lane++ {
		backing := make([]byte, n+32)
		for i := range backing {
			backing[i] = byte(i + 0xC0 + lane*0x40)
		}
		for i := n; i < len(backing); i++ {
			backing[i] = 0xEE
		}
		bufs[lane] = backing[:n:n]
		ptrs[lane] = &bufs[lane][0]
	}
	return bufs, ptrs
}

func referenceLanes(key [16]byte, seeds [4][2]uint64, bufs [4][]byte) [4][2]uint64 {
	var want [4][2]uint64
	for lane := 0; lane < 4; lane++ {
		want[lane][0], want[lane][1] = ChainAbsorb(&key, bufs[lane], seeds[lane][0], seeds[lane][1])
	}
	return want
}

type kernelFn func(*[16]byte, *[4][2]uint64, *[4]*byte, *[4][2]uint64)

// runKernelParity checks one (kernel, shape) pair against the pure-Go
// reference over the fixed case matrix and a random sweep.
func runKernelParity(t *testing.T, name string, n int, kernel kernelFn) {
	t.Helper()
	for _, tc := range laneCases {
		t.Run(tc.name, func(t *testing.T) {
			bufs, ptrs := makeLaneData(n)
			want := referenceLanes(tc.key, tc.seeds, bufs)
			key, seeds := tc.key, tc.seeds
			var got [4][2]uint64
			kernel(&key, &seeds, &ptrs, &got)
			for lane := 0; lane < 4; lane++ {
				if got[lane] != want[lane] {
					t.Fatalf("%s n=%d lane %d: got %x want %x", name, n, lane, got[lane], want[lane])
				}
			}
		})
	}
	t.Run("random", func(t *testing.T) {
		for iter := 0; iter < 256; iter++ {
			var key [16]byte
			var seeds [4][2]uint64
			var raw [64]byte
			rand.Read(key[:])
			rand.Read(raw[:])
			for lane := 0; lane < 4; lane++ {
				seeds[lane][0] = binary.LittleEndian.Uint64(raw[16*lane:])
				seeds[lane][1] = binary.LittleEndian.Uint64(raw[16*lane+8:])
			}
			bufs, ptrs := makeLaneData(n)
			for lane := 0; lane < 4; lane++ {
				rand.Read(bufs[lane])
			}
			want := referenceLanes(key, seeds, bufs)
			var got [4][2]uint64
			kernel(&key, &seeds, &ptrs, &got)
			if got != want {
				t.Fatalf("%s n=%d iter %d: got %x want %x", name, n, iter, got, want)
			}
		}
	})
}

// TestReferenceAgainstRoundHW pins the software-round reference to the
// hardware-round evaluation of the same construction, so the two AES
// round paths agree before any kernel is compared to either.
func TestReferenceAgainstRoundHW(t *testing.T) {
	for _, n := range append([]int{0, 1, 15, 16, 17, 31, 32, 33, 63, 64}, shapes...) {
		for iter := 0; iter < 32; iter++ {
			var key [16]byte
			var s [16]byte
			rand.Read(key[:])
			rand.Read(s[:])
			data := make([]byte, n)
			rand.Read(data)
			seed0 := binary.LittleEndian.Uint64(s[:8])
			seed1 := binary.LittleEndian.Uint64(s[8:])
			wantLo, wantHi := ChainAbsorb(&key, data, seed0, seed1)
			gotLo, gotHi := roundHWChainAbsorb(&key, data, seed0, seed1)
			if gotLo != wantLo || gotHi != wantHi {
				t.Fatalf("n=%d: RoundHW (%x,%x) != software (%x,%x)", n, gotLo, gotHi, wantLo, wantHi)
			}
		}
	}
}

// roundHWChainAbsorb is the reference construction evaluated with the
// hardware-dispatched AES round (test-only mirror of the parent closure).
func roundHWChainAbsorb(key *[16]byte, data []byte, seed0, seed1 uint64) (uint64, uint64) {
	var state [16]byte
	binary.LittleEndian.PutUint64(state[:8], binary.LittleEndian.Uint64(key[:8])^seed0)
	binary.LittleEndian.PutUint64(state[8:], binary.LittleEndian.Uint64(key[8:])^seed1)
	n := len(data)
	full := n &^ 15
	blk := 0
	for off := 0; off < full; off += 16 {
		for i := 0; i < 16; i++ {
			state[i] ^= data[off+i]
		}
		aes.RoundHW((*aes.Block)(&state), (*aes.Block)(&RC[blk&7]))
		blk++
	}
	rem := n - full
	pad := byte(16 - rem)
	for i := 0; i < rem; i++ {
		state[i] ^= data[full+i]
	}
	for i := rem; i < 16; i++ {
		state[i] ^= pad
	}
	aes.RoundHW((*aes.Block)(&state), (*aes.Block)(&RC[blk&7]))
	aes.RoundHW((*aes.Block)(&state), (*aes.Block)(&RC[0]))
	aes.RoundHW((*aes.Block)(&state), (*aes.Block)(&RC[1]))
	return binary.LittleEndian.Uint64(state[:8]), binary.LittleEndian.Uint64(state[8:])
}

// TestDispatchParity runs the public dispatchers (whatever tier the host
// auto-selects) against the reference on every shape.
func TestDispatchParity(t *testing.T) {
	dispatch := map[int]kernelFn{
		13: AESITB128ChainAbsorb13x4,
		20: AESITB128ChainAbsorb20x4,
		36: AESITB128ChainAbsorb36x4,
		68: AESITB128ChainAbsorb68x4,
	}
	for _, n := range shapes {
		t.Run(shapeName(n), func(t *testing.T) {
			runKernelParity(t, "dispatch", n, dispatch[n])
		})
	}
}

// TestScalarBatchParity pins the scalar 4-lane helper to the single-lane
// reference on every shape.
func TestScalarBatchParity(t *testing.T) {
	for _, n := range shapes {
		n := n
		t.Run(shapeName(n), func(t *testing.T) {
			runKernelParity(t, "scalar", n, func(key *[16]byte, seeds *[4][2]uint64, ptrs *[4]*byte, out *[4][2]uint64) {
				scalarBatch(key, seeds, ptrs, n, out)
			})
		})
	}
}

// TestPadVectors pins the tail-pad constants to the PKCS#7 definition.
func TestPadVectors(t *testing.T) {
	for i := 0; i < 16; i++ {
		want4 := byte(0)
		if i >= 4 {
			want4 = 0x0C
		}
		want13 := byte(0)
		if i >= 13 {
			want13 = 0x03
		}
		if pad4Tail[i] != want4 || pad13Tail[i] != want13 {
			t.Fatalf("pad byte %d: pad4=%#x pad13=%#x", i, pad4Tail[i], pad13Tail[i])
		}
	}
}

func shapeName(n int) string {
	return map[int]string{13: "13", 20: "20", 36: "36", 68: "68"}[n]
}
