package aescmacasm

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/binary"
	"testing"
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

// closureReference re-implements the hashes.AESCMACWithKey closure body
// independently of [ChainAbsorb] (crypto/aes block, length tag folded
// into both seed halves, zero-padded absorb of every block), so the
// package reference is pinned to the primitive's definition before any
// kernel is compared to it.
func closureReference(key [16]byte, data []byte, seed0, seed1 uint64) (uint64, uint64) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	lenTag := uint64(len(data))
	var b1 [16]byte
	binary.LittleEndian.PutUint64(b1[0:], seed0^lenTag)
	binary.LittleEndian.PutUint64(b1[8:], seed1^lenTag)
	first := len(data)
	if first > 16 {
		first = 16
	}
	for i := 0; i < first; i++ {
		b1[i] ^= data[i]
	}
	block.Encrypt(b1[:], b1[:])
	for off := 16; off < len(data); off += 16 {
		end := off + 16
		if end > len(data) {
			end = len(data)
		}
		for i := 0; i < end-off; i++ {
			b1[i] ^= data[off+i]
		}
		block.Encrypt(b1[:], b1[:])
	}
	return binary.LittleEndian.Uint64(b1[:8]), binary.LittleEndian.Uint64(b1[8:])
}

// TestChainAbsorbMatchesClosure pins the package reference to the
// closure definition on the four shapes and on lengths around every
// block boundary.
func TestChainAbsorbMatchesClosure(t *testing.T) {
	for _, n := range append([]int{0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65}, shapes...) {
		for iter := 0; iter < 32; iter++ {
			var key [16]byte
			var s [16]byte
			rand.Read(key[:])
			rand.Read(s[:])
			data := make([]byte, n)
			rand.Read(data)
			seed0 := binary.LittleEndian.Uint64(s[:8])
			seed1 := binary.LittleEndian.Uint64(s[8:])
			wantLo, wantHi := closureReference(key, data, seed0, seed1)
			gotLo, gotHi := ChainAbsorb(NewSchedule(key), data, seed0, seed1)
			if gotLo != wantLo || gotHi != wantHi {
				t.Fatalf("n=%d: ChainAbsorb (%x,%x) != closure (%x,%x)", n, gotLo, gotHi, wantLo, wantHi)
			}
		}
	}
}

// TestScheduleMatchesCipher pins the kernels' expanded round keys to the
// crypto/aes key schedule through a one-block encryption: applying the
// eleven round keys by hand must reproduce the block cipher.
func TestScheduleMatchesCipher(t *testing.T) {
	for iter := 0; iter < 64; iter++ {
		var key, pt [16]byte
		rand.Read(key[:])
		rand.Read(pt[:])
		s := NewSchedule(key)
		var want [16]byte
		s.block.Encrypt(want[:], pt[:])
		got := softAES128(&s.roundKeys, pt)
		if got != want {
			t.Fatalf("iter %d: schedule-driven encryption %x != crypto/aes %x", iter, got, want)
		}
	}
}

// softAES128 is a plain table-free AES-128 encryption over an expanded
// schedule, used only to validate [ExpandKeyAES128].
func softAES128(rk *[176]byte, in [16]byte) [16]byte {
	st := in
	for i := 0; i < 16; i++ {
		st[i] ^= rk[i]
	}
	for r := 1; r <= 10; r++ {
		for i := 0; i < 16; i++ {
			st[i] = sbox[st[i]]
		}
		st = shiftRows(st)
		if r != 10 {
			st = mixColumns(st)
		}
		for i := 0; i < 16; i++ {
			st[i] ^= rk[16*r+i]
		}
	}
	return st
}

func shiftRows(s [16]byte) [16]byte {
	var o [16]byte
	for c := 0; c < 4; c++ {
		for r := 0; r < 4; r++ {
			o[4*c+r] = s[4*((c+r)%4)+r]
		}
	}
	return o
}

func xtime(b byte) byte {
	if b&0x80 != 0 {
		return (b << 1) ^ 0x1b
	}
	return b << 1
}

func mixColumns(s [16]byte) [16]byte {
	var o [16]byte
	for c := 0; c < 4; c++ {
		a0, a1, a2, a3 := s[4*c], s[4*c+1], s[4*c+2], s[4*c+3]
		o[4*c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
		o[4*c+1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
		o[4*c+2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
		o[4*c+3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)
	}
	return o
}

// TestAbsorb13Block pins the batch-16 template to the fill block of
// group 0: the 0x03 domain tag and fifteen zero bytes.
func TestAbsorb13Block(t *testing.T) {
	if absorb13Block[0] != 0x03 {
		t.Fatalf("absorb13Block[0] = %#x, want 0x03", absorb13Block[0])
	}
	for i := 1; i < 16; i++ {
		if absorb13Block[i] != 0 {
			t.Fatalf("absorb13Block[%d] = %#x, want 0", i, absorb13Block[i])
		}
	}
	for g := 0; g < 4; g++ {
		for j := 0; j < 4; j++ {
			if laneIdxZ[g][2*j] != uint64(4*g+j) || laneIdxZ[g][2*j+1] != 0 {
				t.Fatalf("laneIdxZ[%d] = %v", g, laneIdxZ[g])
			}
		}
	}
}

func shapeName(n int) string {
	return map[int]string{13: "13", 20: "20", 36: "36", 68: "68"}[n]
}
