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

var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
	0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
	0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
	0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
	0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
	0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
	0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
	0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
	0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
	0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
	0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
	0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
	0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
	0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
	0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
	0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
	0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
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
// group 0 under a zero interlock-nonce fold: the 0x03 domain tag and
// fifteen zero bytes (the kernels XOR the group index and the fold in).
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
