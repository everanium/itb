package aesitb

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"
)

// KAT vectors: key = 00 11 22 .. FF; generic data = 0x00, 0x01, ...
// (n bytes); the noise-fill tests take their nonce from refNonce
// (0x10, 0x11, ...).

type genericVector struct {
	dataLen      int
	seed0, seed1 uint64
	want         string
}

var refKey = [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}

func refNonce(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(0x10 + i)
	}
	return out
}

var genericVectors = []genericVector{
	{0, 0x0, 0x0, "b184dc9639cb19463a318b5bdbef60b3"},
	{1, 0x0, 0x0, "98aa26e22213e0995747f26166741da1"},
	{15, 0x0, 0x0, "67ff582c8131e477e50a0d5ad8159ffa"},
	{16, 0x0, 0x0, "b525d15864f5da4095cac4878e734e65"},
	{17, 0x0, 0x0, "b83d1718c4886682779773e766da4740"},
	{31, 0x0, 0x0, "b4bb6ec276da61c523e83bdb6c71d283"},
	{32, 0x0, 0x0, "6bce525c8ccab6ef9397b24764613f7b"},
	{33, 0x0, 0x0, "12bf744bf5dc16db8fe26756e0bdfdc9"},
	{63, 0x0, 0x0, "b60baf0921ce4914e43c7d22742bc285"},
	{64, 0x0, 0x0, "1f43035d6a9e6d218803d2e171b9d4e1"},
	{0, 0x1, 0x0, "877c1a9b664408e3a0f05d6e0bc743d3"},
	{0, 0x0, 0x1, "3e3957b58667430747216ab9e87dd55a"},
	{5, 0x123456789abcdef, 0xfedcba9876543210, "4769146529998d0c4d2861b4bc1efdfe"},
	{16, 0xffffffffffffffff, 0xffffffffffffffff, "b0e1cbcf08246eb0a7f190fe1ad780dd"},
	{33, 0x7, 0x9, "57e01a09debb3f6a814a92505188b8d0"},
	{64, 0x8000000000000000, 0x1, "98876054889177dd47c546cd01811630"},
	{80, 0x0, 0x0, "bb2af2751c71a52fd0fc49c95ef350c0"},
	{96, 0x0, 0x0, "37d5acf4a140659dba5d810f10b62d0a"},
	{128, 0x123456789abcdef, 0xfedcba987654321, "71f22c5f6678b8026faabb5aa7bb6ee5"},
}

func TestGenericKAT(t *testing.T) {
	for _, v := range genericVectors {
		data := make([]byte, v.dataLen)
		for i := range data {
			data[i] = byte(i)
		}
		got := HashGeneric(refKey, data, v.seed0, v.seed1)
		if g := hex.EncodeToString(got[:]); g != v.want {
			t.Errorf("len=%d seeds=(%#x,%#x): got %s want %s", v.dataLen, v.seed0, v.seed1, g, v.want)
		}
	}
}

// TestRoundConstantsNUMS re-derives every rc row from π itself — the
// fractional hexadecimal expansion computed with Machin's formula
// π = 16·atan(1/5) − 4·atan(1/239) in fixed-point big-integer
// arithmetic — and compares byte-for-byte under the stated loading
// convention (word i = fractional hex digits 32·i + 1 … 32·i + 32, most
// significant byte first = AES state byte 0), so the table cannot drift
// from its stated provenance.
func TestRoundConstantsNUMS(t *testing.T) {
	const fracBits = 8 * 128 // eight 128-bit words
	const guard = 64
	one := new(big.Int).Lsh(big.NewInt(1), fracBits+guard)
	arctanInv := func(x int64) *big.Int {
		sum := new(big.Int)
		term := new(big.Int).Quo(one, big.NewInt(x))
		x2 := big.NewInt(x * x)
		tmp := new(big.Int)
		for n, sign := int64(1), 1; term.Sign() != 0; n, sign = n+2, -sign {
			tmp.Quo(term, big.NewInt(n))
			if sign > 0 {
				sum.Add(sum, tmp)
			} else {
				sum.Sub(sum, tmp)
			}
			term.Quo(term, x2)
		}
		return sum
	}
	pi := new(big.Int).Mul(big.NewInt(16), arctanInv(5))
	pi.Sub(pi, new(big.Int).Mul(big.NewInt(4), arctanInv(239)))
	frac := new(big.Int).Sub(pi, new(big.Int).Mul(big.NewInt(3), one))
	frac.Rsh(frac, guard)
	digits := frac.FillBytes(make([]byte, fracBits/8))
	if got := hex.EncodeToString(digits[:4]); got != "243f6a88" {
		t.Fatalf("pi fraction starts %s, want 243f6a88", got)
	}

	var want [8][16]byte
	for i := range want {
		copy(want[i][:], digits[16*i:16*i+16])
	}
	for i := range want {
		if rc[i] != want[i] {
			t.Errorf("rc[%d] = %x, derived %x", i, rc[i], want[i])
		}
		for j := 0; j < i; j++ {
			if rc[i] == rc[j] {
				t.Errorf("rc[%d] duplicates rc[%d]", i, j)
			}
		}
	}
}

// TestAESRoundFIPS197 validates the in-file round function by running a
// full AES-128 encryption (nine aesRound calls plus a final round without
// MixColumns) over the FIPS-197 Appendix C.1 vector.
func TestAESRoundFIPS197(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}
	rk := expandKey128(key)

	var state [16]byte
	copy(state[:], mustHex("00112233445566778899aabbccddeeff"))
	addRoundKey(&state, &rk[0])
	for r := 1; r < 10; r++ {
		aesRound(&state, &rk[r])
	}
	subBytes(&state)
	shiftRows(&state)
	addRoundKey(&state, &rk[10])
	if got := hex.EncodeToString(state[:]); got != "69c4e0d86a7b0430d8cdb78070b4c55a" {
		t.Fatalf("AES-128 FIPS-197 C.1: got %s", got)
	}
}

// expandKey128 is the FIPS-197 § 5.2 key schedule, test-only.
func expandKey128(key [16]byte) [11][16]byte {
	var w [44][4]byte
	for i := 0; i < 4; i++ {
		copy(w[i][:], key[4*i:4*i+4])
	}
	rcon := byte(1)
	for i := 4; i < 44; i++ {
		tmp := w[i-1]
		if i%4 == 0 {
			tmp = [4]byte{sbox[tmp[1]] ^ rcon, sbox[tmp[2]], sbox[tmp[3]], sbox[tmp[0]]}
			rcon = xtime(rcon)
		}
		for j := 0; j < 4; j++ {
			w[i][j] = w[i-4][j] ^ tmp[j]
		}
	}
	var out [11][16]byte
	for r := 0; r < 11; r++ {
		for c := 0; c < 4; c++ {
			copy(out[r][4*c:4*c+4], w[4*r+c][:])
		}
	}
	return out
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// invAESRound inverts aesRound (AddRoundKey, InvMixColumns, InvShiftRows,
// InvSubBytes), test-only.
func invAESRound(s, rk *[16]byte) {
	addRoundKey(s, rk)
	for col := 0; col < 4; col++ {
		a0, a1, a2, a3 := s[4*col], s[4*col+1], s[4*col+2], s[4*col+3]
		mul := func(b, m byte) byte {
			var p byte
			for ; m != 0; m >>= 1 {
				if m&1 != 0 {
					p ^= b
				}
				b = xtime(b)
			}
			return p
		}
		s[4*col+0] = mul(a0, 14) ^ mul(a1, 11) ^ mul(a2, 13) ^ mul(a3, 9)
		s[4*col+1] = mul(a0, 9) ^ mul(a1, 14) ^ mul(a2, 11) ^ mul(a3, 13)
		s[4*col+2] = mul(a0, 13) ^ mul(a1, 9) ^ mul(a2, 14) ^ mul(a3, 11)
		s[4*col+3] = mul(a0, 11) ^ mul(a1, 13) ^ mul(a2, 9) ^ mul(a3, 14)
	}
	s[5], s[9], s[13], s[1] = s[1], s[5], s[9], s[13]
	s[10], s[14], s[2], s[6] = s[2], s[6], s[10], s[14]
	s[15], s[3], s[7], s[11] = s[3], s[7], s[11], s[15]
	var inv [256]byte
	for i, v := range sbox {
		inv[v] = byte(i)
	}
	for i := range s {
		s[i] = inv[s[i]]
	}
}

// TestGenericOneBlockInversion is the key-recovery negative control the
// Non-PRF classification rests on: the seed enters once, by XOR, ahead of
// a public permutation, so one known (data, full 16-byte output) pair
// inverts — walking the finalising rounds rc[(b+1) mod 8], rc[b mod 8]
// and the absorbed blocks backwards — to key XOR (LE64(seed0) ||
// LE64(seed1)). The inversion is exact at every shipped shape and at
// lengths that wrap the constant cycle, which also pins the documented
// schedule from the other side.
func TestGenericOneBlockInversion(t *testing.T) {
	for _, n := range []int{0, 13, 20, 36, 68, 80, 96, 128} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(7*i + n)
		}
		seed0, seed1 := uint64(0x0123456789abcdef)^uint64(n), uint64(0xfedcba9876543210)
		state := HashGeneric(refKey, data, seed0, seed1)

		padLen := 16 - n%16
		padded := append(append([]byte(nil), data...), bytes.Repeat([]byte{byte(padLen)}, padLen)...)
		b := len(padded) / 16
		invAESRound(&state, &rc[(b+1)%8])
		invAESRound(&state, &rc[b%8])
		for i := b - 1; i >= 0; i-- {
			invAESRound(&state, &rc[i%8])
			var blk [16]byte
			copy(blk[:], padded[16*i:])
			addRoundKey(&state, &blk)
		}
		var want [16]byte
		binary.LittleEndian.PutUint64(want[:8], seed0)
		binary.LittleEndian.PutUint64(want[8:], seed1)
		addRoundKey(&want, &refKey)
		if state != want {
			t.Errorf("n=%d: inversion gives %x, want key^seed %x", n, state, want)
		}
	}
}
