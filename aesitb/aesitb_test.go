package aesitb

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"
)

// KAT vectors: key = 00 11 22 .. FF; nonce = 0x10, 0x11, ... (n bytes);
// generic data = 0x00, 0x01, ... (n bytes).

type pixelVector struct {
	tag  byte
	idx  uint64
	want string
}

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

// nonce length 16
var pixelVectors16 = []pixelVector{
	{DomainStartPixel, 0, "4372ef414898be0c117aed6d516a9d45"},
	{DomainStartPixel, 1, "c531ac84d80815371f68f163cf771ec6"},
	{DomainStartPixel, 42, "af0499dbfe2e7f7b8dc5cef12a38b46c"},
	{DomainStartPixel, 4294967295, "a3523cc769e3dd8070c851a23b6e7314"},
	{DomainStartPixel, 140737488355328, "4f74e94b9444c1af428f4b3ecb86eb33"},
	{DomainChunkLock, 0, "563505ffcade04964a58d887b01d9f10"},
	{DomainChunkLock, 1, "061d2d871206773dc9c6c504e57bac23"},
	{DomainChunkLock, 42, "89d7e7c2c6d2108e84115f49dda24dc2"},
	{DomainLockSeed, 0, "95819815e875361dab5cb4978cfcd08d"},
	{DomainLockSeed, 1, "af9c8532e67b24012ccea11059936a37"},
	{DomainBlockHash, 0, "43de4432e18df941ec594e83b5dea048"},
	{DomainBlockHash, 1, "ec049e47325e97fcd80526b7e5be9078"},
}

// nonce length 32
var pixelVectors32 = []pixelVector{
	{DomainStartPixel, 0, "34f41ab9c2180bc9a7a9f01cd89be06a"},
	{DomainStartPixel, 1, "aeb9576e67bdff980457adbf050dab21"},
	{DomainStartPixel, 42, "a937d9e716cc6c7afd4744463925bf35"},
	{DomainStartPixel, 4294967295, "32a73fe3f8d4bccdbe73480f66e8ba2c"},
	{DomainStartPixel, 140737488355328, "01638d1b5a80b8e262fd61d9d297e66c"},
	{DomainChunkLock, 0, "d07d2854a7ca859c1bee84c1ab628fef"},
	{DomainChunkLock, 1, "5bb5e017c6ab265ea820f97299b76808"},
	{DomainChunkLock, 42, "0b9dc86fd8b504622bbee4f1cb22afcf"},
	{DomainLockSeed, 0, "131e6bd510e0b4aa6c8ecf6369117930"},
	{DomainLockSeed, 1, "fb6a1f491fefa5b40a2403056c177a33"},
	{DomainBlockHash, 0, "f953779a273548656cb0a9be5d621b60"},
	{DomainBlockHash, 1, "5505216021334269ee2db63c7baff08b"},
}

// nonce length 64
var pixelVectors64 = []pixelVector{
	{DomainStartPixel, 0, "8facbe1721eeaaf077ed3c3d88e6d8e7"},
	{DomainStartPixel, 1, "a63527a76ea17b6e4ba94401cd69122d"},
	{DomainStartPixel, 42, "ea1301cdb37c07cf81eccbcb0612a29d"},
	{DomainStartPixel, 4294967295, "c7be181c8c56d402a40e72ae0ab622b8"},
	{DomainStartPixel, 140737488355328, "ec1002c8dd12b5133d33a87707e5546b"},
	{DomainChunkLock, 0, "4a6682219e4b3a50c7f023795ad795a3"},
	{DomainChunkLock, 1, "920aee954d9854eded8e77535fd196a0"},
	{DomainChunkLock, 42, "f23adec575a01c9d0bbfa0b55b206355"},
	{DomainLockSeed, 0, "4ef0f604fe7793f805339c4a16993092"},
	{DomainLockSeed, 1, "a90e081d901921249b8abbd4c3f68a28"},
	{DomainBlockHash, 0, "4eca5c9b0c9bb246799689faa102c0af"},
	{DomainBlockHash, 1, "94a7312cf760a4ab54e1d3d7093b513e"},
}

var genericVectors = []genericVector{
	{0, 0x0, 0x0, "d03e268799c14203bdb3e663165d6b23"},
	{1, 0x0, 0x0, "f2a4e404c80c84451e35cadcc7f22bb9"},
	{15, 0x0, 0x0, "95be57f5a239f3ab144382b7cd8695de"},
	{16, 0x0, 0x0, "3171e8f8165c8ff5203ac9aa371c719a"},
	{17, 0x0, 0x0, "48d3f6fcc2985cf31a074ea2c78b1d09"},
	{31, 0x0, 0x0, "064e72d014e7a41c4fc3b7d1b938f625"},
	{32, 0x0, 0x0, "e08f48e9037d3bc81d03dc0adc1b9d3b"},
	{33, 0x0, 0x0, "7370df93d8fd5e118d33484f582e1750"},
	{63, 0x0, 0x0, "c17822cc92d1a5fb712a1ea655de82ad"},
	{64, 0x0, 0x0, "81615890aab0306bf4b32bbe2d7ca1af"},
	{0, 0x1, 0x0, "787e6d0bae570d2ec58796bcbf68c172"},
	{0, 0x0, 0x1, "e9d430852929ab3d88c240ddc40f823c"},
	{5, 0x123456789abcdef, 0xfedcba9876543210, "7486079419f3f0767b579065d6cc3d93"},
	{16, 0xffffffffffffffff, 0xffffffffffffffff, "2eae20695db216506bd63f96fda12ca0"},
	{33, 0x7, 0x9, "dccfc56b263e1a2fc13052534f15092e"},
	{64, 0x8000000000000000, 0x1, "a7a8e09b329611b7aec6a97b0e75cd25"},
}

func TestSessionKAT(t *testing.T) {
	for _, tc := range []struct {
		nlen int
		vecs []pixelVector
	}{{16, pixelVectors16}, {32, pixelVectors32}, {64, pixelVectors64}} {
		sess, err := NewSession(refKey, refNonce(tc.nlen))
		if err != nil {
			t.Fatalf("nonce %d: %v", tc.nlen, err)
		}
		for _, v := range tc.vecs {
			got := sess.HashPixel(v.tag, v.idx)
			if g := hex.EncodeToString(got[:]); g != v.want {
				t.Errorf("nonce=%d tag=%#x idx=%d: got %s want %s", tc.nlen, v.tag, v.idx, g, v.want)
			}
		}
	}
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

func TestNonceLength(t *testing.T) {
	for _, n := range []int{0, 1, 15, 17, 31, 33, 63, 65} {
		if s, err := NewSession(refKey, make([]byte, n)); err == nil || s != nil {
			t.Errorf("nonce len %d accepted", n)
		}
		if _, err := SessionInit(refKey, make([]byte, n), DomainBlockHash); err == nil {
			t.Errorf("SessionInit accepted nonce len %d", n)
		}
	}
}

func TestIdxAndTagBounds(t *testing.T) {
	sess, _ := NewSession(refKey, refNonce(16))
	_ = sess.HashPixel(DomainBlockHash, MaxIdx-1)
	mustPanic := func(name string, f func()) {
		defer func() {
			if recover() == nil {
				t.Errorf("%s: expected panic", name)
			}
		}()
		f()
	}
	mustPanic("idx", func() { sess.HashPixel(DomainBlockHash, MaxIdx) })
	mustPanic("tag", func() { sess.HashPixel(0x05, 0) })
}

// TestRoundConstantsNUMS re-derives every RC row from the fractional bits
// of sqrt(p) (the FIPS 180-4 initial-hash-value construction) and compares
// byte-for-byte, so the table cannot drift from its stated provenance.
func TestRoundConstantsNUMS(t *testing.T) {
	frac := func(p int64, bits uint) uint64 {
		// floor(frac(sqrt(p)) * 2^bits) == isqrt(p << 2*bits) mod 2^bits
		n := new(big.Int).Lsh(big.NewInt(p), 2*bits)
		n.Sqrt(n)
		mask := new(big.Int).Lsh(big.NewInt(1), bits)
		mask.Sub(mask, big.NewInt(1))
		return n.And(n, mask).Uint64()
	}
	primes8 := []int64{2, 3, 5, 7, 11, 13, 17, 19}
	primes4 := []int64{23, 29, 31, 37}

	var want [8][16]byte
	for i, p := range primes8 {
		binary.BigEndian.PutUint32(want[i/4][4*(i%4):], uint32(frac(p, 32)))
	}
	for i, p := range primes8 {
		binary.BigEndian.PutUint64(want[2+i/2][8*(i%2):], frac(p, 64))
	}
	for i, p := range primes4 {
		binary.BigEndian.PutUint64(want[6+i/2][8*(i%2):], frac(p, 64))
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
