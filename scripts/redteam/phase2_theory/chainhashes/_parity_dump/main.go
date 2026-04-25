// _parity_dump — emit (primitive, data_hex, seed_components, expected_lo_hex)
// triples that the Python chainhashes/ mirrors must reproduce bit-for-bit.
//
// Usage:
//   go run scripts/redteam/phase2_theory/chainhashes/_parity_dump/main.go
//
// Output: JSON array on stdout. One entry per (primitive, test_vector) pair.
// The Python side loads this via chainhashes/_parity_test.py and verifies
// `chainhash_lo(data, seed) == expected_lo` for every entry.
//
// Test vectors are deterministic (data + seed drawn from a fixed-seed PRNG)
// so the JSON dump is stable across runs — any non-match indicates a
// mirror divergence, not a randomness artefact.
package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"math/rand"
	"os"
)

type entry struct {
	Primitive       string   `json:"primitive"`
	DataHex         string   `json:"data_hex"`
	SeedComponents []uint64 `json:"seed_components"`
	ExpectedLoHex   string   `json:"expected_lo_hex"`
	ExpectedHiHex   string   `json:"expected_hi_hex"`
}

// md5Hash128 duplicates redteam_test.go:md5Hash128 bit-for-bit. Kept
// in-file so this helper can be built as a standalone main without
// pulling the whole test package.
func md5Hash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	h := md5.New()
	var keyBuf [16]byte
	binary.LittleEndian.PutUint64(keyBuf[:8], seed0)
	binary.LittleEndian.PutUint64(keyBuf[8:], seed1)
	h.Write(keyBuf[:])
	h.Write(data)
	sum := h.Sum(nil)
	lo = binary.LittleEndian.Uint64(sum[:8])
	hi = binary.LittleEndian.Uint64(sum[8:])
	return
}

// chainHash128MD5 reproduces seed128.go:Seed128.ChainHash128 with MD5 as
// the inner primitive, for a fixed 16-component (1024-bit) seed.
func chainHash128MD5(data []byte, seed []uint64) (lo, hi uint64) {
	lo, hi = md5Hash128(data, seed[0], seed[1])
	for i := 2; i < len(seed); i += 2 {
		lo, hi = md5Hash128(data, seed[i]^lo, seed[i+1]^hi)
	}
	return
}

// --- t1ha1_64le (erthink/t1ha, LE variant) ----------------------------------
//
// Duplicated from harness_test.go so this standalone main can be built
// without pulling the itb test package. Bit-for-bit match with the canonical
// reference at https://github.com/erthink/t1ha/blob/master/src/t1ha1.c.

const (
	t1haPrime0 uint64 = 0xEC99BF0D8372CAAB
	t1haPrime1 uint64 = 0x82434FE90EDCEF39
	t1haPrime2 uint64 = 0xD4F06DB99D67BE4B
	t1haPrime3 uint64 = 0xBD9CACC22C6E9571
	t1haPrime4 uint64 = 0x9C06FAF4D023E3AB
	t1haPrime5 uint64 = 0xC060724A8424F345
	t1haPrime6 uint64 = 0xCB5AF53AE3AAAC31
)

func t1haRot64(v uint64, s uint) uint64 {
	return bits.RotateLeft64(v, -int(s))
}

func t1haMux64(v, prime uint64) uint64 {
	hi, lo := bits.Mul64(v, prime)
	return lo ^ hi
}

func t1haMix64(v, prime uint64) uint64 {
	v *= prime
	return v ^ t1haRot64(v, 41)
}

func t1haFinalWeakAvalanche(a, b uint64) uint64 {
	return t1haMux64(t1haRot64(a+b, 17), t1haPrime4) + t1haMix64(a^b, t1haPrime0)
}

func t1haTail64Le(data []byte, tail int) uint64 {
	n := tail & 7
	if n == 0 {
		return binary.LittleEndian.Uint64(data[:8])
	}
	var r uint64
	for i := 0; i < n; i++ {
		r |= uint64(data[i]) << (8 * i)
	}
	return r
}

func t1ha1_64le(data []byte, seed uint64) uint64 {
	length := uint64(len(data))
	a := seed
	b := length

	pos := 0
	if len(data) > 32 {
		c := t1haRot64(length, 17) + seed
		d := length ^ t1haRot64(seed, 17)
		for {
			w0 := binary.LittleEndian.Uint64(data[pos:])
			w1 := binary.LittleEndian.Uint64(data[pos+8:])
			w2 := binary.LittleEndian.Uint64(data[pos+16:])
			w3 := binary.LittleEndian.Uint64(data[pos+24:])
			pos += 32

			d02 := w0 ^ t1haRot64(w2+d, 17)
			c13 := w1 ^ t1haRot64(w3+c, 17)
			d -= b ^ t1haRot64(w1, 31)
			c += a ^ t1haRot64(w0, 41)
			b ^= t1haPrime0 * (c13 + w2)
			a ^= t1haPrime1 * (d02 + w3)

			if pos+32 > len(data) {
				break
			}
		}

		a ^= t1haPrime6 * (t1haRot64(c, 17) + d)
		b ^= t1haPrime5 * (c + t1haRot64(d, 17))
		length &= 31
	}

	tail := data[pos:]
	if length > 24 {
		b += t1haMux64(binary.LittleEndian.Uint64(tail[:8]), t1haPrime4)
		tail = tail[8:]
	}
	if length > 16 {
		a += t1haMux64(binary.LittleEndian.Uint64(tail[:8]), t1haPrime3)
		tail = tail[8:]
	}
	if length > 8 {
		b += t1haMux64(binary.LittleEndian.Uint64(tail[:8]), t1haPrime2)
		tail = tail[8:]
	}
	if length > 0 {
		a += t1haMux64(t1haTail64Le(tail, int(length)), t1haPrime1)
	}

	return t1haFinalWeakAvalanche(a, b)
}

// t1ha1Hash128 — parallel two-lane 128-bit adapter: two independent
// t1ha1_64le invocations with seed_lo and seed_hi.
func t1ha1Hash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	lo = t1ha1_64le(data, seed0)
	hi = t1ha1_64le(data, seed1)
	return
}

// chainHash128T1ha1 — 8 rounds of ChainHash128 with t1ha1 inner primitive.
func chainHash128T1ha1(data []byte, seed []uint64) (lo, hi uint64) {
	lo, hi = t1ha1Hash128(data, seed[0], seed[1])
	for i := 2; i < len(seed); i += 2 {
		kLo := seed[i] ^ lo
		kHi := seed[i+1] ^ hi
		lo, hi = t1ha1Hash128(data, kLo, kHi)
	}
	return
}

// --- SeaHash (ticki/tfs, Redox OS) ------------------------------------------
//
// Duplicated from harness_test.go so this standalone main can be built
// without pulling the itb test package. Bit-for-bit match with the canonical
// reference at https://github.com/ticki/tfs/tree/master/seahash/src.

const (
	seahashPrime uint64 = 0x6EED0E9DA4D94A4F
	seahashInitA uint64 = 0x16F11FE89B0D677C
	seahashInitB uint64 = 0xB480A793D8E6C86C
	seahashInitC uint64 = 0x6FE2E5AAF078EBC9
	seahashInitD uint64 = 0x14F994A4C5259381
)

func seahashDiffuse(x uint64) uint64 {
	x *= seahashPrime
	x ^= (x >> 32) >> (x >> 60)
	x *= seahashPrime
	return x
}

func seahashReadTail(buf []byte) uint64 {
	var x uint64
	for i, b := range buf {
		x |= uint64(b) << (8 * i)
	}
	return x
}

func seahash64(data []byte, seed uint64) uint64 {
	a, b, c, d := seahashInitA, seahashInitB, seahashInitC, seahashInitD
	if seed != 0 {
		a *= seed
		b *= seed
		c *= seed
		d *= seed
	}

	pos := 0
	for pos+8 <= len(data) {
		n := binary.LittleEndian.Uint64(data[pos:])
		a, b, c, d = b, c, d, seahashDiffuse(a^n)
		pos += 8
	}
	if pos < len(data) {
		n := seahashReadTail(data[pos:])
		a, b, c, d = b, c, d, seahashDiffuse(a^n)
	}
	return seahashDiffuse(a ^ b ^ c ^ d ^ uint64(len(data)))
}

func seahashHash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	lo = seahash64(data, seed0)
	hi = seahash64(data, seed1)
	return
}

func chainHash128SeaHash(data []byte, seed []uint64) (lo, hi uint64) {
	lo, hi = seahashHash128(data, seed[0], seed[1])
	for i := 2; i < len(seed); i += 2 {
		kLo := seed[i] ^ lo
		kHi := seed[i+1] ^ hi
		lo, hi = seahashHash128(data, kLo, kHi)
	}
	return
}

// --- mx3 (jonmaiga/mx3, CC0 license; v3.0.0 2022-04-19) ---------------------
//
// Duplicated from harness_test.go so this standalone main can be built
// without pulling the itb test package. Bit-for-bit match with the canonical
// reference at https://github.com/jonmaiga/mx3/blob/master/mx3.h.

const mx3C uint64 = 0xBEA225F9EB34556D

func mx3Mix(x uint64) uint64 {
	x ^= x >> 32
	x *= mx3C
	x ^= x >> 29
	x *= mx3C
	x ^= x >> 32
	x *= mx3C
	x ^= x >> 29
	return x
}

func mx3MixStream(h, x uint64) uint64 {
	x *= mx3C
	x ^= x >> 39
	h += x * mx3C
	h *= mx3C
	return h
}

func mx3MixStream4(h, a, b, c, d uint64) uint64 {
	a *= mx3C
	b *= mx3C
	c *= mx3C
	d *= mx3C
	a ^= a >> 39
	b ^= b >> 39
	c ^= c >> 39
	d ^= d >> 39
	h += a * mx3C
	h *= mx3C
	h += b * mx3C
	h *= mx3C
	h += c * mx3C
	h *= mx3C
	h += d * mx3C
	h *= mx3C
	return h
}

func mx3Hash(data []byte, seed uint64) uint64 {
	length := uint64(len(data))
	h := mx3MixStream(seed, length+1)

	pos := 0
	for length-uint64(pos) >= 64 {
		w0 := binary.LittleEndian.Uint64(data[pos:])
		w1 := binary.LittleEndian.Uint64(data[pos+8:])
		w2 := binary.LittleEndian.Uint64(data[pos+16:])
		w3 := binary.LittleEndian.Uint64(data[pos+24:])
		w4 := binary.LittleEndian.Uint64(data[pos+32:])
		w5 := binary.LittleEndian.Uint64(data[pos+40:])
		w6 := binary.LittleEndian.Uint64(data[pos+48:])
		w7 := binary.LittleEndian.Uint64(data[pos+56:])
		h = mx3MixStream4(h, w0, w1, w2, w3)
		h = mx3MixStream4(h, w4, w5, w6, w7)
		pos += 64
	}
	for length-uint64(pos) >= 8 {
		h = mx3MixStream(h, binary.LittleEndian.Uint64(data[pos:]))
		pos += 8
	}

	tail := data[pos:]
	switch len(tail) {
	case 0:
		return mx3Mix(h)
	case 1:
		return mx3Mix(mx3MixStream(h, uint64(tail[0])))
	case 2:
		return mx3Mix(mx3MixStream(h, uint64(binary.LittleEndian.Uint16(tail))))
	case 3:
		x := uint64(binary.LittleEndian.Uint16(tail[:2])) |
			uint64(tail[2])<<16
		return mx3Mix(mx3MixStream(h, x))
	case 4:
		return mx3Mix(mx3MixStream(h, uint64(binary.LittleEndian.Uint32(tail))))
	case 5:
		x := uint64(binary.LittleEndian.Uint32(tail[:4])) |
			uint64(tail[4])<<32
		return mx3Mix(mx3MixStream(h, x))
	case 6:
		x := uint64(binary.LittleEndian.Uint32(tail[:4])) |
			uint64(binary.LittleEndian.Uint16(tail[4:6]))<<32
		return mx3Mix(mx3MixStream(h, x))
	case 7:
		x := uint64(binary.LittleEndian.Uint32(tail[:4])) |
			uint64(binary.LittleEndian.Uint16(tail[4:6]))<<32 |
			uint64(tail[6])<<48
		return mx3Mix(mx3MixStream(h, x))
	}
	return mx3Mix(h)
}

func mx3Hash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	lo = mx3Hash(data, seed0)
	hi = mx3Hash(data, seed1)
	return
}

func chainHash128Mx3(data []byte, seed []uint64) (lo, hi uint64) {
	lo, hi = mx3Hash128(data, seed[0], seed[1])
	for i := 2; i < len(seed); i += 2 {
		kLo := seed[i] ^ lo
		kHi := seed[i+1] ^ hi
		lo, hi = mx3Hash128(data, kLo, kHi)
	}
	return
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return b
}

func randSeed16(rng *rand.Rand) []uint64 {
	s := make([]uint64, 16)
	for i := range s {
		s[i] = rng.Uint64()
	}
	return s
}

func main() {
	rng := rand.New(rand.NewSource(1))
	entries := []entry{}

	// MD5 parity vectors (existing set).
	md5Sizes := []int{0, 1, 16, 55, 64, 100, 1000}
	for _, sz := range md5Sizes {
		data := randBytes(rng, sz)
		seed := randSeed16(rng)
		lo, hi := chainHash128MD5(data, seed)
		entries = append(entries, entry{
			Primitive:      "md5",
			DataHex:        hex.EncodeToString(data),
			SeedComponents: seed,
			ExpectedLoHex:  fmt.Sprintf("%016x", lo),
			ExpectedHiHex:  fmt.Sprintf("%016x", hi),
		})
	}

	// SeaHash parity vectors. Size set exercises every SeaHash code path:
	//   0 (empty — final = diffuse(initXOR ^ 0)),
	//   1..7 (pure tail-only, no full block),
	//   8 (exactly one full block, no tail),
	//   9..15 (one block + tail),
	//   16 (two blocks, no tail),
	//   18 ("to be or not to be" length — matches canonical test vector
	//       shape: 2 full blocks + 2-byte tail),
	//   55 (6 blocks + 7-byte tail),
	//   64 (8 blocks, no tail),
	//   100, 1000 (many blocks + variable tail).
	seahashSizes := []int{0, 1, 3, 7, 8, 9, 15, 16, 18, 55, 64, 100, 1000}
	for _, sz := range seahashSizes {
		data := randBytes(rng, sz)
		seed := randSeed16(rng)
		lo, hi := chainHash128SeaHash(data, seed)
		entries = append(entries, entry{
			Primitive:      "seahash",
			DataHex:        hex.EncodeToString(data),
			SeedComponents: seed,
			ExpectedLoHex:  fmt.Sprintf("%016x", lo),
			ExpectedHiHex:  fmt.Sprintf("%016x", hi),
		})
	}

	// t1ha1 parity vectors. Size set exercises every tail-handling branch:
	//   0 (empty), 1 (case 1..8), 8 / 16 / 24 (case-boundary tail64_le),
	//   31 (default + full fall-through, no block), 32 (no block, tail=32),
	//   33 (1 block + case 1..8 with len=1), 55 (1 block + default tail),
	//   64 (2 blocks, no tail), 100 (3 blocks + 9..16 + 1..8 tail),
	//   1000 (many blocks + tail).
	t1ha1Sizes := []int{0, 1, 8, 16, 24, 31, 32, 33, 55, 64, 100, 1000}
	for _, sz := range t1ha1Sizes {
		data := randBytes(rng, sz)
		seed := randSeed16(rng)
		lo, hi := chainHash128T1ha1(data, seed)
		entries = append(entries, entry{
			Primitive:      "t1ha1",
			DataHex:        hex.EncodeToString(data),
			SeedComponents: seed,
			ExpectedLoHex:  fmt.Sprintf("%016x", lo),
			ExpectedHiHex:  fmt.Sprintf("%016x", hi),
		})
	}

	// mx3 parity vectors. Size set exercises every code path:
	//   0 (empty — final tail switch case 0),
	//   1..7 (each tail-switch case 1..7, no full block),
	//   8 (one 8-byte tail-loop iter, then case 0),
	//   9 (one 8-byte iter + case 1),
	//   16 (two 8-byte iters, case 0),
	//   55 (six 8-byte iters + case 7),
	//   63 (seven 8-byte iters + case 7),
	//   64 (one full 64-byte main-loop iter, case 0),
	//   65 (one 64-byte iter + case 1),
	//   100 (one 64-byte iter + 8-byte loop + tail),
	//   1000 (many 64-byte iters + tail).
	mx3Sizes := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 55, 63, 64, 65, 100, 1000}
	for _, sz := range mx3Sizes {
		data := randBytes(rng, sz)
		seed := randSeed16(rng)
		lo, hi := chainHash128Mx3(data, seed)
		entries = append(entries, entry{
			Primitive:      "mx3",
			DataHex:        hex.EncodeToString(data),
			SeedComponents: seed,
			ExpectedLoHex:  fmt.Sprintf("%016x", lo),
			ExpectedHiHex:  fmt.Sprintf("%016x", hi),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entries); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
}
