package blake2basm

import (
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// runReferenceClosure512 replays the bit-exact buffer-packing and
// digest-extraction logic of the hashes.BLAKE2b512 closure on a single
// pixel, using upstream blake2b.Sum512 as the digest oracle. Used as
// the per-lane parity baseline for the 4-pixel-batched ASM kernels.
// Any divergence between a kernel's per-lane output and this reference
// would observably change the digest emitted by hashes.BLAKE2b512Pair.
func runReferenceClosure512(b2key [64]byte, data []byte, seed [8]uint64) [8]uint64 {
	const keyLen = 64
	const seedInjectBytes = 64
	payloadLen := len(data)
	if payloadLen < seedInjectBytes {
		payloadLen = seedInjectBytes
	}
	need := keyLen + payloadLen
	buf := make([]byte, need)
	copy(buf[:keyLen], b2key[:])
	copy(buf[keyLen:keyLen+len(data)], data)
	for i := 0; i < 8; i++ {
		off := keyLen + i*8
		binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
	}
	digest := blake2b.Sum512(buf)
	var out [8]uint64
	for i := 0; i < 8; i++ {
		out[i] = binary.LittleEndian.Uint64(digest[i*8:])
	}
	return out
}

// runReferenceClosure256 — BLAKE2b-256 single-pixel reference. Mirrors
// the hashes.BLAKE2b256 closure layout (32-byte key prefix, 4 seed
// components XOR'd into buf[32:64], blake2b.Sum256 dispatch).
func runReferenceClosure256(b2key [32]byte, data []byte, seed [4]uint64) [4]uint64 {
	const keyLen = 32
	const seedInjectBytes = 32
	payloadLen := len(data)
	if payloadLen < seedInjectBytes {
		payloadLen = seedInjectBytes
	}
	need := keyLen + payloadLen
	buf := make([]byte, need)
	copy(buf[:keyLen], b2key[:])
	copy(buf[keyLen:keyLen+len(data)], data)
	for i := 0; i < 4; i++ {
		off := keyLen + i*8
		binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
	}
	digest := blake2b.Sum256(buf)
	var out [4]uint64
	for i := 0; i < 4; i++ {
		out[i] = binary.LittleEndian.Uint64(digest[i*8:])
	}
	return out
}

// chainAbsorb512Case parameterises a BLAKE2b-512 4-lane parity-test
// scenario. Each scenario fixes a single shared b2key and four
// per-lane seeds; the test injects four distinct per-lane data payloads
// to surface any cross-lane state-leak bugs in the batched kernel.
type chainAbsorb512Case struct {
	name  string
	b2key [64]byte
	seeds [4][8]uint64
}

var chainAbsorb512Cases = []chainAbsorb512Case{
	{
		name:  "zero key, zero seeds",
		b2key: [64]byte{},
		seeds: [4][8]uint64{},
	},
	{
		name:  "ascending key, distinct lane seeds",
		b2key: ascendingKey512(),
		seeds: [4][8]uint64{
			{1, 2, 3, 4, 5, 6, 7, 8},
			{9, 10, 11, 12, 13, 14, 15, 16},
			{17, 18, 19, 20, 21, 22, 23, 24},
			{25, 26, 27, 28, 29, 30, 31, 32},
		},
	},
	{
		name:  "high-bit-set key, high-bit-set seeds",
		b2key: highBitKey512(),
		seeds: [4][8]uint64{
			{0x8000000000000001, 0x8000000000000002, 0x8000000000000003, 0x8000000000000004,
				0x8000000000000005, 0x8000000000000006, 0x8000000000000007, 0x8000000000000008},
			{0x8000000000000009, 0x800000000000000a, 0x800000000000000b, 0x800000000000000c,
				0x800000000000000d, 0x800000000000000e, 0x800000000000000f, 0x8000000000000010},
			{0x8000000000000011, 0x8000000000000012, 0x8000000000000013, 0x8000000000000014,
				0x8000000000000015, 0x8000000000000016, 0x8000000000000017, 0x8000000000000018},
			{0x8000000000000019, 0x800000000000001a, 0x800000000000001b, 0x800000000000001c,
				0x800000000000001d, 0x800000000000001e, 0x800000000000001f, 0x8000000000000020},
		},
	},
	{
		name:  "zero key, all-ones seeds",
		b2key: [64]byte{},
		seeds: [4][8]uint64{
			{0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
				0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
			{0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
				0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
			{0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
				0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
			{0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff,
				0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
		},
	},
}

func ascendingKey512() [64]byte {
	var k [64]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func highBitKey512() [64]byte {
	var k [64]byte
	for i := range k {
		k[i] = 0x80 | byte(i)
	}
	return k
}

// makeLaneData builds four lane-distinct fixed-length data buffers.
// The byte fill at position p in lane l is byte(p + 0xa0 + l*0x40) so
// every lane carries a distinguishable per-byte signature, surfacing
// cross-lane state-leak bugs in the ASM kernel as a visible mismatch.
func makeLaneData512(n int) ([4][]byte, [4]*byte) {
	var bufs [4][]byte
	var ptrs [4]*byte
	for lane := 0; lane < 4; lane++ {
		bufs[lane] = make([]byte, n)
		for i := range bufs[lane] {
			bufs[lane][i] = byte(i + 0xa0 + lane*0x40)
		}
		ptrs[lane] = &bufs[lane][0]
	}
	return bufs, ptrs
}

// runChainAbsorb512Test exercises a single (kernel, length) pair across
// the standard edge-case matrix. Each lane's output must match the
// per-lane scalar reference bit-exactly.
func runChainAbsorb512Test(
	t *testing.T,
	name string,
	dataLen int,
	kernel func(*[8]uint64, *[64]byte, *[4][8]uint64, *[4]*byte, *[4][8]uint64),
) {
	t.Helper()
	for _, tc := range chainAbsorb512Cases {
		t.Run(tc.name, func(t *testing.T) {
			bufs, ptrs := makeLaneData512(dataLen)
			var laneWant [4][8]uint64
			for lane := 0; lane < 4; lane++ {
				laneWant[lane] = runReferenceClosure512(tc.b2key, bufs[lane], tc.seeds[lane])
			}
			var got [4][8]uint64
			kernel(&Blake2bIV512Param, &tc.b2key, &tc.seeds, &ptrs, &got)
			for lane := 0; lane < 4; lane++ {
				if got[lane] != laneWant[lane] {
					t.Fatalf("%s lane %d: got=%x want=%x", name, lane, got[lane], laneWant[lane])
				}
			}
		})
	}
}

func TestBlake2b512ChainAbsorb20x4(t *testing.T) {
	runChainAbsorb512Test(t, "Blake2b512ChainAbsorb20x4", 20, Blake2b512ChainAbsorb20x4)
}

func TestBlake2b512ChainAbsorb36x4(t *testing.T) {
	runChainAbsorb512Test(t, "Blake2b512ChainAbsorb36x4", 36, Blake2b512ChainAbsorb36x4)
}

func TestBlake2b512ChainAbsorb68x4(t *testing.T) {
	runChainAbsorb512Test(t, "Blake2b512ChainAbsorb68x4", 68, Blake2b512ChainAbsorb68x4)
}

// chainAbsorb256Case parameterises a BLAKE2b-256 4-lane parity-test
// scenario. Same shape as the 512-bit case scaled to the 32-byte key
// prefix and 4 seed components.
type chainAbsorb256Case struct {
	name  string
	b2key [32]byte
	seeds [4][4]uint64
}

var chainAbsorb256Cases = []chainAbsorb256Case{
	{
		name:  "zero key, zero seeds",
		b2key: [32]byte{},
		seeds: [4][4]uint64{},
	},
	{
		name:  "ascending key, distinct lane seeds",
		b2key: ascendingKey256(),
		seeds: [4][4]uint64{
			{1, 2, 3, 4},
			{5, 6, 7, 8},
			{9, 10, 11, 12},
			{13, 14, 15, 16},
		},
	},
	{
		name:  "high-bit-set key, high-bit-set seeds",
		b2key: highBitKey256(),
		seeds: [4][4]uint64{
			{0x8000000000000001, 0x8000000000000002, 0x8000000000000003, 0x8000000000000004},
			{0x8000000000000005, 0x8000000000000006, 0x8000000000000007, 0x8000000000000008},
			{0x8000000000000009, 0x800000000000000a, 0x800000000000000b, 0x800000000000000c},
			{0x800000000000000d, 0x800000000000000e, 0x800000000000000f, 0x8000000000000010},
		},
	},
	{
		name:  "zero key, all-ones seeds",
		b2key: [32]byte{},
		seeds: [4][4]uint64{
			{0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
			{0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
			{0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
			{0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff},
		},
	},
}

func ascendingKey256() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func highBitKey256() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = 0x80 | byte(i)
	}
	return k
}

func makeLaneData256(n int) ([4][]byte, [4]*byte) {
	var bufs [4][]byte
	var ptrs [4]*byte
	for lane := 0; lane < 4; lane++ {
		bufs[lane] = make([]byte, n)
		for i := range bufs[lane] {
			bufs[lane][i] = byte(i + 0xb0 + lane*0x40)
		}
		ptrs[lane] = &bufs[lane][0]
	}
	return bufs, ptrs
}

func runChainAbsorb256Test(
	t *testing.T,
	name string,
	dataLen int,
	kernel func(*[8]uint64, *[32]byte, *[4][4]uint64, *[4]*byte, *[4][8]uint64),
) {
	t.Helper()
	for _, tc := range chainAbsorb256Cases {
		t.Run(tc.name, func(t *testing.T) {
			bufs, ptrs := makeLaneData256(dataLen)
			var laneWant [4][4]uint64
			for lane := 0; lane < 4; lane++ {
				laneWant[lane] = runReferenceClosure256(tc.b2key, bufs[lane], tc.seeds[lane])
			}
			var got [4][8]uint64
			kernel(&Blake2bIV256Param, &tc.b2key, &tc.seeds, &ptrs, &got)
			for lane := 0; lane < 4; lane++ {
				for i := 0; i < 4; i++ {
					if got[lane][i] != laneWant[lane][i] {
						t.Fatalf("%s lane %d out[%d]: got=%#x want=%#x",
							name, lane, i, got[lane][i], laneWant[lane][i])
					}
				}
			}
		})
	}
}

func TestBlake2b256ChainAbsorb20x4(t *testing.T) {
	runChainAbsorb256Test(t, "Blake2b256ChainAbsorb20x4", 20, Blake2b256ChainAbsorb20x4)
}

func TestBlake2b256ChainAbsorb36x4(t *testing.T) {
	runChainAbsorb256Test(t, "Blake2b256ChainAbsorb36x4", 36, Blake2b256ChainAbsorb36x4)
}

func TestBlake2b256ChainAbsorb68x4(t *testing.T) {
	runChainAbsorb256Test(t, "Blake2b256ChainAbsorb68x4", 68, Blake2b256ChainAbsorb68x4)
}

// TestBlake2bIV_RFC7693 verifies the IV table matches RFC 7693 §3.2 —
// a regression-fast smoke test that catches accidental edits to
// Blake2bIV's individual entries before any chain-absorb call reaches
// a broken initial state.
func TestBlake2bIV_RFC7693(t *testing.T) {
	want := [8]uint64{
		0x6a09e667f3bcc908,
		0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b,
		0xa54ff53a5f1d36f1,
		0x510e527fade682d1,
		0x9b05688c2b3e6c1f,
		0x1f83d9abfb41bd6b,
		0x5be0cd19137e2179,
	}
	if Blake2bIV != want {
		t.Fatalf("Blake2bIV deviates from RFC 7693 §3.2:\n  got  = %x\n  want = %x", Blake2bIV, want)
	}
}

// TestBlake2bIVParam_DerivedFromIV verifies the precomputed IV-with-
// paramBlock-XOR'd-into-h0 constants for -256 and -512 match the RFC
// 7693 §3.3 parameter-block derivation. Catches regressions in the
// encoded h0[0] values without forcing the rest of the tests to
// re-derive them at runtime.
func TestBlake2bIVParam_DerivedFromIV(t *testing.T) {
	const paramBlock512 = uint64(0x0000_0000_0101_0040) // digestLength=64, fanout=1, depth=1
	const paramBlock256 = uint64(0x0000_0000_0101_0020) // digestLength=32, fanout=1, depth=1

	want512 := Blake2bIV
	want512[0] ^= paramBlock512
	if Blake2bIV512Param != want512 {
		t.Fatalf("Blake2bIV512Param mismatch:\n  got  = %x\n  want = %x", Blake2bIV512Param, want512)
	}

	want256 := Blake2bIV
	want256[0] ^= paramBlock256
	if Blake2bIV256Param != want256 {
		t.Fatalf("Blake2bIV256Param mismatch:\n  got  = %x\n  want = %x", Blake2bIV256Param, want256)
	}
}
