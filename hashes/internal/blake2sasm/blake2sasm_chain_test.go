package blake2sasm

import (
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/blake2s"
)

// runReferenceClosure256 replays the bit-exact buffer-packing and
// digest-extraction logic of the hashes.BLAKE2s256 closure on a single
// pixel, using upstream blake2s.Sum256 as the digest oracle. Used as
// the per-lane parity baseline for the 4-pixel-batched ASM kernels.
// Any divergence between a kernel's per-lane output and this reference
// would observably change the digest emitted by hashes.BLAKE2s256Pair.
func runReferenceClosure256(b2key [32]byte, data []byte, seed [4]uint64) [8]uint32 {
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
	digest := blake2s.Sum256(buf)
	var out [8]uint32
	for i := 0; i < 8; i++ {
		out[i] = binary.LittleEndian.Uint32(digest[i*4:])
	}
	return out
}

// chainAbsorb256Case parameterises a BLAKE2s-256 4-lane parity-test
// scenario. Each scenario fixes a single shared b2key and four
// per-lane seeds; the test injects four distinct per-lane data payloads
// to surface any cross-lane state-leak bugs in the batched kernel.
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

// makeLaneData256 builds four lane-distinct fixed-length data buffers.
// The byte fill at position p in lane l is byte(p + 0xb0 + l*0x40) so
// every lane carries a distinguishable per-byte signature, surfacing
// cross-lane state-leak bugs in the ASM kernel as a visible mismatch.
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

// runChainAbsorb256Test exercises a single (kernel, length) pair across
// the standard edge-case matrix. Each lane's output must match the
// per-lane scalar reference bit-exactly.
func runChainAbsorb256Test(
	t *testing.T,
	name string,
	dataLen int,
	kernel func(*[8]uint32, *[32]byte, *[4][4]uint64, *[4]*byte, *[4][8]uint32),
) {
	t.Helper()
	for _, tc := range chainAbsorb256Cases {
		t.Run(tc.name, func(t *testing.T) {
			bufs, ptrs := makeLaneData256(dataLen)
			var laneWant [4][8]uint32
			for lane := 0; lane < 4; lane++ {
				laneWant[lane] = runReferenceClosure256(tc.b2key, bufs[lane], tc.seeds[lane])
			}
			var got [4][8]uint32
			kernel(&Blake2sIV256Param, &tc.b2key, &tc.seeds, &ptrs, &got)
			for lane := 0; lane < 4; lane++ {
				for i := 0; i < 8; i++ {
					if got[lane][i] != laneWant[lane][i] {
						t.Fatalf("%s lane %d out[%d]: got=%#x want=%#x",
							name, lane, i, got[lane][i], laneWant[lane][i])
					}
				}
			}
		})
	}
}

func TestBlake2s256ChainAbsorb20x4(t *testing.T) {
	runChainAbsorb256Test(t, "Blake2s256ChainAbsorb20x4", 20, Blake2s256ChainAbsorb20x4)
}

func TestBlake2s256ChainAbsorb36x4(t *testing.T) {
	runChainAbsorb256Test(t, "Blake2s256ChainAbsorb36x4", 36, Blake2s256ChainAbsorb36x4)
}

func TestBlake2s256ChainAbsorb68x4(t *testing.T) {
	runChainAbsorb256Test(t, "Blake2s256ChainAbsorb68x4", 68, Blake2s256ChainAbsorb68x4)
}

// TestBlake2sIV_RFC7693 verifies the IV table matches RFC 7693 §3.2 —
// a regression-fast smoke test that catches accidental edits to
// Blake2sIV's individual entries before any chain-absorb call reaches
// a broken initial state.
func TestBlake2sIV_RFC7693(t *testing.T) {
	want := [8]uint32{
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19,
	}
	if Blake2sIV != want {
		t.Fatalf("Blake2sIV deviates from RFC 7693 §3.2:\n  got  = %x\n  want = %x", Blake2sIV, want)
	}
}

// TestBlake2sIVParam_DerivedFromIV verifies the precomputed IV-with-
// paramBlock-XOR'd-into-h0 constant for -256 matches the RFC 7693
// §3.3 parameter-block derivation. Catches regressions in the encoded
// h0[0] value without forcing the rest of the tests to re-derive it
// at runtime.
func TestBlake2sIVParam_DerivedFromIV(t *testing.T) {
	const paramBlock256 = uint32(0x01010020) // digestLength=32, fanout=1, depth=1

	want256 := Blake2sIV
	want256[0] ^= paramBlock256
	if Blake2sIV256Param != want256 {
		t.Fatalf("Blake2sIV256Param mismatch:\n  got  = %x\n  want = %x", Blake2sIV256Param, want256)
	}
}
