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

// runScalarBatch256Test exercises a single (scalarBatchKernel, length)
// pair across the standard edge-case matrix. Each lane's output must
// match the per-lane scalar reference bit-exactly. This drives the
// 4-lane scalar batched chain-absorb path that serves as the fallback
// on hosts without AVX-512+VL and as the parity baseline for the
// ZMM-batched ASM kernels.
func runScalarBatch256Test(
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

// TestScalarBatch256ChainAbsorb20_Parity verifies the scalar 4-lane
// 20-byte BLAKE2s-256 batched chain-absorb matches the per-lane
// reference closure.
func TestScalarBatch256ChainAbsorb20_Parity(t *testing.T) {
	runScalarBatch256Test(t, "scalarBatch256ChainAbsorb20", 20, scalarBatch256ChainAbsorb20)
}

// TestScalarBatch256ChainAbsorb36_Parity — 36-byte counterpart. Two-
// compression-block path through the upstream blake2s.Sum256.
func TestScalarBatch256ChainAbsorb36_Parity(t *testing.T) {
	runScalarBatch256Test(t, "scalarBatch256ChainAbsorb36", 36, scalarBatch256ChainAbsorb36)
}

// TestScalarBatch256ChainAbsorb68_Parity — 68-byte counterpart. Two-
// compression-block path through the upstream blake2s.Sum256.
func TestScalarBatch256ChainAbsorb68_Parity(t *testing.T) {
	runScalarBatch256Test(t, "scalarBatch256ChainAbsorb68", 68, scalarBatch256ChainAbsorb68)
}

// TestPack256Buf_Layout drives the 256-bit BLAKE2s buffer packer with
// known inputs. data region starts at offset 32; the seed XOR covers
// buf[32:64] with 4 uint64 seed components LE (each straddling two
// BLAKE2s 32-bit message words).
func TestPack256Buf_Layout(t *testing.T) {
	var b2key [32]byte
	for i := range b2key {
		b2key[i] = byte(0x20 + i)
	}
	data := make([]byte, 20)
	for i := range data {
		data[i] = byte(0x80 + i)
	}
	seed := [4]uint64{
		0x1111111111111111, 0x2222222222222222,
		0x3333333333333333, 0x4444444444444444,
	}
	buf := make([]byte, 64)
	pack256Buf(buf, &b2key, data, &seed)
	for i := 0; i < 32; i++ {
		if buf[i] != b2key[i] {
			t.Fatalf("buf[%d]=%#x, want b2key[%d]=%#x", i, buf[i], i, b2key[i])
		}
	}
	for i := 0; i < 4; i++ {
		off := 32 + i*8
		var dataChunk [8]byte
		for j := 0; j < 8; j++ {
			if off+j-32 < len(data) {
				dataChunk[j] = data[off+j-32]
			}
		}
		wantWord := binary.LittleEndian.Uint64(dataChunk[:]) ^ seed[i]
		gotWord := binary.LittleEndian.Uint64(buf[off:])
		if gotWord != wantWord {
			t.Fatalf("buf[%d:%d] word: got=%#x want=%#x", off, off+8, gotWord, wantWord)
		}
	}
}

// TestDispatcher_ScalarFallback drives the three public dispatchers
// through their scalar fallback path by temporarily clearing the
// HasAVX512Fused capability flag. Verifies that the scalar branch of
// each dispatcher produces output bit-identical to the per-lane
// reference closure.
func TestDispatcher_ScalarFallback(t *testing.T) {
	saved := HasAVX512Fused
	HasAVX512Fused = false
	t.Cleanup(func() { HasAVX512Fused = saved })

	cases := []struct {
		name    string
		dataLen int
		kernel  func(*[8]uint32, *[32]byte, *[4][4]uint64, *[4]*byte, *[4][8]uint32)
	}{
		{"Blake2s256ChainAbsorb20x4 fallback", 20, Blake2s256ChainAbsorb20x4},
		{"Blake2s256ChainAbsorb36x4 fallback", 36, Blake2s256ChainAbsorb36x4},
		{"Blake2s256ChainAbsorb68x4 fallback", 68, Blake2s256ChainAbsorb68x4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, tc := range chainAbsorb256Cases {
				t.Run(tc.name, func(t *testing.T) {
					bufs, ptrs := makeLaneData256(c.dataLen)
					var laneWant [4][8]uint32
					for lane := 0; lane < 4; lane++ {
						laneWant[lane] = runReferenceClosure256(tc.b2key, bufs[lane], tc.seeds[lane])
					}
					var got [4][8]uint32
					c.kernel(&Blake2sIV256Param, &tc.b2key, &tc.seeds, &ptrs, &got)
					for lane := 0; lane < 4; lane++ {
						for i := 0; i < 8; i++ {
							if got[lane][i] != laneWant[lane][i] {
								t.Fatalf("%s lane %d out[%d]: got=%#x want=%#x",
									c.name, lane, i, got[lane][i], laneWant[lane][i])
							}
						}
					}
				})
			}
		})
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
