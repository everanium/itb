package blake3asm

import (
	"encoding/binary"
	"testing"

	"github.com/zeebo/blake3"
)

// runReferenceClosure256 replays the bit-exact buffer-packing and
// digest-extraction logic of the hashes.BLAKE3 closure on a single
// pixel, using upstream github.com/zeebo/blake3 keyed-hash mode as
// the digest oracle. Used as the per-lane parity baseline for the
// 4-pixel-batched ASM kernels.
func runReferenceClosure256(key [32]byte, data []byte, seed [4]uint64) [8]uint32 {
	const seedInjectBytes = 32
	payloadLen := len(data)
	if payloadLen < seedInjectBytes {
		payloadLen = seedInjectBytes
	}
	mixed := make([]byte, payloadLen)
	copy(mixed[:len(data)], data)
	for i := 0; i < 4; i++ {
		off := i * 8
		binary.LittleEndian.PutUint64(mixed[off:], binary.LittleEndian.Uint64(mixed[off:])^seed[i])
	}
	h, err := blake3.NewKeyed(key[:])
	if err != nil {
		panic(err)
	}
	if _, err := h.Write(mixed); err != nil {
		panic(err)
	}
	var digest [32]byte
	h.Sum(digest[:0])
	var out [8]uint32
	for i := 0; i < 8; i++ {
		out[i] = binary.LittleEndian.Uint32(digest[i*4:])
	}
	return out
}

// chainAbsorb256Case parameterises a BLAKE3-256 4-lane parity-test
// scenario. Each scenario fixes a single shared key and four
// per-lane seeds; the test injects four distinct per-lane data
// payloads to surface any cross-lane state-leak bugs in the batched
// kernel.
type chainAbsorb256Case struct {
	name  string
	key   [32]byte
	seeds [4][4]uint64
}

var chainAbsorb256Cases = []chainAbsorb256Case{
	{
		name:  "zero key, zero seeds",
		key:   [32]byte{},
		seeds: [4][4]uint64{},
	},
	{
		name: "ascending key, distinct lane seeds",
		key:  ascendingKey256(),
		seeds: [4][4]uint64{
			{1, 2, 3, 4},
			{5, 6, 7, 8},
			{9, 10, 11, 12},
			{13, 14, 15, 16},
		},
	},
	{
		name: "high-bit-set key, high-bit-set seeds",
		key:  highBitKey256(),
		seeds: [4][4]uint64{
			{0x8000000000000001, 0x8000000000000002, 0x8000000000000003, 0x8000000000000004},
			{0x8000000000000005, 0x8000000000000006, 0x8000000000000007, 0x8000000000000008},
			{0x8000000000000009, 0x800000000000000a, 0x800000000000000b, 0x800000000000000c},
			{0x800000000000000d, 0x800000000000000e, 0x800000000000000f, 0x8000000000000010},
		},
	},
	{
		name: "zero key, all-ones seeds",
		key:  [32]byte{},
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

// makeLaneData256 builds four lane-distinct fixed-length data
// buffers. The byte fill at position p in lane l is byte(p + 0xc0
// + l*0x40) so every lane carries a distinguishable per-byte
// signature, surfacing cross-lane state-leak bugs in the ASM
// kernel as a visible mismatch.
func makeLaneData256(n int) ([4][]byte, [4]*byte) {
	var bufs [4][]byte
	var ptrs [4]*byte
	for lane := 0; lane < 4; lane++ {
		bufs[lane] = make([]byte, n)
		for i := range bufs[lane] {
			bufs[lane][i] = byte(i + 0xc0 + lane*0x40)
		}
		ptrs[lane] = &bufs[lane][0]
	}
	return bufs, ptrs
}

// runChainAbsorb256Test exercises a single (kernel, length) pair
// across the standard edge-case matrix. Each lane's output must
// match the per-lane scalar reference bit-exactly.
func runChainAbsorb256Test(
	t *testing.T,
	name string,
	dataLen int,
	kernel func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][8]uint32),
) {
	t.Helper()
	for _, tc := range chainAbsorb256Cases {
		t.Run(tc.name, func(t *testing.T) {
			bufs, ptrs := makeLaneData256(dataLen)
			var laneWant [4][8]uint32
			for lane := 0; lane < 4; lane++ {
				laneWant[lane] = runReferenceClosure256(tc.key, bufs[lane], tc.seeds[lane])
			}
			var got [4][8]uint32
			kernel(&tc.key, &tc.seeds, &ptrs, &got)
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

func TestBlake3256ChainAbsorb20x4(t *testing.T) {
	runChainAbsorb256Test(t, "Blake3256ChainAbsorb20x4", 20, Blake3256ChainAbsorb20x4)
}

func TestBlake3256ChainAbsorb36x4(t *testing.T) {
	runChainAbsorb256Test(t, "Blake3256ChainAbsorb36x4", 36, Blake3256ChainAbsorb36x4)
}

func TestBlake3256ChainAbsorb68x4(t *testing.T) {
	runChainAbsorb256Test(t, "Blake3256ChainAbsorb68x4", 68, Blake3256ChainAbsorb68x4)
}

// TestBlake3IV_RFC verifies the IV table matches the BLAKE3 RFC
// — bit-identical to BLAKE2s IV / SHA-256 IV. A regression-fast
// smoke test that catches accidental edits to Blake3IV's individual
// entries before any chain-absorb call reaches a broken initial
// state.
func TestBlake3IV_RFC(t *testing.T) {
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
	if Blake3IV != want {
		t.Fatalf("Blake3IV deviates from RFC:\n  got  = %x\n  want = %x", Blake3IV, want)
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
	kernel func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][8]uint32),
) {
	t.Helper()
	for _, tc := range chainAbsorb256Cases {
		t.Run(tc.name, func(t *testing.T) {
			bufs, ptrs := makeLaneData256(dataLen)
			var laneWant [4][8]uint32
			for lane := 0; lane < 4; lane++ {
				laneWant[lane] = runReferenceClosure256(tc.key, bufs[lane], tc.seeds[lane])
			}
			var got [4][8]uint32
			kernel(&tc.key, &tc.seeds, &ptrs, &got)
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
// 20-byte BLAKE3-256 batched chain-absorb matches the per-lane
// reference closure.
func TestScalarBatch256ChainAbsorb20_Parity(t *testing.T) {
	runScalarBatch256Test(t, "scalarBatch256ChainAbsorb20", 20, scalarBatch256ChainAbsorb20)
}

// TestScalarBatch256ChainAbsorb36_Parity — 36-byte counterpart.
func TestScalarBatch256ChainAbsorb36_Parity(t *testing.T) {
	runScalarBatch256Test(t, "scalarBatch256ChainAbsorb36", 36, scalarBatch256ChainAbsorb36)
}

// TestScalarBatch256ChainAbsorb68_Parity — 68-byte counterpart. Runs
// two BLAKE3 blocks per lane (block 1: data[0:64], block 2: data[64:68]).
func TestScalarBatch256ChainAbsorb68_Parity(t *testing.T) {
	runScalarBatch256Test(t, "scalarBatch256ChainAbsorb68", 68, scalarBatch256ChainAbsorb68)
}

// TestPack256Buf_Layout verifies pack256Buf lays out the BLAKE3 mixed
// buffer correctly: data first, with seed[0..3] XOR'd into the first
// 32 bytes (LE uint64 over 4 × 8-byte chunks). Unlike BLAKE2{b,s}, no
// key prefix exists in the buffer — the key lives in keyed-hash state.
func TestPack256Buf_Layout(t *testing.T) {
	data := make([]byte, 36)
	for i := range data {
		data[i] = byte(0x80 + i)
	}
	seed := [4]uint64{
		0x1111111111111111, 0x2222222222222222,
		0x3333333333333333, 0x4444444444444444,
	}
	mixed := make([]byte, 36)
	pack256Buf(mixed, data, &seed)
	for i := 0; i < 4; i++ {
		off := i * 8
		wantWord := binary.LittleEndian.Uint64(data[off:]) ^ seed[i]
		gotWord := binary.LittleEndian.Uint64(mixed[off:])
		if gotWord != wantWord {
			t.Fatalf("mixed[%d:%d] word: got=%#x want=%#x",
				off, off+8, gotWord, wantWord)
		}
	}
	// Bytes past offset 32 are copied verbatim, no seed XOR.
	for i := 32; i < 36; i++ {
		if mixed[i] != data[i] {
			t.Fatalf("mixed[%d]=%#x, want data[%d]=%#x", i, mixed[i], i, data[i])
		}
	}
}

// TestPack256Buf_ShortMixed exercises pack256Buf's early-break
// branch when len(mixed) is below the 32-byte seed-injection region.
// The branch `if off+8 > len(mixed) { break }` triggers when mixed is
// short enough that the next 8-byte word would overflow.
func TestPack256Buf_ShortMixed(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}
	seed := [4]uint64{0xaaaaaaaaaaaaaaaa, 0xbbbbbbbbbbbbbbbb, 0xcccccccccccccccc, 0xdddddddddddddddd}
	// 4-byte mixed cannot hold any full 8-byte seed word; the loop
	// must break at i=0 without applying any seed XOR.
	mixed := make([]byte, 4)
	pack256Buf(mixed, data, &seed)
	for i := 0; i < 4; i++ {
		if mixed[i] != data[i] {
			t.Fatalf("mixed[%d]=%#x, want data[%d]=%#x", i, mixed[i], i, data[i])
		}
	}
}

// TestBlake3KeyedSum_Roundtrip verifies blake3KeyedSum produces output
// identical to the upstream zeebo/blake3 keyed-hash mode for the same
// key and input.
func TestBlake3KeyedSum_Roundtrip(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(0x20 + i)
	}
	mixed := []byte("blake3 keyed sum reference")
	var got [32]byte
	blake3KeyedSum(&key, mixed, got[:])

	h, err := blake3.NewKeyed(key[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Write(mixed); err != nil {
		t.Fatal(err)
	}
	var want [32]byte
	h.Sum(want[:0])

	if got != want {
		t.Fatalf("blake3KeyedSum mismatch\n  got:  %x\n  want: %x", got, want)
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
		kernel  func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][8]uint32)
	}{
		{"Blake3256ChainAbsorb20x4 fallback", 20, Blake3256ChainAbsorb20x4},
		{"Blake3256ChainAbsorb36x4 fallback", 36, Blake3256ChainAbsorb36x4},
		{"Blake3256ChainAbsorb68x4 fallback", 68, Blake3256ChainAbsorb68x4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, tc := range chainAbsorb256Cases {
				t.Run(tc.name, func(t *testing.T) {
					bufs, ptrs := makeLaneData256(c.dataLen)
					var laneWant [4][8]uint32
					for lane := 0; lane < 4; lane++ {
						laneWant[lane] = runReferenceClosure256(tc.key, bufs[lane], tc.seeds[lane])
					}
					var got [4][8]uint32
					c.kernel(&tc.key, &tc.seeds, &ptrs, &got)
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

// TestBlake3Flags verifies the domain-separation flag constants
// match the BLAKE3 RFC §2.1 numeric values.
func TestBlake3Flags(t *testing.T) {
	if FlagChunkStart != 0x01 {
		t.Errorf("FlagChunkStart = %#x, want 0x01", FlagChunkStart)
	}
	if FlagChunkEnd != 0x02 {
		t.Errorf("FlagChunkEnd = %#x, want 0x02", FlagChunkEnd)
	}
	if FlagRoot != 0x08 {
		t.Errorf("FlagRoot = %#x, want 0x08", FlagRoot)
	}
	if FlagKeyedHash != 0x10 {
		t.Errorf("FlagKeyedHash = %#x, want 0x10", FlagKeyedHash)
	}
	if FlagsSingleBlock != 0x1B {
		t.Errorf("FlagsSingleBlock = %#x, want 0x1B", FlagsSingleBlock)
	}
	if FlagsTwoBlockFirst != 0x11 {
		t.Errorf("FlagsTwoBlockFirst = %#x, want 0x11", FlagsTwoBlockFirst)
	}
	if FlagsTwoBlockFinal != 0x1A {
		t.Errorf("FlagsTwoBlockFinal = %#x, want 0x1A", FlagsTwoBlockFinal)
	}
}
