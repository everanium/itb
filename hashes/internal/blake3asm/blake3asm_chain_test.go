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
