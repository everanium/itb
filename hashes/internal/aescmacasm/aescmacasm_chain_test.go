package aescmacasm

import (
	"crypto/aes"
	"encoding/binary"
	"testing"
)

// runReferenceClosure128 replays the bit-exact closure body from
// hashes/aescmac.go on a single pixel using crypto/aes.cipher.Block
// as the keyed permutation oracle. Used as the per-lane parity
// baseline for the 4-pixel-batched ASM kernels.
func runReferenceClosure128(key [16]byte, data []byte, seed0, seed1 uint64) (uint64, uint64) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	lenTag := uint64(len(data))
	var b1 [16]byte
	binary.LittleEndian.PutUint64(b1[0:], seed0^lenTag)
	binary.LittleEndian.PutUint64(b1[8:], seed1^lenTag)
	firstBlockLen := len(data)
	if firstBlockLen > 16 {
		firstBlockLen = 16
	}
	for i := 0; i < firstBlockLen; i++ {
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

// chainAbsorb128Case parameterises an AES-CMAC-128 4-lane parity-test
// scenario. Each scenario fixes a single shared 16-byte AES key and
// four per-lane seeds (each lane's seed is a [2]uint64 = (seed0,
// seed1)); the test injects four distinct per-lane data payloads to
// surface any cross-lane state-leak bugs in the batched kernel.
type chainAbsorb128Case struct {
	name  string
	key   [16]byte
	seeds [4][2]uint64
}

var chainAbsorb128Cases = []chainAbsorb128Case{
	{
		name:  "zero key, zero seeds",
		key:   [16]byte{},
		seeds: [4][2]uint64{},
	},
	{
		name: "ascending key, distinct lane seeds",
		key:  ascendingKey128(),
		seeds: [4][2]uint64{
			{1, 2},
			{3, 4},
			{5, 6},
			{7, 8},
		},
	},
	{
		name: "high-bit-set key, high-bit-set seeds",
		key:  highBitKey128(),
		seeds: [4][2]uint64{
			{0x8000000000000001, 0x8000000000000002},
			{0x8000000000000003, 0x8000000000000004},
			{0x8000000000000005, 0x8000000000000006},
			{0x8000000000000007, 0x8000000000000008},
		},
	},
	{
		name: "zero key, all-ones seeds",
		key:  [16]byte{},
		seeds: [4][2]uint64{
			{0xffffffffffffffff, 0xffffffffffffffff},
			{0xffffffffffffffff, 0xffffffffffffffff},
			{0xffffffffffffffff, 0xffffffffffffffff},
			{0xffffffffffffffff, 0xffffffffffffffff},
		},
	},
}

func ascendingKey128() [16]byte {
	var k [16]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

func highBitKey128() [16]byte {
	var k [16]byte
	for i := range k {
		k[i] = 0x80 | byte(i)
	}
	return k
}

// makeLaneData128 builds four lane-distinct fixed-length data
// buffers. The byte fill at position p in lane l is byte(p + 0xc0
// + l*0x40) so every lane carries a distinguishable per-byte
// signature, surfacing cross-lane state-leak bugs in the ASM kernel
// as a visible mismatch.
func makeLaneData128(n int) ([4][]byte, [4]*byte) {
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

// runChainAbsorb128Test exercises a single (kernel, length) pair
// across the standard edge-case matrix. Each lane's output must
// match the per-lane scalar reference bit-exactly.
func runChainAbsorb128Test(
	t *testing.T,
	name string,
	dataLen int,
	kernel func(*[176]byte, *[16]byte, *[4][2]uint64, *[4]*byte, *[4][2]uint64),
) {
	t.Helper()
	for _, tc := range chainAbsorb128Cases {
		t.Run(tc.name, func(t *testing.T) {
			roundKeys := ExpandKeyAES128(tc.key)
			bufs, ptrs := makeLaneData128(dataLen)
			var laneWant [4][2]uint64
			for lane := 0; lane < 4; lane++ {
				lo, hi := runReferenceClosure128(tc.key, bufs[lane], tc.seeds[lane][0], tc.seeds[lane][1])
				laneWant[lane][0] = lo
				laneWant[lane][1] = hi
			}
			var got [4][2]uint64
			kernel(&roundKeys, &tc.key, &tc.seeds, &ptrs, &got)
			for lane := 0; lane < 4; lane++ {
				if got[lane] != laneWant[lane] {
					t.Fatalf("%s lane %d: got=%x want=%x",
						name, lane, got[lane], laneWant[lane])
				}
			}
		})
	}
}

func TestAESCMAC128ChainAbsorb20x4(t *testing.T) {
	runChainAbsorb128Test(t, "AESCMAC128ChainAbsorb20x4", 20, AESCMAC128ChainAbsorb20x4)
}

func TestAESCMAC128ChainAbsorb36x4(t *testing.T) {
	runChainAbsorb128Test(t, "AESCMAC128ChainAbsorb36x4", 36, AESCMAC128ChainAbsorb36x4)
}

func TestAESCMAC128ChainAbsorb68x4(t *testing.T) {
	runChainAbsorb128Test(t, "AESCMAC128ChainAbsorb68x4", 68, AESCMAC128ChainAbsorb68x4)
}
