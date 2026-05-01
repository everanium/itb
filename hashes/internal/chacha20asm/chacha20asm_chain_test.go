package chacha20asm

import (
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/chacha20"
)

// runReferenceClosure256 replays the bit-exact closure body from
// hashes/chacha20.go on a single pixel using upstream
// golang.org/x/crypto/chacha20 as the keystream oracle. Used as the
// per-lane parity baseline for the 4-pixel-batched ASM kernels.
func runReferenceClosure256(fixedKey [32]byte, data []byte, seed [4]uint64) [4]uint64 {
	var key [32]byte
	copy(key[:], fixedKey[:])
	for i := 0; i < 4; i++ {
		off := i * 8
		v := binary.LittleEndian.Uint64(key[off:])
		binary.LittleEndian.PutUint64(key[off:], v^seed[i])
	}
	var nonce [12]byte
	c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		panic(err)
	}
	var state [32]byte
	binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))
	const chunkSize = 24
	if len(data) <= chunkSize {
		copy(state[8:8+len(data)], data)
		c.XORKeyStream(state[:], state[:])
	} else {
		copy(state[8:8+chunkSize], data[0:chunkSize])
		c.XORKeyStream(state[:], state[:])
		off := chunkSize
		for off < len(data) {
			end := off + chunkSize
			if end > len(data) {
				end = len(data)
			}
			for i := 0; i < end-off; i++ {
				state[8+i] ^= data[off+i]
			}
			c.XORKeyStream(state[:], state[:])
			off = end
		}
	}
	return [4]uint64{
		binary.LittleEndian.Uint64(state[0:]),
		binary.LittleEndian.Uint64(state[8:]),
		binary.LittleEndian.Uint64(state[16:]),
		binary.LittleEndian.Uint64(state[24:]),
	}
}

// chainAbsorb256Case parameterises a ChaCha20-256 4-lane parity-test
// scenario. Each scenario fixes a single shared fixed-key and four
// per-lane seeds; the test injects four distinct per-lane data
// payloads to surface any cross-lane state-leak bugs in the batched
// kernel.
type chainAbsorb256Case struct {
	name     string
	fixedKey [32]byte
	seeds    [4][4]uint64
}

var chainAbsorb256Cases = []chainAbsorb256Case{
	{
		name:     "zero key, zero seeds",
		fixedKey: [32]byte{},
		seeds:    [4][4]uint64{},
	},
	{
		name:     "ascending key, distinct lane seeds",
		fixedKey: ascendingKey256(),
		seeds: [4][4]uint64{
			{1, 2, 3, 4},
			{5, 6, 7, 8},
			{9, 10, 11, 12},
			{13, 14, 15, 16},
		},
	},
	{
		name:     "high-bit-set key, high-bit-set seeds",
		fixedKey: highBitKey256(),
		seeds: [4][4]uint64{
			{0x8000000000000001, 0x8000000000000002, 0x8000000000000003, 0x8000000000000004},
			{0x8000000000000005, 0x8000000000000006, 0x8000000000000007, 0x8000000000000008},
			{0x8000000000000009, 0x800000000000000a, 0x800000000000000b, 0x800000000000000c},
			{0x800000000000000d, 0x800000000000000e, 0x800000000000000f, 0x8000000000000010},
		},
	},
	{
		name:     "zero key, all-ones seeds",
		fixedKey: [32]byte{},
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
	kernel func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64),
) {
	t.Helper()
	for _, tc := range chainAbsorb256Cases {
		t.Run(tc.name, func(t *testing.T) {
			bufs, ptrs := makeLaneData256(dataLen)
			var laneWant [4][4]uint64
			for lane := 0; lane < 4; lane++ {
				laneWant[lane] = runReferenceClosure256(tc.fixedKey, bufs[lane], tc.seeds[lane])
			}
			var got [4][4]uint64
			kernel(&tc.fixedKey, &tc.seeds, &ptrs, &got)
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

func TestChaCha20256ChainAbsorb20x4(t *testing.T) {
	runChainAbsorb256Test(t, "ChaCha20256ChainAbsorb20x4", 20, ChaCha20256ChainAbsorb20x4)
}

func TestChaCha20256ChainAbsorb36x4(t *testing.T) {
	runChainAbsorb256Test(t, "ChaCha20256ChainAbsorb36x4", 36, ChaCha20256ChainAbsorb36x4)
}

func TestChaCha20256ChainAbsorb68x4(t *testing.T) {
	runChainAbsorb256Test(t, "ChaCha20256ChainAbsorb68x4", 68, ChaCha20256ChainAbsorb68x4)
}
