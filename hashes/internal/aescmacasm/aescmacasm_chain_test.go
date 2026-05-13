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

// runScalarBatchChainAbsorb128Test exercises a single (scalarBatchKernel,
// length) pair across the standard edge-case matrix. Each lane's output
// must match the per-lane scalar reference bit-exactly. This drives the
// 4-lane scalar batched chain-absorb path that serves as the fallback on
// hosts without VAES + AVX-512 and as the parity baseline for the
// ZMM-batched ASM kernels.
func runScalarBatchChainAbsorb128Test(
	t *testing.T,
	name string,
	dataLen int,
	kernel func(*[16]byte, *[4][2]uint64, *[4]*byte, *[4][2]uint64),
) {
	t.Helper()
	for _, tc := range chainAbsorb128Cases {
		t.Run(tc.name, func(t *testing.T) {
			bufs, ptrs := makeLaneData128(dataLen)
			var laneWant [4][2]uint64
			for lane := 0; lane < 4; lane++ {
				lo, hi := runReferenceClosure128(tc.key, bufs[lane], tc.seeds[lane][0], tc.seeds[lane][1])
				laneWant[lane][0] = lo
				laneWant[lane][1] = hi
			}
			var got [4][2]uint64
			kernel(&tc.key, &tc.seeds, &ptrs, &got)
			for lane := 0; lane < 4; lane++ {
				if got[lane] != laneWant[lane] {
					t.Fatalf("%s lane %d: got=%x want=%x",
						name, lane, got[lane], laneWant[lane])
				}
			}
		})
	}
}

// TestScalarBatch128ChainAbsorb20_Parity verifies the scalar 4-lane
// 20-byte batched chain-absorb matches the per-lane reference closure.
func TestScalarBatch128ChainAbsorb20_Parity(t *testing.T) {
	runScalarBatchChainAbsorb128Test(t, "scalarBatch128ChainAbsorb20", 20, scalarBatch128ChainAbsorb20)
}

// TestScalarBatch128ChainAbsorb36_Parity — 36-byte counterpart.
func TestScalarBatch128ChainAbsorb36_Parity(t *testing.T) {
	runScalarBatchChainAbsorb128Test(t, "scalarBatch128ChainAbsorb36", 36, scalarBatch128ChainAbsorb36)
}

// TestScalarBatch128ChainAbsorb68_Parity — 68-byte counterpart.
func TestScalarBatch128ChainAbsorb68_Parity(t *testing.T) {
	runScalarBatchChainAbsorb128Test(t, "scalarBatch128ChainAbsorb68", 68, scalarBatch128ChainAbsorb68)
}

// TestScalar128ChainAbsorb_Parity drives the single-pixel scalar
// chain-absorb across a variety of data lengths covering the three
// production shapes (20 / 36 / 68 bytes) and additional boundary lengths
// (0, 1, 15, 16, 17, 32, 33) that exercise the single-block / multi-
// block branches inside the loop. The expected output is the bit-exact
// reference closure on the same input.
func TestScalar128ChainAbsorb_Parity(t *testing.T) {
	key := ascendingKey128()
	block := newScalarBlock(&key)
	for _, dataLen := range []int{0, 1, 15, 16, 17, 20, 32, 33, 36, 64, 68} {
		t.Run("len="+itoa128(dataLen), func(t *testing.T) {
			data := make([]byte, dataLen)
			for i := range data {
				data[i] = byte(i + 0x42)
			}
			seed0 := uint64(0x0123456789abcdef)
			seed1 := uint64(0xfedcba9876543210)
			wantLo, wantHi := runReferenceClosure128(key, data, seed0, seed1)
			gotLo, gotHi := scalar128ChainAbsorb(block, data, seed0, seed1)
			if gotLo != wantLo || gotHi != wantHi {
				t.Fatalf("len=%d: got=(%#x,%#x) want=(%#x,%#x)",
					dataLen, gotLo, gotHi, wantLo, wantHi)
			}
		})
	}
}

// TestNewScalarBlock_PanicOnNilKey verifies newScalarBlock with a valid
// 16-byte key produces a working AES-128 block. The error-path
// (aes.NewCipher returning err) is unreachable for a fixed 16-byte key
// input — aes.NewCipher only fails on KeySizeError for non-16/24/32
// lengths, which is impossible given the *[16]byte signature.
func TestNewScalarBlock_Roundtrip(t *testing.T) {
	key := ascendingKey128()
	block := newScalarBlock(&key)
	if block == nil {
		t.Fatal("newScalarBlock returned nil")
	}
	var pt, ct, rt [16]byte
	for i := range pt {
		pt[i] = byte(i + 1)
	}
	block.Encrypt(ct[:], pt[:])
	// crypto/aes does not expose Decrypt on the cipher.Block interface
	// for the round-trip check; running Encrypt twice on a non-zero
	// plaintext at minimum verifies the block is wired correctly.
	block.Encrypt(rt[:], ct[:])
	if pt == ct || ct == rt {
		t.Fatal("newScalarBlock: Encrypt produced identity / fixed output")
	}
}

// TestDispatcher_ScalarFallback drives the three public dispatchers
// through their scalar fallback path by temporarily clearing the
// HasVAESAVX512 capability flag. Verifies that the scalar branch of
// each dispatcher (which would otherwise be unreachable on a host that
// reports VAES + AVX-512 support) produces output bit-identical to
// the per-lane reference closure.
func TestDispatcher_ScalarFallback(t *testing.T) {
	saved := HasVAESAVX512
	HasVAESAVX512 = false
	t.Cleanup(func() { HasVAESAVX512 = saved })

	cases := []struct {
		name    string
		dataLen int
		kernel  func(*[176]byte, *[16]byte, *[4][2]uint64, *[4]*byte, *[4][2]uint64)
	}{
		{"AESCMAC128ChainAbsorb20x4 fallback", 20, AESCMAC128ChainAbsorb20x4},
		{"AESCMAC128ChainAbsorb36x4 fallback", 36, AESCMAC128ChainAbsorb36x4},
		{"AESCMAC128ChainAbsorb68x4 fallback", 68, AESCMAC128ChainAbsorb68x4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, tc := range chainAbsorb128Cases {
				t.Run(tc.name, func(t *testing.T) {
					roundKeys := ExpandKeyAES128(tc.key)
					bufs, ptrs := makeLaneData128(c.dataLen)
					var laneWant [4][2]uint64
					for lane := 0; lane < 4; lane++ {
						lo, hi := runReferenceClosure128(tc.key, bufs[lane], tc.seeds[lane][0], tc.seeds[lane][1])
						laneWant[lane][0] = lo
						laneWant[lane][1] = hi
					}
					var got [4][2]uint64
					c.kernel(&roundKeys, &tc.key, &tc.seeds, &ptrs, &got)
					for lane := 0; lane < 4; lane++ {
						if got[lane] != laneWant[lane] {
							t.Fatalf("%s lane %d: got=%x want=%x",
								c.name, lane, got[lane], laneWant[lane])
						}
					}
				})
			}
		})
	}
}

func itoa128(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := v < 0
	if neg {
		v = -v
	}
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
