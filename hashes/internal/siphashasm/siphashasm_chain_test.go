package siphashasm

import (
	"testing"

	"github.com/dchest/siphash"
)

// runReferenceClosure128 calls the upstream dchest/siphash
// Hash128 directly — same as the public hashes.SipHash24
// closure. Used as the per-lane parity baseline for the
// 4-pixel-batched ASM kernels.
func runReferenceClosure128(data []byte, seed0, seed1 uint64) (uint64, uint64) {
	return siphash.Hash128(seed0, seed1, data)
}

// chainAbsorb128Case parameterises a SipHash-2-4-128 4-lane parity-
// test scenario. SipHash has no fixed key — the per-lane (seed0,
// seed1) pair is the entire SipHash key — so each scenario just
// fixes the four per-lane seeds. The test injects four distinct
// per-lane data payloads to surface any cross-lane state-leak bugs
// in the batched kernel.
type chainAbsorb128Case struct {
	name  string
	seeds [4][2]uint64
}

var chainAbsorb128Cases = []chainAbsorb128Case{
	{
		name:  "zero seeds",
		seeds: [4][2]uint64{},
	},
	{
		name: "ascending distinct lane seeds",
		seeds: [4][2]uint64{
			{1, 2},
			{3, 4},
			{5, 6},
			{7, 8},
		},
	},
	{
		name: "high-bit-set seeds",
		seeds: [4][2]uint64{
			{0x8000000000000001, 0x8000000000000002},
			{0x8000000000000003, 0x8000000000000004},
			{0x8000000000000005, 0x8000000000000006},
			{0x8000000000000007, 0x8000000000000008},
		},
	},
	{
		name: "all-ones seeds",
		seeds: [4][2]uint64{
			{0xffffffffffffffff, 0xffffffffffffffff},
			{0xffffffffffffffff, 0xffffffffffffffff},
			{0xffffffffffffffff, 0xffffffffffffffff},
			{0xffffffffffffffff, 0xffffffffffffffff},
		},
	},
}

// makeLaneData128 builds four lane-distinct fixed-length data
// buffers. The byte fill at position p in lane l is byte(p + 0xc0
// + l*0x40) so every lane carries a distinguishable per-byte
// signature, surfacing cross-lane state-leak bugs in the ASM
// kernel as a visible mismatch.
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
	kernel func(*[4][2]uint64, *[4]*byte, *[4][2]uint64),
) {
	t.Helper()
	for _, tc := range chainAbsorb128Cases {
		t.Run(tc.name, func(t *testing.T) {
			bufs, ptrs := makeLaneData128(dataLen)
			var laneWant [4][2]uint64
			for lane := 0; lane < 4; lane++ {
				lo, hi := runReferenceClosure128(bufs[lane], tc.seeds[lane][0], tc.seeds[lane][1])
				laneWant[lane][0] = lo
				laneWant[lane][1] = hi
			}
			var got [4][2]uint64
			kernel(&tc.seeds, &ptrs, &got)
			for lane := 0; lane < 4; lane++ {
				if got[lane] != laneWant[lane] {
					t.Fatalf("%s lane %d: got=%x want=%x",
						name, lane, got[lane], laneWant[lane])
				}
			}
		})
	}
}

func TestSipHash24Chain128Absorb20x4(t *testing.T) {
	runChainAbsorb128Test(t, "SipHash24Chain128Absorb20x4", 20, SipHash24Chain128Absorb20x4)
}

func TestSipHash24Chain128Absorb36x4(t *testing.T) {
	runChainAbsorb128Test(t, "SipHash24Chain128Absorb36x4", 36, SipHash24Chain128Absorb36x4)
}

func TestSipHash24Chain128Absorb68x4(t *testing.T) {
	runChainAbsorb128Test(t, "SipHash24Chain128Absorb68x4", 68, SipHash24Chain128Absorb68x4)
}
