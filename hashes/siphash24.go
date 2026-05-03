package hashes

import (
	"github.com/dchest/siphash"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes/internal/siphashasm"
)

// SipHash24 returns a SipHash-2-4 itb.HashFunc128 closure.
//
// SipHash-2-4 is a designed PRF whose 128-bit key is supplied per call
// as the (seed0, seed1) pair — exactly the shape ITB's Seed128
// ChainHash128 produces from the seed components. There is no
// pre-keyed state to cache (no fixed key, no internal hasher object,
// no scratch buffer) so the closure is a direct call into siphash.
//
// Returns: (low64, high64) of SipHash128(key=(seed0, seed1), data).
//
// No WithKey variant — the seed components are the entire SipHash key.
// Long-lived seed serialization is a matter of saving Components only.
func SipHash24() itb.HashFunc128 {
	return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
		return siphash.Hash128(seed0, seed1, data)
	}
}

// SipHash24Pair returns a (single, batched) SipHash-2-4-128 hash
// pair for itb.Seed128 integration. SipHash has no fixed key — the
// per-call (seed0, seed1) pair is the entire SipHash key — so the
// factory takes no arguments and returns no key, distinguishing it
// from the AESCMACPair / AESCMACPairWithKey shape used by the other
// W128 primitive in the registry.
//
// On amd64 with AVX-512+VL the batched arm dispatches to a fused
// ZMM-batched chain-absorb kernel for ITB's three SetNonceBits buf
// shapes (20 / 36 / 68 byte inputs) — the 4 SipHash state words
// (v0..v3) are held in qwords 0..3 of four ZMM registers (Z0..Z3),
// and the SipRound body (VPADDQ / VPXORQ / VPROLQ on u64) advances
// four independent SipHash chains concurrently per instruction. On
// hosts without AVX-512+VL, and for non-{20,36,68} input lengths,
// the batched arm falls back to four single-call invocations of
// dchest/siphash and remains bit-exact.
//
// Realistic uplift target: modest on Rocket Lake (the dchest/siphash
// scalar path is already very fast, leaving little headroom);
// larger on AMD Zen 5 / Sapphire Rapids+ where the 4-lane parallel
// SipRound retires through a full-width 512-bit ALU without the
// AVX-512 frequency throttle.
func SipHash24Pair() (itb.HashFunc128, itb.BatchHashFunc128) {
	single := SipHash24()
	// On hosts without the AVX-512 fused chain-absorb path the batched
	// closure falls into the scalar Go reference; under that path
	// process_cgo.go's nil-fallback (driving 4 single calls through
	// dchest/siphash's already-fast scalar implementation) outperforms
	// the 4-lane wrapper. Return nil to opt into that fallback.
	if !siphashasm.HasAVX512Fused {
		return single, nil
	}
	batched := func(data *[4][]byte, seeds [4][2]uint64) [4][2]uint64 {
		commonLen := len(data[0])
		if (commonLen == 20 || commonLen == 36 || commonLen == 68) &&
			len(data[1]) == commonLen &&
			len(data[2]) == commonLen &&
			len(data[3]) == commonLen {
			var dataPtrs [4]*byte
			dataPtrs[0] = &data[0][0]
			dataPtrs[1] = &data[1][0]
			dataPtrs[2] = &data[2][0]
			dataPtrs[3] = &data[3][0]
			var out [4][2]uint64
			seedsCopy := seeds
			switch commonLen {
			case 20:
				siphashasm.SipHash24Chain128Absorb20x4(
					&seedsCopy,
					&dataPtrs,
					&out,
				)
			case 36:
				siphashasm.SipHash24Chain128Absorb36x4(
					&seedsCopy,
					&dataPtrs,
					&out,
				)
			case 68:
				siphashasm.SipHash24Chain128Absorb68x4(
					&seedsCopy,
					&dataPtrs,
					&out,
				)
			}
			return out
		}
		var out [4][2]uint64
		for lane := 0; lane < 4; lane++ {
			lo, hi := single(data[lane], seeds[lane][0], seeds[lane][1])
			out[lane][0] = lo
			out[lane][1] = hi
		}
		return out
	}
	return single, batched
}
