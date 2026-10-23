package aesitbasm

import (
	"encoding/binary"
	"runtime"

	"github.com/everanium/areion"
)

// AES-ITB noise filler.
//
// The filler is the counter-driven standalone use of the AES-ITB-128
// primitive that produces carrier noise and residue for the DRBG arm
// the "aesitb128" token selects. Block i of a filler keyed by K (16
// bytes) and N (32 bytes) is the primitive's generic hash with the
// 128-bit block index in the seed slot and the nonce in the data slot:
//
//	block(i) = HashGeneric(K, N, lo(i), hi(i))
//
// i.e. [ChainAbsorb] over the 32-byte nonce — three padded
// 16-byte blocks (two nonce blocks and one full PKCS#7 pad block)
// absorbed under RC[0], RC[1], RC[2] and finalised under RC[3], RC[4],
// five AES rounds in all. Every input except the counter is a per-call
// constant, so the whole call folds into one pre-whitening block and a
// five-entry round-key table ([NoiseSchedule]); per block the kernels
// run one XOR, five AESENC and one 16-byte store. The fold is exact
// because AESENC(x, k) XOR m == AESENC(x, k XOR m).
//
// Output is the full 16-byte state in state byte order (the (lo, hi)
// pair of [ChainAbsorb] read as two little-endian words), block after
// block, the last block truncated to the requested length. The counter
// is a 128-bit little-endian pair; the kernels receive runs that never
// cross a 64-bit carry (the driver splits at a lo wrap), and nothing is
// detected past 2^128 blocks, which no process can reach.
//
// Every tier is constant-time: the loop trip counts depend only on the
// public block count, no memory access is indexed by the key or the
// nonce, and no branch depends on either.

// NoiseSchedule is the folded per-call constant set of the AES-ITB noise
// filler: C is the pre-whitening block the counter is XORed into, RK the
// round keys of the five public rounds that follow. The layout is the
// one the kernels read (C at offset 0, RK[r] at 16 + 16·r).
type NoiseSchedule struct {
	C  [16]byte
	RK [5][16]byte
}

// noisePad16 is the full PKCS#7 pad block that follows a block-aligned
// 32-byte input.
var noisePad16 = [16]byte{
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
	0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
}

// noiseIncTab holds the 128-bit counter increments [j, 0] for
// j = 0 .. 32 at offset 16·j; the kernels add entries to the counter
// base to synthesise the blocks of one iteration and to advance the
// base by the group width.
var noiseIncTab = [33][2]uint64{
	{0, 0}, {1, 0}, {2, 0}, {3, 0}, {4, 0}, {5, 0}, {6, 0}, {7, 0},
	{8, 0}, {9, 0}, {10, 0}, {11, 0}, {12, 0}, {13, 0}, {14, 0}, {15, 0},
	{16, 0}, {17, 0}, {18, 0}, {19, 0}, {20, 0}, {21, 0}, {22, 0}, {23, 0},
	{24, 0}, {25, 0}, {26, 0}, {27, 0}, {28, 0}, {29, 0}, {30, 0}, {31, 0},
	{32, 0},
}

// NewNoiseSchedule folds key and nonce into the kernel-side constant
// set:
//
//	C     = key XOR nonce[0:16]
//	RK[0] = RC[0] XOR nonce[16:32]
//	RK[1] = RC[1] XOR PAD16
//	RK[2] = RC[2];  RK[3] = RC[3];  RK[4] = RC[4]
func NewNoiseSchedule(key *[16]byte, nonce *[32]byte) NoiseSchedule {
	var s NoiseSchedule
	for i := 0; i < 16; i++ {
		s.C[i] = key[i] ^ nonce[i]
		s.RK[0][i] = RC[0][i] ^ nonce[16+i]
		s.RK[1][i] = RC[1][i] ^ noisePad16[i]
	}
	s.RK[2] = RC[2]
	s.RK[3] = RC[3]
	s.RK[4] = RC[4]
	return s
}

// NoiseFill writes len(dst) filler bytes starting at block index
// (lo, hi) into dst. The selected assembly tier runs on the longest
// prefix that is a whole number of its block group and that does not
// cross a 64-bit carry of lo; the remaining whole blocks and the
// trailing partial block run through the single-block Go path. dst is
// never read.
func NoiseFill(s *NoiseSchedule, dst []byte, lo, hi uint64) {
	gran := noiseFillGran()
	for gran > 0 && len(dst) >= 16*gran {
		n := len(dst) / 16
		n -= n % gran
		// The kernel derives block j of the run as (lo + j, hi); a run
		// that reached lo == 2^64 would need the carry it does not
		// implement, so the run is capped at the blocks left before the
		// wrap (room + 1 of them, room being the increments available).
		if room := ^lo; uint64(n-1) > room {
			n = int(room) + 1
			n -= n % gran
			if n == 0 {
				break
			}
		}
		noiseFillKernel(s, &dst[0], n, lo, hi)
		dst = dst[16*n:]
		lo += uint64(n)
		if lo < uint64(n) {
			hi++
		}
	}
	noiseFillGeneric(s, dst, lo, hi)
}

// noiseFillGeneric is the Go fallback path. Bulk 4-block groups run
// through the 4-lane bitsliced AES round with the round keys pre-packed
// once; the trailing < 64-byte tail runs through noiseBlockHW.
func noiseFillGeneric(s *NoiseSchedule, dst []byte, lo, hi uint64) {
	if len(dst) >= 64 && ^lo >= 3 {
		var bsRK [5]bsState
		for r := range s.RK {
			bsPackBroadcast(&bsRK[r], &s.RK[r])
		}
		var blk4 [4][16]byte
		var out4 [4][2]uint64
		var q bsState
		c0 := binary.LittleEndian.Uint64(s.C[:8])
		c1 := binary.LittleEndian.Uint64(s.C[8:])
		for len(dst) >= 64 && ^lo >= 3 {
			for lane := 0; lane < 4; lane++ {
				binary.LittleEndian.PutUint64(blk4[lane][:8], c0^(lo+uint64(lane)))
				binary.LittleEndian.PutUint64(blk4[lane][8:], c1^hi)
			}
			bsPack4(&q, &blk4[0], &blk4[1], &blk4[2], &blk4[3])
			for r := range bsRK {
				bsRound(&q, &bsRK[r])
			}
			bsUnpackWords4(&q, &out4)
			for lane := 0; lane < 4; lane++ {
				binary.LittleEndian.PutUint64(dst[16*lane:16*lane+8], out4[lane][0])
				binary.LittleEndian.PutUint64(dst[16*lane+8:16*lane+16], out4[lane][1])
			}
			dst = dst[64:]
			lo += 4
			if lo < 4 {
				hi++
			}
		}
		clear(bsRK[:])
		clear(blk4[:])
		clear(out4[:])
		clear(q[:])
		runtime.KeepAlive(&bsRK)
		runtime.KeepAlive(&blk4)
		runtime.KeepAlive(&out4)
		runtime.KeepAlive(&q)
	}

	var blk [16]byte
	for len(dst) > 0 {
		noiseBlockHW(s, &blk, lo, hi)
		n := copy(dst, blk[:])
		dst = dst[n:]
		lo++
		if lo == 0 {
			hi++
		}
	}
	clear(blk[:])
	runtime.KeepAlive(&blk)
}

// noiseBlockHW evaluates one filler block through the folded schedule.
func noiseBlockHW(s *NoiseSchedule, out *[16]byte, lo, hi uint64) {
	*out = s.C
	binary.LittleEndian.PutUint64(out[:8], binary.LittleEndian.Uint64(out[:8])^lo)
	binary.LittleEndian.PutUint64(out[8:], binary.LittleEndian.Uint64(out[8:])^hi)
	for r := range s.RK {
		areion.AES128Round((*areion.Block)(out), (*areion.Block)(&s.RK[r]))
	}
}
