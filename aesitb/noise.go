package aesitb

import (
	"crypto/rand"

	"github.com/everanium/itb/internal/aesitbasm"
)

// FillNoise overwrites dst with AES-ITB noise filler bytes under a
// 16-byte key and a 32-byte nonce drawn from crypto/rand for this call
// alone. Neither is returned or retained, so the output cannot be
// reproduced by anyone, the caller included. The previous contents of
// dst are ignored.
//
// Block i of the filler, for i = 0, 1, …, is the primitive's generic
// hash with the 128-bit block index in the seed slot and the nonce in
// the data slot — [HashGeneric](key, nonce, lo(i), hi(i)), the full
// 16-byte state in state byte order — and the last block is truncated
// to len(dst). Every block is a function of the key, the nonce and its
// index alone, so the per-architecture kernels of internal/aesitbasm
// evaluate the blocks in parallel; a build or host without a kernel
// runs the same construction one block at a time. The key and the first
// half of the nonce meet the block index in the same XOR ahead of the
// first round, so a call is fixed by 256 fresh bits rather than 384.
//
// FillNoise is the carrier-noise and residue filler of the "aesitb128"
// DRBG arm. It is not a PRF, not a cipher and not a general-purpose
// random source: see the package Warning. The output is uniform
// marginally and blocks within one call are pairwise distinct; nothing
// stronger is claimed.
//
// FillNoise returns the crypto/rand error when the key draw fails; dst
// is then unchanged.
func FillNoise(dst []byte) error {
	var seed [16 + 32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return err
	}
	fillNoiseKeyed((*[16]byte)(seed[:16]), (*[32]byte)(seed[16:]), dst)
	clear(seed[:])
	return nil
}

// fillNoiseKeyed is the deterministic form behind [FillNoise]: the
// filler under a caller-supplied key and nonce from block 0. It exists
// for the known-answer and parity tests; the folded schedule is wiped
// before return.
func fillNoiseKeyed(key *[16]byte, nonce *[32]byte, dst []byte) {
	sched := aesitbasm.NewNoiseSchedule(key, nonce)
	aesitbasm.NoiseFill(&sched, dst, 0, 0)
	clear(sched.C[:])
	for i := range sched.RK {
		clear(sched.RK[i][:])
	}
}
