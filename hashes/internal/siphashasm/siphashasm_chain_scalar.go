package siphashasm

import (
	"unsafe"

	"github.com/dchest/siphash"
)

// scalar128ChainAbsorb is the pure-Go reference implementation of
// the SipHash-2-4-128 chain-absorb closure for a single pixel. The
// construction is a thin wrapper over github.com/dchest/siphash —
// the same package the public hashes.SipHash24 closure delegates
// to, so any divergence here would observably change the digest
// emitted by hashes.SipHash24.
//
// SipHash-2-4 is keyed by the per-call (seed0, seed1) pair — there
// is no fixed key, no internal hasher object, no scratch buffer.
// The closure is a direct call into siphash.Hash128.
//
// Used as the production fallback on hosts without AVX-512+VL and
// as the parity baseline for the ZMM-batched ASM kernels.
func scalar128ChainAbsorb(data []byte, seed0, seed1 uint64) (uint64, uint64) {
	return siphash.Hash128(seed0, seed1, data)
}

// scalarBatch128ChainAbsorb20 is the scalar 4-lane reference for
// the SipHash-2-4-128 batched chain-absorb at the 20-byte data
// shape. Loops the per-lane scalar reference; each lane is bit-
// exact equivalent to the public hashes.SipHash24 closure on the
// same input. Used as the production fallback on hosts without
// AVX-512+VL and as the parity baseline for the ZMM-batched ASM
// kernel.
func scalarBatch128ChainAbsorb20(
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[20]byte)(unsafe.Pointer(dataPtrs[lane]))
		out[lane][0], out[lane][1] = scalar128ChainAbsorb(data[:], seeds[lane][0], seeds[lane][1])
	}
}

// scalarBatch128ChainAbsorb36 — 36-byte counterpart.
func scalarBatch128ChainAbsorb36(
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[36]byte)(unsafe.Pointer(dataPtrs[lane]))
		out[lane][0], out[lane][1] = scalar128ChainAbsorb(data[:], seeds[lane][0], seeds[lane][1])
	}
}

// scalarBatch128ChainAbsorb68 — 68-byte counterpart.
func scalarBatch128ChainAbsorb68(
	seeds *[4][2]uint64,
	dataPtrs *[4]*byte,
	out *[4][2]uint64,
) {
	for lane := 0; lane < 4; lane++ {
		data := (*[68]byte)(unsafe.Pointer(dataPtrs[lane]))
		out[lane][0], out[lane][1] = scalar128ChainAbsorb(data[:], seeds[lane][0], seeds[lane][1])
	}
}
