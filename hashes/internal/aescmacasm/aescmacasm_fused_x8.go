package aescmacasm

// Eight-lane fused cascade dispatchers ([FusedChain20x8] / [FusedChain36x8]
// / [FusedChain68x8]) run the ChainHash128 cascade of aescmacasm_fused.go on
// eight lanes with distinct data over one shared component slice — the
// shape the itb pixel pipeline drives through its eight-lane batched hook
// at the 128 / 256 / 512-bit nonce-buf shapes. The ZMM x8 kernels
// (aescmac_fusedchain128_<shape>x8_avx512_amd64.s) keep the eight states
// in two registers whose cascade rounds are interleaved; every other
// build and every other selected tier runs the eight lanes as two
// four-lane calls of the x4 dispatcher, so the result is bit-exact with
// eight [ScalarFusedChain] evaluations on every arm.

// fusedX4Dispatch is the signature of the four-lane fused dispatchers.
type fusedX4Dispatch func(s *Schedule, components []uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

// fusedChainX8ViaX4 runs an eight-lane cascade as two four-lane calls of
// x4: lanes 0..3 first, then lanes 4..7. The x4 dispatcher applies its own
// tier selection and component guard, so this is the fallback of every
// arm that has no eight-lane kernel.
func fusedChainX8ViaX4(x4 fusedX4Dispatch, s *Schedule, components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	lo := [4]*byte{dataPtrs[0], dataPtrs[1], dataPtrs[2], dataPtrs[3]}
	hi := [4]*byte{dataPtrs[4], dataPtrs[5], dataPtrs[6], dataPtrs[7]}
	var o [4][2]uint64
	x4(s, components, &lo, &o)
	copy(out[0:4], o[:])
	x4(s, components, &hi, &o)
	copy(out[4:8], o[:])
}
