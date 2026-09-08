package siphashasm

// Eight-lane fused cascade dispatchers ([FusedChain20x8] / [FusedChain36x8]
// / [FusedChain68x8]) run the ChainHash128 cascade of siphashasm_fused.go on
// eight lanes with distinct data over one shared component slice — the
// shape the itb pixel pipeline drives through its eight-lane batched hook
// at the 128 / 256 / 512-bit nonce-buf shapes. The ZMM x8 kernels
// (siphash_fusedchain128_<shape>x8_avx512_amd64.s) hold the eight lanes in
// one qword each of the 512-bit state registers; every other build and
// every other selected tier runs the eight lanes as two four-lane calls
// of the x4 dispatcher, so the result is bit-exact with eight
// [ScalarFusedChain] evaluations on every arm.

// fusedChainX8ViaX4 runs an eight-lane cascade at shape n as two
// four-lane calls of the shape's x4 dispatcher: lanes 0..3 first, then
// lanes 4..7. The x4 dispatcher applies its own tier selection and
// component guard, so this is the fallback of every arm that has no
// eight-lane kernel. The dispatchers are called directly (not through a
// function value) so the lane-pointer halves stay on the stack.
func fusedChainX8ViaX4(n int, components []uint64, dataPtrs *[8]*byte, out *[8][2]uint64) {
	lo := [4]*byte{dataPtrs[0], dataPtrs[1], dataPtrs[2], dataPtrs[3]}
	hi := [4]*byte{dataPtrs[4], dataPtrs[5], dataPtrs[6], dataPtrs[7]}
	outLo, outHi := (*[4][2]uint64)(out[0:4]), (*[4][2]uint64)(out[4:8])
	switch n {
	case 20:
		FusedChain20x4(components, &lo, outLo)
		FusedChain20x4(components, &hi, outHi)
	case 36:
		FusedChain36x4(components, &lo, outLo)
		FusedChain36x4(components, &hi, outHi)
	case 68:
		FusedChain68x4(components, &lo, outLo)
		FusedChain68x4(components, &hi, outHi)
	}
}
