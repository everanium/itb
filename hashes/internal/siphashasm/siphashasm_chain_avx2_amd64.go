//go:build amd64 && !purego && !noitbasm

package siphashasm

// AVX2 (no AVX-512) 4-lane YMM chain-absorb kernels for SipHash-2-4-128,
// the fallback batched path for AVX2-only hosts (HasAVX2Fused == true).
// SipHash's 4-word state fits AVX2's 16-register file, so the layout is
// identical to the AVX-512 tier (v0..v3 in Y0..Y3, lane = qword); the
// SipRound immediate rotates are synthesized (VPSHUFD for 32, VPSHUFB
// mask for 16, VPSLLQ/VPSRLQ/VPOR for 13/21/17). Output is bit-exact
// with the AVX-512 kernels and the Go single closure; verified by the
// tests in siphashasm_chain_avx2_test.go.

//go:noescape
func sipHash24Chain128Absorb13x4Avx2Asm(seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24Chain128Absorb20x4Avx2Asm(seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24Chain128Absorb36x4Avx2Asm(seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)

//go:noescape
func sipHash24Chain128Absorb68x4Avx2Asm(seeds *[4][2]uint64, dataPtrs *[4]*byte, out *[4][2]uint64)
