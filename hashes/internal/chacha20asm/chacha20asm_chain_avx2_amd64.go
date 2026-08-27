//go:build amd64 && !purego && !noitbasm

package chacha20asm

// This file declares the AVX2 (no AVX-512) 4-lane chain-absorb kernels
// for ChaCha20-256, the fallback batched path for AVX2-only hosts
// (HasAVX2Fused == true). The single-block widths (13/20/36) pack 4
// pixel lanes per XMM; the 68-byte width uses a dual-counter YMM fusion
// (counter 0 in the low 128 bits, counter 1 in the high 128 bits — the
// measured winner over two sequential XMM compressions). Immediate
// rotates are synthesized (VPSHUFB byte-masks for 16/8; VPSLLD/VPSRLD/
// VPOR for 12/7). Output is bit-exact with the AVX-512 kernels and the
// Go single closure; verified by the tests in
// chacha20asm_chain_avx2_test.go.

//go:noescape
func chaCha20256ChainAbsorb13x4Avx2Asm(fixedKey *[32]byte, seeds *[4][4]uint64, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func chaCha20256ChainAbsorb20x4Avx2Asm(fixedKey *[32]byte, seeds *[4][4]uint64, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func chaCha20256ChainAbsorb36x4Avx2Asm(fixedKey *[32]byte, seeds *[4][4]uint64, dataPtrs *[4]*byte, out *[4][4]uint64)

//go:noescape
func chaCha20256ChainAbsorb68x4Avx2Asm(fixedKey *[32]byte, seeds *[4][4]uint64, dataPtrs *[4]*byte, out *[4][4]uint64)
