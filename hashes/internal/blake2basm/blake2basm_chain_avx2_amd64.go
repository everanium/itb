//go:build amd64 && !purego && !noitbasm

package blake2basm

import "golang.org/x/sys/cpu"

// HasAVX2Fused reports whether the runtime CPU supports the AVX2 fused
// chain-absorb kernels: AVX2 present but AVX-512F absent. On hosts with
// AVX-512F the wider HasAVX512Fused path is taken instead; the two
// flags are mutually exclusive by construction. AVX2-only silicon
// (Zen 3, Cascade Lake, and AVX2-without-VAES cloud VMs) selects the
// YMM/XMM AVX2 kernels declared in this file, which hold four
// lane-isolated BLAKE2b states in registers with the message words
// spilled to stack slots (AVX2 exposes only 16 vector registers, half
// the AVX-512 file), and synthesise the ARX rotates that the AVX-512
// kernels express with VPRORQ.
var HasAVX2Fused = cpu.X86.HasAVX2 && !cpu.X86.HasAVX512F

// blake2b256ChainAbsorb20x4Avx2Asm is the AVX2 YMM-batched fused
// chain-absorb kernel implemented in blake2b_chain256_20_avx2_amd64.s.
//
//go:noescape
func blake2b256ChainAbsorb20x4Avx2Asm(
	h0 *[8]uint64,
	b2key *[32]byte,
	seeds *[4][4]uint64,
	dataPtrs *[4]*byte,
	out *[4][8]uint64,
)

// blake2b256ChainAbsorb13x4Avx2Asm — 13-byte AVX2 kernel
// (blake2b_chain256_13_avx2_amd64.s).
//
//go:noescape
func blake2b256ChainAbsorb13x4Avx2Asm(h0 *[8]uint64, b2key *[32]byte,
	seeds *[4][4]uint64, dataPtrs *[4]*byte, out *[4][8]uint64)

// blake2b256ChainAbsorb36x4Avx2Asm — 36-byte AVX2 kernel
// (blake2b_chain256_36_avx2_amd64.s).
//
//go:noescape
func blake2b256ChainAbsorb36x4Avx2Asm(h0 *[8]uint64, b2key *[32]byte,
	seeds *[4][4]uint64, dataPtrs *[4]*byte, out *[4][8]uint64)

// blake2b256ChainAbsorb68x4Avx2Asm — 68-byte AVX2 kernel
// (blake2b_chain256_68_avx2_amd64.s).
//
//go:noescape
func blake2b256ChainAbsorb68x4Avx2Asm(h0 *[8]uint64, b2key *[32]byte,
	seeds *[4][4]uint64, dataPtrs *[4]*byte, out *[4][8]uint64)

// blake2b512ChainAbsorb13x4Avx2Asm — 13-byte AVX2 kernel
// (blake2b_chain512_13_avx2_amd64.s).
//
//go:noescape
func blake2b512ChainAbsorb13x4Avx2Asm(h0 *[8]uint64, b2key *[64]byte,
	seeds *[4][8]uint64, dataPtrs *[4]*byte, out *[4][8]uint64)

// blake2b512ChainAbsorb20x4Avx2Asm — 20-byte AVX2 kernel
// (blake2b_chain512_20_avx2_amd64.s).
//
//go:noescape
func blake2b512ChainAbsorb20x4Avx2Asm(h0 *[8]uint64, b2key *[64]byte,
	seeds *[4][8]uint64, dataPtrs *[4]*byte, out *[4][8]uint64)

// blake2b512ChainAbsorb36x4Avx2Asm — 36-byte AVX2 kernel
// (blake2b_chain512_36_avx2_amd64.s).
//
//go:noescape
func blake2b512ChainAbsorb36x4Avx2Asm(h0 *[8]uint64, b2key *[64]byte,
	seeds *[4][8]uint64, dataPtrs *[4]*byte, out *[4][8]uint64)

// blake2b512ChainAbsorb68x4Avx2Asm — 68-byte two-block AVX2 kernel
// (blake2b_chain512_68_avx2_amd64.s).
//
//go:noescape
func blake2b512ChainAbsorb68x4Avx2Asm(h0 *[8]uint64, b2key *[64]byte,
	seeds *[4][8]uint64, dataPtrs *[4]*byte, out *[4][8]uint64)
