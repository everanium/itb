//go:build amd64 && !purego && !noitbasm

package blake2sasm

import "golang.org/x/sys/cpu"

// HasAVX2Fused reports whether the runtime CPU supports the AVX2 fused
// chain-absorb kernels: AVX2 present but AVX-512F absent. Mutually
// exclusive with HasAVX512Fused. AVX2-only silicon (Zen 3, Cascade
// Lake, AVX2-without-VAES cloud VMs) selects the XMM AVX2 kernels
// declared here, which hold four lane-isolated BLAKE2s states in
// registers with the message words spilled to stack slots and the ARX
// rotates synthesised (AVX2 has no VPRORD).
var HasAVX2Fused = cpu.X86.HasAVX2 && !cpu.X86.HasAVX512F

// blake2s256ChainAbsorb13x4Avx2Asm — 13-byte AVX2 kernel
// (blake2s_chain256_13_avx2_amd64.s).
//
//go:noescape
func blake2s256ChainAbsorb13x4Avx2Asm(h0 *[8]uint32, b2key *[32]byte,
	seeds *[4][4]uint64, dataPtrs *[4]*byte, out *[4][8]uint32)

// blake2s256ChainAbsorb20x4Avx2Asm — 20-byte AVX2 kernel
// (blake2s_chain256_20_avx2_amd64.s).
//
//go:noescape
func blake2s256ChainAbsorb20x4Avx2Asm(h0 *[8]uint32, b2key *[32]byte,
	seeds *[4][4]uint64, dataPtrs *[4]*byte, out *[4][8]uint32)

// blake2s256ChainAbsorb36x4Avx2Asm — 36-byte two-block AVX2 kernel
// (blake2s_chain256_36_avx2_amd64.s).
//
//go:noescape
func blake2s256ChainAbsorb36x4Avx2Asm(h0 *[8]uint32, b2key *[32]byte,
	seeds *[4][4]uint64, dataPtrs *[4]*byte, out *[4][8]uint32)

// blake2s256ChainAbsorb68x4Avx2Asm — 68-byte two-block AVX2 kernel
// (blake2s_chain256_68_avx2_amd64.s).
//
//go:noescape
func blake2s256ChainAbsorb68x4Avx2Asm(h0 *[8]uint32, b2key *[32]byte,
	seeds *[4][4]uint64, dataPtrs *[4]*byte, out *[4][8]uint32)
