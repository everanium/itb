//go:build amd64 && !purego && !noitbasm

package chacha20ctr

import (
	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

var (
	// HasAVX512 reports whether the AVX-512 (F + VL) ChaCha20 keystream XOR
	// kernel is active on the running host.
	HasAVX512 = cpuid.AVX512F && cpuid.AVX512VL
	// HasAVX2 reports whether the AVX2 ChaCha20 keystream XOR kernel is active
	// on the running host.
	HasAVX2 = cpuid.AVX2
)

func init() {
	applyHashTier()
}

func applyHashTier() {
	switch forcetier.HashTier() {
	case "":
	case "avx512":
		if !cpuid.AVX512F || !cpuid.AVX512VL {
			forcetier.Warnf("chacha20ctr: avx512 tier needs AVX-512F+VL; keeping auto-dispatch")
			return
		}
		HasAVX512, HasAVX2 = true, false
	case "avx2", "vex":
		if !cpuid.AVX2 {
			forcetier.Warnf("chacha20ctr: %s tier needs AVX2; keeping auto-dispatch", forcetier.HashTier())
			return
		}
		HasAVX512, HasAVX2 = false, true
	case "aesni", "vaesavx2":
		// ChaCha20 has no AES-based arm; keep auto-dispatch.
	case "neon", "sve2", "sve":
		// arm64-only tokens; keep auto-dispatch.
	case "gpr", "scalar":
		HasAVX512, HasAVX2 = false, false
	}
}

//go:noescape
func chacha20XORBlocksAvx512Asm(key *[8]uint32, nonce *[3]uint32, counter uint32, dst, src *byte, nBlocks int)

//go:noescape
func chacha20XORBlocksAvx2Asm(key *[8]uint32, nonce *[3]uint32, counter uint32, dst, src *byte, nBlocks int)

// XORKeyStreamBlocks XORs full 64-byte blocks of RFC 8439 ChaCha20 keystream
// from src into dst starting at counter. len(src) must be a non-negative
// multiple of BlockSize (64).
func XORKeyStreamBlocks(dst, src []byte, key *[8]uint32, nonce *[3]uint32, counter uint32) {
	nBlocks := len(src) / BlockSize
	if nBlocks <= 0 {
		return
	}
	if len(src) < nBlocks*BlockSize || len(dst) < nBlocks*BlockSize {
		panic("chacha20: buffer smaller than nBlocks")
	}
	if uint64(counter)+uint64(nBlocks) > 1<<32 {
		panic("chacha20: counter overflow")
	}
	if HasAVX512 {
		chacha20XORBlocksAvx512Asm(key, nonce, counter, &dst[0], &src[0], nBlocks)
		return
	}
	if HasAVX2 {
		chacha20XORBlocksAvx2Asm(key, nonce, counter, &dst[0], &src[0], nBlocks)
		return
	}
	scalarXORKeyStreamBlocks(dst[:nBlocks*BlockSize], src[:nBlocks*BlockSize], key, nonce, counter)
}
