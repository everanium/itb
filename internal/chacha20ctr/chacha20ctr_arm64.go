//go:build arm64 && !purego && !noitbasm

package chacha20ctr

import (
	"github.com/everanium/itb/internal/cpuid"
	"github.com/everanium/itb/internal/forcetier"
)

// HasNEON reports whether the ARM64 NEON 4-block ChaCha20 keystream XOR
// kernel is active on the running host.
var HasNEON = cpuid.ASIMD

func init() {
	applyHashTier()
}

func applyHashTier() {
	switch forcetier.HashTier() {
	case "":
	case "neon", "sve2", "sve":
		if !cpuid.ASIMD {
			forcetier.Warnf("chacha20ctr: %s tier needs Advanced SIMD; keeping auto-dispatch", forcetier.HashTier())
			return
		}
		HasNEON = true
	case "gpr", "scalar":
		HasNEON = false
	}
}

//go:noescape
func xorKeyStreamVX(dst, src []byte, key *[8]uint32, nonce *[3]uint32, counter *uint32)

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
	nBytes := nBlocks * BlockSize
	if HasNEON {
		xorKeyStreamVX(dst[:nBytes], src[:nBytes], key, nonce, &counter)
		return
	}
	scalarXORKeyStreamBlocks(dst[:nBytes], src[:nBytes], key, nonce, counter)
}
