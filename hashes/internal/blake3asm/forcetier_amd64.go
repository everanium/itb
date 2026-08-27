//go:build amd64 && !purego && !noitbasm

package blake3asm

import (
	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/internal/forcetier"
)

// init applies ITB_FORCE_HASH_TIER to the BLAKE3 fused chain-absorb
// dispatch flags. Both flags are assigned explicitly as one consistent
// set. A forced arm the silicon cannot execute keeps auto-dispatch
// with a stderr note. BLAKE3 has no AES-based arm, so an aesni force
// disables both batched arms (scalar behaviour) with a stderr note;
// the parity script's skip matrix avoids that pairing.
func init() {
	switch forcetier.HashTier() {
	case "avx512":
		if !cpu.X86.HasAVX512F {
			forcetier.Warnf("blake3asm: avx512 tier needs AVX-512F; keeping auto-dispatch")
			return
		}
		HasAVX512Fused, HasAVX2Fused = true, false
	case "avx2":
		if !cpu.X86.HasAVX2 {
			forcetier.Warnf("blake3asm: avx2 tier needs AVX2; keeping auto-dispatch")
			return
		}
		HasAVX512Fused, HasAVX2Fused = false, true
	case "aesni":
		forcetier.Warnf("blake3asm: no aesni arm; forcing scalar")
		HasAVX512Fused, HasAVX2Fused = false, false
	case "scalar":
		HasAVX512Fused, HasAVX2Fused = false, false
	}
}
