//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"bytes"
	"testing"
)

// TestAreionRC4x_TableInit verifies that init() correctly populates
// the AreionRC4x pre-broadcast round-constant table. Each of the 15
// canonical 16-byte constants must be replicated 4 times to fill its
// 64-byte slot. A regression in init() (off-by-one loop bound,
// stride mismatch, wrong source array) would surface here as a
// fail-fast smoke test before reaching any encrypt path that consumes
// the table via the assembly kernels.
func TestAreionRC4x_TableInit(t *testing.T) {
	for r := 0; r < 15; r++ {
		want := Constants[r][:]
		for copyIdx := 0; copyIdx < 4; copyIdx++ {
			offset := r*64 + copyIdx*16
			got := AreionRC4x[offset : offset+16]
			if !bytes.Equal(got, want) {
				t.Fatalf("round %d copy %d mismatch: got %x want %x", r, copyIdx, got, want)
			}
		}
	}
}

// TestVAESFlags_MutualExclusion verifies the dispatch invariant that
// HasVAESAVX512 and HasVAESAVX2NoAVX512 are never both true on the
// same CPU — the AVX-2 flag is defined to exclude AVX-512 explicitly,
// so any future regression in the derivation expressions (e.g.
// dropping the `&& !aes.CPU.HasAVX512` clause) would create
// ambiguous dispatch routing in the parent package.
func TestVAESFlags_MutualExclusion(t *testing.T) {
	if HasVAESAVX512 && HasVAESAVX2NoAVX512 {
		t.Fatal("HasVAESAVX512 and HasVAESAVX2NoAVX512 both true — dispatch logic ambiguous")
	}
}
