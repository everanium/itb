package hashes

import (
	"testing"

	"github.com/everanium/itb/internal/forcetier"
)

// dispatch_env_test.go — the disarm knobs of the fused cascade hooks,
// asserted for every shipped registry entry: under
// ITB_FORCE_CHAINHASH_SEQ a seed built through the name-keyed
// constructor carries no fused hook at any width, under
// ITB_FORCE_CHAINHASH_X4 it carries no eight-lane hook, and with neither
// variable set every entry whose registry row populates a factory
// carries the hook the factory builds. The tier variables are asserted
// by the forcetier tests of every kernel package.

// TestRegistryFusedHooksFollowDisarmKnobs walks the registry at every
// width and checks the hooks of a name-keyed seed against the knobs.
func TestRegistryFusedHooksFollowDisarmKnobs(t *testing.T) {
	seq, x4 := forcetier.ChainHashSeq(), forcetier.ChainHashX4()
	for _, spec := range Registry {
		t.Run(spec.Name, func(t *testing.T) {
			switch spec.Width {
			case W128:
				s, _, err := NewSeed128(spec.Name, 512)
				if err != nil {
					t.Fatal(err)
				}
				has := s.FusedChain != nil || s.BatchFusedChain != nil
				switch {
				case seq && has:
					t.Fatal("ITB_FORCE_CHAINHASH_SEQ: fused hooks present")
				case !seq && spec.FusedChainHash128 != nil && !has:
					t.Fatal("registry factory present but no fused hook installed")
				}
				if x4 && s.BatchFusedChain8() != nil {
					t.Fatal("ITB_FORCE_CHAINHASH_X4: eight-lane hook present")
				}
				if (seq || spec.FusedChainHash128 == nil) && s.BatchFusedChain8() != nil {
					t.Fatal("eight-lane hook present without the four-lane factory")
				}
			case W256:
				s, _, err := NewSeed256(spec.Name, 1024)
				if err != nil {
					t.Fatal(err)
				}
				has := s.FusedChain != nil || s.BatchFusedChain != nil
				switch {
				case seq && has:
					t.Fatal("ITB_FORCE_CHAINHASH_SEQ: fused hooks present")
				case !seq && spec.FusedChainHash256 != nil && !has:
					t.Fatal("registry factory present but no fused hook installed")
				}
				if x4 && s.BatchFusedChain8() != nil {
					t.Fatal("ITB_FORCE_CHAINHASH_X4: eight-lane hook present")
				}
				if (seq || spec.FusedChainHash256x8 == nil) && s.BatchFusedChain8() != nil {
					t.Fatal("eight-lane hook present without its factory")
				}
				if spec.InterlockFillBatch16x256 == nil && s.InterlockFillX16() != nil {
					t.Fatal("batch-16 fill hook present without its factory")
				}
				if spec.InterlockFillBatch32x256 == nil && s.InterlockFillX32() != nil {
					t.Fatal("batch-32 fill hook present without its factory")
				}
			case W512:
				s, _, err := NewSeed512(spec.Name, 1024)
				if err != nil {
					t.Fatal(err)
				}
				has := s.FusedChain != nil || s.BatchFusedChain != nil
				switch {
				case seq && has:
					t.Fatal("ITB_FORCE_CHAINHASH_SEQ: fused hooks present")
				case !seq && spec.FusedChainHash512 != nil && !has:
					t.Fatal("registry factory present but no fused hook installed")
				}
				if x4 && s.BatchFusedChain8() != nil {
					t.Fatal("ITB_FORCE_CHAINHASH_X4: eight-lane hook present")
				}
				if (seq || spec.FusedChainHash512x8 == nil) && s.BatchFusedChain8() != nil {
					t.Fatal("eight-lane hook present without its factory")
				}
				if spec.InterlockFillBatch16x512 == nil && s.InterlockFillX16() != nil {
					t.Fatal("batch-16 fill hook present without its factory")
				}
				if spec.InterlockFillBatch32x512 == nil && s.InterlockFillX32() != nil {
					t.Fatal("batch-32 fill hook present without its factory")
				}
			}
		})
	}
}
