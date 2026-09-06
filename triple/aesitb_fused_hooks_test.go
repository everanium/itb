package triple

import (
	"testing"

	"github.com/everanium/itb"
)

// TestAESITBProfilesFusedHooksAttached pins that every one of the eight
// inner seeds of an AES-ITB pipeline carries the fused ChainHash hooks,
// both when built by Init and when rebuilt from a saved blob by Load —
// a seed without them silently runs the sequential loop.
func TestAESITBProfilesFusedHooksAttached(t *testing.T) {
	for _, name := range []string{
		ProfileSingleMsgAESITBMACV1, ProfileSingleMsgAESITBNoMACV1,
		ProfileStreamingAEADAESITBMACV1, ProfileStreamingNoAEADAESITBV1,
	} {
		t.Run(name, func(t *testing.T) {
			p, blob, err := Init(name, Opts{})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			check := func(label string, seeds [8]any) {
				for i, s := range seeds {
					seed, ok := s.(*itb.Seed128)
					if !ok {
						t.Fatalf("%s: seed %d is %T, want *itb.Seed128", label, i, s)
					}
					if seed.FusedChain == nil || seed.BatchFusedChain == nil {
						t.Errorf("%s: seed %d lacks fused hooks (FusedChain=%v BatchFusedChain=%v)",
							label, i, seed.FusedChain != nil, seed.BatchFusedChain != nil)
					}
					if seed.BatchHash == nil {
						t.Errorf("%s: seed %d lacks the batched arm", label, i)
					}
				}
			}
			check("Init", p.seeds)
			q, err := Load(blob)
			if err != nil {
				t.Fatal(err)
			}
			defer q.Close()
			check("Load", q.seeds)
		})
	}
}
