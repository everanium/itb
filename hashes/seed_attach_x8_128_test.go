package hashes

import (
	"strings"
	"testing"

	"github.com/everanium/itb"
)

// goX8Factory128 returns a FusedChainHash128x8 factory evaluating the
// cascade in Go over the single arm of mk; corrupt flips an output bit,
// decline returns a nil evaluator.
func goX8Factory128(mk func(key ...[]byte) (itb.HashFunc128, itb.BatchHashFunc128, []byte, error), corrupt, decline bool) func(key []byte) (itb.BatchFusedChainHashFunc128x8, error) {
	return func(key []byte) (itb.BatchFusedChainHashFunc128x8, error) {
		single, _, _, err := mk(key)
		if err != nil {
			return nil, err
		}
		if decline {
			return nil, nil
		}
		return func(components []uint64, data *[8][]byte) ([8][2]uint64, bool) {
			var out [8][2]uint64
			for l := range data {
				lo, hi := single(data[l], components[0], components[1])
				for i := 2; i < len(components); i += 2 {
					lo, hi = single(data[l], components[i]^lo, components[i+1]^hi)
				}
				out[l] = [2]uint64{lo, hi}
				if corrupt {
					out[l][1] ^= 1
				}
			}
			return out, true
		}, nil
	}
}

// TestRegisterCustomX8Factory128 registers custom width-128 primitives
// carrying a pure-Go eight-lane factory and pins that the name-keyed
// constructor installs the hook, that the hook agrees with the
// sequential cascade of the single arm, that a declining factory leaves
// the hook nil, and that a divergent factory is rejected at Register
// time — the width-128 counterpart of TestWide32AttachCustomFactories.
func TestRegisterCustomX8Factory128(t *testing.T) {
	mk := makeCustom128PairFactory()
	name := customFactoryName + "x8f"
	if err := Register(Spec{Name: name, Width: W128, Make128Pair: mk, FusedChainHash128: goFused128Factory(mk), FusedChainHash128x8: goX8Factory128(mk, false, false)}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	s, key, err := NewSeed128(name, 1024)
	if err != nil {
		t.Fatal(err)
	}
	x8 := s.BatchFusedChain8()
	if x8 == nil {
		t.Fatal("NewSeed128 left the eight-lane hook nil")
	}
	plain := manualSeed128(t, name, key, s.Components)
	for _, n := range []int{13, 20, 36, 68} {
		var lanes [8][]byte
		for l := range lanes {
			lanes[l] = make([]byte, n)
			for i := range lanes[l] {
				lanes[l][i] = byte(i*3 + l*7 + 1)
			}
		}
		out, ok := x8(s.Components, &lanes)
		if !ok {
			t.Fatalf("len %d: the eight-lane hook declined", n)
		}
		for l := range lanes {
			lo, hi := plain.ChainHash128(lanes[l])
			if out[l] != [2]uint64{lo, hi} {
				t.Fatalf("len %d lane %d: the eight-lane hook diverges from the sequential cascade", n, l)
			}
		}
	}
	declining := customFactoryName + "x8dcl"
	if err := Register(Spec{Name: declining, Width: W128, Make128Pair: mk, FusedChainHash128x8: goX8Factory128(mk, false, true)}); err != nil {
		t.Fatalf("Register(declining): %v", err)
	}
	d, _, err := NewSeed128(declining, 512)
	if err != nil {
		t.Fatal(err)
	}
	if d.BatchFusedChain8() != nil {
		t.Fatal("a declining eight-lane factory populated the hook")
	}
	bad := customFactoryName + "x8bad"
	err = Register(Spec{Name: bad, Width: W128, Make128Pair: mk, FusedChainHash128x8: goX8Factory128(mk, true, false)})
	if err == nil || !strings.Contains(err.Error(), "diverges") {
		t.Fatalf("Register of a divergent FusedChainHash128x8 factory: err=%v", err)
	}
}
