package hashes

import (
	"fmt"
	"testing"

	"github.com/everanium/itb"
)

// seed_attach_test.go — the Low-Level attach surface: AttachFused128 /
// AttachInterlockBatch16 and the SeedFromComponents128x16 helper that
// composes them. The hooks are performance paths only, so every test
// below pins agreement between a hooked seed and the same seed on the
// arms alone rather than the presence of any hook: the wire-level
// counterpart (every registry primitive at every width, hooked and
// arms-only constellations decrypting each other) is the root
// package's TestCascadeCrossConstructorRoundTrip.

// pixelShapes are the per-pixel and fill input shapes the fused hooks
// accept, plus one shape outside the kernel set that must fall back to
// the sequential loop.
var pixelShapes = []int{13, 20, 36, 68, 21}

// manualSeed128 builds a seed from components through the arms alone.
func manualSeed128(t *testing.T, name string, key []byte, comps []uint64) *itb.Seed128 {
	t.Helper()
	var keyArg [][]byte
	if len(key) > 0 {
		keyArg = [][]byte{key}
	}
	single, batched, _, err := Make128Pair(name, keyArg...)
	if err != nil {
		t.Fatalf("Make128Pair(%q): %v", name, err)
	}
	s, err := itb.SeedFromComponents128(single, comps...)
	if err != nil {
		t.Fatal(err)
	}
	s.BatchHash = batched
	return s
}

// assertChainHashAgree pins ChainHash128 and BatchChainHash128 of two
// seeds on every pixel shape.
func assertChainHashAgree(t *testing.T, label string, a, b *itb.Seed128) {
	t.Helper()
	for _, n := range pixelShapes {
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = byte(i*7 + n)
		}
		aLo, aHi := a.ChainHash128(buf)
		bLo, bHi := b.ChainHash128(buf)
		if aLo != bLo || aHi != bHi {
			t.Fatalf("%s: ChainHash128 differs at len %d", label, n)
		}
		if a.BatchHash == nil || b.BatchHash == nil {
			continue
		}
		var lanes [4][]byte
		for l := range lanes {
			lanes[l] = append([]byte(nil), buf...)
			lanes[l][0] ^= byte(l)
		}
		la, lb := lanes, lanes
		outA := a.BatchChainHash128(&la)
		outB := b.BatchChainHash128(&lb)
		if outA != outB {
			t.Fatalf("%s: BatchChainHash128 differs at len %d", label, n)
		}
	}
}

// TestAttachHooksWireIndependent pins, for every width-128 registry
// primitive, that a seed with every hook the primitive offers and the
// same seed on the arms alone agree on the per-pixel cascade, and that
// the batch-16 hook — when the primitive attaches one — agrees with
// sixteen sequential cascades over the fill blocks.
func TestAttachHooksWireIndependent(t *testing.T) {
	comps := make([]uint64, 16)
	for i := range comps {
		comps[i] = uint64(i+1) * 0x9E3779B97F4A7C15
	}
	for _, spec := range Registry {
		if spec.Width != W128 {
			continue
		}
		t.Run(spec.Name, func(t *testing.T) {
			_, _, key, err := Make128Pair(spec.Name)
			if err != nil {
				t.Fatal(err)
			}
			plain := manualSeed128(t, spec.Name, key, comps)
			hooked := manualSeed128(t, spec.Name, key, comps)
			if err := AttachFused128(hooked, spec.Name, key); err != nil {
				t.Fatalf("AttachFused128: %v", err)
			}
			if err := AttachInterlockBatch16(hooked, spec.Name, key); err != nil {
				t.Fatalf("AttachInterlockBatch16: %v", err)
			}
			if plain.FusedChain != nil || plain.BatchFusedChain != nil || plain.InterlockFillX16() != nil {
				t.Fatal("arms-only seed carries a hook")
			}
			assertChainHashAgree(t, "hooked vs arms-only", hooked, plain)
			if fill := hooked.InterlockFillX16(); fill != nil {
				var out [16][2]uint64
				lockComps := append([]uint64{0x1122334455667788, 0x99AABBCCDDEEFF00}, comps...)
				for _, base := range []uint64{0, 15, 0xFFFFFFFFFFFFFFF0} {
					fill(lockComps, base, &out)
					for i := 0; i < 16; i++ {
						buf := make([]byte, 13)
						buf[0] = 0x03
						g := base + uint64(i)
						for j := 0; j < 8; j++ {
							buf[1+j] = byte(g >> (8 * j))
						}
						lo, hi := plain.Hash(buf, lockComps[0], lockComps[1])
						for k := 2; k < len(lockComps); k += 2 {
							lo, hi = plain.Hash(buf, lockComps[k]^lo, lockComps[k+1]^hi)
						}
						if out[i] != [2]uint64{lo, hi} {
							t.Fatalf("batch-16 hook lane %d base %#x diverges from the sequential cascade", i, base)
						}
					}
				}
			}
		})
	}
}

// TestSeedFromComponents128x16 checks the existing-components helper on
// every width-128 registry primitive: the components are copied
// verbatim, the arms are wired, and the seed agrees with the arms-only
// build on the same key and components.
func TestSeedFromComponents128x16(t *testing.T) {
	comps := make([]uint64, 16)
	for i := range comps {
		comps[i] = uint64(i+1) * 0xC2B2AE3D27D4EB4F
	}
	for _, spec := range Registry {
		if spec.Width != W128 {
			continue
		}
		t.Run(spec.Name, func(t *testing.T) {
			_, _, key, err := Make128Pair(spec.Name)
			if err != nil {
				t.Fatal(err)
			}
			s, err := SeedFromComponents128x16(spec.Name, key, comps...)
			if err != nil {
				t.Fatalf("SeedFromComponents128x16(%q): %v", spec.Name, err)
			}
			if len(s.Components) != len(comps) {
				t.Fatalf("components: got %d words, want %d", len(s.Components), len(comps))
			}
			for i := range comps {
				if s.Components[i] != comps[i] {
					t.Fatalf("component %d differs", i)
				}
			}
			if s.Hash == nil {
				t.Fatal("Hash not wired")
			}
			assertChainHashAgree(t, "helper vs arms-only", s, manualSeed128(t, spec.Name, key, comps))
		})
	}
}

// TestSeedFromComponents128x16Keyless checks the keyless primitive: an
// empty key is accepted (the blob key field of siphash24 is empty) and
// an explicit key is rejected.
func TestSeedFromComponents128x16Keyless(t *testing.T) {
	comps := make([]uint64, 8)
	for i := range comps {
		comps[i] = uint64(i + 1)
	}
	s, err := SeedFromComponents128x16(CipherSipHash24, nil, comps...)
	if err != nil {
		t.Fatalf("SeedFromComponents128x16(siphash24, nil): %v", err)
	}
	assertChainHashAgree(t, "siphash24 helper vs arms-only", s, manualSeed128(t, CipherSipHash24, nil, comps))
	if _, err := SeedFromComponents128x16(CipherSipHash24, make([]byte, 16), comps...); err == nil {
		t.Fatal("siphash24 accepted an explicit key")
	}
}

// TestSeedFromComponents128x16Errors checks error propagation: an
// empty key for a keyed primitive, a wrong key length, an unknown or
// non-128 primitive, and a bad component count.
func TestSeedFromComponents128x16Errors(t *testing.T) {
	comps := make([]uint64, 8)
	for i := range comps {
		comps[i] = uint64(i + 1)
	}
	for _, tc := range []struct {
		label string
		name  string
		key   []byte
		comps []uint64
	}{
		{"aesitb128 empty key", CipherAESITB128, nil, comps},
		{"aescmac empty key", CipherAES128CTR, nil, comps},
		{"15-byte key", CipherAESITB128, make([]byte, 15), comps},
		{"unknown primitive", "no_such_primitive", make([]byte, 16), comps},
		{"width-512 primitive", CipherAreion512, make([]byte, 64), comps},
		{"6-word component slice", CipherAESITB128, make([]byte, 16), comps[:6]},
		{"odd component count", CipherAESITB128, make([]byte, 16), comps[:7]},
	} {
		if s, err := SeedFromComponents128x16(tc.name, tc.key, tc.comps...); err == nil || s != nil {
			t.Fatalf("%s did not fail", tc.label)
		}
	}
}

// TestAttachHelpersNoOp checks that the attach helpers leave a seed
// unchanged, without error, for an unknown name and for a primitive
// without the factories.
func TestAttachHelpersNoOp(t *testing.T) {
	comps := make([]uint64, 8)
	for i := range comps {
		comps[i] = uint64(i + 1)
	}
	s := manualSeed128(t, CipherSipHash24, nil, comps)
	for _, name := range []string{"no_such_primitive", CipherSipHash24} {
		if err := AttachFused128(s, name, nil); err != nil {
			t.Fatalf("AttachFused128(%q): %v", name, err)
		}
		if err := AttachInterlockBatch16(s, name, nil); err != nil {
			t.Fatalf("AttachInterlockBatch16(%q): %v", name, err)
		}
		if s.FusedChain != nil || s.BatchFusedChain != nil || s.InterlockFillX16() != nil {
			t.Fatalf("AttachFused128 / AttachInterlockBatch16(%q) populated a hook", name)
		}
	}
}

// TestWideSeedsConstructorArms pins, for every width-256 / width-512
// registry primitive, that the explicit Low-Level constructor sequence
// wires the batched arm and that the batched cascade agrees with the
// single-lane cascade on every pixel shape — the same arms the
// Interlocked Barrier cascade fill consumes at those widths.
func TestWideSeedsConstructorArms(t *testing.T) {
	for _, spec := range Registry {
		if spec.Width == W128 {
			continue
		}
		for _, bits := range []int{512, 1024, 2048} {
			t.Run(fmt.Sprintf("%s/%d", spec.Name, bits), func(t *testing.T) {
				for _, n := range pixelShapes {
					buf := make([]byte, n)
					for i := range buf {
						buf[i] = byte(i*11 + n)
					}
					var lanes [4][]byte
					for l := range lanes {
						lanes[l] = append([]byte(nil), buf...)
						lanes[l][0] ^= byte(l)
					}
					switch spec.Width {
					case W256:
						s, err := newSeed256(spec.Name, bits)
						if err != nil {
							t.Fatal(err)
						}
						if s.BatchHash == nil {
							t.Fatal("BatchHash not wired")
						}
						got := s.BatchChainHash256(&lanes)
						for l := range lanes {
							if got[l] != s.ChainHash256(lanes[l]) {
								t.Fatalf("len %d lane %d: batched cascade diverges from the single-lane cascade", n, l)
							}
						}
					case W512:
						s, err := newSeed512(spec.Name, bits)
						if err != nil {
							t.Fatal(err)
						}
						if s.BatchHash == nil {
							t.Fatal("BatchHash not wired")
						}
						got := s.BatchChainHash512(&lanes)
						for l := range lanes {
							if got[l] != s.ChainHash512(lanes[l]) {
								t.Fatalf("len %d lane %d: batched cascade diverges from the single-lane cascade", n, l)
							}
						}
					}
				}
			})
		}
	}
}
