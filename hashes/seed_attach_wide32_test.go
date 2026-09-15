package hashes

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/everanium/itb"
)

// seed_attach_wide32_test.go — the eight-lane fused hook and the
// batch-32 fill hook of the width-256 / width-512 attach surface:
// Spec.FusedChainHash256x8 / FusedChainHash512x8 through attachFused256 /
// attachFused512 and Spec.InterlockFillBatch32x256 / x512 through
// attachInterlockBatch32x256 / x512. On the shipped registry the helpers
// are pinned entry by entry — a hook an entry's factory returns must be
// bit-exact with the sequential cascade of the entry's single arm, and
// an entry without a factory leaves the seed unhooked — and the helpers
// are exercised through custom primitives registered with pure-Go
// factories, including divergent factories the Register smoke must
// reject and declining factories (nil kernel) that leave the seed on
// the narrower paths.

// goX8Factory256 returns a FusedChainHash256x8 factory evaluating the
// cascade lane by lane in Go over the supplied single arm; corrupt flips
// one output word, decline makes the factory return a nil kernel.
func goX8Factory256(mk func(key ...[]byte) (itb.HashFunc256, itb.BatchHashFunc256, []byte, error), corrupt, decline bool) func(key []byte) (itb.BatchFusedChainHashFunc256x8, error) {
	return func(key []byte) (itb.BatchFusedChainHashFunc256x8, error) {
		single, _, _, err := mk(key)
		if err != nil {
			return nil, err
		}
		if decline {
			return nil, nil
		}
		return func(components []uint64, data *[8][]byte) ([8][4]uint64, bool) {
			var out [8][4]uint64
			for l := range data {
				out[l] = cascade256(single, components, data[l])
				if corrupt {
					out[l][1] ^= 1
				}
			}
			return out, true
		}, nil
	}
}

// goFill32Factory256 returns an InterlockFillBatch32x256 factory
// evaluating the fill cascade in Go; corrupt / decline as above.
func goFill32Factory256(mk func(key ...[]byte) (itb.HashFunc256, itb.BatchHashFunc256, []byte, error), corrupt, decline bool) func(key []byte) (itb.InterlockFillFunc32x256, error) {
	return func(key []byte) (itb.InterlockFillFunc32x256, error) {
		single, _, _, err := mk(key)
		if err != nil {
			return nil, err
		}
		if decline {
			return nil, nil
		}
		return func(components []uint64, base uint64, out *[16][4]uint64) {
			for i := range out {
				var block [13]byte
				block[0] = 0x03
				binary.LittleEndian.PutUint64(block[1:9], base+uint64(i))
				out[i] = cascade256(single, components, block[:])
				if corrupt {
					out[i][2] ^= 1
				}
			}
		}, nil
	}
}

// goX8Factory512 / goFill32Factory512 are the width-512 twins.
func goX8Factory512(mk func(key ...[]byte) (itb.HashFunc512, itb.BatchHashFunc512, []byte, error), corrupt, decline bool) func(key []byte) (itb.BatchFusedChainHashFunc512x8, error) {
	return func(key []byte) (itb.BatchFusedChainHashFunc512x8, error) {
		single, _, _, err := mk(key)
		if err != nil {
			return nil, err
		}
		if decline {
			return nil, nil
		}
		return func(components []uint64, data *[8][]byte) ([8][8]uint64, bool) {
			var out [8][8]uint64
			for l := range data {
				out[l] = cascade512(single, components, data[l])
				if corrupt {
					out[l][1] ^= 1
				}
			}
			return out, true
		}, nil
	}
}

func goFill32Factory512(mk func(key ...[]byte) (itb.HashFunc512, itb.BatchHashFunc512, []byte, error), corrupt, decline bool) func(key []byte) (itb.InterlockFillFunc32x512, error) {
	return func(key []byte) (itb.InterlockFillFunc32x512, error) {
		single, _, _, err := mk(key)
		if err != nil {
			return nil, err
		}
		if decline {
			return nil, nil
		}
		return func(components []uint64, base uint64, out *[8][8]uint64) {
			for i := range out {
				var block [13]byte
				block[0] = 0x03
				binary.LittleEndian.PutUint64(block[1:9], base+uint64(i))
				out[i] = cascade512(single, components, block[:])
				if corrupt {
					out[i][2] ^= 1
				}
			}
		}, nil
	}
}

// cascade256 / cascade512 are the sequential ChainHash cascades over a
// single arm.
func cascade256(single itb.HashFunc256, components []uint64, data []byte) [4]uint64 {
	var seed [4]uint64
	copy(seed[:], components[0:4])
	h := single(data, seed)
	for i := 4; i < len(components); i += 4 {
		for j := 0; j < 4; j++ {
			seed[j] = components[i+j] ^ h[j]
		}
		h = single(data, seed)
	}
	return h
}

func cascade512(single itb.HashFunc512, components []uint64, data []byte) [8]uint64 {
	var seed [8]uint64
	copy(seed[:], components[0:8])
	h := single(data, seed)
	for i := 8; i < len(components); i += 8 {
		for j := 0; j < 8; j++ {
			seed[j] = components[i+j] ^ h[j]
		}
		h = single(data, seed)
	}
	return h
}

// TestWide32AttachHelpersRegistry pins the attach helpers on every
// shipped entry: an entry that populates an eight-lane or batch-32
// factory yields hooks that are bit-exact with the sequential cascade of
// its single arm (an eight-lane hook may decline a shape with ok =
// false), an entry without one leaves the seed unhooked, and unknown
// names are no-ops.
func TestWide32AttachHelpersRegistry(t *testing.T) {
	comps := make([]uint64, 16)
	for i := range comps {
		comps[i] = 0x0123456789abcdef ^ uint64(i)*0x9e3779b97f4a7c15
	}
	const base = uint64(0x00FFFFFFFFFFFFF8)
	for _, spec := range Registry {
		switch spec.Width {
		case W256:
			s, err := newSeed256(spec.Name, 512)
			if err != nil {
				t.Fatal(err)
			}
			single, _, key, err := Make256Pair(spec.Name)
			if err != nil {
				t.Fatal(err)
			}
			if err := attachFused256(s, spec.Name, key); err != nil {
				t.Fatalf("attachFused256: %v", err)
			}
			if err := attachInterlockBatch32x256(s, spec.Name, key); err != nil {
				t.Fatalf("attachInterlockBatch32x256: %v", err)
			}
			if spec.FusedChainHash256x8 == nil && s.BatchFusedChain8() != nil {
				t.Fatalf("%s: attach populated an eight-lane hook without a factory", spec.Name)
			}
			if spec.InterlockFillBatch32x256 == nil && s.InterlockFillX32() != nil {
				t.Fatalf("%s: attach populated a batch-32 hook without a factory", spec.Name)
			}
			if x8 := s.BatchFusedChain8(); x8 != nil {
				for _, n := range []int{13, 20, 36, 68} {
					var lanes [8][]byte
					for l := range lanes {
						lanes[l] = make([]byte, n)
						for i := range lanes[l] {
							lanes[l][i] = byte(i*3 + l*7 + 1)
						}
					}
					out, ok := x8(comps, &lanes)
					if !ok {
						continue
					}
					for l := range lanes {
						if out[l] != cascade256(single, comps, lanes[l]) {
							t.Fatalf("%s: eight-lane hook lane %d diverges at len=%d", spec.Name, l, n)
						}
					}
				}
			}
			if fill := s.InterlockFillX32(); fill != nil {
				var out [16][4]uint64
				fill(comps, base, &out)
				for i := range out {
					var block [13]byte
					block[0] = 0x03
					binary.LittleEndian.PutUint64(block[1:9], base+uint64(i))
					if out[i] != cascade256(single, comps, block[:]) {
						t.Fatalf("%s: batch-32 hook group %d diverges", spec.Name, i)
					}
				}
			}
		case W512:
			s, err := newSeed512(spec.Name, 512)
			if err != nil {
				t.Fatal(err)
			}
			single, _, key, err := Make512Pair(spec.Name)
			if err != nil {
				t.Fatal(err)
			}
			if err := attachFused512(s, spec.Name, key); err != nil {
				t.Fatalf("attachFused512: %v", err)
			}
			if err := attachInterlockBatch32x512(s, spec.Name, key); err != nil {
				t.Fatalf("attachInterlockBatch32x512: %v", err)
			}
			if spec.FusedChainHash512x8 == nil && s.BatchFusedChain8() != nil {
				t.Fatalf("%s: attach populated an eight-lane hook without a factory", spec.Name)
			}
			if spec.InterlockFillBatch32x512 == nil && s.InterlockFillX32() != nil {
				t.Fatalf("%s: attach populated a batch-32 hook without a factory", spec.Name)
			}
			if x8 := s.BatchFusedChain8(); x8 != nil {
				for _, n := range []int{13, 20, 36, 68} {
					var lanes [8][]byte
					for l := range lanes {
						lanes[l] = make([]byte, n)
						for i := range lanes[l] {
							lanes[l][i] = byte(i*3 + l*7 + 1)
						}
					}
					out, ok := x8(comps, &lanes)
					if !ok {
						continue
					}
					for l := range lanes {
						if out[l] != cascade512(single, comps, lanes[l]) {
							t.Fatalf("%s: eight-lane hook lane %d diverges at len=%d", spec.Name, l, n)
						}
					}
				}
			}
			if fill := s.InterlockFillX32(); fill != nil {
				var out [8][8]uint64
				fill(comps, base, &out)
				for i := range out {
					var block [13]byte
					block[0] = 0x03
					binary.LittleEndian.PutUint64(block[1:9], base+uint64(i))
					if out[i] != cascade512(single, comps, block[:]) {
						t.Fatalf("%s: batch-32 hook group %d diverges", spec.Name, i)
					}
				}
			}
		}
	}
	s256, err := newSeed256(CipherAreion256, 512)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachInterlockBatch32x256(s256, "no_such_primitive_256", nil); err != nil || s256.InterlockFillX32() != nil {
		t.Fatalf("attachInterlockBatch32x256(unknown): err=%v", err)
	}
	s512, err := newSeed512(CipherAreion512, 512)
	if err != nil {
		t.Fatal(err)
	}
	if err := attachInterlockBatch32x512(s512, "no_such_primitive_512", nil); err != nil || s512.InterlockFillX32() != nil {
		t.Fatalf("attachInterlockBatch32x512(unknown): err=%v", err)
	}
}

// TestWide32AttachCustomFactories registers custom W256 / W512
// primitives carrying pure-Go eight-lane and batch-32 factories and pins
// that the attach helpers and the name-keyed constructors populate the
// hooks, that the hooked seed agrees with the same seed on the arms
// alone, that a declining factory leaves the hook nil, and that a
// divergent factory is rejected at Register time.
func TestWide32AttachCustomFactories(t *testing.T) {
	mk256 := makeCustom256PairFactory()
	mk512 := makeCustom512PairFactory()
	t.Run("256", func(t *testing.T) {
		name := customFactoryName + "w32x256"
		spec := Spec{Name: name, Width: W256, Make256Pair: mk256,
			FusedChainHash256:        goFused256Factory(mk256, false),
			FusedChainHash256x8:      goX8Factory256(mk256, false, false),
			InterlockFillBatch32x256: goFill32Factory256(mk256, false, false)}
		if err := Register(spec); err != nil {
			t.Fatalf("Register: %v", err)
		}
		s, key, err := NewSeed256(name, 1024)
		if err != nil {
			t.Fatal(err)
		}
		if s.BatchFusedChain8() == nil || s.InterlockFillX32() == nil {
			t.Fatal("NewSeed256 left a wide hook nil")
		}
		single, _, _, err := Make256Pair(name, key)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := itb.SeedFromComponents256(single, s.Components...)
		if err != nil {
			t.Fatal(err)
		}
		re, err := SeedFromComponents256(name, key, s.Components...)
		if err != nil {
			t.Fatal(err)
		}
		if re.BatchFusedChain8() == nil || re.InterlockFillX32() == nil {
			t.Fatal("SeedFromComponents256 left a wide hook nil")
		}
		for _, n := range pixelShapes {
			var lanes [8][]byte
			for l := range lanes {
				lanes[l] = make([]byte, n)
				for i := range lanes[l] {
					lanes[l][i] = byte(i*5 + l + n)
				}
			}
			out, ok := s.BatchFusedChain8()(s.Components, &lanes)
			if !ok {
				t.Fatalf("len %d: hook declined", n)
			}
			for l := range lanes {
				if out[l] != plain.ChainHash256(lanes[l]) {
					t.Fatalf("len %d lane %d: eight-lane hook diverges from ChainHash256", n, l)
				}
			}
		}
		var fill [16][4]uint64
		s.InterlockFillX32()(s.Components, 0x1234, &fill)
		for i := range fill {
			var block [13]byte
			block[0] = 0x03
			binary.LittleEndian.PutUint64(block[1:9], 0x1234+uint64(i))
			if fill[i] != plain.ChainHash256(block[:]) {
				t.Fatalf("group %d: batch-32 hook diverges from ChainHash256", i)
			}
		}
		decl := customFactoryName + "w256decl"
		spec.Name = decl
		spec.FusedChainHash256x8 = goX8Factory256(mk256, false, true)
		spec.InterlockFillBatch32x256 = goFill32Factory256(mk256, false, true)
		if err := Register(spec); err != nil {
			t.Fatalf("Register(declining): %v", err)
		}
		d, _, err := NewSeed256(decl, 512)
		if err != nil {
			t.Fatal(err)
		}
		if d.BatchFusedChain8() != nil || d.InterlockFillX32() != nil {
			t.Fatal("declining factories populated a wide hook")
		}
		only := customFactoryName + "w256only"
		if err := Register(Spec{Name: only, Width: W256, Make256Pair: mk256, FusedChainHash256x8: goX8Factory256(mk256, false, false)}); err != nil {
			t.Fatalf("Register(x8 only): %v", err)
		}
		o, okey, err := NewSeed256(only, 512)
		if err != nil {
			t.Fatal(err)
		}
		if o.BatchFusedChain8() == nil || o.FusedChain != nil || o.BatchFusedChain != nil || o.InterlockFillX32() != nil {
			t.Fatal("x8-only entry: attach did not install exactly the eight-lane hook")
		}
		osingle, _, _, err := Make256Pair(only, okey)
		if err != nil {
			t.Fatal(err)
		}
		otwin, err := itb.SeedFromComponents256(osingle, o.Components...)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range pixelShapes {
			buf := make([]byte, n)
			for i := range buf {
				buf[i] = byte(i*3 + n)
			}
			var lanes [8][]byte
			for l := range lanes {
				lanes[l] = buf
			}
			out, ok := o.BatchFusedChain8()(o.Components, &lanes)
			if !ok || out[7] != otwin.ChainHash256(buf) {
				t.Fatalf("x8-only entry: len %d hook ok=%v diverges from ChainHash256", n, ok)
			}
		}
		for _, bad := range []struct {
			suffix string
			spec   Spec
		}{
			{"x8b", Spec{Name: "", Width: W256, Make256Pair: mk256, FusedChainHash256x8: goX8Factory256(mk256, true, false)}},
			{"f32b", Spec{Name: "", Width: W256, Make256Pair: mk256, InterlockFillBatch32x256: goFill32Factory256(mk256, true, false)}},
		} {
			bad.spec.Name = customFactoryName + "w256" + bad.suffix
			err := Register(bad.spec)
			if err == nil || !strings.Contains(err.Error(), "diverges") {
				t.Fatalf("Register of a divergent %s factory: err=%v", bad.suffix, err)
			}
		}
	})
	t.Run("512", func(t *testing.T) {
		name := customFactoryName + "w32x512"
		spec := Spec{Name: name, Width: W512, Make512Pair: mk512,
			FusedChainHash512:        goFused512Factory(mk512, false),
			FusedChainHash512x8:      goX8Factory512(mk512, false, false),
			InterlockFillBatch32x512: goFill32Factory512(mk512, false, false)}
		if err := Register(spec); err != nil {
			t.Fatalf("Register: %v", err)
		}
		s, key, err := NewSeed512(name, 1024)
		if err != nil {
			t.Fatal(err)
		}
		if s.BatchFusedChain8() == nil || s.InterlockFillX32() == nil {
			t.Fatal("NewSeed512 left a wide hook nil")
		}
		single, _, _, err := Make512Pair(name, key)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := itb.SeedFromComponents512(single, s.Components...)
		if err != nil {
			t.Fatal(err)
		}
		re, err := SeedFromComponents512(name, key, s.Components...)
		if err != nil {
			t.Fatal(err)
		}
		if re.BatchFusedChain8() == nil || re.InterlockFillX32() == nil {
			t.Fatal("SeedFromComponents512 left a wide hook nil")
		}
		for _, n := range pixelShapes {
			var lanes [8][]byte
			for l := range lanes {
				lanes[l] = make([]byte, n)
				for i := range lanes[l] {
					lanes[l][i] = byte(i*5 + l + n)
				}
			}
			out, ok := s.BatchFusedChain8()(s.Components, &lanes)
			if !ok {
				t.Fatalf("len %d: hook declined", n)
			}
			for l := range lanes {
				if out[l] != plain.ChainHash512(lanes[l]) {
					t.Fatalf("len %d lane %d: eight-lane hook diverges from ChainHash512", n, l)
				}
			}
		}
		var fill [8][8]uint64
		s.InterlockFillX32()(s.Components, 0x1234, &fill)
		for i := range fill {
			var block [13]byte
			block[0] = 0x03
			binary.LittleEndian.PutUint64(block[1:9], 0x1234+uint64(i))
			if fill[i] != plain.ChainHash512(block[:]) {
				t.Fatalf("group %d: batch-32 hook diverges from ChainHash512", i)
			}
		}
		decl := customFactoryName + "w512decl"
		spec.Name = decl
		spec.FusedChainHash512x8 = goX8Factory512(mk512, false, true)
		spec.InterlockFillBatch32x512 = goFill32Factory512(mk512, false, true)
		if err := Register(spec); err != nil {
			t.Fatalf("Register(declining): %v", err)
		}
		d, _, err := NewSeed512(decl, 512)
		if err != nil {
			t.Fatal(err)
		}
		if d.BatchFusedChain8() != nil || d.InterlockFillX32() != nil {
			t.Fatal("declining factories populated a wide hook")
		}
		only := customFactoryName + "w512only"
		if err := Register(Spec{Name: only, Width: W512, Make512Pair: mk512, FusedChainHash512x8: goX8Factory512(mk512, false, false)}); err != nil {
			t.Fatalf("Register(x8 only): %v", err)
		}
		o, okey, err := NewSeed512(only, 512)
		if err != nil {
			t.Fatal(err)
		}
		if o.BatchFusedChain8() == nil || o.FusedChain != nil || o.BatchFusedChain != nil || o.InterlockFillX32() != nil {
			t.Fatal("x8-only entry: attach did not install exactly the eight-lane hook")
		}
		osingle, _, _, err := Make512Pair(only, okey)
		if err != nil {
			t.Fatal(err)
		}
		otwin, err := itb.SeedFromComponents512(osingle, o.Components...)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range pixelShapes {
			buf := make([]byte, n)
			for i := range buf {
				buf[i] = byte(i*3 + n)
			}
			var lanes [8][]byte
			for l := range lanes {
				lanes[l] = buf
			}
			out, ok := o.BatchFusedChain8()(o.Components, &lanes)
			if !ok || out[7] != otwin.ChainHash512(buf) {
				t.Fatalf("x8-only entry: len %d hook ok=%v diverges from ChainHash512", n, ok)
			}
		}
		for _, bad := range []struct {
			suffix string
			spec   Spec
		}{
			{"x8b", Spec{Width: W512, Make512Pair: mk512, FusedChainHash512x8: goX8Factory512(mk512, true, false)}},
			{"f32b", Spec{Width: W512, Make512Pair: mk512, InterlockFillBatch32x512: goFill32Factory512(mk512, true, false)}},
		} {
			bad.spec.Name = customFactoryName + "w512" + bad.suffix
			err := Register(bad.spec)
			if err == nil || !strings.Contains(err.Error(), "diverges") {
				t.Fatalf("Register of a divergent %s factory: err=%v", bad.suffix, err)
			}
		}
	})
}
