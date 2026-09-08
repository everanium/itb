package hashes

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/everanium/itb"
)

// register_cascade_test.go — user-registered primitives under the
// universal Interlocked Barrier cascade fill. A custom primitive brings
// its own arms and, optionally, its own whole-cascade factories; it
// never reaches the shipped assembly. The tests pin that the attach
// helpers are no-ops on a custom name without factories at every
// width, and that a custom width-128 primitive with a fused factory
// produces a wire its arms-only twin decrypts and vice versa — the
// cascade fill is the wire, the hooks only evaluate it.

// makeCustom128PairFactory wraps the ARX builder around a SHA-256
// one-shot at width 128 with a 32-byte fixed key.
func makeCustom128PairFactory() func(key ...[]byte) (itb.HashFunc128, itb.BatchHashFunc128, []byte, error) {
	return func(key ...[]byte) (itb.HashFunc128, itb.BatchHashFunc128, []byte, error) {
		fixedKey := make([]byte, 32)
		if len(key) > 0 {
			if len(key[0]) != 32 {
				return nil, nil, nil, fmt.Errorf("custom test factory: key must be 32 bytes, got %d", len(key[0]))
			}
			copy(fixedKey, key[0])
		} else if _, err := rand.Read(fixedKey); err != nil {
			return nil, nil, nil, err
		}
		single := BuildARXChainAbsorb128(sha256.Sum256, fixedKey)
		batched := func(data *[4][]byte, seeds [4][2]uint64) [4][2]uint64 {
			var out [4][2]uint64
			for l := range data {
				out[l][0], out[l][1] = single(data[l], seeds[l][0], seeds[l][1])
			}
			return out
		}
		return single, batched, fixedKey, nil
	}
}

// goFused128Factory returns a FusedChainHash128 factory evaluating the
// cascade in Go over the single arm the pair factory builds.
func goFused128Factory(mk func(key ...[]byte) (itb.HashFunc128, itb.BatchHashFunc128, []byte, error)) func(key []byte) (itb.FusedChainHashFunc128, itb.BatchFusedChainHashFunc128, error) {
	return func(key []byte) (itb.FusedChainHashFunc128, itb.BatchFusedChainHashFunc128, error) {
		single, _, _, err := mk(key)
		if err != nil {
			return nil, nil, err
		}
		fs := func(components []uint64, data []byte) (uint64, uint64, bool) {
			switch len(data) {
			case 13, 20, 36, 68:
			default:
				return 0, 0, false
			}
			lo, hi := single(data, components[0], components[1])
			for i := 2; i < len(components); i += 2 {
				lo, hi = single(data, components[i]^lo, components[i+1]^hi)
			}
			return lo, hi, true
		}
		fb := func(components []uint64, data *[4][]byte) ([4][2]uint64, bool) {
			var out [4][2]uint64
			for l := range data {
				var ok bool
				if out[l][0], out[l][1], ok = fs(components, data[l]); !ok {
					return out, false
				}
			}
			return out, true
		}
		return fs, fb, nil
	}
}

// goFill16Factory returns an InterlockFillBatch16 factory evaluating
// sixteen sequential cascades over the fill blocks in Go.
func goFill16Factory(mk func(key ...[]byte) (itb.HashFunc128, itb.BatchHashFunc128, []byte, error)) func(key []byte) (itb.InterlockFillFunc16, error) {
	return func(key []byte) (itb.InterlockFillFunc16, error) {
		single, _, _, err := mk(key)
		if err != nil {
			return nil, err
		}
		return func(components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
			for i := 0; i < 16; i++ {
				var buf [13]byte
				buf[0] = 0x03
				g := groupIdxBase + uint64(i)
				for j := 0; j < 8; j++ {
					buf[1+j] = byte(g >> (8 * j))
				}
				lo, hi := single(buf[:], components[0], components[1])
				for k := 2; k < len(components); k += 2 {
					lo, hi = single(buf[:], components[k]^lo, components[k+1]^hi)
				}
				out[i] = [2]uint64{lo, hi}
			}
		}, nil
	}
}

// TestRegisterCustomAttachNoOp registers factory-less custom primitives
// at every width and pins that the attach helpers leave their seeds
// without hooks and without error.
func TestRegisterCustomAttachNoOp(t *testing.T) {
	n128, n256, n512 := customFactoryName+"noop128", customFactoryName+"noop256", customFactoryName+"noop512"
	if err := Register(Spec{Name: n128, Width: W128, Make128Pair: makeCustom128PairFactory()}); err != nil {
		t.Fatal(err)
	}
	if err := Register(Spec{Name: n256, Width: W256, Make256Pair: makeCustom256PairFactory()}); err != nil {
		t.Fatal(err)
	}
	if err := Register(Spec{Name: n512, Width: W512, Make512Pair: makeCustom512PairFactory()}); err != nil {
		t.Fatal(err)
	}
	s128, err := newSeed128(n128, 512)
	if err != nil {
		t.Fatal(err)
	}
	if s128.FusedChain != nil || s128.BatchFusedChain != nil || s128.InterlockFillX16() != nil || s128.BatchFusedChain8() != nil {
		t.Fatal("custom width-128 primitive without factories carries a hook")
	}
	s256, err := newSeed256(n256, 512)
	if err != nil {
		t.Fatal(err)
	}
	if err := AttachFused256(s256, n256, nil); err != nil {
		t.Fatal(err)
	}
	if err := AttachInterlockBatch16x256(s256, n256, nil); err != nil {
		t.Fatal(err)
	}
	if s256.FusedChain != nil || s256.BatchFusedChain != nil || s256.InterlockFillX16() != nil {
		t.Fatal("custom width-256 primitive without factories carries a hook")
	}
	s512, err := newSeed512(n512, 512)
	if err != nil {
		t.Fatal(err)
	}
	if err := AttachFused512(s512, n512, nil); err != nil {
		t.Fatal(err)
	}
	if err := AttachInterlockBatch16x512(s512, n512, nil); err != nil {
		t.Fatal(err)
	}
	if s512.FusedChain != nil || s512.BatchFusedChain != nil || s512.InterlockFillX16() != nil {
		t.Fatal("custom width-512 primitive without factories carries a hook")
	}
}

// TestRegisterCustomFusedCrossConstructor registers a custom width-128
// primitive carrying pure-Go fused cascade and batch-16 fill factories,
// builds one hooked and one arms-only constellation over the same
// components and keys, and pins that each decrypts the other's wire at
// every shipped key size.
func TestRegisterCustomFusedCrossConstructor(t *testing.T) {
	mk := makeCustom128PairFactory()
	name := customFactoryName + "fxc128"
	if err := Register(Spec{Name: name, Width: W128, Make128Pair: mk, FusedChainHash128: goFused128Factory(mk), InterlockFillBatch16: goFill16Factory(mk)}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	cfg := &itb.Config{NonceBits: itb.DefaultNonceBits, BarrierFill: itb.DefaultBarrierFill}
	plain := make([]byte, 4_000)
	rand.Read(plain)
	for _, bits := range []int{512, 1024, 2048} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			var hooked, plainSeeds [8]*itb.Seed128
			for i := range hooked {
				single, batched, key, err := Make128Pair(name)
				if err != nil {
					t.Fatal(err)
				}
				h, err := itb.NewSeed128(bits, single)
				if err != nil {
					t.Fatal(err)
				}
				h.BatchHash = batched
				p, err := itb.SeedFromComponents128(single, h.Components...)
				if err != nil {
					t.Fatal(err)
				}
				p.BatchHash = batched
				if err := AttachFused128(h, name, key); err != nil {
					t.Fatal(err)
				}
				if err := AttachInterlockBatch16(h, name, key); err != nil {
					t.Fatal(err)
				}
				if h.FusedChain == nil || h.BatchFusedChain == nil || h.InterlockFillX16() == nil {
					t.Fatal("attach helpers left a custom-primitive hook nil")
				}
				hooked[i], plainSeeds[i] = h, p
			}
			enc := func(s [8]*itb.Seed128) []byte {
				w, err := itb.Encrypt3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], plain)
				if err != nil {
					t.Fatal(err)
				}
				return w
			}
			dec := func(s [8]*itb.Seed128, w []byte) []byte {
				got, err := itb.Decrypt3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], w)
				if err != nil {
					t.Fatal(err)
				}
				return got
			}
			if !bytes.Equal(dec(plainSeeds, enc(hooked)), plain) {
				t.Fatal("arms-only constellation cannot decrypt the hooked constellation's wire")
			}
			if !bytes.Equal(dec(hooked, enc(plainSeeds)), plain) {
				t.Fatal("hooked constellation cannot decrypt the arms-only constellation's wire")
			}
		})
	}
}
