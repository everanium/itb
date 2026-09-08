package itb_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/aesitbasm"
	"github.com/everanium/itb/triple"
)

// Eight-lane fused-cascade parity: on hosts whose selected tier carries
// the eight-lane ZMM arm, every shipping aesitb128 constructor attaches
// the eight-lane hook, the hook agrees lane for lane with the four-lane
// path, and the wire produced through the eight-pixel stride decrypts
// through the four-pixel stride and vice versa.

// x8Hosted skips the test on hosts (or forced tiers) without the
// eight-lane arm; the four-lane parity tests cover those.
func x8Hosted(t *testing.T) {
	t.Helper()
	if !aesitbasm.FusedX8Active() {
		t.Skip("eight-lane ZMM fused arm not selected on this host / tier")
	}
}

// withX8Arm runs fn with the eight-lane arm set as given and restores
// the flag afterwards; seeds attached inside fn carry the hook exactly
// when armed is true.
func withX8Arm(t *testing.T, armed bool, fn func()) {
	t.Helper()
	saved := aesitbasm.FusedHasVAESAVX512X8
	aesitbasm.FusedHasVAESAVX512X8 = armed
	defer func() { aesitbasm.FusedHasVAESAVX512X8 = saved }()
	fn()
}

// newAESITBSeedX16 builds a fresh aesitb128 seed through the explicit
// Low-Level sequence every shipping constructor runs — Make128Pair
// arms, itb.NewSeed128, BatchHash and both attach helpers — under an
// optional caller-supplied fixed key, and returns the key the arms are
// bound to.
func newAESITBSeedX16(t *testing.T, bits int, key []byte) (*itb.Seed128, []byte) {
	t.Helper()
	var keyArg [][]byte
	if len(key) > 0 {
		keyArg = [][]byte{key}
	}
	single, batched, fixedKey, err := hashes.Make128Pair(hashes.CipherAESITB128, keyArg...)
	if err != nil {
		t.Fatal(err)
	}
	s, err := itb.NewSeed128(bits, single)
	if err != nil {
		t.Fatal(err)
	}
	s.BatchHash = batched
	if err := hashes.AttachFused128(s, hashes.CipherAESITB128, fixedKey); err != nil {
		t.Fatal(err)
	}
	if err := hashes.AttachInterlockBatch16(s, hashes.CipherAESITB128, fixedKey); err != nil {
		t.Fatal(err)
	}
	return s, fixedKey
}

// aesitbSeedFromComponentsX16 rebuilds an aesitb128 seed from existing
// components under its fixed key through the explicit Low-Level
// sequence, with both attach helpers applied.
func aesitbSeedFromComponentsX16(t *testing.T, key []byte, comps []uint64) *itb.Seed128 {
	t.Helper()
	single, batched, _, err := hashes.Make128Pair(hashes.CipherAESITB128, key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := itb.SeedFromComponents128(single, comps...)
	if err != nil {
		t.Fatal(err)
	}
	s.BatchHash = batched
	if err := hashes.AttachFused128(s, hashes.CipherAESITB128, key); err != nil {
		t.Fatal(err)
	}
	if err := hashes.AttachInterlockBatch16(s, hashes.CipherAESITB128, key); err != nil {
		t.Fatal(err)
	}
	return s
}

// TestAESITBFusedX8Attach pins the attach step: every shipping
// constructor path carries the eight-lane hook when the arm is
// selected, none carries it when the arm is disarmed or the sequential
// loop is forced, and non-aesitb128 primitives never carry it.
func TestAESITBFusedX8Attach(t *testing.T) {
	x8Hosted(t)
	fromHelper, key := newAESITBSeedX16(t, 1024, nil)
	if fromHelper.BatchFusedChain8() == nil {
		t.Fatal("the attach sequence left the eight-lane hook nil")
	}
	fromComponents := aesitbSeedFromComponentsX16(t, key, fromHelper.Components)
	if fromComponents.BatchFusedChain8() == nil {
		t.Fatal("the components attach sequence left the eight-lane hook nil")
	}
	bare := &itb.Seed128{}
	if err := hashes.AttachFused128(bare, hashes.CipherAESITB128, key); err != nil {
		t.Fatal(err)
	}
	if bare.BatchFusedChain8() == nil {
		t.Fatal("AttachFused128 left the eight-lane hook nil")
	}

	withX8Arm(t, false, func() {
		s := &itb.Seed128{}
		if err := hashes.AttachFused128(s, hashes.CipherAESITB128, key); err != nil {
			t.Fatal(err)
		}
		if s.BatchFusedChain == nil || s.BatchFusedChain8() != nil {
			t.Fatal("disarmed eight-lane arm: want four-lane hook only")
		}
	})
	t.Setenv("ITB_FORCE_CHAINHASH_SEQ", "1")
	seq := &itb.Seed128{}
	if err := hashes.AttachFused128(seq, hashes.CipherAESITB128, key); err != nil {
		t.Fatal(err)
	}
	if seq.BatchFusedChain != nil || seq.BatchFusedChain8() != nil {
		t.Fatal("ITB_FORCE_CHAINHASH_SEQ=1: fused hooks populated")
	}
	t.Setenv("ITB_FORCE_CHAINHASH_SEQ", "")
	other := &itb.Seed128{}
	if err := hashes.AttachFused128(other, hashes.CipherAreion256, nil); err != nil || other.BatchFusedChain8() != nil {
		t.Fatalf("non-fused primitive: err=%v hook=%v", err, other.BatchFusedChain8() != nil)
	}
}

// TestAESITBFusedX8HookParity pins the eight-lane hook to the four-lane
// batched cascade over the lane halves, on every nonce-buf shape and
// every shipped KeyBits, and checks that non-shape lengths decline.
func TestAESITBFusedX8HookParity(t *testing.T) {
	x8Hosted(t)
	for _, bits := range fusedKeyBits {
		s, _ := newAESITBSeedX16(t, bits, aesitbParityKey[:])
		hook := s.BatchFusedChain8()
		if hook == nil {
			t.Fatalf("bits=%d: eight-lane hook nil", bits)
		}
		for _, n := range []int{20, 36, 68} {
			for iter := 0; iter < 64; iter++ {
				var lanes [8][]byte
				for l := range lanes {
					lanes[l] = make([]byte, n)
					rand.Read(lanes[l])
				}
				got, ok := hook(s.Components, &lanes)
				if !ok {
					t.Fatalf("bits=%d n=%d: hook declined a nonce-buf shape", bits, n)
				}
				lo := [4][]byte{lanes[0], lanes[1], lanes[2], lanes[3]}
				hi := [4][]byte{lanes[4], lanes[5], lanes[6], lanes[7]}
				wantLo, wantHi := s.BatchChainHash128(&lo), s.BatchChainHash128(&hi)
				for l := 0; l < 4; l++ {
					if got[l] != wantLo[l] || got[4+l] != wantHi[l] {
						t.Fatalf("bits=%d n=%d iter %d: eight-lane hook diverged from the four-lane cascade", bits, n, iter)
					}
				}
				for l := 0; l < 8; l++ {
					rLo, rHi := referenceCascade(s.Components, lanes[l])
					if got[l][0] != rLo || got[l][1] != rHi {
						t.Fatalf("bits=%d n=%d lane %d: eight-lane hook != reference cascade", bits, n, l)
					}
				}
			}
		}
		for _, n := range []int{13, 17, 33, 65} {
			var lanes [8][]byte
			for l := range lanes {
				lanes[l] = make([]byte, n)
			}
			if _, ok := hook(s.Components, &lanes); ok {
				t.Fatalf("bits=%d: hook accepted non-shape length %d", bits, n)
			}
		}
		mixed := [8][]byte{make([]byte, 68), make([]byte, 68), make([]byte, 68), make([]byte, 68),
			make([]byte, 68), make([]byte, 68), make([]byte, 36), make([]byte, 68)}
		if _, ok := hook(s.Components, &mixed); ok {
			t.Fatalf("bits=%d: hook accepted mixed lane lengths", bits)
		}
	}
}

// TestAESITBFusedX8WireRoundTrip encrypts through a pipeline built with
// the eight-lane arm and decrypts through one built without it (four-lane
// fused kernels, four-pixel stride), and vice versa, on every AES-ITB
// profile and every nonce width, so the wire is pinned equal across the
// two pixel strides.
func TestAESITBFusedX8WireRoundTrip(t *testing.T) {
	x8Hosted(t)
	plain := make([]byte, 300_007)
	rand.Read(plain)
	for _, nb := range []int{128, 256, 512} {
		for _, tc := range []struct {
			profile   string
			streaming bool
		}{
			{triple.ProfileSingleMsgAESITBNoMACV1, false},
			{triple.ProfileSingleMsgAESITBMACV1, false},
			{triple.ProfileStreamingAEADAESITBMACV1, true},
			{triple.ProfileStreamingNoAEADAESITBV1, true},
		} {
			t.Run(fmt.Sprintf("%s/nb%d", tc.profile, nb), func(t *testing.T) {
				opts := triple.Opts{NonceBits: nb}
				var pX8 *triple.Pipeline
				var blob []byte
				var err error
				withX8Arm(t, true, func() { pX8, blob, err = triple.Init(tc.profile, opts) })
				if err != nil {
					t.Fatalf("Init(x8): %v", err)
				}
				defer pX8.Close()
				var pX4 *triple.Pipeline
				withX8Arm(t, false, func() { pX4, err = triple.Load(blob) })
				if err != nil {
					t.Fatalf("Load(x4): %v", err)
				}
				defer pX4.Close()
				run := func(enc, dec *triple.Pipeline) {
					var wire, got []byte
					var err error
					if tc.streaming {
						wire, err = enc.EncryptStreamBytes(plain)
					} else {
						wire, err = enc.EncryptMessage(plain)
					}
					if err != nil {
						t.Fatalf("encrypt: %v", err)
					}
					if tc.streaming {
						got, err = dec.DecryptStreamBytes(wire)
					} else {
						got, err = dec.DecryptMessage(wire)
					}
					if err != nil || !bytes.Equal(got, plain) {
						t.Fatalf("decrypt: err=%v match=%v", err, bytes.Equal(got, plain))
					}
				}
				run(pX8, pX4)
				run(pX4, pX8)
			})
		}
	}
}

// TestAESITBFusedX8LowLevelRoundTrip drives the Low-Level Encrypt3x128Cfg
// / Decrypt3x128Cfg entry points with seeds built through the Low-Level
// helper: the eight-lane hook is attached there as well, and a message
// encrypted with the hook decrypts through seeds rebuilt from the same
// components without it. Every nonce width and odd pixel counts, so the
// eight-, four- and single-pixel tails are all exercised.
func TestAESITBFusedX8LowLevelRoundTrip(t *testing.T) {
	x8Hosted(t)
	build := func(armed bool, keys [][]byte, comps [][]uint64) [8]*itb.Seed128 {
		var out [8]*itb.Seed128
		withX8Arm(t, armed, func() {
			for i := range out {
				if comps == nil {
					out[i], keys[i] = newAESITBSeedX16(t, 512, nil)
				} else {
					out[i] = aesitbSeedFromComponentsX16(t, keys[i], comps[i])
				}
				if (out[i].BatchFusedChain8() != nil) != armed {
					t.Fatalf("seed %d: eight-lane hook presence %v, want %v", i, out[i].BatchFusedChain8() != nil, armed)
				}
			}
		})
		return out
	}
	keys := make([][]byte, 8)
	x8 := build(true, keys, nil)
	comps := make([][]uint64, 8)
	for i := range comps {
		comps[i] = append([]uint64(nil), x8[i].Components...)
	}
	x4 := build(false, keys, comps)
	for _, nb := range []int{128, 256, 512} {
		cfg := &itb.Config{NonceBits: nb}
		for _, size := range []int{1, 77, 4093, 65_537} {
			plain := make([]byte, size)
			rand.Read(plain)
			wire, err := itb.Encrypt3x128Cfg(cfg, x8[0], x8[1], x8[2], x8[3], x8[4], x8[5], x8[6], x8[7], plain)
			if err != nil {
				t.Fatalf("nb=%d size=%d encrypt(x8): %v", nb, size, err)
			}
			got, err := itb.Decrypt3x128Cfg(cfg, x4[0], x4[1], x4[2], x4[3], x4[4], x4[5], x4[6], x4[7], wire)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("nb=%d size=%d decrypt(x4): err=%v match=%v", nb, size, err, bytes.Equal(got, plain))
			}
			wire, err = itb.Encrypt3x128Cfg(cfg, x4[0], x4[1], x4[2], x4[3], x4[4], x4[5], x4[6], x4[7], plain)
			if err != nil {
				t.Fatalf("nb=%d size=%d encrypt(x4): %v", nb, size, err)
			}
			got, err = itb.Decrypt3x128Cfg(cfg, x8[0], x8[1], x8[2], x8[3], x8[4], x8[5], x8[6], x8[7], wire)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("nb=%d size=%d decrypt(x8): err=%v match=%v", nb, size, err, bytes.Equal(got, plain))
			}
		}
	}
}
