package itb_test

import (
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/aesitb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/triple"
)

// Fused-cascade parity: a Seed128 with the fused hooks attached must
// return exactly what the same seed returns through the sequential
// per-round loop, on every per-pixel shape and every shipped KeyBits
// (8 / 16 / 32 components), and both must agree with the cascade
// composed from the leaf reference package's HashGeneric.

var fusedShapes = []int{13, 20, 36, 68}
var fusedKeyBits = []int{512, 1024, 2048}

func newAESITBSeedPair(t *testing.T, bits int) (fused, seq *itb.Seed128) {
	t.Helper()
	single, batched, key, err := hashes.Make128Pair(hashes.CipherAESITB128, aesitbParityKey[:])
	if err != nil {
		t.Fatal(err)
	}
	fused, err = itb.NewSeed128(bits, single)
	if err != nil {
		t.Fatal(err)
	}
	fused.BatchHash = batched
	if err := hashes.AttachFused128(fused, hashes.CipherAESITB128, key); err != nil {
		t.Fatal(err)
	}
	if fused.FusedChain == nil || fused.BatchFusedChain == nil {
		t.Fatal("AttachFused128 left the fused hooks nil")
	}
	seq = &itb.Seed128{Components: append([]uint64(nil), fused.Components...), Hash: single, BatchHash: batched}
	return fused, seq
}

func referenceCascade(comps []uint64, data []byte) (uint64, uint64) {
	out := aesitb.HashGeneric(aesitbParityKey, data, comps[0], comps[1])
	lo, hi := binary.LittleEndian.Uint64(out[:8]), binary.LittleEndian.Uint64(out[8:])
	for i := 2; i < len(comps); i += 2 {
		out = aesitb.HashGeneric(aesitbParityKey, data, comps[i]^lo, comps[i+1]^hi)
		lo, hi = binary.LittleEndian.Uint64(out[:8]), binary.LittleEndian.Uint64(out[8:])
	}
	return lo, hi
}

func TestAESITBFusedChainHashParity(t *testing.T) {
	for _, bits := range fusedKeyBits {
		fused, seq := newAESITBSeedPair(t, bits)
		for _, n := range fusedShapes {
			for iter := 0; iter < 64; iter++ {
				data := make([]byte, n)
				rand.Read(data)
				fLo, fHi := fused.ChainHash128(data)
				sLo, sHi := seq.ChainHash128(data)
				rLo, rHi := referenceCascade(fused.Components, data)
				if fLo != sLo || fHi != sHi {
					t.Fatalf("bits=%d n=%d: fused (%x,%x) != sequential (%x,%x)", bits, n, fLo, fHi, sLo, sHi)
				}
				if fLo != rLo || fHi != rHi {
					t.Fatalf("bits=%d n=%d: fused (%x,%x) != reference cascade (%x,%x)", bits, n, fLo, fHi, rLo, rHi)
				}
			}
		}
		// Non-shape lengths must decline the fused path and still agree.
		for _, n := range []int{0, 1, 17, 33, 65} {
			data := make([]byte, n)
			rand.Read(data)
			fLo, fHi := fused.ChainHash128(data)
			sLo, sHi := seq.ChainHash128(data)
			if fLo != sLo || fHi != sHi {
				t.Fatalf("bits=%d non-shape n=%d: fused hook diverged from sequential", bits, n)
			}
		}
	}
}

func TestAESITBFusedBatchChainHashParity(t *testing.T) {
	for _, bits := range fusedKeyBits {
		fused, seq := newAESITBSeedPair(t, bits)
		for _, n := range fusedShapes {
			for iter := 0; iter < 64; iter++ {
				var lanes [4][]byte
				for l := range lanes {
					lanes[l] = make([]byte, n)
					rand.Read(lanes[l])
				}
				f := fused.BatchChainHash128(&lanes)
				s := seq.BatchChainHash128(&lanes)
				if f != s {
					t.Fatalf("bits=%d n=%d: batched fused %x != sequential %x", bits, n, f, s)
				}
				for l := 0; l < 4; l++ {
					rLo, rHi := referenceCascade(fused.Components, lanes[l])
					if f[l][0] != rLo || f[l][1] != rHi {
						t.Fatalf("bits=%d n=%d lane %d: batched fused != reference cascade", bits, n, l)
					}
				}
			}
		}
		// Mixed lane lengths decline the fused path.
		lanes := [4][]byte{make([]byte, 20), make([]byte, 20), make([]byte, 36), make([]byte, 20)}
		if fused.BatchChainHash128(&lanes) != seq.BatchChainHash128(&lanes) {
			t.Fatalf("bits=%d: mixed-length lanes diverged", bits)
		}
	}
}

// TestAESITBFusedSeqEnvToggle pins ITB_FORCE_CHAINHASH_SEQ: the factory
// returns nil evaluators when it is set, so the seed stays sequential.
func TestAESITBFusedSeqEnvToggle(t *testing.T) {
	t.Setenv("ITB_FORCE_CHAINHASH_SEQ", "1")
	s := &itb.Seed128{}
	if err := hashes.AttachFused128(s, hashes.CipherAESITB128, aesitbParityKey[:]); err != nil {
		t.Fatal(err)
	}
	if s.FusedChain != nil || s.BatchFusedChain != nil {
		t.Fatal("fused hooks populated despite ITB_FORCE_CHAINHASH_SEQ=1")
	}
	if err := hashes.AttachFused128(s, hashes.CipherAreion256, nil); err != nil || s.FusedChain != nil {
		t.Fatalf("non-fused primitive: err=%v hooks=%v", err, s.FusedChain != nil)
	}
}

// TestAESITBFusedWireRoundTrip encrypts through a pipeline built with the
// sequential loop and decrypts through one built with the fused hooks,
// and vice versa, so the wire bytes are pinned equal across the two
// paths on every AES-ITB profile.
func TestAESITBFusedWireRoundTrip(t *testing.T) {
	plain := make([]byte, 200_000)
	rand.Read(plain)
	for _, tc := range []struct {
		profile   string
		streaming bool
	}{
		{triple.ProfileSingleMsgAESITBNoMACV1, false},
		{triple.ProfileSingleMsgAESITBMACV1, false},
		{triple.ProfileStreamingAEADAESITBMACV1, true},
		{triple.ProfileStreamingNoAEADAESITBV1, true},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			t.Setenv("ITB_FORCE_CHAINHASH_SEQ", "1")
			pSeq, blob, err := triple.Init(tc.profile, triple.Opts{})
			t.Setenv("ITB_FORCE_CHAINHASH_SEQ", "")
			if err != nil {
				t.Fatalf("Init(seq): %v", err)
			}
			defer pSeq.Close()
			pFused, err := triple.Load(blob)
			if err != nil {
				t.Fatalf("Load(fused): %v", err)
			}
			defer pFused.Close()
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
				if err != nil || string(got) != string(plain) {
					t.Fatalf("decrypt: err=%v match=%v", err, string(got) == string(plain))
				}
			}
			run(pSeq, pFused)
			run(pFused, pSeq)
		})
	}
}
