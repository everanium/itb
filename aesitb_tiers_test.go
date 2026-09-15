package itb_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/everanium/itb/internal/aesitbasm"
	"github.com/everanium/itb/triple"
)

// tierFlags is a snapshot of the aesitbasm dispatch flags — the
// fused-cascade family.
type tierFlags struct {
	fzmm, fymm, fvex, faesni, farm bool
}

func readTierFlags() tierFlags {
	return tierFlags{
		aesitbasm.FusedHasVAESAVX512, aesitbasm.FusedHasVAESAVX2,
		aesitbasm.FusedHasAVXAESNI, aesitbasm.FusedHasAESNI, aesitbasm.FusedHasARMAES,
	}
}

func (f tierFlags) apply() {
	aesitbasm.FusedHasVAESAVX512, aesitbasm.FusedHasVAESAVX2 = f.fzmm, f.fymm
	aesitbasm.FusedHasAVXAESNI, aesitbasm.FusedHasAESNI, aesitbasm.FusedHasARMAES = f.fvex, f.faesni, f.farm
}

// withTierFlags installs f for the remainder of the test and registers a
// Cleanup that restores the flags the test started with, so every test
// that mutates the package-level dispatch flags leaves them as found
// regardless of how it exits.
func withTierFlags(t *testing.T, f tierFlags) {
	t.Helper()
	saved := readTierFlags()
	t.Cleanup(saved.apply)
	f.apply()
}

// TestAESITBCrossTierRoundTrip encrypts under one dispatch tier and
// decrypts under the other, both directions, on the AES-ITB Single
// Message and Streaming AEAD profiles. The per-pixel hash is the same
// function on every tier, so wire produced by the scalar reference must
// decrypt under the SIMD tier and vice versa.
func TestAESITBCrossTierRoundTrip(t *testing.T) {
	auto := readTierFlags()
	if auto == (tierFlags{}) {
		t.Skip("no assembly tier on this host; scalar is the only path")
	}
	scalar := tierFlags{}

	plain := make([]byte, 300_000)
	rand.Read(plain)

	for _, tc := range []struct {
		profile   string
		streaming bool
	}{
		{triple.ProfileSingleMsgAESITBNoMACV1, false},
		{triple.ProfileSingleMsgAESITBMACV1, false},
		{triple.ProfileStreamingAEADAESITBMACV1, true},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			withTierFlags(t, auto)
			p, _, err := triple.Init(tc.profile, triple.Opts{})
			if err != nil {
				t.Fatalf("Init: %v", err)
			}
			defer p.Close()
			enc := func(in []byte) ([]byte, error) {
				if tc.streaming {
					return p.EncryptStreamBytes(in)
				}
				return p.EncryptMessage(in)
			}
			dec := func(in []byte) ([]byte, error) {
				if tc.streaming {
					return p.DecryptStreamBytes(in)
				}
				return p.DecryptMessage(in)
			}

			scalar.apply()
			wireScalar, err := enc(plain)
			if err != nil {
				t.Fatalf("scalar encrypt: %v", err)
			}
			auto.apply()
			wireAuto, err := enc(plain)
			if err != nil {
				t.Fatalf("auto-tier encrypt: %v", err)
			}

			got, err := dec(wireScalar)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("scalar wire under auto tier: err=%v match=%v", err, bytes.Equal(got, plain))
			}
			scalar.apply()
			got, err = dec(wireAuto)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("auto-tier wire under scalar: err=%v match=%v", err, bytes.Equal(got, plain))
			}
		})
	}
}

// TestAESITBRoundConstantsAgree pins the kernel package's round-constant
// table to the recorded rows the reference package re-derives from sqrt(p).
func TestAESITBRoundConstantsAgree(t *testing.T) {
	want := [8]string{
		"6a09e667bb67ae853c6ef372a54ff53a",
		"510e527f9b05688c1f83d9ab5be0cd19",
		"6a09e667f3bcc908bb67ae8584caa73b",
		"3c6ef372fe94f82ba54ff53a5f1d36f1",
		"510e527fade682d19b05688c2b3e6c1f",
		"1f83d9abfb41bd6b5be0cd19137e2179",
		"cbbb9d5dc1059ed8629a292a367cd507",
		"9159015a3070dd17152fecd8f70e5939",
	}
	for i := range want {
		if got := hexOf(aesitbasm.RC[i][:]); got != want[i] {
			t.Errorf("aesitbasm.RC[%d] = %s, want %s", i, got, want[i])
		}
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
