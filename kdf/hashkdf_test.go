package kdf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// hashSupported lists the hash-based registry names exercised by these tests.
var hashSupported = []string{
	"areion256",
	"areion512",
	"blake2b256",
	"blake2b512",
	"blake2s",
	"blake3",
}

// TestHashDeriveRegressionVectors pins one deterministic output per
// hash-based primitive as a regression anchor. These vectors were produced
// by this implementation; any change to a construction that alters output
// is a regression and must be reviewed deliberately.
func TestHashDeriveRegressionVectors(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"areion256", "700bf355c49115f23730ee0cef09c72c8bb9ef17597471319916a22793edc2ce9f07e5de5a39c0b41534e5d0849ee4eb"},
		{"areion512", "a3c85d9503db6ee5775bf191ba96575557cd12c9b85ddca4e7bf31f4594483bbc8ab8577c4026253642a7f424ea367ea"},
		{"blake2b256", "379fa446ad8255588fe2cb1069b23d981223ef121fd786fcb144bcb4003a37f493b33691e2ef76427142ba0d3327230d"},
		{"blake2b512", "2c627dac356879a482b472f393c5612eeccde18114eeea79cb9e83e7fb731c2f6261a42181ab44896beda9b2a6905937"},
		{"blake2s", "c9f97f55a6e1e617f020be1cde08e9bbce9dd4ae8234f27135745c9ad4b261391c5238d53612a548b0496bf8e15b7796"},
		{"blake3", "560c70e521e2b1a5f7a19ba6676186d10050eb79456b84341613e663bafffc8f301f3dc9860b89b3d6c631a19e4b6af3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := Derive(c.name, master32, "schedule:0", 48)
			if err != nil {
				t.Fatal(err)
			}
			got := hex.EncodeToString(out)
			if got != c.want {
				t.Errorf("Derive(%q, schedule:0, 48) = %s, want %s", c.name, got, c.want)
			}
		})
	}
}

// TestHashStretchAreion512Regression pins the deterministic 32->64 key
// stretch path used to key the areion512 PRF. The stretch is an internal
// key schedule; pinning it guards against an accidental change to the
// expansion label or counter-mode parameters.
func TestHashStretchAreion512Regression(t *testing.T) {
	a, err := stretchAreion512Key(master32)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 64 {
		t.Fatalf("stretch length = %d, want 64", len(a))
	}
	// Determinism: re-run yields the same bytes.
	b, err := stretchAreion512Key(master32)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("areion512 key stretch is not deterministic")
	}
	const want = "6d8a0313f69f1814d955f14f84c9b40f9c5c469eb9c25abbad52ab87097d6e9a782f5fde09d721137ea9c5939dfc2d959f941c65f4b7f91996b7c5e2f861058f"
	if got := hex.EncodeToString(a); got != want {
		t.Errorf("stretchAreion512Key(master32) = %s, want %s", got, want)
	}
}

// TestHashDeterminism confirms repeated derivation with the same arguments
// produces identical output.
func TestHashDeterminism(t *testing.T) {
	for _, name := range hashSupported {
		t.Run(name, func(t *testing.T) {
			a, err := Derive(name, master32, "deterministic:1", 40)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Derive(name, master32, "deterministic:1", 40)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a, b) {
				t.Errorf("%s: repeated derivation differs", name)
			}
		})
	}
}

// TestHashTwoEndpoint confirms two independent callers holding the same
// master derive identical subkeys.
func TestHashTwoEndpoint(t *testing.T) {
	alice := append([]byte(nil), master32...)
	bob := append([]byte(nil), master32...)
	for _, name := range hashSupported {
		t.Run(name, func(t *testing.T) {
			ka, err := Derive(name, alice, "schedule:7", 32)
			if err != nil {
				t.Fatal(err)
			}
			kb, err := Derive(name, bob, "schedule:7", 32)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ka, kb) {
				t.Errorf("%s: two endpoints derived different subkeys", name)
			}
		})
	}
}

// TestHashDomainSeparationLabel confirms distinct labels yield distinct
// subkeys.
func TestHashDomainSeparationLabel(t *testing.T) {
	for _, name := range hashSupported {
		t.Run(name, func(t *testing.T) {
			a, err := Derive(name, master32, "x:1", 32)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Derive(name, master32, "x:2", 32)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(a, b) {
				t.Errorf("%s: labels x:1 and x:2 produced equal subkeys", name)
			}
		})
	}
}

// TestHashDomainSeparationPrimitive confirms the same master and label
// under different primitives yield different subkeys.
func TestHashDomainSeparationPrimitive(t *testing.T) {
	outs := make(map[string][]byte)
	for _, name := range hashSupported {
		out, err := Derive(name, master32, "schedule:0", 32)
		if err != nil {
			t.Fatal(err)
		}
		outs[name] = out
	}
	for i := 0; i < len(hashSupported); i++ {
		for j := i + 1; j < len(hashSupported); j++ {
			a, b := hashSupported[i], hashSupported[j]
			if bytes.Equal(outs[a], outs[b]) {
				t.Errorf("%s and %s produced equal subkeys for the same label", a, b)
			}
		}
	}
}

// TestHashOutputLength confirms every requested length returns exactly
// outLen bytes, including a non-block-multiple length.
func TestHashOutputLength(t *testing.T) {
	for _, name := range hashSupported {
		t.Run(name, func(t *testing.T) {
			for _, n := range []int{16, 32, 64, 100} {
				out, err := Derive(name, master32, "len:probe", n)
				if err != nil {
					t.Fatal(err)
				}
				if len(out) != n {
					t.Errorf("%s: outLen %d returned %d bytes", name, n, len(out))
				}
			}
		})
	}
}

// TestHashErrMasterTooShort confirms each hash-based primitive rejects a
// master shorter than 32 bytes and accepts an exactly-32-byte master.
func TestHashErrMasterTooShort(t *testing.T) {
	for _, name := range hashSupported {
		t.Run(name, func(t *testing.T) {
			short := make([]byte, hashKDFMasterMin-1)
			if _, err := Derive(name, short, "x", 16); err == nil {
				t.Errorf("%s: short master (%d bytes) returned nil error", name, hashKDFMasterMin-1)
			}
			exact := make([]byte, hashKDFMasterMin)
			if _, err := Derive(name, exact, "x", 16); err != nil {
				t.Errorf("%s: 32-byte master returned error: %v", name, err)
			}
		})
	}
}
