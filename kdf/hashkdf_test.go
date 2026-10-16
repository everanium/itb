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
		{"areion256", "532b24f778a23d35e9bd6528e683488784c6f41c8923136ed5fdeb4a98c1ec9c0865e19e28b93d7d84e5659671df4957"},
		{"areion512", "0614ee107929601089c977015fb27574db2d741f1256025e489f477b2445904756ef5ad2d33418df739c2bebcff8ae6e"},
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
	const want = "13642916eed3989a26d1ac931a226406292c21c4807b80a7fc36089b19c392c80c384ac7f5852af251814b41d76016446b0c05f508fd42f8aa961c92b85274c5"
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
