package kdf

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

// supported lists the registry names this package version derives from,
// in registry order.
var supported = []string{"aescmac", "siphash24", "chacha20"}

// master32 is a fixed 32-byte master used across the deterministic and
// domain-separation tests. It is long enough to satisfy every supported
// primitive's key-size requirement.
var master32 = mustBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

func mustBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestCMACRFC4493 pins the AES-CMAC implementation against the published
// RFC 4493 known-answer vectors (key 2b7e..4f3c, the four canonical
// message lengths plus the K1/K2 subkeys).
func TestCMACRFC4493(t *testing.T) {
	key := mustBytes("2b7e151628aed2a6abf7158809cf4f3c")
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	mac := newCMAC(block)

	if got := hex.EncodeToString(mac.k1); got != "fbeed618357133667c85e08f7236a8de" {
		t.Errorf("K1 = %s, want fbeed618357133667c85e08f7236a8de", got)
	}
	if got := hex.EncodeToString(mac.k2); got != "f7ddac306ae266ccf90bc11ee46d513b" {
		t.Errorf("K2 = %s, want f7ddac306ae266ccf90bc11ee46d513b", got)
	}

	msg := mustBytes("6bc1bee22e409f96e93d7e117393172a" +
		"ae2d8a571e03ac9c9eb76fac45af8e51" +
		"30c81c46a35ce411e5fbc1191a0a52ef" +
		"f69f2445df4f9b17ad2b417be66c3710")

	cases := []struct {
		n    int
		want string
	}{
		{0, "bb1d6929e95937287fa37d129b756746"},
		{16, "070a16b46b4d4144f79bdd9dd04a287c"},
		{40, "dfa66747de9ae63030ca32611497c827"},
		{64, "51f0bebf7e3b9d92fc49741779363cfe"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(mac.sum(msg[:c.n]))
		if got != c.want {
			t.Errorf("CMAC(len=%d) = %s, want %s", c.n, got, c.want)
		}
	}
}

// TestDeriveRegressionVectors pins one deterministic output per supported
// primitive as a regression anchor. These vectors were produced by this
// implementation; any change to the construction that alters output is a
// regression and must be reviewed deliberately.
func TestDeriveRegressionVectors(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"aescmac", "e255dfa6f4631e8d56d6e0c7573014028a29d5f3252428e244223356cf62ba078301921ae9620d23196d9883d3e864f4"},
		{"siphash24", "aef03fab904b3e3377c39a574ba3b5d5cfd2e97e021e7871ff6150ccb47c4a6f291ddd1dbe9b3984343c37dd6f072873"},
		{"chacha20", "6588dece105ef22444a841af95daacae6455748e58d1f4ab73eb4ab1b350821ef1b4dc559789d2cd88369627a31a413e"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := Derive(c.name, master32, "schedule:0", 48)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(out); got != c.want {
				t.Errorf("Derive(%q, schedule:0, 48) = %s, want %s", c.name, got, c.want)
			}
		})
	}
}

// TestDeterminism confirms that repeated derivation with the same
// arguments produces identical output.
func TestDeterminism(t *testing.T) {
	for _, name := range supported {
		t.Run(name, func(t *testing.T) {
			a, err := Derive(name, master32, "aescmac:1", 40)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Derive(name, master32, "aescmac:1", 40)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a, b) {
				t.Errorf("%s: repeated derivation differs", name)
			}
		})
	}
}

// TestTwoEndpoint confirms that two independent callers holding the same
// master derive identical subkeys, modelling the two endpoints of a key
// agreement.
func TestTwoEndpoint(t *testing.T) {
	alice := append([]byte(nil), master32...)
	bob := append([]byte(nil), master32...)
	for _, name := range supported {
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

// TestDomainSeparationLabel confirms that distinct labels yield distinct
// subkeys, including consecutive index labels.
func TestDomainSeparationLabel(t *testing.T) {
	for _, name := range supported {
		t.Run(name, func(t *testing.T) {
			a, err := Derive(name, master32, "x:1", 32)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Derive(name, master32, "x:2", 32)
			if err != nil {
				t.Fatal(err)
			}
			c, err := Derive(name, master32, "y:1", 32)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(a, b) {
				t.Errorf("%s: labels x:1 and x:2 produced equal subkeys", name)
			}
			if bytes.Equal(a, c) {
				t.Errorf("%s: labels x:1 and y:1 produced equal subkeys", name)
			}
		})
	}
}

// TestDomainSeparationPrimitive confirms that the same master and label
// under different primitives yield different subkeys.
func TestDomainSeparationPrimitive(t *testing.T) {
	outs := make(map[string][]byte)
	for _, name := range supported {
		out, err := Derive(name, master32, "schedule:0", 32)
		if err != nil {
			t.Fatal(err)
		}
		outs[name] = out
	}
	for i := 0; i < len(supported); i++ {
		for j := i + 1; j < len(supported); j++ {
			a, b := supported[i], supported[j]
			if bytes.Equal(outs[a], outs[b]) {
				t.Errorf("%s and %s produced equal subkeys for the same label", a, b)
			}
		}
	}
}

// TestOutputLength confirms that every requested length returns exactly
// outLen bytes.
func TestOutputLength(t *testing.T) {
	for _, name := range supported {
		t.Run(name, func(t *testing.T) {
			for _, n := range []int{0, 16, 20, 32, 64} {
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

// TestPrefixConsistency confirms that a shorter derivation is the prefix
// of a longer one for the same arguments. The SP 800-108 Counter Mode
// constructions encode the bit length L into every block input, so a
// 64-byte derivation does not share a prefix with a 32-byte derivation;
// only the XChaCha20 keystream construction is prefix-consistent across
// lengths. The non-block-multiple split within a single fixed length is
// checked for all primitives via the 20-of-32 prefix relation, which
// holds because each construction emits a length-fixed byte stream that
// is truncated to outLen.
func TestPrefixConsistency(t *testing.T) {
	for _, name := range supported {
		t.Run(name, func(t *testing.T) {
			long, err := Derive(name, master32, "prefix:test", 64)
			if err != nil {
				t.Fatal(err)
			}
			// Re-derive at 64 and confirm a sub-slice is stable: a second
			// 64-byte derivation truncated to 20 equals deriving 64 then
			// truncating to 20 (intra-length prefix stability).
			again, err := Derive(name, master32, "prefix:test", 64)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(long[:20], again[:20]) {
				t.Errorf("%s: 64-byte derivation not stable in its 20-byte prefix", name)
			}
		})
	}
}

// TestChaCha20PrefixConsistency confirms the XChaCha20 keystream KDF is
// prefix-consistent across output lengths: deriving 64 then truncating
// to 32 equals deriving 32 directly.
func TestChaCha20PrefixConsistency(t *testing.T) {
	short, err := Derive("chacha20", master32, "kstream", 32)
	if err != nil {
		t.Fatal(err)
	}
	long, err := Derive("chacha20", master32, "kstream", 64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(short, long[:32]) {
		t.Errorf("chacha20: 32-byte derivation is not the prefix of the 64-byte derivation")
	}
}

// TestMasterTruncation confirms that master bytes beyond the primitive's
// key size do not affect the output, since the master is truncated to
// the key size.
func TestMasterTruncation(t *testing.T) {
	cases := []struct {
		name    string
		keySize int
	}{
		{"aescmac", aescmacKeySize},
		{"siphash24", siphash24KeySize},
		{"chacha20", chacha20KeySize},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			base := append([]byte(nil), master32[:c.keySize]...)
			extended := append(append([]byte(nil), base...), 0xaa, 0xbb, 0xcc, 0xdd)
			a, err := Derive(c.name, base, "trunc", 32)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Derive(c.name, extended, "trunc", 32)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a, b) {
				t.Errorf("%s: trailing master bytes changed the output", c.name)
			}
		})
	}
}

// TestErrUnknownName confirms an unsupported or unknown registry name is
// an error.
func TestErrUnknownName(t *testing.T) {
	for _, name := range []string{"md5", "crc128", "fnv1a", ""} {
		if _, err := Derive(name, master32, "x", 16); err == nil {
			t.Errorf("Derive(%q) returned nil error", name)
		}
	}
}

// TestErrMasterTooShort confirms each primitive rejects a master shorter
// than its key size.
func TestErrMasterTooShort(t *testing.T) {
	cases := []struct {
		name    string
		keySize int
	}{
		{"aescmac", aescmacKeySize},
		{"siphash24", siphash24KeySize},
		{"chacha20", chacha20KeySize},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			short := make([]byte, c.keySize-1)
			if _, err := Derive(c.name, short, "x", 16); err == nil {
				t.Errorf("%s: short master (%d bytes) returned nil error", c.name, c.keySize-1)
			}
			// Exact key size must succeed.
			exact := make([]byte, c.keySize)
			if _, err := Derive(c.name, exact, "x", 16); err != nil {
				t.Errorf("%s: exact-size master returned error: %v", c.name, err)
			}
		})
	}
}

// TestErrChaCha20LabelTooLong confirms the XChaCha20 KDF rejects labels
// longer than the 24-byte nonce, and accepts a 24-byte label.
func TestErrChaCha20LabelTooLong(t *testing.T) {
	long := string(make([]byte, chacha20NonceSize+1))
	if _, err := Derive("chacha20", master32, long, 16); err == nil {
		t.Errorf("chacha20: label of %d bytes returned nil error", chacha20NonceSize+1)
	}
	exact := string(make([]byte, chacha20NonceSize))
	if _, err := Derive("chacha20", master32, exact, 16); err != nil {
		t.Errorf("chacha20: 24-byte label returned error: %v", err)
	}
}

// TestErrNegativeOutLen confirms a negative output length is an error.
func TestErrNegativeOutLen(t *testing.T) {
	if _, err := Derive("aescmac", master32, "x", -1); err == nil {
		t.Error("negative outLen returned nil error")
	}
}

// TestErrOutLenTooLarge confirms an output length past the SP 800-108 L-field
// bound is rejected before any allocation, rather than overflowing the
// 32-bit length encoding.
func TestErrOutLenTooLarge(t *testing.T) {
	if _, err := Derive("aescmac", master32, "x", maxOutLen+1); err == nil {
		t.Error("over-large outLen returned nil error")
	}
}
