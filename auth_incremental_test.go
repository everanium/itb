package itb

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// macIncForTest wraps macFuncForTest's keyed closure into the
// multi-slice arm by joining the chunks — the reference shape of the
// MACIncrementalFunc contract. Used to prove the authenticated entry
// points feed the incremental arm exactly the byte sequence the
// legacy concatenation path MACs, in the same order.
func macIncForTest(key [32]byte) MACIncrementalFunc {
	mac := macFuncForTest(key)
	return func(chunks ...[]byte) []byte {
		return mac(bytes.Join(chunks, nil))
	}
}

// TestMACIncrementalCrossPathMessage encrypts through one MAC arm and
// decrypts through the other, both directions, across all three
// widths. A tag computed by the incremental arm must verify under the
// legacy concatenation arm and vice versa — any part-ordering or
// framing divergence between the two arms fails the MAC check.
func TestMACIncrementalCrossPathMessage(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	mac := macFuncForTest(key)
	cfgInc := &Config{MACIncremental: macIncForTest(key)}
	cfgLegacy := &Config{}

	pt := genTestPlaintext(t, 65536)

	t.Run("512", func(t *testing.T) {
		n, l, d1, d2, d3, s1, s2, s3 := mkTriple512(t)
		for _, dir := range []struct {
			name     string
			enc, dec *Config
		}{
			{"inc-enc/legacy-dec", cfgInc, cfgLegacy},
			{"legacy-enc/inc-dec", cfgLegacy, cfgInc},
		} {
			t.Run(dir.name, func(t *testing.T) {
				ct, err := EncryptAuthenticated3x512Cfg(dir.enc, n, l, d1, d2, d3, s1, s2, s3, pt, mac)
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				out, err := DecryptAuthenticated3x512Cfg(dir.dec, n, l, d1, d2, d3, s1, s2, s3, ct, mac)
				if err != nil {
					t.Fatalf("decrypt: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatal("cross-arm round-trip mismatch")
				}
			})
		}
	})

	t.Run("128", func(t *testing.T) {
		n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
		ct, err := EncryptAuthenticated3x128Cfg(cfgInc, n, l, d1, d2, d3, s1, s2, s3, pt, mac)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		out, err := DecryptAuthenticated3x128Cfg(cfgLegacy, n, l, d1, d2, d3, s1, s2, s3, ct, mac)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(pt, out) {
			t.Fatal("cross-arm round-trip mismatch")
		}
	})

	t.Run("256", func(t *testing.T) {
		n, l, d1, d2, d3, s1, s2, s3 := mkTriple256(t)
		ct, err := EncryptAuthenticated3x256Cfg(cfgLegacy, n, l, d1, d2, d3, s1, s2, s3, pt, mac)
		if err != nil {
			t.Fatalf("encrypt: %v", err)
		}
		out, err := DecryptAuthenticated3x256Cfg(cfgInc, n, l, d1, d2, d3, s1, s2, s3, ct, mac)
		if err != nil {
			t.Fatalf("decrypt: %v", err)
		}
		if !bytes.Equal(pt, out) {
			t.Fatal("cross-arm round-trip mismatch")
		}
	})
}

// TestMACIncrementalCrossPathStream is the streaming-chunk
// counterpart: the MAC input carries the streamID / cumulative-offset
// / final-flag trailer, so the cross-arm check also pins the
// trailer's part ordering through the incremental arm.
func TestMACIncrementalCrossPathStream(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	mac := macFuncForTest(key)
	cfgInc := &Config{MACIncremental: macIncForTest(key)}
	cfgLegacy := &Config{}

	var streamID [32]byte
	if _, err := rand.Read(streamID[:]); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	pt := genTestPlaintext(t, 32768)
	const offset = 0x0123456789AB

	n, l, d1, d2, d3, s1, s2, s3 := mkTriple512(t)
	for _, dir := range []struct {
		name     string
		enc, dec *Config
	}{
		{"inc-enc/legacy-dec", cfgInc, cfgLegacy},
		{"legacy-enc/inc-dec", cfgLegacy, cfgInc},
	} {
		for _, finalFlag := range []bool{false, true} {
			t.Run(dir.name, func(t *testing.T) {
				ct, err := EncryptStreamAuthenticated3x512Cfg(dir.enc, n, l, d1, d2, d3, s1, s2, s3,
					pt, mac, streamID, offset, finalFlag)
				if err != nil {
					t.Fatalf("encrypt: %v", err)
				}
				out, gotFinal, err := DecryptStreamAuthenticated3x512Cfg(dir.dec, n, l, d1, d2, d3, s1, s2, s3,
					ct, mac, streamID, offset)
				if err != nil {
					t.Fatalf("decrypt: %v", err)
				}
				if gotFinal != finalFlag {
					t.Fatalf("final flag mismatch: got %v want %v", gotFinal, finalFlag)
				}
				if !bytes.Equal(pt, out) {
					t.Fatal("cross-arm stream round-trip mismatch")
				}
			})
		}
	}
}
