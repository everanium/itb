package itb

import (
	"bytes"
	"strings"
	"testing"
)

// TestDecryptStreamAuthenticatedRejectsTrailingBytes checks that the
// exported per-chunk authenticated decoder accepts exactly one chunk:
// bytes past the length its header announces are rejected before the
// MAC authenticates anything, at every width, while the exact chunk
// still decrypts.
func TestDecryptStreamAuthenticatedRejectsTrailingBytes(t *testing.T) {
	pt := generateData(1500)
	var sid [streamIDPrefixLen]byte
	copy(sid[:], bytes.Repeat([]byte{0x11}, streamIDPrefixLen))
	var macCalls int
	inner := newHMACBlake3Bench(bytes.Repeat([]byte{0x3c}, 32))
	// Only non-empty inputs are counted: the decoder probes the tag
	// size with an empty input, which authenticates nothing.
	mac := func(b []byte) []byte {
		if len(b) > 0 {
			macCalls++
		}
		return inner(b)
	}
	tails := []int{1, 7, 8, 4096}
	check := func(t *testing.T, name string, chunk []byte, dec func([]byte) ([]byte, bool, error)) {
		t.Helper()
		for _, tail := range tails {
			macCalls = 0
			_, _, err := dec(append(bytes.Clone(chunk), make([]byte, tail)...))
			if err == nil || !strings.Contains(err.Error(), "trailing bytes") {
				t.Fatalf("%s +%d bytes: err = %v, want a trailing-bytes error", name, tail, err)
			}
			if macCalls != 0 {
				t.Fatalf("%s +%d bytes: MAC authenticated %d inputs", name, tail, macCalls)
			}
		}
		back, final, err := dec(chunk)
		if err != nil || !final || !bytes.Equal(back, pt) {
			t.Fatalf("%s exact chunk: err=%v final=%v match=%v", name, err, final, bytes.Equal(back, pt))
		}
	}

	t.Run("128", func(t *testing.T) {
		ns, ls, d1, d2, d3, s1, s2, s3 := seedFixtures128(t, 1024)
		chunk, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, pt, mac, sid, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		check(t, "128", chunk, func(c []byte) ([]byte, bool, error) {
			return DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, c, mac, sid, 0)
		})
	})
	t.Run("256", func(t *testing.T) {
		ns, ls, d1, d2, d3, s1, s2, s3 := seedFixtures256(t, 1024)
		chunk, err := EncryptStreamAuthenticated3x256Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, pt, mac, sid, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		check(t, "256", chunk, func(c []byte) ([]byte, bool, error) {
			return DecryptStreamAuthenticated3x256Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, c, mac, sid, 0)
		})
	})
	t.Run("512", func(t *testing.T) {
		ns, ls, d1, d2, d3, s1, s2, s3 := seedFixtures512(t, 1024)
		chunk, err := EncryptStreamAuthenticated3x512Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, pt, mac, sid, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		check(t, "512", chunk, func(c []byte) ([]byte, bool, error) {
			return DecryptStreamAuthenticated3x512Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, c, mac, sid, 0)
		})
	})
}
