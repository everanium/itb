package itb

import (
	"strings"
	"testing"
)

// TestNilSeedRejected checks that every exported entry guarded by the
// eight-seed check returns an error, not a panic, when any one of the
// eight seeds is nil — at every width and in every slot.
func TestNilSeedRejected(t *testing.T) {
	data := []byte("nil seed probe")
	mac := func(b []byte) []byte { return make([]byte, 32) }
	wantNil := func(t *testing.T, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), "seed is nil") {
			t.Fatalf("err = %v, want a nil-seed error", err)
		}
	}
	for slot := 0; slot < 8; slot++ {
		a0, a1, a2, a3, a4, a5, a6, a7 := seedFixtures128(t, 1024)
		s128 := []*Seed128{a0, a1, a2, a3, a4, a5, a6, a7}
		b0, b1, b2, b3, b4, b5, b6, b7 := seedFixtures256(t, 1024)
		s256 := []*Seed256{b0, b1, b2, b3, b4, b5, b6, b7}
		c0, c1, c2, c3, c4, c5, c6, c7 := seedFixtures512(t, 1024)
		s512 := []*Seed512{c0, c1, c2, c3, c4, c5, c6, c7}
		s128[slot], s256[slot], s512[slot] = nil, nil, nil
		_, err := Encrypt3x128Cfg(nil, s128[0], s128[1], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7], data)
		wantNil(t, err)
		_, err = Decrypt3x128Cfg(nil, s128[0], s128[1], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7], make([]byte, 256))
		wantNil(t, err)
		_, err = EncryptAuthenticated3x128Cfg(nil, s128[0], s128[1], s128[2], s128[3], s128[4], s128[5], s128[6], s128[7], data, mac)
		wantNil(t, err)
		_, err = Encrypt3x256Cfg(nil, s256[0], s256[1], s256[2], s256[3], s256[4], s256[5], s256[6], s256[7], data)
		wantNil(t, err)
		_, err = DecryptAuthenticated3x256Cfg(nil, s256[0], s256[1], s256[2], s256[3], s256[4], s256[5], s256[6], s256[7], make([]byte, 256), mac)
		wantNil(t, err)
		_, err = Encrypt3x512Cfg(nil, s512[0], s512[1], s512[2], s512[3], s512[4], s512[5], s512[6], s512[7], data)
		wantNil(t, err)
		_, err = Decrypt3x512Cfg(nil, s512[0], s512[1], s512[2], s512[3], s512[4], s512[5], s512[6], s512[7], make([]byte, 256))
		wantNil(t, err)
	}
}
