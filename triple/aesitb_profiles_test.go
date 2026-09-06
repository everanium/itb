package triple

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// TestAESITBProfilesRoundTrip drives every shipped AES-ITB profile
// through Init and an encrypt / decrypt round-trip on the API shape the
// profile's mode exposes.
func TestAESITBProfilesRoundTrip(t *testing.T) {
	plain := make([]byte, 200_000)
	rand.Read(plain)
	cases := []struct {
		name      string
		streaming bool
	}{
		{ProfileSingleMsgAESITBMACV1, false},
		{ProfileSingleMsgAESITBNoMACV1, false},
		{ProfileStreamingAEADAESITBMACV1, true},
		{ProfileStreamingNoAEADAESITBV1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prof, err := Lookup(tc.name)
			if err != nil {
				t.Fatalf("Lookup(%q): %v", tc.name, err)
			}
			if prof.InnerHash != "aesitb128" || prof.Width != 128 {
				t.Fatalf("profile %q: InnerHash=%q Width=%d", tc.name, prof.InnerHash, prof.Width)
			}
			if prof.Wrapper || prof.Parallax || prof.OuterCipher != "" || len(prof.ParallaxPalette) != 0 || prof.ParallaxSegmentSize != 0 {
				t.Fatalf("profile %q: wrapper/parallax layers must be off (Wrapper=%v Parallax=%v OuterCipher=%q palette=%v seg=%d)",
					tc.name, prof.Wrapper, prof.Parallax, prof.OuterCipher, prof.ParallaxPalette, prof.ParallaxSegmentSize)
			}
			p, _, err := Init(tc.name, Opts{})
			if err != nil {
				t.Fatalf("Init: %v", err)
			}
			defer p.Close()
			var wire, got []byte
			if tc.streaming {
				wire, err = p.EncryptStreamBytes(plain)
				if err != nil {
					t.Fatalf("EncryptStreamBytes: %v", err)
				}
				got, err = p.DecryptStreamBytes(wire)
				if err != nil {
					t.Fatalf("DecryptStreamBytes: %v", err)
				}
			} else {
				wire, err = p.EncryptMessage(plain)
				if err != nil {
					t.Fatalf("EncryptMessage: %v", err)
				}
				got, err = p.DecryptMessage(wire)
				if err != nil {
					t.Fatalf("DecryptMessage: %v", err)
				}
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("round-trip mismatch (%d bytes)", len(plain))
			}
		})
	}
}

// TestAESITBProfilesListed pins the four names into Profiles().
func TestAESITBProfilesListed(t *testing.T) {
	want := map[string]bool{
		ProfileSingleMsgAESITBMACV1:     false,
		ProfileSingleMsgAESITBNoMACV1:   false,
		ProfileStreamingAEADAESITBMACV1: false,
		ProfileStreamingNoAEADAESITBV1:  false,
	}
	for _, name := range Profiles() {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("Profiles() lacks %q", name)
		}
	}
}
