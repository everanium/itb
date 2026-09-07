package triple_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/everanium/itb/triple"
)

// TestAESITBCascadePersistRoundTrip pins the Triple reopen path of the
// aesitb128 profiles: a Pipeline reloaded from Save output must decrypt
// the originating Pipeline's wire and vice versa, at every shipped key
// size. The reopen path re-attaches the batch-16 hook that selects the
// Interlocked Barrier cascade fill; a reload that lost it would decrypt
// to a mismatching plaintext with no error oracle on the No MAC profile.
func TestAESITBCascadePersistRoundTrip(t *testing.T) {
	plain := make([]byte, 50_000)
	rand.Read(plain)
	for _, profile := range []string{
		triple.ProfileSingleMsgAESITBNoMACV1,
		triple.ProfileSingleMsgAESITBMACV1,
		triple.ProfileStreamingAEADAESITBMACV1,
		triple.ProfileStreamingNoAEADAESITBV1,
	} {
		for _, bits := range []int{512, 1024, 2048} {
			t.Run(profile, func(t *testing.T) {
				sender, _, err := triple.Init(profile, triple.Opts{KeyBits: bits})
				if err != nil {
					t.Fatalf("Init: %v", err)
				}
				defer sender.Close()
				receiver, err := triple.Load(sender.Save())
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				defer receiver.Close()
				streaming := profile == triple.ProfileStreamingAEADAESITBMACV1 || profile == triple.ProfileStreamingNoAEADAESITBV1
				enc := func(p *triple.Pipeline, in []byte) ([]byte, error) {
					if streaming {
						return p.EncryptStreamBytes(in)
					}
					return p.EncryptMessage(in)
				}
				dec := func(p *triple.Pipeline, in []byte) ([]byte, error) {
					if streaming {
						return p.DecryptStreamBytes(in)
					}
					return p.DecryptMessage(in)
				}
				for _, dir := range []struct {
					name string
					a, b *triple.Pipeline
				}{{"sender→loaded", sender, receiver}, {"loaded→sender", receiver, sender}} {
					wire, err := enc(dir.a, plain)
					if err != nil {
						t.Fatalf("%d-bit %s encrypt: %v", bits, dir.name, err)
					}
					got, err := dec(dir.b, wire)
					if err != nil || !bytes.Equal(got, plain) {
						t.Fatalf("%d-bit %s: err=%v match=%v", bits, dir.name, err, bytes.Equal(got, plain))
					}
				}
			})
		}
	}
}
