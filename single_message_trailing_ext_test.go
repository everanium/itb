package itb_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/everanium/itb/triple"
)

// TestExtTripleDecryptMessageRejectsTrailingBytes pins the receive-side
// contract of [triple.Pipeline.DecryptMessage] on the shipped Single
// Message profiles: a wire with bytes past its one chunk is rejected,
// with the wrapper layer off and on, while the exact wire still
// round-trips. The Pipeline's direct path requires the chunk the
// header announces to end exactly at the wire's end before it hands
// the wire to the Low-Level Single Message decoder, and the streaming
// fallback that receives everything else fails on the tail, so the
// behaviour does not depend on which path the Low-Level decoder's own
// exact-length rule would have caught.
func TestExtTripleDecryptMessageRejectsTrailingBytes(t *testing.T) {
	off := false
	for _, name := range []string{triple.ProfileSingleMsgTripleNoMACV1, triple.ProfileSingleMsgTripleMACV1} {
		for _, wrap := range []bool{false, true} {
			wrap := wrap
			t.Run(fmt.Sprintf("%s/wrapper=%v", name, wrap), func(t *testing.T) {
				p, _, err := triple.Init(name, triple.Opts{WithParallax: &off, WithWrapper: &wrap})
				if err != nil {
					t.Fatalf("triple.Init: %v", err)
				}
				defer p.Close()

				pt := genTestPlaintextExt(t, 2500)
				wire, err := p.EncryptMessage(pt)
				if err != nil {
					t.Fatalf("EncryptMessage: %v", err)
				}
				for _, tail := range []int{1, 7, 8, 4096} {
					long := append(bytes.Clone(wire), make([]byte, tail)...)
					if _, err := p.DecryptMessage(long); err == nil {
						t.Fatalf("DecryptMessage accepted %d trailing bytes", tail)
					}
				}
				back, err := p.DecryptMessage(wire)
				if err != nil || !bytes.Equal(back, pt) {
					t.Fatalf("exact wire: err=%v match=%v", err, bytes.Equal(back, pt))
				}
			})
		}
	}
}
