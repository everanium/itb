package itb_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/triple"
	"github.com/everanium/itb/wrapper"
)

// TestExtTripleDecryptMessageRejectsNonSquareHeader checks the Triple
// Single Message surface against a header rewritten to another
// factorisation of the same W·H. With the wrapper layer on, the
// rewrite is applied as an XOR delta through the outer keystream —
// the W/H values are inferable from the wire length — so the outer
// cipher does not stand in for the square-header rule.
func TestExtTripleDecryptMessageRejectsNonSquareHeader(t *testing.T) {
	off := false
	for _, name := range []string{triple.ProfileSingleMsgTripleNoMACV1, triple.ProfileSingleMsgTripleMACV1} {
		for _, wrap := range []bool{false, true} {
			wrap := wrap
			t.Run(fmt.Sprintf("%s/wrapper=%v", name, wrap), func(t *testing.T) {
				p, blob, err := triple.Init(name, triple.Opts{WithParallax: &off, WithWrapper: &wrap})
				if err != nil {
					t.Fatalf("triple.Init: %v", err)
				}
				defer p.Close()

				pt := genTestPlaintextExt(t, 2000)
				wire, err := p.EncryptMessage(pt)
				if err != nil {
					t.Fatalf("EncryptMessage: %v", err)
				}
				lead := 0
				if wrap {
					pr, err := triple.Inspect(blob)
					if err != nil {
						t.Fatalf("Inspect: %v", err)
					}
					n, err := wrapper.NonceSize(pr.OuterCipher)
					if err != nil {
						t.Fatalf("NonceSize: %v", err)
					}
					lead = n
				}
				dimsOff := lead + 32 + itb.DefaultNonceBits/8
				hdrLen := 32 + itb.DefaultNonceBits/8 + 4
				p2 := (len(wire) - lead - hdrLen) / itb.Channels
				side := 1
				for side*side < p2 {
					side++
				}
				if side*side != p2 {
					t.Fatalf("container is not square: %d pixels", p2)
				}
				tried := 0
				for w := 1; w <= p2 && w <= 0xFFFF; w++ {
					if p2%w != 0 || w == side || p2/w > 0xFFFF {
						continue
					}
					tampered := bytes.Clone(wire)
					var oldD, newD [4]byte
					binary.BigEndian.PutUint16(oldD[:], uint16(side))
					binary.BigEndian.PutUint16(oldD[2:], uint16(side))
					binary.BigEndian.PutUint16(newD[:], uint16(w))
					binary.BigEndian.PutUint16(newD[2:], uint16(p2/w))
					for i := 0; i < 4; i++ {
						tampered[dimsOff+i] ^= oldD[i] ^ newD[i]
					}
					if _, err := p.DecryptMessage(tampered); err == nil {
						t.Fatalf("DecryptMessage accepted header %dx%d (genuine %dx%d)", w, p2/w, side, side)
					}
					tried++
				}
				if tried == 0 {
					t.Fatalf("no same-product rewrite for %d pixels", p2)
				}
				back, err := p.DecryptMessage(wire)
				if err != nil || !bytes.Equal(back, pt) {
					t.Fatalf("genuine wire: err=%v match=%v", err, bytes.Equal(back, pt))
				}
			})
		}
	}
}
