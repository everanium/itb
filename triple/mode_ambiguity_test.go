package triple

import (
	"bytes"
	"fmt"
	"testing"
)

// TestStreamModeAmbiguityParityAEADvsNoMAC ratifies the D18
// mode-ambiguity envelope invariants (`.ITB-48.md` §11 item 16
// items 1/2/3) at the Pipeline layer. Encrypts a matched plaintext
// through both the Streaming AEAD and Streaming Non-AEAD (No MAC)
// Triple profiles and asserts full-stream byte-length identity
// between the two wires.
//
// Container-size determinism. For plaintexts small enough that the
// per-Third pixel budget reaches the MinPixels floor (unified with
// MinPixelsAuth as of the CCA-resistant floor sweep — see
// `.ITB-48.md` §11 item 16 item 4), the itb container width/height
// is a function only of the profile-resolved keyBits (via MinPixels)
// and the barrier fill (from [itb.Config.BarrierFill]) — NOT of the
// specific seed bytes, nonce bytes, or cobs-encoded byte distribution
// on the wire. This lets the test compare two independent Pipelines
// with independently-generated seeds / masters and still observe
// identical wire byte-lengths at the floor.
//
// The Streaming AEAD path prepends a 32-byte streamID; the No-MAC
// path prepends a 32-byte dummy prefix (per `.ITB-48.md` §11 item 16
// item 2). Both prefixes are the same length so full-stream lengths
// remain comparable.
//
// The test picks plaintext sizes that stay under the MinPixels
// container floor at the shipped keyBits so per-Third pixel counts
// clamp to MinPixels on every third. Above that floor the cobsLens
// distribution begins to influence container width; that regime is
// out of scope for this specific parity property (which is what the
// D18 items 1/2/3 actually claim).
func TestStreamModeAmbiguityParityAEADvsNoMAC(t *testing.T) {
	// Small sizes so the per-Third pixel count clamps to MinPixels on
	// every third — the container size is then a function only of
	// keyBits / barrierFill / streamID-prefix length.
	sizes := []int{1, 6, 64, 512, 1024}

	for _, sz := range sizes {
		sz := sz
		t.Run(fmt.Sprintf("plaintext=%d", sz), func(t *testing.T) {
			// Two Pipelines sharing profile-shape but differing on
			// MAC-presence. Parallax + wrapper toggles both off so the
			// itb container byte-length is the sole contributor to
			// wire length; the additional per-Pipeline randomness
			// (parallax master, wrapper key) does not enter the size
			// equation.
			commonOpts := Opts{
				WithParallax: boolPtrHelper(false),
				WithWrapper:  boolPtrHelper(false),
			}
			aead, _, err := Init(ProfileStreamingAEADTripleMACV1, commonOpts)
			if err != nil {
				t.Fatalf("Init AEAD: %v", err)
			}
			defer aead.Close()
			nomac, _, err := Init(ProfileStreamingNoAEADTripleV1, commonOpts)
			if err != nil {
				t.Fatalf("Init No-MAC: %v", err)
			}
			defer nomac.Close()

			plaintext := freshBytes(t, sz)

			var aeadWire, plainWire bytes.Buffer
			if err := aead.EncryptStream(bytes.NewReader(plaintext), &aeadWire); err != nil {
				t.Fatalf("AEAD EncryptStream: %v", err)
			}
			if err := nomac.EncryptStream(bytes.NewReader(plaintext), &plainWire); err != nil {
				t.Fatalf("No-MAC EncryptStream: %v", err)
			}

			// Full-stream length parity. Ratifies D18 item 1
			// ("streamID and dummy prefixes are the same length") +
			// item 2 ("chunk containers pack tags and tag-stubs into
			// symmetric positions") through the Pipeline layer.
			if aeadWire.Len() != plainWire.Len() {
				t.Fatalf("wire byte-length mismatch at plaintext=%d: aead=%d nomac=%d (diff=%d)",
					sz, aeadWire.Len(), plainWire.Len(), aeadWire.Len()-plainWire.Len())
			}
		})
	}
}
