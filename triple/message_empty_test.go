package triple

import (
	"bytes"
	"errors"
	"testing"
)

// emptyPayloadToggleCases spans the four parallax × wrapper postures
// for the empty-input rejection tests below. The rejection contract
// is posture-independent: every Pipeline cipher entry point returns
// [ErrEmptyInput] on empty input before any wire is produced or
// parsed, so no zero-payload wire exists to distinguish across
// profiles or toggle postures.
var emptyPayloadToggleCases = []struct {
	name     string
	parallax bool
	wrapper  bool
}{
	{"parallaxOn_wrapperOn", true, true},
	{"parallaxOff_wrapperOn", false, true},
	{"parallaxOn_wrapperOff", true, false},
	{"parallaxOff_wrapperOff", false, false},
}

// runEmptyMessageRejection Init/Opens the profile at the given
// toggles and asserts both message-shape entry points reject empty
// input with [ErrEmptyInput] — encrypt side on an empty plaintext,
// decrypt side on an empty wire.
func runEmptyMessageRejection(t *testing.T, profile string, parallax, wrapper bool) {
	t.Helper()
	opts := Opts{
		WithParallax: boolPtrHelper(parallax),
		WithWrapper:  boolPtrHelper(wrapper),
	}
	pipe, blob, err := Init(profile, opts)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer pipe.Close()
	rx, err := Load(blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rx.Close()

	if _, err := pipe.EncryptMessage(nil); !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("EncryptMessage(nil): got err=%v, want %v", err, ErrEmptyInput)
	}
	if _, err := pipe.EncryptMessage([]byte{}); !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("EncryptMessage(empty): got err=%v, want %v", err, ErrEmptyInput)
	}
	if _, err := rx.DecryptMessage(nil); !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("DecryptMessage(nil): got err=%v, want %v", err, ErrEmptyInput)
	}
	if _, err := rx.DecryptMessage([]byte{}); !errors.Is(err, ErrEmptyInput) {
		t.Fatalf("DecryptMessage(empty): got err=%v, want %v", err, ErrEmptyInput)
	}
}

// TestEncryptMessageEmptyPayloadNoMAC pins the empty-input rejection
// contract on the Single Message No MAC profile across every toggle
// posture.
func TestEncryptMessageEmptyPayloadNoMAC(t *testing.T) {
	for _, tc := range emptyPayloadToggleCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runEmptyMessageRejection(t, ProfileSingleMsgTripleNoMACV1,
				tc.parallax, tc.wrapper)
		})
	}
}

// TestEncryptMessageEmptyPayloadMAC is the MAC-arm counterpart of
// [TestEncryptMessageEmptyPayloadNoMAC] — same rejection contract on
// the Single Message MAC profile.
func TestEncryptMessageEmptyPayloadMAC(t *testing.T) {
	for _, tc := range emptyPayloadToggleCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runEmptyMessageRejection(t, ProfileSingleMsgTripleMACV1,
				tc.parallax, tc.wrapper)
		})
	}
}

// TestEncryptStreamEmptyPayloadNoMAC pins the same empty-input
// rejection contract on the Streaming Non-AEAD surfaces: the
// IO-Driven [Pipeline.EncryptStream] / [Pipeline.DecryptStream] pair
// and the whole-buffer [Pipeline.EncryptStreamBytes] /
// [Pipeline.DecryptStreamBytes] pair all return [ErrEmptyInput] for
// empty input under every toggle posture, with no wire byte written.
func TestEncryptStreamEmptyPayloadNoMAC(t *testing.T) {
	for _, tc := range emptyPayloadToggleCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			opts := Opts{
				WithParallax: boolPtrHelper(tc.parallax),
				WithWrapper:  boolPtrHelper(tc.wrapper),
			}
			pipe, blob, err := Init(ProfileStreamingNoAEADTripleV1, opts)
			if err != nil {
				t.Fatalf("Init: %v", err)
			}
			defer pipe.Close()
			rx, err := Load(blob)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer rx.Close()

			// IO-Driven direction: rejection surfaces before any wire
			// byte reaches the destination.
			var wire bytes.Buffer
			if err := pipe.EncryptStream(bytes.NewReader(nil), &wire); !errors.Is(err, ErrEmptyInput) {
				t.Fatalf("EncryptStream(empty): got err=%v, want %v", err, ErrEmptyInput)
			}
			if wire.Len() != 0 {
				t.Fatalf("EncryptStream(empty) wrote %d wire bytes; want 0", wire.Len())
			}
			var plain bytes.Buffer
			if err := rx.DecryptStream(bytes.NewReader(nil), &plain); !errors.Is(err, ErrEmptyInput) {
				t.Fatalf("DecryptStream(empty): got err=%v, want %v", err, ErrEmptyInput)
			}
			if plain.Len() != 0 {
				t.Fatalf("DecryptStream(empty) wrote %d plaintext bytes; want 0", plain.Len())
			}

			// Whole-buffer direction.
			if _, err := pipe.EncryptStreamBytes(nil); !errors.Is(err, ErrEmptyInput) {
				t.Fatalf("EncryptStreamBytes(nil): got err=%v, want %v", err, ErrEmptyInput)
			}
			if _, err := rx.DecryptStreamBytes(nil); !errors.Is(err, ErrEmptyInput) {
				t.Fatalf("DecryptStreamBytes(nil): got err=%v, want %v", err, ErrEmptyInput)
			}
		})
	}
}

// TestEncryptMessageSmallPayloadBoundaryMatrix walks small payload
// sizes around chunk-header and block boundaries across both Single
// Message profiles and every parallax × wrapper posture. The size=0
// row asserts the [ErrEmptyInput] rejection; every non-zero size
// asserts a byte-exact round-trip with a non-empty wire.
func TestEncryptMessageSmallPayloadBoundaryMatrix(t *testing.T) {
	sizes := []int{0, 1, 4, 15, 16, 4095, 4096}
	profiles := []struct {
		name    string
		profile string
	}{
		{"MAC", ProfileSingleMsgTripleMACV1},
		{"NoMAC", ProfileSingleMsgTripleNoMACV1},
	}
	for _, pr := range profiles {
		for _, tc := range emptyPayloadToggleCases {
			pr, tc := pr, tc
			t.Run(pr.name+"/"+tc.name, func(t *testing.T) {
				opts := Opts{
					WithParallax: boolPtrHelper(tc.parallax),
					WithWrapper:  boolPtrHelper(tc.wrapper),
				}
				pipe, blob, err := Init(pr.profile, opts)
				if err != nil {
					t.Fatalf("Init: %v", err)
				}
				defer pipe.Close()
				rx, err := Load(blob)
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				defer rx.Close()

				for _, sz := range sizes {
					plaintext := freshBytes(t, sz)
					wire, err := pipe.EncryptMessage(plaintext)
					if sz == 0 {
						if !errors.Is(err, ErrEmptyInput) {
							t.Fatalf("sz=0: EncryptMessage: got err=%v, want %v",
								err, ErrEmptyInput)
						}
						continue
					}
					if err != nil {
						t.Fatalf("sz=%d: EncryptMessage: %v", sz, err)
					}
					if len(wire) == 0 {
						t.Fatalf("sz=%d: empty wire; want an envelope", sz)
					}
					recovered, err := rx.DecryptMessage(wire)
					if err != nil {
						t.Fatalf("sz=%d: DecryptMessage: %v", sz, err)
					}
					if !bytes.Equal(recovered, plaintext) {
						t.Fatalf("sz=%d: round-trip mismatch (%d bytes back)", sz, len(recovered))
					}
				}
			})
		}
	}
}
