package triple

import (
	"bytes"
	"testing"
)

// emptyPayloadToggleCases spans the four parallax × wrapper postures
// for the empty-payload wire-envelope tests below. wantEnvelope holds
// for every wrapper-on posture: the wire must carry at least the
// outer cipher nonce even when the payload is empty, so a receiver
// can distinguish an empty message from no message at all. With the
// wrapper disengaged the No MAC arm's empty-payload wire is empty by
// contract (mirrors the itb-root stream encoders' empty-input
// behaviour); only the round-trip is asserted there.
var emptyPayloadToggleCases = []struct {
	name         string
	parallax     bool
	wrapper      bool
	wantEnvelope bool
}{
	{"parallaxOn_wrapperOn", true, true, true},
	{"parallaxOff_wrapperOn", false, true, true},
	{"parallaxOn_wrapperOff", true, false, false},
	{"parallaxOff_wrapperOff", false, false, false},
}

// runEmptyMessageRoundTrip Init/Opens the profile at the given
// toggles, encrypts an empty payload via [Pipeline.EncryptMessage],
// asserts the wire-envelope expectation, and asserts the wire
// decrypts back to an empty plaintext via [Pipeline.DecryptMessage].
func runEmptyMessageRoundTrip(t *testing.T, profile string, parallax, wrapper, wantEnvelope bool) {
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
	rx, err := Open(profile, blob, opts)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer rx.Close()

	wire, err := pipe.EncryptMessage(nil)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if wantEnvelope && len(wire) == 0 {
		t.Fatalf("empty payload produced an empty wire; want the outer cipher envelope")
	}
	recovered, err := rx.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if len(recovered) != 0 {
		t.Fatalf("recovered non-empty plaintext: len=%d", len(recovered))
	}
}

// TestEncryptMessageEmptyPayloadNoMAC pins the empty-payload wire
// contract on the Single Message No MAC profile: under every
// wrapper-on posture the wire is non-empty (at least the outer cipher
// nonce) and decrypts back to an empty plaintext.
func TestEncryptMessageEmptyPayloadNoMAC(t *testing.T) {
	for _, tc := range emptyPayloadToggleCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runEmptyMessageRoundTrip(t, ProfileSingleMsgTripleNoMACV1,
				tc.parallax, tc.wrapper, tc.wantEnvelope)
		})
	}
}

// TestEncryptMessageEmptyPayloadMAC is the MAC-arm counterpart of
// [TestEncryptMessageEmptyPayloadNoMAC]. The MAC arm always emits the
// streamID prefix plus a final-flag chunk, so the wire is non-empty
// under every posture.
func TestEncryptMessageEmptyPayloadMAC(t *testing.T) {
	for _, tc := range emptyPayloadToggleCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runEmptyMessageRoundTrip(t, ProfileSingleMsgTripleMACV1,
				tc.parallax, tc.wrapper, true)
		})
	}
}

// TestEncryptStreamEmptyPayloadNoMAC pins the same empty-payload wire
// contract on the Streaming Non-AEAD surfaces: the IO-Driven
// [Pipeline.EncryptStream] and the whole-buffer
// [Pipeline.EncryptStreamBytes] both emit the outer cipher envelope
// for an empty input under every wrapper-on posture, and the wire
// decrypts back to an empty plaintext through both receive-side
// counterparts.
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
			rx, err := Open(ProfileStreamingNoAEADTripleV1, blob, opts)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer rx.Close()

			// IO-Driven direction.
			var wire bytes.Buffer
			if err := pipe.EncryptStream(bytes.NewReader(nil), &wire); err != nil {
				t.Fatalf("EncryptStream: %v", err)
			}
			if tc.wantEnvelope && wire.Len() == 0 {
				t.Fatalf("EncryptStream: empty input produced an empty wire; want the outer cipher envelope")
			}
			var plain bytes.Buffer
			if err := rx.DecryptStream(bytes.NewReader(wire.Bytes()), &plain); err != nil {
				t.Fatalf("DecryptStream: %v", err)
			}
			if plain.Len() != 0 {
				t.Fatalf("DecryptStream recovered non-empty plaintext: len=%d", plain.Len())
			}

			// Whole-buffer direction.
			wireBytes, err := pipe.EncryptStreamBytes(nil)
			if err != nil {
				t.Fatalf("EncryptStreamBytes: %v", err)
			}
			if tc.wantEnvelope && len(wireBytes) == 0 {
				t.Fatalf("EncryptStreamBytes: empty input produced an empty wire; want the outer cipher envelope")
			}
			recovered, err := rx.DecryptStreamBytes(wireBytes)
			if err != nil {
				t.Fatalf("DecryptStreamBytes: %v", err)
			}
			if len(recovered) != 0 {
				t.Fatalf("DecryptStreamBytes recovered non-empty plaintext: len=%d", len(recovered))
			}

			// Cross-decode: the IO-Driven wire through the whole-buffer
			// receive entry and vice versa.
			crossA, err := rx.DecryptStreamBytes(wire.Bytes())
			if err != nil || len(crossA) != 0 {
				t.Fatalf("cross-decode stream→bytes: len=%d err=%v", len(crossA), err)
			}
			var crossB bytes.Buffer
			if err := rx.DecryptStream(bytes.NewReader(wireBytes), &crossB); err != nil || crossB.Len() != 0 {
				t.Fatalf("cross-decode bytes→stream: len=%d err=%v", crossB.Len(), err)
			}
		})
	}
}

// TestEncryptMessageSmallPayloadBoundaryMatrix walks small payload
// sizes around chunk-header and block boundaries across both Single
// Message profiles and every parallax × wrapper posture, asserting a
// byte-exact round-trip and — for every combination whose wire must
// carry an envelope (any non-empty payload, any MAC arm, any
// wrapper-on posture) — a non-empty wire.
func TestEncryptMessageSmallPayloadBoundaryMatrix(t *testing.T) {
	sizes := []int{0, 1, 4, 15, 16, 4095, 4096}
	profiles := []struct {
		name    string
		profile string
		mac     bool
	}{
		{"MAC", ProfileSingleMsgTripleMACV1, true},
		{"NoMAC", ProfileSingleMsgTripleNoMACV1, false},
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
				rx, err := Open(pr.profile, blob, opts)
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				defer rx.Close()

				for _, sz := range sizes {
					plaintext := freshBytes(t, sz)
					wire, err := pipe.EncryptMessage(plaintext)
					if err != nil {
						t.Fatalf("sz=%d: EncryptMessage: %v", sz, err)
					}
					wantEnvelope := sz > 0 || pr.mac || tc.wrapper
					if wantEnvelope && len(wire) == 0 {
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
