package triple

import (
	"testing"
)

// boolPtr returns a *bool with the value b — helper for testing the
// three-state Opts.WithParallax / WithWrapper fields.
func boolPtr(b bool) *bool { return &b }

// TestOpenReconstructsToggleFromBlob verifies that a Pipeline built
// with WithParallax=false round-trips through Init → Load
// reconstructing the parallax-off posture from the blob's record
// rather than the profile default.
func TestOpenReconstructsToggleFromBlob(t *testing.T) {
	off := false
	sender, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{
		WithParallax: &off,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer sender.Close()

	if sender.resolved.Parallax {
		t.Fatalf("sender Parallax true, want false")
	}
	if sender.parallaxSched != nil || sender.parallaxCS != nil {
		t.Fatalf("sender carries parallax handles when parallax off")
	}

	receiver, err := Load(blob)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer receiver.Close()

	if receiver.resolved.Parallax {
		t.Fatalf("receiver Parallax true, want false (record parallax=false ignored)")
	}
	if receiver.parallaxSched != nil || receiver.parallaxCS != nil {
		t.Fatalf("receiver carries parallax handles after blob-recovered off")
	}
}

// TestLoadReproducesInitToggles verifies that the layer set resolved
// at Init — the profile default with the Opts toggles folded in — is
// what Load reproduces, with no receiver-side override: a sender that
// disables both layers yields a receiver with both layers off, and a
// sender that keeps the profile default yields both on.
func TestLoadReproducesInitToggles(t *testing.T) {
	cases := []struct {
		label    string
		opts     Opts
		parallax bool
		wrapper  bool
	}{
		{"both_off", Opts{WithParallax: boolPtr(false), WithWrapper: boolPtr(false)}, false, false},
		{"profile_default", Opts{}, true, true},
		{"explicit_on", Opts{WithParallax: boolPtr(true), WithWrapper: boolPtr(true)}, true, true},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			sender, blob, err := Init(ProfileStreamingAEADTripleMACV1, c.opts)
			if err != nil {
				t.Fatalf("Init: %v", err)
			}
			defer sender.Close()
			if sender.resolved.Parallax != c.parallax || sender.resolved.Wrapper != c.wrapper {
				t.Fatalf("sender toggles = (%v, %v), want (%v, %v)",
					sender.resolved.Parallax, sender.resolved.Wrapper, c.parallax, c.wrapper)
			}
			receiver, err := Load(blob)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			defer receiver.Close()
			if receiver.resolved.Parallax != c.parallax || receiver.resolved.Wrapper != c.wrapper {
				t.Fatalf("receiver toggles = (%v, %v), want (%v, %v)",
					receiver.resolved.Parallax, receiver.resolved.Wrapper, c.parallax, c.wrapper)
			}
			if (receiver.parallaxSched != nil) != c.parallax {
				t.Fatalf("receiver parallax handles present=%v, want %v", receiver.parallaxSched != nil, c.parallax)
			}
			if (receiver.wrapperKey != nil) != c.wrapper {
				t.Fatalf("receiver wrapperKey present=%v, want %v", receiver.wrapperKey != nil, c.wrapper)
			}
		})
	}
}

// TestOpenReconstructsWrapperToggleFromBlob mirrors
// TestOpenReconstructsToggleFromBlob for the wrapper layer. Sender
// disables the wrapper; receiver-side Load must recover wrapper-off
// from the blob's record.
func TestOpenReconstructsWrapperToggleFromBlob(t *testing.T) {
	off := false
	sender, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{
		WithWrapper: &off,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer sender.Close()

	if sender.resolved.Wrapper {
		t.Fatalf("sender Wrapper true, want false")
	}
	if sender.wrapperKey != nil {
		t.Fatalf("sender carries wrapperKey when wrapper off")
	}

	receiver, err := Load(blob)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer receiver.Close()

	if receiver.resolved.Wrapper {
		t.Fatalf("receiver Wrapper true, want false")
	}
	if receiver.wrapperKey != nil {
		t.Fatalf("receiver carries wrapperKey after blob-recovered off")
	}
}
