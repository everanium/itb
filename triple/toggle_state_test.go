package triple

import (
	"testing"
)

// boolPtr returns a *bool with the value b — helper for testing the
// three-state Opts.WithParallax / WithWrapper fields.
func boolPtr(b bool) *bool { return &b }

// TestOpenReconstructsToggleFromBlob verifies that a Pipeline built
// with WithParallax=false round-trips through Init → Open (with an
// empty Opts on the receiving side) reconstructing the parallax-off
// posture from the blob's recorded wp field rather than the profile
// default.
func TestOpenReconstructsToggleFromBlob(t *testing.T) {
	off := false
	sender, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{
		WithParallax: &off,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer sender.Close()

	if sender.resolved.parallaxOn {
		t.Fatalf("sender parallaxOn true, want false")
	}
	if sender.parallaxSched != nil || sender.parallaxCS != nil {
		t.Fatalf("sender carries parallax handles when parallax off")
	}

	receiver, err := Open(ProfileStreamingAEADTripleMACV1, blob, Opts{})
	if err != nil {
		t.Fatalf("Open (empty Opts): %v", err)
	}
	defer receiver.Close()

	if receiver.resolved.parallaxOn {
		t.Fatalf("receiver parallaxOn true, want false (blob wp=false ignored)")
	}
	if receiver.parallaxSched != nil || receiver.parallaxCS != nil {
		t.Fatalf("receiver carries parallax handles after blob-recovered off")
	}
}

// TestOptsOverridesBlobToggle verifies that a non-nil Opts.WithParallax
// on the receiving side overrides the blob's recorded shape.
func TestOptsOverridesBlobToggle(t *testing.T) {
	// Sender enables parallax explicitly (matches the profile
	// default; the point is the blob records wp=true).
	sender, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{
		WithParallax: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer sender.Close()

	if !sender.resolved.parallaxOn {
		t.Fatalf("sender parallaxOn false, want true")
	}

	// Receiver forces parallax OFF via Opts even though the blob
	// carries wp=true.
	receiver, err := Open(ProfileStreamingAEADTripleMACV1, blob, Opts{
		WithParallax: boolPtr(false),
	})
	if err != nil {
		t.Fatalf("Open with override off: %v", err)
	}
	defer receiver.Close()

	if receiver.resolved.parallaxOn {
		t.Fatalf("receiver parallaxOn true (Opts override off ignored)")
	}
	if receiver.parallaxSched != nil || receiver.parallaxCS != nil {
		t.Fatalf("receiver carries parallax handles after Opts-forced off")
	}
}

// TestOpenReconstructsWrapperToggleFromBlob mirrors
// TestOpenReconstructsToggleFromBlob for the wrapper layer. Sender
// disables the wrapper; receiver-side Open with empty Opts must
// recover wrapper-off from the blob's ww field.
func TestOpenReconstructsWrapperToggleFromBlob(t *testing.T) {
	off := false
	sender, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{
		WithWrapper: &off,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer sender.Close()

	if sender.resolved.wrapperOn {
		t.Fatalf("sender wrapperOn true, want false")
	}
	if sender.wrapperKey != nil {
		t.Fatalf("sender carries wrapperKey when wrapper off")
	}

	receiver, err := Open(ProfileStreamingAEADTripleMACV1, blob, Opts{})
	if err != nil {
		t.Fatalf("Open (empty Opts): %v", err)
	}
	defer receiver.Close()

	if receiver.resolved.wrapperOn {
		t.Fatalf("receiver wrapperOn true, want false")
	}
	if receiver.wrapperKey != nil {
		t.Fatalf("receiver carries wrapperKey after blob-recovered off")
	}
}
