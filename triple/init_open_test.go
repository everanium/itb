package triple

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"github.com/everanium/itb"
)

// allProfiles enumerates the shipped profile names in the same order
// as their registration in profile.go, giving downstream tests a
// stable iteration order.
func allProfiles() []string {
	return []string{
		ProfileStreamingAEADTripleMACV1,
		ProfileStreamingNoAEADTripleV1,
		ProfileSingleMsgTripleMACV1,
		ProfileSingleMsgTripleNoMACV1,
		ProfileBlobTripleMACV1,
	}
}

// TestPipelineInitOpenRoundTripAllProfiles constructs a Pipeline for
// every shipped profile, exports the blob, reconstructs a receiver-
// side Pipeline via Open, and verifies the reconstructed state
// matches the sender's on the load-bearing fields (profile name,
// layer toggles, MAC name / key, wrapper cipher name, seed
// Components).
func TestPipelineInitOpenRoundTripAllProfiles(t *testing.T) {
	for _, prof := range allProfiles() {
		t.Run(prof, func(t *testing.T) {
			sender, blob, err := Init(prof, Opts{})
			if err != nil {
				t.Fatalf("Init(%q): %v", prof, err)
			}
			defer sender.Close()

			receiver, err := Open(prof, blob, Opts{})
			if err != nil {
				t.Fatalf("Open(%q): %v", prof, err)
			}
			defer receiver.Close()

			if sender.profileName != receiver.profileName {
				t.Fatalf("profileName: sender %q vs receiver %q",
					sender.profileName, receiver.profileName)
			}
			if sender.resolved.parallaxOn != receiver.resolved.parallaxOn {
				t.Fatalf("parallaxOn: sender %v vs receiver %v",
					sender.resolved.parallaxOn, receiver.resolved.parallaxOn)
			}
			if sender.resolved.wrapperOn != receiver.resolved.wrapperOn {
				t.Fatalf("wrapperOn: sender %v vs receiver %v",
					sender.resolved.wrapperOn, receiver.resolved.wrapperOn)
			}
			if sender.macName != receiver.macName {
				t.Fatalf("macName: sender %q vs receiver %q",
					sender.macName, receiver.macName)
			}
			if !bytes.Equal(sender.macKey, receiver.macKey) {
				t.Fatalf("macKey: sender %x vs receiver %x",
					sender.macKey, receiver.macKey)
			}
			if sender.wrapperCipher != receiver.wrapperCipher {
				t.Fatalf("wrapperCipher: sender %q vs receiver %q",
					sender.wrapperCipher, receiver.wrapperCipher)
			}
			if !bytes.Equal(sender.wrapperKey, receiver.wrapperKey) {
				t.Fatalf("wrapperKey: sender %x vs receiver %x",
					sender.wrapperKey, receiver.wrapperKey)
			}
			// Compare the 8-seed Components byte-for-byte.
			if err := seedsEqual(sender, receiver); err != nil {
				t.Fatalf("seeds mismatch: %v", err)
			}
		})
	}
}

// seedsEqual compares each of the 8 seed slots' Components between
// two Pipelines and returns an error describing the first mismatch.
// Helper for TestPipelineInitOpenRoundTripAllProfiles + related tests.
func seedsEqual(a, b *Pipeline) error {
	if a.width != b.width {
		return errors.New("width mismatch")
	}
	for i := 0; i < 8; i++ {
		aComps := seedComponentsFor(a.seeds[i], a.width)
		bComps := seedComponentsFor(b.seeds[i], b.width)
		if len(aComps) != len(bComps) {
			return errors.New("component-count mismatch")
		}
		for j := range aComps {
			if aComps[j] != bComps[j] {
				return errors.New("component byte mismatch")
			}
		}
	}
	return nil
}

// seedComponentsFor extracts the raw Components slice out of a typed
// seed via a width switch. Test-side accessor to avoid reflection.
func seedComponentsFor(handle any, width int) []uint64 {
	switch width {
	case 128:
		if s, ok := handle.(*itb.Seed128); ok {
			return s.Components
		}
	case 256:
		if s, ok := handle.(*itb.Seed256); ok {
			return s.Components
		}
	case 512:
		if s, ok := handle.(*itb.Seed512); ok {
			return s.Components
		}
	}
	return nil
}

// TestPipelineInitMastersOverride verifies that Init consumes
// explicit Opts.PermMaster / WrapMaster bytes instead of drawing
// fresh CSPRNG masters when both are supplied.
func TestPipelineInitMastersOverride(t *testing.T) {
	perm := freshBytes(t, 32)
	wrap := freshBytes(t, 32)

	pipe, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{
		PermMaster: perm,
		WrapMaster: wrap,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer pipe.Close()

	// Decode the wrap-layer to inspect the pm / wm slots.
	var got blobWrapV1
	if err := json.Unmarshal(blob, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if !bytes.Equal(got.PermMaster, perm) {
		t.Fatalf("blob PermMaster: got %x, want %x", got.PermMaster, perm)
	}
	if !bytes.Equal(got.WrapMaster, wrap) {
		t.Fatalf("blob WrapMaster: got %x, want %x", got.WrapMaster, wrap)
	}
}

// TestPipelineOpenMastersOverride verifies that Open accepts the
// trailing 2-master variadic override and consumes those bytes
// instead of the blob's stored masters.
func TestPipelineOpenMastersOverride(t *testing.T) {
	sender, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer sender.Close()

	// Fresh masters that DON'T match the sender's — Open should
	// consume these rather than the blob's stored pair. Since the
	// wrapper key is a deterministic function of the wrapper master,
	// the receiver's wrapperKey will differ from the sender's.
	newPerm := freshBytes(t, 32)
	newWrap := freshBytes(t, 32)

	receiver, err := Open(ProfileStreamingAEADTripleMACV1, blob, Opts{}, newPerm, newWrap)
	if err != nil {
		t.Fatalf("Open with overrides: %v", err)
	}
	defer receiver.Close()

	// The wrapper key on the receiver was derived from newWrap, not
	// from the blob's wm; so bytes.Equal against sender.wrapperKey
	// must be false.
	if bytes.Equal(receiver.wrapperKey, sender.wrapperKey) {
		t.Fatalf("receiver wrapperKey unexpectedly matches sender (override ignored)")
	}
}

// TestPipelineOpenErrMastersArity exercises the arity check on the
// trailing variadic. Anything other than 0 or 2 must be rejected.
func TestPipelineOpenErrMastersArity(t *testing.T) {
	_, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Arity 1 — the invalid case the arity rule flags.
	_, err = Open(ProfileStreamingAEADTripleMACV1, blob, Opts{}, freshBytes(t, 32))
	if !errors.Is(err, ErrMastersArity) {
		t.Fatalf("Open arity=1: got err=%v, want %v", err, ErrMastersArity)
	}
	// Arity 3 — also invalid.
	_, err = Open(ProfileStreamingAEADTripleMACV1, blob, Opts{},
		freshBytes(t, 32), freshBytes(t, 32), freshBytes(t, 32))
	if !errors.Is(err, ErrMastersArity) {
		t.Fatalf("Open arity=3: got err=%v, want %v", err, ErrMastersArity)
	}
}

// TestPipelineOpenErrMissingMasters exercises the failure path when
// the blob has no masters AND the caller supplies none. Build a
// synthetic blob without pm / wm and confirm Open surfaces
// ErrMissingMasters.
func TestPipelineOpenErrMissingMasters(t *testing.T) {
	// Init a real blob to reuse its inner-blob bytes so the decode
	// path proceeds far enough to reach the master-resolution check.
	_, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Strip the masters from the wire and re-marshal.
	var w blobWrapV1
	if err := json.Unmarshal(blob, &w); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	w.PermMaster = nil
	w.WrapMaster = nil
	stripped, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	_, err = Open(ProfileStreamingAEADTripleMACV1, stripped, Opts{})
	if !errors.Is(err, ErrMissingMasters) {
		t.Fatalf("Open on master-stripped blob: got err=%v, want %v",
			err, ErrMissingMasters)
	}
}

// TestPipelineErrIdenticalMasters exercises the sanity check that
// rejects PermMaster == WrapMaster at Init.
func TestPipelineErrIdenticalMasters(t *testing.T) {
	shared := freshBytes(t, 32)
	_, _, err := Init(ProfileStreamingAEADTripleMACV1, Opts{
		PermMaster: shared,
		WrapMaster: shared,
	})
	if !errors.Is(err, ErrIdenticalMasters) {
		t.Fatalf("Init with identical masters: got err=%v, want %v",
			err, ErrIdenticalMasters)
	}
}

// TestPipelineInitUnknownProfile verifies the ErrUnknownProfile
// surface fires for a bogus profile name.
func TestPipelineInitUnknownProfile(t *testing.T) {
	_, _, err := Init("no-such-profile-xyz", Opts{})
	if !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("Init(unknown): got err=%v, want %v", err, ErrUnknownProfile)
	}
}

// TestPipelineOpenErrBlobMismatch verifies Open rejects a blob whose
// wrap-layer profile field disagrees with the profile argument.
func TestPipelineOpenErrBlobMismatch(t *testing.T) {
	_, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	_, err = Open(ProfileStreamingNoAEADTripleV1, blob, Opts{})
	if !errors.Is(err, ErrBlobMismatch) {
		t.Fatalf("Open with mismatched profile: got err=%v, want %v",
			err, ErrBlobMismatch)
	}
}

// freshBytes draws n bytes of CSPRNG-random data via crypto/rand.
// Test helper used across the package's test files.
func freshBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return b
}
