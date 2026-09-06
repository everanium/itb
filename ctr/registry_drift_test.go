package ctr

import (
	"testing"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/hashprf"
)

// TestDispatchCoversRegistry pins the ctr dispatch tables to the outer-
// cipher-eligible shipped hashes.Registry entries (hashes.KeystreamNames):
// every such name must construct a keystream through KeySize / NonceSize /
// New with correctly sized inputs. Inner-PRF-only entries (hashes.
// ClassNone) are intentionally out of scope — they MUST NOT surface as
// user-selectable outer ciphers and are expected to fail the ctr / kdf
// dispatch with an unknown-cipher error; that rejection is enforced by
// TestInnerPRFOnlyRejectedByDispatch below.
func TestDispatchCoversRegistry(t *testing.T) {
	for _, name := range hashes.KeystreamNames() {
		ksize, err := KeySize(name)
		if err != nil {
			t.Errorf("KeySize(%q): %v", name, err)
			continue
		}
		nsize, err := NonceSize(name)
		if err != nil {
			t.Errorf("NonceSize(%q): %v", name, err)
			continue
		}
		key := make([]byte, ksize)
		nonce := make([]byte, nsize)
		if _, err := New(name, key, nonce); err != nil {
			t.Errorf("New(%q): %v", name, err)
		}
		if _, err := NewResettable(name, key, nonce); err != nil {
			t.Errorf("NewResettable(%q): %v", name, err)
		}
		if _, err := streamBlockSize(name); err != nil {
			t.Errorf("streamBlockSize(%q): %v", name, err)
		}
	}
}

// TestClassMatchesDispatch binds the Class field on every shipped
// Registry entry to the code path ctr actually takes: PRF-counter names
// must resolve through internal/hashprf, native-stream names must not,
// and inner-PRF-only names (ClassNone) must be rejected by hashprf.
func TestClassMatchesDispatch(t *testing.T) {
	for _, info := range hashes.FullView() {
		_, err := hashprf.KeySize(info.Name)
		switch info.Class {
		case hashes.ClassPRFCounter:
			if err != nil {
				t.Errorf("%q is ClassPRFCounter but hashprf.KeySize failed: %v", info.Name, err)
			}
		case hashes.ClassNativeStream:
			if err == nil {
				t.Errorf("%q is ClassNativeStream but hashprf.KeySize accepted it", info.Name)
			}
		case hashes.ClassNone:
			if err == nil {
				t.Errorf("%q is ClassNone (inner-PRF-only) but hashprf.KeySize accepted it — the primitive would be reachable as a wrapper outer cipher", info.Name)
			}
		default:
			t.Errorf("%q has unexpected Class %d", info.Name, info.Class)
		}
	}
}

// TestInnerPRFOnlyRejectedByDispatch pins the ctr rejection path for
// every inner-PRF-only shipped Registry entry (hashes.ClassNone).
// KeySize / NonceSize / New must all return an unknown-cipher error so
// the primitive stays reachable through the hashes.Make{N}(Pair) inner-
// PRF factories but never surfaces as user-selectable keystream material.
func TestInnerPRFOnlyRejectedByDispatch(t *testing.T) {
	for _, info := range hashes.FullView() {
		if info.Class != hashes.ClassNone {
			continue
		}
		if _, err := KeySize(info.Name); err == nil {
			t.Errorf("KeySize(%q): inner-PRF-only primitive accepted by ctr dispatch", info.Name)
		}
		if _, err := NonceSize(info.Name); err == nil {
			t.Errorf("NonceSize(%q): inner-PRF-only primitive accepted by ctr dispatch", info.Name)
		}
		if _, err := New(info.Name, nil, nil); err == nil {
			t.Errorf("New(%q): inner-PRF-only primitive accepted by ctr dispatch", info.Name)
		}
	}
}
