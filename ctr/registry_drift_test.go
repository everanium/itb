package ctr

import (
	"testing"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/hashprf"
)

// TestDispatchCoversRegistry pins the ctr dispatch tables to the shipped
// hashes.Registry: every shipped name must construct a keystream through
// KeySize / NonceSize / New with correctly sized inputs.
func TestDispatchCoversRegistry(t *testing.T) {
	for _, name := range hashes.Names() {
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
// must resolve through internal/hashprf, native-stream names must not.
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
		default:
			t.Errorf("%q has unexpected Class %d", info.Name, info.Class)
		}
	}
}
