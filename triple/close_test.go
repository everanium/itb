package triple

import (
	"bytes"
	"errors"
	"testing"

	"github.com/everanium/itb"
)

// TestPipelineCloseZeroisesState verifies Close wipes every piece of
// secret material the Pipeline carries: seed Components across all
// eight slots, per-slot PRF keys, wrapper key, and MAC key. The
// zero-check is done directly against the underlying byte buffers so
// a partial wipe surfaces as a specific slot's diagnostic.
func TestPipelineCloseZeroisesState(t *testing.T) {
	pipe, _, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Capture references to the underlying slices BEFORE Close, so
	// the post-Close in-place wipe is observed through the aliased
	// buffers rather than the Pipeline's own (post-Close) nils.
	seedComps := make([][]uint64, 8)
	for i, s := range pipe.seeds {
		seedComps[i] = seedComponentsHandle(s, pipe.width)
	}
	prfKeyAliases := [8][]byte{}
	for i, k := range pipe.prfKeys {
		prfKeyAliases[i] = k
	}
	wrapperKeyAlias := pipe.wrapperKey
	macKeyAlias := pipe.macKey

	if err := pipe.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Seed Components must be all zero.
	for i, comps := range seedComps {
		if comps == nil {
			continue
		}
		for j, v := range comps {
			if v != 0 {
				t.Fatalf("seed[%d].Components[%d] = %d, want 0", i, j, v)
			}
		}
	}
	// PRF keys must be all zero (nil for siphash24 profiles).
	for i, k := range prfKeyAliases {
		if k == nil {
			continue
		}
		if !allZero(k) {
			t.Fatalf("prfKey[%d] not zeroed: %x", i, k)
		}
	}
	// Wrapper key must be zeroed.
	if wrapperKeyAlias != nil && !allZero(wrapperKeyAlias) {
		t.Fatalf("wrapperKey not zeroed: %x", wrapperKeyAlias)
	}
	// MAC key must be zeroed.
	if macKeyAlias != nil && !allZero(macKeyAlias) {
		t.Fatalf("macKey not zeroed: %x", macKeyAlias)
	}
}

// TestPipelineClosedRejectsSubsequentCalls verifies every cipher-path
// stub + Rekey returns ErrClosed after Close.
func TestPipelineClosedRejectsSubsequentCalls(t *testing.T) {
	pipe, _, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := pipe.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Idempotent: a second Close returns nil.
	if err := pipe.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// EncryptStream must return ErrClosed rather than
	// ErrNotYetImplemented — the isClosed guard runs first.
	if err := pipe.EncryptStream(bytes.NewReader(nil), &bytes.Buffer{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("EncryptStream: got err=%v, want %v", err, ErrClosed)
	}
	if err := pipe.DecryptStream(bytes.NewReader(nil), &bytes.Buffer{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("DecryptStream: got err=%v, want %v", err, ErrClosed)
	}
	if _, err := pipe.EncryptMessage(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("EncryptMessage: got err=%v, want %v", err, ErrClosed)
	}
	if _, err := pipe.DecryptMessage(nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("DecryptMessage: got err=%v, want %v", err, ErrClosed)
	}
	if _, err := pipe.Rekey(freshBytes(t, 32), freshBytes(t, 32)); !errors.Is(err, ErrClosed) {
		t.Fatalf("Rekey: got err=%v, want %v", err, ErrClosed)
	}
}

// seedComponentsHandle mirrors seedComponentsFor from init_open_test.go
// but returns the slice directly rather than a copy so the caller can
// observe post-Close in-place mutation through the aliased buffer.
func seedComponentsHandle(handle any, width int) []uint64 {
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

// allZero reports whether every byte of b is zero.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
