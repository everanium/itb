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

	// Capture references to the underlying slices and seed structs BEFORE
	// Close, so the post-Close in-place wipe and closure stubbing are
	// observed through the aliased handles rather than the Pipeline's
	// own (post-Close) nils.
	seedHandles := pipe.seeds
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

	// Seed Components must be all zero, and per-seed closures must be
	// scrubbed (Hash replaced with non-nil zero-returning stub;
	// BatchHash, FusedChain, BatchFusedChain nilled).
	for i, comps := range seedComps {
		if comps == nil {
			continue
		}
		for j, v := range comps {
			if v != 0 {
				t.Fatalf("seed[%d].Components[%d] = %d, want 0", i, j, v)
			}
		}
		s512, ok := seedHandles[i].(*itb.Seed512)
		if !ok || s512 == nil {
			t.Fatalf("seed[%d] unexpected type %T", i, seedHandles[i])
		}
		if s512.Hash == nil {
			t.Fatalf("seed[%d].Hash is nil after Close (want zero-returning stub)", i)
		}
		if out := s512.Hash([]byte("probe"), [8]uint64{}); out != ([8]uint64{}) {
			t.Fatalf("seed[%d].Hash stub returned %x, want zero [8]uint64", i, out)
		}
		if s512.BatchHash != nil || s512.FusedChain != nil || s512.BatchFusedChain != nil {
			t.Fatalf("seed[%d] batch/fused closures not nilled after Close", i)
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
	// MAC key must be zeroed, and MAC closures replaced with non-nil
	// zero-returning stubs.
	if macKeyAlias != nil && !allZero(macKeyAlias) {
		t.Fatalf("macKey not zeroed: %x", macKeyAlias)
	}
	if pipe.macFunc == nil {
		t.Fatal("pipe.macFunc is nil after Close (want zero-returning stub)")
	}
	if tag := pipe.macFunc([]byte("probe")); len(tag) != 32 || !allZero(tag) {
		t.Fatalf("pipe.macFunc stub returned %x, want 32 zero bytes", tag)
	}
	if pipe.cfg.MACIncremental == nil {
		t.Fatal("pipe.cfg.MACIncremental is nil after Close (want zero-returning stub)")
	}
	if sum := pipe.cfg.MACIncremental([]byte("probe")); len(sum) != 32 || !allZero(sum) {
		t.Fatalf("pipe.cfg.MACIncremental stub returned %x, want 32 zero bytes", sum)
	}
	if pipe.parallaxCS != nil {
		t.Fatal("pipe.parallaxCS not nilled after Close")
	}
}

// TestPipelineRekeyZeroisesOldState verifies Rekey wipes the retired
// wrapperKey in place on success and preserves the live Pipeline state
// when validation fails before swap.
func TestPipelineRekeyZeroisesOldState(t *testing.T) {
	pipe, _, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer pipe.Close()

	oldWrapperKey := pipe.wrapperKey
	msg := []byte("rekey lifecycle check")
	ctBefore, err := pipe.EncryptMessage(msg)
	if err != nil {
		t.Fatalf("EncryptMessage before failed Rekey: %v", err)
	}

	// Failed Rekey (short permMaster) must leave live state untouched.
	if _, err := pipe.Rekey([]byte("short"), freshBytes(t, 32)); err == nil {
		t.Fatal("Rekey with short permMaster succeeded, want error")
	}
	if allZero(oldWrapperKey) {
		t.Fatal("failed Rekey prematurely zeroed old wrapperKey")
	}
	ptBefore, err := pipe.DecryptMessage(ctBefore)
	if err != nil || !bytes.Equal(ptBefore, msg) {
		t.Fatalf("DecryptMessage after failed Rekey: err=%v, got=%q", err, ptBefore)
	}

	// Successful Rekey must wipe the retired wrapperKey in place.
	if _, err := pipe.Rekey(freshBytes(t, 32), freshBytes(t, 32)); err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	if !allZero(oldWrapperKey) {
		t.Fatalf("old wrapperKey not zeroed after successful Rekey: %x", oldWrapperKey)
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
