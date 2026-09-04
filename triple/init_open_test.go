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
// side Pipeline via Load, and verifies the reconstructed state
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

			receiver, err := Load(blob)
			if err != nil {
				t.Fatalf("Load(%q): %v", prof, err)
			}
			defer receiver.Close()

			if sender.resolved.Name != receiver.resolved.Name {
				t.Fatalf("profileName: sender %q vs receiver %q",
					sender.resolved.Name, receiver.resolved.Name)
			}
			if sender.resolved.Parallax != receiver.resolved.Parallax {
				t.Fatalf("Parallax: sender %v vs receiver %v",
					sender.resolved.Parallax, receiver.resolved.Parallax)
			}
			if sender.resolved.Wrapper != receiver.resolved.Wrapper {
				t.Fatalf("Wrapper: sender %v vs receiver %v",
					sender.resolved.Wrapper, receiver.resolved.Wrapper)
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
	var got blobWrapV2
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

// TestPipelineOpenMastersOverride verifies that Load accepts the
// trailing 2-master variadic override and consumes those bytes
// instead of the blob's stored masters.
func TestPipelineOpenMastersOverride(t *testing.T) {
	sender, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer sender.Close()

	// Fresh masters that DON'T match the sender's — Load should
	// consume these rather than the blob's stored pair. Since the
	// wrapper key is a deterministic function of the wrapper master,
	// the receiver's wrapperKey will differ from the sender's.
	newPerm := freshBytes(t, 32)
	newWrap := freshBytes(t, 32)

	receiver, err := Load(blob, newPerm, newWrap)
	if err != nil {
		t.Fatalf("Load with overrides: %v", err)
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
	_, err = Load(blob, freshBytes(t, 32))
	if !errors.Is(err, ErrMastersArity) {
		t.Fatalf("Load arity=1: got err=%v, want %v", err, ErrMastersArity)
	}
	// Arity 3 — also invalid.
	_, err = Load(blob, freshBytes(t, 32), freshBytes(t, 32), freshBytes(t, 32))
	if !errors.Is(err, ErrMastersArity) {
		t.Fatalf("Load arity=3: got err=%v, want %v", err, ErrMastersArity)
	}
}

// TestPipelineOpenErrMissingMasters exercises the failure path when
// the blob has no masters AND the caller supplies none. Build a
// synthetic blob without pm / wm and confirm Load surfaces
// ErrMissingMasters.
func TestPipelineOpenErrMissingMasters(t *testing.T) {
	// Init a real blob to reuse its inner-blob bytes so the decode
	// path proceeds far enough to reach the master-resolution check.
	_, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	// Strip the masters from the wire and re-marshal.
	var w blobWrapV2
	if err := json.Unmarshal(blob, &w); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	w.PermMaster = nil
	w.WrapMaster = nil
	stripped, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	_, err = Load(stripped)
	if !errors.Is(err, ErrMissingMasters) {
		t.Fatalf("Load on master-stripped blob: got err=%v, want %v",
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

// TestPipelineInitRejectsBadOptsCommon pins the fail-fast rejection of
// [Opts.NonceBits] / [Opts.BarrierFill] outside the shipped enum
// ([Opts.MaxWorkers] is clamped, never rejected — see persist_test.go). Every case must surface an error before the
// blob-producing step runs; the shipped default profile is engaged
// only as a valid backdrop for the Opts probe.
func TestPipelineInitRejectsBadOptsCommon(t *testing.T) {
	cases := []struct {
		label string
		opts  Opts
	}{
		{"nonce_bits_999", Opts{NonceBits: 999}},
		{"nonce_bits_neg", Opts{NonceBits: -1}},
		{"barrier_fill_5", Opts{BarrierFill: 5}},
		{"barrier_fill_neg", Opts{BarrierFill: -1}},
		{"barrier_fill_huge", Opts{BarrierFill: 1 << 30}},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			pipe, _, err := Init(ProfileStreamingAEADTripleMACV1, c.opts)
			if err == nil {
				pipe.Close()
				t.Fatalf("Init accepted invalid opts: %s", c.label)
			}
		})
	}
}

// TestPipelineInitRejectsBadKeyBits pins the fail-fast rejection of
// an out-of-range [Opts.KeyBits] override at [Init]. The sentinel 0
// stays valid (defer to profile default); every other rejection
// surfaces as an [ErrBadKeyBits]-wrapped error so the [capi] mapper
// routes it to the shared StatusBadKeyBits status code.
func TestPipelineInitRejectsBadKeyBits(t *testing.T) {
	cases := []int{-1, 1, 100, 511, 700, 2049, 1 << 20}
	for _, kb := range cases {
		_, _, err := Init(ProfileStreamingAEADTripleMACV1, Opts{KeyBits: kb})
		if err == nil {
			t.Fatalf("Init accepted KeyBits=%d, want rejection", kb)
		}
		if !errors.Is(err, ErrBadKeyBits) {
			t.Fatalf("Init KeyBits=%d: got err=%v, want wrap of ErrBadKeyBits", kb, err)
		}
	}
}

// TestPipelineInitRejectsBadChunkSize pins the fail-fast rejection of
// an [Opts.ChunkSize] override above the parallax package's
// [parallax.MaxChunkSize] cap. Zero remains the "defer to
// itb.DefaultChunkSize" sentinel; a value beyond the cap would fail
// deferred inside the parallax builder — the upfront reject moves
// the surface to the construction boundary.
func TestPipelineInitRejectsBadChunkSize(t *testing.T) {
	for _, cs := range []int{-1, 1 << 40, 5 << 40} {
		_, _, err := Init(ProfileStreamingAEADTripleMACV1, Opts{ChunkSize: cs})
		if err == nil {
			t.Fatalf("Init accepted ChunkSize=%d, want rejection", cs)
		}
	}
}

// TestPipelineInitRejectsOverlongStrings pins the fail-fast rejection
// of Opts string overrides that exceed [hashes.MaxNameLen]. Reaching
// the downstream lookup with an over-long name would produce a
// cryptic "unknown ..." message; the upfront check gives a "name too
// long" surface at the entry point.
func TestPipelineInitRejectsOverlongStrings(t *testing.T) {
	long := "abcdefghijklmnopqr" // 18 bytes, > hashes.MaxNameLen (12)
	cases := []struct {
		label string
		opts  Opts
	}{
		{"mac_name_too_long", Opts{MacName: long}},
		{"inner_hash_too_long", Opts{InnerHash: long}},
		{"outer_cipher_too_long", Opts{OuterCipher: long}},
		{"parallax_palette_too_long", Opts{ParallaxPalette: []string{"aescmac", "chacha20", long}}},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			pipe, _, err := Init(ProfileStreamingAEADTripleMACV1, c.opts)
			if err == nil {
				pipe.Close()
				t.Fatalf("Init accepted overlong string: %s", c.label)
			}
		})
	}
}

// TestPipelineInitRejectsOversizedMasters pins the upper-cap
// rejection of [Opts.PermMaster] / [Opts.WrapMaster] longer than
// the parallax / wrapper MaxMasterKeySize (128 bytes). The cap
// protects [prepareMasters] from amplifying an adversarial slice
// into two append-copies plus the downstream base64 blob string.
func TestPipelineInitRejectsOversizedMasters(t *testing.T) {
	perm := freshBytes(t, 129) // one byte past parallax.MaxMasterKeySize
	wrap := freshBytes(t, 129) // one byte past wrapper.MaxMasterKeySize
	cases := []struct {
		label string
		opts  Opts
	}{
		{"perm_master_129", Opts{PermMaster: perm}},
		{"wrap_master_129", Opts{WrapMaster: wrap}},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			pipe, _, err := Init(ProfileStreamingAEADTripleMACV1, c.opts)
			if err == nil {
				pipe.Close()
				t.Fatalf("Init accepted oversized master: %s", c.label)
			}
		})
	}
}

// TestPipelineRekeyRejectsOversizedMasters pins the upper-cap
// rejection on the [Pipeline.Rekey] path. Symmetric with
// [TestPipelineInitRejectsOversizedMasters] on the entry-side
// prepareMasters check.
func TestPipelineRekeyRejectsOversizedMasters(t *testing.T) {
	pipe, _, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer pipe.Close()
	goodPerm := freshBytes(t, 32)
	goodWrap := freshBytes(t, 32)
	badPerm := freshBytes(t, 129)
	badWrap := freshBytes(t, 129)
	if _, err := pipe.Rekey(badPerm, goodWrap); err == nil {
		t.Fatal("Rekey accepted oversized permMaster")
	}
	if _, err := pipe.Rekey(goodPerm, badWrap); err == nil {
		t.Fatal("Rekey accepted oversized wrapMaster")
	}
}

// TestPipelineOpenRejectsOversizedMasters pins the upper-cap
// rejection on the [Load] rekey-on-import trailing-variadic path.
func TestPipelineOpenRejectsOversizedMasters(t *testing.T) {
	_, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	goodPerm := freshBytes(t, 32)
	goodWrap := freshBytes(t, 32)
	badPerm := freshBytes(t, 129)
	badWrap := freshBytes(t, 129)
	if _, err := Load(blob, badPerm, goodWrap); err == nil {
		t.Fatal("Load accepted oversized permMaster override")
	}
	if _, err := Load(blob, goodPerm, badWrap); err == nil {
		t.Fatal("Load accepted oversized wrapMaster override")
	}
}

// TestPipelineOpenRejectsOversizedBlobMasters pins the upper-cap
// rejection when the persisted wrap-layer carries an oversized
// PermMaster / WrapMaster. A hostile persisted blob cannot then
// force the [Load] path to amplify the multi-megabyte slice.
func TestPipelineOpenRejectsOversizedBlobMasters(t *testing.T) {
	_, blob, err := Init(ProfileStreamingAEADTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	var w blobWrapV2
	if err := json.Unmarshal(blob, &w); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	origPerm := w.PermMaster
	origWrap := w.WrapMaster

	// PermMaster: replace with a 129-byte slice; keep WrapMaster.
	w.PermMaster = freshBytes(t, 129)
	w.WrapMaster = origWrap
	permBlob, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := Load(permBlob); err == nil {
		t.Fatal("Load accepted blob with oversized PermMaster slot")
	}

	// WrapMaster: replace with a 129-byte slice; restore PermMaster.
	w.PermMaster = origPerm
	w.WrapMaster = freshBytes(t, 129)
	wrapBlob, err := json.Marshal(w)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := Load(wrapBlob); err == nil {
		t.Fatal("Load accepted blob with oversized WrapMaster slot")
	}
}

// TestPipelineOpenRejectsOversizedBlob pins the top-level byte-length
// cap on the [Load] entry surface. A 2 MiB persisted blob is rejected
// before json.Decoder allocates for any wrap-layer field. Mirrors
// [TestBlobDecodeRejectsOversizedInput] at the triple boundary.
func TestPipelineOpenRejectsOversizedBlob(t *testing.T) {
	oversized := bytes.Repeat([]byte{'{'}, 2*itb.MaxBlobJSONSize)
	if _, err := Load(oversized); err == nil {
		t.Fatal("Load accepted 2 MiB blob (cap is itb.MaxBlobJSONSize)")
	}
}
