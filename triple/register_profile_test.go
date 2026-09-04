package triple

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/parallax"
)

// baseValidProfile returns a Profile literal that passes every
// [Register] validation check when combined with a fresh
// user-defined name. Individual test cases mutate one field to
// exercise the corresponding rejection path.
func baseValidProfile() Profile {
	return Profile{
		Mode:                modeStreamingAEAD,
		Width:               512,
		ChunkSize:           itb.DefaultChunkSize,
		InnerHash:           defaultInnerHash,
		KeyBits:             defaultKeyBits,
		MacName:             defaultMacName,
		OuterCipher:         defaultOuterCipher,
		ParallaxPalette:     defaultParallaxPalette(),
		ParallaxSegmentSize: parallax.DefaultSegmentSize,
		Parallax:            true,
		Wrapper:             true,
	}
}

// TestRegisterRoundTrip installs a fresh custom profile and
// exercises Init → Open against it: the Pipeline reconstructs and
// decrypts a message-shape round-trip identical to the shipped
// profile behaviour.
func TestRegisterRoundTrip(t *testing.T) {
	name := "userns-triple-roundtrip-v1"
	prof := baseValidProfile()
	prof.Mode = modeSingleMsgMAC
	if err := Register(name, prof); err != nil {
		t.Fatalf("Register: %v", err)
	}

	sender, blob, err := Init(name, Opts{})
	if err != nil {
		t.Fatalf("Init(%q): %v", name, err)
	}
	defer sender.Close()

	receiver, err := Load(blob)
	if err != nil {
		t.Fatalf("Open(%q): %v", name, err)
	}
	defer receiver.Close()

	plain := []byte("register-profile round-trip payload")
	wire, err := sender.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := receiver.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip plaintext mismatch: got %q, want %q", got, plain)
	}
}

// TestRegisterDuplicateName verifies a second registration
// under the same name returns [ErrProfileExists], regardless of
// whether the payload differs from the earlier record.
func TestRegisterDuplicateName(t *testing.T) {
	name := "userns-triple-duplicate-v1"
	if err := Register(name, baseValidProfile()); err != nil {
		t.Fatalf("Register initial: %v", err)
	}
	// Re-register with a different payload — must still fail.
	second := baseValidProfile()
	second.Mode = modeSingleMsgNoMAC
	second.MacName = ""
	err := Register(name, second)
	if !errors.Is(err, ErrProfileExists) {
		t.Fatalf("Register duplicate: got %v, want %v", err, ErrProfileExists)
	}
}

// TestRegisterShippedNameCollision verifies re-registering
// one of the shipped profile names is refused (the shipped catalogue
// occupies the reserved namespace, so the caller hits the reserved-
// prefix guard before the duplicate-name check).
func TestRegisterShippedNameCollision(t *testing.T) {
	err := Register(ProfileStreamingAEADTripleMACV1, baseValidProfile())
	if err == nil {
		t.Fatalf("Register against shipped name: got nil, want error")
	}
	if !strings.Contains(err.Error(), "reserved prefix") {
		t.Fatalf("Register against shipped name: got %v, want reserved-prefix rejection",
			err)
	}
}

// TestRegisterValidation exercises every documented rejection
// path via table-driven cases.
func TestRegisterValidation(t *testing.T) {
	// Each case builds on baseValidProfile and mutates one field to
	// trigger a specific rejection.
	type tc struct {
		label   string
		name    string
		mutate  func(*Profile)
		wantSub string
	}
	cases := []tc{
		{
			label:   "empty-name",
			name:    "",
			mutate:  func(p *Profile) {},
			wantSub: "does not match pattern",
		},
		{
			label:   "uppercase-name",
			name:    "UserNS-Bad-Case-v1",
			mutate:  func(p *Profile) {},
			wantSub: "does not match pattern",
		},
		{
			label:   "underscore-name",
			name:    "userns_bad_underscore_v1",
			mutate:  func(p *Profile) {},
			wantSub: "does not match pattern",
		},
		{
			label:   "reserved-prefix-streaming",
			name:    "streaming-userns-v1",
			mutate:  func(p *Profile) {},
			wantSub: "reserved prefix",
		},
		{
			label:   "reserved-prefix-singlemsg",
			name:    "singlemsg-userns-v1",
			mutate:  func(p *Profile) {},
			wantSub: "reserved prefix",
		},
		{
			label:   "reserved-prefix-blob",
			name:    "blob-userns-v1",
			mutate:  func(p *Profile) {},
			wantSub: "reserved prefix",
		},
		{
			label: "bad-mode",
			name:  "userns-triple-badmode-v1",
			mutate: func(p *Profile) {
				p.Mode = "not-a-mode"
			},
			wantSub: "Mode",
		},
		{
			label: "bad-width",
			name:  "userns-triple-badwidth-v1",
			mutate: func(p *Profile) {
				p.Width = 384
			},
			wantSub: "Width",
		},
		{
			label: "unknown-innerhash",
			name:  "userns-triple-badhash-v1",
			mutate: func(p *Profile) {
				p.InnerHash = "no-such-hash"
			},
			wantSub: "InnerHash",
		},
		{
			label: "innerhash-width-mismatch",
			name:  "userns-triple-widthmix-v1",
			mutate: func(p *Profile) {
				// blake2s is 256-bit; profile Width remains 512.
				p.InnerHash = "blake2s"
			},
			wantSub: "width 256, profile Width is 512",
		},
		{
			label: "bad-keybits-multiple",
			name:  "userns-triple-badkeybits-v1",
			mutate: func(p *Profile) {
				p.KeyBits = 700
			},
			wantSub: "not a multiple of Width",
		},
		{
			label: "zero-keybits",
			name:  "userns-triple-zerokeybits-v1",
			mutate: func(p *Profile) {
				p.KeyBits = 0
			},
			wantSub: "KeyBits",
		},
		{
			label: "unknown-macname",
			name:  "userns-triple-badmac-v1",
			mutate: func(p *Profile) {
				p.MacName = "hmac-no-such-mac"
			},
			wantSub: "MacName",
		},
		{
			label: "unknown-outercipher",
			name:  "userns-triple-badouter-v1",
			mutate: func(p *Profile) {
				p.OuterCipher = "not-a-cipher"
			},
			wantSub: "OuterCipher",
		},
		{
			label: "empty-palette",
			name:  "userns-triple-emptypal-v1",
			mutate: func(p *Profile) {
				p.ParallaxPalette = nil
			},
			wantSub: "ParallaxPalette size 0",
		},
		{
			label: "undersized-palette",
			name:  "userns-triple-shortpal-v1",
			mutate: func(p *Profile) {
				p.ParallaxPalette = []string{"chacha20"}
			},
			wantSub: "below minimum",
		},
		{
			label: "palette-with-unknown-entry",
			name:  "userns-triple-badpalentry-v1",
			mutate: func(p *Profile) {
				p.ParallaxPalette = []string{"chacha20", "blake3", "not-a-cipher"}
			},
			wantSub: "ParallaxPalette[2]",
		},
		{
			label: "palette-with-empty-entry",
			name:  "userns-triple-emptypalentry-v1",
			mutate: func(p *Profile) {
				p.ParallaxPalette = []string{"chacha20", "", "blake3"}
			},
			wantSub: "ParallaxPalette[1] is empty",
		},
		{
			label: "negative-segmentsize",
			name:  "userns-triple-negseg-v1",
			mutate: func(p *Profile) {
				p.ParallaxSegmentSize = -1
			},
			wantSub: "ParallaxSegmentSize",
		},
		{
			label: "negative-chunksize",
			name:  "userns-triple-negchunk-v1",
			mutate: func(p *Profile) {
				p.ChunkSize = -1
			},
			wantSub: "ChunkSize",
		},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			p := baseValidProfile()
			c.mutate(&p)
			err := Register(c.name, p)
			if err == nil {
				t.Fatalf("Register: got nil, want rejection containing %q",
					c.wantSub)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("Register: got %v, want error containing %q",
					err, c.wantSub)
			}
		})
	}
}

// TestRegisterConcurrent spawns N goroutines each registering
// a distinct name. All N must succeed with no data race under -race,
// exercising profileRegistryMu's per-writer serialisation.
func TestRegisterConcurrent(t *testing.T) {
	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("userns-triple-concurrent-%02d-v1", idx)
			if err := Register(name, baseValidProfile()); err != nil {
				errs <- fmt.Errorf("worker %d: %w", idx, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("%v", err)
	}
	// Verify every worker's profile is now visible via lookupProfile.
	for i := 0; i < workers; i++ {
		name := fmt.Sprintf("userns-triple-concurrent-%02d-v1", i)
		if _, err := Lookup(name); err != nil {
			t.Errorf("Lookup(%q) after concurrent register: %v", name, err)
		}
	}
}

// TestRegisterNoMacMode confirms a No MAC profile with an
// empty MacName registers cleanly, mirroring the shipped
// streaming-noaead-triple-v1 shape.
func TestRegisterNoMacMode(t *testing.T) {
	p := baseValidProfile()
	p.Mode = modeStreamingNoAEAD
	p.MacName = ""
	if err := Register("userns-triple-nomac-v1", p); err != nil {
		t.Fatalf("Register No-MAC: %v", err)
	}
}

// TestRegisterWrapperOffSkipsOuterCipher verifies OuterCipher
// validation is skipped when Wrapper is false — a wrapper-off
// profile is allowed to leave OuterCipher empty or hold a placeholder
// value, since the field is inert.
func TestRegisterWrapperOffSkipsOuterCipher(t *testing.T) {
	p := baseValidProfile()
	p.Wrapper = false
	p.OuterCipher = "" // wrapper-off — OuterCipher never consumed.
	if err := Register("userns-triple-nowrap-v1", p); err != nil {
		t.Fatalf("Register wrapper-off: %v", err)
	}
}

// TestRegisterParallaxOffSkipsPaletteChecks verifies
// ParallaxPalette validation is skipped when Parallax is false; the
// palette field is inert for parallax-off profiles.
func TestRegisterParallaxOffSkipsPaletteChecks(t *testing.T) {
	p := baseValidProfile()
	p.Parallax = false
	p.ParallaxPalette = nil
	if err := Register("userns-triple-nopar-v1", p); err != nil {
		t.Fatalf("Register parallax-off: %v", err)
	}
}

// TestRegisterNameNormalisedAfterRegister confirms the name
// argument is copied into p.Name after successful registration, so
// [lookupProfile] returns a record whose Name matches the requested
// key.
func TestRegisterNameNormalisedAfterRegister(t *testing.T) {
	name := "userns-triple-namefill-v1"
	p := baseValidProfile()
	if err := Register(name, p); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := Lookup(name)
	if err != nil {
		t.Fatalf("lookupProfile: %v", err)
	}
	if got.Name != name {
		t.Fatalf("registered profile Name: got %q, want %q", got.Name, name)
	}
}

// TestRegisterRejectsOversizeChunkSize pins the upper-bound
// check on [Profile.ChunkSize]: any value beyond
// [parallax.MaxChunkSize] would fail deferred inside the parallax
// builder at [Init] time; the Register-side reject surfaces
// the misconfiguration at the registration boundary.
func TestRegisterRejectsOversizeChunkSize(t *testing.T) {
	p := baseValidProfile()
	p.ChunkSize = parallax.MaxChunkSize + 1
	err := Register("userns-triple-oversizechunk-v1", p)
	if err == nil {
		t.Fatalf("Register accepted oversize ChunkSize=%d", p.ChunkSize)
	}
	if !strings.Contains(err.Error(), "above maximum") {
		t.Fatalf("Register ChunkSize oversize: got %v, want error mentioning \"above maximum\"", err)
	}
}

// TestRegisterRejectsOversizeParallaxSegmentSize pins the
// upper-bound check on [Profile.ParallaxSegmentSize] mirroring the
// ChunkSize case. The parallax builder would refuse the value
// downstream anyway; the reject-at-registration surface is cleaner.
func TestRegisterRejectsOversizeParallaxSegmentSize(t *testing.T) {
	p := baseValidProfile()
	p.ParallaxSegmentSize = parallax.MaxSegmentSize + 1
	err := Register("userns-triple-oversizeseg-v1", p)
	if err == nil {
		t.Fatalf("Register accepted oversize ParallaxSegmentSize=%d", p.ParallaxSegmentSize)
	}
	if !strings.Contains(err.Error(), "above maximum") {
		t.Fatalf("Register ParallaxSegmentSize oversize: got %v, want error mentioning \"above maximum\"", err)
	}
}

// TestRegisterRejectsNonCoprimeParallaxSegmentSize pins the
// coprime-to-504 check moved up from [parallax.NewSchedule]. A value
// that shares a factor with the parallax pipeline period is refused
// at registration so the error message says "not coprime" instead of
// the downstream parallax builder's cryptic failure.
func TestRegisterRejectsNonCoprimeParallaxSegmentSize(t *testing.T) {
	p := baseValidProfile()
	// 504 = 2^3 * 3^2 * 7. Any positive multiple of 2, 3, or 7 is
	// non-coprime. 100 shares factor 2 → non-coprime.
	p.ParallaxSegmentSize = 100
	err := Register("userns-triple-notcoprime-v1", p)
	if err == nil {
		t.Fatalf("Register accepted non-coprime ParallaxSegmentSize=%d", p.ParallaxSegmentSize)
	}
	if !strings.Contains(err.Error(), "not coprime") {
		t.Fatalf("Register ParallaxSegmentSize coprime: got %v, want error mentioning \"not coprime\"", err)
	}
}

// TestRegisterRejectsOverlongStrings pins the fail-fast
// rejection of registry-name fields whose length exceeds
// [hashes.MaxNameLen]. Reaching the downstream registry lookup with
// an over-long name would produce a cryptic "unknown ..." error; the
// upfront reject gives a clean "length ... exceeds ..." message.
func TestRegisterRejectsOverlongStrings(t *testing.T) {
	long := "abcdefghijklmnopqr" // 18 bytes, > hashes.MaxNameLen (12)
	cases := []struct {
		label   string
		nameSfx string
		mutate  func(*Profile)
	}{
		{"mac-name-too-long", "mac", func(p *Profile) { p.MacName = long }},
		{"inner-hash-too-long", "inner", func(p *Profile) { p.InnerHash = long }},
		{"outer-cipher-too-long", "outer", func(p *Profile) { p.OuterCipher = long }},
		{"palette-entry-too-long", "palette", func(p *Profile) {
			p.ParallaxPalette = []string{"aescmac", "chacha20", long}
		}},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			p := baseValidProfile()
			c.mutate(&p)
			err := Register("userns-triple-longstr-"+c.nameSfx+"-v1", p)
			if err == nil {
				t.Fatalf("Register accepted overlong string: %s", c.label)
			}
			if !strings.Contains(err.Error(), "exceeds hashes.MaxNameLen") {
				t.Fatalf("Register %s: got %v, want error mentioning \"exceeds hashes.MaxNameLen\"", c.label, err)
			}
		})
	}
}
