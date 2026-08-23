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
// [RegisterProfile] validation check when combined with a fresh
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
		ParallaxOn:          true,
		WrapperOn:           true,
	}
}

// TestRegisterProfileRoundTrip installs a fresh custom profile and
// exercises Init → Open against it: the Pipeline reconstructs and
// decrypts a message-shape round-trip identical to the shipped
// profile behaviour.
func TestRegisterProfileRoundTrip(t *testing.T) {
	name := "userns-triple-roundtrip-v1"
	prof := baseValidProfile()
	prof.Mode = modeSingleMsgMAC
	if err := RegisterProfile(name, prof); err != nil {
		t.Fatalf("RegisterProfile: %v", err)
	}

	sender, blob, err := Init(name, Opts{})
	if err != nil {
		t.Fatalf("Init(%q): %v", name, err)
	}
	defer sender.Close()

	receiver, err := Open(name, blob, Opts{})
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

// TestRegisterProfileDuplicateName verifies a second registration
// under the same name returns [ErrProfileExists], regardless of
// whether the payload differs from the earlier record.
func TestRegisterProfileDuplicateName(t *testing.T) {
	name := "userns-triple-duplicate-v1"
	if err := RegisterProfile(name, baseValidProfile()); err != nil {
		t.Fatalf("RegisterProfile initial: %v", err)
	}
	// Re-register with a different payload — must still fail.
	second := baseValidProfile()
	second.Mode = modeSingleMsgNoMAC
	second.MacName = ""
	err := RegisterProfile(name, second)
	if !errors.Is(err, ErrProfileExists) {
		t.Fatalf("RegisterProfile duplicate: got %v, want %v", err, ErrProfileExists)
	}
}

// TestRegisterProfileShippedNameCollision verifies re-registering
// one of the shipped profile names is refused (the shipped catalogue
// occupies the reserved namespace, so the caller hits the reserved-
// prefix guard before the duplicate-name check).
func TestRegisterProfileShippedNameCollision(t *testing.T) {
	err := RegisterProfile(ProfileStreamingAEADTripleMACV1, baseValidProfile())
	if err == nil {
		t.Fatalf("RegisterProfile against shipped name: got nil, want error")
	}
	if !strings.Contains(err.Error(), "reserved prefix") {
		t.Fatalf("RegisterProfile against shipped name: got %v, want reserved-prefix rejection",
			err)
	}
}

// TestRegisterProfileValidation exercises every documented rejection
// path via table-driven cases.
func TestRegisterProfileValidation(t *testing.T) {
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
			err := RegisterProfile(c.name, p)
			if err == nil {
				t.Fatalf("RegisterProfile: got nil, want rejection containing %q",
					c.wantSub)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("RegisterProfile: got %v, want error containing %q",
					err, c.wantSub)
			}
		})
	}
}

// TestRegisterProfileConcurrent spawns N goroutines each registering
// a distinct name. All N must succeed with no data race under -race,
// exercising profileRegistryMu's per-writer serialisation.
func TestRegisterProfileConcurrent(t *testing.T) {
	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("userns-triple-concurrent-%02d-v1", idx)
			if err := RegisterProfile(name, baseValidProfile()); err != nil {
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
		if _, err := lookupProfile(name); err != nil {
			t.Errorf("lookupProfile(%q) after concurrent register: %v", name, err)
		}
	}
}

// TestRegisterProfileNoMacMode confirms a No-MAC profile with an
// empty MacName registers cleanly, mirroring the shipped
// streaming-noaead-triple-v1 shape.
func TestRegisterProfileNoMacMode(t *testing.T) {
	p := baseValidProfile()
	p.Mode = modeStreamingNoAEAD
	p.MacName = ""
	if err := RegisterProfile("userns-triple-nomac-v1", p); err != nil {
		t.Fatalf("RegisterProfile No-MAC: %v", err)
	}
}

// TestRegisterProfileWrapperOffSkipsOuterCipher verifies OuterCipher
// validation is skipped when WrapperOn is false — a wrapper-off
// profile is allowed to leave OuterCipher empty or hold a placeholder
// value, since the field is inert.
func TestRegisterProfileWrapperOffSkipsOuterCipher(t *testing.T) {
	p := baseValidProfile()
	p.WrapperOn = false
	p.OuterCipher = "" // wrapper-off — OuterCipher never consumed.
	if err := RegisterProfile("userns-triple-nowrap-v1", p); err != nil {
		t.Fatalf("RegisterProfile wrapper-off: %v", err)
	}
}

// TestRegisterProfileParallaxOffSkipsPaletteChecks verifies
// ParallaxPalette validation is skipped when ParallaxOn is false; the
// palette field is inert for parallax-off profiles.
func TestRegisterProfileParallaxOffSkipsPaletteChecks(t *testing.T) {
	p := baseValidProfile()
	p.ParallaxOn = false
	p.ParallaxPalette = nil
	if err := RegisterProfile("userns-triple-nopar-v1", p); err != nil {
		t.Fatalf("RegisterProfile parallax-off: %v", err)
	}
}

// TestRegisterProfileNameNormalisedAfterRegister confirms the name
// argument is copied into p.Name after successful registration, so
// [lookupProfile] returns a record whose Name matches the requested
// key.
func TestRegisterProfileNameNormalisedAfterRegister(t *testing.T) {
	name := "userns-triple-namefill-v1"
	p := baseValidProfile()
	if err := RegisterProfile(name, p); err != nil {
		t.Fatalf("RegisterProfile: %v", err)
	}
	got, err := lookupProfile(name)
	if err != nil {
		t.Fatalf("lookupProfile: %v", err)
	}
	if got.Name != name {
		t.Fatalf("registered profile Name: got %q, want %q", got.Name, name)
	}
}
