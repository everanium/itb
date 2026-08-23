package triple

import (
	"strings"
	"testing"
)

// baseMixedProfile returns a Profile literal populated with a
// width-256 mixed-primitive constellation that passes every
// [RegisterProfile] validation check when combined with a fresh
// user-defined name. Individual test cases mutate one field or one
// [Profile.MixedHashes] slot to exercise the corresponding rejection
// path.
func baseMixedProfile() Profile {
	p := baseValidProfile()
	p.Width = 256
	p.InnerHash = "" // mixed and single are mutually exclusive
	p.MixedHashes = [8]string{
		"areion256", "blake3", "blake2b256", "blake2s",
		"chacha20", "areion256", "blake3", "blake2b256",
	}
	return p
}

// TestRegisterProfileMixedValidation exercises every mixed-path
// rejection case via table-driven cases.
func TestRegisterProfileMixedValidation(t *testing.T) {
	type tc struct {
		label   string
		name    string
		mutate  func(*Profile)
		wantSub string
	}
	cases := []tc{
		{
			label: "mixed-with-innerhash-set",
			name:  "userns-triple-mixed-innerset-v1",
			mutate: func(p *Profile) {
				p.InnerHash = "blake3"
			},
			wantSub: "must be empty when MixedHashes is populated",
		},
		{
			label: "partial-population-slot0-empty",
			name:  "userns-triple-mixed-slot0empty-v1",
			mutate: func(p *Profile) {
				p.MixedHashes[0] = ""
			},
			wantSub: "MixedHashes[0] is empty",
		},
		{
			label: "partial-population-slot7-empty",
			name:  "userns-triple-mixed-slot7empty-v1",
			mutate: func(p *Profile) {
				p.MixedHashes[7] = ""
			},
			wantSub: "MixedHashes[7] is empty",
		},
		{
			label: "unknown-primitive-slot4",
			name:  "userns-triple-mixed-unknown-v1",
			mutate: func(p *Profile) {
				p.MixedHashes[4] = "not-a-hash"
			},
			wantSub: "MixedHashes[4]",
		},
		{
			label: "width-mismatch-slot3",
			name:  "userns-triple-mixed-widthmix-v1",
			mutate: func(p *Profile) {
				// aescmac is width 128; profile is width 256.
				p.MixedHashes[3] = "aescmac"
			},
			wantSub: "MixedHashes[3]",
		},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			p := baseMixedProfile()
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

// TestRegisterProfileMixedRepeatsAllowed confirms repeated primitive
// entries within a single mixed profile are accepted — the constraint
// is uniform width, not eight-distinct primitives.
func TestRegisterProfileMixedRepeatsAllowed(t *testing.T) {
	name := "userns-triple-mixed-repeats-v1"
	p := baseMixedProfile()
	// Deliberately use 8 identical entries — should still register.
	for i := range p.MixedHashes {
		p.MixedHashes[i] = "blake3"
	}
	if err := RegisterProfile(name, p); err != nil {
		t.Fatalf("RegisterProfile with 8 identical MixedHashes entries: %v", err)
	}
}

// TestRegisterProfileMixedWidth128 confirms width-128 mixed profiles
// register cleanly (spot-check for the smaller pool of shipped 128-bit
// primitives).
func TestRegisterProfileMixedWidth128(t *testing.T) {
	name := "userns-triple-mixed-w128-v1"
	p := baseMixedProfile()
	p.Width = 128
	p.MixedHashes = [8]string{
		"aescmac", "siphash24", "aescmac", "siphash24",
		"aescmac", "siphash24", "aescmac", "siphash24",
	}
	if err := RegisterProfile(name, p); err != nil {
		t.Fatalf("RegisterProfile width-128 mixed: %v", err)
	}
}

// TestRegisterProfileMixedWidth512 confirms width-512 mixed profiles
// register cleanly.
func TestRegisterProfileMixedWidth512(t *testing.T) {
	name := "userns-triple-mixed-w512-v1"
	p := baseMixedProfile()
	p.Width = 512
	p.MixedHashes = [8]string{
		"areion512", "blake2b512", "areion512", "blake2b512",
		"areion512", "blake2b512", "areion512", "blake2b512",
	}
	if err := RegisterProfile(name, p); err != nil {
		t.Fatalf("RegisterProfile width-512 mixed: %v", err)
	}
}

// TestRegisterProfileSinglePathUnaffected confirms the single-primitive
// dispatch path (empty MixedHashes) is unchanged by the mixed-path
// validator addition — the baseValidProfile shape still registers.
func TestRegisterProfileSinglePathUnaffected(t *testing.T) {
	name := "userns-triple-single-unaffected-v1"
	p := baseValidProfile()
	// MixedHashes zero-value; InnerHash carries the default primitive.
	if err := RegisterProfile(name, p); err != nil {
		t.Fatalf("RegisterProfile single-primitive path: %v", err)
	}
}
