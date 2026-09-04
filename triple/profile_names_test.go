package triple

import (
	"sort"
	"strings"
	"testing"
)

// TestProfilesIncludesShipped verifies every shipped profile
// constant surfaces through the [Profiles] snapshot.
func TestProfilesIncludesShipped(t *testing.T) {
	shipped := []string{
		ProfileStreamingAEADTripleMACV1,
		ProfileStreamingNoAEADTripleV1,
		ProfileSingleMsgTripleMACV1,
		ProfileSingleMsgTripleNoMACV1,
		ProfileBlobTripleMACV1,
		ProfileStreamingAEADTripleMACMixedV1,
		ProfileStreamingNoAEADTripleMixedV1,
		ProfileSingleMsgTripleMACMixedV1,
		ProfileSingleMsgTripleNoMACMixedV1,
	}
	names := Profiles()
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		seen[n] = true
	}
	for _, want := range shipped {
		if !seen[want] {
			t.Errorf("Profiles() missing shipped profile %q", want)
		}
	}
}

// TestProfilesSorted verifies the returned slice is in ascending
// lexicographic order so successive callers get a stable listing.
func TestProfilesSorted(t *testing.T) {
	names := Profiles()
	if !sort.StringsAreSorted(names) {
		t.Fatalf("Profiles() not sorted: %v", names)
	}
}

// TestProfilesSnapshotIsCopy verifies mutating the returned slice
// does not affect subsequent calls — the snapshot posture prevents
// caller-side mutation leaking into the registry view.
func TestProfilesSnapshotIsCopy(t *testing.T) {
	first := Profiles()
	if len(first) == 0 {
		t.Fatalf("Profiles() empty on shipped registry")
	}
	first[0] = "mutated-name-should-not-persist"
	second := Profiles()
	if second[0] == "mutated-name-should-not-persist" {
		t.Fatalf("Profiles() shares backing array with previous return value")
	}
}

// TestProfilesPicksUpRegistration confirms a fresh
// [Register] call surfaces the new name on the next
// [Profiles] snapshot.
func TestProfilesPicksUpRegistration(t *testing.T) {
	const custom = "userns-profilenames-witness-v1"
	before := Profiles()
	for _, n := range before {
		if n == custom {
			t.Skipf("witness name %q already registered from an earlier test", custom)
		}
	}
	if err := Register(custom, baseValidProfile()); err != nil {
		t.Fatalf("Register: %v", err)
	}
	after := Profiles()
	found := false
	for _, n := range after {
		if n == custom {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Profiles() did not surface %q after Register; got %v", custom, after)
	}
	if len(after) != len(before)+1 {
		t.Fatalf("Profiles() length %d, want %d (before) + 1", len(after), len(before))
	}
	if !sort.StringsAreSorted(after) {
		t.Fatalf("Profiles() unsorted after registration: %v", after)
	}
}

// TestProfilesRegexShape confirms every returned name matches the
// profile-name pattern [profileNameRegexp] enforces on user
// registrations — shipped constants must satisfy the same pattern so
// the CLI-side round-trip encoders can rely on a uniform character set.
func TestProfilesRegexShape(t *testing.T) {
	for _, name := range Profiles() {
		if !profileNameRegexp.MatchString(name) {
			t.Errorf("Profiles() entry %q violates profileNameRegexp", name)
		}
		if strings.ContainsAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
			t.Errorf("Profiles() entry %q has uppercase — pattern is lowercase-only", name)
		}
	}
}
