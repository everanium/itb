package hashes

import (
	"testing"

	"github.com/everanium/itb"
)

func TestNamesMatchesRegistry(t *testing.T) {
	got := Names()
	if len(got) != len(Registry) {
		t.Fatalf("Names() length %d, want %d", len(got), len(Registry))
	}
	for i := range Registry {
		if got[i] != Registry[i].Name {
			t.Fatalf("Names()[%d] = %q, want %q", i, got[i], Registry[i].Name)
		}
	}
}

func TestNamesReturnsFreshCopy(t *testing.T) {
	a := Names()
	b := Names()
	if len(a) == 0 || len(b) == 0 {
		t.Fatal("Names() returned an empty slice")
	}
	if &a[0] == &b[0] {
		t.Fatal("Names() returned a shared backing array across calls")
	}
	a[0] = "mutated"
	if b[0] == "mutated" || Registry[0].Name == "mutated" {
		t.Fatal("mutating a Names() result leaked into another copy or into Registry")
	}
}

func TestNamesExcludesRegistered(t *testing.T) {
	const custom = "namestest1"
	spec := Spec{
		Name:  custom,
		Width: W128,
		Make128Pair: func(key ...[]byte) (itb.HashFunc128, itb.BatchHashFunc128, []byte, error) {
			return func(_ []byte, _, _ uint64) (uint64, uint64) { return 0, 0 }, nil, nil, nil
		},
		Class: ClassPRFCounter,
	}
	if err := Register(spec); err != nil && err != ErrHashExists {
		t.Fatalf("Register(%q): %v", custom, err)
	}
	for _, n := range Names() {
		if n == custom {
			t.Fatalf("Names() includes user-registered primitive %q", custom)
		}
	}
	if got := ClassOf(custom); got != ClassNone {
		t.Fatalf("ClassOf(%q) = %d, want ClassNone for a user-registered primitive", custom, got)
	}
	for _, info := range FullView() {
		if info.Name == custom {
			t.Fatalf("FullView() includes user-registered primitive %q", custom)
		}
	}
}

func TestRegistryClassPopulated(t *testing.T) {
	// Every shipped Registry entry must carry a Class value the ctr /
	// kdf / wrapper / parallax packages recognise: ClassNativeStream
	// and ClassPRFCounter mark outer-cipher-eligible primitives;
	// ClassNone marks inner-PRF-only primitives (AES-ITB and future
	// entries whose reduced-round structure makes them safe only
	// under ITB's compound inner-PRF stack). Any other Class value
	// is a drift bug.
	for i := range Registry {
		switch Registry[i].Class {
		case ClassNone, ClassNativeStream, ClassPRFCounter:
			// recognised
		default:
			t.Errorf("Registry[%d] (%q) has unrecognised Class %d", i, Registry[i].Name, Registry[i].Class)
		}
	}
}

func TestClassOf(t *testing.T) {
	cases := []struct {
		name string
		want Class
	}{
		{CipherAESITB128, ClassNone},
		{CipherAreion256, ClassPRFCounter},
		{CipherAreion512, ClassPRFCounter},
		{CipherBLAKE2b256, ClassPRFCounter},
		{CipherBLAKE2b512, ClassPRFCounter},
		{CipherBLAKE2s, ClassPRFCounter},
		{CipherBLAKE3, ClassPRFCounter},
		{CipherAES128CTR, ClassNativeStream},
		{CipherSipHash24, ClassNativeStream},
		{CipherChaCha20, ClassNativeStream},
		{"nope", ClassNone},
		{"", ClassNone},
	}
	for _, c := range cases {
		if got := ClassOf(c.name); got != c.want {
			t.Errorf("ClassOf(%q) = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestFullViewMatchesRegistry(t *testing.T) {
	view := FullView()
	if len(view) != len(Registry) {
		t.Fatalf("FullView() length %d, want %d", len(view), len(Registry))
	}
	for i := range Registry {
		want := Info{Name: Registry[i].Name, Width: Registry[i].Width, Class: Registry[i].Class}
		if view[i] != want {
			t.Errorf("FullView()[%d] = %+v, want %+v", i, view[i], want)
		}
	}
}
