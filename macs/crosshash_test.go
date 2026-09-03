package macs_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"hash"
	"strings"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/triple"
)

// sha256ARXFactory returns a Make256Pair factory backed by
// hashes.BuildARXChainAbsorb256 over crypto/sha256 — the minimal
// valid pixel-hash arm a custom hashes.Spec needs so the cross-hash
// tests can register composition-focused specs through the standard
// hashes.Register validation.
func sha256ARXFactory() func(key ...[]byte) (itb.HashFunc256, itb.BatchHashFunc256, []byte, error) {
	return func(key ...[]byte) (itb.HashFunc256, itb.BatchHashFunc256, []byte, error) {
		var fixedKey [32]byte
		if len(key) > 0 {
			copy(fixedKey[:], key[0])
		} else if _, err := rand.Read(fixedKey[:]); err != nil {
			return nil, nil, nil, err
		}
		h := hashes.BuildARXChainAbsorb256(sha256.Sum256, fixedKey[:])
		return h, nil, fixedKey[:], nil
	}
}

// TestBuildHMACWithRegisteredCustomHash exercises the cross-package
// composition path end-to-end: a custom hash registered via
// hashes.Register with a populated HashHash field becomes usable
// through macs.BuildHMAC with no additional wiring, the resulting MAC
// registers and dispatches by name, the tag matches an independent
// stdlib HMAC reference byte-for-byte, and the custom-hash-derived
// MAC round-trips through the Triple pipeline.
func TestBuildHMACWithRegisteredCustomHash(t *testing.T) {
	err := hashes.Register(hashes.Spec{
		Name:        "xh_sha256",
		Width:       hashes.W256,
		Make256Pair: sha256ARXFactory(),
		HashHash:    func() hash.Hash { return sha256.New() },
	})
	if err != nil {
		t.Fatalf("hashes.Register: %v", err)
	}

	spec, err := macs.BuildHMAC("xh_sha256", macs.HMACSpec{Name: "xh_hmac"})
	if err != nil {
		t.Fatalf("BuildHMAC(custom hash): %v", err)
	}
	if spec.KeySize != 32 || spec.TagSize != 32 || spec.MinKeyBytes != 16 {
		t.Fatalf("spec sizes = %d/%d/%d, want 32/32/16",
			spec.KeySize, spec.TagSize, spec.MinKeyBytes)
	}
	if err := macs.Register(spec); err != nil {
		t.Fatalf("macs.Register: %v", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	mac, inc, _, err := macs.MakeMACPair("xh_hmac", key)
	if err != nil {
		t.Fatalf("MakeMACPair: %v", err)
	}
	msg := []byte("cross-package custom-hash HMAC probe")
	tag := mac(msg)
	if len(tag) != 32 {
		t.Fatalf("tag len = %d, want 32", len(tag))
	}
	if !bytes.Equal(tag, inc(msg[:9], msg[9:])) {
		t.Fatal("incremental arm diverges from one-shot arm")
	}

	// Independent stdlib HMAC-SHA256 reference.
	ref := hmac.New(sha256.New, key)
	ref.Write(msg)
	if !bytes.Equal(tag, ref.Sum(nil)) {
		t.Fatal("tag does not match independent hmac.New(sha256.New, key) reference")
	}

	// Triple integration: a profile referencing the custom-hash-derived
	// MAC initialises, round-trips a Single Message wire, and re-opens
	// its seed blob in-process.
	profile := "userns-xhash-hmac-v1"
	err = triple.RegisterProfile(profile, triple.Profile{
		Mode:      "singlemsg-mac",
		Width:     256,
		InnerHash: "blake3",
		KeyBits:   512,
		MacName:   "xh_hmac",
	})
	if err != nil {
		t.Fatalf("RegisterProfile: %v", err)
	}
	p, blob, err := triple.Init(profile, triple.Opts{})
	if err != nil {
		t.Fatalf("triple.Init: %v", err)
	}
	defer p.Close()
	plain := []byte("custom-hash-derived MAC through the Triple pipeline")
	wire, err := p.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := p.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("decrypt mismatch on originating pipeline")
	}
	p2, err := triple.Open(profile, blob, triple.Opts{})
	if err != nil {
		t.Fatalf("triple.Open: %v", err)
	}
	defer p2.Close()
	got2, err := p2.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage on reopened pipeline: %v", err)
	}
	if !bytes.Equal(got2, plain) {
		t.Fatal("decrypt mismatch on reopened pipeline")
	}
}

// TestBuildKeyedHashWithRegisteredCustomHash exercises the
// cross-package keyed-mode path: a custom hash registered with a
// populated KeyedHash field (exact-32-byte key contract) composes
// through macs.BuildKeyedHash, the key-geometry defaults are
// discovered from the constructor (MinKeyBytes falls back to KeySize
// because the constructor rejects a 16-byte key), and the tag matches
// the same keyed construction invoked directly.
func TestBuildKeyedHashWithRegisteredCustomHash(t *testing.T) {
	newKeyed := func(key []byte) (hash.Hash, error) {
		if len(key) != 32 {
			return nil, errKeyLen(len(key))
		}
		return hmac.New(sha256.New, key), nil
	}
	err := hashes.Register(hashes.Spec{
		Name:        "xh_keyed",
		Width:       hashes.W256,
		Make256Pair: sha256ARXFactory(),
		KeyedHash:   newKeyed,
	})
	if err != nil {
		t.Fatalf("hashes.Register: %v", err)
	}

	spec, err := macs.BuildKeyedHash("xh_keyed", macs.KeyedHashSpec{Name: "xh_khmac", KeySize: 32})
	if err != nil {
		t.Fatalf("BuildKeyedHash(custom hash): %v", err)
	}
	if spec.KeySize != 32 || spec.TagSize != 32 || spec.MinKeyBytes != 32 {
		t.Fatalf("spec sizes = %d/%d/%d, want 32/32/32 (exact-key contract)",
			spec.KeySize, spec.TagSize, spec.MinKeyBytes)
	}
	if err := macs.Register(spec); err != nil {
		t.Fatalf("macs.Register: %v", err)
	}

	key := bytes.Repeat([]byte{0x6B}, 32)
	mac, err := macs.Make("xh_khmac", key)
	if err != nil {
		t.Fatalf("Make: %v", err)
	}
	msg := []byte("cross-package custom keyed-hash probe")
	ref, _ := newKeyed(key)
	ref.Write(msg)
	if !bytes.Equal(mac(msg), ref.Sum(nil)) {
		t.Fatal("tag does not match the keyed construction invoked directly")
	}

	// An explicit KeySize the constructor rejects fails at build time.
	if _, err := macs.BuildKeyedHash("xh_keyed", macs.KeyedHashSpec{Name: "xh_bad", KeySize: 16}); err == nil {
		t.Error("BuildKeyedHash(xh_keyed, KeySize 16): expected error (exact 32-byte key)")
	}
}

// errKeyLen is a plain error type for the exact-key test constructor.
type errKeyLen int

func (e errKeyLen) Error() string { return "xh_keyed key must be exactly 32 bytes" }

// TestBuildKeyedHashRequiresExplicitKeySize pins the removal of
// implicit key-size discovery: [macs.BuildKeyedHash] no longer walks
// a probe ladder when KeyedHashSpec.KeySize is zero. The caller must
// supply an explicit KeySize matching a length the primitive's keyed
// constructor accepts, and any explicit value the constructor
// accepts continues to build a working Spec — exercised here by
// registering a 48-byte-key custom primitive and building it under
// explicit KeySize=48.
func TestBuildKeyedHashRequiresExplicitKeySize(t *testing.T) {
	newKeyed := func(key []byte) (hash.Hash, error) {
		if len(key) != 48 {
			return nil, errKeyLen(len(key))
		}
		return hmac.New(sha256.New, key), nil
	}
	err := hashes.Register(hashes.Spec{
		Name:        "xh_key48",
		Width:       hashes.W256,
		Make256Pair: sha256ARXFactory(),
		KeyedHash:   newKeyed,
	})
	if err != nil {
		t.Fatalf("hashes.Register: %v", err)
	}
	// Zero KeySize surfaces the directive error — no implicit
	// discovery.
	_, err = macs.BuildKeyedHash("xh_key48", macs.KeyedHashSpec{Name: "xh_k48"})
	if err == nil || !strings.Contains(err.Error(), "KeyedHashSpec.KeySize is required") {
		t.Fatalf("zero-KeySize build: got %v, want required-KeySize directive error", err)
	}
	// Explicit KeySize matching the constructor's contract still
	// works.
	spec, err := macs.BuildKeyedHash("xh_key48", macs.KeyedHashSpec{Name: "xh_k48", KeySize: 48})
	if err != nil {
		t.Fatalf("BuildKeyedHash(KeySize 48): %v", err)
	}
	if spec.KeySize != 48 || spec.MinKeyBytes != 48 || spec.TagSize != 32 {
		t.Fatalf("spec sizes = %d/%d/%d, want 48/48/32",
			spec.KeySize, spec.MinKeyBytes, spec.TagSize)
	}
	if err := macs.Register(spec); err != nil {
		t.Fatalf("macs.Register: %v", err)
	}
	if _, err := macs.Make("xh_k48", bytes.Repeat([]byte{0x21}, 48)); err != nil {
		t.Fatalf("Make with 48-byte key: %v", err)
	}
	// The same discipline applies to a shipped primitive: zero
	// KeySize errors, explicit KeySize builds.
	if _, err := macs.BuildKeyedHash("blake3", macs.KeyedHashSpec{Name: "kh_bl3_missing"}); err == nil ||
		!strings.Contains(err.Error(), "KeyedHashSpec.KeySize is required") {
		t.Fatalf("blake3 zero-KeySize build: got %v, want required-KeySize directive error", err)
	}
}

// TestBuildersRejectPrimitivesWithoutForm pins the rejection wording
// for primitives that lack the composition form each builder needs:
// shipped entries without the form, an unknown name, and a custom
// hash registered with neither optional field populated.
func TestBuildersRejectPrimitivesWithoutForm(t *testing.T) {
	if _, err := macs.BuildHMAC("areion256", macs.HMACSpec{Name: "rj_a"}); err == nil ||
		!strings.Contains(err.Error(), "no unkeyed hash.Hash form") {
		t.Errorf("BuildHMAC(areion256): got %v, want no-hash.Hash-form error", err)
	}
	if _, err := macs.BuildKeyedHash("areion256", macs.KeyedHashSpec{Name: "rj_b"}); err == nil ||
		!strings.Contains(err.Error(), "no native keyed-hash form") {
		t.Errorf("BuildKeyedHash(areion256): got %v, want no-keyed-form error", err)
	}
	if _, err := macs.BuildHMAC("siphash24", macs.HMACSpec{Name: "rj_c"}); err == nil ||
		!strings.Contains(err.Error(), "no unkeyed hash.Hash form") {
		t.Errorf("BuildHMAC(siphash24): got %v, want no-hash.Hash-form error", err)
	}
	if _, err := macs.BuildHMAC("rj_missing", macs.HMACSpec{Name: "rj_d"}); err == nil ||
		!strings.Contains(err.Error(), "unknown hash primitive") {
		t.Errorf("BuildHMAC(rj_missing): got %v, want unknown-primitive error", err)
	}
	if _, err := macs.BuildKeyedHash("rj_missing", macs.KeyedHashSpec{Name: "rj_e"}); err == nil ||
		!strings.Contains(err.Error(), "unknown hash primitive") {
		t.Errorf("BuildKeyedHash(rj_missing): got %v, want unknown-primitive error", err)
	}

	// A custom hash registered without either composition field is
	// resolvable by hashes.Find yet rejected by both builders.
	err := hashes.Register(hashes.Spec{
		Name:        "xh_bare",
		Width:       hashes.W256,
		Make256Pair: sha256ARXFactory(),
	})
	if err != nil {
		t.Fatalf("hashes.Register: %v", err)
	}
	if _, err := macs.BuildHMAC("xh_bare", macs.HMACSpec{Name: "rj_f"}); err == nil ||
		!strings.Contains(err.Error(), "no unkeyed hash.Hash form") {
		t.Errorf("BuildHMAC(xh_bare): got %v, want no-hash.Hash-form error", err)
	}
	if _, err := macs.BuildKeyedHash("xh_bare", macs.KeyedHashSpec{Name: "rj_g"}); err == nil ||
		!strings.Contains(err.Error(), "no native keyed-hash form") {
		t.Errorf("BuildKeyedHash(xh_bare): got %v, want no-keyed-form error", err)
	}
}
