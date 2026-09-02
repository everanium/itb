package macs_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/blake2b"

	"github.com/everanium/itb"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/triple"
)

// stubFactory returns a valid deterministic 32-byte-tag MakeMAC
// factory (HMAC-SHA256 over the stdlib) for validation-table cases
// that exercise fields other than the factory itself.
func stubFactory() func(key []byte) (itb.MACFunc, error) {
	return func(key []byte) (itb.MACFunc, error) {
		keyCopy := append([]byte(nil), key...)
		return func(data []byte) []byte {
			h := hmac.New(sha256.New, keyCopy)
			h.Write(data)
			return h.Sum(nil)
		}, nil
	}
}

// TestRegisterRoundtripBuildHMAC registers a BuildHMAC-produced
// custom primitive and exercises the full name-keyed path: Find
// resolves it, Make / MakeIncremental build working closures,
// determinism and constant tag length hold, the incremental arm
// matches the one-shot arm over a multi-chunk split, and the tag
// matches an independently computed HMAC reference byte-for-byte.
func TestRegisterRoundtripBuildHMAC(t *testing.T) {
	spec, err := macs.BuildHMAC("blake2b256", macs.HMACSpec{Name: "rt_hmac_b2b"})
	if err != nil {
		t.Fatalf("BuildHMAC: %v", err)
	}
	if err := macs.Register(spec); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok := macs.Find("rt_hmac_b2b")
	if !ok {
		t.Fatal("Find(rt_hmac_b2b): not found after Register")
	}
	if got.KeySize != 32 || got.TagSize != 32 || got.MinKeyBytes != 16 {
		t.Fatalf("Find spec sizes = %d/%d/%d, want 32/32/16",
			got.KeySize, got.TagSize, got.MinKeyBytes)
	}

	key := make([]byte, got.KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	mac, err := macs.Make("rt_hmac_b2b", key)
	if err != nil {
		t.Fatalf("Make: %v", err)
	}
	inc, err := macs.MakeIncremental("rt_hmac_b2b", key)
	if err != nil {
		t.Fatalf("MakeIncremental: %v", err)
	}

	msg := []byte("the quick brown fox jumps over the lazy dog")
	tag := mac(msg)
	if len(tag) != got.TagSize {
		t.Fatalf("tag len = %d, want %d", len(tag), got.TagSize)
	}
	if !bytes.Equal(tag, mac(msg)) {
		t.Fatal("determinism: two calls over the same input disagree")
	}
	if !bytes.Equal(tag, inc(msg[:7], msg[7:20], msg[20:])) {
		t.Fatal("incremental arm diverges from one-shot arm")
	}

	// Independent HMAC-BLAKE2b-256 reference.
	ref := hmac.New(func() hash.Hash {
		hh, _ := blake2b.New256(nil)
		return hh
	}, key)
	ref.Write(msg)
	if !bytes.Equal(tag, ref.Sum(nil)) {
		t.Fatal("tag does not match independent HMAC-BLAKE2b-256 reference")
	}
}

// TestRegisterValidation exercises every static-field rejection path
// plus duplicate and shipped-name shadowing.
func TestRegisterValidation(t *testing.T) {
	valid := func() macs.Spec {
		return macs.Spec{
			Name: "vtbl_ok", KeySize: 32, TagSize: 32, MinKeyBytes: 16,
			MakeMAC: stubFactory(),
		}
	}
	cases := []struct {
		label   string
		mutate  func(*macs.Spec)
		wantSub string
	}{
		{"empty-name", func(s *macs.Spec) { s.Name = "" }, "Name is empty"},
		{"hyphen", func(s *macs.Spec) { s.Name = "bad-name" }, "illegal character"},
		{"uppercase", func(s *macs.Spec) { s.Name = "BadName" }, "illegal character"},
		{"too-long", func(s *macs.Spec) { s.Name = "a234567890123" }, "exceeds"},
		{"min-key-floor", func(s *macs.Spec) { s.MinKeyBytes = 8 }, "MinKeyBytes"},
		{"key-below-min", func(s *macs.Spec) { s.KeySize = 16; s.MinKeyBytes = 32 }, "KeySize"},
		{"tag-floor", func(s *macs.Spec) { s.TagSize = 15 }, "TagSize"},
		{"tag-ceiling", func(s *macs.Spec) { s.TagSize = 65 }, "TagSize"},
		{"nil-make", func(s *macs.Spec) { s.MakeMAC = nil }, "MakeMAC is nil"},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			s := valid()
			c.mutate(&s)
			err := macs.Register(s)
			if err == nil {
				t.Fatalf("Register accepted invalid spec %+v", s)
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Fatalf("error %v, want substring %q", err, c.wantSub)
			}
		})
	}

	// Duplicate registration.
	dup := valid()
	dup.Name = "dup_name0"
	if err := macs.Register(dup); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	err := macs.Register(dup)
	if !errors.Is(err, macs.ErrMACExists) {
		t.Fatalf("duplicate Register: got %v, want ErrMACExists", err)
	}

	// Shipped-name shadowing.
	shadow := valid()
	shadow.Name = "kmac256"
	err = macs.Register(shadow)
	if !errors.Is(err, macs.ErrMACExists) {
		t.Fatalf("shadow Register: got %v, want ErrMACExists", err)
	}
	if !strings.Contains(err.Error(), "shadows shipped") {
		t.Fatalf("shadow Register error %v, want shadow wording", err)
	}
}

// TestRegisterSmokeFailures confirms the register-time smoke
// validation rejects factories violating the closure contracts:
// wrong tag length, non-determinism, and a user-supplied incremental
// arm that diverges from the one-shot arm.
func TestRegisterSmokeFailures(t *testing.T) {
	t.Run("bad-tag-length", func(t *testing.T) {
		err := macs.Register(macs.Spec{
			Name: "smoke_badtag", KeySize: 32, TagSize: 32, MinKeyBytes: 16,
			MakeMAC: func(key []byte) (itb.MACFunc, error) {
				return func(data []byte) []byte { return make([]byte, 16) }, nil
			},
		})
		if err == nil || !strings.Contains(err.Error(), "tag length") {
			t.Fatalf("got %v, want tag-length error", err)
		}
	})
	t.Run("non-deterministic", func(t *testing.T) {
		err := macs.Register(macs.Spec{
			Name: "smoke_nondet", KeySize: 32, TagSize: 32, MinKeyBytes: 16,
			MakeMAC: func(key []byte) (itb.MACFunc, error) {
				var ctr byte
				return func(data []byte) []byte {
					out := make([]byte, 32)
					ctr++
					out[0] = ctr
					return out
				}, nil
			},
		})
		if err == nil || !strings.Contains(err.Error(), "non-deterministic") {
			t.Fatalf("got %v, want non-determinism error", err)
		}
	})
	t.Run("incremental-drift", func(t *testing.T) {
		err := macs.Register(macs.Spec{
			Name: "smoke_drift", KeySize: 32, TagSize: 32, MinKeyBytes: 16,
			MakeMAC: stubFactory(),
			MakeIncrementalMAC: func(key []byte) (itb.MACIncrementalFunc, error) {
				mac, _ := stubFactory()(key)
				return func(chunks ...[]byte) []byte {
					// Deliberately drops every chunk after the first.
					if len(chunks) == 0 {
						return mac(nil)
					}
					return mac(chunks[0])
				}, nil
			},
		})
		if err == nil || !strings.Contains(err.Error(), "diverges") {
			t.Fatalf("got %v, want cross-arm divergence error", err)
		}
	})
}

// TestSynthesizedIncremental registers a one-shot-only Spec and
// confirms MakeIncremental returns a working synthesized concat arm
// equivalent to the one-shot arm over arbitrary splits, including
// zero chunks and empty chunks.
func TestSynthesizedIncremental(t *testing.T) {
	err := macs.Register(macs.Spec{
		Name: "syn_inc", KeySize: 32, TagSize: 32, MinKeyBytes: 16,
		MakeMAC: stubFactory(),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	key := bytes.Repeat([]byte{0x42}, 32)
	mac, err := macs.Make("syn_inc", key)
	if err != nil {
		t.Fatalf("Make: %v", err)
	}
	inc, err := macs.MakeIncremental("syn_inc", key)
	if err != nil {
		t.Fatalf("MakeIncremental: %v", err)
	}
	msg := []byte("synthesized incremental equivalence probe")
	if !bytes.Equal(mac(msg), inc(msg[:1], []byte{}, msg[1:9], msg[9:])) {
		t.Fatal("synthesized incremental arm diverges from one-shot arm")
	}
	if !bytes.Equal(mac(nil), inc()) {
		t.Fatal("synthesized incremental arm over zero chunks != one-shot over empty input")
	}
}

// TestBuildKeyedHashVariants exercises the keyed-hash builder across
// tag geometries and key contracts: a 64-byte-tag primitive, a
// 16-byte-tag exact-key primitive, and the BLAKE3 keyed mode
// cross-validated byte-for-byte against the shipped hmac-blake3
// factory under the same key.
func TestBuildKeyedHashVariants(t *testing.T) {
	t.Run("blake2b512-64-byte-tag", func(t *testing.T) {
		spec, err := macs.BuildKeyedHash("blake2b512", macs.KeyedHashSpec{Name: "kh_b2b512"})
		if err != nil {
			t.Fatalf("BuildKeyedHash: %v", err)
		}
		if spec.TagSize != 64 {
			t.Fatalf("TagSize = %d, want 64", spec.TagSize)
		}
		if err := macs.Register(spec); err != nil {
			t.Fatalf("Register: %v", err)
		}
		key := bytes.Repeat([]byte{0x24}, 32)
		mac, err := macs.Make("kh_b2b512", key)
		if err != nil {
			t.Fatalf("Make: %v", err)
		}
		if got := len(mac([]byte("x"))); got != 64 {
			t.Fatalf("tag len = %d, want 64", got)
		}
		// Independent keyed-BLAKE2b-512 reference.
		ref, _ := blake2b.New512(key)
		ref.Write([]byte("x"))
		if !bytes.Equal(mac([]byte("x")), ref.Sum(nil)) {
			t.Fatal("tag does not match independent keyed BLAKE2b-512 reference")
		}
	})
	t.Run("siphash24-16-byte-tag", func(t *testing.T) {
		spec, err := macs.BuildKeyedHash("siphash24", macs.KeyedHashSpec{Name: "kh_sip"})
		if err != nil {
			t.Fatalf("BuildKeyedHash: %v", err)
		}
		if spec.TagSize != 16 || spec.KeySize != 16 || spec.MinKeyBytes != 16 {
			t.Fatalf("spec sizes = %d/%d/%d, want 16/16/16",
				spec.TagSize, spec.KeySize, spec.MinKeyBytes)
		}
		if err := macs.Register(spec); err != nil {
			t.Fatalf("Register: %v", err)
		}
		key := bytes.Repeat([]byte{0x77}, 16)
		mac, inc, _, err := macs.MakeMACPair("kh_sip", key)
		if err != nil {
			t.Fatalf("MakeMACPair: %v", err)
		}
		msg := []byte("siphash 128-bit keyed probe")
		if got := len(mac(msg)); got != 16 {
			t.Fatalf("tag len = %d, want 16", got)
		}
		if !bytes.Equal(mac(msg), inc(msg[:5], msg[5:])) {
			t.Fatal("incremental arm diverges from one-shot arm")
		}
	})
	t.Run("blake3-matches-shipped", func(t *testing.T) {
		spec, err := macs.BuildKeyedHash("blake3", macs.KeyedHashSpec{Name: "xv_blake3"})
		if err != nil {
			t.Fatalf("BuildKeyedHash: %v", err)
		}
		if err := macs.Register(spec); err != nil {
			t.Fatalf("Register: %v", err)
		}
		key := bytes.Repeat([]byte{0x5A}, 32)
		custom, err := macs.Make("xv_blake3", key)
		if err != nil {
			t.Fatalf("Make: %v", err)
		}
		shipped, err := macs.HMACBLAKE3(key)
		if err != nil {
			t.Fatalf("HMACBLAKE3: %v", err)
		}
		for _, msg := range [][]byte{nil, []byte("a"), bytes.Repeat([]byte{0xC3}, 4096)} {
			if !bytes.Equal(custom(msg), shipped(msg)) {
				t.Fatalf("BuildKeyedHash(blake3) diverges from shipped hmac-blake3 on %d-byte input", len(msg))
			}
		}
	})
}

// TestBuilderErrors exercises the builder-side rejection paths:
// primitives without the required form, tag-size overrides that
// demand truncation, and key-size overrides on exact-key primitives.
func TestBuilderErrors(t *testing.T) {
	if _, err := macs.BuildHMAC("areion256", macs.HMACSpec{Name: "be_a"}); err == nil {
		t.Error("BuildHMAC(areion256): expected error (no hash.Hash form)")
	}
	if _, err := macs.BuildHMAC("nonsense", macs.HMACSpec{Name: "be_b"}); err == nil {
		t.Error("BuildHMAC(nonsense): expected error")
	}
	if _, err := macs.BuildHMAC("blake2b256", macs.HMACSpec{Name: "be_c", TagSize: 64}); err == nil {
		t.Error("BuildHMAC TagSize 64 over 32-byte hash: expected error")
	}
	if _, err := macs.BuildKeyedHash("chacha20", macs.KeyedHashSpec{Name: "be_d"}); err == nil {
		t.Error("BuildKeyedHash(chacha20): expected error (no keyed-hash form)")
	}
	if _, err := macs.BuildKeyedHash("blake3", macs.KeyedHashSpec{Name: "be_e", KeySize: 64}); err == nil {
		t.Error("BuildKeyedHash(blake3, KeySize 64): expected error (exact 32-byte key)")
	}
	if _, err := macs.BuildKeyedHash("siphash24", macs.KeyedHashSpec{Name: "be_f", KeySize: 32}); err == nil {
		t.Error("BuildKeyedHash(siphash24, KeySize 32): expected error (exact 16-byte key)")
	}
	if _, err := macs.BuildKeyedHash("blake2b256", macs.KeyedHashSpec{Name: "be_g", KeySize: 96}); err == nil {
		t.Error("BuildKeyedHash(blake2b256, KeySize 96): expected error (64-byte ceiling)")
	}
	if _, err := macs.BuildKeyedHash("blake2b256", macs.KeyedHashSpec{Name: "be_h", TagSize: 16}); err == nil {
		t.Error("BuildKeyedHash(blake2b256, TagSize 16): expected error (truncation unsupported)")
	}
}

// TestMakeMACPair exercises the convenience dispatcher for shipped
// and custom names plus its error paths.
func TestMakeMACPair(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	mac, inc, spec, err := macs.MakeMACPair("kmac256", key)
	if err != nil {
		t.Fatalf("MakeMACPair(kmac256): %v", err)
	}
	if spec.Name != "kmac256" || spec.TagSize != 32 {
		t.Fatalf("spec = %+v, want kmac256/32", spec)
	}
	msg := []byte("pair dispatch probe")
	if !bytes.Equal(mac(msg), inc(msg[:3], msg[3:])) {
		t.Fatal("kmac256 pair arms diverge")
	}
	if _, _, _, err := macs.MakeMACPair("nonsense", key); err == nil {
		t.Error("MakeMACPair(nonsense): expected error")
	}
	if _, _, _, err := macs.MakeMACPair("kmac256", key[:8]); err == nil {
		t.Error("MakeMACPair(kmac256, 8-byte key): expected error")
	}
}

// TestCustomKeyLengthGate confirms the existing MinKeyBytes gate in
// Make / MakeIncremental covers user-registered primitives.
func TestCustomKeyLengthGate(t *testing.T) {
	err := macs.Register(macs.Spec{
		Name: "gate_short", KeySize: 32, TagSize: 32, MinKeyBytes: 24,
		MakeMAC: stubFactory(),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, err := macs.Make("gate_short", make([]byte, 16)); err == nil ||
		!strings.Contains(err.Error(), "too short") {
		t.Fatalf("Make(gate_short, 16-byte key): got %v, want key-too-short error", err)
	}
	if _, err := macs.MakeIncremental("gate_short", make([]byte, 16)); err == nil ||
		!strings.Contains(err.Error(), "too short") {
		t.Fatalf("MakeIncremental(gate_short, 16-byte key): got %v, want key-too-short error", err)
	}
}

// TestRegisterTripleIntegration routes a registered custom MAC
// through the Triple pipeline end-to-end: profile registration with
// the custom MacName, session initialisation, Single Message
// encrypt / decrypt round-trip, and blob re-open in-process.
func TestRegisterTripleIntegration(t *testing.T) {
	spec, err := macs.BuildKeyedHash("blake2s", macs.KeyedHashSpec{Name: "it_kh_b2s"})
	if err != nil {
		t.Fatalf("BuildKeyedHash: %v", err)
	}
	if err := macs.Register(spec); err != nil {
		t.Fatalf("Register: %v", err)
	}

	profile := "userns-macs-custom-mac-v1"
	err = triple.RegisterProfile(profile, triple.Profile{
		Mode:      "singlemsg-mac",
		Width:     256,
		InnerHash: "blake3",
		KeyBits:   512,
		MacName:   "it_kh_b2s",
	})
	if err != nil {
		t.Fatalf("RegisterProfile with custom MacName: %v", err)
	}

	p, blob, err := triple.Init(profile, triple.Opts{})
	if err != nil {
		t.Fatalf("triple.Init: %v", err)
	}
	defer p.Close()

	msg := []byte("custom-MAC Single Message round-trip through the Triple pipeline")
	wire, err := p.EncryptMessage(msg)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := p.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("decrypt mismatch on originating pipeline")
	}

	p2, err := triple.Open(profile, blob, triple.Opts{})
	if err != nil {
		t.Fatalf("triple.Open with custom MacName blob: %v", err)
	}
	defer p2.Close()
	got2, err := p2.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage on reopened pipeline: %v", err)
	}
	if !bytes.Equal(got2, msg) {
		t.Fatal("decrypt mismatch on reopened pipeline")
	}
}

// TestRegisterConcurrency races parallel Register calls (unique
// names) against parallel Find / Make traffic on shipped and custom
// names. Run with -race in the standard suite.
func TestRegisterConcurrency(t *testing.T) {
	const n = 8
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("conc_%d", i)
		wg.Add(1)
		go func() {
			defer wg.Done()
			spec, err := macs.BuildKeyedHash("blake2b256", macs.KeyedHashSpec{Name: name})
			if err != nil {
				t.Errorf("BuildKeyedHash(%s): %v", name, err)
				return
			}
			if err := macs.Register(spec); err != nil {
				t.Errorf("Register(%s): %v", name, err)
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Shipped lookups and dispatch race the registrations.
			if _, ok := macs.Find("hmac-sha256"); !ok {
				t.Error("Find(hmac-sha256) failed during concurrent Register")
			}
			if _, err := macs.Make("kmac256", bytes.Repeat([]byte{1}, 32)); err != nil {
				t.Errorf("Make(kmac256) during concurrent Register: %v", err)
			}
			macs.Find(name) // may miss before registration lands; must not race
		}()
	}
	wg.Wait()
	key := bytes.Repeat([]byte{0x33}, 32)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("conc_%d", i)
		if _, ok := macs.Find(name); !ok {
			t.Errorf("Find(%s) after concurrent Register: not found", name)
		}
		if _, err := macs.Make(name, key); err != nil {
			t.Errorf("Make(%s): %v", name, err)
		}
	}
}

// TestRegistryInvariantAfterRegister pins the FFI iteration contract:
// Register never grows or mutates the shipped Registry array, and
// shipped entries keep nil factory fields.
func TestRegistryInvariantAfterRegister(t *testing.T) {
	err := macs.Register(macs.Spec{
		Name: "inv_probe", KeySize: 32, TagSize: 32, MinKeyBytes: 16,
		MakeMAC: stubFactory(),
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(macs.Registry) != 3 {
		t.Fatalf("len(Registry) = %d after Register, want 3", len(macs.Registry))
	}
	wantNames := []string{"kmac256", "hmac-sha256", "hmac-blake3"}
	for i, want := range wantNames {
		if macs.Registry[i].Name != want {
			t.Errorf("Registry[%d].Name = %q, want %q", i, macs.Registry[i].Name, want)
		}
		if macs.Registry[i].MakeMAC != nil || macs.Registry[i].MakeIncrementalMAC != nil {
			t.Errorf("Registry[%d] %s: factory fields must stay nil", i, macs.Registry[i].Name)
		}
	}
	// Shipped resolution is unaffected by the customs fallthrough.
	spec, ok := macs.Find("hmac-blake3")
	if !ok || spec.TagSize != 32 || spec.MinKeyBytes != 32 {
		t.Fatalf("Find(hmac-blake3) = %+v, %v — shipped resolution regressed", spec, ok)
	}
}
