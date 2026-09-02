package hashes

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/everanium/itb"
)

// customFactoryName is the base for unique Spec.Name identifiers used
// in Register tests. Each test that mutates the customs slice appends
// its own suffix so parallel `go test` runs do not collide.
const customFactoryName = "rt_"

// makeCustom256PairFactory returns a Make256Pair-shaped factory that
// wraps the ARX builder around a SHA-256 one-shot. The factory is
// deterministic once the CSPRNG-generated fixedKey is fixed, so the
// same key input yields the same closure output — enough for the
// round-trip assertions below without pulling in a full custom PRF
// implementation.
func makeCustom256PairFactory() func(key ...[]byte) (itb.HashFunc256, itb.BatchHashFunc256, []byte, error) {
	return func(key ...[]byte) (itb.HashFunc256, itb.BatchHashFunc256, []byte, error) {
		var fixedKey []byte
		if len(key) == 0 {
			fixedKey = make([]byte, 32)
			if _, err := rand.Read(fixedKey); err != nil {
				return nil, nil, nil, err
			}
		} else {
			if len(key[0]) != 32 {
				return nil, nil, nil, fmt.Errorf("custom test factory: key must be 32 bytes, got %d", len(key[0]))
			}
			fixedKey = append([]byte(nil), key[0]...)
		}
		fn := BuildARXChainAbsorb256(sha256.Sum256, fixedKey)
		return fn, nil, fixedKey, nil
	}
}

// TestRegisterRoundtrip registers a custom SHA-256-backed HashFunc256
// primitive and confirms it round-trips through Find, Make256Pair, and
// a full Triple Ouroboros encrypt/decrypt on the shipped 256-bit path.
func TestRegisterRoundtrip(t *testing.T) {
	name := customFactoryName + "roundtrip"
	spec := Spec{
		Name:        name,
		Width:       W256,
		Make256Pair: makeCustom256PairFactory(),
	}
	if err := Register(spec); err != nil {
		t.Fatalf("Register(%q): %v", name, err)
	}

	got, ok := Find(name)
	if !ok {
		t.Fatalf("Find(%q): not found after Register", name)
	}
	if got.Name != name || got.Width != W256 {
		t.Fatalf("Find(%q) = %+v, want Name=%q Width=W256", name, got, name)
	}
	if got.Make256Pair == nil {
		t.Fatalf("Find(%q): Make256Pair factory field nil after Register", name)
	}

	// Make256Pair name-keyed dispatch must reach the registered factory.
	h, _, keyBytes, err := Make256Pair(name)
	if err != nil {
		t.Fatalf("Make256Pair(%q): %v", name, err)
	}
	if len(keyBytes) != 32 {
		t.Fatalf("Make256Pair(%q): fixedKey len=%d, want 32", name, len(keyBytes))
	}

	// Make256 (non-Pair) must also resolve the custom Spec.
	h2, keyBytes2, err := Make256(name)
	if err != nil {
		t.Fatalf("Make256(%q): %v", name, err)
	}
	if len(keyBytes2) != 32 {
		t.Fatalf("Make256(%q): fixedKey len=%d, want 32", name, len(keyBytes2))
	}
	_ = h2

	// Full Triple 3x256 encrypt/decrypt round-trip using the registered
	// primitive across all 8 seed slots. The identical fixed key on
	// each slot keeps the test hermetic — different slots receive
	// different Components via NewSeed256, so ChainHash still evolves
	// per slot as expected.
	mk := func() *itb.Seed256 {
		fn, _, _, err := Make256Pair(name, keyBytes)
		if err != nil {
			t.Fatalf("Make256Pair(%q, key): %v", name, err)
		}
		s, err := itb.NewSeed256(1024, fn)
		if err != nil {
			t.Fatalf("NewSeed256: %v", err)
		}
		return s
	}
	ns, ls := mk(), mk()
	d1, d2, d3 := mk(), mk(), mk()
	s1, s2, s3 := mk(), mk(), mk()

	plaintext := []byte("Register API round-trip through a user-supplied SHA-256 wrapper")
	ct, err := itb.Encrypt3x256Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3x256Cfg: %v", err)
	}
	pt, err := itb.Decrypt3x256Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x256Cfg: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("Register(%q) round-trip: plaintext mismatch", name)
	}

	_ = h
}

// TestRegisterAppearsInAllPrimitives confirms that a registered custom
// primitive shows up in AllPrimitives() after the shipped Registry
// entries and is absent from the immutable Registry itself.
func TestRegisterAppearsInAllPrimitives(t *testing.T) {
	name := customFactoryName + "allp"
	spec := Spec{
		Name:        name,
		Width:       W256,
		Make256Pair: makeCustom256PairFactory(),
	}
	if err := Register(spec); err != nil {
		t.Fatalf("Register(%q): %v", name, err)
	}
	// Shipped Registry stays untouched.
	for _, s := range Registry {
		if s.Name == name {
			t.Fatalf("Registry unexpectedly grew a user-registered entry %q", name)
		}
	}
	// AllPrimitives snapshot includes the registered entry after the
	// shipped ones.
	snap := AllPrimitives()
	found := -1
	for i, s := range snap {
		if s.Name == name {
			found = i
			break
		}
	}
	if found < 0 {
		t.Fatalf("AllPrimitives(): missing registered %q", name)
	}
	if found < len(Registry) {
		t.Fatalf("AllPrimitives(): registered %q at index %d, want >= %d (after shipped set)", name, found, len(Registry))
	}
	// Snapshot is a fresh copy — mutating the returned slice must not
	// affect a subsequent snapshot.
	snap[0].Name = "tampered"
	snap2 := AllPrimitives()
	if snap2[0].Name == "tampered" {
		t.Fatalf("AllPrimitives(): returned slice shares backing storage with subsequent snapshot")
	}
}

// TestRegisterRejectsDuplicate confirms that Register refuses to
// overwrite a previously-registered primitive and refuses to shadow a
// shipped Registry entry.
func TestRegisterRejectsDuplicate(t *testing.T) {
	name := customFactoryName + "duplicate"
	spec := Spec{
		Name:        name,
		Width:       W256,
		Make256Pair: makeCustom256PairFactory(),
	}
	if err := Register(spec); err != nil {
		t.Fatalf("Register(%q) first call: %v", name, err)
	}
	if err := Register(spec); !errors.Is(err, ErrHashExists) {
		t.Fatalf("Register(%q) second call: err=%v, want ErrHashExists", name, err)
	}
	// Shadowing a shipped primitive is also refused with ErrHashExists.
	spec.Name = "blake3"
	if err := Register(spec); !errors.Is(err, ErrHashExists) {
		t.Fatalf("Register(shipped-shadow): err=%v, want ErrHashExists", err)
	}
}

// TestRegisterValidatesSpec exercises every rejection path in
// validateRegisterSpec. Each sub-case constructs a Spec that violates
// exactly one invariant and confirms Register returns a non-nil error.
func TestRegisterValidatesSpec(t *testing.T) {
	good256 := makeCustom256PairFactory()
	cases := []struct {
		label string
		spec  Spec
	}{
		{"empty-name", Spec{Name: "", Width: W256, Make256Pair: good256}},
		{"name-too-long", Spec{Name: "abcdefghijklm", Width: W256, Make256Pair: good256}}, // 13 chars > MaxNameLen=12
		{"dash-in-name", Spec{Name: "bad-name", Width: W256, Make256Pair: good256}},
		{"uppercase-in-name", Spec{Name: "BadName", Width: W256, Make256Pair: good256}},
		{"space-in-name", Spec{Name: "bad name", Width: W256, Make256Pair: good256}},
		{"unsupported-width", Spec{Name: customFactoryName + "badwidth", Width: Width(64), Make256Pair: good256}},
		{"missing-factory-w256", Spec{Name: customFactoryName + "nofac256", Width: W256}},
		{"missing-factory-w128", Spec{Name: customFactoryName + "nofac128", Width: W128}},
		{"missing-factory-w512", Spec{Name: customFactoryName + "nofac512", Width: W512}},
		{"wrong-width-factory", Spec{Name: customFactoryName + "wrongwidth", Width: W128, Make256Pair: good256}},
		{"cross-width-factory", Spec{Name: customFactoryName + "crosswidth", Width: W256, Make128Pair: func(key ...[]byte) (itb.HashFunc128, itb.BatchHashFunc128, []byte, error) {
			return nil, nil, nil, nil
		}, Make256Pair: good256}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			if err := Register(tc.spec); err == nil {
				t.Fatalf("Register(%s): nil error, want validation error", tc.label)
			}
		})
	}
}

// TestRegisterConcurrent exercises the customsMu mutex path by running
// many parallel Register calls with unique names. Exactly one Register
// per name must succeed; duplicates return ErrHashExists. Run under
// -race to catch missing lock coverage.
func TestRegisterConcurrent(t *testing.T) {
	const N = 32
	factory := makeCustom256PairFactory()
	var wg sync.WaitGroup
	var success int32
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("%sconc_%d", customFactoryName, i)
			spec := Spec{Name: name, Width: W256, Make256Pair: factory}
			if err := Register(spec); err == nil {
				atomic.AddInt32(&success, 1)
			}
		}(i)
	}
	wg.Wait()
	if int(success) != N {
		t.Fatalf("Register concurrent: success=%d, want %d", success, N)
	}
	// A second concurrent pass at the same names must all fail with
	// ErrHashExists — no duplicate registration slips through.
	var dupOk int32
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := fmt.Sprintf("%sconc_%d", customFactoryName, i)
			spec := Spec{Name: name, Width: W256, Make256Pair: factory}
			if err := Register(spec); errors.Is(err, ErrHashExists) {
				atomic.AddInt32(&dupOk, 1)
			}
		}(i)
	}
	wg.Wait()
	if int(dupOk) != N {
		t.Fatalf("Register concurrent-duplicate: got %d ErrHashExists, want %d", dupOk, N)
	}
}

// TestRegisterMake128Pair confirms the 128-bit dispatch path resolves
// a registered custom primitive. Uses BuildCBCMACChainAbsorb128 over a
// trivial 16-byte identity permutation so the test does not import
// crypto/aes but still exercises the interface-callback factory shape.
func TestRegisterMake128Pair(t *testing.T) {
	name := customFactoryName + "make128"
	spec := Spec{
		Name:  name,
		Width: W128,
		Make128Pair: func(key ...[]byte) (itb.HashFunc128, itb.BatchHashFunc128, []byte, error) {
			var fixedKey [16]byte
			if len(key) > 0 {
				if len(key[0]) != 16 {
					return nil, nil, nil, fmt.Errorf("test factory: want 16-byte key, got %d", len(key[0]))
				}
				copy(fixedKey[:], key[0])
			} else if _, err := rand.Read(fixedKey[:]); err != nil {
				return nil, nil, nil, err
			}
			// Trivial closure — the point is exercising the dispatch,
			// not implementing a real CBC-MAC. Return a HashFunc128
			// that XORs the seed with a hash of data.
			fn := func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
				d := sha256.Sum256(append(fixedKey[:], data...))
				var a, b uint64
				for i := 0; i < 8; i++ {
					a |= uint64(d[i]) << (8 * i)
					b |= uint64(d[i+8]) << (8 * i)
				}
				return a ^ seed0, b ^ seed1
			}
			return fn, nil, fixedKey[:], nil
		},
	}
	if err := Register(spec); err != nil {
		t.Fatalf("Register(%q): %v", name, err)
	}
	h, _, key, err := Make128Pair(name)
	if err != nil {
		t.Fatalf("Make128Pair(%q): %v", name, err)
	}
	if h == nil || len(key) != 16 {
		t.Fatalf("Make128Pair(%q): h=%v, key len=%d", name, h, len(key))
	}

	// Wrong-width fall-through: Make256Pair for a W128 name must fail
	// with the width-mismatch error, not the unknown-name error.
	if _, _, _, err := Make256Pair(name); err == nil {
		t.Fatalf("Make256Pair(%q): nil error, want width-mismatch error", name)
	}
}

// TestRegisterSmokeRejectsNilSingleArm confirms [Register]'s smoke
// stage rejects a Make{N}Pair factory that returns a nil single-arm
// closure. Reaching Encrypt with a nil closure would deref-crash on
// the per-pixel hash call; the smoke check surfaces the bug at
// registration time.
func TestRegisterSmokeRejectsNilSingleArm(t *testing.T) {
	name := customFactoryName + "smoke_nil_single"
	spec := Spec{
		Name:  name,
		Width: W256,
		Make256Pair: func(key ...[]byte) (itb.HashFunc256, itb.BatchHashFunc256, []byte, error) {
			return nil, nil, make([]byte, 32), nil
		},
	}
	if err := Register(spec); err == nil {
		t.Fatalf("Register accepted a factory that returns a nil single-arm closure")
	}
}

// TestRegisterSmokeRejectsNonDeterministic confirms [Register]'s smoke
// stage rejects a Make{N}Pair factory whose single-arm output differs
// between two calls over the same seed / data. A non-deterministic hash
// closure would corrupt every ChainHash slot and desynchronise the
// sender / receiver pair; the smoke check surfaces the bug at
// registration time.
func TestRegisterSmokeRejectsNonDeterministic(t *testing.T) {
	name := customFactoryName + "smoke_nondet"
	counter := uint64(0)
	spec := Spec{
		Name:  name,
		Width: W256,
		Make256Pair: func(key ...[]byte) (itb.HashFunc256, itb.BatchHashFunc256, []byte, error) {
			// Fresh counter capture per factory invocation; the returned
			// closure increments state on every call so two invocations
			// with identical inputs disagree.
			var s uint64
			single := func(data []byte, seed [4]uint64) [4]uint64 {
				s++
				return [4]uint64{s + counter, 0, 0, 0}
			}
			return single, nil, make([]byte, 32), nil
		},
	}
	if err := Register(spec); err == nil {
		t.Fatalf("Register accepted a non-deterministic factory")
	}
}

// TestRegisterSmokeRejectsBatchedDivergence confirms [Register]'s
// smoke stage rejects a Make{N}Pair factory whose batched arm returns
// output that disagrees with the single arm over identical inputs.
// Divergence between the two arms would corrupt every per-pixel dispatch
// that fell into the batched code path; the smoke check surfaces the
// bug at registration time.
func TestRegisterSmokeRejectsBatchedDivergence(t *testing.T) {
	name := customFactoryName + "smoke_batched_diverge"
	spec := Spec{
		Name:  name,
		Width: W256,
		Make256Pair: func(key ...[]byte) (itb.HashFunc256, itb.BatchHashFunc256, []byte, error) {
			single := func(data []byte, seed [4]uint64) [4]uint64 {
				return [4]uint64{0xAAAA, 0, 0, 0}
			}
			batched := func(data *[4][]byte, seeds [4][4]uint64) [4][4]uint64 {
				// Deliberately different from single — every lane returns
				// a divergent tuple to trip the parity smoke.
				return [4][4]uint64{
					{0xBBBB, 0, 0, 0},
					{0xBBBB, 0, 0, 0},
					{0xBBBB, 0, 0, 0},
					{0xBBBB, 0, 0, 0},
				}
			}
			return single, batched, make([]byte, 32), nil
		},
	}
	if err := Register(spec); err == nil {
		t.Fatalf("Register accepted a factory whose batched arm diverges from the single arm")
	}
}

// TestRegisterMake512Pair mirrors TestRegisterMake128Pair for the
// 512-bit dispatch path.
func TestRegisterMake512Pair(t *testing.T) {
	name := customFactoryName + "make512"
	spec := Spec{
		Name:  name,
		Width: W512,
		Make512Pair: func(key ...[]byte) (itb.HashFunc512, itb.BatchHashFunc512, []byte, error) {
			var fixedKey [64]byte
			if len(key) > 0 {
				if len(key[0]) != 64 {
					return nil, nil, nil, fmt.Errorf("test factory: want 64-byte key, got %d", len(key[0]))
				}
				copy(fixedKey[:], key[0])
			} else if _, err := rand.Read(fixedKey[:]); err != nil {
				return nil, nil, nil, err
			}
			fn := BuildARXChainAbsorb512(func(d []byte) [64]byte {
				var out [64]byte
				h1 := sha256.Sum256(append([]byte{0x01}, d...))
				h2 := sha256.Sum256(append([]byte{0x02}, d...))
				copy(out[0:32], h1[:])
				copy(out[32:64], h2[:])
				return out
			}, fixedKey[:])
			return fn, nil, fixedKey[:], nil
		},
	}
	if err := Register(spec); err != nil {
		t.Fatalf("Register(%q): %v", name, err)
	}
	h, _, key, err := Make512Pair(name)
	if err != nil {
		t.Fatalf("Make512Pair(%q): %v", name, err)
	}
	if h == nil || len(key) != 64 {
		t.Fatalf("Make512Pair(%q): h=%v, key len=%d", name, h, len(key))
	}
}
