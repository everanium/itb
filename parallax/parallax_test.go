package parallax

import (
	"bytes"
	"crypto/rand"
	mrand "math/rand/v2"
	"testing"

	"github.com/everanium/itb/ctr"
)

// registryCanonical lists every primitive ctr.NewResettable currently
// accepts, in the project's canonical primitive order. The list is held
// inside _test.go only — package code never depends on it; the runtime
// path queries ctr.KeySize / ctr.NonceSize.
var registryCanonical = []string{
	ctr.CipherAreion256,
	ctr.CipherAreion512,
	ctr.CipherBLAKE2b256,
	ctr.CipherBLAKE2b512,
	ctr.CipherBLAKE2s,
	ctr.CipherBLAKE3,
	ctr.CipherAES128CTR,
	ctr.CipherSipHash24,
	ctr.CipherChaCha20,
}

func mustMaster(t *testing.T) []byte {
	t.Helper()
	master, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	return master
}

func mustSchedule(t *testing.T, palette []string, segSize int) *Schedule {
	t.Helper()
	s, err := NewSchedule(palette, segSize)
	if err != nil {
		t.Fatalf("NewSchedule(%v, %d): %v", palette, segSize, err)
	}
	return s
}

func mustCipherset(t *testing.T, master []byte, s *Schedule) *Cipherset {
	t.Helper()
	cs, err := NewCipherset(master, s)
	if err != nil {
		t.Fatalf("NewCipherset: %v", err)
	}
	return cs
}

func randomPlaintext(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return buf
}

// shuffledRegistry returns the canonical list permuted under a
// deterministic seed for reproducible test runs.
func shuffledRegistry(seed uint64) []string {
	r := mrand.New(mrand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	out := append([]string(nil), registryCanonical...)
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// drawWithReplacement returns n names drawn from the canonical
// registry under a deterministic seed.
func drawWithReplacement(seed uint64, n int) []string {
	r := mrand.New(mrand.NewPCG(seed, seed^0xbf58476d1ce4e5b9))
	out := make([]string, n)
	for i := range out {
		out[i] = registryCanonical[r.IntN(len(registryCanonical))]
	}
	return out
}

func roundTrip(t *testing.T, palette []string, sizes []int) {
	t.Helper()
	schedule := mustSchedule(t, palette, DefaultSegmentSize)
	master := mustMaster(t)
	cs := mustCipherset(t, master, schedule)
	for _, n := range sizes {
		pt := randomPlaintext(t, n)
		wire, err := schedule.Encrypt(pt, cs)
		if err != nil {
			t.Fatalf("Encrypt(N=%d, size=%d): %v", len(palette), n, err)
		}
		if len(wire) != NonceSize+n {
			t.Fatalf("wire length mismatch: got %d want %d", len(wire), NonceSize+n)
		}
		recovered, err := schedule.Decrypt(wire, cs)
		if err != nil {
			t.Fatalf("Decrypt(N=%d, size=%d): %v", len(palette), n, err)
		}
		if !bytes.Equal(pt, recovered) {
			t.Fatalf("round-trip mismatch (N=%d, size=%d)", len(palette), n)
		}
	}
}

func TestRoundTripPaletteCompositions(t *testing.T) {
	sizes := []int{1, 17, 18, 100, 1024, 65537, 1048577}
	cases := []struct {
		name    string
		palette []string
	}{
		{"N3-distinct", []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}},
		{"N9-shuffled-seed42", shuffledRegistry(42)},
		{"N9-shuffled-seed1337", shuffledRegistry(1337)},
		{"N24-replacement", drawWithReplacement(0xc0ffee, 24)},
		{"N36-replacement", drawWithReplacement(0xdecaf, 36)},
		{"N254-replacement", drawWithReplacement(0xfeedface, 254)},
		{"N3-duplicate-aescmac", []string{ctr.CipherAES128CTR, ctr.CipherAES128CTR, ctr.CipherAES128CTR}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			roundTrip(t, tc.palette, sizes)
		})
	}
}

func TestEncryptInPlaceRoundTrip(t *testing.T) {
	schedule := mustSchedule(t, shuffledRegistry(7), DefaultSegmentSize)
	cs := mustCipherset(t, mustMaster(t), schedule)
	for _, n := range []int{1, 17, 18, 100, 1024, 65537} {
		pt := randomPlaintext(t, n)
		buf := append([]byte(nil), pt...)
		wire, err := schedule.EncryptInPlace(buf, cs)
		if err != nil {
			t.Fatalf("EncryptInPlace(size=%d): %v", n, err)
		}
		if len(wire) != NonceSize+n {
			t.Fatalf("size=%d wire length %d want %d", n, len(wire), NonceSize+n)
		}
		// buf is documented as MUTATED; under non-zero plaintext the
		// post-call buf must differ from the original plaintext.
		if n > 0 && bytes.Equal(buf, pt) {
			t.Fatalf("EncryptInPlace did not mutate buf (size=%d)", n)
		}
		recovered, err := schedule.DecryptInPlace(wire, cs)
		if err != nil {
			t.Fatalf("DecryptInPlace(size=%d): %v", n, err)
		}
		if !bytes.Equal(pt, recovered) {
			t.Fatalf("InPlace round-trip mismatch (size=%d)", n)
		}
		// DecryptInPlace returns an aliased slice of the wire body.
		if n > 0 && &recovered[0] != &wire[NonceSize] {
			t.Fatalf("DecryptInPlace did not alias wire body (size=%d)", n)
		}
	}
}

func TestEmptyPlaintextRoundTrip(t *testing.T) {
	schedule := mustSchedule(t, []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}, DefaultSegmentSize)
	cs := mustCipherset(t, mustMaster(t), schedule)

	wire, err := schedule.Encrypt(nil, cs)
	if err != nil {
		t.Fatalf("Encrypt(nil): %v", err)
	}
	if len(wire) != NonceSize {
		t.Fatalf("Encrypt(nil) wire len=%d want %d", len(wire), NonceSize)
	}
	pt, err := schedule.Decrypt(wire, cs)
	if err != nil {
		t.Fatalf("Decrypt(nonce-only): %v", err)
	}
	if len(pt) != 0 {
		t.Fatalf("Decrypt(nonce-only) returned %d bytes, want 0", len(pt))
	}

	// In-place variants on an empty buffer.
	empty := []byte{}
	wire2, err := schedule.EncryptInPlace(empty, cs)
	if err != nil {
		t.Fatalf("EncryptInPlace(empty): %v", err)
	}
	if len(wire2) != NonceSize {
		t.Fatalf("EncryptInPlace(empty) wire len=%d want %d", len(wire2), NonceSize)
	}
	out, err := schedule.DecryptInPlace(wire2, cs)
	if err != nil {
		t.Fatalf("DecryptInPlace(nonce-only): %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("DecryptInPlace(nonce-only) returned %d bytes, want 0", len(out))
	}
}

func TestDeterminismWithFixedNonce(t *testing.T) {
	// Two independent Ciphersets over the same master and schedule
	// must agree on encryption and decryption for any plaintext.
	palette := []string{ctr.CipherBLAKE3, ctr.CipherChaCha20, ctr.CipherAES128CTR}
	schedule := mustSchedule(t, palette, DefaultSegmentSize)
	master := mustMaster(t)
	encCs := mustCipherset(t, master, schedule)
	decCs := mustCipherset(t, master, schedule)
	pt := randomPlaintext(t, 4096)
	wire, err := schedule.Encrypt(pt, encCs)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	recovered, err := schedule.Decrypt(wire, decCs)
	if err != nil {
		t.Fatalf("Decrypt with independent cipherset: %v", err)
	}
	if !bytes.Equal(pt, recovered) {
		t.Fatalf("independent-cipherset round-trip mismatch")
	}

	// Subkey determinism: NewCipherset on the same master and schedule
	// produces equal per-slot subkeys.
	for i := range encCs.subkeys {
		if !bytes.Equal(encCs.subkeys[i], decCs.subkeys[i]) {
			t.Fatalf("subkey[%d] mismatch across cipherset instances", i)
		}
	}
	if !bytes.Equal(encCs.scheduleSubkey, decCs.scheduleSubkey) {
		t.Fatalf("scheduleSubkey mismatch across cipherset instances")
	}
}

func TestTwoSchedulesEquivalent(t *testing.T) {
	// Encrypt under one Schedule, decrypt under a freshly constructed
	// Schedule of equal palette / segment size and a freshly built
	// Cipherset from the same master.
	palette := shuffledRegistry(99)
	master := mustMaster(t)
	sched1 := mustSchedule(t, palette, DefaultSegmentSize)
	sched2 := mustSchedule(t, palette, DefaultSegmentSize)
	cs1 := mustCipherset(t, master, sched1)
	cs2 := mustCipherset(t, master, sched2)
	pt := randomPlaintext(t, 9999)
	wire, err := sched1.Encrypt(pt, cs1)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := sched2.Decrypt(wire, cs2)
	if err != nil {
		t.Fatalf("Decrypt across independent schedules: %v", err)
	}
	if !bytes.Equal(pt, got) {
		t.Fatalf("cross-schedule round-trip mismatch")
	}
}

func TestCrossScheduleCiphersetAccepted(t *testing.T) {
	// A Cipherset built under sched1 may be passed to an equivalent
	// sched2.Encrypt / Decrypt because sameSchedule does the
	// content-wise check.
	palette := []string{"aescmac", "chacha20", "blake3", "blake2s"}
	master := mustMaster(t)
	sched1 := mustSchedule(t, palette, DefaultSegmentSize)
	sched2 := mustSchedule(t, palette, DefaultSegmentSize)
	cs1 := mustCipherset(t, master, sched1)
	pt := randomPlaintext(t, 1000)
	wire, err := sched2.Encrypt(pt, cs1) // cs1.schedule != sched2 by pointer
	if err != nil {
		t.Fatalf("Encrypt with cross-schedule cipherset: %v", err)
	}
	got, err := sched2.Decrypt(wire, cs1)
	if err != nil {
		t.Fatalf("Decrypt with cross-schedule cipherset: %v", err)
	}
	if !bytes.Equal(pt, got) {
		t.Fatalf("cross-schedule cipherset round-trip mismatch")
	}
}

func TestCiphersetMismatchedScheduleRejected(t *testing.T) {
	// A Cipherset built under one palette must not be accepted by a
	// schedule with a different palette.
	master := mustMaster(t)
	sched1 := mustSchedule(t, []string{"aescmac", "chacha20", "blake3"}, DefaultSegmentSize)
	sched2 := mustSchedule(t, []string{"aescmac", "chacha20", "blake2s"}, DefaultSegmentSize)
	cs1 := mustCipherset(t, master, sched1)
	if _, err := sched2.Encrypt([]byte("hi"), cs1); err == nil {
		t.Fatal("sched2.Encrypt accepted a cipherset bound to a different palette")
	}
	// Differing segment sizes also reject.
	sched3 := mustSchedule(t, []string{"aescmac", "chacha20", "blake3"}, 19)
	if _, err := sched3.Encrypt([]byte("hi"), cs1); err == nil {
		t.Fatal("sched3.Encrypt accepted a cipherset bound to a different segment size")
	}
}

func TestPaletteAccessors(t *testing.T) {
	palette := []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}
	schedule := mustSchedule(t, palette, DefaultSegmentSize)
	if schedule.PaletteSize() != len(palette) {
		t.Fatalf("PaletteSize=%d want %d", schedule.PaletteSize(), len(palette))
	}
	if schedule.SegmentSize() != DefaultSegmentSize {
		t.Fatalf("SegmentSize=%d want %d", schedule.SegmentSize(), DefaultSegmentSize)
	}
	got := schedule.Palette()
	if len(got) != len(palette) {
		t.Fatalf("Palette len mismatch: %d vs %d", len(got), len(palette))
	}
	for i := range got {
		if got[i] != palette[i] {
			t.Fatalf("Palette[%d]=%q want %q", i, got[i], palette[i])
		}
	}
	// Mutating the returned copy must not affect the schedule.
	got[0] = "tampered"
	got2 := schedule.Palette()
	if got2[0] != palette[0] {
		t.Fatalf("Palette() returned a live reference, mutation leaked")
	}
}

func TestGenerateMasterKey(t *testing.T) {
	a, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey a: %v", err)
	}
	if len(a) != MasterKeySize {
		t.Fatalf("GenerateMasterKey returned %d bytes, want %d", len(a), MasterKeySize)
	}
	b, err := GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatalf("GenerateMasterKey produced identical keys on two calls")
	}
}

func TestNilCiphersetRejected(t *testing.T) {
	schedule := mustSchedule(t, []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}, DefaultSegmentSize)
	if _, err := schedule.Encrypt([]byte("hi"), nil); err == nil {
		t.Fatal("Encrypt(nil cs) returned no error")
	}
	if _, err := schedule.Decrypt(make([]byte, NonceSize), nil); err == nil {
		t.Fatal("Decrypt(nil cs) returned no error")
	}
	if _, err := schedule.EncryptInPlace([]byte("hi"), nil); err == nil {
		t.Fatal("EncryptInPlace(nil cs) returned no error")
	}
	if _, err := schedule.DecryptInPlace(make([]byte, NonceSize), nil); err == nil {
		t.Fatal("DecryptInPlace(nil cs) returned no error")
	}
}

func TestNilScheduleRejected(t *testing.T) {
	master := mustMaster(t)
	if _, err := NewCipherset(master, nil); err == nil {
		t.Fatal("NewCipherset(nil schedule) returned no error")
	}
}
