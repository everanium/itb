package parallax

import (
	"bytes"
	"strings"
	"testing"

	"github.com/everanium/itb/ctr"
)

func TestSegmentSizeCoprimeValidation(t *testing.T) {
	palette := []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}
	for s := 1; s <= 50; s++ {
		_, err := NewSchedule(palette, s)
		want := gcd(s, itbPipelinePeriod) == 1
		got := err == nil
		if got != want {
			t.Fatalf("NewSchedule(seg=%d): err=%v want-coprime=%v", s, err, want)
		}
	}
	// Cap behaviour.
	if _, err := NewSchedule(palette, MaxSegmentSize+1); err == nil {
		t.Fatalf("NewSchedule(seg=%d) accepted oversize", MaxSegmentSize+1)
	}
	if _, err := NewSchedule(palette, 0); err == nil {
		t.Fatal("NewSchedule(seg=0) accepted")
	}
	if _, err := NewSchedule(palette, -1); err == nil {
		t.Fatal("NewSchedule(seg=-1) accepted")
	}
}

func TestSegmentSizeVariants(t *testing.T) {
	palette := []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3, ctr.CipherBLAKE2b256}
	master := mustMaster(t)
	for _, seg := range []int{11, 17, 19, 23, 47, 2393} {
		if gcd(seg, itbPipelinePeriod) != 1 {
			t.Fatalf("test setup error: seg=%d not coprime to %d", seg, itbPipelinePeriod)
		}
		s := mustSchedule(t, palette, seg)
		cs := mustCipherset(t, master, s)
		// Vary plaintext size around segment boundaries.
		n := len(palette)
		for _, size := range []int{1, seg - 1, seg, seg + 1, n*seg - 1, n * seg, n*seg + 1, 7*n*seg + 13} {
			if size < 1 {
				continue
			}
			pt := randomPlaintext(t, size)
			wire, err := s.Encrypt(pt, cs)
			if err != nil {
				t.Fatalf("seg=%d size=%d Encrypt: %v", seg, size, err)
			}
			recovered, err := s.Decrypt(wire, cs)
			if err != nil {
				t.Fatalf("seg=%d size=%d Decrypt: %v", seg, size, err)
			}
			if !bytes.Equal(pt, recovered) {
				t.Fatalf("seg=%d size=%d round-trip mismatch", seg, size)
			}
		}
	}
}

func TestPaletteSizeBoundsInvalid(t *testing.T) {
	cases := [][]string{
		// Below minimum.
		{ctr.CipherAES128CTR, ctr.CipherChaCha20},
		// Empty.
		{},
		// Single.
		{ctr.CipherAES128CTR},
	}
	for _, c := range cases {
		if _, err := NewSchedule(c, DefaultSegmentSize); err == nil {
			t.Fatalf("NewSchedule(palette len=%d) accepted", len(c))
		}
	}

	// Above maximum.
	tooBig := make([]string, MaxPaletteSize+1)
	for i := range tooBig {
		tooBig[i] = ctr.CipherAES128CTR
	}
	if _, err := NewSchedule(tooBig, DefaultSegmentSize); err == nil {
		t.Fatalf("NewSchedule(palette len=%d) accepted", len(tooBig))
	}
}

func TestPaletteEntryNameInvalid(t *testing.T) {
	// 13-char name (one over the limit). Use an unknown but
	// length-valid name to also exercise the unknown-cipher path.
	long := strings.Repeat("a", MaxCipherNameLen+1)
	palette := []string{long, ctr.CipherChaCha20, ctr.CipherBLAKE3}
	if _, err := NewSchedule(palette, DefaultSegmentSize); err == nil {
		t.Fatalf("NewSchedule accepted %d-char name", MaxCipherNameLen+1)
	}

	// Empty entry.
	palette = []string{"", ctr.CipherChaCha20, ctr.CipherBLAKE3}
	if _, err := NewSchedule(palette, DefaultSegmentSize); err == nil {
		t.Fatal("NewSchedule accepted empty palette entry")
	}

	// Unknown cipher name within length cap.
	palette = []string{"nope", ctr.CipherChaCha20, ctr.CipherBLAKE3}
	if _, err := NewSchedule(palette, DefaultSegmentSize); err == nil {
		t.Fatal("NewSchedule accepted unknown cipher name")
	}
}

func TestMasterTooShortRejected(t *testing.T) {
	s := mustSchedule(t, []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}, DefaultSegmentSize)
	short := make([]byte, MasterKeySize-1)
	if _, err := NewCipherset(short, s); err == nil {
		t.Fatal("NewCipherset accepted short master")
	}
}

func TestDecryptWireTooShort(t *testing.T) {
	s := mustSchedule(t, []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}, DefaultSegmentSize)
	cs := mustCipherset(t, mustMaster(t), s)
	if _, err := s.Decrypt(make([]byte, NonceSize-1), cs); err == nil {
		t.Fatal("Decrypt accepted wire shorter than nonce")
	}
	if _, err := s.DecryptInPlace(make([]byte, NonceSize-1), cs); err == nil {
		t.Fatal("DecryptInPlace accepted wire shorter than nonce")
	}
}

func TestSchedulePaletteIsolation(t *testing.T) {
	// Mutating the user-supplied palette slice after construction must
	// not affect the stored schedule.
	palette := []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}
	s := mustSchedule(t, palette, DefaultSegmentSize)
	palette[0] = "tampered"
	if s.Palette()[0] != ctr.CipherAES128CTR {
		t.Fatalf("schedule mutated by external palette write")
	}
}

func TestTwoIndependentEncryptionsDiffer(t *testing.T) {
	// Same plaintext, same cipherset, two Encrypt calls — the
	// per-message nonces are independent, so the wire bytes must differ.
	schedule := mustSchedule(t, []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}, DefaultSegmentSize)
	cs := mustCipherset(t, mustMaster(t), schedule)
	pt := randomPlaintext(t, 1024)
	a, err := schedule.Encrypt(pt, cs)
	if err != nil {
		t.Fatalf("Encrypt a: %v", err)
	}
	b, err := schedule.Encrypt(pt, cs)
	if err != nil {
		t.Fatalf("Encrypt b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("two Encrypt calls produced identical wire under independent nonces")
	}
}

func TestEdgeOneByte(t *testing.T) {
	palette := shuffledRegistry(11)
	schedule := mustSchedule(t, palette, DefaultSegmentSize)
	cs := mustCipherset(t, mustMaster(t), schedule)
	pt := []byte{0x42}
	wire, err := schedule.Encrypt(pt, cs)
	if err != nil {
		t.Fatalf("Encrypt(1 byte): %v", err)
	}
	got, err := schedule.Decrypt(wire, cs)
	if err != nil {
		t.Fatalf("Decrypt(1 byte): %v", err)
	}
	if !bytes.Equal(pt, got) {
		t.Fatalf("1-byte round-trip mismatch")
	}
}

func TestExactNSegments(t *testing.T) {
	palette := []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3, ctr.CipherBLAKE2s, ctr.CipherSipHash24}
	schedule := mustSchedule(t, palette, DefaultSegmentSize)
	cs := mustCipherset(t, mustMaster(t), schedule)
	n := len(palette) * DefaultSegmentSize
	pt := randomPlaintext(t, n)
	wire, err := schedule.Encrypt(pt, cs)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := schedule.Decrypt(wire, cs)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(pt, got) {
		t.Fatalf("N*S round-trip mismatch")
	}
}

// TestDecryptWireTooShortAllPalettes exercises the wire-too-short
// rejection path across several palette compositions; the existing
// TestDecryptWireTooShort only covered a single mixed N=3 palette.
// The rejection is wire-prefix-only (it triggers before any slot
// cipher is consulted) so the palette should not matter — this test
// makes that invariant explicit.
func TestDecryptWireTooShortAllPalettes(t *testing.T) {
	palettes := [][]string{
		{ctr.CipherAES128CTR, ctr.CipherAES128CTR, ctr.CipherAES128CTR},
		{ctr.CipherChaCha20, ctr.CipherChaCha20, ctr.CipherChaCha20},
		{ctr.CipherBLAKE3, ctr.CipherBLAKE2b512, ctr.CipherBLAKE2s},
		{ctr.CipherAreion256, ctr.CipherAreion512, ctr.CipherSipHash24},
		{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3, ctr.CipherAreion512, ctr.CipherSipHash24},
	}
	for _, palette := range palettes {
		s := mustSchedule(t, palette, DefaultSegmentSize)
		cs := mustCipherset(t, mustMaster(t), s)
		for wireLen := 0; wireLen < NonceSize; wireLen++ {
			if _, err := s.Decrypt(make([]byte, wireLen), cs); err == nil {
				t.Fatalf("Decrypt accepted wire of length %d under palette %v", wireLen, palette)
			}
			if _, err := s.DecryptInPlace(make([]byte, wireLen), cs); err == nil {
				t.Fatalf("DecryptInPlace accepted wire of length %d under palette %v", wireLen, palette)
			}
		}
	}
}

// TestSegmentSizeMaxBoundary pins behaviour at the upper edge of the
// segment-size domain: the cap itself fails the coprime check; the
// largest accepted value is 65533; round-tripping at 65533 across a
// plaintext spanning multiple segments under that value succeeds.
func TestSegmentSizeMaxBoundary(t *testing.T) {
	palette := []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}
	// MaxSegmentSize itself (65535) shares factor 3 with 504 → reject.
	if _, err := NewSchedule(palette, MaxSegmentSize); err == nil {
		t.Fatalf("NewSchedule accepted S=MaxSegmentSize (gcd with 504 is non-trivial)")
	}
	// MaxSegmentSize+1 (65536) shares factor 8 with 504 → reject.
	// (This case also exceeds the cap; either check is sufficient.)
	if _, err := NewSchedule(palette, MaxSegmentSize+1); err == nil {
		t.Fatalf("NewSchedule accepted S above MaxSegmentSize")
	}
	// 65533 is the largest accepted S (coprime to 504, within cap).
	const accepted = 65533
	if gcd(accepted, itbPipelinePeriod) != 1 {
		t.Fatalf("test invariant broken: %d not coprime to %d", accepted, itbPipelinePeriod)
	}
	s, err := NewSchedule(palette, accepted)
	if err != nil {
		t.Fatalf("NewSchedule rejected the largest accepted S (%d): %v", accepted, err)
	}
	cs := mustCipherset(t, mustMaster(t), s)
	// Plaintext spans several segments at S=65533 so the worker
	// partitioning is exercised, not just a single-segment fast path.
	plaintext := make([]byte, accepted*4+11)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	wire, err := s.Encrypt(plaintext, cs)
	if err != nil {
		t.Fatalf("Encrypt at S=%d: %v", accepted, err)
	}
	got, err := s.Decrypt(wire, cs)
	if err != nil {
		t.Fatalf("Decrypt at S=%d: %v", accepted, err)
	}
	if !bytes.Equal(plaintext, got) {
		t.Fatalf("round-trip at S=%d corrupted the plaintext", accepted)
	}
}

// TestSetSegmentSizeAfterConstruction confirms SetSegmentSize routes
// the same validator as NewSchedule and that a valid call swaps the
// observable segment size while an invalid call leaves the Schedule
// unchanged.
func TestSetSegmentSizeAfterConstruction(t *testing.T) {
	palette := []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}
	s := mustSchedule(t, palette, DefaultSegmentSize)
	if got := s.SegmentSize(); got != DefaultSegmentSize {
		t.Fatalf("initial SegmentSize = %d, want %d", got, DefaultSegmentSize)
	}
	if err := s.SetSegmentSize(16381); err != nil {
		t.Fatalf("SetSegmentSize(16381) rejected: %v", err)
	}
	if got := s.SegmentSize(); got != 16381 {
		t.Fatalf("SegmentSize after Set = %d, want 16381", got)
	}
	for _, bad := range []int{0, -1, MaxSegmentSize + 1} {
		if err := s.SetSegmentSize(bad); err == nil {
			t.Fatalf("SetSegmentSize(%d) accepted, want error", bad)
		}
	}
	// gcd(6, 504) = 6 → non-coprime, must be rejected even though it
	// passes the positive/upper-bound checks.
	if err := s.SetSegmentSize(6); err == nil {
		t.Fatalf("SetSegmentSize(6) accepted, want non-coprime error")
	}
	if got := s.SegmentSize(); got != 16381 {
		t.Fatalf("SegmentSize after rejected Set = %d, want 16381 (unchanged)", got)
	}
}

// TestChunkSizeDefaultAfterConstruction confirms a freshly constructed
// Schedule reports DefaultChunkSize from ChunkSize().
func TestChunkSizeDefaultAfterConstruction(t *testing.T) {
	palette := []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}
	s := mustSchedule(t, palette, DefaultSegmentSize)
	if got := s.ChunkSize(); got != DefaultChunkSize {
		t.Fatalf("default ChunkSize = %d, want %d", got, DefaultChunkSize)
	}
}

// TestSetChunkSizeAfterConstruction confirms SetChunkSize accepts
// values inside [1, MaxChunkSize], updates the observable value, and
// rejects values outside the range while leaving the Schedule
// unchanged.
func TestSetChunkSizeAfterConstruction(t *testing.T) {
	palette := []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}
	s := mustSchedule(t, palette, DefaultSegmentSize)
	if err := s.SetChunkSize(1 << 20); err != nil {
		t.Fatalf("SetChunkSize(1 MiB) rejected: %v", err)
	}
	if got := s.ChunkSize(); got != 1<<20 {
		t.Fatalf("ChunkSize after Set = %d, want 1 MiB", got)
	}
	for _, bad := range []int{0, -1, -1 << 20, MaxChunkSize + 1} {
		if err := s.SetChunkSize(bad); err == nil {
			t.Fatalf("SetChunkSize(%d) accepted, want error", bad)
		}
	}
	if got := s.ChunkSize(); got != 1<<20 {
		t.Fatalf("ChunkSize after rejected Set = %d, want 1 MiB (unchanged)", got)
	}
}

// TestChunkSizeMaxBoundary pins the boundary at MaxChunkSize and
// confirms a plaintext that spans multiple chunks at the boundary
// round-trips through the streaming surface.
func TestChunkSizeMaxBoundary(t *testing.T) {
	palette := []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3}
	s := mustSchedule(t, palette, DefaultSegmentSize)
	if err := s.SetChunkSize(MaxChunkSize); err != nil {
		t.Fatalf("SetChunkSize(MaxChunkSize) rejected: %v", err)
	}
	if got := s.ChunkSize(); got != MaxChunkSize {
		t.Fatalf("ChunkSize after Set(MaxChunkSize) = %d, want %d", got, MaxChunkSize)
	}
	if err := s.SetChunkSize(MaxChunkSize + 1); err == nil {
		t.Fatalf("SetChunkSize(MaxChunkSize+1) accepted, want error")
	}
}
