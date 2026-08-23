// Package easy_test (external) — comprehensive round-trip matrix and
// cross-encryptor scenarios for the [easy.Encryptor] surface.
//
// The matrix mirrors the primitive / width coverage of
// itb_ext_test.go's bench cohort: every PRF-grade primitive at
// widths 512 / 1024 / 2048 bits, exercised through Encrypt /
// Decrypt, EncryptAuth / DecryptAuth, and EncryptStream /
// DecryptStream. Small-payload bytes.Equal round-trip.
package easy_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/everanium/itb/easy"
)

// generateDataEasy fills an n-byte slice with crypto/rand bytes for
// test plaintext. The "Easy" suffix mirrors the "Ext" suffix used by
// itb_ext_test.go's helpers — both denote the in-package-test
// counterpart of an internal helper, the Easy variant living in
// the github.com/everanium/itb/easy sub-package.
func generateDataEasy(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// primitiveSpec lists every shipped (primitive name, key_bits
// widths) combination the round-trip matrix exercises. The
// universally-valid {512, 1024, 2048} triple is used across all
// primitives — the lower 256-bit key_bits corner is omitted
// because the Seed{128,256,512} constructors in the itb root
// require bits >= 512.
var primitiveSpec = []struct {
	name   string
	widths []int
}{
	{"areion256", []int{512, 1024, 2048}},
	{"areion512", []int{512, 1024, 2048}},
	{"blake2b256", []int{512, 1024, 2048}},
	{"blake2b512", []int{512, 1024, 2048}},
	{"blake2s", []int{512, 1024, 2048}},
	{"blake3", []int{512, 1024, 2048}},
	{"aescmac", []int{512, 1024, 2048}},
	{"siphash24", []int{512, 1024, 2048}},
	{"chacha20", []int{512, 1024, 2048}},
}

// newEncryptorFor builds a fresh Triple-Ouroboros encryptor for the
// given primitive name and key_bits.
func newEncryptorFor(primitive string, keyBits int) *easy.Encryptor {
	return easy.New3(primitive, keyBits)
}

// TestEasyRoundtripMatrix exercises plain Encrypt → Decrypt on every
// (primitive, key_bits) combination at a 1 KiB payload.
func TestEasyRoundtripMatrix(t *testing.T) {
	plaintext := generateDataEasy(1024)
	for _, ps := range primitiveSpec {
		for _, kb := range ps.widths {
			name := fmt.Sprintf("%s_%dbit", ps.name, kb)
			t.Run(name, func(t *testing.T) {
				enc := newEncryptorFor(ps.name, kb)
				defer enc.Close()
				ct, err := enc.Encrypt(plaintext)
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				pt, err := enc.Decrypt(ct)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(pt, plaintext) {
					t.Errorf("roundtrip mismatch: got %d bytes, want %d", len(pt), len(plaintext))
				}
			})
		}
	}
}

// TestEasyAuthRoundtripMatrix exercises EncryptAuth → DecryptAuth on
// the same matrix as [TestEasyRoundtripMatrix].
func TestEasyAuthRoundtripMatrix(t *testing.T) {
	plaintext := generateDataEasy(1024)
	for _, ps := range primitiveSpec {
		for _, kb := range ps.widths {
			name := fmt.Sprintf("%s_%dbit", ps.name, kb)
			t.Run(name, func(t *testing.T) {
				enc := newEncryptorFor(ps.name, kb)
				defer enc.Close()
				ct, err := enc.EncryptAuth(plaintext)
				if err != nil {
					t.Fatalf("EncryptAuth: %v", err)
				}
				pt, err := enc.DecryptAuth(ct)
				if err != nil {
					t.Fatalf("DecryptAuth: %v", err)
				}
				if !bytes.Equal(pt, plaintext) {
					t.Errorf("auth roundtrip mismatch: got %d bytes, want %d", len(pt), len(plaintext))
				}
			})
		}
	}
}

// TestEasyStreamRoundtripMatrix exercises EncryptStream → DecryptStream
// on the same matrix at a slightly larger 4 KiB payload (small enough
// to remain a single chunk under the auto-detect heuristic but still
// exercises the chunk-walking decode path).
func TestEasyStreamRoundtripMatrix(t *testing.T) {
	plaintext := generateDataEasy(4096)
	for _, ps := range primitiveSpec {
		for _, kb := range ps.widths {
			name := fmt.Sprintf("%s_%dbit", ps.name, kb)
			t.Run(name, func(t *testing.T) {
				enc := newEncryptorFor(ps.name, kb)
				defer enc.Close()
				var streamed bytes.Buffer
				err := enc.EncryptStream(plaintext, func(chunk []byte) error {
					_, e := streamed.Write(chunk)
					return e
				})
				if err != nil {
					t.Fatalf("EncryptStream: %v", err)
				}
				var recovered bytes.Buffer
				err = enc.DecryptStream(streamed.Bytes(), func(chunk []byte) error {
					_, e := recovered.Write(chunk)
					return e
				})
				if err != nil {
					t.Fatalf("DecryptStream: %v", err)
				}
				if !bytes.Equal(recovered.Bytes(), plaintext) {
					t.Errorf("stream roundtrip mismatch: got %d bytes, want %d",
						recovered.Len(), len(plaintext))
				}
			})
		}
	}
}

// TestErrMismatchErrorContainsField verifies the public Stringer
// surface formats the field name into the error message.
func TestErrMismatchErrorContainsField(t *testing.T) {
	e := &easy.ErrMismatch{Field: "primitive"}
	msg := e.Error()
	if msg == "" {
		t.Fatalf("ErrMismatch.Error returned empty string")
	}
	// The exact wording is part of the package contract; assert the
	// field name appears verbatim somewhere in the message.
	wantSubstr := `"primitive"`
	if !strings.Contains(msg, wantSubstr) {
		t.Errorf("ErrMismatch.Error: %q does not contain %q", msg, wantSubstr)
	}
}

// TestSetNonceBitsInvalidPanics exercises the default-branch rejection
// of values outside {128, 256, 512}.
func TestSetNonceBitsInvalidPanics(t *testing.T) {
	enc := easy.New3("blake3", 1024, "kmac256")
	defer enc.Close()

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("SetNonceBits(64): expected panic, got nil")
		}
	}()
	enc.SetNonceBits(64)
}

// TestSetBarrierFillInvalidPanics exercises the default-branch
// rejection of values outside {1, 2, 4, 8, 16, 32}.
func TestSetBarrierFillInvalidPanics(t *testing.T) {
	enc := easy.New3("blake3", 1024, "kmac256")
	defer enc.Close()

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("SetBarrierFill(3): expected panic, got nil")
		}
	}()
	enc.SetBarrierFill(3)
}

// TestPRFKeysSipHashReturnsNil verifies the siphash24 path through
// PRFKeys - the primitive has no fixed PRF key, so the getter returns
// nil rather than an empty slice.
func TestPRFKeysSipHashReturnsNil(t *testing.T) {
	enc := easy.New3("siphash24", 1024, "kmac256")
	defer enc.Close()

	if got := enc.PRFKeys(); got != nil {
		t.Errorf("siphash24 PRFKeys() = %v, want nil", got)
	}
}

// TestNonceBitsGlobalFallback verifies the read path that returns
// itb.GetNonceBits when the encryptor never set a per-instance
// override.
func TestNonceBitsGlobalFallback(t *testing.T) {
	enc := easy.New3("blake3", 1024, "kmac256")
	defer enc.Close()

	got := enc.NonceBits()
	if got != 128 && got != 256 && got != 512 {
		t.Errorf("NonceBits global fallback returned %d, want one of {128,256,512}", got)
	}
}

// TestParseChunkLenDimensionOverflow constructs a header that
// declares width and height multiplying to a value exceeding the
// per-instance pixel cap.
func TestParseChunkLenDimensionOverflow(t *testing.T) {
	enc := easy.New3("blake3", 1024, "kmac256")
	defer enc.Close()

	header := make([]byte, enc.HeaderSize())
	nonceSz := enc.HeaderSize() - 4
	header[nonceSz+0] = 0xFF
	header[nonceSz+1] = 0xFF
	header[nonceSz+2] = 0xFF
	header[nonceSz+3] = 0xFF

	if _, err := enc.ParseChunkLen(header); err == nil {
		t.Fatalf("ParseChunkLen(0xFFFF × 0xFFFF): want pixel-cap error, got nil")
	}
}

// TestNewUnknownNamePanics drives easy.New3 with a string that
// resolves neither in the hash registry nor in the MAC registry.
func TestNewUnknownNamePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("New3(\"nonexistent\"): expected panic, got nil")
		}
	}()
	_ = easy.New3("nonexistent-primitive-or-mac")
}

// TestNewUnsupportedArgTypePanics drives easy.New3 with a value whose
// type the constructor's switch does not handle.
func TestNewUnsupportedArgTypePanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("New3(3.14): expected panic on unsupported arg type, got nil")
		}
	}()
	_ = easy.New3(3.14)
}

// TestPrimitiveAtOutOfRangeReturnsEmpty verifies that PrimitiveAt
// returns the empty string for negative or beyond-len slots.
func TestPrimitiveAtOutOfRangeReturnsEmpty(t *testing.T) {
	enc := easy.New3("blake3", 1024, "kmac256")
	defer enc.Close()

	if got := enc.PrimitiveAt(-1); got != "" {
		t.Errorf("PrimitiveAt(-1) = %q, want \"\"", got)
	}
	if got := enc.PrimitiveAt(99); got != "" {
		t.Errorf("PrimitiveAt(99) = %q, want \"\"", got)
	}
}

// TestIsMixedSinglePrimitiveFalse exercises the IsMixed branch on a
// single-primitive encryptor (the predicate must return false).
func TestIsMixedSinglePrimitiveFalse(t *testing.T) {
	enc := easy.New3("blake3", 1024, "kmac256")
	defer enc.Close()

	if enc.IsMixed() {
		t.Errorf("IsMixed on single-primitive encryptor = true, want false")
	}
}

// TestSeedCountIsEight verifies that a fresh Triple-Ouroboros
// encryptor always carries eight seed slots (noise + lockSeed +
// 3 data + 3 start).
func TestSeedCountIsEight(t *testing.T) {
	enc := easy.New3("areion512", 1024, "kmac256")
	defer enc.Close()
	if got := len(enc.SeedComponents()); got != 8 {
		t.Errorf("SeedComponents count = %d, want 8", got)
	}
}

// TestSetMemoryLimitRoundTrip exercises the package-level
// SetMemoryLimit setter and its negative-argument query convention.
// Restores the live limit on test exit so the rest of the suite is
// untouched.
func TestSetMemoryLimitRoundTrip(t *testing.T) {
	initial := easy.SetMemoryLimit(-1)
	t.Cleanup(func() {
		easy.SetMemoryLimit(initial)
	})

	const target = int64(256 << 20) // 256 MiB
	prev := easy.SetMemoryLimit(target)
	if prev != initial {
		t.Fatalf("SetMemoryLimit(%d): returned previous=%d, want %d", target, prev, initial)
	}
	if got := easy.SetMemoryLimit(-1); got != target {
		t.Fatalf("SetMemoryLimit query: got %d, want %d", got, target)
	}
}

// TestSetGCPercentRoundTrip exercises easy.SetGCPercent - both the
// set path and the protected query path (-1 returns the live value
// without leaving GC disabled). Restores the live percentage on test
// exit.
func TestSetGCPercentRoundTrip(t *testing.T) {
	initial := easy.SetGCPercent(-1)
	t.Cleanup(func() {
		easy.SetGCPercent(initial)
	})

	const target = 50
	prev := easy.SetGCPercent(target)
	if prev != initial {
		t.Fatalf("SetGCPercent(%d): returned previous=%d, want %d", target, prev, initial)
	}
	if got := easy.SetGCPercent(-1); got != target {
		t.Fatalf("SetGCPercent query: got %d, want %d", got, target)
	}

	live := debug.SetGCPercent(-1)
	if live != target {
		t.Fatalf("debug.SetGCPercent(-1) live probe: got %d, want %d (wrapper query leaked)", live, target)
	}
	debug.SetGCPercent(target) // restore - the probe above disabled GC.
}
