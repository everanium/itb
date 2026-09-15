package itb

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

// TestCOBSBoundary pins the run-length code boundary cases of the COBS
// encoder — the transitions between short (< 0xFF) and full (== 0xFF)
// group headers around 254 non-zero bytes, and the mixed shapes that
// combine full runs with adjacent zeros. Each case round-trips
// through the encoder + decoder and verifies the encoded wire carries
// no 0x00 byte.
func TestCOBSBoundary(t *testing.T) {
	nonZero := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = 0xAA
		}
		return b
	}
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"single-nonzero", []byte{0x42}},
		{"run-253", nonZero(253)},
		{"run-254-boundary", nonZero(254)},
		{"run-255-over-boundary", nonZero(255)},
		{"run-508-two-boundaries", nonZero(508)},
		{"run-509", nonZero(509)},
		{"run-254-then-zero", append(nonZero(254), 0x00)},
		{"run-254-then-nonzero", append(nonZero(254), 0x11)},
		{"run-254-then-zero-then-nonzero", append(nonZero(254), 0x00, 0x11)},
		{"zero-then-run-254", append([]byte{0x00}, nonZero(254)...)},
		{"zero-run-254-zero", append(append([]byte{0x00}, nonZero(254)...), 0x00)},
		{"all-ff-500", bytes.Repeat([]byte{0xFF}, 500)},
		{"alternating-zeros", bytes.Repeat([]byte{0x00, 0xAA}, 128)},
		{"leading-zeros", bytes.Repeat([]byte{0x00}, 128)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc := cobsEncode(tc.data)
			for i, b := range enc {
				if b == 0 {
					t.Fatalf("encoded contains 0x00 at index %d (len=%d)", i, len(enc))
				}
			}
			dec := cobsDecode(enc)
			if !bytes.Equal(dec, tc.data) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes", len(dec), len(tc.data))
			}
		})
	}
}

// TestCOBSRandomRoundtrip runs random-uniform payloads (the shape the
// interlock lane bytes carry on the shipping wire) through encode +
// decode at 1 KB, 1 MB, and 16 MB, and verifies byte equality with
// the original input. Also checks the encoded wire carries no 0x00.
func TestCOBSRandomRoundtrip(t *testing.T) {
	for _, sz := range []int{1024, 1024 * 1024, 16 * 1024 * 1024} {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			data := make([]byte, sz)
			if _, err := rand.Read(data); err != nil {
				t.Fatal(err)
			}
			enc := cobsEncode(data)
			for i, b := range enc {
				if b == 0 {
					t.Fatalf("encoded contains 0x00 at index %d (len=%d)", i, len(enc))
				}
			}
			dec := cobsDecode(enc)
			if !bytes.Equal(dec, data) {
				t.Fatalf("round-trip mismatch at %d bytes", sz)
			}
		})
	}
}
