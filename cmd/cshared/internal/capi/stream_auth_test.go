package capi

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

// freshStreamID returns a CSPRNG-fresh 32-byte Streaming AEAD anchor
// for one stream's worth of test traffic. A new value is drawn per
// subtest to keep cross-stream isolation explicit; reusing an array
// across goroutine-parallel subtests would give false confidence.
func freshStreamID(t *testing.T) [32]byte {
	t.Helper()
	var sid [32]byte
	if _, err := rand.Read(sid[:]); err != nil {
		t.Fatal(err)
	}
	return sid
}

// TestEncryptStreamAuthRoundtripAllMACsAllWidths is the central
// regression for the Single + Streaming AEAD FFI surface: 3 MACs ×
// 3 hash widths = 9 round-trip checks plus finalFlag preservation.
// Mirrors TestEncryptAuthRoundtripAllMACsAllWidths shape.
func TestEncryptStreamAuthRoundtripAllMACsAllWidths(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	for _, macName := range macNames {
		for _, w := range []int{128, 256, 512} {
			hashName := hashByWidth[w]
			t.Run(fmt.Sprintf("%s/%s", macName, hashName), func(t *testing.T) {
				macID, st := NewMAC(macName, makeMACKey32(t))
				if st != StatusOK {
					t.Fatalf("NewMAC: %v", st)
				}
				defer FreeMAC(macID)

				ns, ds, ss := newSingleSeeds(t, hashName, 1024)
				defer freeAll(ns, ds, ss)

				sid := freshStreamID(t)
				const offset uint64 = 0

				ctBuf := make([]byte, 1<<20)
				ctLen, st := EncryptStreamAuth(ns, ds, ss, macID, plaintext, ctBuf, sid, offset, true)
				if st != StatusOK {
					t.Fatalf("EncryptStreamAuth: %v", st)
				}

				ptBuf := make([]byte, len(plaintext)+1024)
				ptLen, ff, st := DecryptStreamAuth(ns, ds, ss, macID, ctBuf[:ctLen], ptBuf, sid, offset)
				if st != StatusOK {
					t.Fatalf("DecryptStreamAuth: %v", st)
				}
				if !bytes.Equal(plaintext, ptBuf[:ptLen]) {
					t.Fatalf("plaintext mismatch")
				}
				if ff != true {
					t.Fatalf("finalFlag round-trip: got %v, want true", ff)
				}

				// Repeat with finalFlag=false on a non-terminal chunk.
				ctLen2, st := EncryptStreamAuth(ns, ds, ss, macID, plaintext, ctBuf, sid, offset, false)
				if st != StatusOK {
					t.Fatalf("EncryptStreamAuth (non-final): %v", st)
				}
				_, ff2, st := DecryptStreamAuth(ns, ds, ss, macID, ctBuf[:ctLen2], ptBuf, sid, offset)
				if st != StatusOK {
					t.Fatalf("DecryptStreamAuth (non-final): %v", st)
				}
				if ff2 != false {
					t.Fatalf("finalFlag round-trip (non-final): got %v, want false", ff2)
				}
			})
		}
	}
}

// TestEncryptStreamAuth3RoundtripAllMACsAllWidths covers Triple +
// Streaming AEAD across the 3 × 3 = 9 matrix.
func TestEncryptStreamAuth3RoundtripAllMACsAllWidths(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	for _, macName := range macNames {
		for _, w := range []int{128, 256, 512} {
			hashName := hashByWidth[w]
			t.Run(fmt.Sprintf("%s/%s", macName, hashName), func(t *testing.T) {
				macID, st := NewMAC(macName, makeMACKey32(t))
				if st != StatusOK {
					t.Fatalf("NewMAC: %v", st)
				}
				defer FreeMAC(macID)

				ids := newSevenSeeds(t, hashName, 1024)
				defer func() {
					for _, id := range ids {
						FreeSeed(id)
					}
				}()

				sid := freshStreamID(t)
				const offset uint64 = 0

				ctBuf := make([]byte, 1<<20)
				ctLen, st := EncryptStreamAuth3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6],
					macID, plaintext, ctBuf, sid, offset, true)
				if st != StatusOK {
					t.Fatalf("EncryptStreamAuth3: %v", st)
				}

				ptBuf := make([]byte, len(plaintext)+1024)
				ptLen, ff, st := DecryptStreamAuth3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6],
					macID, ctBuf[:ctLen], ptBuf, sid, offset)
				if st != StatusOK {
					t.Fatalf("DecryptStreamAuth3: %v", st)
				}
				if !bytes.Equal(plaintext, ptBuf[:ptLen]) {
					t.Fatalf("plaintext mismatch")
				}
				if ff != true {
					t.Fatalf("finalFlag round-trip: got %v, want true", ff)
				}
			})
		}
	}
}

// TestDecryptStreamAuthTamperRejection flips one byte of the on-wire
// chunk and asserts MAC verification rejects it.
func TestDecryptStreamAuthTamperRejection(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	macID, st := NewMAC("kmac256", makeMACKey32(t))
	if st != StatusOK {
		t.Fatalf("NewMAC: %v", st)
	}
	defer FreeMAC(macID)

	ns, ds, ss := newSingleSeeds(t, "blake3", 1024)
	defer freeAll(ns, ds, ss)

	sid := freshStreamID(t)

	ctBuf := make([]byte, 1<<20)
	ctLen, st := EncryptStreamAuth(ns, ds, ss, macID, plaintext, ctBuf, sid, 0, true)
	if st != StatusOK {
		t.Fatalf("EncryptStreamAuth: %v", st)
	}

	tampered := append([]byte(nil), ctBuf[:ctLen]...)
	// Default-config header layout: nonce(16) + width(2) + height(2).
	const tStart = 16 + 4
	tEnd := tStart + 256
	if tEnd > len(tampered) {
		tEnd = len(tampered)
	}
	for i := tStart; i < tEnd; i++ {
		tampered[i] ^= 0x01
	}

	ptBuf := make([]byte, len(plaintext)+1024)
	_, _, st = DecryptStreamAuth(ns, ds, ss, macID, tampered, ptBuf, sid, 0)
	if st != StatusMACFailure {
		t.Fatalf("tampered DecryptStreamAuth: %v, want StatusMACFailure", st)
	}
}

// TestDecryptStreamAuthCrossStreamReplay encrypts under streamID_A and
// asserts that a decrypt under streamID_B is rejected. Same PRF / MAC
// keys; only the streaming anchor differs. This is the cross-stream
// replay defence.
func TestDecryptStreamAuthCrossStreamReplay(t *testing.T) {
	macID, st := NewMAC("hmac-blake3", makeMACKey32(t))
	if st != StatusOK {
		t.Fatalf("NewMAC: %v", st)
	}
	defer FreeMAC(macID)

	ns, ds, ss := newSingleSeeds(t, "blake3", 1024)
	defer freeAll(ns, ds, ss)

	sidA := freshStreamID(t)
	sidB := freshStreamID(t)

	plaintext := []byte("cross-stream replay payload")
	ctBuf := make([]byte, 1<<16)
	ctLen, st := EncryptStreamAuth(ns, ds, ss, macID, plaintext, ctBuf, sidA, 0, true)
	if st != StatusOK {
		t.Fatalf("EncryptStreamAuth: %v", st)
	}

	ptBuf := make([]byte, len(plaintext)+1024)
	_, _, st = DecryptStreamAuth(ns, ds, ss, macID, ctBuf[:ctLen], ptBuf, sidB, 0)
	if st != StatusMACFailure {
		t.Fatalf("cross-stream replay: %v, want StatusMACFailure", st)
	}
}

// TestDecryptStreamAuthOffsetReorder encrypts at cumulativePixelOffset
// = 0 and asserts decrypt at cumulativePixelOffset = 1024 is rejected.
// This is the chunk-reorder / silent-mid-stream-drop defence.
func TestDecryptStreamAuthOffsetReorder(t *testing.T) {
	macID, st := NewMAC("hmac-sha256", makeMACKey32(t))
	if st != StatusOK {
		t.Fatalf("NewMAC: %v", st)
	}
	defer FreeMAC(macID)

	ns, ds, ss := newSingleSeeds(t, "siphash24", 1024)
	defer freeAll(ns, ds, ss)

	sid := freshStreamID(t)
	plaintext := []byte("offset-reorder payload")

	ctBuf := make([]byte, 1<<16)
	ctLen, st := EncryptStreamAuth(ns, ds, ss, macID, plaintext, ctBuf, sid, 0, true)
	if st != StatusOK {
		t.Fatalf("EncryptStreamAuth: %v", st)
	}

	ptBuf := make([]byte, len(plaintext)+1024)
	_, _, st = DecryptStreamAuth(ns, ds, ss, macID, ctBuf[:ctLen], ptBuf, sid, 1024)
	if st != StatusMACFailure {
		t.Fatalf("offset-reorder: %v, want StatusMACFailure", st)
	}
}

// TestEncryptStreamAuthEmptyFinal verifies the empty-stream
// terminator chunk path: zero-byte plaintext with finalFlag=true must
// round-trip cleanly.
func TestEncryptStreamAuthEmptyFinal(t *testing.T) {
	macID, st := NewMAC("kmac256", makeMACKey32(t))
	if st != StatusOK {
		t.Fatalf("NewMAC: %v", st)
	}
	defer FreeMAC(macID)

	ns, ds, ss := newSingleSeeds(t, "blake3", 1024)
	defer freeAll(ns, ds, ss)

	sid := freshStreamID(t)
	ctBuf := make([]byte, 1<<16)
	ctLen, st := EncryptStreamAuth(ns, ds, ss, macID, []byte{}, ctBuf, sid, 0, true)
	if st != StatusOK {
		t.Fatalf("EncryptStreamAuth (empty / final): %v", st)
	}

	ptBuf := make([]byte, 1024)
	ptLen, ff, st := DecryptStreamAuth(ns, ds, ss, macID, ctBuf[:ctLen], ptBuf, sid, 0)
	if st != StatusOK {
		t.Fatalf("DecryptStreamAuth (empty / final): %v", st)
	}
	if ptLen != 0 {
		t.Fatalf("expected 0-byte plaintext, got %d", ptLen)
	}
	if ff != true {
		t.Fatalf("finalFlag: got %v, want true", ff)
	}
}

// TestEncryptStreamAuthEmptyNonFinal verifies that the underlying
// streaming function rejects a zero-byte plaintext when finalFlag is
// false (a non-terminal empty chunk is meaningless and the cipher
// rejects it the same way the single-shot Auth path does on empty
// input).
func TestEncryptStreamAuthEmptyNonFinal(t *testing.T) {
	macID, st := NewMAC("kmac256", makeMACKey32(t))
	if st != StatusOK {
		t.Fatalf("NewMAC: %v", st)
	}
	defer FreeMAC(macID)

	ns, ds, ss := newSingleSeeds(t, "blake3", 1024)
	defer freeAll(ns, ds, ss)

	sid := freshStreamID(t)
	ctBuf := make([]byte, 1<<16)
	_, st = EncryptStreamAuth(ns, ds, ss, macID, []byte{}, ctBuf, sid, 0, false)
	if st != StatusEncryptFailed {
		t.Fatalf("EncryptStreamAuth (empty / non-final): %v, want StatusEncryptFailed", st)
	}
}

// TestEasyEncryptStreamAuthRoundtrip exercises the Easy Mode FFI
// streaming path across the 3-mode × 3-width matrix using the bound
// MAC closure in the constructed encryptor.
func TestEasyEncryptStreamAuthRoundtrip(t *testing.T) {
	plaintext := make([]byte, 2048)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		primitive string
		mode      int
		label     string
	}{
		{"siphash24", 1, "siphash24-single"},
		{"blake3", 1, "blake3-single"},
		{"blake2b512", 1, "blake2b512-single"},
		{"siphash24", 3, "siphash24-triple"},
		{"blake3", 3, "blake3-triple"},
		{"blake2b512", 3, "blake2b512-triple"},
	}

	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			id, st := NewEasy(c.primitive, 1024, "kmac256", c.mode)
			if st != StatusOK {
				t.Fatalf("NewEasy: %v", st)
			}
			defer FreeEasy(id)

			sid := freshStreamID(t)
			ctBuf := make([]byte, 1<<20)
			ctLen, st := EasyEncryptStreamAuth(id, plaintext, ctBuf, sid, 0, true)
			if st != StatusOK {
				t.Fatalf("EasyEncryptStreamAuth: %v", st)
			}

			ptBuf := make([]byte, len(plaintext)+1024)
			ptLen, ff, st := EasyDecryptStreamAuth(id, ctBuf[:ctLen], ptBuf, sid, 0)
			if st != StatusOK {
				t.Fatalf("EasyDecryptStreamAuth: %v", st)
			}
			if !bytes.Equal(plaintext, ptBuf[:ptLen]) {
				t.Fatalf("plaintext mismatch")
			}
			if ff != true {
				t.Fatalf("finalFlag: got %v, want true", ff)
			}
		})
	}
}

// TestEasyDecryptStreamAuthTamperRejection flips one byte of an Easy
// mode Streaming AEAD chunk and asserts the MAC catches it.
func TestEasyDecryptStreamAuthTamperRejection(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	id, st := NewEasy("blake3", 1024, "hmac-blake3", 1)
	if st != StatusOK {
		t.Fatalf("NewEasy: %v", st)
	}
	defer FreeEasy(id)

	sid := freshStreamID(t)
	ctBuf := make([]byte, 1<<20)
	ctLen, st := EasyEncryptStreamAuth(id, plaintext, ctBuf, sid, 0, true)
	if st != StatusOK {
		t.Fatalf("EasyEncryptStreamAuth: %v", st)
	}

	tampered := append([]byte(nil), ctBuf[:ctLen]...)
	const tStart = 16 + 4
	tEnd := tStart + 256
	if tEnd > len(tampered) {
		tEnd = len(tampered)
	}
	for i := tStart; i < tEnd; i++ {
		tampered[i] ^= 0x01
	}

	ptBuf := make([]byte, len(plaintext)+1024)
	_, _, st = EasyDecryptStreamAuth(id, tampered, ptBuf, sid, 0)
	if st != StatusMACFailure {
		t.Fatalf("tampered EasyDecryptStreamAuth: %v, want StatusMACFailure", st)
	}
}
