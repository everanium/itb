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

// TestEncryptStreamAuth3RoundtripAllMACsAllWidths covers Triple +
// Streaming AEAD across the 3 × 3 = 9 matrix. Mirrors the shape of
// the non-stream TestEncryptAuth3RoundtripAllMACsAllWidths.
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

				ids := newEightSeeds(t, hashName, 1024)
				defer freeAll(ids[:]...)

				sid := freshStreamID(t)
				const offset uint64 = 0

				ctBuf := make([]byte, 1<<20)
				ctLen, st := EncryptStreamAuth3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6], ids[7],
					macID, plaintext, ctBuf, sid, offset, true)
				if st != StatusOK {
					t.Fatalf("EncryptStreamAuth3: %v", st)
				}

				ptBuf := make([]byte, len(plaintext)+1024)
				ptLen, ff, st := DecryptStreamAuth3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6], ids[7],
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

				// Repeat with finalFlag=false on a non-terminal chunk.
				ctLen2, st := EncryptStreamAuth3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6], ids[7],
					macID, plaintext, ctBuf, sid, offset, false)
				if st != StatusOK {
					t.Fatalf("EncryptStreamAuth3 (non-final): %v", st)
				}
				_, ff2, st := DecryptStreamAuth3(
					ids[0], ids[1], ids[2], ids[3],
					ids[4], ids[5], ids[6], ids[7],
					macID, ctBuf[:ctLen2], ptBuf, sid, offset)
				if st != StatusOK {
					t.Fatalf("DecryptStreamAuth3 (non-final): %v", st)
				}
				if ff2 != false {
					t.Fatalf("finalFlag round-trip (non-final): got %v, want false", ff2)
				}
			})
		}
	}
}

// TestDecryptStreamAuth3TamperRejection flips one byte of the on-wire
// chunk and asserts MAC verification rejects it.
func TestDecryptStreamAuth3TamperRejection(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}

	macID, st := NewMAC("kmac256", makeMACKey32(t))
	if st != StatusOK {
		t.Fatalf("NewMAC: %v", st)
	}
	defer FreeMAC(macID)

	ids := newEightSeeds(t, "blake3", 1024)
	defer freeAll(ids[:]...)

	sid := freshStreamID(t)

	ctBuf := make([]byte, 1<<20)
	ctLen, st := EncryptStreamAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		macID, plaintext, ctBuf, sid, 0, true)
	if st != StatusOK {
		t.Fatalf("EncryptStreamAuth3: %v", st)
	}

	tampered := append([]byte(nil), ctBuf[:ctLen]...)
	// Default-config header layout: nonce(64) + width(2) + height(2).
	const tStart = 64 + 4
	tEnd := tStart + 256
	if tEnd > len(tampered) {
		tEnd = len(tampered)
	}
	for i := tStart; i < tEnd; i++ {
		tampered[i] ^= 0x01
	}

	ptBuf := make([]byte, len(plaintext)+1024)
	_, _, st = DecryptStreamAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		macID, tampered, ptBuf, sid, 0)
	if st != StatusMACFailure {
		t.Fatalf("tampered DecryptStreamAuth3: %v, want StatusMACFailure", st)
	}
}

// TestDecryptStreamAuth3CrossStreamReplay encrypts under streamID_A
// and asserts that a decrypt under streamID_B is rejected. Same
// PRF / MAC keys; only the streaming anchor differs. This is the
// cross-stream replay defence.
func TestDecryptStreamAuth3CrossStreamReplay(t *testing.T) {
	macID, st := NewMAC("hmac-blake3", makeMACKey32(t))
	if st != StatusOK {
		t.Fatalf("NewMAC: %v", st)
	}
	defer FreeMAC(macID)

	ids := newEightSeeds(t, "blake3", 1024)
	defer freeAll(ids[:]...)

	sidA := freshStreamID(t)
	sidB := freshStreamID(t)

	plaintext := []byte("cross-stream replay payload")
	ctBuf := make([]byte, 1<<16)
	ctLen, st := EncryptStreamAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		macID, plaintext, ctBuf, sidA, 0, true)
	if st != StatusOK {
		t.Fatalf("EncryptStreamAuth3: %v", st)
	}

	ptBuf := make([]byte, len(plaintext)+1024)
	_, _, st = DecryptStreamAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		macID, ctBuf[:ctLen], ptBuf, sidB, 0)
	if st != StatusMACFailure {
		t.Fatalf("cross-stream replay: %v, want StatusMACFailure", st)
	}
}

// TestDecryptStreamAuth3OffsetReorder encrypts at cumulativePixelOffset
// = 0 and asserts decrypt at cumulativePixelOffset = 1024 is rejected.
// This is the chunk-reorder / silent-mid-stream-drop defence.
func TestDecryptStreamAuth3OffsetReorder(t *testing.T) {
	macID, st := NewMAC("hmac-sha256", makeMACKey32(t))
	if st != StatusOK {
		t.Fatalf("NewMAC: %v", st)
	}
	defer FreeMAC(macID)

	ids := newEightSeeds(t, "siphash24", 1024)
	defer freeAll(ids[:]...)

	sid := freshStreamID(t)
	plaintext := []byte("offset-reorder payload")

	ctBuf := make([]byte, 1<<16)
	ctLen, st := EncryptStreamAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		macID, plaintext, ctBuf, sid, 0, true)
	if st != StatusOK {
		t.Fatalf("EncryptStreamAuth3: %v", st)
	}

	ptBuf := make([]byte, len(plaintext)+1024)
	_, _, st = DecryptStreamAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		macID, ctBuf[:ctLen], ptBuf, sid, 1024)
	if st != StatusMACFailure {
		t.Fatalf("offset-reorder: %v, want StatusMACFailure", st)
	}
}

// TestEncryptStreamAuth3EmptyFinal verifies the empty-stream
// terminator chunk path: zero-byte plaintext with finalFlag=true must
// round-trip cleanly.
func TestEncryptStreamAuth3EmptyFinal(t *testing.T) {
	macID, st := NewMAC("kmac256", makeMACKey32(t))
	if st != StatusOK {
		t.Fatalf("NewMAC: %v", st)
	}
	defer FreeMAC(macID)

	ids := newEightSeeds(t, "blake3", 1024)
	defer freeAll(ids[:]...)

	sid := freshStreamID(t)
	ctBuf := make([]byte, 1<<16)
	ctLen, st := EncryptStreamAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		macID, []byte{}, ctBuf, sid, 0, true)
	if st != StatusOK {
		t.Fatalf("EncryptStreamAuth3 (empty / final): %v", st)
	}

	ptBuf := make([]byte, 1024)
	ptLen, ff, st := DecryptStreamAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		macID, ctBuf[:ctLen], ptBuf, sid, 0)
	if st != StatusOK {
		t.Fatalf("DecryptStreamAuth3 (empty / final): %v", st)
	}
	if ptLen != 0 {
		t.Fatalf("expected 0-byte plaintext, got %d", ptLen)
	}
	if ff != true {
		t.Fatalf("finalFlag: got %v, want true", ff)
	}
}

// TestEncryptStreamAuth3EmptyNonFinal verifies that the underlying
// streaming function rejects a zero-byte plaintext when finalFlag is
// false (a non-terminal empty chunk is meaningless and the cipher
// rejects it the same way the message-mode Auth path does on empty
// input).
func TestEncryptStreamAuth3EmptyNonFinal(t *testing.T) {
	macID, st := NewMAC("kmac256", makeMACKey32(t))
	if st != StatusOK {
		t.Fatalf("NewMAC: %v", st)
	}
	defer FreeMAC(macID)

	ids := newEightSeeds(t, "blake3", 1024)
	defer freeAll(ids[:]...)

	sid := freshStreamID(t)
	ctBuf := make([]byte, 1<<16)
	_, st = EncryptStreamAuth3(
		ids[0], ids[1], ids[2], ids[3],
		ids[4], ids[5], ids[6], ids[7],
		macID, []byte{}, ctBuf, sid, 0, false)
	if st != StatusEncryptFailed {
		t.Fatalf("EncryptStreamAuth3 (empty / non-final): %v, want StatusEncryptFailed", st)
	}
}

