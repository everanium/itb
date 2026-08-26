package parallax

import (
	"bytes"
	"testing"
)

// intoSizes spans empty, sub-segment, segment-boundary, and
// multi-segment payloads for the EncryptInto / DecryptInto sweep.
var intoSizes = []int{0, 1, 16, 51, 257, 8 * 1024, 65*1024 + 7, 1024 * 1024}

// TestEncryptIntoWireIdentity verifies that the body EncryptInto
// writes into a caller-supplied dst is byte-identical to the wire
// body EncryptInPlace produces under the same nonce. The nonce is
// taken from an EncryptInPlace wire and replayed through
// transformInto — the exact call EncryptInto issues after drawing its
// nonce — so the two entry points are compared on identical inputs.
func TestEncryptIntoWireIdentity(t *testing.T) {
	master := mustMaster(t)
	for _, pp := range streamPaletteCases {
		for _, n := range intoSizes {
			if n == 0 {
				continue
			}
			t.Run(pp.label+"/n"+itoa(n), func(t *testing.T) {
				s := mustSchedule(t, pp.palette, DefaultSegmentSize)
				cs := mustCipherset(t, master, s)
				pt := randomPlaintext(t, n)

				buf := append([]byte(nil), pt...)
				wireOld, err := s.EncryptInPlace(buf, cs)
				if err != nil {
					t.Fatalf("EncryptInPlace: %v", err)
				}
				nonce := wireOld[:NonceSize]

				dst := make([]byte, n)
				if err := transformInto(s, cs, nonce, dst, pt); err != nil {
					t.Fatalf("transformInto: %v", err)
				}
				if !bytes.Equal(dst, wireOld[NonceSize:]) {
					t.Fatal("EncryptInto core body differs from EncryptInPlace wire body under the same nonce")
				}
			})
		}
	}
}

// TestEncryptIntoRoundTripAgainstDecrypt round-trips EncryptInto
// output through the pre-existing Decrypt entry, proving the
// caller-assembled wire is consumed unchanged by the old path.
func TestEncryptIntoRoundTripAgainstDecrypt(t *testing.T) {
	master := mustMaster(t)
	for _, pp := range streamPaletteCases {
		for _, n := range intoSizes {
			t.Run(pp.label+"/n"+itoa(n), func(t *testing.T) {
				s := mustSchedule(t, pp.palette, DefaultSegmentSize)
				cs := mustCipherset(t, master, s)
				pt := randomPlaintext(t, n)

				wire := make([]byte, NonceSize+n)
				nonce, err := s.EncryptInto(wire[NonceSize:], pt, cs)
				if err != nil {
					t.Fatalf("EncryptInto: %v", err)
				}
				if len(nonce) != NonceSize {
					t.Fatalf("nonce length %d, want %d", len(nonce), NonceSize)
				}
				copy(wire[:NonceSize], nonce)

				got, err := s.Decrypt(wire, cs)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(got, pt) {
					t.Fatal("Decrypt of EncryptInto wire does not recover plaintext")
				}
			})
		}
	}
}

// TestDecryptIntoAgainstEncryptInPlace decrypts EncryptInPlace wires
// through DecryptInto, both into a disjoint dst and into a dst that
// exactly aliases the wire body.
func TestDecryptIntoAgainstEncryptInPlace(t *testing.T) {
	master := mustMaster(t)
	for _, pp := range streamPaletteCases {
		for _, n := range intoSizes {
			t.Run(pp.label+"/n"+itoa(n), func(t *testing.T) {
				s := mustSchedule(t, pp.palette, DefaultSegmentSize)
				cs := mustCipherset(t, master, s)
				pt := randomPlaintext(t, n)

				buf := append([]byte(nil), pt...)
				wire, err := s.EncryptInPlace(buf, cs)
				if err != nil {
					t.Fatalf("EncryptInPlace: %v", err)
				}

				// Disjoint dst.
				dst := make([]byte, n)
				got, err := s.DecryptInto(dst, wire, cs)
				if err != nil {
					t.Fatalf("DecryptInto: %v", err)
				}
				if !bytes.Equal(got, pt) {
					t.Fatal("DecryptInto does not recover plaintext")
				}

				// dst exactly aliasing the wire body.
				got, err = s.DecryptInto(wire[NonceSize:], wire, cs)
				if err != nil {
					t.Fatalf("DecryptInto (aliased): %v", err)
				}
				if !bytes.Equal(got, pt) {
					t.Fatal("aliased DecryptInto does not recover plaintext")
				}
			})
		}
	}
}

// TestEncryptIntoAliased encrypts with dst exactly aliasing src and
// verifies the result decrypts to the original plaintext.
func TestEncryptIntoAliased(t *testing.T) {
	master := mustMaster(t)
	s := mustSchedule(t, streamPaletteCases[2].palette, DefaultSegmentSize)
	cs := mustCipherset(t, master, s)
	pt := randomPlaintext(t, 65*1024+7)

	buf := append([]byte(nil), pt...)
	nonce, err := s.EncryptInto(buf, buf, cs)
	if err != nil {
		t.Fatalf("EncryptInto (aliased): %v", err)
	}
	wire := append(append([]byte(nil), nonce...), buf...)
	got, err := s.Decrypt(wire, cs)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatal("aliased EncryptInto wire does not recover plaintext")
	}
}

// TestEncryptIntoErrors exercises the argument-validation failures of
// both Into entries.
func TestEncryptIntoErrors(t *testing.T) {
	master := mustMaster(t)
	s := mustSchedule(t, streamPaletteCases[0].palette, DefaultSegmentSize)
	cs := mustCipherset(t, master, s)

	if _, err := s.EncryptInto(make([]byte, 3), make([]byte, 4), cs); err == nil {
		t.Fatal("EncryptInto accepted dst/src length mismatch")
	}
	if _, err := s.EncryptInto(nil, nil, nil); err == nil {
		t.Fatal("EncryptInto accepted nil cipherset")
	}
	if _, err := s.DecryptInto(nil, make([]byte, NonceSize-1), cs); err == nil {
		t.Fatal("DecryptInto accepted wire shorter than nonce")
	}
	if _, err := s.DecryptInto(make([]byte, 5), make([]byte, NonceSize+4), cs); err == nil {
		t.Fatal("DecryptInto accepted dst/body length mismatch")
	}
	if _, err := s.DecryptInto(nil, make([]byte, NonceSize), nil); err == nil {
		t.Fatal("DecryptInto accepted nil cipherset")
	}

	// Nonce-only wire decrypts to the empty dst without error.
	got, err := s.DecryptInto([]byte{}, make([]byte, NonceSize), cs)
	if err != nil {
		t.Fatalf("DecryptInto (nonce-only wire): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("nonce-only wire produced %d plaintext bytes", len(got))
	}
}
