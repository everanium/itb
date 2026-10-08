package hashes

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

// zeroPadThreshold is the input length below which a registry closure
// zero-pads its data to a fixed block without a length tag, so an input
// and its trailing-zero extension within that block hash alike under one
// key and seed. Every name absent from the map separates trailing-zero
// extensions at every length. ITB never relies on the distinction: no
// call site can turn one of its inputs into a trailing-zero extension of
// another under the same key and seed.
var zeroPadThreshold = map[string]int{
	"blake2b256": 32,
	"blake2b512": 64,
	"blake2s":    32,
	"blake3":     32,
}

// digestOf builds the registry closure for spec under a random key and
// returns it as a function of data alone under one fixed random seed.
func digestOf(t *testing.T, spec Spec) func([]byte) []byte {
	t.Helper()
	var s [8]uint64
	for i := range s {
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		s[i] = binary.LittleEndian.Uint64(b[:])
	}
	switch spec.Width {
	case W128:
		h, _, err := Make128(spec.Name)
		if err != nil {
			t.Fatal(err)
		}
		return func(d []byte) []byte {
			lo, hi := h(d, s[0], s[1])
			return binary.LittleEndian.AppendUint64(binary.LittleEndian.AppendUint64(nil, lo), hi)
		}
	case W256:
		h, _, err := Make256(spec.Name)
		if err != nil {
			t.Fatal(err)
		}
		return func(d []byte) []byte {
			out := h(d, [4]uint64{s[0], s[1], s[2], s[3]})
			var b []byte
			for _, w := range out {
				b = binary.LittleEndian.AppendUint64(b, w)
			}
			return b
		}
	case W512:
		h, _, err := Make512(spec.Name)
		if err != nil {
			t.Fatal(err)
		}
		return func(d []byte) []byte {
			out := h(d, s)
			var b []byte
			for _, w := range out {
				b = binary.LittleEndian.AppendUint64(b, w)
			}
			return b
		}
	}
	t.Fatalf("%s: unknown width %d", spec.Name, spec.Width)
	return nil
}

// TestRegistryTrailingZeroLengthHandling pins the length handling of every
// registry closure against trailing-zero extension: below a primitive's
// zero-pad threshold an input and its one-byte zero extension collide,
// and at and above it — or at every length for a primitive with a
// length tag or injective padding — they differ.
func TestRegistryTrailingZeroLengthHandling(t *testing.T) {
	for _, spec := range Registry {
		t.Run(spec.Name, func(t *testing.T) {
			h := digestOf(t, spec)
			threshold := zeroPadThreshold[spec.Name]
			for n := 0; n <= 72; n++ {
				d := make([]byte, n)
				if _, err := rand.Read(d); err != nil {
					t.Fatal(err)
				}
				ext := append(append([]byte{}, d...), 0)
				same := bytes.Equal(h(d), h(ext))
				if n+1 <= threshold && !same {
					t.Fatalf("len %d vs %d: digests differ below the %d-byte zero-pad threshold", n, n+1, threshold)
				}
				if n+1 > threshold && same {
					t.Fatalf("len %d vs %d: trailing-zero extension collides", n, n+1)
				}
			}
		})
	}
}
