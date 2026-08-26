package macs

import (
	"bytes"
	"math/rand"
	"testing"
)

// TestMakeIncrementalParity pins the MACIncrementalFunc contract for
// every shipped primitive: the incremental arm over an arbitrary
// chunk split emits the same tag, byte-for-byte, as the Make-built
// MACFunc over the concatenation. 100 random (key, chunk-split)
// tuples per primitive, spanning 0..6 chunks with empty chunks
// included and total sizes crossing the KMAC sponge-rate boundary.
func TestMakeIncrementalParity(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1234))
	for _, spec := range Registry {
		t.Run(spec.Name, func(t *testing.T) {
			for i := 0; i < 100; i++ {
				key := make([]byte, spec.KeySize)
				rng.Read(key)
				mac, err := Make(spec.Name, key)
				if err != nil {
					t.Fatal(err)
				}
				inc, err := MakeIncremental(spec.Name, key)
				if err != nil {
					t.Fatal(err)
				}

				nChunks := rng.Intn(7)
				chunks := make([][]byte, nChunks)
				for j := range chunks {
					// Lengths sweep 0, sub-rate, rate-boundary,
					// multi-block shapes.
					lens := []int{0, 1, 17, 135, 136, 137, 500, 4096}
					c := make([]byte, lens[rng.Intn(len(lens))])
					rng.Read(c)
					chunks[j] = c
				}

				var joined []byte
				for _, c := range chunks {
					joined = append(joined, c...)
				}

				want := mac(joined)
				got := inc(chunks...)
				if !bytes.Equal(got, want) {
					t.Fatalf("fixture %d (%d chunks, %d bytes total): incremental tag differs\ngot  %x\nwant %x",
						i, nChunks, len(joined), got, want)
				}
			}
		})
	}
}

// TestMakeIncrementalErrors mirrors the Make error surface: unknown
// name and short key are rejected identically.
func TestMakeIncrementalErrors(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	if _, err := MakeIncremental("nonsense", key); err == nil {
		t.Error("MakeIncremental(nonsense): expected error")
	}
	if _, err := MakeIncremental("kmac256", key[:8]); err == nil {
		t.Error("MakeIncremental(kmac256, 8-byte key): expected error")
	}
	if _, err := MakeIncremental("hmac-blake3", key[:16]); err == nil {
		t.Error("MakeIncremental(hmac-blake3, 16-byte key): expected error")
	}
}
