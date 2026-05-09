package wrapper

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestWrapRoundTrip(t *testing.T) {
	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatal(err)
			}
			plaintext := make([]byte, 4096)
			rand.Read(plaintext)
			wire, err := Wrap(name, key, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := Unwrap(name, key, wire)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, recovered) {
				t.Fatalf("%s: round-trip mismatch", name)
			}
		})
	}
}

func TestWrapStreamReaderWriter(t *testing.T) {
	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatal(err)
			}
			plaintext := make([]byte, 50*1024)
			rand.Read(plaintext)

			// Wrap via NewWrapWriter.
			var wireBuf bytes.Buffer
			ww, err := NewWrapWriter(name, key, &wireBuf)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ww.Write(plaintext); err != nil {
				t.Fatal(err)
			}
			// Unwrap via NewUnwrapReader.
			rr, err := NewUnwrapReader(name, key, bytes.NewReader(wireBuf.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			recovered := make([]byte, len(plaintext))
			off := 0
			for off < len(recovered) {
				n, err := rr.Read(recovered[off:])
				if err != nil {
					t.Fatal(err)
				}
				off += n
			}
			if !bytes.Equal(plaintext, recovered) {
				t.Fatalf("%s: rw round-trip mismatch", name)
			}
		})
	}
}
