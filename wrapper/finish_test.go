package wrapper

import (
	"bytes"
	"io"
	"testing"
)

// TestFinishWrapStreamEmptyStream pins the empty-inner-stream
// contract for every shipped outer cipher: a WrapWriter that never
// received a non-empty Write emits exactly the per-stream nonce on
// FinishWrapStream, and both receive-side entries decode the
// nonce-only wire to an empty inner stream.
func TestFinishWrapStreamEmptyStream(t *testing.T) {
	for _, name := range CipherNames {
		name := name
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			nlen, err := NonceSize(name)
			if err != nil {
				t.Fatalf("NonceSize: %v", err)
			}

			var dst bytes.Buffer
			w, err := NewWrapWriter(name, key, &dst)
			if err != nil {
				t.Fatalf("NewWrapWriter: %v", err)
			}
			if _, err := w.Write(nil); err != nil {
				t.Fatalf("empty Write: %v", err)
			}
			if dst.Len() != 0 {
				t.Fatalf("empty Write emitted %d bytes; want 0", dst.Len())
			}
			if err := FinishWrapStream(w); err != nil {
				t.Fatalf("FinishWrapStream: %v", err)
			}
			if dst.Len() != nlen {
				t.Fatalf("finished empty stream emitted %d bytes; want nonce length %d", dst.Len(), nlen)
			}

			// Idempotent: a second finish emits nothing further.
			if err := FinishWrapStream(w); err != nil {
				t.Fatalf("second FinishWrapStream: %v", err)
			}
			if dst.Len() != nlen {
				t.Fatalf("second finish emitted extra bytes: %d total; want %d", dst.Len(), nlen)
			}

			// The nonce-only wire decodes to an empty inner stream on
			// both receive-side entries.
			r, err := NewUnwrapReader(name, key, bytes.NewReader(dst.Bytes()))
			if err != nil {
				t.Fatalf("NewUnwrapReader: %v", err)
			}
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if len(got) != 0 {
				t.Fatalf("NewUnwrapReader decoded %d bytes; want 0", len(got))
			}
			buf := append([]byte(nil), dst.Bytes()...)
			inner, err := UnwrapInPlace(name, key, buf)
			if err != nil {
				t.Fatalf("UnwrapInPlace: %v", err)
			}
			if len(inner) != 0 {
				t.Fatalf("UnwrapInPlace decoded %d bytes; want 0", len(inner))
			}
		})
	}
}

// TestFinishWrapStreamNoOpAfterWrite pins the no-op arms: a WrapWriter
// whose nonce already left with the first body write is untouched by
// FinishWrapStream, and a writer not produced by NewWrapWriter passes
// through untouched as well.
func TestFinishWrapStreamNoOpAfterWrite(t *testing.T) {
	name := CipherNames[0]
	key, err := GenerateKey(name)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var dst bytes.Buffer
	w, err := NewWrapWriter(name, key, &dst)
	if err != nil {
		t.Fatalf("NewWrapWriter: %v", err)
	}
	body := []byte("empty-stream finish must not fire here")
	if _, err := w.Write(body); err != nil {
		t.Fatalf("Write: %v", err)
	}
	emitted := dst.Len()
	if err := FinishWrapStream(w); err != nil {
		t.Fatalf("FinishWrapStream: %v", err)
	}
	if dst.Len() != emitted {
		t.Fatalf("finish after body write emitted extra bytes: %d -> %d", emitted, dst.Len())
	}

	var plain bytes.Buffer
	if err := FinishWrapStream(&plain); err != nil {
		t.Fatalf("FinishWrapStream on foreign writer: %v", err)
	}
	if plain.Len() != 0 {
		t.Fatalf("foreign writer received %d bytes; want 0", plain.Len())
	}
}
