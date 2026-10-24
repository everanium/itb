package ctr

import (
	"bytes"
	"io"
	"reflect"
	"testing"
	"unsafe"

	"github.com/everanium/itb/hashes"
)

func extractInnerStructView(v any) reflect.Value {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Pointer && !rv.IsNil() {
		return reflect.NewAt(rv.Type().Elem(), unsafe.Pointer(rv.Pointer())).Elem()
	}
	if rv.Kind() == reflect.Struct && rv.NumField() > 0 && rv.Field(0).Kind() == reflect.Pointer {
		f := rv.Field(0)
		if !f.IsNil() {
			return reflect.NewAt(f.Type().Elem(), unsafe.Pointer(f.Pointer())).Elem()
		}
	}
	return reflect.Value{}
}

func TestCTRCloseAndKeystreamBufferZeroization(t *testing.T) {
	ciphers := []string{
		hashes.CipherAES128CTR,
		hashes.CipherAreion256,
		hashes.CipherAreion512,
		hashes.CipherBLAKE2b256,
		hashes.CipherBLAKE2b512,
		hashes.CipherBLAKE2s,
		hashes.CipherBLAKE3,
		hashes.CipherSipHash24,
		hashes.CipherChaCha20,
	}

	// Negative control: confirm a non-zero byte slice is flagged by allZeroBytes.
	if allZeroBytes([]byte{0, 0, 1, 0}) {
		t.Fatal("negative control failed: allZeroBytes reported true on non-zero slice")
	}

	for _, name := range ciphers {
		t.Run(name, func(t *testing.T) {
			ksLen, err := KeySize(name)
			if err != nil {
				t.Fatalf("KeySize(%q): %v", name, err)
			}
			nsLen, err := NonceSize(name)
			if err != nil {
				t.Fatalf("NonceSize(%q): %v", name, err)
			}
			key := make([]byte, ksLen)
			for i := range key {
				key[i] = byte(0x21 + i*5)
			}
			nonce := make([]byte, nsLen)
			for i := range nonce {
				nonce[i] = byte(0x71 + i*3)
			}

			// Both New and NewAt must return an io.Closer.
			s1, err := New(name, key, nonce)
			if err != nil {
				t.Fatalf("New(%q): %v", name, err)
			}
			c1, ok := s1.(io.Closer)
			if !ok {
				t.Fatalf("New(%q) concrete type %T does not implement io.Closer", name, s1)
			}

			s2, err := NewAt(name, key, nonce, 37)
			if err != nil {
				t.Fatalf("NewAt(%q): %v", name, err)
			}
			c2, ok := s2.(io.Closer)
			if !ok {
				t.Fatalf("NewAt(%q) concrete type %T does not implement io.Closer", name, s2)
			}
			_ = c2.Close()

			// Consume a partial block (5 bytes) so buffered keystream is populated,
			// and verify the consumed prefix [0:5] is immediately zeroed in place.
			src := []byte{1, 2, 3, 4, 5}
			dst := make([]byte, len(src))
			s1.XORKeyStream(dst, src)

			var preResetAESStream reflect.Value
			switch impl := s1.(type) {
			case *aesResettable:
				preResetAESStream = extractInnerStructView(impl.stream)
				if !preResetAESStream.IsValid() || preResetAESStream.IsZero() {
					t.Fatal("expected non-zero inner *aes.CTR state before ResetCounter")
				}
			case *sipCTR:
				if !allZeroBytes(impl.keystrm[:5]) {
					t.Fatalf("sipCTR consumed keystream bytes [0:5] not zeroed: %x", impl.keystrm[:5])
				}
			case *prfHashCTR:
				if !allZeroBytes(impl.keystrm[:5]) {
					t.Fatalf("prfHashCTR consumed keystream bytes [0:5] not zeroed: %x", impl.keystrm[:5])
				}
			case *prfHashCTRBatch:
				if !allZeroBytes(impl.keystrm[:5]) {
					t.Fatalf("prfHashCTRBatch consumed keystream bytes [0:5] not zeroed: %x", impl.keystrm[:5])
				}
			case *chaCha20Resettable:
				if !allZeroBytes(impl.buf[:5]) {
					t.Fatalf("chaCha20Resettable consumed keystream bytes [0:5] not zeroed: %x", impl.buf[:5])
				}
			}

			// ResetCounter must clear any buffered keystream bytes and wipe old *aes.CTR.
			if r, ok := s1.(ResettableKeystream); ok {
				if err := r.ResetCounter(13); err != nil {
					t.Fatalf("ResetCounter(%q): %v", name, err)
				}
			}
			if preResetAESStream.IsValid() && !preResetAESStream.IsZero() {
				t.Fatal("old *aes.CTR struct inside cipher.aesCtrWrapper was not zeroed on ResetCounter")
			}

			var preCloseAESStream, preCloseAESBlock reflect.Value
			if impl, ok := s1.(*aesResettable); ok {
				preCloseAESStream = extractInnerStructView(impl.stream)
				preCloseAESBlock = extractInnerStructView(impl.block)
			}

			// Close must zero all internal state.
			if err := c1.Close(); err != nil {
				t.Fatalf("Close(%q): %v", name, err)
			}

			switch impl := s1.(type) {
			case *aesResettable:
				if !allZeroBytes(impl.nonce[:]) {
					t.Fatalf("aesResettable nonce not zeroed on Close: %x", impl.nonce)
				}
				if impl.block != nil || impl.stream != nil {
					t.Fatal("aesResettable block/stream not nilled on Close")
				}
				if !preCloseAESStream.IsValid() || !preCloseAESStream.IsZero() {
					t.Fatal("inner *aes.CTR struct inside cipher.aesCtrWrapper was not zeroed on Close")
				}
				if !preCloseAESBlock.IsValid() || !preCloseAESBlock.IsZero() {
					t.Fatal("inner *aes.Block struct was not zeroed on Close")
				}
			case *sipCTR:
				if impl.k0 != 0 || impl.k1 != 0 || !allZeroBytes(impl.keystrm[:]) {
					t.Fatal("sipCTR state not zeroed on Close")
				}
			case *prfHashCTR:
				if !allZeroBytes(impl.input[:]) || !allZeroBytes(impl.keystrm[:]) {
					t.Fatal("prfHashCTR state not zeroed on Close")
				}
			case *prfHashCTRBatch:
				if !allZeroBytes(impl.keystrm[:]) {
					t.Fatal("prfHashCTRBatch keystrm not zeroed on Close")
				}
				for lane := range impl.inStore {
					if !allZeroBytes(impl.inStore[lane][:]) {
						t.Fatalf("prfHashCTRBatch inStore[%d] not zeroed on Close", lane)
					}
				}
			case *chaCha20Resettable:
				if impl.key != ([8]uint32{}) || impl.nonce != ([3]uint32{}) || !allZeroBytes(impl.buf[:]) {
					t.Fatal("chaCha20Resettable state not zeroed on Close")
				}
			}
		})
	}
}

func allZeroBytes(b []byte) bool {
	return bytes.Equal(b, make([]byte, len(b)))
}
