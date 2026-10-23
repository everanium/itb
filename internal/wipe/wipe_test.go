package wipe

import (
	"crypto/aes"
	"crypto/cipher"
	"reflect"
	"testing"
	"unsafe"
)

func TestBytesAndUint64s(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	Bytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("b[%d] = %d, want 0", i, v)
		}
	}
	Bytes(nil)

	u := []uint64{0xdeadbeef, 0xcafebabe}
	Uint64s(u)
	for i, v := range u {
		if v != 0 {
			t.Fatalf("u[%d] = %#x, want 0", i, v)
		}
	}
	Uint64s(nil)
}

func TestStructPtr(t *testing.T) {
	var key [16]byte
	var iv [16]byte
	for i := range key {
		key[i] = byte(i + 1)
		iv[i] = byte(0xa0 + i)
	}
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	st := cipher.NewCTR(blk, iv[:])
	// Extract the underlying *aes.CTR pointer inside cipher.aesCtrWrapper
	// before wiping so we can verify its embedded aes.Block copy is zeroed.
	stVal := reflect.ValueOf(st)
	var innerCTR reflect.Value
	if stVal.Kind() == reflect.Struct && stVal.NumField() > 0 && stVal.Field(0).Kind() == reflect.Pointer {
		f := stVal.Field(0)
		innerCTR = reflect.NewAt(f.Type().Elem(), unsafe.Pointer(f.Pointer())).Elem()
	}

	StructPtr(st)
	StructPtr(blk)

	if !reflect.ValueOf(blk).Elem().IsZero() {
		t.Fatalf("expected *aes.Block struct to be all-zero after StructPtr")
	}
	if innerCTR.IsValid() && !innerCTR.IsZero() {
		t.Fatalf("expected *aes.CTR embedded inside cipher.Stream value wrapper to be all-zero after StructPtr")
	}
	StructPtr(nil)
}

func TestCallStackHelpers(t *testing.T) {
	CallStack2K([9][8]uint64{})
	CallStack4K([9][8]uint64{})
	CallStack8K([9][8]uint64{})
	CallStack12K([9][8]uint64{})
}
