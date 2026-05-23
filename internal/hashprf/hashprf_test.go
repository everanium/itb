package hashprf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// prims enumerates the six primitives with their expected key and block
// (output) widths.
var prims = []struct {
	name      string
	keySize   int
	blockSize int
}{
	{Areion256, 32, 32},
	{Areion512, 64, 64},
	{BLAKE2b256, 32, 32},
	{BLAKE2b512, 32, 64},
	{BLAKE2s, 32, 32},
	{BLAKE3, 32, 32},
}

// TestKeyBlockSizes verifies the declared key and block sizes and the
// unknown-name error paths.
func TestKeyBlockSizes(t *testing.T) {
	for _, p := range prims {
		ks, err := KeySize(p.name)
		if err != nil {
			t.Fatalf("KeySize(%q): %v", p.name, err)
		}
		if ks != p.keySize {
			t.Errorf("KeySize(%q) = %d, want %d", p.name, ks, p.keySize)
		}
		bs, err := BlockSize(p.name)
		if err != nil {
			t.Fatalf("BlockSize(%q): %v", p.name, err)
		}
		if bs != p.blockSize {
			t.Errorf("BlockSize(%q) = %d, want %d", p.name, bs, p.blockSize)
		}
	}
	if _, err := KeySize("nope"); err == nil {
		t.Error("KeySize(unknown) returned nil error")
	}
	if _, err := BlockSize("nope"); err == nil {
		t.Error("BlockSize(unknown) returned nil error")
	}
	if _, _, err := New("nope", make([]byte, 32)); err == nil {
		t.Error("New(unknown) returned nil error")
	}
}

// TestNewKeyLength rejects keys whose length does not match KeySize.
func TestNewKeyLength(t *testing.T) {
	for _, p := range prims {
		for _, bad := range []int{0, p.keySize - 1, p.keySize + 1} {
			if _, _, err := New(p.name, make([]byte, bad)); err == nil {
				t.Errorf("New(%q) accepted key length %d (want %d)", p.name, bad, p.keySize)
			}
		}
	}
}

// TestPRFShape confirms New returns the declared block size and the PRF
// writes exactly that many bytes, and is deterministic for fixed inputs.
func TestPRFShape(t *testing.T) {
	for _, p := range prims {
		key := bytes.Repeat([]byte{0x5a}, p.keySize)
		prf, bs, err := New(p.name, key)
		if err != nil {
			t.Fatalf("New(%q): %v", p.name, err)
		}
		if bs != p.blockSize {
			t.Errorf("New(%q) blockSize = %d, want %d", p.name, bs, p.blockSize)
		}
		in := []byte("hashprf-input")
		out1 := make([]byte, bs)
		out2 := make([]byte, bs)
		prf(out1, in)
		prf(out2, in)
		if !bytes.Equal(out1, out2) {
			t.Errorf("%s: PRF is not deterministic", p.name)
		}
		// Distinct input yields distinct output.
		other := make([]byte, bs)
		prf(other, []byte("different-input"))
		if bytes.Equal(out1, other) {
			t.Errorf("%s: distinct inputs produced equal output", p.name)
		}
	}
}

// TestPRFRegression pins one output per primitive over a fixed key and
// input as a regression anchor. These vectors were produced by this
// implementation.
func TestPRFRegression(t *testing.T) {
	in := []byte("regression-vector-input")
	cases := []struct {
		name string
		want string
	}{
		{Areion256, "4e4dba2c59c8fe930649304b16365131028038d4efe7dd1c351b7e6b5d56b880"},
		{Areion512, "571772eb3d57f5d75be5b28fd960bdb32fab0594dea148decaa27002c99b1dd29f881c3e6347a512269b71e8685ef3cf38f2f655d062fa70af49cf9de8130213"},
		{BLAKE2b256, "7a172a3e6d568847321a0f43318e77f8fa0566fd38230a0f39232d729a7d2fda"},
		{BLAKE2b512, "3a8f333fff6613bfc0b0d0490f9529eee4642b91e7df425e4da1bc4f290ba38b36ee17e8f6130916985d38ee0a46ae4a45c03c9018252b770b011552c48c786d"},
		{BLAKE2s, "45d3b20804c1380a77049cb9c89829e23d7e32a5a98bc15a9aea274fcdf19c97"},
		{BLAKE3, "7b7b8ae52baa66b5b0b815c6a12f2e20dabb95844d6146abcd98916da653c0d1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ks, _ := KeySize(c.name)
			key := make([]byte, ks)
			for i := range key {
				key[i] = byte(i)
			}
			prf, bs, err := New(c.name, key)
			if err != nil {
				t.Fatal(err)
			}
			out := make([]byte, bs)
			prf(out, in)
			if got := hex.EncodeToString(out); got != c.want {
				t.Errorf("%s PRF = %s, want %s", c.name, got, c.want)
			}
		})
	}
}
