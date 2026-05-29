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

// batchPrims lists the primitives that expose a 4-wide batch PRF (only the
// Areion family; BLAKE has no native SIMD batch path).
var batchPrims = []struct {
	name      string
	keySize   int
	blockSize int
}{
	{Areion256, 32, 32},
	{Areion512, 64, 64},
}

// nonBatchPrims lists primitives that do NOT expose a batch path; NewBatch
// must report ok=false with no error for each.
var nonBatchPrims = []struct {
	name    string
	keySize int
}{
	{BLAKE2b256, 32},
	{BLAKE2b512, 32},
	{BLAKE2s, 32},
	{BLAKE3, 32},
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

// TestNewBatchShape verifies NewBatch returns the declared block size and
// ok=true for batch-capable primitives, and writes exactly blockSize bytes
// into each of the four lanes.
func TestNewBatchShape(t *testing.T) {
	for _, p := range batchPrims {
		key := bytes.Repeat([]byte{0xa5}, p.keySize)
		batch, bs, ok, err := NewBatch(p.name, key)
		if err != nil {
			t.Fatalf("NewBatch(%q): %v", p.name, err)
		}
		if !ok {
			t.Fatalf("NewBatch(%q) ok = false, want true", p.name)
		}
		if bs != p.blockSize {
			t.Errorf("NewBatch(%q) blockSize = %d, want %d", p.name, bs, p.blockSize)
		}
		var in [4][]byte
		var dst [4][]byte
		for lane := 0; lane < 4; lane++ {
			in[lane] = []byte("batch-input-lane-X")
			in[lane][len(in[lane])-1] = byte('0' + lane)
			dst[lane] = make([]byte, bs)
		}
		batch(&dst, &in)
		// Per-lane output is non-zero (PRF over a non-trivial key/input).
		zero := make([]byte, bs)
		for lane := 0; lane < 4; lane++ {
			if bytes.Equal(dst[lane], zero) {
				t.Errorf("%s lane %d: PRF output is all zero", p.name, lane)
			}
		}
		// Distinct lane inputs produce distinct outputs.
		for i := 0; i < 4; i++ {
			for j := i + 1; j < 4; j++ {
				if bytes.Equal(dst[i], dst[j]) {
					t.Errorf("%s: lane %d and lane %d produced equal output", p.name, i, j)
				}
			}
		}
	}
}

// TestNewBatchEqualsSingle is the load-bearing security claim of the batch
// path: each lane's batched output must equal the single-input PRF over the
// same key and input, byte-for-byte. The CTR keystream's batched code path
// relies on this equivalence to remain interoperable with the single-block
// path under the same (key, nonce, counter).
func TestNewBatchEqualsSingle(t *testing.T) {
	for _, p := range batchPrims {
		key := make([]byte, p.keySize)
		for i := range key {
			key[i] = byte(0x10 + i)
		}
		// Build the batched and the single-input PRF over the same key.
		batch, bs, ok, err := NewBatch(p.name, key)
		if err != nil || !ok {
			t.Fatalf("NewBatch(%q): err=%v ok=%v", p.name, err, ok)
		}
		single, sbs, err := New(p.name, key)
		if err != nil {
			t.Fatalf("New(%q): %v", p.name, err)
		}
		if bs != sbs {
			t.Fatalf("%s: batch blockSize %d != single blockSize %d", p.name, bs, sbs)
		}
		// Four distinct inputs of equal length across the batch. The Areion
		// SIMD batch path requires every lane to feed an input of the same
		// length (it interleaves the lanes through one shared permutation
		// pipeline); the canonical caller - the ctr PRF-counter keystream -
		// always supplies four 24-byte (nonce || counter) inputs, so this
		// equivalence test exercises the same regime.
		base := bytes.Repeat([]byte{0x00}, 24)
		inputs := [4][]byte{}
		for lane := 0; lane < 4; lane++ {
			b := append([]byte(nil), base...)
			b[0] = byte(0xa0 + lane) // distinct per lane
			b[8] = byte(lane)        // distinct counter-shaped tail
			inputs[lane] = b
		}
		var batchIn [4][]byte
		var batchOut [4][]byte
		for lane := 0; lane < 4; lane++ {
			batchIn[lane] = inputs[lane]
			batchOut[lane] = make([]byte, bs)
		}
		batch(&batchOut, &batchIn)
		// Single-input PRF over each lane's input.
		for lane := 0; lane < 4; lane++ {
			singleOut := make([]byte, bs)
			single(singleOut, inputs[lane])
			if !bytes.Equal(batchOut[lane], singleOut) {
				t.Errorf("%s lane %d: batched output differs from single-input PRF\n  batch:  %x\n  single: %x",
					p.name, lane, batchOut[lane], singleOut)
			}
		}
	}
}

// TestNewBatchUnsupported verifies NewBatch returns ok=false with no error
// for primitives lacking a SIMD batch path (the BLAKE family). Callers fall
// back to four independent New() invocations in that case.
func TestNewBatchUnsupported(t *testing.T) {
	for _, p := range nonBatchPrims {
		key := bytes.Repeat([]byte{0x42}, p.keySize)
		batch, bs, ok, err := NewBatch(p.name, key)
		if err != nil {
			t.Errorf("NewBatch(%q): unexpected error %v", p.name, err)
		}
		if ok {
			t.Errorf("NewBatch(%q): ok = true, want false (no batch path for this primitive)", p.name)
		}
		if batch != nil {
			t.Errorf("NewBatch(%q): batch != nil for unsupported primitive", p.name)
		}
		if bs != 0 {
			t.Errorf("NewBatch(%q): blockSize = %d, want 0 for unsupported primitive", p.name, bs)
		}
	}
}

// TestNewBatchErrors verifies the unknown-name and wrong-key-length error
// paths of NewBatch.
func TestNewBatchErrors(t *testing.T) {
	if _, _, _, err := NewBatch("nope", make([]byte, 32)); err == nil {
		t.Error("NewBatch(unknown): expected error, got nil")
	}
	for _, p := range batchPrims {
		for _, bad := range []int{0, p.keySize - 1, p.keySize + 1} {
			if _, _, _, err := NewBatch(p.name, make([]byte, bad)); err == nil {
				t.Errorf("NewBatch(%q): accepted key length %d (want %d)", p.name, bad, p.keySize)
			}
		}
	}
	// Unknown-name error path on the BLAKE family side too - NewBatch must
	// reject the name before reaching the ok=false branch.
	for _, p := range nonBatchPrims {
		for _, bad := range []int{0, p.keySize - 1, p.keySize + 1} {
			if _, _, _, err := NewBatch(p.name, make([]byte, bad)); err == nil {
				t.Errorf("NewBatch(%q): accepted key length %d (want %d)", p.name, bad, p.keySize)
			}
		}
	}
}
