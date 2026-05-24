package ctr

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/everanium/itb/internal/hashprf"
)

// TestBatchKeystreamParity confirms the 4-wide batched keystream for the
// Areion primitives is byte-identical to the single-block PRF-CTR definition:
// block i = PRF(nonce(16) || LE64(i)). The single-block reference is built
// directly from hashprf.New so the test does not depend on the dispatch in
// newPrfHashCTR (which now routes Areion through the batch path).
func TestBatchKeystreamParity(t *testing.T) {
	for _, name := range []string{CipherAreion256, CipherAreion512} {
		ksize, err := hashprf.KeySize(name)
		if err != nil {
			t.Fatalf("%s: KeySize: %v", name, err)
		}
		key := make([]byte, ksize)
		for i := range key {
			key[i] = byte(i*31 + 7)
		}
		nonce := make([]byte, hashCTRNonceSize)
		for i := range nonce {
			nonce[i] = byte(i*13 + 1)
		}

		// Batched keystream under test.
		ks, err := New(name, key, nonce)
		if err != nil {
			t.Fatalf("%s: New: %v", name, err)
		}
		if _, ok := ks.(*prfHashCTRBatch); !ok {
			t.Fatalf("%s: expected *prfHashCTRBatch, got %T", name, ks)
		}
		const total = 4096 // not a multiple of 64 — exercises the tail drain
		got := make([]byte, total)
		ks.XORKeyStream(got, make([]byte, total))

		// Single-block reference: PRF(nonce || LE64(counter)) per blockSize.
		prf, blockSize, err := hashprf.New(name, key)
		if err != nil {
			t.Fatalf("%s: hashprf.New: %v", name, err)
		}
		want := make([]byte, 0, total)
		in := make([]byte, hashCTRNonceSize+8)
		copy(in[:hashCTRNonceSize], nonce)
		blk := make([]byte, blockSize)
		for c := uint64(0); len(want) < total; c++ {
			binary.LittleEndian.PutUint64(in[hashCTRNonceSize:], c)
			prf(blk, in)
			want = append(want, blk...)
		}
		want = want[:total]

		if !bytes.Equal(got, want) {
			t.Fatalf("%s: batched keystream diverges from single-block reference", name)
		}
	}
}
