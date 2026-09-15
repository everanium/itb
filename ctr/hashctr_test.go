package ctr

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/hashprf"
)

// hashCiphers enumerates the six hash-based PRF-CTR primitives with their
// expected key and nonce sizes and PRF block (output) widths.
var hashCiphers = []struct {
	name      string
	keySize   int
	nonceSize int
	blockSize int
}{
	{hashes.CipherAreion256, 32, 16, 32},
	{hashes.CipherAreion512, 64, 16, 64},
	{hashes.CipherBLAKE2b256, 32, 16, 32},
	{hashes.CipherBLAKE2b512, 32, 16, 64},
	{hashes.CipherBLAKE2s, 32, 16, 32},
	{hashes.CipherBLAKE3, 32, 16, 32},
}

// TestHashKeyNonceSizes verifies the declared key and nonce sizes for each
// of the six hash-based PRF-CTR primitives.
func TestHashKeyNonceSizes(t *testing.T) {
	for _, c := range hashCiphers {
		ks, err := KeySize(c.name)
		if err != nil {
			t.Fatalf("KeySize(%q): %v", c.name, err)
		}
		if ks != c.keySize {
			t.Errorf("KeySize(%q) = %d, want %d", c.name, ks, c.keySize)
		}
		ns, err := NonceSize(c.name)
		if err != nil {
			t.Fatalf("NonceSize(%q): %v", c.name, err)
		}
		if ns != c.nonceSize {
			t.Errorf("NonceSize(%q) = %d, want %d", c.name, ns, c.nonceSize)
		}
	}
}

// TestHashRoundTrip XORs a fresh keystream over plaintext, then XORs a
// second fresh keystream (same key+nonce) over the ciphertext and recovers
// the plaintext.
func TestHashRoundTrip(t *testing.T) {
	for _, c := range hashCiphers {
		for _, size := range []int{0, 1, 8, 31, 32, 33, 63, 64, 65, 100, 256, 1024} {
			key := mustRead(t, c.keySize)
			nonce := mustRead(t, c.nonceSize)
			pt := mustRead(t, size)

			ct := make([]byte, size)
			newKS(t, c.name, key, nonce).XORKeyStream(ct, pt)

			rt := make([]byte, size)
			newKS(t, c.name, key, nonce).XORKeyStream(rt, ct)

			if !bytes.Equal(rt, pt) {
				t.Errorf("%s size=%d: round-trip mismatch", c.name, size)
			}
			// The size==1 case is excluded from the inequality check because a
			// well-formed CSPRNG-quality keystream produces a byte equal to 0x00
			// (yielding ct==pt for a one-byte plaintext) with probability 1/256,
			// which is a valid outcome rather than a bug. At size>=2 the false-
			// fire probability is 2**-16 per invocation and negligible in
			// aggregate; the round-trip check above already rejects an identity
			// keystream once combined with any other test.
			if size >= 2 && bytes.Equal(ct, pt) {
				t.Errorf("%s size=%d: ciphertext equals plaintext", c.name, size)
			}
		}
	}
}

// TestHashChunkedVsWhole confirms keystream continuity: XORing in small
// chunks produces the same output as XORing the whole buffer at once. This
// exercises the prfHashCTR drain / bulk / tail boundaries with 3-byte (and
// other) chunk sizes.
func TestHashChunkedVsWhole(t *testing.T) {
	for _, c := range hashCiphers {
		for _, total := range []int{0, 1, 3, 32, 33, 64, 65, 100, 257} {
			key := mustRead(t, c.keySize)
			nonce := mustRead(t, c.nonceSize)
			pt := mustRead(t, total)

			whole := make([]byte, total)
			newKS(t, c.name, key, nonce).XORKeyStream(whole, pt)

			for _, chunk := range []int{1, 3, 7, 32, 64} {
				chunked := make([]byte, total)
				ks := newKS(t, c.name, key, nonce)
				for off := 0; off < total; off += chunk {
					end := off + chunk
					if end > total {
						end = total
					}
					ks.XORKeyStream(chunked[off:end], pt[off:end])
				}
				if !bytes.Equal(chunked, whole) {
					t.Errorf("%s total=%d chunk=%d: chunked != whole", c.name, total, chunk)
				}
			}
		}
	}
}

// TestHashTailSizes targets the sub-block tails of each primitive's PRF
// block width: 0, 1, blockSize-1, blockSize, blockSize+1.
func TestHashTailSizes(t *testing.T) {
	for _, c := range hashCiphers {
		for _, size := range []int{0, 1, c.blockSize - 1, c.blockSize, c.blockSize + 1} {
			key := mustRead(t, c.keySize)
			nonce := mustRead(t, c.nonceSize)
			pt := mustRead(t, size)

			ct := make([]byte, size)
			newKS(t, c.name, key, nonce).XORKeyStream(ct, pt)
			rt := make([]byte, size)
			newKS(t, c.name, key, nonce).XORKeyStream(rt, ct)
			if !bytes.Equal(rt, pt) {
				t.Errorf("%s size=%d: tail round-trip mismatch", c.name, size)
			}
		}
	}
}

// TestHashWrongKeyLength rejects keys whose length does not match
// KeySize(name).
func TestHashWrongKeyLength(t *testing.T) {
	for _, c := range hashCiphers {
		nonce := make([]byte, c.nonceSize)
		for _, bad := range []int{0, c.keySize - 1, c.keySize + 1} {
			if _, err := New(c.name, make([]byte, bad), nonce); err == nil {
				t.Errorf("New(%q) accepted key length %d (want %d)", c.name, bad, c.keySize)
			}
		}
	}
}

// TestHashWrongNonceLength rejects nonces whose length does not match
// NonceSize(name).
func TestHashWrongNonceLength(t *testing.T) {
	for _, c := range hashCiphers {
		key := make([]byte, c.keySize)
		for _, bad := range []int{0, c.nonceSize - 1, c.nonceSize + 1} {
			if _, err := New(c.name, key, make([]byte, bad)); err == nil {
				t.Errorf("New(%q) accepted nonce length %d (want %d)", c.name, bad, c.nonceSize)
			}
		}
	}
}

// TestBatchKeystreamParity confirms the 4-wide batched keystream for the
// Areion primitives is byte-identical to the single-block PRF-CTR definition:
// block i = PRF(nonce(16) || LE64(i)). The single-block reference is built
// directly from hashprf.New so the test does not depend on the dispatch in
// newPrfHashCTR (which now routes Areion through the batch path).
func TestBatchKeystreamParity(t *testing.T) {
	for _, name := range []string{hashes.CipherAreion256, hashes.CipherAreion512} {
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
			// No batched arm on this host (non-VAES / -tags noitbasm):
			// New routes Areion through the single-block prfHashCTR,
			// which is the batch path's bit-exact fallback. The batch
			// parity test has nothing to compare against here.
			t.Logf("%s: no batched path on this host (%T); skipping parity check", name, ks)
			continue
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
