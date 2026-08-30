package ctr

import (
	"bytes"
	"testing"
)

// TestNewAtParity proves NewAt is byte-exact: for every cipher and a range of
// byte offsets (block-aligned and intra-block), the keystream from NewAt at
// offset O equals the serial keystream sliced at [O:]. This is the correctness
// guarantee the parallel wrapper relies on, and it is purely deterministic
// counter arithmetic — independent of CPU count or scheduling. On a 1-core
// host the wrapper simply runs one worker (offset 0 == New); the seek math
// here holds regardless.
func TestNewAtParity(t *testing.T) {
	const total = 8192
	for _, name := range []string{
		CipherAreion256, CipherAreion512, CipherBLAKE2b256, CipherBLAKE2b512,
		CipherBLAKE2s, CipherBLAKE3, CipherAES128CTR, CipherSipHash24,
		CipherChaCha20,
	} {
		ksize, err := KeySize(name)
		if err != nil {
			t.Fatalf("%s: KeySize: %v", name, err)
		}
		nsize, err := NonceSize(name)
		if err != nil {
			t.Fatalf("%s: NonceSize: %v", name, err)
		}
		key := make([]byte, ksize)
		nonce := make([]byte, nsize)
		for i := range key {
			key[i] = byte(i*37 + 5)
		}
		for i := range nonce {
			nonce[i] = byte(i*19 + 3)
		}

		// Serial reference keystream.
		ref, err := New(name, key, nonce)
		if err != nil {
			t.Fatalf("%s: New: %v", name, err)
		}
		full := make([]byte, total)
		ref.XORKeyStream(full, full)

		// Offsets: 0, intra-block, block-aligned, cross-block, and an odd large one.
		for _, off := range []int{0, 1, 15, 16, 31, 32, 63, 64, 100, 1000, 4097} {
			if off >= total {
				continue
			}
			ks, err := NewAt(name, key, nonce, off)
			if err != nil {
				t.Fatalf("%s: NewAt(%d): %v", name, off, err)
			}
			got := make([]byte, total-off)
			ks.XORKeyStream(got, got)
			if !bytes.Equal(got, full[off:]) {
				t.Fatalf("%s: NewAt(%d) diverges from serial[%d:]", name, off, off)
			}
		}
	}
}

// TestNewAtChaCha20CounterOverflow guards against silent uint32 wrap of the
// ChaCha20 block counter in `NewAt`. RFC 8439 fixes the ChaCha20 block
// counter at 32 bits; a byteOffset at or above 2^38 (~256 GiB) implies a
// block index at or above 2^32, which `uint32(blockOff)` would silently
// truncate — corrupting the outer-layer format-deniability keystream past
// the seek point. Inner ITB confidentiality does not ride the outer cipher,
// so this is not a confidentiality break; but the caller must see an
// explicit error, not a wrapped keystream.
//
// Boundary: block index 2^32 − 1 (byteOffset (2^38 − 64)..(2^38 − 1)) is the
// last valid ChaCha20 counter and must succeed; block index 2^32 (byteOffset
// 2^38 onward) is the first overflowing seek and must return an error whose
// text names both the failure ("counter overflow") and the intact layer
// ("inner ITB confidentiality unaffected"), so a future reader of the error
// does not misread it as a confidentiality regression. The AES-CTR escape
// (128-bit big-endian counter) is separately covered by `TestNewAtParity`
// on `CipherAES128CTR`.
func TestNewAtChaCha20CounterOverflow(t *testing.T) {
	ksize, err := KeySize(CipherChaCha20)
	if err != nil {
		t.Fatalf("KeySize: %v", err)
	}
	nsize, err := NonceSize(CipherChaCha20)
	if err != nil {
		t.Fatalf("NonceSize: %v", err)
	}
	key := make([]byte, ksize)
	nonce := make([]byte, nsize)

	// ChaCha20 block size = 64 bytes; counter width = 32 bits.
	// Last valid block index = 2^32 − 1; last valid byteOffset in that block
	// = block_index * 64 + 63 = (2^32 − 1) * 64 + 63 = 2^38 − 1.
	// First overflowing byteOffset = 2^38 (block index = 2^32).
	const lastValidByteOffset = (1 << 38) - 1
	const firstOverflowByteOffset = 1 << 38

	// The last valid seek must succeed — no bogus rejection at the boundary.
	if _, err := NewAt(CipherChaCha20, key, nonce, lastValidByteOffset); err != nil {
		t.Fatalf("NewAt(chacha20, byteOffset=2^38-1): expected success at the last valid block index, got error: %v", err)
	}

	// A block-aligned last valid position (2^32 − 1 whole blocks in) must also succeed.
	if _, err := NewAt(CipherChaCha20, key, nonce, (1<<32-1)*64); err != nil {
		t.Fatalf("NewAt(chacha20, byteOffset=(2^32-1)*64): expected success at block-aligned last valid counter, got error: %v", err)
	}

	// First overflowing seek must return an explicit error, not a silently
	// wrapped keystream.
	_, err = NewAt(CipherChaCha20, key, nonce, firstOverflowByteOffset)
	if err == nil {
		t.Fatalf("NewAt(chacha20, byteOffset=2^38): expected counter-overflow error, got nil (silent uint32 wrap)")
	}

	// The error text must both (a) name the failure and (b) reassure that
	// inner ITB confidentiality is intact, so a future reader does not
	// misdiagnose this as a confidentiality break.
	msg := err.Error()
	for _, needle := range []string{"chacha20", "overflow", "confidentiality unaffected"} {
		if !bytes.Contains([]byte(msg), []byte(needle)) {
			t.Errorf("NewAt overflow error text missing %q for scope clarity: %q", needle, msg)
		}
	}
}
