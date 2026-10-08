package chacha20asm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/chacha20"
)

// The HChaCha20 step and the slot chain against independent references:
// the HChaCha20 vector of draft-irtf-cfrg-xchacha § 2.2.1, the HChaCha20
// function of golang.org/x/crypto/chacha20 on random inputs, and the
// ChaCha20 block function of the same package (RFC 8439 § 2.3) — the
// permuted words 0..3 and 12..15 are the keystream words minus the
// public state words, so the block function pins the step with the
// feed-forward included.

func hchachaRef(t *testing.T, key *[8]uint32, in *[4]uint32) [8]uint32 {
	t.Helper()
	var kb [32]byte
	var nb [16]byte
	for i := range key {
		binary.LittleEndian.PutUint32(kb[4*i:], key[i])
	}
	for i := range in {
		binary.LittleEndian.PutUint32(nb[4*i:], in[i])
	}
	out, err := chacha20.HChaCha20(kb[:], nb[:])
	if err != nil {
		t.Fatal(err)
	}
	var w [8]uint32
	for i := range w {
		w[i] = binary.LittleEndian.Uint32(out[4*i:])
	}
	return w
}

func TestHChaCha20DraftVector(t *testing.T) {
	var kb [32]byte
	for i := range kb {
		kb[i] = byte(i)
	}
	nonce := []byte{0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
		0x00, 0x00, 0x00, 0x00, 0x31, 0x41, 0x59, 0x27}
	expected := []byte{0x82, 0x41, 0x3b, 0x42, 0x27, 0xb2, 0x7b, 0xfe,
		0xd3, 0x0e, 0x42, 0x50, 0x8a, 0x87, 0x7d, 0x73,
		0xa0, 0xf9, 0xe4, 0xd5, 0x8a, 0x74, 0xa8, 0x53,
		0xc1, 0x2e, 0xc4, 0x13, 0x26, 0xd3, 0xec, 0xdc}
	var key [8]uint32
	var in [4]uint32
	for i := range key {
		key[i] = binary.LittleEndian.Uint32(kb[4*i:])
	}
	for i := range in {
		in[i] = binary.LittleEndian.Uint32(nonce[4*i:])
	}
	out := HChaCha20(&key, &in)
	var got [32]byte
	for i := range out {
		binary.LittleEndian.PutUint32(got[4*i:], out[i])
	}
	if !bytes.Equal(got[:], expected) {
		t.Fatalf("HChaCha20 draft vector: got %x, want %x", got[:], expected)
	}
}

func TestHChaCha20MatchesUpstream(t *testing.T) {
	for i := 0; i < 256; i++ {
		var kb [32]byte
		var nb [16]byte
		rand.Read(kb[:])
		rand.Read(nb[:])
		var key [8]uint32
		var in [4]uint32
		for j := range key {
			key[j] = binary.LittleEndian.Uint32(kb[4*j:])
		}
		for j := range in {
			in[j] = binary.LittleEndian.Uint32(nb[4*j:])
		}
		if got, want := HChaCha20(&key, &in), hchachaRef(t, &key, &in); got != want {
			t.Fatalf("HChaCha20 diverges from x/crypto on key %x in %x: got %08x want %08x", kb, nb, got, want)
		}
	}
}

// TestHChaCha20AgainstBlockFunction derives the step from the RFC 8439
// block function: with the counter and nonce words as the input, the
// keystream block of golang.org/x/crypto/chacha20 minus the public
// state words must equal the step's output.
func TestHChaCha20AgainstBlockFunction(t *testing.T) {
	for i := 0; i < 64; i++ {
		var kb [32]byte
		var nb [12]byte
		var ctr [4]byte
		rand.Read(kb[:])
		rand.Read(nb[:])
		rand.Read(ctr[:])
		c, err := chacha20.NewUnauthenticatedCipher(kb[:], nb[:])
		if err != nil {
			t.Fatal(err)
		}
		counter := binary.LittleEndian.Uint32(ctr[:])
		if counter == 0xFFFFFFFF {
			counter--
		}
		c.SetCounter(counter)
		var block [64]byte
		c.XORKeyStream(block[:], block[:])
		var key [8]uint32
		var in [4]uint32
		for j := range key {
			key[j] = binary.LittleEndian.Uint32(kb[4*j:])
		}
		in[0] = counter
		for j := 1; j < 4; j++ {
			in[j] = binary.LittleEndian.Uint32(nb[4*(j-1):])
		}
		got := HChaCha20(&key, &in)
		var want [8]uint32
		for j := 0; j < 4; j++ {
			want[j] = binary.LittleEndian.Uint32(block[4*j:]) - sigma[j]
			want[4+j] = binary.LittleEndian.Uint32(block[4*(12+j):]) - in[j]
		}
		if got != want {
			t.Fatalf("HChaCha20 diverges from the block function: got %08x want %08x", got, want)
		}
	}
}

// chainRef is the slot chain over x/crypto's HChaCha20, independent of
// HChaCha20Chain's own step and encoding code.
func chainRef(t *testing.T, key *[32]byte, data []byte) [4]uint64 {
	t.Helper()
	k := append([]byte(nil), key[:]...)
	blocks := (len(data) + 14) / 15
	if blocks == 0 {
		blocks = 1
	}
	for j := 0; j < blocks; j++ {
		var slot [16]byte
		r := copy(slot[:15], data[15*j:])
		if j == blocks-1 {
			slot[15] = 0x80 | byte(r)
		}
		var err error
		k, err = chacha20.HChaCha20(k, slot[:])
		if err != nil {
			t.Fatal(err)
		}
	}
	var out [4]uint64
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(k[8*i:])
	}
	return out
}

func TestHChaCha20ChainMatchesReference(t *testing.T) {
	for n := 0; n <= 80; n++ {
		for i := 0; i < 4; i++ {
			var key [32]byte
			rand.Read(key[:])
			data := make([]byte, n)
			rand.Read(data)
			if got, want := HChaCha20Chain(&key, data), chainRef(t, &key, data); got != want {
				t.Fatalf("n=%d: chain diverges from the x/crypto reference: got %016x want %016x", n, got, want)
			}
		}
		if want := (n + 14) / 15; (n > 0 && SlotBlocks(n) != want) || (n == 0 && SlotBlocks(0) != 1) {
			t.Fatalf("SlotBlocks(%d) = %d", n, SlotBlocks(n))
		}
	}
}
