package ctr

import (
	"encoding/binary"
	"fmt"

	"github.com/everanium/itb/internal/hashprf"
)

// Cipher names for the six hash-based PRF-CTR keystreams. The names match
// the ITB registry identifiers for these primitives.
const (
	CipherAreion256  = "areion256"
	CipherAreion512  = "areion512"
	CipherBLAKE2b256 = "blake2b256"
	CipherBLAKE2b512 = "blake2b512"
	CipherBLAKE2s    = "blake2s"
	CipherBLAKE3     = "blake3"
)

// hashCTRNonceSize is the nonce length shared by all six hash-based
// PRF-CTR keystreams.
const hashCTRNonceSize = 16

// newPrfHashCTR validates the key and nonce lengths for one of the six
// hash-based primitives, builds the keyed PRF via internal/hashprf, and
// returns a prfHashCTR keystream.
func newPrfHashCTR(name string, key, nonce []byte) (Keystream, error) {
	ksize, err := hashprf.KeySize(name)
	if err != nil {
		return nil, fmt.Errorf("ctr: %w", err)
	}
	if len(key) != ksize {
		return nil, fmt.Errorf("ctr: %s key must be %d bytes, got %d", name, ksize, len(key))
	}
	if len(nonce) != hashCTRNonceSize {
		return nil, fmt.Errorf("ctr: %s nonce must be %d bytes, got %d", name, hashCTRNonceSize, len(nonce))
	}
	prf, blockSize, err := hashprf.New(name, key)
	if err != nil {
		return nil, fmt.Errorf("ctr: %w", err)
	}
	c := &prfHashCTR{
		prf:       prf,
		blockSize: blockSize,
		keystrm:   make([]byte, blockSize),
		input:     make([]byte, hashCTRNonceSize+8),
	}
	copy(c.input[:hashCTRNonceSize], nonce)
	return c, nil
}

// prfHashCTR is a counter-mode keystream over a fixed-output-width keyed
// PRF. Keystream block i is
//
//	PRF(nonce(16) || LE64(counter_i))   (blockSize bytes per call)
//
// XORed over src into dst. The counter is a uint64 starting at 0. XORing
// PRF output with plaintext is the canonical PRF-secure stream, sound
// under the same PRF assumption that justifies AES-CTR.
//
// The drain / bulk / tail discipline mirrors sipCTR: a partial-block
// buffer drains leftover keystream bytes, a bulk loop emits whole blocks,
// and a tail refill consumes the leading bytes of one fresh block.
type prfHashCTR struct {
	prf       func(dst, in []byte)
	blockSize int
	counter   uint64
	input     []byte // nonce(16) || LE64(counter), reused per block
	keystrm   []byte // one PRF block; unconsumed tail at keystrm[blockSize-keystrmN:]
	keystrmN  int    // number of unconsumed bytes in keystrm
}

// refill computes one fresh keystream block from the current counter into
// keystrm and advances the counter, marking the whole block unconsumed.
func (c *prfHashCTR) refill() {
	binary.LittleEndian.PutUint64(c.input[hashCTRNonceSize:], c.counter)
	c.prf(c.keystrm, c.input)
	c.counter++
	c.keystrmN = c.blockSize
}

func (c *prfHashCTR) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("ctr/hash: short dst")
	}
	n := len(src)
	i := 0

	// Drain leftover bytes from a previous partial refill, byte by byte.
	if c.keystrmN > 0 {
		off := c.blockSize - c.keystrmN
		take := c.keystrmN
		if take > n {
			take = n
		}
		for j := 0; j < take; j++ {
			dst[i+j] = src[i+j] ^ c.keystrm[off+j]
		}
		i += take
		c.keystrmN -= take
	}

	// Bulk path: one PRF block per blockSize bytes of output.
	for n-i >= c.blockSize {
		binary.LittleEndian.PutUint64(c.input[hashCTRNonceSize:], c.counter)
		c.prf(c.keystrm, c.input)
		c.counter++
		for j := 0; j < c.blockSize; j++ {
			dst[i+j] = src[i+j] ^ c.keystrm[j]
		}
		i += c.blockSize
	}

	// Tail (< blockSize bytes): refill the buffer and consume its lead.
	if i < n {
		c.refill()
		rem := n - i
		for j := 0; j < rem; j++ {
			dst[i+j] = src[i+j] ^ c.keystrm[j]
		}
		c.keystrmN -= rem
	}
}
