package ctr

import (
	"encoding/binary"

	"github.com/everanium/itb/internal/hashprf"
)

// prfHashCTRBatch is the 4-wide batched counterpart of prfHashCTR. It emits
// the identical keystream — block i is PRF(nonce(16) || LE64(counter_i)) — but
// computes four consecutive blocks per refill through a SIMD BatchHashFunc,
// amortising the per-block PRF dispatch cost over a 4-lane batch. It is used
// for the Areion primitives, whose registry BatchHashFunc is bit-exact with
// the single-input HashFunc, so the keystream matches prfHashCTR byte-for-byte.
//
// The keystream buffer holds 4*blockSize bytes; XORKeyStream drains it and
// refills four blocks at a time. The counter advances by four per refill.
type prfHashCTRBatch struct {
	batch     func(dst, in *[4][]byte)
	blockSize int
	counter   uint64
	inStore   [4][hashCTRNonceSize + 8]byte // nonce(16) || LE64(counter) per lane
	in        [4][]byte                     // slices into inStore
	out       [4][]byte                     // slices into keystrm (one block each)
	keystrm   []byte                        // 4*blockSize; lane k at [k*blockSize:]
	keystrmN  int                           // unconsumed trailing bytes of keystrm
}

// newPrfHashCTRBatch validates lengths, builds the batch PRF, and wires the
// per-lane input / output slice views. It is only reached for primitives whose
// hashprf.NewBatch reports a batch path (the Areion family).
func newPrfHashCTRBatch(name string, key, nonce []byte,
	batch func(dst, in *[4][]byte), blockSize int) (Keystream, error) {
	c := &prfHashCTRBatch{
		batch:     batch,
		blockSize: blockSize,
		keystrm:   make([]byte, 4*blockSize),
	}
	for lane := 0; lane < 4; lane++ {
		copy(c.inStore[lane][:hashCTRNonceSize], nonce)
		c.in[lane] = c.inStore[lane][:]
		c.out[lane] = c.keystrm[lane*blockSize : (lane+1)*blockSize]
	}
	return c, nil
}

// refill computes four fresh keystream blocks (counters counter..counter+3)
// into keystrm via one batch call and advances the counter by four.
func (c *prfHashCTRBatch) refill() {
	for lane := 0; lane < 4; lane++ {
		binary.LittleEndian.PutUint64(c.inStore[lane][hashCTRNonceSize:], c.counter+uint64(lane))
	}
	c.batch(&c.out, &c.in)
	c.counter += 4
	c.keystrmN = 4 * c.blockSize
}

func (c *prfHashCTRBatch) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("ctr/hashbatch: short dst")
	}
	n := len(src)
	i := 0
	for i < n {
		if c.keystrmN == 0 {
			c.refill()
		}
		off := len(c.keystrm) - c.keystrmN
		take := c.keystrmN
		if take > n-i {
			take = n - i
		}
		for j := 0; j < take; j++ {
			dst[i+j] = src[i+j] ^ c.keystrm[off+j]
		}
		i += take
		c.keystrmN -= take
	}
}

// tryNewPrfHashCTRBatch returns a batched keystream when name has a SIMD batch
// path, or (nil, false, nil) when it does not (caller falls back to the
// single-block prfHashCTR). Key / nonce lengths are validated by the caller.
func tryNewPrfHashCTRBatch(name string, key, nonce []byte) (Keystream, bool, error) {
	batch, blockSize, ok, err := hashprf.NewBatch(name, key)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}
	ks, err := newPrfHashCTRBatch(name, key, nonce, batch, blockSize)
	if err != nil {
		return nil, false, err
	}
	return ks, true, nil
}
