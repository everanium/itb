package ctr

import (
	"encoding/binary"
	"runtime"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/blake2bctr"
	"github.com/everanium/itb/internal/blake2sctr"
	"github.com/everanium/itb/internal/blake3ctr"
	"github.com/everanium/itb/internal/hashprf"
	"github.com/everanium/itb/internal/wipe"
)

const (
	batchModeClosure uint8 = iota
	batchModeBlake2b256
	batchModeBlake2b512
	batchModeBlake2s
	batchModeBlake3
)

// prfHashCTRBatch is the 4-wide batched counterpart of prfHashCTR. It emits
// the identical keystream — block i is PRF(nonce(16) || LE64(counter_i)) — but
// computes four (or eight) consecutive blocks per SIMD pass, amortising the
// per-block PRF dispatch cost.
type prfHashCTRBatch struct {
	batch        func(dst, in *[4][]byte)
	closeBatch   func()
	blockSize    int
	counter      uint64
	mode         uint8
	hKey64       [8]uint64
	nWords64     [2]uint64
	hKey32       [8]uint32
	nWords32     [4]uint32
	inStore      [4][hashCTRNonceSize + 8]byte // nonce(16) || LE64(counter) per lane
	in           [4][]byte                     // slices into inStore
	out          [4][]byte                     // slices into keystrm (one block each)
	keystrmStore [4 * 64]byte
	keystrm      []byte // 4*blockSize slice into keystrmStore
	keystrmN     int    // unconsumed trailing bytes of keystrm
}

// newPrfHashCTRBatch validates lengths, builds the batch PRF, and wires the
// per-lane input / output slice views.
func newPrfHashCTRBatch(name string, key, nonce []byte,
	batch func(dst, in *[4][]byte), closeBatch func(), blockSize int) (Keystream, error) {
	c := &prfHashCTRBatch{
		batch:      batch,
		closeBatch: closeBatch,
		blockSize:  blockSize,
	}
	c.keystrm = c.keystrmStore[:4*blockSize]
	if batch != nil {
		for lane := 0; lane < 4; lane++ {
			copy(c.inStore[lane][:hashCTRNonceSize], nonce)
			c.in[lane] = c.inStore[lane][:]
			c.out[lane] = c.keystrm[lane*blockSize : (lane+1)*blockSize]
		}
	}
	switch name {
	case hashes.CipherBLAKE2b256:
		var keyBlock [4]uint64
		blake2bctr.InitKey256(key, &c.hKey64, &keyBlock)
		clear(keyBlock[:])
		runtime.KeepAlive(&keyBlock)
		c.nWords64[0] = binary.LittleEndian.Uint64(nonce[0:8])
		c.nWords64[1] = binary.LittleEndian.Uint64(nonce[8:16])
		c.mode = batchModeBlake2b256
	case hashes.CipherBLAKE2b512:
		var keyBlock [4]uint64
		blake2bctr.InitKey512(key, &c.hKey64, &keyBlock)
		clear(keyBlock[:])
		runtime.KeepAlive(&keyBlock)
		c.nWords64[0] = binary.LittleEndian.Uint64(nonce[0:8])
		c.nWords64[1] = binary.LittleEndian.Uint64(nonce[8:16])
		c.mode = batchModeBlake2b512
	case hashes.CipherBLAKE2s:
		var keyWords [8]uint32
		blake2sctr.InitKey(key, &c.hKey32, &keyWords)
		clear(keyWords[:])
		runtime.KeepAlive(&keyWords)
		c.nWords32[0] = binary.LittleEndian.Uint32(nonce[0:4])
		c.nWords32[1] = binary.LittleEndian.Uint32(nonce[4:8])
		c.nWords32[2] = binary.LittleEndian.Uint32(nonce[8:12])
		c.nWords32[3] = binary.LittleEndian.Uint32(nonce[12:16])
		c.mode = batchModeBlake2s
	case hashes.CipherBLAKE3:
		blake3ctr.InitKey(key, &c.hKey32)
		c.nWords32[0] = binary.LittleEndian.Uint32(nonce[0:4])
		c.nWords32[1] = binary.LittleEndian.Uint32(nonce[4:8])
		c.nWords32[2] = binary.LittleEndian.Uint32(nonce[8:12])
		c.nWords32[3] = binary.LittleEndian.Uint32(nonce[12:16])
		c.mode = batchModeBlake3
	}
	return c, nil
}

func (c *prfHashCTRBatch) xorDirectBlocks(dst, src []byte, counter uint64) {
	switch c.mode {
	case batchModeBlake2b256:
		blake2bctr.XORKeyStreamBlocks256(dst, src, &c.hKey64, &c.nWords64, counter)
	case batchModeBlake2b512:
		blake2bctr.XORKeyStreamBlocks512(dst, src, &c.hKey64, &c.nWords64, counter)
	case batchModeBlake2s:
		blake2sctr.XORKeyStreamBlocks(dst, src, &c.hKey32, &c.nWords32, counter)
	case batchModeBlake3:
		blake3ctr.XORKeyStreamBlocks(dst, src, &c.hKey32, &c.nWords32, counter)
	}
}

// refill computes four fresh keystream blocks (counters counter..counter+3)
// into keystrm via one batch call and advances the counter by four.
func (c *prfHashCTRBatch) refill() {
	if c.mode != batchModeClosure {
		clear(c.keystrm)
		c.xorDirectBlocks(c.keystrm, c.keystrm, c.counter)
		c.counter += 4
		c.keystrmN = 4 * c.blockSize
		return
	}
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
	if c.mode != batchModeClosure {
		if c.keystrmN > 0 {
			off := len(c.keystrm) - c.keystrmN
			take := c.keystrmN
			if take > n {
				take = n
			}
			for j := 0; j < take; j++ {
				dst[i+j] = src[i+j] ^ c.keystrm[off+j]
				c.keystrm[off+j] = 0
			}
			i += take
			c.keystrmN -= take
		}
		if nBlocks := (n - i) / c.blockSize; nBlocks > 0 {
			adv := nBlocks * c.blockSize
			c.xorDirectBlocks(dst[i:i+adv], src[i:i+adv], c.counter)
			c.counter += uint64(nBlocks)
			i += adv
		}
		if i < n {
			c.refill()
			rem := n - i
			for j := 0; j < rem; j++ {
				dst[i+j] = src[i+j] ^ c.keystrm[j]
				c.keystrm[j] = 0
			}
			c.keystrmN -= rem
		}
		return
	}
	for i < n {
		if c.keystrmN == 0 {
			c.refill()
		}
		off := len(c.keystrm) - c.keystrmN
		take := c.keystrmN
		if take > n-i {
			take = n - i
		}
		j := 0
		for ; j+8 <= take; j += 8 {
			s := binary.LittleEndian.Uint64(src[i+j : i+j+8])
			k := binary.LittleEndian.Uint64(c.keystrm[off+j : off+j+8])
			binary.LittleEndian.PutUint64(dst[i+j:i+j+8], s^k)
		}
		for ; j < take; j++ {
			dst[i+j] = src[i+j] ^ c.keystrm[off+j]
		}
		i += take
		c.keystrmN -= take
	}
	if n > 0 {
		clear(c.keystrm[:len(c.keystrm)-c.keystrmN])
	}
}

func (c *prfHashCTRBatch) Close() error {
	if c.closeBatch != nil {
		c.closeBatch()
		c.closeBatch = nil
	}
	*c = prfHashCTRBatch{}
	runtime.KeepAlive(c)
	wipe.CallStack512B()
	return nil
}

// tryNewPrfHashCTRBatch returns a batched keystream when name has a SIMD batch
// path, or (nil, false, nil) when it does not (caller falls back to the
// single-block prfHashCTR). Key / nonce lengths are validated by the caller.
func tryNewPrfHashCTRBatch(name string, key, nonce []byte) (Keystream, bool, error) {
	switch name {
	case hashes.CipherBLAKE2b256, hashes.CipherBLAKE2s, hashes.CipherBLAKE3:
		ks, err := newPrfHashCTRBatch(name, key, nonce, nil, nil, 32)
		if err != nil {
			return nil, false, err
		}
		return ks, true, nil
	case hashes.CipherBLAKE2b512:
		ks, err := newPrfHashCTRBatch(name, key, nonce, nil, nil, 64)
		if err != nil {
			return nil, false, err
		}
		return ks, true, nil
	}
	batch, blockSize, ok, closeBatch, err := hashprf.NewBatchRawWithClose(name, key)
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}
	ks, err := newPrfHashCTRBatch(name, key, nonce, batch, closeBatch, blockSize)
	if err != nil {
		if closeBatch != nil {
			closeBatch()
		}
		return nil, false, err
	}
	return ks, true, nil
}
