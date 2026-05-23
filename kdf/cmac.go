package kdf

import (
	"crypto/cipher"
	"crypto/subtle"
)

// cmac is a CMAC (RFC 4493) instance over a keyed block cipher. It
// computes a full-width tag (one cipher block) over arbitrary-length
// input, as required by the SP 800-108 Counter Mode PRF.
type cmac struct {
	block cipher.Block
	bs    int    // cipher block size
	k1    []byte // subkey for messages whose final block is complete
	k2    []byte // subkey for messages requiring 10* padding
}

// newCMAC builds a CMAC instance over an already-keyed block cipher.
// The two subkeys K1 and K2 are derived once per RFC 4493 §2.3.
func newCMAC(block cipher.Block) *cmac {
	bs := block.BlockSize()

	// L = AES_K(0^bs)
	l := make([]byte, bs)
	block.Encrypt(l, l)

	k1 := dbl(l)
	k2 := dbl(k1)

	return &cmac{
		block: block,
		bs:    bs,
		k1:    k1,
		k2:    k2,
	}
}

// sum returns the CMAC tag (one block, bs bytes) over msg.
func (c *cmac) sum(msg []byte) []byte {
	bs := c.bs

	// Number of blocks, rounding up; a single empty/short block when msg
	// is empty so the final-block path always runs over one block.
	var n int
	if len(msg) == 0 {
		n = 1
	} else {
		n = (len(msg) + bs - 1) / bs
	}

	lastComplete := len(msg) != 0 && len(msg)%bs == 0

	// Final block M_last: either M_n XOR K1 (complete last block) or
	// (M_n || 10*) XOR K2 (incomplete / empty last block).
	last := make([]byte, bs)
	lastOff := (n - 1) * bs
	if lastComplete {
		copy(last, msg[lastOff:])
		xorInto(last, c.k1)
	} else {
		rem := copy(last, msg[lastOff:])
		last[rem] = 0x80 // 10* padding
		xorInto(last, c.k2)
	}

	// CBC-MAC chain X over blocks 1 .. n-1, then the final block.
	x := make([]byte, bs)
	for i := 0; i < n-1; i++ {
		xorInto(x, msg[i*bs:(i+1)*bs])
		c.block.Encrypt(x, x)
	}
	xorInto(x, last)
	c.block.Encrypt(x, x)
	return x
}

// dbl performs the GF(2^128) doubling used to derive CMAC subkeys
// (RFC 4493 §2.3). The block size is the field width; the reduction
// polynomial constant 0x87 matches the 128-bit field.
func dbl(in []byte) []byte {
	bs := len(in)
	out := make([]byte, bs)
	carry := byte(0)
	for i := bs - 1; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	// Constant-time conditional XOR of the reduction constant when the
	// top bit of the input was set.
	msb := in[0] >> 7
	out[bs-1] ^= byte(subtle.ConstantTimeSelect(int(msb), 0x87, 0x00))
	return out
}

// xorInto XORs src into dst in place. Caller guarantees len(src) <= len(dst).
func xorInto(dst, src []byte) {
	for i := range src {
		dst[i] ^= src[i]
	}
}
