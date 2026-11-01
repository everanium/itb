package kdf

import (
	"crypto/subtle"
	"runtime"

	"github.com/everanium/areion"
)

// cmac is a CMAC (RFC 4493) instance over AES-128. It computes a
// full-width 16-byte tag over arbitrary-length input, as required by
// the SP 800-108 Counter Mode PRF.
type cmac struct {
	rk [11][16]byte
	k1 [16]byte // subkey for messages whose final block is complete
	k2 [16]byte // subkey for messages requiring 10* padding
}

// newCMAC builds a CMAC instance over a 16-byte AES-128 key.
// The two subkeys K1 and K2 are derived once per RFC 4493 §2.3.
func newCMAC(key []byte) cmac {
	var c cmac
	var k [16]byte
	copy(k[:], key[:16])
	areion.ExpandKey128(&k, &c.rk)
	clear(k[:])
	runtime.KeepAlive(&k)

	// L = AES_K(0^128)
	var l [16]byte
	areion.AES128EncryptBlock(&c.rk, &l, &l)

	c.k1 = dbl128(l)
	c.k2 = dbl128(c.k1)
	// L is the encryption of the zero block under the key; only the
	// subkeys are kept.
	clear(l[:])
	runtime.KeepAlive(&l)

	return c
}

// sum returns the CMAC tag (one 16-byte block) over msg.
func (c *cmac) sum(msg []byte) []byte {
	const bs = 16

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
	var last [16]byte
	lastOff := (n - 1) * bs
	if lastComplete {
		copy(last[:], msg[lastOff:])
		xorInto(last[:], c.k1[:])
	} else {
		rem := copy(last[:], msg[lastOff:])
		last[rem] = 0x80 // 10* padding
		xorInto(last[:], c.k2[:])
	}

	// CBC-MAC chain X over blocks 1 .. n-1, then the final block.
	var x [16]byte
	for i := 0; i < n-1; i++ {
		xorInto(x[:], msg[i*bs:(i+1)*bs])
		areion.AES128EncryptBlock(&c.rk, &x, &x)
	}
	xorInto(x[:], last[:])
	var outBlk [16]byte
	areion.AES128EncryptBlock(&c.rk, &outBlk, &x)
	out := make([]byte, bs)
	copy(out, outBlk[:])
	// last, x, and outBlk carry the masked final block and intermediate state; zero them.
	clear(last[:])
	clear(x[:])
	clear(outBlk[:])
	runtime.KeepAlive(&last)
	runtime.KeepAlive(&x)
	runtime.KeepAlive(&outBlk)
	return out
}

// dbl128 performs the GF(2^128) doubling used to derive CMAC subkeys
// (RFC 4493 §2.3). The reduction polynomial constant 0x87 matches the
// 128-bit field.
func dbl128(in [16]byte) [16]byte {
	var out [16]byte
	carry := byte(0)
	for i := 15; i >= 0; i-- {
		out[i] = in[i]<<1 | carry
		carry = in[i] >> 7
	}
	// Constant-time conditional XOR of the reduction constant when the
	// top bit of the input was set.
	msb := in[0] >> 7
	out[15] ^= byte(subtle.ConstantTimeSelect(int(msb), 0x87, 0x00))
	return out
}

// xorInto XORs src into dst in place. Caller guarantees len(src) <= len(dst).
func xorInto(dst, src []byte) {
	for i := range src {
		dst[i] ^= src[i]
	}
}
