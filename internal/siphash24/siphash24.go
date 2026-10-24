// Package siphash24 implements SipHash-2-4 in its 128-bit output mode
// (Aumasson & Bernstein 2012 §2.4) in pure Go under the register ABI with
// explicit internal state zeroization.
package siphash24

import (
	"encoding/binary"
	"hash"
	"math/bits"
	"runtime"

	"github.com/everanium/itb/internal/wipe"
)

const (
	// BlockSize is the message block size of SipHash-2-4 in bytes.
	BlockSize = 8
	// Size128 is the output size of SipHash-2-4-128 in bytes.
	Size128 = 16

	initV0 = 0x736f6d6570736575
	initV1 = 0x646f72616e646f6d ^ 0xee
	initV2 = 0x6c7967656e657261
	initV3 = 0x7465646279746573
)

func sipRound4(v *[4]uint64) {
	v[0] += v[1]
	v[1] = bits.RotateLeft64(v[1], 13)
	v[1] ^= v[0]
	v[0] = bits.RotateLeft64(v[0], 32)
	v[2] += v[3]
	v[3] = bits.RotateLeft64(v[3], 16)
	v[3] ^= v[2]
	v[0] += v[3]
	v[3] = bits.RotateLeft64(v[3], 21)
	v[3] ^= v[0]
	v[2] += v[1]
	v[1] = bits.RotateLeft64(v[1], 17)
	v[1] ^= v[2]
	v[2] = bits.RotateLeft64(v[2], 32)
}

func sipRound6(v *[6]uint64) {
	v[0] += v[1]
	v[1] = bits.RotateLeft64(v[1], 13)
	v[1] ^= v[0]
	v[0] = bits.RotateLeft64(v[0], 32)
	v[2] += v[3]
	v[3] = bits.RotateLeft64(v[3], 16)
	v[3] ^= v[2]
	v[0] += v[3]
	v[3] = bits.RotateLeft64(v[3], 21)
	v[3] ^= v[0]
	v[2] += v[1]
	v[1] = bits.RotateLeft64(v[1], 17)
	v[1] ^= v[2]
	v[2] = bits.RotateLeft64(v[2], 32)
}

// Hash128 returns the 128-bit SipHash-2-4 digest (lo, hi) of p under the
// 128-bit key (k0, k1) and zeroes its internal state words before returning.
func Hash128(k0, k1 uint64, p []byte) (lo, hi uint64) {
	var v [6]uint64
	v[0] = k0 ^ initV0
	v[1] = k1 ^ initV1
	v[2] = k0 ^ initV2
	v[3] = k1 ^ initV3

	n := len(p)
	off := 0
	for ; off+8 <= n; off += 8 {
		v[4] = binary.LittleEndian.Uint64(p[off:])
		v[3] ^= v[4]
		sipRound6(&v)
		sipRound6(&v)
		v[0] ^= v[4]
	}

	v[5] = uint64(n) << 56
	rem := p[off:]
	switch len(rem) {
	case 7:
		v[5] |= uint64(rem[6]) << 48
		fallthrough
	case 6:
		v[5] |= uint64(rem[5]) << 40
		fallthrough
	case 5:
		v[5] |= uint64(rem[4]) << 32
		fallthrough
	case 4:
		v[5] |= uint64(rem[3]) << 24
		fallthrough
	case 3:
		v[5] |= uint64(rem[2]) << 16
		fallthrough
	case 2:
		v[5] |= uint64(rem[1]) << 8
		fallthrough
	case 1:
		v[5] |= uint64(rem[0])
	}
	v[3] ^= v[5]
	sipRound6(&v)
	sipRound6(&v)
	v[0] ^= v[5]

	v[2] ^= 0xee
	sipRound6(&v)
	sipRound6(&v)
	sipRound6(&v)
	sipRound6(&v)
	lo = (v[0] ^ v[1]) ^ (v[2] ^ v[3])

	v[1] ^= 0xdd
	sipRound6(&v)
	sipRound6(&v)
	sipRound6(&v)
	sipRound6(&v)
	hi = (v[0] ^ v[1]) ^ (v[2] ^ v[3])

	clear(v[:])
	runtime.KeepAlive(&v)
	return lo, hi
}

// Sum128Into writes the 16-byte little-endian SipHash-2-4-128 digest of p
// under key (k0, k1) into out[:16] and zeroes its internal state before
// returning.
func Sum128Into(out []byte, k0, k1 uint64, p []byte) {
	lo, hi := Hash128(k0, k1, p)
	binary.LittleEndian.PutUint64(out[:8], lo)
	binary.LittleEndian.PutUint64(out[8:16], hi)
}

func sipRound(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = bits.RotateLeft64(v1, 13)
	v1 ^= v0
	v0 = bits.RotateLeft64(v0, 32)
	v2 += v3
	v3 = bits.RotateLeft64(v3, 16)
	v3 ^= v2
	v0 += v3
	v3 = bits.RotateLeft64(v3, 21)
	v3 ^= v0
	v2 += v1
	v1 = bits.RotateLeft64(v1, 17)
	v1 ^= v2
	v2 = bits.RotateLeft64(v2, 32)
	return v0, v1, v2, v3
}

// Block128Raw computes SipHash-2-4-128 over a single 16-byte block (m0 || m1)
// under key (k0, k1) entirely in CPU registers with a zero-byte stack frame.
// Callers running a bulk loop scrub registers once at the end of the loop via
// wipe.ClobberRegs.
func Block128Raw(k0, k1, m0, m1 uint64) (lo, hi uint64) {
	v0 := k0 ^ initV0
	v1 := k1 ^ initV1
	v2 := k0 ^ initV2
	v3 := k1 ^ initV3

	v3 ^= m0
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0 ^= m0

	v3 ^= m1
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0 ^= m1

	const b = uint64(16) << 56
	v3 ^= b
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0 ^= b

	v2 ^= 0xee
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	lo = (v0 ^ v1) ^ (v2 ^ v3)

	v1 ^= 0xdd
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	hi = (v0 ^ v1) ^ (v2 ^ v3)
	return lo, hi
}

// Block128Into computes SipHash-2-4-128 over a single 16-byte block (m0 || m1)
// under key (k0, k1), writes the 16-byte little-endian digest into out, and
// zeroes its internal register state before returning.
func Block128Into(out *[16]byte, k0, k1, m0, m1 uint64) {
	lo, hi := Block128Raw(k0, k1, m0, m1)
	binary.LittleEndian.PutUint64(out[:8], lo)
	binary.LittleEndian.PutUint64(out[8:], hi)
	wipe.ClobberRegs()
}

type digest128 struct {
	v0, v1, v2, v3 uint64
	k0, k1         uint64
	x              [BlockSize]byte
	nx             int
	total          int
}

// New128 returns a streaming hash.Hash computing SipHash-2-4-128 under the
// 16-byte key.
func New128(key []byte) hash.Hash {
	d := new(digest128)
	d.k0 = binary.LittleEndian.Uint64(key[:8])
	d.k1 = binary.LittleEndian.Uint64(key[8:16])
	d.Reset()
	return d
}

func (d *digest128) Reset() {
	d.v0 = d.k0 ^ initV0
	d.v1 = d.k1 ^ initV1
	d.v2 = d.k0 ^ initV2
	d.v3 = d.k1 ^ initV3
	clear(d.x[:])
	d.nx = 0
	d.total = 0
	runtime.KeepAlive(d)
}

// Close zeroes the entire digest state including the stored key words.
func (d *digest128) Close() error {
	*d = digest128{}
	runtime.KeepAlive(d)
	return nil
}

func (d *digest128) Size() int      { return Size128 }
func (d *digest128) BlockSize() int { return BlockSize }

func (d *digest128) Write(p []byte) (nn int, err error) {
	nn = len(p)
	d.total += nn
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == BlockSize {
			m := binary.LittleEndian.Uint64(d.x[:])
			var v [4]uint64
			v[0], v[1], v[2], v[3] = d.v0, d.v1, d.v2, d.v3
			v[3] ^= m
			sipRound4(&v)
			sipRound4(&v)
			v[0] ^= m
			d.v0, d.v1, d.v2, d.v3 = v[0], v[1], v[2], v[3]
			clear(v[:])
			clear(d.x[:])
			runtime.KeepAlive(&v)
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= BlockSize {
		var v [4]uint64
		v[0], v[1], v[2], v[3] = d.v0, d.v1, d.v2, d.v3
		for len(p) >= BlockSize {
			m := binary.LittleEndian.Uint64(p[:8])
			v[3] ^= m
			sipRound4(&v)
			sipRound4(&v)
			v[0] ^= m
			p = p[8:]
		}
		d.v0, d.v1, d.v2, d.v3 = v[0], v[1], v[2], v[3]
		clear(v[:])
		runtime.KeepAlive(&v)
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return nn, nil
}

func (d *digest128) Sum(in []byte) []byte {
	var v [5]uint64
	v[0], v[1], v[2], v[3] = d.v0, d.v1, d.v2, d.v3
	v[4] = uint64(d.total) << 56
	switch d.nx {
	case 7:
		v[4] |= uint64(d.x[6]) << 48
		fallthrough
	case 6:
		v[4] |= uint64(d.x[5]) << 40
		fallthrough
	case 5:
		v[4] |= uint64(d.x[4]) << 32
		fallthrough
	case 4:
		v[4] |= uint64(d.x[3]) << 24
		fallthrough
	case 3:
		v[4] |= uint64(d.x[2]) << 16
		fallthrough
	case 2:
		v[4] |= uint64(d.x[1]) << 8
		fallthrough
	case 1:
		v[4] |= uint64(d.x[0])
	}

	var s [4]uint64
	s[0], s[1], s[2], s[3] = v[0], v[1], v[2], v[3]^v[4]
	sipRound4(&s)
	sipRound4(&s)
	s[0] ^= v[4]

	s[2] ^= 0xee
	sipRound4(&s)
	sipRound4(&s)
	sipRound4(&s)
	sipRound4(&s)
	lo := (s[0] ^ s[1]) ^ (s[2] ^ s[3])

	s[1] ^= 0xdd
	sipRound4(&s)
	sipRound4(&s)
	sipRound4(&s)
	sipRound4(&s)
	hi := (s[0] ^ s[1]) ^ (s[2] ^ s[3])

	var out [Size128]byte
	binary.LittleEndian.PutUint64(out[:8], lo)
	binary.LittleEndian.PutUint64(out[8:16], hi)
	ret := append(in, out[:]...)

	clear(v[:])
	clear(s[:])
	clear(out[:])
	runtime.KeepAlive(&v)
	runtime.KeepAlive(&s)
	runtime.KeepAlive(&out)
	return ret
}

func initCTRStateRaw(vInit *[4]uint64, k0, k1, nonceHi uint64) {
	v0 := k0 ^ initV0
	v1 := k1 ^ initV1
	v2 := k0 ^ initV2
	v3 := (k1 ^ initV3) ^ nonceHi
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0, v1, v2, v3 = sipRound(v0, v1, v2, v3)
	v0 ^= nonceHi
	vInit[0], vInit[1], vInit[2], vInit[3] = v0, v1, v2, v3
}

// InitCTRState precomputes the 4-word SipHash-2-4-128 state after absorbing
// the constant high 64-bit nonce word nonceHi under key (k0, k1) and zeroes
// its working registers before returning.
func InitCTRState(vInit *[4]uint64, k0, k1, nonceHi uint64) {
	initCTRStateRaw(vInit, k0, k1, nonceHi)
	wipe.ClobberRegs()
}

// XORKeyStreamBlocks XORs nBlocks = len(src) / 16 blocks of 16-byte
// SipHash-2-4-128 counter-mode keystream into dst starting at counter.
// Block b (0 <= b < nBlocks) is Block128Raw(k0, k1, nonceHi, nonceLo^(counter+b)).
func XORKeyStreamBlocks(dst, src []byte, k0, k1, nonceHi, nonceLo, counter uint64) {
	nBlocks := len(src) / Size128
	if nBlocks <= 0 {
		return
	}
	if len(dst) < nBlocks*Size128 {
		panic("siphash24: dst smaller than src")
	}
	var vInit [4]uint64
	initCTRStateRaw(&vInit, k0, k1, nonceHi)
	k0, k1, nonceHi = 0, 0, 0
	XORKeyStreamBlocksWithState(dst, src, &vInit, nonceLo, counter)
	nonceLo = 0
	clear(vInit[:])
	runtime.KeepAlive(&vInit)
	runtime.KeepAlive(&k0)
	runtime.KeepAlive(&k1)
	runtime.KeepAlive(&nonceHi)
	runtime.KeepAlive(&nonceLo)
	wipe.CallStack512B()
}

//go:noinline
func scalarXORKeyStreamBlocksWithState(dst, src []byte, vInit *[4]uint64, nonceLo, counter uint64) {
	nBlocks := len(src) / Size128
	if nBlocks <= 0 {
		return
	}
	if len(dst) < nBlocks*Size128 {
		panic("siphash24: dst smaller than src")
	}
	const bPad = uint64(16) << 56
	var s [6]uint64
	ctr := counter
	for b := 0; b < nBlocks; b++ {
		s[4] = nonceLo ^ ctr
		s[0] = vInit[0]
		s[1] = vInit[1]
		s[2] = vInit[2]
		s[3] = vInit[3] ^ s[4]
		sipRound6(&s)
		sipRound6(&s)
		s[0] ^= s[4]

		s[3] ^= bPad
		sipRound6(&s)
		sipRound6(&s)
		s[0] ^= bPad

		s[2] ^= 0xee
		sipRound6(&s)
		sipRound6(&s)
		sipRound6(&s)
		sipRound6(&s)
		s[5] = (s[0] ^ s[1]) ^ (s[2] ^ s[3])

		s[1] ^= 0xdd
		sipRound6(&s)
		sipRound6(&s)
		sipRound6(&s)
		sipRound6(&s)
		hi := (s[0] ^ s[1]) ^ (s[2] ^ s[3])

		off := b * Size128
		srcLo := binary.LittleEndian.Uint64(src[off:])
		srcHi := binary.LittleEndian.Uint64(src[off+8:])
		binary.LittleEndian.PutUint64(dst[off:], srcLo^s[5])
		binary.LittleEndian.PutUint64(dst[off+8:], srcHi^hi)
		ctr++
	}
	nonceLo = 0
	clear(s[:])
	runtime.KeepAlive(&s)
	runtime.KeepAlive(&nonceLo)
	wipe.CallStack512B()
}

//go:noinline
func scalarBatchPRFx4(dst, in *[4][]byte, k0, k1 uint64) {
	var v [6]uint64
	for lane := 0; lane < 4; lane++ {
		if len(dst[lane]) < Size128 {
			panic("siphash24: dst buffer smaller than 16 bytes")
		}
		p := in[lane]
		v[0] = k0 ^ initV0
		v[1] = k1 ^ initV1
		v[2] = k0 ^ initV2
		v[3] = k1 ^ initV3

		n := len(p)
		off := 0
		for ; off+8 <= n; off += 8 {
			v[4] = binary.LittleEndian.Uint64(p[off:])
			v[3] ^= v[4]
			sipRound6(&v)
			sipRound6(&v)
			v[0] ^= v[4]
		}

		v[5] = uint64(n) << 56
		rem := p[off:]
		switch len(rem) {
		case 7:
			v[5] |= uint64(rem[6]) << 48
			fallthrough
		case 6:
			v[5] |= uint64(rem[5]) << 40
			fallthrough
		case 5:
			v[5] |= uint64(rem[4]) << 32
			fallthrough
		case 4:
			v[5] |= uint64(rem[3]) << 24
			fallthrough
		case 3:
			v[5] |= uint64(rem[2]) << 16
			fallthrough
		case 2:
			v[5] |= uint64(rem[1]) << 8
			fallthrough
		case 1:
			v[5] |= uint64(rem[0])
		}
		v[3] ^= v[5]
		sipRound6(&v)
		sipRound6(&v)
		v[0] ^= v[5]

		v[2] ^= 0xee
		sipRound6(&v)
		sipRound6(&v)
		sipRound6(&v)
		sipRound6(&v)
		lo := (v[0] ^ v[1]) ^ (v[2] ^ v[3])

		v[1] ^= 0xdd
		sipRound6(&v)
		sipRound6(&v)
		sipRound6(&v)
		sipRound6(&v)
		hi := (v[0] ^ v[1]) ^ (v[2] ^ v[3])

		binary.LittleEndian.PutUint64(dst[lane][:8], lo)
		binary.LittleEndian.PutUint64(dst[lane][8:16], hi)
	}
	k0, k1 = 0, 0
	clear(v[:])
	runtime.KeepAlive(&v)
	runtime.KeepAlive(&k0)
	runtime.KeepAlive(&k1)
	wipe.CallStack512B()
}
