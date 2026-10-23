package aesitbasm

import (
	"encoding/binary"
	"math/bits"
	"runtime"
)

// bsState holds up to four 128-bit AES blocks in 64-bit bitsliced form
// (Boyar-Peralta S-box and linear layer, matching github.com/everanium/areion).
type bsState [8]uint64

const bsByte0Mask = 0x0101010101010101

var bsRC [8]bsState

func init() {
	for i := range RC {
		bsPackBroadcast(&bsRC[i], &RC[i])
	}
}

func bsPrepWord(u uint64) uint64 {
	t := ((u >> 24) ^ u) & 0x00000000ff00ff00
	u ^= t ^ (t << 24)
	t = ((u >> 16) ^ u) & 0x00000000ffff0000
	u ^= t ^ (t << 16)
	return u
}

func bsUnprepWord(u uint64) uint64 {
	t := ((u >> 16) ^ u) & 0x00000000ffff0000
	u ^= t ^ (t << 16)
	t = ((u >> 24) ^ u) & 0x00000000ff00ff00
	u ^= t ^ (t << 24)
	return u
}

func bsPrepBlock(lo, hi uint64) (uint64, uint64) {
	u0 := uint64(uint32(lo)) | (hi << 32)
	u1 := (lo >> 32) | (hi & 0xffffffff00000000)
	return bsPrepWord(u0), bsPrepWord(u1)
}

func bsUnprepBlock(u0, u1 uint64) (uint64, uint64) {
	u0 = bsUnprepWord(u0)
	u1 = bsUnprepWord(u1)
	lo := uint64(uint32(u0)) | (u1 << 32)
	hi := (u0 >> 32) | (u1 & 0xffffffff00000000)
	return lo, hi
}

func bsOrtho(w *[8]uint64) {
	const (
		m1 = 0x5555555555555555
		m2 = 0x3333333333333333
		m4 = 0x0f0f0f0f0f0f0f0f
	)
	t := ((w[0] >> 1) ^ w[1]) & m1
	w[0] ^= t << 1
	w[1] ^= t
	t = ((w[2] >> 1) ^ w[3]) & m1
	w[2] ^= t << 1
	w[3] ^= t
	t = ((w[4] >> 1) ^ w[5]) & m1
	w[4] ^= t << 1
	w[5] ^= t
	t = ((w[6] >> 1) ^ w[7]) & m1
	w[6] ^= t << 1
	w[7] ^= t

	t = ((w[0] >> 2) ^ w[2]) & m2
	w[0] ^= t << 2
	w[2] ^= t
	t = ((w[1] >> 2) ^ w[3]) & m2
	w[1] ^= t << 2
	w[3] ^= t
	t = ((w[4] >> 2) ^ w[6]) & m2
	w[4] ^= t << 2
	w[6] ^= t
	t = ((w[5] >> 2) ^ w[7]) & m2
	w[5] ^= t << 2
	w[7] ^= t

	t = ((w[0] >> 4) ^ w[4]) & m4
	w[0] ^= t << 4
	w[4] ^= t
	t = ((w[1] >> 4) ^ w[5]) & m4
	w[1] ^= t << 4
	w[5] ^= t
	t = ((w[2] >> 4) ^ w[6]) & m4
	w[2] ^= t << 4
	w[6] ^= t
	t = ((w[3] >> 4) ^ w[7]) & m4
	w[3] ^= t << 4
	w[7] ^= t
}

func bsPackWords1(q *bsState, lo, hi uint64) {
	u0, u1 := bsPrepBlock(lo, hi)
	q[0] = (u0 & bsByte0Mask) | ((u1 & bsByte0Mask) << 4)
	q[1] = ((u0 >> 1) & bsByte0Mask) | (((u1 >> 1) & bsByte0Mask) << 4)
	q[2] = ((u0 >> 2) & bsByte0Mask) | (((u1 >> 2) & bsByte0Mask) << 4)
	q[3] = ((u0 >> 3) & bsByte0Mask) | (((u1 >> 3) & bsByte0Mask) << 4)
	q[4] = ((u0 >> 4) & bsByte0Mask) | (((u1 >> 4) & bsByte0Mask) << 4)
	q[5] = ((u0 >> 5) & bsByte0Mask) | (((u1 >> 5) & bsByte0Mask) << 4)
	q[6] = ((u0 >> 6) & bsByte0Mask) | (((u1 >> 6) & bsByte0Mask) << 4)
	q[7] = ((u0 >> 7) & bsByte0Mask) | (((u1 >> 7) & bsByte0Mask) << 4)
}

func bsPack1(q *bsState, b0 *[16]byte) {
	bsPackWords1(q, binary.LittleEndian.Uint64(b0[0:8]), binary.LittleEndian.Uint64(b0[8:16]))
}

func bsPackBroadcast(q *bsState, b0 *[16]byte) {
	bsPack1(q, b0)
	for k := 0; k < 8; k++ {
		q[k] *= 0xf
	}
}

func bsPackBroadcastWords(q *bsState, lo, hi uint64) {
	bsPackWords1(q, lo, hi)
	for k := 0; k < 8; k++ {
		q[k] *= 0xf
	}
}

func bsUnpackWords1(q *bsState) (uint64, uint64) {
	u0 := (q[0] & bsByte0Mask) |
		((q[1] & bsByte0Mask) << 1) |
		((q[2] & bsByte0Mask) << 2) |
		((q[3] & bsByte0Mask) << 3) |
		((q[4] & bsByte0Mask) << 4) |
		((q[5] & bsByte0Mask) << 5) |
		((q[6] & bsByte0Mask) << 6) |
		((q[7] & bsByte0Mask) << 7)
	u1 := ((q[0] >> 4) & bsByte0Mask) |
		(((q[1] >> 4) & bsByte0Mask) << 1) |
		(((q[2] >> 4) & bsByte0Mask) << 2) |
		(((q[3] >> 4) & bsByte0Mask) << 3) |
		(((q[4] >> 4) & bsByte0Mask) << 4) |
		(((q[5] >> 4) & bsByte0Mask) << 5) |
		(((q[6] >> 4) & bsByte0Mask) << 6) |
		(((q[7] >> 4) & bsByte0Mask) << 7)
	return bsUnprepBlock(u0, u1)
}

func bsPack4(q *bsState, b0, b1, b2, b3 *[16]byte) {
	u00, u10 := bsPrepBlock(binary.LittleEndian.Uint64(b0[0:8]), binary.LittleEndian.Uint64(b0[8:16]))
	u01, u11 := bsPrepBlock(binary.LittleEndian.Uint64(b1[0:8]), binary.LittleEndian.Uint64(b1[8:16]))
	u02, u12 := bsPrepBlock(binary.LittleEndian.Uint64(b2[0:8]), binary.LittleEndian.Uint64(b2[8:16]))
	u03, u13 := bsPrepBlock(binary.LittleEndian.Uint64(b3[0:8]), binary.LittleEndian.Uint64(b3[8:16]))
	*q = bsState{u00, u01, u02, u03, u10, u11, u12, u13}
	bsOrtho((*[8]uint64)(q))
}

func bsUnpackWords4(q *bsState, out *[4][2]uint64) {
	w := *(*[8]uint64)(q)
	bsOrtho(&w)
	out[0][0], out[0][1] = bsUnprepBlock(w[0], w[4])
	out[1][0], out[1][1] = bsUnprepBlock(w[1], w[5])
	out[2][0], out[2][1] = bsUnprepBlock(w[2], w[6])
	out[3][0], out[3][1] = bsUnprepBlock(w[3], w[7])
	clear(w[:])
	runtime.KeepAlive(&w)
}

func bsSubBytes(q *bsState) {
	u0, u1, u2, u3, u4, u5, u6, u7 := q[7], q[6], q[5], q[4], q[3], q[2], q[1], q[0]

	y14 := u3 ^ u5
	y13 := u0 ^ u6
	y9 := u0 ^ u3
	y8 := u0 ^ u5
	t0 := u1 ^ u2
	y1 := t0 ^ u7
	y4 := y1 ^ u3
	y12 := y13 ^ y14
	y2 := y1 ^ u0
	y5 := y1 ^ u6
	y3 := y5 ^ y8
	t1 := u4 ^ y12
	y15 := t1 ^ u5
	y20 := t1 ^ u1
	y6 := y15 ^ u7
	y10 := y15 ^ t0
	y11 := y20 ^ y9
	y7 := u7 ^ y11
	y17 := y10 ^ y11
	y19 := y10 ^ y8
	y16 := t0 ^ y11
	y21 := y13 ^ y16
	y18 := u0 ^ y16

	t2 := y12 & y15
	t3 := y3 & y6
	t4 := t3 ^ t2
	t5 := y4 & u7
	t6 := t5 ^ t2
	t7 := y13 & y16
	t8 := y5 & y1
	t9 := t8 ^ t7
	t10 := y2 & y7
	t11 := t10 ^ t7
	t12 := y9 & y11
	t13 := y14 & y17
	t14 := t13 ^ t12
	t15 := y8 & y10
	t16 := t15 ^ t12
	t17 := t4 ^ t14
	t18 := t6 ^ t16
	t19 := t9 ^ t14
	t20 := t11 ^ t16
	t21 := t17 ^ y20
	t22 := t18 ^ y19
	t23 := t19 ^ y21
	t24 := t20 ^ y18

	t25 := t21 ^ t22
	t26 := t21 & t23
	t27 := t24 ^ t26
	t28 := t25 & t27
	t29 := t28 ^ t22
	t30 := t23 ^ t24
	t31 := t22 ^ t26
	t32 := t31 & t30
	t33 := t32 ^ t24
	t34 := t23 ^ t33
	t35 := t27 ^ t33
	t36 := t24 & t35
	t37 := t36 ^ t34
	t38 := t27 ^ t36
	t39 := t29 & t38
	t40 := t25 ^ t39
	t41 := t40 ^ t37
	t42 := t29 ^ t33
	t43 := t29 ^ t40
	t44 := t33 ^ t37
	t45 := t42 ^ t41

	z0 := t44 & y15
	z1 := t37 & y6
	z2 := t33 & u7
	z3 := t43 & y16
	z4 := t40 & y1
	z5 := t29 & y7
	z6 := t42 & y11
	z7 := t45 & y17
	z8 := t41 & y10
	z9 := t44 & y12
	z10 := t37 & y3
	z11 := t33 & y4
	z12 := t43 & y13
	z13 := t40 & y5
	z14 := t29 & y2
	z15 := t42 & y9
	z16 := t45 & y14
	z17 := t41 & y8

	t46 := z15 ^ z16
	t47 := z10 ^ z11
	t48 := z5 ^ z13
	t49 := z9 ^ z10
	t50 := z2 ^ z12
	t51 := z2 ^ z5
	t52 := z7 ^ z8
	t53 := z0 ^ z3
	t54 := z6 ^ z7
	t55 := z16 ^ z17
	t56 := z12 ^ t48
	t57 := t50 ^ t53
	t58 := z4 ^ t46
	t59 := z3 ^ t54
	t60 := t46 ^ t57
	t61 := z14 ^ t57
	t62 := t52 ^ t58
	t63 := t49 ^ t58
	t64 := z4 ^ t59
	t65 := t61 ^ t62
	t66 := z1 ^ t63
	s0 := t59 ^ t63
	s6 := ^(t56 ^ t62)
	s7 := ^(t48 ^ t60)
	t67 := t64 ^ t65
	s3 := t53 ^ t66
	s4 := t51 ^ t66
	s5 := t47 ^ t65
	s1 := ^(t64 ^ s3)
	s2 := ^(t55 ^ t67)

	q[7], q[6], q[5], q[4], q[3], q[2], q[1], q[0] = s0, s1, s2, s3, s4, s5, s6, s7
}

func bsShiftRows(q *bsState) {
	for k := 0; k < 8; k++ {
		x := q[k]
		q[k] = uint64(uint16(x)) |
			uint64(bits.RotateLeft16(uint16(x>>16), -4))<<16 |
			uint64(bits.RotateLeft16(uint16(x>>32), 8))<<32 |
			uint64(bits.RotateLeft16(uint16(x>>48), 4))<<48
	}
}

func bsMixColumns(q *bsState) {
	var a, b [8]uint64
	for k := 0; k < 8; k++ {
		r1 := bits.RotateLeft64(q[k], -16)
		ak := q[k] ^ r1
		a[k] = ak
		b[k] = r1 ^ bits.RotateLeft64(ak, 32)
	}
	a7 := a[7]
	q[0] = a7 ^ b[0]
	q[1] = a[0] ^ a7 ^ b[1]
	q[2] = a[1] ^ b[2]
	q[3] = a[2] ^ a7 ^ b[3]
	q[4] = a[3] ^ a7 ^ b[4]
	q[5] = a[4] ^ b[5]
	q[6] = a[5] ^ b[6]
	q[7] = a[6] ^ b[7]
	clear(a[:])
	clear(b[:])
	runtime.KeepAlive(&a)
	runtime.KeepAlive(&b)
}

func bsRound(q, rk *bsState) {
	bsSubBytes(q)
	bsShiftRows(q)
	bsMixColumns(q)
	for k := 0; k < 8; k++ {
		q[k] ^= rk[k]
	}
}

func paddedBlock(dst *[16]byte, key *[16]byte, data []byte, blk, full int) {
	off := 16 * blk
	if off < full {
		copy(dst[:], data[off:off+16])
	} else {
		rem := len(data) - full
		pad := byte(16 - rem)
		copy(dst[:rem], data[full:])
		for i := rem; i < 16; i++ {
			dst[i] = pad
		}
	}
	if key != nil {
		for i := 0; i < 16; i++ {
			dst[i] ^= key[i]
		}
	}
}
