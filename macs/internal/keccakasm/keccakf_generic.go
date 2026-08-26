package keccakasm

import "math/bits"

// keccakRC holds the 24 Keccak-f[1600] round constants (FIPS 202
// Section 3.2.5). Public values at fixed offsets.
var keccakRC = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// keccakRot holds the rho step rotation offsets, indexed [x][y] for
// lane A[x, y] stored at a[x + 5*y].
var keccakRot = [5][5]int{
	{0, 36, 3, 41, 18},
	{1, 44, 10, 45, 2},
	{62, 6, 43, 15, 61},
	{28, 55, 25, 21, 56},
	{27, 20, 39, 8, 14},
}

// keccakF1600Generic applies the Keccak-f[1600] permutation in place
// using portable scalar Go. Lane A[x, y] lives at a[x + 5*y] in
// little-endian 64-bit words — the same convention as the AVX-512
// kernel and the FIPS 202 byte-to-lane mapping. Serves as the
// fallback arm of the dispatcher and as the parity oracle for the
// AVX-512 kernel in tests.
func keccakF1600Generic(a *[25]uint64) {
	var c [5]uint64
	var b [25]uint64
	for r := 0; r < 24; r++ {
		// theta
		for x := 0; x < 5; x++ {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := 0; x < 5; x++ {
			d := c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
			for y := 0; y < 25; y += 5 {
				a[x+y] ^= d
			}
		}
		// rho + pi
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				b[y+5*((2*x+3*y)%5)] = bits.RotateLeft64(a[x+5*y], keccakRot[x][y])
			}
		}
		// chi
		for x := 0; x < 5; x++ {
			for y := 0; y < 25; y += 5 {
				a[x+y] = b[x+y] ^ (^b[(x+1)%5+y] & b[(x+2)%5+y])
			}
		}
		// iota
		a[0] ^= keccakRC[r]
	}
}
