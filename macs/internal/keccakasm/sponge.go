package keccakasm

import "encoding/binary"

// Rate is the cSHAKE256 / SHAKE256 sponge rate in bytes (1088-bit
// rate, 512-bit capacity).
const Rate = 136

// CShake256 is a minimal absorb-then-squeeze cSHAKE256-domain sponge
// over the vendored Keccak-f[1600] permutation. It covers exactly the
// shape KMAC256 needs: arbitrary absorb, cSHAKE domain padding
// (0x04), and a single 32-byte squeeze. The NIST SP 800-185 framing
// (bytepad / encode_string prefixes, right_encode suffix) stays in
// the parent macs/ package — callers write those encodings as
// ordinary data.
//
// The zero value is ready to use. Clone copies the full sponge state,
// so a key-prefixed template can be absorbed once and cloned per MAC
// invocation.
type CShake256 struct {
	a   [25]uint64
	buf [Rate]byte
	n   int
}

// NewCShake256 returns a fresh cSHAKE256-domain sponge.
func NewCShake256() *CShake256 {
	return &CShake256{}
}

// Clone returns an independent copy of the sponge state.
func (s *CShake256) Clone() *CShake256 {
	c := *s
	return &c
}

// absorb XORs one full rate-sized block into the state and applies
// the permutation, through the per-arm absorbBlock dispatch (fused
// XOR+permute kernel on the AVX-512 tier).
func (s *CShake256) absorb(block []byte) {
	absorbBlock(&s.a, block)
}

// absorbBlockGeneric is the portable absorb arm: XOR the rate block
// into the state lanes, then permute via the dispatched permutation.
func absorbBlockGeneric(a *[25]uint64, block []byte) {
	for i := 0; i < Rate/8; i++ {
		a[i] ^= binary.LittleEndian.Uint64(block[i*8:])
	}
	keccakF1600(a)
}

// Write absorbs p into the sponge. It never fails.
func (s *CShake256) Write(p []byte) {
	if s.n > 0 {
		k := copy(s.buf[s.n:], p)
		s.n += k
		p = p[k:]
		if s.n == Rate {
			s.absorb(s.buf[:])
			s.n = 0
		}
	}
	for len(p) >= Rate {
		s.absorb(p[:Rate])
		p = p[Rate:]
	}
	s.n += copy(s.buf[s.n:], p)
}

// Sum256 applies the cSHAKE256 padding (domain byte 0x04, final bit
// 0x80 — merging into 0x84 when they share the last rate byte) and
// squeezes 32 output bytes. Sum256 consumes the sponge: call it on a
// Clone when the absorbed prefix must be reused.
func (s *CShake256) Sum256() [32]byte {
	var block [Rate]byte
	copy(block[:], s.buf[:s.n])
	block[s.n] = 0x04
	block[Rate-1] |= 0x80
	s.absorb(block[:])
	var out [32]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], s.a[i])
	}
	return out
}
