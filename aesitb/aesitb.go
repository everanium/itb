package aesitb

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Domain tags of the ITB per-pixel derivation domains. Sessions are keyed
// by tag byte, as in the reference construction: the tag is XORed into
// byte 0 of the key-initialised state before the nonce is absorbed.
const (
	DomainStartPixel byte = 0x02
	DomainChunkLock  byte = 0x03
	DomainLockSeed   byte = 0x04
	DomainBlockHash  byte = 0x00
)

// domains lists every shipped domain tag in reference order.
var domains = [4]byte{DomainStartPixel, DomainChunkLock, DomainLockSeed, DomainBlockHash}

// nonceLengths lists the accepted nonce sizes in bytes.
var nonceLengths = [3]int{16, 32, 64}

// MaxIdx is the exclusive upper bound of the per-pixel index (48 bits).
const MaxIdx uint64 = 1 << 48

// ErrNonceLen is returned by NewSession / SessionInit for a nonce whose
// length is not 16, 32 or 64 bytes.
var ErrNonceLen = errors.New("aesitb: nonce length must be 16, 32, or 64 bytes")

// sbox is the FIPS-197 § 5.1.1 substitution table.
var sbox = [256]byte{
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
}

// The 16-byte state is column-major: s[4*col+row], the FIPS-197 § 3.4
// byte order and the AESENC in-register layout.

func subBytes(s *[16]byte) {
	for i := range s {
		s[i] = sbox[s[i]]
	}
}

func shiftRows(s *[16]byte) {
	s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
	s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
	s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
}

func xtime(b byte) byte {
	if b&0x80 != 0 {
		return (b << 1) ^ 0x1b
	}
	return b << 1
}

func mixColumns(s *[16]byte) {
	for col := 0; col < 4; col++ {
		s0, s1, s2, s3 := s[4*col], s[4*col+1], s[4*col+2], s[4*col+3]
		s[4*col+0] = xtime(s0) ^ (s1 ^ xtime(s1)) ^ s2 ^ s3
		s[4*col+1] = s0 ^ xtime(s1) ^ (s2 ^ xtime(s2)) ^ s3
		s[4*col+2] = s0 ^ s1 ^ xtime(s2) ^ (s3 ^ xtime(s3))
		s[4*col+3] = (s0 ^ xtime(s0)) ^ s1 ^ s2 ^ xtime(s3)
	}
}

func addRoundKey(s, rk *[16]byte) {
	for i := range s {
		s[i] ^= rk[i]
	}
}

// aesRound applies one full AES encryption round (SubBytes, ShiftRows,
// MixColumns, AddRoundKey) — the semantics of the AESENC instruction.
func aesRound(s, rk *[16]byte) {
	subBytes(s)
	shiftRows(s)
	mixColumns(s)
	addRoundKey(s, rk)
}

// rc holds the eight pairwise-distinct round constants, each a big-endian
// packing of FIPS 180-4 initial-hash-value words (fractional bits of the
// square roots of small primes):
//
//   - rc[0..1]: SHA-256 IV (== BLAKE3 IV), p ∈ {2, 3, 5, 7, 11, 13, 17, 19}, 32-bit words
//   - rc[2..5]: SHA-512 IV, same primes, 64-bit words
//   - rc[6..7]: SHA-384 IV first four words, p ∈ {23, 29, 31, 37}, 64-bit words
//
// Schedule: session init absorbs nonce chunk c under rc[absorbRC[c]] and
// closes with rc[1] then rc[7]; HashPixel applies rc[2] then rc[3];
// HashGeneric cycles rc[0..7] over its blocks and finalises with rc[0]
// then rc[1].
var rc = [8][16]byte{
	{0x6A, 0x09, 0xE6, 0x67, 0xBB, 0x67, 0xAE, 0x85, 0x3C, 0x6E, 0xF3, 0x72, 0xA5, 0x4F, 0xF5, 0x3A},
	{0x51, 0x0E, 0x52, 0x7F, 0x9B, 0x05, 0x68, 0x8C, 0x1F, 0x83, 0xD9, 0xAB, 0x5B, 0xE0, 0xCD, 0x19},
	{0x6A, 0x09, 0xE6, 0x67, 0xF3, 0xBC, 0xC9, 0x08, 0xBB, 0x67, 0xAE, 0x85, 0x84, 0xCA, 0xA7, 0x3B},
	{0x3C, 0x6E, 0xF3, 0x72, 0xFE, 0x94, 0xF8, 0x2B, 0xA5, 0x4F, 0xF5, 0x3A, 0x5F, 0x1D, 0x36, 0xF1},
	{0x51, 0x0E, 0x52, 0x7F, 0xAD, 0xE6, 0x82, 0xD1, 0x9B, 0x05, 0x68, 0x8C, 0x2B, 0x3E, 0x6C, 0x1F},
	{0x1F, 0x83, 0xD9, 0xAB, 0xFB, 0x41, 0xBD, 0x6B, 0x5B, 0xE0, 0xCD, 0x19, 0x13, 0x7E, 0x21, 0x79},
	{0xCB, 0xBB, 0x9D, 0x5D, 0xC1, 0x05, 0x9E, 0xD8, 0x62, 0x9A, 0x29, 0x2A, 0x36, 0x7C, 0xD5, 0x07},
	{0x91, 0x59, 0x01, 0x5A, 0x30, 0x70, 0xDD, 0x17, 0x15, 0x2F, 0xEC, 0xD8, 0xF7, 0x0E, 0x59, 0x39},
}

// absorbRC maps nonce chunk index (0..3) to the rc index applied after
// that chunk is absorbed during session init.
var absorbRC = [4]int{0, 4, 5, 6}

func validNonce(nonce []byte) bool {
	for _, n := range nonceLengths {
		if len(nonce) == n {
			return true
		}
	}
	return false
}

// SessionInit returns the pre-permuted state for (key, nonce, tag):
//
//	state = key XOR (tag || 0^15)
//	for each 16-byte nonce chunk c: state = AESRound(state XOR chunk_c, rc[absorbRC[c]])
//	state = AESRound(AESRound(state, rc[1]), rc[7])
func SessionInit(key [16]byte, nonce []byte, tag byte) ([16]byte, error) {
	if !validNonce(nonce) {
		return [16]byte{}, fmt.Errorf("%w: got %d bytes", ErrNonceLen, len(nonce))
	}
	state := key
	state[0] ^= tag
	for c := 0; c < len(nonce)/16; c++ {
		for i := 0; i < 16; i++ {
			state[i] ^= nonce[16*c+i]
		}
		aesRound(&state, &rc[absorbRC[c]])
	}
	aesRound(&state, &rc[1])
	aesRound(&state, &rc[7])
	return state, nil
}

// Session holds the pre-computed per-domain states for one (key, nonce).
type Session struct {
	states map[byte][16]byte
}

// NewSession pre-computes the state of every shipped domain tag
// (DomainStartPixel, DomainChunkLock, DomainLockSeed, DomainBlockHash).
func NewSession(key [16]byte, nonce []byte) (*Session, error) {
	if !validNonce(nonce) {
		return nil, fmt.Errorf("%w: got %d bytes", ErrNonceLen, len(nonce))
	}
	s := &Session{states: make(map[byte][16]byte, len(domains))}
	for _, tag := range domains {
		st, err := SessionInit(key, nonce, tag)
		if err != nil {
			return nil, err
		}
		s.states[tag] = st
	}
	return s, nil
}

// HashPixel returns AESRound(AESRound(state_tag XOR (LE64(idx) || 0^8), rc[2]), rc[3]).
// idx must be below MaxIdx and tag must be a shipped domain tag; violations panic.
func (s *Session) HashPixel(tag byte, idx uint64) [16]byte {
	state, ok := s.states[tag]
	if !ok {
		panic(fmt.Sprintf("aesitb: unknown domain tag %#x", tag))
	}
	if idx >= MaxIdx {
		panic(fmt.Sprintf("aesitb: idx %d exceeds 48-bit range", idx))
	}
	var idxBlock [16]byte
	binary.LittleEndian.PutUint64(idxBlock[:8], idx)
	addRoundKey(&state, &idxBlock)
	aesRound(&state, &rc[2])
	aesRound(&state, &rc[3])
	return state
}

// HashGeneric is the nonce-free Merkle–Damgård fallback:
//
//	state  = key XOR (LE64(seed0) || LE64(seed1))
//	padded = data || PKCS#7 padding to a 16-byte multiple (always ≥ 1 byte)
//	state  = AESRound(state XOR block_i, rc[i mod 8])   for each block i
//	out    = AESRound(AESRound(state, rc[0]), rc[1])
func HashGeneric(key [16]byte, data []byte, seed0, seed1 uint64) [16]byte {
	var seedBlock [16]byte
	binary.LittleEndian.PutUint64(seedBlock[:8], seed0)
	binary.LittleEndian.PutUint64(seedBlock[8:], seed1)
	state := key
	addRoundKey(&state, &seedBlock)

	padLen := 16 - len(data)%16
	padded := make([]byte, 0, len(data)+padLen)
	padded = append(padded, data...)
	for i := 0; i < padLen; i++ {
		padded = append(padded, byte(padLen))
	}
	for i := 0; i < len(padded)/16; i++ {
		var block [16]byte
		copy(block[:], padded[16*i:16*i+16])
		addRoundKey(&state, &block)
		aesRound(&state, &rc[i%8])
	}
	aesRound(&state, &rc[0])
	aesRound(&state, &rc[1])
	return state
}
