package hashes

import (
	"crypto/rand"
	"encoding/binary"
	"sync"

	"golang.org/x/crypto/blake2b"

	"github.com/everanium/itb"
)

// BLAKE2b512 returns a cached BLAKE2b-512 itb.HashFunc512 with a
// freshly-generated 64-byte fixed key.
//
// BLAKE2b natively supports 512-bit output and up to a 64-byte key.
// The construction is identical to BLAKE2b256 modulo widths:
// H(key || data ^ seed) where the payload is zero-padded out to 64
// bytes when shorter, ensuring all eight seed uint64's contribute
// regardless of how short the caller's data is.
// BLAKE2b512 returns a cached BLAKE2b-512 itb.HashFunc512 along with
// the 64-byte fixed key the closure is bound to. With no argument a
// fresh key is generated via crypto/rand; passing a single
// caller-supplied [64]byte uses that key instead. Save the returned
// key for cross-process persistence.
func BLAKE2b512(key ...[64]byte) (itb.HashFunc512, [64]byte) {
	var k [64]byte
	if len(key) > 0 {
		k = key[0]
	} else if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	return BLAKE2b512WithKey(k), k
}

// BLAKE2b512WithKey returns the BLAKE2b-512 closure built around a
// caller-supplied 64-byte fixed key, for serialization paths.
func BLAKE2b512WithKey(b2key [64]byte) itb.HashFunc512 {
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

	return func(data []byte, seed [8]uint64) [8]uint64 {
		const keyLen = 64
		const seedInjectBytes = 64
		payloadLen := len(data)
		if payloadLen < seedInjectBytes {
			payloadLen = seedInjectBytes
		}
		need := keyLen + payloadLen
		bufPtr := pool.Get().(*[]byte)
		buf := *bufPtr
		if cap(buf) < need {
			buf = make([]byte, need)
		} else {
			buf = buf[:need]
		}
		for i := keyLen + len(data); i < need; i++ {
			buf[i] = 0
		}
		copy(buf[:keyLen], b2key[:])
		copy(buf[keyLen:keyLen+len(data)], data)
		for i := 0; i < 8; i++ {
			off := keyLen + i*8
			binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
		}
		digest := blake2b.Sum512(buf)
		*bufPtr = buf
		pool.Put(bufPtr)
		return [8]uint64{
			binary.LittleEndian.Uint64(digest[0:]),
			binary.LittleEndian.Uint64(digest[8:]),
			binary.LittleEndian.Uint64(digest[16:]),
			binary.LittleEndian.Uint64(digest[24:]),
			binary.LittleEndian.Uint64(digest[32:]),
			binary.LittleEndian.Uint64(digest[40:]),
			binary.LittleEndian.Uint64(digest[48:]),
			binary.LittleEndian.Uint64(digest[56:]),
		}
	}
}
