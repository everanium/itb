package hashes

import (
	"crypto/rand"
	"encoding/binary"
	"sync"

	"golang.org/x/crypto/blake2s"

	"github.com/everanium/itb"
)

// BLAKE2s returns a cached BLAKE2s-256 itb.HashFunc256 with a
// freshly-generated 32-byte fixed key.
//
// Same construction as BLAKE2b256: H(key || data ^ seed) using
// blake2s.Sum256 (no allocation, no keyed-mode handle). The payload
// region is zero-padded to 32 bytes for short inputs so all four
// seed uint64's contribute to the digest.
func BLAKE2s() itb.HashFunc256 {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		panic(err)
	}
	return BLAKE2sWithKey(key)
}

// BLAKE2sWithKey returns the BLAKE2s-256 closure built around a
// caller-supplied 32-byte fixed key, for serialization paths.
func BLAKE2sWithKey(b2key [32]byte) itb.HashFunc256 {
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

	return func(data []byte, seed [4]uint64) [4]uint64 {
		const keyLen = 32
		const seedInjectBytes = 32
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
		for i := 0; i < 4; i++ {
			off := keyLen + i*8
			binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
		}
		digest := blake2s.Sum256(buf)
		*bufPtr = buf
		pool.Put(bufPtr)
		return [4]uint64{
			binary.LittleEndian.Uint64(digest[0:]),
			binary.LittleEndian.Uint64(digest[8:]),
			binary.LittleEndian.Uint64(digest[16:]),
			binary.LittleEndian.Uint64(digest[24:]),
		}
	}
}
