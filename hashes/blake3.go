package hashes

import (
	"crypto/rand"
	"encoding/binary"
	"sync"

	"github.com/zeebo/blake3"

	"github.com/everanium/itb"
)

// BLAKE3 returns a cached BLAKE3-256 itb.HashFunc256 with a freshly-
// generated 32-byte BLAKE3 key.
//
// The pre-keyed BLAKE3 hasher template is created once via
// blake3.NewKeyed; each call clones the template instead of
// re-keying, sidestepping the data race that Reset() on a shared
// hasher would cause when ITB's process256 dispatches multiple
// goroutines on the same seed. A sync.Pool of scratch buffers keeps
// per-call allocation at zero.
//
// Seed components are mixed into the hashed payload as XOR over the
// first 32 bytes; the input is zero-padded out to 32 bytes when the
// caller's data is shorter, so all four seed uint64's contribute
// regardless of how short the caller's data is.
// BLAKE3 returns a cached BLAKE3-256 itb.HashFunc256 along with the
// 32-byte BLAKE3 key the closure is bound to. With no argument a
// fresh key is generated via crypto/rand; passing a single
// caller-supplied [32]byte uses that key instead. Save the returned
// key for cross-process persistence.
func BLAKE3(key ...[32]byte) (itb.HashFunc256, [32]byte) {
	var k [32]byte
	if len(key) > 0 {
		k = key[0]
	} else if _, err := rand.Read(k[:]); err != nil {
		panic(err)
	}
	return BLAKE3WithKey(k), k
}

// BLAKE3WithKey returns the BLAKE3 closure built around a caller-
// supplied 32-byte BLAKE3 key, for serialization across processes.
func BLAKE3WithKey(key [32]byte) itb.HashFunc256 {
	template, _ := blake3.NewKeyed(key[:])
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

	return func(data []byte, seed [4]uint64) [4]uint64 {
		h := template.Clone()

		const seedInjectBytes = 32
		payloadLen := len(data)
		if payloadLen < seedInjectBytes {
			payloadLen = seedInjectBytes
		}
		mixedPtr := pool.Get().(*[]byte)
		mixed := *mixedPtr
		if cap(mixed) < payloadLen {
			mixed = make([]byte, payloadLen)
		} else {
			mixed = mixed[:payloadLen]
		}
		for i := len(data); i < payloadLen; i++ {
			mixed[i] = 0
		}
		copy(mixed[:len(data)], data)
		for i := 0; i < 4; i++ {
			off := i * 8
			binary.LittleEndian.PutUint64(mixed[off:], binary.LittleEndian.Uint64(mixed[off:])^seed[i])
		}
		h.Write(mixed)
		*mixedPtr = mixed
		pool.Put(mixedPtr)

		var buf [32]byte
		h.Sum(buf[:0])
		return [4]uint64{
			binary.LittleEndian.Uint64(buf[0:]),
			binary.LittleEndian.Uint64(buf[8:]),
			binary.LittleEndian.Uint64(buf[16:]),
			binary.LittleEndian.Uint64(buf[24:]),
		}
	}
}
