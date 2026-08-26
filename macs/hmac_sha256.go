package macs

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"sync"

	"github.com/everanium/itb"
)

// HMACSHA256 returns a cached HMAC-SHA256 itb.MACFunc keyed by key.
// Tag size is 32 bytes regardless of key length. HMAC accepts keys
// of arbitrary length (RFC 2104) — short keys get zero-padded to
// the SHA-256 block size, long keys get hashed first; the
// per-package Make dispatcher applies a 16-byte minimum on top of
// this for ITB keying-discipline reasons, but HMACSHA256 itself
// only rejects an empty key.
//
// Caching strategy: the underlying hash.Hash returned by
// hmac.New(sha256.New, key) carries the key-XOR'd ipad SHA256 state
// after construction. A sync.Pool of these instances lets each call
// take a pre-keyed hasher from the pool, Reset() it (restoring to
// post-ipad state), Write the data, finalize, and return it — no
// per-call key-derivation cost. The pool is the standard idiom for
// reusing mutable hasher state across goroutines.
func HMACSHA256(key []byte) (itb.MACFunc, error) {
	if len(key) == 0 {
		return nil, errKey
	}
	keyCopy := append([]byte(nil), key...)

	pool := &sync.Pool{
		New: func() any {
			h := hmac.New(sha256.New, keyCopy)
			return h
		},
	}

	return func(data []byte) []byte {
		h := pool.Get().(hash.Hash)
		h.Reset()
		h.Write(data)
		var sum [32]byte
		h.Sum(sum[:0])
		pool.Put(h)
		out := make([]byte, 32)
		copy(out, sum[:])
		return out
	}, nil
}

// HMACSHA256Incremental returns the multi-slice arm of [HMACSHA256]:
// an itb.MACIncrementalFunc absorbing its chunks in order and
// emitting the same tag as the HMAC-SHA256 itb.MACFunc over the
// concatenation of those chunks, byte-for-byte. Same pooled pre-keyed
// hasher strategy — only the concat copy disappears.
func HMACSHA256Incremental(key []byte) (itb.MACIncrementalFunc, error) {
	if len(key) == 0 {
		return nil, errKey
	}
	keyCopy := append([]byte(nil), key...)

	pool := &sync.Pool{
		New: func() any {
			h := hmac.New(sha256.New, keyCopy)
			return h
		},
	}

	return func(chunks ...[]byte) []byte {
		h := pool.Get().(hash.Hash)
		h.Reset()
		for _, c := range chunks {
			h.Write(c)
		}
		var sum [32]byte
		h.Sum(sum[:0])
		pool.Put(h)
		out := make([]byte, 32)
		copy(out, sum[:])
		return out
	}, nil
}

// errKey is the sentinel returned when a factory receives an empty
// key. The Make dispatcher applies a stricter MinKeyBytes check
// before reaching the per-primitive factories; this guard exists
// only for direct callers of the typed factory.
var errKey = macError("macs: hmac-sha256 key must not be empty")

type macError string

func (e macError) Error() string { return string(e) }
