package macs

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
	"runtime"
	"sync"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/wipe"
)

// hmacSHA256Entry bundles a pre-keyed HMAC-SHA256 hasher with a reusable
// 32-byte scratch digest buffer and a 64-byte zero block so per-call Sum
// neither escapes a local [32]byte to the heap nor leaves message or ipad/opad
// residue inside the pooled sha256.digest block buffers.
type hmacSHA256Entry struct {
	h    hash.Hash
	sum  [32]byte
	zero [sha256.BlockSize]byte
}

func newHMACSHA256Entry(key []byte) *hmacSHA256Entry {
	e := &hmacSHA256Entry{
		h: hmac.New(sha256.New, key),
	}
	scrubHMACSHA256Entry(e)
	return e
}

func scrubHMACSHA256Entry(e *hmacSHA256Entry) {
	e.h.Reset()
	e.h.Write(e.zero[:1])
	e.h.Write(e.zero[:sha256.BlockSize-1])
	e.h.Sum(e.sum[:0])
	clear(e.sum[:])
	e.h.Reset()
	runtime.KeepAlive(e)
}

//go:noinline
func evalHMACSHA256(e *hmacSHA256Entry, out, data []byte) {
	e.h.Write(data)
	e.h.Sum(e.sum[:0])
	copy(out, e.sum[:])
	scrubHMACSHA256Entry(e)
}

//go:noinline
func evalHMACSHA256Inc(e *hmacSHA256Entry, out []byte, chunks [][]byte) {
	for _, c := range chunks {
		e.h.Write(c)
	}
	e.h.Sum(e.sum[:0])
	copy(out, e.sum[:])
	scrubHMACSHA256Entry(e)
}

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
			return newHMACSHA256Entry(keyCopy)
		},
	}

	return func(data []byte) []byte {
		e := pool.Get().(*hmacSHA256Entry)
		out := make([]byte, 32)
		evalHMACSHA256(e, out, data)
		pool.Put(e)
		wipe.CallStack2K([9][8]uint64{})
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
			return newHMACSHA256Entry(keyCopy)
		},
	}

	return func(chunks ...[]byte) []byte {
		e := pool.Get().(*hmacSHA256Entry)
		out := make([]byte, 32)
		evalHMACSHA256Inc(e, out, chunks)
		pool.Put(e)
		wipe.CallStack2K([9][8]uint64{})
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
