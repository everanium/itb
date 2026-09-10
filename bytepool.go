package itb

import (
	"sync"

	"github.com/everanium/itb/internal/poolstats"
)

// bufferPool is a process-wide *[]byte pool used for internal scratch
// buffers inside Encrypt* / Decrypt* / Encrypt3x* / Decrypt3x* paths.
// Pooled buffers hold plaintext or plaintext-derived data and are wiped
// before being returned to the pool.
//
// Storing pointers-to-slice-header (`*[]byte`) instead of slice values
// avoids the slice-header copy that sync.Pool would otherwise perform on
// every Get / Put — the same idiom the cached hash wrappers in
// `process_cgo.go` use, and the form go vet's SA6002 rule expects for
// size-tracked pooled objects.
//
// Scope — the pool manages ONLY internal scratch space:
//   - encrypt-side `payload` / `payloads[i]` (COBS-encoded plaintext +
//     null terminator + DRBG fill, consumed by `process*`)
//   - decrypt-side `decoded` / `decoded[i]` (plaintext extracted from
//     ciphertext, consumed by `cobsDecode`)
//   - Triple 3-snake split outputs `p0` / `p1` / `p2` (plaintext-derived
//     per-snake byte streams, consumed by `cobsEncode`)
//
// The ciphertext output buffer returned to the caller is NOT pooled. It
// is allocated separately and its lifetime extends past the encrypt
// function, so it must never enter the pool.
//
// Default capacity 4096 bytes covers the smallest realistic payloads
// (4 KB plaintext class). acquireBuffer grows the buffer transparently
// when a larger size is requested. Single-class pool (no size tiering)
// — ITB plaintext upper bound is bounded by maxDataSize and the pool
// settles at the working-set's maximum after warm-up.
var bufferPool = &sync.Pool{
	New: func() any {
		poolstats.BufNew.Add(1)
		b := make([]byte, 0, 4096)
		return &b
	},
}

// acquireBuffer returns a slice of exactly n bytes drawn from
// [bufferPool], growing the underlying capacity by allocating a fresh
// `make([]byte, n)` if the pooled buffer is too small. The returned
// slice is zero-initialised — pool releases wipe the buffer via
// [secureWipe], and a freshly-allocated buffer from `make` is also zero
// — so callers may rely on initial zero state without an extra clear
// pass.
//
// Always paired with a [releaseBuffer] call when the buffer is no
// longer needed.
func acquireBuffer(n int) (*[]byte, []byte) {
	ptr := bufferPool.Get().(*[]byte)
	buf := *ptr
	poolstats.BufGet.Add(1)
	if cap(buf) < n {
		poolstats.BufRegrow.Add(1)
		poolstats.BufRegrowBytes.Add(int64(n))
		buf = make([]byte, n)
	} else {
		buf = buf[:n]
	}
	return ptr, buf
}

// releaseBuffer zero-wipes the buffer through [secureWipe] (preserving
// the heap-hygiene contract for plaintext-derived data) and returns it
// to [bufferPool] for reuse on the next [acquireBuffer] call. The wipe
// is unconditional — every release targets sensitive content, since the
// pool is reserved for internal scratch space holding plaintext or its
// derivatives.
func releaseBuffer(ptr *[]byte, buf []byte) {
	secureWipe(buf)
	*ptr = buf
	bufferPool.Put(ptr)
}

// stagePool is a process-wide *[]byte pool for the chunk-budget read
// stage of the streaming encrypt entry points. A stage buffer is sized
// to the stream's chunk budget (up to maxDataSize) rather than to the
// payload, so it is kept apart from [bufferPool]: mixing chunk-budget
// items into the scratch pool would inflate what every small
// acquireBuffer call retains.
//
// The pool's New returns an empty item; the first checkout on a miss
// allocates exactly the requested width and the release stores that
// width back, so items converge on the widest chunk budget requested
// across the pipelines sharing the pool and are never regrown into
// throw-away capacity.
var stagePool = &sync.Pool{
	New: func() any {
		var b []byte
		return &b
	},
}

// acquireStage returns a slice of exactly n bytes drawn from
// [stagePool], allocating a fresh n-byte buffer when the pooled item is
// narrower. Contents are unspecified beyond what the caller writes —
// stage consumers fill a prefix through io.ReadFull and read back only
// that prefix, so no zero pass is performed on borrow.
//
// Always paired with a [releaseStage] call carrying the high-water
// mark of bytes the caller wrote.
func acquireStage(n int) (*[]byte, []byte) {
	ptr := stagePool.Get().(*[]byte)
	buf := *ptr
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	return ptr, buf[:n]
}

// releaseStage wipes the written prefix buf[:used] through [secureWipe]
// (the stage holds plaintext) and returns the buffer to [stagePool].
// Wiping the high-water mark rather than the full capacity keeps the
// release cost proportional to the bytes actually staged.
func releaseStage(ptr *[]byte, buf []byte, used int) {
	secureWipe(buf[:used])
	*ptr = buf[:0]
	stagePool.Put(ptr)
}
