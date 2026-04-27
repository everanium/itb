package itb

import "sync"

// bufferPool is a process-wide *[]byte pool used for internal scratch
// buffers inside Encrypt* / Decrypt* / Encrypt3x* / Decrypt3x* paths.
// Pooled buffers hold plaintext or plaintext-derived data and are wiped
// before being returned to the pool.
//
// Storing pointers-to-slice-header (`*[]byte`) instead of slice values
// avoids the slice-header copy that sync.Pool would otherwise perform on
// every Get / Put — the same idiom the cached hash wrappers in `doc.go`
// use, and the form go vet's SA6002 rule expects for size-tracked pooled
// objects.
//
// Scope — the pool manages ONLY internal scratch space:
//   - encrypt-side `payload` / `payloads[i]` (COBS-encoded plaintext +
//     null terminator + CSPRNG fill, consumed by `process*`)
//   - decrypt-side `decoded` / `decoded[i]` (plaintext extracted from
//     ciphertext, consumed by `cobsDecode`)
//   - bit-soup split outputs `p0` / `p1` / `p2` (plaintext-derived bit
//     permutations, consumed by `cobsEncode`)
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
	if cap(buf) < n {
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
