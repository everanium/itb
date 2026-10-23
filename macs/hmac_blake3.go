package macs

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/zeebo/blake3"

	"github.com/everanium/itb"
	"github.com/everanium/itb/internal/wipe"
)

type blake3MACEntry struct {
	h   *blake3.Hasher
	sum [32]byte
}

func newBLAKE3MACPool(template *blake3.Hasher) *sync.Pool {
	return &sync.Pool{
		New: func() any {
			return &blake3MACEntry{
				h: template.Clone(),
			}
		},
	}
}

var blake3MACZeroChunk [1024]byte

func scrubBLAKE3MACEntry(e *blake3MACEntry, tmpl *blake3.Hasher, nWritten int) {
	if nWritten <= len(blake3MACZeroChunk) {
		e.h.Reset()
		if nWritten > 0 {
			_, _ = e.h.Write(blake3MACZeroChunk[:nWritten])
			e.h.Reset()
		}
		return
	}
	*e.h = *tmpl
}

//go:noinline
func evalHMACBLAKE3(e *blake3MACEntry, tmpl *blake3.Hasher, out, data []byte) {
	_, _ = e.h.Write(data)
	e.h.Sum(e.sum[:0])
	copy(out, e.sum[:])
	scrubBLAKE3MACEntry(e, tmpl, len(data))
	clear(e.sum[:])
	runtime.KeepAlive(e)
}

//go:noinline
func evalHMACBLAKE3Inc(e *blake3MACEntry, tmpl *blake3.Hasher, out []byte, chunks [][]byte) {
	total := 0
	for _, c := range chunks {
		_, _ = e.h.Write(c)
		total += len(c)
	}
	e.h.Sum(e.sum[:0])
	copy(out, e.sum[:])
	scrubBLAKE3MACEntry(e, tmpl, total)
	clear(e.sum[:])
	runtime.KeepAlive(e)
}

// HMACBLAKE3 returns a cached BLAKE3-keyed itb.MACFunc.
//
// BLAKE3 has a native keyed mode (`blake3.NewKeyed(key32)`) that
// derives the per-message hashing state from a 32-byte key once;
// this is the recommended construction for "HMAC-BLAKE3" (no nested
// HMAC wrapper is required because BLAKE3-keyed is itself a sound
// keyed PRF — see the BLAKE3 spec, section 6).
//
// Caching strategy: the keyed template hasher is built once at
// factory construction. Each call borrows a pooled clone, copies the
// clean template state into it, writes the data, finalizes to 32
// bytes, overwrites the full 8 KiB chunk buffer and CV stack from the
// clean template, and returns the entry to the pool.
//
// Key length must be exactly 32 bytes. Shorter keys are rejected.
func HMACBLAKE3(key []byte) (itb.MACFunc, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("macs: hmac-blake3 key must be exactly 32 bytes, got %d", len(key))
	}
	template, err := blake3.NewKeyed(key)
	if err != nil {
		return nil, fmt.Errorf("macs: blake3.NewKeyed: %w", err)
	}
	pool := newBLAKE3MACPool(template)
	return func(data []byte) []byte {
		e := pool.Get().(*blake3MACEntry)
		out := make([]byte, 32)
		evalHMACBLAKE3(e, template, out, data)
		pool.Put(e)
		wipe.CallStack2K([9][8]uint64{})
		return out
	}, nil
}

// HMACBLAKE3Incremental returns the multi-slice arm of [HMACBLAKE3]:
// an itb.MACIncrementalFunc absorbing its chunks in order and
// emitting the same tag as the BLAKE3-keyed itb.MACFunc over the
// concatenation of those chunks, byte-for-byte. Same keyed-template
// pool strategy — only the concat copy disappears.
func HMACBLAKE3Incremental(key []byte) (itb.MACIncrementalFunc, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("macs: hmac-blake3 key must be exactly 32 bytes, got %d", len(key))
	}
	template, err := blake3.NewKeyed(key)
	if err != nil {
		return nil, fmt.Errorf("macs: blake3.NewKeyed: %w", err)
	}
	pool := newBLAKE3MACPool(template)
	return func(chunks ...[]byte) []byte {
		e := pool.Get().(*blake3MACEntry)
		out := make([]byte, 32)
		evalHMACBLAKE3Inc(e, template, out, chunks)
		pool.Put(e)
		wipe.CallStack2K([9][8]uint64{})
		return out
	}, nil
}
