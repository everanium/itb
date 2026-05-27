package wrapper

import (
	"runtime"
	"sync"

	"github.com/everanium/itb/ctr"
)

// maxWrapWorkers caps the keystream-XOR goroutine count. It is fixed rather
// than user-configurable: ITB's own encrypt / decrypt already saturates every
// core, so the wrapper's XOR pass — a secondary, partly memory-bound step
// layered on top — must not over-subscribe by spawning a goroutine per core a
// second time. The effective count is min(maxWrapWorkers, GOMAXPROCS, chunks),
// so a single-core machine runs exactly one worker (the serial path) with no
// goroutine overhead, a 16-HT host runs 16, and a high-core host (e.g. a 192-HT
// EPYC) is capped here — 32 gives such hosts more keystream parallelism while
// staying a small fraction of the cores ITB's own workers use, so the two
// layers do not contend. Past ~32 the XOR is memory-bandwidth-bound and extra
// workers do not help.
const maxWrapWorkers = 32

// parallelThreshold is the minimum buffer length before the XOR is split
// across workers. Below it, goroutine setup and per-worker keystream keying
// outweigh the parallel speedup, so the XOR runs serially on the caller's
// goroutine.
const parallelThreshold = 256 * 1024

// wrapWorkers returns the worker count for an n-byte buffer.
func wrapWorkers(n int) int {
	w := runtime.GOMAXPROCS(0)
	if w > maxWrapWorkers {
		w = maxWrapWorkers
	}
	if w < 1 {
		w = 1
	}
	return w
}

// xorParallel XORs the outer cipher keystream of (name, key, nonce) over src
// into dst starting at keystream offset 0. It is the base-0 form of
// xorParallelAt; see there for the parallelisation contract.
func xorParallel(name string, key, nonce, dst, src []byte) error {
	return xorParallelAt(name, key, nonce, 0, dst, src)
}

// xorParallelAt XORs the (name, key, nonce) keystream over src into dst,
// applying keystream byte base+i to src byte i. For buffers at or above
// parallelThreshold it splits the work across up to maxWrapWorkers goroutines,
// each seeking its own keystream to its absolute offset via ctr.NewAt; below
// the threshold (or with one worker) it runs serially. The output is identical
// to a single serial keystream regardless of worker count (see
// ctr.TestNewAtParity), so this is a transparent speedup. dst and src may alias
// (in-place XOR); each worker touches a disjoint [start:end] range. base lets a
// streaming caller continue one logical keystream across successive chunks by
// passing the cumulative byte offset already consumed before this chunk.
func xorParallelAt(name string, key, nonce []byte, base int, dst, src []byte) error {
	n := len(src)
	workers := wrapWorkers(n)
	if n < parallelThreshold || workers <= 1 {
		ks, err := ctr.NewAt(name, key, nonce, base)
		if err != nil {
			return err
		}
		ks.XORKeyStream(dst[:n], src)
		return nil
	}

	chunk := (n + workers - 1) / workers
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for w := 0; w < workers; w++ {
		start := w * chunk
		if start >= n {
			break
		}
		end := start + chunk
		if end > n {
			end = n
		}
		wg.Add(1)
		go func(w, start, end int) {
			defer wg.Done()
			ks, err := ctr.NewAt(name, key, nonce, base+start)
			if err != nil {
				errs[w] = err
				return
			}
			ks.XORKeyStream(dst[start:end], src[start:end])
		}(w, start, end)
	}
	wg.Wait()
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// XORParallel applies the (name, key, nonce) outer cipher keystream over src
// into dst with the same chunk-parallel scheme as Wrap / WrapInPlace: at or
// above parallelThreshold the work is split across up to maxWrapWorkers
// goroutines, below it the pass runs serially. dst and src may alias (in-place
// XOR). The output is byte-identical to a single serial keystream regardless of
// worker count.
//
// It is exposed for the C ABI, which owns its output buffers (a caller-supplied
// out slice or an in-place blob) and so cannot use the allocating Wrap /
// WrapInPlace helpers, yet still needs the multi-core keystream pass rather than
// a single-goroutine XOR.
func XORParallel(name string, key, nonce, dst, src []byte) error {
	return xorParallel(name, key, nonce, dst, src)
}

// XORParallelAt is XORParallel with a base keystream offset: src byte i is
// XORed with keystream byte base+i. The streaming wrapper passes the cumulative
// byte count already emitted on the stream so a single large chunk is XORed in
// parallel while still continuing the one logical keystream the matching reader
// expects. dst and src may alias.
func XORParallelAt(name string, key, nonce []byte, base int, dst, src []byte) error {
	return xorParallelAt(name, key, nonce, base, dst, src)
}

// ParallelThreshold is the chunk size at or above which XORParallel /
// XORParallelAt split the keystream XOR across workers. It is exposed so the C
// ABI streaming handle can decide, per Update, whether to reseed-and-parallelise
// a large chunk or advance its serial keystream for a small one (where the
// per-chunk reseed keying would outweigh the parallel speedup).
const ParallelThreshold = parallelThreshold
