package parallax

import (
	"runtime"
	"sync"

	"github.com/everanium/itb/ctr"
)

// maxWorkers caps the goroutine count for the parallax XOR pass. The
// value mirrors wrapper.maxWrapWorkers so the keystream layer cannot
// over-subscribe a many-core host on top of ITB's own per-core workers.
const maxWorkers = 32

// parallelThreshold is the minimum buffer length before the segment loop
// is split across workers. Below it, the per-worker keystream setup —
// which has to construct N ResettableKeystream instances regardless of
// per-segment work — dominates, so the loop runs serially in the
// caller's goroutine.
const parallelThreshold = 8 * 1024

// minSegsPerWorker keeps each worker busy with enough segments to
// amortise the per-worker keystream-setup cost. The worker count is
// further bounded by total-segments / minSegsPerWorker.
const minSegsPerWorker = 8

// runWorkers dispatches the segment loop across one or more goroutines.
// Every goroutine constructs its own copy of N ctr.ResettableKeystream
// instances under (palette[s], subkeys[s], slice nonce); each segment
// resets its slot's keystream counter to the segment's absolute byte
// offset and XORs S bytes (or fewer for the tail segment). dst and src
// may alias for in-place XOR. The segment width is supplied by the
// caller so single-message and streaming paths can route through their
// own per-mode S values.
func runWorkers(s *Schedule, cs *Cipherset, pi []int, nonce, dst, src []byte, segSize int) error {
	total := len(src)
	if total == 0 {
		return nil
	}
	numSegs := (total + segSize - 1) / segSize

	workers := workerCount(total, numSegs)
	if workers <= 1 {
		return runRange(s, cs, pi, nonce, dst, src, 0, numSegs, segSize)
	}

	segsPerWorker := (numSegs + workers - 1) / workers
	var wg sync.WaitGroup
	errs := make([]error, workers)
	for w := 0; w < workers; w++ {
		start := w * segsPerWorker
		if start >= numSegs {
			break
		}
		end := start + segsPerWorker
		if end > numSegs {
			end = numSegs
		}
		wg.Add(1)
		go func(idx, segStart, segEnd int) {
			defer wg.Done()
			errs[idx] = runRange(s, cs, pi, nonce, dst, src, segStart, segEnd, segSize)
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

// runRange is the per-worker hot loop. It builds one keystream per
// palette slot at offset 0 and walks segments [segStart, segEnd),
// repositioning each slot's keystream counter to the segment's
// absolute byte offset before XOR. segSize is the per-mode segment
// width supplied by the caller.
func runRange(s *Schedule, cs *Cipherset, pi []int, nonce, dst, src []byte, segStart, segEnd, segSize int) error {
	total := len(src)
	n := len(pi)
	ks, err := buildKeystreamsForRange(s, cs, nonce)
	if err != nil {
		return err
	}

	for segIdx := segStart; segIdx < segEnd; segIdx++ {
		slot := pi[segIdx%n]
		off := segIdx * segSize
		end := off + segSize
		if end > total {
			end = total
		}
		if err := ks[slot].ResetCounter(off); err != nil {
			return err
		}
		ks[slot].XORKeyStream(dst[off:end], src[off:end])
	}
	return nil
}

// buildKeystreamsForRange constructs one keystream per palette slot
// under the slot's subkey and a per-cipher truncated view of the
// per-message nonce. Each keystream is built at offset 0; the per-segment
// hot loop above reseats the counter via ResetCounter before each XOR.
func buildKeystreamsForRange(s *Schedule, cs *Cipherset, nonce []byte) ([]ctr.ResettableKeystream, error) {
	ks := make([]ctr.ResettableKeystream, len(s.palette))
	for i, name := range s.palette {
		sliceNonce, err := sliceNonceFor(name, nonce)
		if err != nil {
			return nil, err
		}
		built, err := ctr.NewResettable(name, cs.subkeys[i], sliceNonce)
		if err != nil {
			return nil, err
		}
		ks[i] = built
	}
	return ks, nil
}

// workerCount picks the goroutine count for a buf of total bytes
// carrying numSegs segments. Mirrors the wrapper's wrapWorkers shape
// while honouring the minSegsPerWorker floor that keeps every worker
// busy enough to amortise its keystream-setup cost.
func workerCount(total, numSegs int) int {
	if total < parallelThreshold {
		return 1
	}
	w := runtime.GOMAXPROCS(0)
	if w > maxWorkers {
		w = maxWorkers
	}
	if w < 1 {
		w = 1
	}
	limit := numSegs / minSegsPerWorker
	if limit < 1 {
		limit = 1
	}
	if w > limit {
		w = limit
	}
	return w
}
