package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
)

// worker is one stress goroutine's private state. The plaintext buffer
// is generated once at startup and never mutated; the wire and
// round-trip buffers are reused across iterations via Reset so the
// steady-state allocation profile stays flat.
type worker struct {
	id        int
	plaintext []byte
	wireBuf   bytes.Buffer
	plainBuf  bytes.Buffer

	// Counters read concurrently by the monitor goroutine.
	iters    atomic.Int64
	bytesEnc atomic.Int64
	bytesDec atomic.Int64
}

// runLoop is the worker goroutine body: one warmup iteration, the
// warmup barrier, then the main loop until the context cancels or the
// fixed per-worker iteration budget is spent. Pipeline errors are
// returned to the launcher (which cancels the whole run); data
// mismatches panic inside iterate.
func (w *worker) runLoop(ctx context.Context, r *runState, warmupWG *sync.WaitGroup) error {
	// Warmup iteration — counted in the totals; its completion feeds
	// the post-warmup heap / goroutine baselines.
	if err := w.iterate(r, 0); err != nil {
		warmupWG.Done()
		return err
	}
	warmupWG.Done()
	select {
	case <-r.release:
	case <-ctx.Done():
		return nil
	}

	for iter := int64(1); ; iter++ {
		if r.cfg.iterations > 0 && iter >= r.cfg.iterations {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		if err := w.iterate(r, iter); err != nil {
			return err
		}
	}
}

// iterate performs one encrypt -> decrypt -> compare round-trip on the
// shared Pipeline. Under --shape both, even iterations exercise the
// streaming surface and odd iterations the Single Message surface, so
// both shapes interleave inside every worker.
func (w *worker) iterate(r *runState, iter int64) error {
	shape := r.cfg.shape
	if shape == shapeBoth {
		if iter%2 == 0 {
			shape = shapeStream
		} else {
			shape = shapeMessage
		}
	}

	var got []byte
	switch shape {
	case shapeStream:
		w.wireBuf.Reset()
		if err := r.streamPipe.EncryptStream(bytes.NewReader(w.plaintext), &w.wireBuf); err != nil {
			return fmt.Errorf("g%d iter %d: EncryptStream: %w", w.id, iter, err)
		}
		w.plainBuf.Reset()
		if err := r.streamPipe.DecryptStream(bytes.NewReader(w.wireBuf.Bytes()), &w.plainBuf); err != nil {
			return fmt.Errorf("g%d iter %d: DecryptStream: %w", w.id, iter, err)
		}
		got = w.plainBuf.Bytes()
	case shapeMessage:
		wire, err := r.msgPipe.EncryptMessage(w.plaintext)
		if err != nil {
			return fmt.Errorf("g%d iter %d: EncryptMessage: %w", w.id, iter, err)
		}
		out, err := r.msgPipe.DecryptMessage(wire)
		if err != nil {
			return fmt.Errorf("g%d iter %d: DecryptMessage: %w", w.id, iter, err)
		}
		got = out
	}

	if !bytes.Equal(w.plaintext, got) {
		panic(fmt.Sprintf(
			"loop: DATA MISMATCH g%d iter %d shape=%s: want %d bytes sha256=%x, got %d bytes sha256=%x",
			w.id, iter, shape,
			len(w.plaintext), sha256.Sum256(w.plaintext),
			len(got), sha256.Sum256(got)))
	}

	w.iters.Add(1)
	w.bytesEnc.Add(int64(len(w.plaintext)))
	w.bytesDec.Add(int64(len(got)))
	return nil
}
