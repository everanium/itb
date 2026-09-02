package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	mrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

// worker is one stress goroutine's private state. The plaintext buffer
// is generated once at startup and mutated only by the rotating
// payload mode (refilled in place before each iteration); the wire and
// round-trip buffers are reused across iterations via Reset so the
// steady-state allocation profile stays flat.
type worker struct {
	id        int
	plaintext []byte
	wireBuf   bytes.Buffer
	plainBuf  bytes.Buffer

	// payloadMode is the plaintext content policy (payload* constants);
	// rotating mode refills plaintext before every iteration.
	payloadMode string

	// rng is the deterministic plaintext source for seeded runs; nil
	// selects crypto/rand (the default).
	rng *mrand.ChaCha8

	// Counters read concurrently by the monitor goroutine.
	iters    atomic.Int64
	bytesEnc atomic.Int64
	bytesDec atomic.Int64
	nanosEnc atomic.Int64 // wall time this worker spent inside Encrypt calls
	nanosDec atomic.Int64 // wall time this worker spent inside Decrypt calls
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
		if err := w.maintenance(r, iter); err != nil {
			return err
		}
	}
}

// iterate performs one encrypt -> decrypt -> compare round-trip on the
// shared Pipeline. Under --shape both, even iterations exercise the
// streaming surface and odd iterations the Single Message surface, so
// both shapes interleave inside every worker. The whole round-trip
// runs under the pipeMu read lock so pipeline-mutating maintenance
// (Rekey, blob cycle) never lands between an encrypt and its matching
// decrypt.
func (w *worker) iterate(r *runState, iter int64) error {
	if w.payloadMode == payloadRotating {
		if err := fillPayload(payloadRotating, w.rng, w.plaintext); err != nil {
			return fmt.Errorf("g%d iter %d: payload refill: %w", w.id, iter, err)
		}
	}

	r.pipeMu.RLock()
	defer r.pipeMu.RUnlock()

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
		encStart := time.Now()
		if err := r.streamPipe.EncryptStream(bytes.NewReader(w.plaintext), &w.wireBuf); err != nil {
			return fmt.Errorf("g%d iter %d: EncryptStream: %w", w.id, iter, err)
		}
		w.nanosEnc.Add(time.Since(encStart).Nanoseconds())
		w.plainBuf.Reset()
		decStart := time.Now()
		if err := r.streamPipe.DecryptStream(bytes.NewReader(w.wireBuf.Bytes()), &w.plainBuf); err != nil {
			return fmt.Errorf("g%d iter %d: DecryptStream: %w", w.id, iter, err)
		}
		w.nanosDec.Add(time.Since(decStart).Nanoseconds())
		got = w.plainBuf.Bytes()
	case shapeMessage:
		encStart := time.Now()
		wire, err := r.msgPipe.EncryptMessage(w.plaintext)
		if err != nil {
			return fmt.Errorf("g%d iter %d: EncryptMessage: %w", w.id, iter, err)
		}
		w.nanosEnc.Add(time.Since(encStart).Nanoseconds())
		decStart := time.Now()
		out, err := r.msgPipe.DecryptMessage(wire)
		if err != nil {
			return fmt.Errorf("g%d iter %d: DecryptMessage: %w", w.id, iter, err)
		}
		w.nanosDec.Add(time.Since(decStart).Nanoseconds())
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
