package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	mrand "math/rand/v2"
	"os"
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

// One iteration. In order: refill the plaintext under rotating mode;
// take the read lock; pick the surface; encrypt (timed); decrypt
// (timed); compare the round-trip with the plaintext; bump the
// counters; release the lock. The whole round-trip runs under the
// pipeMu read lock so pipeline-mutating maintenance (Rekey, blob
// cycle) never lands between an encrypt and its matching decrypt —
// maintenance runs after this returns, from runLoop.
func (w *worker) iterate(r *runState, iter int64) error {
	if w.payloadMode == payloadRotating {
		if err := fillPayload(payloadRotating, w.rng, w.plaintext); err != nil {
			return fmt.Errorf("g%d iter %d: payload refill: %w", w.id, iter, err)
		}
	}

	r.pipeMu.RLock()
	defer r.pipeMu.RUnlock()

	// Shape dispatch. message is one whole-buffer call on the Single
	// Message Pipeline; stream_one_shot is one whole-buffer call on
	// the streaming Pipeline (EncryptStreamBytes — the entry the C
	// ABI's ITB_Triple_EncryptStream routes to); stream hands the
	// same streaming Pipeline an io.Reader / io.Writer pair and ITB
	// runs the chunk loop itself. Under both the three rotate by
	// iteration number so the session path and the whole-buffer path
	// alternate on one handle inside every worker — the cross-path
	// state-reuse hazard this harness exists to catch.
	shape := r.cfg.shape
	if shape == shapeBoth {
		switch iter % 3 {
		case 0:
			shape = shapeStream
		case 1:
			shape = shapeMessage
		default:
			shape = shapeStreamOneShot
		}
	}

	var got []byte
	switch shape {
	case shapeStream:
		// Pump loop. Not applicable here: EncryptStream takes the
		// io.Reader / io.Writer pair and ITB drives the chunk loop
		// internally, so this harness never feeds or drains a session
		// by hand. A binding has no reader / writer entry on the C ABI
		// and drives the loop itself over a stream session.
		w.wireBuf.Reset()
		encStart := time.Now()
		if err := r.streamPipe.EncryptStream(bytes.NewReader(w.plaintext), &w.wireBuf); err != nil {
			return fmt.Errorf("g%d iter %d shape=%s: encrypt: %w", w.id, iter, shape, err)
		}
		w.nanosEnc.Add(time.Since(encStart).Nanoseconds())
		w.plainBuf.Reset()
		decStart := time.Now()
		if err := r.streamPipe.DecryptStream(bytes.NewReader(w.wireBuf.Bytes()), &w.plainBuf); err != nil {
			return fmt.Errorf("g%d iter %d shape=%s: decrypt: %w", w.id, iter, shape, err)
		}
		w.nanosDec.Add(time.Since(decStart).Nanoseconds())
		got = w.plainBuf.Bytes()
	case shapeStreamOneShot:
		encStart := time.Now()
		wire, err := r.streamPipe.EncryptStreamBytes(w.plaintext)
		if err != nil {
			return fmt.Errorf("g%d iter %d shape=%s: encrypt: %w", w.id, iter, shape, err)
		}
		w.nanosEnc.Add(time.Since(encStart).Nanoseconds())
		decStart := time.Now()
		out, err := r.streamPipe.DecryptStreamBytes(wire)
		if err != nil {
			return fmt.Errorf("g%d iter %d shape=%s: decrypt: %w", w.id, iter, shape, err)
		}
		w.nanosDec.Add(time.Since(decStart).Nanoseconds())
		got = out
	case shapeMessage:
		encStart := time.Now()
		wire, err := r.msgPipe.EncryptMessage(w.plaintext)
		if err != nil {
			return fmt.Errorf("g%d iter %d shape=%s: encrypt: %w", w.id, iter, shape, err)
		}
		w.nanosEnc.Add(time.Since(encStart).Nanoseconds())
		decStart := time.Now()
		out, err := r.msgPipe.DecryptMessage(wire)
		if err != nil {
			return fmt.Errorf("g%d iter %d shape=%s: decrypt: %w", w.id, iter, shape, err)
		}
		w.nanosDec.Add(time.Since(decStart).Nanoseconds())
		got = out
	}

	// Failure model. A cipher call that returns an error is a worker
	// error: it is returned to the launcher, listed in the summary,
	// and forces the FAIL verdict while the other workers finish their
	// in-flight iteration. A round-trip that returns without error but
	// with different bytes is a data mismatch: the process terminates
	// here, without summary or cleanup, because the Pipeline state
	// that produced the wrong bytes is the evidence and nothing that
	// runs afterwards may touch it.
	if !bytes.Equal(w.plaintext, got) {
		off := firstDifference(w.plaintext, got)
		fmt.Fprintf(os.Stderr,
			"loop: DATA MISMATCH g%d iter %d shape=%s: want %d bytes, got %d bytes, first difference at offset %d: want %s got %s\n",
			w.id, iter, shape, len(w.plaintext), len(got), off,
			hexWindow(w.plaintext, off), hexWindow(got, off))
		os.Exit(3)
	}

	w.iters.Add(1)
	w.bytesEnc.Add(int64(len(w.plaintext)))
	w.bytesDec.Add(int64(len(got)))
	return nil
}

// firstDifference returns the first offset at which a and b differ;
// the shorter length when one is a prefix of the other.
func firstDifference(a, b []byte) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// hexWindow renders up to 16 bytes of buf from off as lowercase hex,
// or "-" when buf has no bytes there.
func hexWindow(buf []byte, off int) string {
	if off >= len(buf) {
		return "-"
	}
	end := min(off+16, len(buf))
	return hex.EncodeToString(buf[off:end])
}
