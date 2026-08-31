package capi

import (
	"errors"
	"io"
	"runtime/cgo"
	"sync"
)

// TripleStreamHandle carries a single incremental Triple encrypt or
// decrypt session across the cgo boundary. One goroutine drives the
// underlying Pipeline stream via an io.Pipe on the input side and a
// grow-on-demand spool on the output side; the FFI surface pumps
// bytes in through Write, signals end-of-input through End, and
// drains produced bytes out through Read.
//
// The direction (encrypt vs decrypt) is fixed at Begin time so a
// single Write / Read pair covers both branches — the binding does
// not need to spell it out on every call.
type TripleStreamHandle struct {
	pipeHandle *TripleHandle
	inW        *io.PipeWriter
	spool      *streamSpool
	done       chan struct{}

	mu        sync.Mutex
	err       error
	endCalled bool
	freed     bool
}

// TripleStreamID is the opaque uintptr the FFI passes as a session
// reference. Internally a runtime/cgo.Handle onto a *TripleStreamHandle.
type TripleStreamID uintptr

// resolveTripleStream returns the *TripleStreamHandle behind an
// opaque TripleStreamID, or (nil, StatusBadHandle) on a stale or
// zero handle. Mirrors resolveTriple's panic-recovery shape.
func resolveTripleStream(id TripleStreamID) (h *TripleStreamHandle, st Status) {
	if id == 0 {
		setLastErr(StatusBadHandle)
		return nil, StatusBadHandle
	}
	defer func() {
		if r := recover(); r != nil {
			setLastErr(StatusBadHandle)
			h, st = nil, StatusBadHandle
		}
	}()
	v := cgo.Handle(id).Value()
	hh, ok := v.(*TripleStreamHandle)
	if !ok || hh == nil {
		setLastErr(StatusBadHandle)
		return nil, StatusBadHandle
	}
	return hh, StatusOK
}

// errStreamCancelled is the sentinel piped through the input side
// when StreamFree closes down a session mid-flight. Never surfaces
// to the binding — the cipher goroutine sees it, records nothing
// new (StreamFree already recorded a cancellation state on the
// session), and returns.
var errStreamCancelled = errors.New("triple stream cancelled")

// TripleEncryptStreamBegin opens an incremental encrypt session over
// an already-open Pipeline handle. The returned session id is
// distinct from the Pipeline id and lives until [TripleStreamFree]
// releases it. Multiple concurrent sessions per Pipeline are
// permitted — the Pipeline's cipher path is concurrent-safe by
// construction.
func TripleEncryptStreamBegin(id TripleHandleID) (out TripleStreamID, st Status) {
	defer recoverPanic(&st, StatusInternal)
	h, st := resolveTriple(id)
	if st != StatusOK {
		return 0, st
	}
	return startTripleStream(h, true), StatusOK
}

// TripleDecryptStreamBegin is the receive-side counterpart of
// [TripleEncryptStreamBegin].
func TripleDecryptStreamBegin(id TripleHandleID) (out TripleStreamID, st Status) {
	defer recoverPanic(&st, StatusInternal)
	h, st := resolveTriple(id)
	if st != StatusOK {
		return 0, st
	}
	return startTripleStream(h, false), StatusOK
}

func startTripleStream(h *TripleHandle, encrypt bool) TripleStreamID {
	pr, pw := io.Pipe()
	sess := &TripleStreamHandle{
		pipeHandle: h,
		inW:        pw,
		spool:      newStreamSpool(),
		done:       make(chan struct{}),
	}
	go func() {
		defer func() {
			if r := recover(); r != nil {
				sess.mu.Lock()
				if sess.err == nil {
					sess.err = errors.New("triple stream: goroutine panic")
				}
				sess.mu.Unlock()
			}
			sess.mu.Lock()
			runErr := sess.err
			sess.mu.Unlock()
			// Close the pipe reader with the recorded error so any
			// pending StreamWrite on the writer end wakes up with
			// io.ErrClosedPipe (or the recorded error) rather than
			// blocking forever after the cipher goroutine returns.
			if runErr != nil {
				_ = pr.CloseWithError(runErr)
			} else {
				_ = pr.Close()
			}
			sess.spool.close()
			close(sess.done)
		}()
		var runErr error
		if encrypt {
			runErr = h.pipe.EncryptStream(pr, sess.spool)
		} else {
			runErr = h.pipe.DecryptStream(pr, sess.spool)
		}
		if runErr != nil && !errors.Is(runErr, errStreamCancelled) {
			sess.mu.Lock()
			if sess.err == nil {
				sess.err = runErr
			}
			sess.mu.Unlock()
		}
	}()
	return TripleStreamID(cgo.NewHandle(sess))
}

// TripleStreamWrite feeds src bytes into an open session. Blocks
// until the cipher chain accepts the bytes (bounded by the chain's
// chunk granularity — the spool never blocks the producer, so
// forward progress is guaranteed while the session is live). An
// empty src is a no-op returning StatusOK. Returns the mapped
// cipher-chain error if the session has already failed; the error
// is sticky.
func TripleStreamWrite(id TripleStreamID, src []byte) (st Status) {
	defer recoverPanic(&st, StatusInternal)
	sess, st := resolveTripleStream(id)
	if st != StatusOK {
		return st
	}
	sess.mu.Lock()
	if sess.err != nil {
		s := mapTripleError(sess.err)
		sess.mu.Unlock()
		setLastErr(s)
		return s
	}
	if sess.endCalled {
		sess.mu.Unlock()
		setLastErr(StatusBadInput)
		return StatusBadInput
	}
	sess.mu.Unlock()
	if len(src) == 0 {
		return StatusOK
	}
	_, werr := sess.inW.Write(src)
	if werr != nil {
		sess.mu.Lock()
		if sess.err == nil {
			sess.err = werr
		}
		e := sess.err
		sess.mu.Unlock()
		s := mapTripleError(e)
		setLastErr(s)
		return s
	}
	return StatusOK
}

// TripleStreamEnd signals end-of-input to the cipher chain. The
// terminal chunk plus any MAC / envelope finalisation flow into the
// spool and become visible to subsequent [TripleStreamRead] calls.
// Idempotent — a second End on the same session returns StatusOK
// without re-closing the pipe. After End, [TripleStreamWrite] on
// the same session returns StatusBadInput.
func TripleStreamEnd(id TripleStreamID) (st Status) {
	defer recoverPanic(&st, StatusInternal)
	sess, st := resolveTripleStream(id)
	if st != StatusOK {
		return st
	}
	sess.mu.Lock()
	if sess.endCalled {
		sess.mu.Unlock()
		return StatusOK
	}
	sess.endCalled = true
	sess.mu.Unlock()
	_ = sess.inW.Close()
	return StatusOK
}

// TripleStreamRead drains up to len(dst) produced bytes into dst.
// The (n, finished) pair encodes drain state: finished == 1 once
// the session has ended AND the spool is fully drained; 0
// otherwise. Never returns StatusBufferTooSmall — partial drains
// are the normal mode; remaining bytes stay spooled. After End,
// a Read with an empty spool blocks until the terminal bytes
// arrive or the session errors, so the drain loop never busy-spins.
// The mapped cipher-chain error becomes sticky once the failure
// point is reached — every subsequent Read returns the same code.
func TripleStreamRead(id TripleStreamID, dst []byte) (n int, finished bool, st Status) {
	defer recoverPanic(&st, StatusInternal)
	sess, st := resolveTripleStream(id)
	if st != StatusOK {
		return 0, false, st
	}
	if len(dst) == 0 {
		sess.mu.Lock()
		if sess.err != nil {
			e := sess.err
			sess.mu.Unlock()
			s := mapTripleError(e)
			setLastErr(s)
			return 0, false, s
		}
		done := sess.endCalled && sess.spool.empty() && sess.isDone()
		sess.mu.Unlock()
		return 0, done, StatusOK
	}
	sess.mu.Lock()
	endedFlag := sess.endCalled
	sess.mu.Unlock()
	got, drained := sess.spool.read(dst, endedFlag)
	// If end-of-input has been signalled and we consumed the spool's
	// currently-visible bytes, sync with the cipher goroutine's
	// close(done) teardown step so `finished` accurately reflects
	// reality. The goroutine's tail runs
	// `spool.close() → close(done)` as two distinct steps, and even
	// before spool.close() there is a bounded window between the
	// final produced byte and the goroutine's return: without this
	// sync, a Read that consumed the last spooled bytes can see
	// `isDone() == false` because `close(done)` has not fired yet,
	// forcing an exact-size-dst caller to issue an extra probe Read
	// (or throw) to pick up the lagging finished flag.
	//
	// The wait is bounded to a single trailing chunk's compute +
	// teardown time — once endCalled is true the goroutine is on its
	// exit path. Waiting is skipped while endCalled is false (a
	// mid-stream drain of an open spool must not block on teardown
	// that has not started); it is also skipped when the drain
	// returned drained == false (the spool still holds bytes, so the
	// caller loops for another Read without any teardown to sync).
	//
	// After the wait, the spool may have gained more bytes (the
	// goroutine could have produced its final chunk while we were
	// blocked). Re-check emptiness before reporting finished so the
	// caller does not treat a mid-stream drain as end-of-stream and
	// drop bytes that are still in the spool.
	if drained && endedFlag {
		<-sess.done
	}
	sess.mu.Lock()
	if sess.err != nil {
		e := sess.err
		sess.mu.Unlock()
		s := mapTripleError(e)
		setLastErr(s)
		return got, false, s
	}
	fin := sess.endCalled && drained && sess.spool.empty() && sess.isDone()
	sess.mu.Unlock()
	return got, fin, StatusOK
}

// TripleStreamFree cancels the session (if still running) and
// releases the cgo.Handle. Safe to call from any state — mid-flight,
// mid-error, or after a clean drain. Wipes the spool. A second Free
// on the same id returns StatusBadHandle, matching the other _Free
// entries on this ABI.
func TripleStreamFree(id TripleStreamID) (st Status) {
	if id == 0 {
		setLastErr(StatusBadHandle)
		return StatusBadHandle
	}
	defer func() {
		if r := recover(); r != nil {
			setLastErr(StatusBadHandle)
			st = StatusBadHandle
		}
	}()
	v := cgo.Handle(id).Value()
	sess, ok := v.(*TripleStreamHandle)
	if !ok || sess == nil {
		setLastErr(StatusBadHandle)
		return StatusBadHandle
	}
	sess.mu.Lock()
	if sess.freed {
		sess.mu.Unlock()
		setLastErr(StatusBadHandle)
		return StatusBadHandle
	}
	sess.freed = true
	alreadyEnded := sess.endCalled
	sess.mu.Unlock()
	if !alreadyEnded {
		_ = sess.inW.CloseWithError(errStreamCancelled)
	}
	<-sess.done
	sess.spool.wipe()
	cgo.Handle(id).Delete()
	return StatusOK
}

func (sess *TripleStreamHandle) isDone() bool {
	select {
	case <-sess.done:
		return true
	default:
		return false
	}
}

// streamSpool is a grow-on-demand byte queue guarded by mutex + cond.
// The cipher goroutine writes without blocking (grow-on-demand);
// readers block on the cond until bytes arrive or the spool is
// closed. Once closed, remaining bytes drain normally and empty
// reads return with no wait so the drain loop terminates cleanly.
type streamSpool struct {
	mu     sync.Mutex
	cond   *sync.Cond
	buf    []byte
	closed bool
}

func newStreamSpool() *streamSpool {
	s := &streamSpool{}
	s.cond = sync.NewCond(&s.mu)
	return s
}

// Write appends bytes to the spool. Never blocks — the cipher path
// depends on this to make forward progress against a slow reader.
func (s *streamSpool) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.mu.Lock()
	s.buf = append(s.buf, p...)
	s.cond.Broadcast()
	s.mu.Unlock()
	return len(p), nil
}

// read drains up to len(dst) bytes into dst. When wait is true and
// the spool is empty and still open, blocks on cond until bytes
// arrive or the spool closes; the cipher goroutine calls close on
// return, which wakes every reader so the drain loop terminates
// cleanly. When wait is false, returns immediately with whatever is
// currently spooled (possibly zero bytes). Returns the number of
// bytes copied and whether the spool is now empty.
func (s *streamSpool) read(dst []byte, wait bool) (n int, drained bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if wait {
		for len(s.buf) == 0 && !s.closed {
			s.cond.Wait()
		}
	}
	n = copy(dst, s.buf)
	s.buf = s.buf[n:]
	drained = len(s.buf) == 0
	return n, drained
}

func (s *streamSpool) empty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buf) == 0
}

func (s *streamSpool) close() {
	s.mu.Lock()
	s.closed = true
	s.cond.Broadcast()
	s.mu.Unlock()
}

// wipe zeroes the spooled bytes and drops the underlying buffer so
// key-adjacent plaintext / wire fragments do not linger on the heap
// after StreamFree.
func (s *streamSpool) wipe() {
	s.mu.Lock()
	for i := range s.buf {
		s.buf[i] = 0
	}
	s.buf = nil
	s.mu.Unlock()
}
