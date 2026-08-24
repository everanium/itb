package wrapper

// wrapper_race_test.go — regression coverage for the wrapper writer's
// nonce/first-body batching invariant.
//
// NewWrapWriter must emit the outer cipher's per-stream nonce and the
// first inner payload in a single atomic dst.Write call. If the nonce
// and the first body land on the destination io.Writer as two separate
// writes, a concurrent reader draining the destination between the two
// calls can consume-and-discard the nonce independently. The receiving
// side then sees a wire missing the leading nonce and NewUnwrapReader
// fails at io.ReadFull (or, in bindings that route via a spool, at the
// first stream_write with an "internal error").
//
// The tests below pin the invariant "wrapper nonce and first inner
// body are emitted as ONE atomic dst.Write call" via a recordingWriter
// (borrowed shape from stream_prefix_batch_test.go at the itb-root
// package) that captures every Write invocation's length. The first
// captured length must strictly exceed the nonce length, proving the
// nonce and the first payload were batched into one write.

import (
	"bytes"
	"crypto/rand"
	"io"
	"sync"
	"testing"
)

// wrapRecordingWriter is an io.Writer that appends every Write call's
// bytes to an internal buffer and records the length of each individual
// invocation. Lets a test assert per-Write batching invariants without
// coupling to the itb-root test-only recordingWriter.
type wrapRecordingWriter struct {
	mu    sync.Mutex
	buf   bytes.Buffer
	calls []int
}

func (w *wrapRecordingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, len(p))
	return w.buf.Write(p)
}

func (w *wrapRecordingWriter) Bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Bytes()
}

func (w *wrapRecordingWriter) Calls() []int {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]int, len(w.calls))
	copy(out, w.calls)
	return out
}

// TestWrapperNonceBodyBatching pins the wrapper writer's nonce and
// first-inner-body batching invariant across every supported outer
// cipher. The first dst.Write call must carry BOTH the nonce and the
// first inner payload, so that a concurrent drain between two separate
// writes cannot strand the nonce on its own.
func TestWrapperNonceBodyBatching(t *testing.T) {
	for _, name := range CipherNames {
		t.Run(name, func(t *testing.T) {
			key, err := GenerateKey(name)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			nlen, err := NonceSize(name)
			if err != nil {
				t.Fatalf("NonceSize: %v", err)
			}

			pt := make([]byte, 4096)
			if _, err := rand.Read(pt); err != nil {
				t.Fatalf("rand: %v", err)
			}

			var w wrapRecordingWriter
			ww, err := NewWrapWriter(name, key, &w)
			if err != nil {
				t.Fatalf("NewWrapWriter: %v", err)
			}
			if _, err := ww.Write(pt); err != nil {
				t.Fatalf("Write: %v", err)
			}

			calls := w.Calls()
			if len(calls) == 0 {
				t.Fatal("no dst.Write calls recorded")
			}
			// Batching invariant: the first dst.Write must carry the
			// nonce AND the first inner body. A first write of exactly
			// nlen bytes is the pre-fix bug (standalone nonce write).
			if calls[0] <= nlen {
				t.Fatalf("first dst.Write = %d bytes, want > %d "+
					"(nonce batched with first inner body); "+
					"per-Write breakdown: %v", calls[0], nlen, calls)
			}
			// Round-trip: the emitted wire must decode back to the
			// original plaintext through NewUnwrapReader.
			rr, err := NewUnwrapReader(name, key, bytes.NewReader(w.Bytes()))
			if err != nil {
				t.Fatalf("NewUnwrapReader: %v", err)
			}
			recovered := make([]byte, len(pt))
			if _, err := io.ReadFull(rr, recovered); err != nil {
				t.Fatalf("ReadFull: %v", err)
			}
			if !bytes.Equal(pt, recovered) {
				t.Fatalf("%s: wrapper batched-nonce round-trip mismatch", name)
			}
		})
	}
}
