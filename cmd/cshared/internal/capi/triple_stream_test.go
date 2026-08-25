package capi

import (
	"bytes"
	"sync"
	"testing"

	"github.com/everanium/itb/triple"
)

// tripleStreamRoundTrip is the shared feed-and-drain harness across
// the incremental stream tests: opens both sides on the given
// profile, pumps plain through the encrypt session in feedChunk
// bytes at a time (with a companion drain into wire between feeds),
// then pumps wire through the decrypt session in drainChunk bytes at
// a time and returns the recovered plaintext.
func tripleStreamRoundTrip(t *testing.T, profile string, plain []byte, feedChunk, drainChunk int) []byte {
	t.Helper()
	blob := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(profile, "", blob)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v", st)
	}
	defer FreeTriple(sID)

	rID, st := TripleOpen(profile, blob[:blobLen], "")
	if st != StatusOK {
		t.Fatalf("TripleOpen: %v", st)
	}
	defer FreeTriple(rID)

	encID, st := TripleEncryptStreamBegin(sID)
	if st != StatusOK {
		t.Fatalf("TripleEncryptStreamBegin: %v", st)
	}
	defer TripleStreamFree(encID)

	var wireOut bytes.Buffer
	drainBuf := make([]byte, drainChunk)
	drain := func(session TripleStreamID, dst *bytes.Buffer) bool {
		n, fin, st := TripleStreamRead(session, drainBuf)
		if st != StatusOK {
			t.Fatalf("TripleStreamRead: %v", st)
		}
		dst.Write(drainBuf[:n])
		return fin
	}

	for off := 0; off < len(plain); off += feedChunk {
		end := off + feedChunk
		if end > len(plain) {
			end = len(plain)
		}
		if st := TripleStreamWrite(encID, plain[off:end]); st != StatusOK {
			t.Fatalf("TripleStreamWrite at off=%d: %v", off, st)
		}
		drain(encID, &wireOut)
	}
	if st := TripleStreamEnd(encID); st != StatusOK {
		t.Fatalf("TripleStreamEnd: %v", st)
	}
	for {
		if drain(encID, &wireOut) {
			break
		}
	}

	decID, st := TripleDecryptStreamBegin(rID)
	if st != StatusOK {
		t.Fatalf("TripleDecryptStreamBegin: %v", st)
	}
	defer TripleStreamFree(decID)

	var plainOut bytes.Buffer
	wire := wireOut.Bytes()
	for off := 0; off < len(wire); off += feedChunk {
		end := off + feedChunk
		if end > len(wire) {
			end = len(wire)
		}
		if st := TripleStreamWrite(decID, wire[off:end]); st != StatusOK {
			t.Fatalf("TripleStreamWrite (decrypt) at off=%d: %v", off, st)
		}
		drain(decID, &plainOut)
	}
	if st := TripleStreamEnd(decID); st != StatusOK {
		t.Fatalf("TripleStreamEnd (decrypt): %v", st)
	}
	for {
		if drain(decID, &plainOut) {
			break
		}
	}
	return plainOut.Bytes()
}

// TestTripleStreamPumpRoundTrip covers the six-export stream-pump
// surface end-to-end: Begin (encrypt) → Write chunks → drain
// interleaved Reads → End → drain to finished → Begin (decrypt) →
// pump wire → drain to recovered plaintext. Runs across every
// cipher-bearing shipped profile with default opts.
func TestTripleStreamPumpRoundTrip(t *testing.T) {
	profiles := []string{
		triple.ProfileStreamingAEADTripleMACV1,
		triple.ProfileStreamingNoAEADTripleV1,
	}
	for _, prof := range profiles {
		t.Run(prof, func(t *testing.T) {
			pt := triplePlaintext(t, 32*1024)
			got := tripleStreamRoundTrip(t, prof, pt, 4096, 8192)
			if !bytes.Equal(got, pt) {
				t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(pt))
			}
		})
	}
}

// TestTripleStreamPumpTinyChunks confirms the pump copes with
// pathologically small feed / drain increments — the spool and the
// io.Pipe scheduling both have to keep up regardless of caller
// batch size.
func TestTripleStreamPumpTinyChunks(t *testing.T) {
	pt := triplePlaintext(t, 3000)
	got := tripleStreamRoundTrip(t, triple.ProfileStreamingAEADTripleMACV1, pt, 17, 23)
	if !bytes.Equal(got, pt) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d bytes", len(got), len(pt))
	}
}

// TestTripleStreamPumpEmptyPlaintext verifies the End-drain path
// with no fed bytes — a common corner case for streaming callers
// that hit an immediate EOF on the input source.
func TestTripleStreamPumpEmptyPlaintext(t *testing.T) {
	got := tripleStreamRoundTrip(t, triple.ProfileStreamingAEADTripleMACV1, nil, 64, 64)
	if len(got) != 0 {
		t.Fatalf("recovered plaintext non-empty: %d bytes", len(got))
	}
}

// TestTripleStreamEndIdempotent asserts a second StreamEnd on the
// same session returns StatusOK without re-closing the pipe, and
// subsequent Write returns StatusBadInput.
func TestTripleStreamEndIdempotent(t *testing.T) {
	blob := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, "", blob)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v", st)
	}
	defer FreeTriple(sID)
	_ = blobLen

	encID, st := TripleEncryptStreamBegin(sID)
	if st != StatusOK {
		t.Fatalf("TripleEncryptStreamBegin: %v", st)
	}
	defer TripleStreamFree(encID)

	if st := TripleStreamWrite(encID, []byte("hello")); st != StatusOK {
		t.Fatalf("TripleStreamWrite: %v", st)
	}
	if st := TripleStreamEnd(encID); st != StatusOK {
		t.Fatalf("TripleStreamEnd: %v", st)
	}
	if st := TripleStreamEnd(encID); st != StatusOK {
		t.Fatalf("second TripleStreamEnd not idempotent: %v", st)
	}
	if st := TripleStreamWrite(encID, []byte("more")); st != StatusBadInput {
		t.Fatalf("TripleStreamWrite after End: got %v, want StatusBadInput", st)
	}

	// Drain to finished to give the goroutine a clean exit before
	// StreamFree runs; this is what a real caller would do anyway.
	buf := make([]byte, 4096)
	for {
		_, fin, st := TripleStreamRead(encID, buf)
		if st != StatusOK {
			t.Fatalf("TripleStreamRead: %v", st)
		}
		if fin {
			break
		}
	}
}

// TestTripleStreamFreeMidFlight exercises the cancellation path —
// Free called while the cipher goroutine is still running. The
// deferred inW.CloseWithError signals the chain, StreamFree waits
// for the goroutine to return, then reclaims the handle.
func TestTripleStreamFreeMidFlight(t *testing.T) {
	blob := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, "", blob)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v", st)
	}
	defer FreeTriple(sID)
	_ = blobLen

	encID, st := TripleEncryptStreamBegin(sID)
	if st != StatusOK {
		t.Fatalf("TripleEncryptStreamBegin: %v", st)
	}
	if st := TripleStreamWrite(encID, []byte("partial")); st != StatusOK {
		t.Fatalf("TripleStreamWrite: %v", st)
	}
	if st := TripleStreamFree(encID); st != StatusOK {
		t.Fatalf("TripleStreamFree mid-flight: %v", st)
	}
	if st := TripleStreamFree(encID); st != StatusBadHandle {
		t.Fatalf("second TripleStreamFree: got %v, want StatusBadHandle", st)
	}
}

// TestTripleStreamConcurrentSessions confirms multiple concurrent
// sessions over the same Pipeline handle produce independent wires
// that each decrypt cleanly on the receiver side.
func TestTripleStreamConcurrentSessions(t *testing.T) {
	blob := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, "", blob)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v", st)
	}
	defer FreeTriple(sID)
	rID, st := TripleOpen(triple.ProfileStreamingAEADTripleMACV1, blob[:blobLen], "")
	if st != StatusOK {
		t.Fatalf("TripleOpen: %v", st)
	}
	defer FreeTriple(rID)

	const streams = 4
	plains := make([][]byte, streams)
	for i := range plains {
		plains[i] = triplePlaintext(t, 6000+i*333)
	}
	wires := make([][]byte, streams)

	var encWG sync.WaitGroup
	for i := 0; i < streams; i++ {
		encWG.Add(1)
		go func(idx int) {
			defer encWG.Done()
			encID, st := TripleEncryptStreamBegin(sID)
			if st != StatusOK {
				t.Errorf("Begin[%d]: %v", idx, st)
				return
			}
			defer TripleStreamFree(encID)
			pt := plains[idx]
			for off := 0; off < len(pt); off += 512 {
				end := off + 512
				if end > len(pt) {
					end = len(pt)
				}
				if st := TripleStreamWrite(encID, pt[off:end]); st != StatusOK {
					t.Errorf("Write[%d]: %v", idx, st)
					return
				}
			}
			if st := TripleStreamEnd(encID); st != StatusOK {
				t.Errorf("End[%d]: %v", idx, st)
				return
			}
			var wire bytes.Buffer
			buf := make([]byte, 4096)
			for {
				n, fin, st := TripleStreamRead(encID, buf)
				if st != StatusOK {
					t.Errorf("Read[%d]: %v", idx, st)
					return
				}
				wire.Write(buf[:n])
				if fin {
					break
				}
			}
			wires[idx] = wire.Bytes()
		}(i)
	}
	encWG.Wait()
	if t.Failed() {
		return
	}

	for i, w := range wires {
		decID, st := TripleDecryptStreamBegin(rID)
		if st != StatusOK {
			t.Fatalf("DecryptBegin[%d]: %v", i, st)
		}
		if st := TripleStreamWrite(decID, w); st != StatusOK {
			TripleStreamFree(decID)
			t.Fatalf("DecryptWrite[%d]: %v", i, st)
		}
		if st := TripleStreamEnd(decID); st != StatusOK {
			TripleStreamFree(decID)
			t.Fatalf("DecryptEnd[%d]: %v", i, st)
		}
		var out bytes.Buffer
		buf := make([]byte, 4096)
		for {
			n, fin, st := TripleStreamRead(decID, buf)
			if st != StatusOK {
				TripleStreamFree(decID)
				t.Fatalf("DecryptRead[%d]: %v", i, st)
			}
			out.Write(buf[:n])
			if fin {
				break
			}
		}
		TripleStreamFree(decID)
		if !bytes.Equal(out.Bytes(), plains[i]) {
			t.Fatalf("stream %d decrypt mismatch: got %d bytes, want %d", i, out.Len(), len(plains[i]))
		}
	}
}

// TestTripleStreamStickyError tampers the wire so the decrypt
// pipeline emits a MAC failure mid-drain, then verifies the mapped
// error surfaces from Read and remains sticky across subsequent
// Read calls.
func TestTripleStreamStickyError(t *testing.T) {
	prof := triple.ProfileStreamingAEADTripleMACV1
	blob := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(prof, "", blob)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v", st)
	}
	defer FreeTriple(sID)
	rID, st := TripleOpen(prof, blob[:blobLen], "")
	if st != StatusOK {
		t.Fatalf("TripleOpen: %v", st)
	}
	defer FreeTriple(rID)

	pt := triplePlaintext(t, 4096)
	wireBuf := make([]byte, len(pt)+64<<10)
	wLen, st := TripleEncryptStream(sID, pt, wireBuf)
	if st != StatusOK {
		t.Fatalf("TripleEncryptStream: %v", st)
	}
	// Tamper — invert every bit of the last byte so MAC verification
	// fails deterministically. A single-bit flip is not sufficient
	// here: each container byte carries seven authenticated data bits
	// plus one noise bit at a per-pixel keyed position, and noise bits
	// are discarded by decode before the MAC input is assembled — so a
	// one-bit tamper lands on the noise bit with probability ~1/8 and
	// the wire decrypts cleanly. Inverting the full byte flips all
	// seven data bits regardless of where the noise bit sits.
	wireBuf[wLen-1] ^= 0xFF

	decID, st := TripleDecryptStreamBegin(rID)
	if st != StatusOK {
		t.Fatalf("TripleDecryptStreamBegin: %v", st)
	}
	defer TripleStreamFree(decID)

	if st := TripleStreamWrite(decID, wireBuf[:wLen]); st != StatusOK {
		t.Fatalf("TripleStreamWrite (tampered): %v", st)
	}
	if st := TripleStreamEnd(decID); st != StatusOK {
		t.Fatalf("TripleStreamEnd: %v", st)
	}
	buf := make([]byte, 4096)
	var firstErr Status
	for {
		_, fin, st := TripleStreamRead(decID, buf)
		if st != StatusOK {
			firstErr = st
			break
		}
		if fin {
			t.Fatalf("Read reached finished on tampered wire without surfacing error")
		}
	}
	if firstErr == StatusOK {
		t.Fatalf("expected non-OK first error")
	}
	// Sticky — a second Read returns the same code.
	_, _, secondErr := TripleStreamRead(decID, buf)
	if secondErr != firstErr {
		t.Fatalf("sticky error mismatch: first %v, second %v", firstErr, secondErr)
	}
}

// TestTripleStreamFreeStaleHandle covers the double-Free posture
// plus the zero-id and foreign-value branches.
func TestTripleStreamFreeStaleHandle(t *testing.T) {
	if st := TripleStreamFree(0); st != StatusBadHandle {
		t.Fatalf("Free(0): got %v, want StatusBadHandle", st)
	}
	// Foreign-value branch: pass a plain SeedHandle id here — its
	// cgo.Handle resolves to *seedHandleRec, not *TripleStreamHandle,
	// so the type assertion fails and StatusBadHandle is returned.
	blob := make([]byte, 1<<15)
	sID, _, st := TripleInit(triple.ProfileStreamingAEADTripleMACV1, "", blob)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v", st)
	}
	defer FreeTriple(sID)
	if st := TripleStreamFree(TripleStreamID(sID)); st != StatusBadHandle {
		t.Fatalf("Free(foreign id): got %v, want StatusBadHandle", st)
	}
}

// TestTripleStreamWriteBadHandle + TestTripleStreamReadBadHandle +
// TestTripleStreamEndBadHandle assert the resolve path uniformly
// rejects zero and stale ids on every pump entry point.
func TestTripleStreamWriteBadHandle(t *testing.T) {
	if st := TripleStreamWrite(0, []byte("x")); st != StatusBadHandle {
		t.Fatalf("Write(0): got %v, want StatusBadHandle", st)
	}
	if st := TripleStreamEnd(0); st != StatusBadHandle {
		t.Fatalf("End(0): got %v, want StatusBadHandle", st)
	}
	if _, _, st := TripleStreamRead(0, make([]byte, 8)); st != StatusBadHandle {
		t.Fatalf("Read(0): got %v, want StatusBadHandle", st)
	}
}
