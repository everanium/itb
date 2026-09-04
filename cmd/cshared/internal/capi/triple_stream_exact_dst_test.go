package capi

// triple_stream_exact_dst_test.go — regression coverage for the
// TripleStreamRead teardown-flag sync invariant.
//
// The cipher goroutine's tail runs `spool.close() → close(done)` as
// two distinct steps. Without the drained-and-closed sync on
// [TripleStreamRead], a Read that returns the last spooled bytes can
// see `finished == false` because `close(done)` has not fired yet.
// Exact-size-dst callers (dst pre-sized to the produced wire's or
// plaintext's exact length) treat "dst full and finished == false"
// as a hard error, so the teardown race manifests as a spurious
// throw on the caller side.
//
// The test below drives many back-to-back exact-size-dst encrypt /
// decrypt round-trips against ONE Pipeline session per side. Each
// iteration ends with a drain call whose dst has exactly enough
// room for the remaining bytes; every such call must return
// `finished == true` in the same round without hanging or forcing
// an additional probe Read.

import (
	"bytes"
	"testing"

	"github.com/everanium/itb/triple"
)

// TestTripleStreamExactDstFinishedFlag pins the teardown-flag sync
// invariant end-to-end via TripleStreamWrite / TripleStreamRead. Runs
// many back-to-back decrypt round-trips against ONE Pipeline session
// with dst pre-sized to the exact plaintext length; every finalising
// Read must report finished == true in the same call rather than
// lagging behind the cipher goroutine's teardown.
func TestTripleStreamExactDstFinishedFlag(t *testing.T) {
	const iterations = 100
	const size = 4096

	blob := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(triple.ProfileStreamingNoAEADTripleV1, "", blob)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v", st)
	}
	defer FreeTriple(sID)

	rID, st := TripleLoad(blob[:blobLen])
	if st != StatusOK {
		t.Fatalf("TripleLoad: %v", st)
	}
	defer FreeTriple(rID)

	pt := triplePlaintext(t, size)

	// One pre-encrypt to obtain a wire suitable for the decrypt loop.
	// The wire is discarded and rebuilt each iteration to keep the
	// encrypt and decrypt sides symmetrically stressed on the same
	// Pipeline pair.
	for i := 0; i < iterations; i++ {
		wire := pumpEncryptCollect(t, sID, pt)

		out := make([]byte, size)
		decID, st := TripleDecryptStreamBegin(rID)
		if st != StatusOK {
			t.Fatalf("iter %d: TripleDecryptStreamBegin: %v", i, st)
		}
		if st := TripleStreamWrite(decID, wire); st != StatusOK {
			TripleStreamFree(decID)
			t.Fatalf("iter %d: TripleStreamWrite (decrypt): %v", i, st)
		}
		if st := TripleStreamEnd(decID); st != StatusOK {
			TripleStreamFree(decID)
			t.Fatalf("iter %d: TripleStreamEnd (decrypt): %v", i, st)
		}
		decUsed, decFin := drainExact(t, decID, out)
		TripleStreamFree(decID)
		if decUsed != size {
			t.Fatalf("iter %d: decrypt drained %d bytes, want %d", i, decUsed, size)
		}
		if !decFin {
			t.Fatalf("iter %d: decrypt exact-size dst call returned finished=false; "+
				"teardown-flag sync broken", i)
		}
		if !bytes.Equal(out, pt) {
			t.Fatalf("iter %d: decrypted plaintext mismatch", i)
		}
	}
}

// pumpEncryptCollect produces the wire for one plaintext under an
// encrypt session on the given Pipeline. Drains with generous slack
// so any teardown-flag lag on the encrypt side does not confound the
// decrypt-side assertion this file targets.
func pumpEncryptCollect(t *testing.T, sID TripleHandleID, pt []byte) []byte {
	t.Helper()
	encID, st := TripleEncryptStreamBegin(sID)
	if st != StatusOK {
		t.Fatalf("pumpEncryptCollect: TripleEncryptStreamBegin: %v", st)
	}
	defer TripleStreamFree(encID)
	if st := TripleStreamWrite(encID, pt); st != StatusOK {
		t.Fatalf("pumpEncryptCollect: TripleStreamWrite: %v", st)
	}
	if st := TripleStreamEnd(encID); st != StatusOK {
		t.Fatalf("pumpEncryptCollect: TripleStreamEnd: %v", st)
	}
	scratch := make([]byte, 64<<10)
	used := 0
	for {
		n, fin, st := TripleStreamRead(encID, scratch[used:])
		if st != StatusOK {
			t.Fatalf("pumpEncryptCollect: TripleStreamRead: %v", st)
		}
		used += n
		if fin {
			break
		}
		if used == len(scratch) {
			doubled := make([]byte, len(scratch)*2)
			copy(doubled, scratch)
			scratch = doubled
		}
	}
	out := make([]byte, used)
	copy(out, scratch[:used])
	return out
}

// drainExact drains the session into dst, capping each Read at the
// remaining tail of dst. Returns the total bytes drained and the
// finished flag returned by the final Read. If the final Read
// consumed the full remaining tail without seeing finished == true,
// returns (used, false) — that is the exact regression the sync
// closes.
func drainExact(t *testing.T, id TripleStreamID, dst []byte) (int, bool) {
	t.Helper()
	used := 0
	for used < len(dst) {
		n, fin, st := TripleStreamRead(id, dst[used:])
		if st != StatusOK {
			t.Fatalf("drainExact: TripleStreamRead: %v", st)
		}
		used += n
		if fin {
			return used, true
		}
		if n == 0 {
			// Would spin forever — the goroutine is either producing
			// more than dst can hold (out-of-band error for this test)
			// or the finished flag is lagging. Return with finished=false
			// so the caller test sees the invariant break.
			return used, false
		}
	}
	// dst is full; the finished flag must have arrived in the same
	// Read that consumed the last byte. If it did not, do NOT make a
	// probe call — the regression under test is exactly that lag.
	return used, false
}
