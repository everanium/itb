package capi

import (
	"testing"

	"github.com/everanium/itb/triple"
)

// tripleEmptyPair Init/Opens a sender + receiver handle pair on the
// given profile with default opts (full stack: parallax on + wrapper
// on) and registers cleanup. Shared by the empty-input tests below.
func tripleEmptyPair(t *testing.T, profile string) (TripleHandleID, TripleHandleID) {
	t.Helper()
	blobBuf := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(profile, "", blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v", st)
	}
	t.Cleanup(func() { FreeTriple(sID) })
	rID, st := TripleLoad(blobBuf[:blobLen])
	if st != StatusOK {
		t.Fatalf("TripleLoad: %v", st)
	}
	t.Cleanup(func() { FreeTriple(rID) })
	return sID, rID
}

// TestTripleEncryptMessageEmptyPayload pins the empty-input rejection
// contract on the FFI Single Message surface: for both Single Message
// profiles an empty plaintext (encrypt side) and an empty wire
// (decrypt side) are rejected with StatusBadInput — the mapping of
// [triple.ErrEmptyInput] — and no wire bytes are reported.
func TestTripleEncryptMessageEmptyPayload(t *testing.T) {
	profiles := []string{
		triple.ProfileSingleMsgTripleMACV1,
		triple.ProfileSingleMsgTripleNoMACV1,
	}
	for _, prof := range profiles {
		t.Run(prof, func(t *testing.T) {
			sID, rID := tripleEmptyPair(t, prof)

			wireBuf := make([]byte, 64<<10)
			wLen, st := TripleEncryptMessage(sID, nil, wireBuf)
			if st != StatusBadInput {
				t.Fatalf("TripleEncryptMessage(empty): got %v, want %v", st, StatusBadInput)
			}
			if wLen != 0 {
				t.Fatalf("TripleEncryptMessage(empty): reported %d wire bytes; want 0", wLen)
			}
			ptOut := make([]byte, 1024)
			pLen, st := TripleDecryptMessage(rID, nil, ptOut)
			if st != StatusBadInput {
				t.Fatalf("TripleDecryptMessage(empty): got %v, want %v", st, StatusBadInput)
			}
			if pLen != 0 {
				t.Fatalf("TripleDecryptMessage(empty): reported %d plaintext bytes; want 0", pLen)
			}
		})
	}
}

// TestTripleEncryptStreamEmptyPayload is the Streaming counterpart of
// [TestTripleEncryptMessageEmptyPayload]: the whole-buffer FFI stream
// entries reject empty input with StatusBadInput on both Streaming
// profiles, symmetric across encrypt and decrypt.
func TestTripleEncryptStreamEmptyPayload(t *testing.T) {
	profiles := []string{
		triple.ProfileStreamingAEADTripleMACV1,
		triple.ProfileStreamingNoAEADTripleV1,
	}
	for _, prof := range profiles {
		t.Run(prof, func(t *testing.T) {
			sID, rID := tripleEmptyPair(t, prof)

			wireBuf := make([]byte, 64<<10)
			wLen, st := TripleEncryptStream(sID, nil, wireBuf)
			if st != StatusBadInput {
				t.Fatalf("TripleEncryptStream(empty): got %v, want %v", st, StatusBadInput)
			}
			if wLen != 0 {
				t.Fatalf("TripleEncryptStream(empty): reported %d wire bytes; want 0", wLen)
			}
			ptOut := make([]byte, 1024)
			pLen, st := TripleDecryptStream(rID, nil, ptOut)
			if st != StatusBadInput {
				t.Fatalf("TripleDecryptStream(empty): got %v, want %v", st, StatusBadInput)
			}
			if pLen != 0 {
				t.Fatalf("TripleDecryptStream(empty): reported %d plaintext bytes; want 0", pLen)
			}
		})
	}
}

// TestTripleStreamSessionEmptyPayload drives the incremental session
// surface (Begin → End → Read, no Write at all) on both Streaming
// profiles and asserts the same contract: the underlying Pipeline
// rejects the empty stream with [triple.ErrEmptyInput], which
// surfaces on the drain as the sticky StatusBadInput — no wire byte
// is ever produced. Symmetric on the decrypt session.
func TestTripleStreamSessionEmptyPayload(t *testing.T) {
	profiles := []string{
		triple.ProfileStreamingAEADTripleMACV1,
		triple.ProfileStreamingNoAEADTripleV1,
	}
	for _, prof := range profiles {
		t.Run(prof, func(t *testing.T) {
			sID, rID := tripleEmptyPair(t, prof)

			for _, dir := range []struct {
				name  string
				id    TripleHandleID
				begin func(TripleHandleID) (TripleStreamID, Status)
			}{
				{"encrypt", sID, TripleEncryptStreamBegin},
				{"decrypt", rID, TripleDecryptStreamBegin},
			} {
				sessID, st := dir.begin(dir.id)
				if st != StatusOK {
					t.Fatalf("%s Begin: %v", dir.name, st)
				}
				if st := TripleStreamEnd(sessID); st != StatusOK {
					t.Fatalf("%s TripleStreamEnd: %v", dir.name, st)
				}
				buf := make([]byte, 4096)
				var got int
				var readSt Status
				for {
					n, fin, st := TripleStreamRead(sessID, buf)
					got += n
					readSt = st
					if st != StatusOK || fin {
						break
					}
				}
				if readSt != StatusBadInput {
					t.Fatalf("%s drain after empty End: got %v, want %v",
						dir.name, readSt, StatusBadInput)
				}
				if got != 0 {
					t.Fatalf("%s drain after empty End produced %d bytes; want 0",
						dir.name, got)
				}
				if st := TripleStreamFree(sessID); st != StatusOK {
					t.Fatalf("%s TripleStreamFree: %v", dir.name, st)
				}
			}
		})
	}
}
