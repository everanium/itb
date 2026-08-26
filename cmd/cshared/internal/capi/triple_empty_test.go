package capi

import (
	"testing"

	"github.com/everanium/itb/triple"
)

// tripleEmptyPair Init/Opens a sender + receiver handle pair on the
// given profile with default opts (full stack: parallax on + wrapper
// on) and registers cleanup. Shared by the empty-payload tests below.
func tripleEmptyPair(t *testing.T, profile string) (TripleHandleID, TripleHandleID) {
	t.Helper()
	blobBuf := make([]byte, 1<<15)
	sID, blobLen, st := TripleInit(profile, "", blobBuf)
	if st != StatusOK {
		t.Fatalf("TripleInit: %v", st)
	}
	t.Cleanup(func() { FreeTriple(sID) })
	rID, st := TripleOpen(profile, blobBuf[:blobLen], "")
	if st != StatusOK {
		t.Fatalf("TripleOpen: %v", st)
	}
	t.Cleanup(func() { FreeTriple(rID) })
	return sID, rID
}

// TestTripleEncryptMessageEmptyPayload pins the empty-payload wire
// contract on the FFI Single Message surface: for both Single Message
// profiles the wire is non-empty (the shipped profiles engage the
// wrapper layer, so at minimum the outer cipher nonce is on the wire)
// and decrypts back to an empty plaintext.
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
			if st != StatusOK {
				t.Fatalf("TripleEncryptMessage: %v", st)
			}
			if wLen == 0 {
				t.Fatalf("empty payload produced an empty wire; want the outer cipher envelope")
			}
			ptOut := make([]byte, 1024)
			pLen, st := TripleDecryptMessage(rID, wireBuf[:wLen], ptOut)
			if st != StatusOK {
				t.Fatalf("TripleDecryptMessage: %v", st)
			}
			if pLen != 0 {
				t.Fatalf("recovered non-empty plaintext: len=%d", pLen)
			}
		})
	}
}

// TestTripleEncryptStreamEmptyPayload is the Streaming counterpart of
// [TestTripleEncryptMessageEmptyPayload]: the whole-buffer FFI stream
// entries emit a non-empty wire for an empty input on both Streaming
// profiles and decrypt back to an empty plaintext.
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
			if st != StatusOK {
				t.Fatalf("TripleEncryptStream: %v", st)
			}
			if wLen == 0 {
				t.Fatalf("empty payload produced an empty wire; want the outer cipher envelope")
			}
			ptOut := make([]byte, 1024)
			pLen, st := TripleDecryptStream(rID, wireBuf[:wLen], ptOut)
			if st != StatusOK {
				t.Fatalf("TripleDecryptStream: %v", st)
			}
			if pLen != 0 {
				t.Fatalf("recovered non-empty plaintext: len=%d", pLen)
			}
		})
	}
}

// TestTripleStreamSessionEmptyPayload drives the incremental session
// surface (Begin → End → Read, no Write at all) on both Streaming
// profiles and asserts the same contract: the drained wire is
// non-empty and the receive-side session decodes it back to an empty
// plaintext.
func TestTripleStreamSessionEmptyPayload(t *testing.T) {
	profiles := []string{
		triple.ProfileStreamingAEADTripleMACV1,
		triple.ProfileStreamingNoAEADTripleV1,
	}
	for _, prof := range profiles {
		t.Run(prof, func(t *testing.T) {
			sID, rID := tripleEmptyPair(t, prof)

			encID, st := TripleEncryptStreamBegin(sID)
			if st != StatusOK {
				t.Fatalf("TripleEncryptStreamBegin: %v", st)
			}
			defer TripleStreamFree(encID)
			if st := TripleStreamEnd(encID); st != StatusOK {
				t.Fatalf("TripleStreamEnd: %v", st)
			}
			var wire []byte
			buf := make([]byte, 64<<10)
			for {
				n, fin, st := TripleStreamRead(encID, buf)
				if st != StatusOK {
					t.Fatalf("TripleStreamRead: %v", st)
				}
				wire = append(wire, buf[:n]...)
				if fin {
					break
				}
			}
			if len(wire) == 0 {
				t.Fatalf("empty session produced an empty wire; want the outer cipher envelope")
			}

			decID, st := TripleDecryptStreamBegin(rID)
			if st != StatusOK {
				t.Fatalf("TripleDecryptStreamBegin: %v", st)
			}
			defer TripleStreamFree(decID)
			if st := TripleStreamWrite(decID, wire); st != StatusOK {
				t.Fatalf("TripleStreamWrite: %v", st)
			}
			if st := TripleStreamEnd(decID); st != StatusOK {
				t.Fatalf("TripleStreamEnd: %v", st)
			}
			var plain []byte
			for {
				n, fin, st := TripleStreamRead(decID, buf)
				if st != StatusOK {
					t.Fatalf("TripleStreamRead (decrypt): %v", st)
				}
				plain = append(plain, buf[:n]...)
				if fin {
					break
				}
			}
			if len(plain) != 0 {
				t.Fatalf("recovered non-empty plaintext: len=%d", len(plain))
			}
		})
	}
}
