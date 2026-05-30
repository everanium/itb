package parallax

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	mrand "math/rand/v2"
	"strings"
	"testing"

	"github.com/everanium/itb/ctr"
)

// streamPaletteCases enumerates representative palette shapes the
// streaming round-trip suite sweeps.
var streamPaletteCases = []struct {
	label   string
	palette []string
}{
	// PRF-counter family: small-block keyed-PRF slots.
	{"prf-only", []string{ctr.CipherBLAKE3, ctr.CipherSipHash24, ctr.CipherBLAKE2s}},
	// Native-block family: AES-NI and ChaCha20 keystreams.
	{"rebuild-only", []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherAES128CTR}},
	// Mixed palette spanning both families.
	{"mixed", []string{ctr.CipherAES128CTR, ctr.CipherChaCha20, ctr.CipherBLAKE3, ctr.CipherSipHash24}},
}

// streamSizes spans sub-chunk, exact-chunk, and multi-chunk payloads
// for the round-trip sweep. A small explicit chunk size is set on the
// schedule per case so the chunk boundaries are exercised within
// reasonable test plaintext lengths.
var streamSizes = []int{
	0, 1, 16, 17, 18, 51, 100,
	17 * 9,          // multi-chunk under the test chunk size
	17 * 9 * 3,      // larger multi-chunk
	17*9*3 + 5,      // multi-chunk + partial tail
	8 * 1024,        // crosses worker threshold inside one chunk
	65*1024 + 7,     // multiple chunk-boundary crossings under the test chunk size
	1024 * 1024,     // 1 MiB
	4*1024*1024 + 3, // 4 MiB + tail
}

// testChunkSize is the chunk size every stream test pins on the
// Schedule so the chunk-boundary path is reachable at test-friendly
// plaintext lengths. The value is below every entry in streamSizes
// above 257 to force multiple chunk-boundary crossings.
const testChunkSize = 257

// mustScheduleWithChunk returns a schedule with the supplied palette
// and chunk size set on top of DefaultSegmentSize.
func mustScheduleWithChunk(t *testing.T, palette []string, chunkSize int) *Schedule {
	t.Helper()
	s, err := NewSchedule(palette, DefaultSegmentSize)
	if err != nil {
		t.Fatalf("NewSchedule: %v", err)
	}
	if err := s.SetChunkSize(chunkSize); err != nil {
		t.Fatalf("SetChunkSize: %v", err)
	}
	return s
}

func TestStreamRoundTripWriterWriter(t *testing.T) {
	master := mustMaster(t)
	for _, pp := range streamPaletteCases {
		for _, n := range streamSizes {
			t.Run(pp.label+"/n"+itoa(n), func(t *testing.T) {
				s := mustScheduleWithChunk(t, pp.palette, testChunkSize)
				cs := mustCipherset(t, master, s)
				pt := randomPlaintext(t, n)

				wireBuf := &bytes.Buffer{}
				enc, err := s.NewEncryptWriter(cs, wireBuf)
				if err != nil {
					t.Fatalf("NewEncryptWriter: %v", err)
				}
				if err := writeInChunks(enc, pt); err != nil {
					t.Fatalf("write plaintext: %v", err)
				}
				if err := enc.Close(); err != nil {
					t.Fatalf("close encrypt writer: %v", err)
				}

				ptBuf := &bytes.Buffer{}
				dec, err := s.NewDecryptWriter(cs, ptBuf)
				if err != nil {
					t.Fatalf("NewDecryptWriter: %v", err)
				}
				if err := writeInChunks(dec, wireBuf.Bytes()); err != nil {
					t.Fatalf("write wire: %v", err)
				}
				if err := dec.Close(); err != nil {
					t.Fatalf("close decrypt writer: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("round-trip mismatch (size=%d)", n)
				}
			})
		}
	}
}

func TestStreamRoundTripReaderReader(t *testing.T) {
	master := mustMaster(t)
	for _, pp := range streamPaletteCases {
		for _, n := range streamSizes {
			t.Run(pp.label+"/n"+itoa(n), func(t *testing.T) {
				s := mustScheduleWithChunk(t, pp.palette, testChunkSize)
				cs := mustCipherset(t, master, s)
				pt := randomPlaintext(t, n)

				encReader, err := s.NewEncryptReader(cs, bytes.NewReader(pt))
				if err != nil {
					t.Fatalf("NewEncryptReader: %v", err)
				}
				wire, err := io.ReadAll(encReader)
				if err != nil {
					t.Fatalf("read wire: %v", err)
				}
				decReader, err := s.NewDecryptReader(cs, bytes.NewReader(wire))
				if err != nil {
					t.Fatalf("NewDecryptReader: %v", err)
				}
				got, err := io.ReadAll(decReader)
				if err != nil {
					t.Fatalf("read plaintext: %v", err)
				}
				if !bytes.Equal(pt, got) {
					t.Fatalf("round-trip mismatch (size=%d)", n)
				}
			})
		}
	}
}

func TestStreamRoundTripCrossShapes(t *testing.T) {
	master := mustMaster(t)
	pp := streamPaletteCases[2] // mixed
	for _, n := range []int{1, 17, 100, 1024, 65*1024 + 7} {
		t.Run("ER/DW/n"+itoa(n), func(t *testing.T) {
			s := mustScheduleWithChunk(t, pp.palette, testChunkSize)
			cs := mustCipherset(t, master, s)
			pt := randomPlaintext(t, n)

			encReader, err := s.NewEncryptReader(cs, bytes.NewReader(pt))
			if err != nil {
				t.Fatalf("NewEncryptReader: %v", err)
			}
			wire, err := io.ReadAll(encReader)
			if err != nil {
				t.Fatalf("read wire: %v", err)
			}
			ptBuf := &bytes.Buffer{}
			dec, err := s.NewDecryptWriter(cs, ptBuf)
			if err != nil {
				t.Fatalf("NewDecryptWriter: %v", err)
			}
			if err := writeInChunks(dec, wire); err != nil {
				t.Fatalf("write wire: %v", err)
			}
			if err := dec.Close(); err != nil {
				t.Fatalf("close dec: %v", err)
			}
			if !bytes.Equal(pt, ptBuf.Bytes()) {
				t.Fatalf("ER+DW round-trip mismatch (size=%d)", n)
			}
		})
		t.Run("EW/DR/n"+itoa(n), func(t *testing.T) {
			s := mustScheduleWithChunk(t, pp.palette, testChunkSize)
			cs := mustCipherset(t, master, s)
			pt := randomPlaintext(t, n)

			wireBuf := &bytes.Buffer{}
			enc, err := s.NewEncryptWriter(cs, wireBuf)
			if err != nil {
				t.Fatalf("NewEncryptWriter: %v", err)
			}
			if err := writeInChunks(enc, pt); err != nil {
				t.Fatalf("write plaintext: %v", err)
			}
			if err := enc.Close(); err != nil {
				t.Fatalf("close enc: %v", err)
			}
			decReader, err := s.NewDecryptReader(cs, bytes.NewReader(wireBuf.Bytes()))
			if err != nil {
				t.Fatalf("NewDecryptReader: %v", err)
			}
			got, err := io.ReadAll(decReader)
			if err != nil {
				t.Fatalf("read plaintext: %v", err)
			}
			if !bytes.Equal(pt, got) {
				t.Fatalf("EW+DR round-trip mismatch (size=%d)", n)
			}
		})
	}
}

// TestStreamCloseRequired confirms that omitting Close on the writer
// path with a plaintext that has a pending partial chunk leaves the
// trailing data unflushed.
func TestStreamCloseRequired(t *testing.T) {
	s := mustScheduleWithChunk(t, streamPaletteCases[2].palette, testChunkSize)
	cs := mustCipherset(t, mustMaster(t), s)
	pt := randomPlaintext(t, testChunkSize*3+5) // tail of 5 bytes

	wireBuf := &bytes.Buffer{}
	ew, err := s.NewEncryptWriter(cs, wireBuf)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := ew.Write(pt); err != nil {
		t.Fatalf("Write: %v", err)
	}
	preCloseLen := wireBuf.Len()
	// Then close and confirm the tail lands.
	if err := ew.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if wireBuf.Len() <= preCloseLen {
		t.Fatalf("Close did not flush the pending partial chunk (pre-close=%d, post-close=%d)",
			preCloseLen, wireBuf.Len())
	}
	// Round-trip the closed wire and confirm full plaintext recovery.
	ptBuf := &bytes.Buffer{}
	dw, err := s.NewDecryptWriter(cs, ptBuf)
	if err != nil {
		t.Fatalf("NewDecryptWriter: %v", err)
	}
	if _, err := dw.Write(wireBuf.Bytes()); err != nil {
		t.Fatalf("dw.Write: %v", err)
	}
	if err := dw.Close(); err != nil {
		t.Fatalf("dw.Close: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatalf("post-close round-trip mismatch")
	}
}

// TestStreamDoubleCloseIdempotent confirms Close is safe to call more
// than once.
func TestStreamDoubleCloseIdempotent(t *testing.T) {
	s := mustScheduleWithChunk(t, streamPaletteCases[2].palette, testChunkSize)
	cs := mustCipherset(t, mustMaster(t), s)
	wireBuf := &bytes.Buffer{}
	ew, err := s.NewEncryptWriter(cs, wireBuf)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := ew.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close 1: %v", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close 2 (should be idempotent): %v", err)
	}
	// Write after Close errors.
	if _, err := ew.Write([]byte("x")); err == nil {
		t.Fatal("Write after Close returned no error")
	}
}

// TestStreamWriterEmptyClose confirms Close on a writer that received
// zero bytes flushes nothing to dst and returns nil.
func TestStreamWriterEmptyClose(t *testing.T) {
	s := mustScheduleWithChunk(t, streamPaletteCases[2].palette, testChunkSize)
	cs := mustCipherset(t, mustMaster(t), s)
	wireBuf := &bytes.Buffer{}
	ew, err := s.NewEncryptWriter(cs, wireBuf)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := wireBuf.Len(); got != 0 {
		t.Fatalf("empty-close wire length: got %d want 0", got)
	}
	// Decrypt-Writer round-trips an empty wire as empty plaintext.
	ptBuf := &bytes.Buffer{}
	dw, err := s.NewDecryptWriter(cs, ptBuf)
	if err != nil {
		t.Fatalf("NewDecryptWriter: %v", err)
	}
	if err := dw.Close(); err != nil {
		t.Fatalf("dw.Close: %v", err)
	}
	if ptBuf.Len() != 0 {
		t.Fatalf("Decrypt of empty wire produced %d bytes, want 0", ptBuf.Len())
	}
}

// TestStreamReadFullConsumer pins behaviour against io.ReadFull, which
// strictly enforces n == len(p) || error.
func TestStreamReadFullConsumer(t *testing.T) {
	s := mustScheduleWithChunk(t, streamPaletteCases[2].palette, testChunkSize)
	cs := mustCipherset(t, mustMaster(t), s)
	pt := randomPlaintext(t, testChunkSize*5+3)

	encReader, err := s.NewEncryptReader(cs, bytes.NewReader(pt))
	if err != nil {
		t.Fatalf("NewEncryptReader: %v", err)
	}
	wire, err := io.ReadAll(encReader)
	if err != nil {
		t.Fatalf("ReadAll wire: %v", err)
	}
	// The next read must signal EOF.
	one := make([]byte, 1)
	if n, err := encReader.Read(one); err != io.EOF || n != 0 {
		t.Fatalf("post-EOF Read: n=%d err=%v want 0/EOF", n, err)
	}

	decReader, err := s.NewDecryptReader(cs, bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	got := make([]byte, len(pt))
	if _, err := io.ReadFull(decReader, got); err != nil {
		t.Fatalf("ReadFull pt: %v", err)
	}
	if !bytes.Equal(pt, got) {
		t.Fatalf("ReadFull round-trip mismatch")
	}
	if n, err := decReader.Read(one); err != io.EOF || n != 0 {
		t.Fatalf("post-EOF Read on decrypt: n=%d err=%v want 0/EOF", n, err)
	}
}

// TestStreamWriterTinyWrites stresses the accumulator with many
// 1-byte Write calls, the worst case for per-Write overhead.
func TestStreamWriterTinyWrites(t *testing.T) {
	s := mustScheduleWithChunk(t, streamPaletteCases[2].palette, testChunkSize)
	cs := mustCipherset(t, mustMaster(t), s)
	pt := randomPlaintext(t, 1024)

	wireBuf := &bytes.Buffer{}
	ew, err := s.NewEncryptWriter(cs, wireBuf)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	for i := 0; i < len(pt); i++ {
		if _, err := ew.Write(pt[i : i+1]); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ptBuf := &bytes.Buffer{}
	dw, err := s.NewDecryptWriter(cs, ptBuf)
	if err != nil {
		t.Fatalf("NewDecryptWriter: %v", err)
	}
	if _, err := dw.Write(wireBuf.Bytes()); err != nil {
		t.Fatalf("dw.Write: %v", err)
	}
	if err := dw.Close(); err != nil {
		t.Fatalf("dw.Close: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatalf("tiny-Write round-trip mismatch")
	}
}

// TestStreamReaderTinyReads stresses the reader with 1-byte Read
// targets, exercising the per-frame serve loop on each.
func TestStreamReaderTinyReads(t *testing.T) {
	s := mustScheduleWithChunk(t, streamPaletteCases[2].palette, testChunkSize)
	cs := mustCipherset(t, mustMaster(t), s)
	pt := randomPlaintext(t, 1024)

	encReader, err := s.NewEncryptReader(cs, bytes.NewReader(pt))
	if err != nil {
		t.Fatalf("NewEncryptReader: %v", err)
	}
	wire := make([]byte, 0, 4096)
	one := make([]byte, 1)
	for {
		n, err := encReader.Read(one)
		if n > 0 {
			wire = append(wire, one[0])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	decReader, err := s.NewDecryptReader(cs, bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	got, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(pt, got) {
		t.Fatalf("tiny-Read round-trip mismatch")
	}
}

// TestStreamLargePlaintextMultiMiB round-trips a multi-MiB plaintext
// over randomly-sized Write chunks against the default 16 MiB chunk
// size, exercising the per-chunk Single Message path inside the
// streaming loop without an artificial chunk-size cap.
func TestStreamLargePlaintextMultiMiB(t *testing.T) {
	if testing.Short() {
		t.Skip("multi-MiB test skipped in -short mode")
	}
	s := mustSchedule(t, streamPaletteCases[2].palette, DefaultSegmentSize)
	cs := mustCipherset(t, mustMaster(t), s)
	pt := make([]byte, 4*1024*1024+97)
	if _, err := rand.Read(pt); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	wireBuf := &bytes.Buffer{}
	ew, err := s.NewEncryptWriter(cs, wireBuf)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	// Randomly-sized chunks 1..64KiB.
	rng := mrand.New(mrand.NewPCG(7, 13))
	cursor := 0
	for cursor < len(pt) {
		n := 1 + rng.IntN(64*1024)
		if cursor+n > len(pt) {
			n = len(pt) - cursor
		}
		if _, err := ew.Write(pt[cursor : cursor+n]); err != nil {
			t.Fatalf("Write: %v", err)
		}
		cursor += n
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	dr, err := s.NewDecryptReader(cs, bytes.NewReader(wireBuf.Bytes()))
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(pt, got) {
		t.Fatalf("multi-MiB round-trip mismatch")
	}
}

// TestStreamNilCipherset confirms argument validation at the
// constructor surface.
func TestStreamNilCipherset(t *testing.T) {
	s := mustSchedule(t, streamPaletteCases[2].palette, DefaultSegmentSize)
	if _, err := s.NewEncryptWriter(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("NewEncryptWriter(nil cs) returned no error")
	}
	if _, err := s.NewDecryptWriter(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("NewDecryptWriter(nil cs) returned no error")
	}
	if _, err := s.NewEncryptReader(nil, bytes.NewReader(nil)); err == nil {
		t.Fatal("NewEncryptReader(nil cs) returned no error")
	}
	if _, err := s.NewDecryptReader(nil, bytes.NewReader(nil)); err == nil {
		t.Fatal("NewDecryptReader(nil cs) returned no error")
	}
}

// TestStreamDecryptWriterEmptyClose confirms Close on a DecryptWriter
// that received zero bytes returns nil and writes nothing to dst.
func TestStreamDecryptWriterEmptyClose(t *testing.T) {
	s := mustSchedule(t, streamPaletteCases[2].palette, DefaultSegmentSize)
	cs := mustCipherset(t, mustMaster(t), s)

	ptBuf := &bytes.Buffer{}
	dw, err := s.NewDecryptWriter(cs, ptBuf)
	if err != nil {
		t.Fatalf("NewDecryptWriter: %v", err)
	}
	if err := dw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if ptBuf.Len() != 0 {
		t.Fatalf("dst.Len(): got %d, want 0", ptBuf.Len())
	}
}

// TestStreamDecryptWriterMidFrameClose confirms a Close issued while
// the decrypter is mid-frame (length prefix only, or partial body)
// surfaces an error.
func TestStreamDecryptWriterMidFrameClose(t *testing.T) {
	s := mustScheduleWithChunk(t, streamPaletteCases[2].palette, testChunkSize)
	cs := mustCipherset(t, mustMaster(t), s)

	// Build a real wire then truncate it mid-frame.
	pt := randomPlaintext(t, testChunkSize*2)
	wireBuf := &bytes.Buffer{}
	ew, err := s.NewEncryptWriter(cs, wireBuf)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := ew.Write(pt); err != nil {
		t.Fatalf("ew.Write: %v", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("ew.Close: %v", err)
	}
	truncated := wireBuf.Bytes()[:wireBuf.Len()-5] // drop tail of last frame

	dw, err := s.NewDecryptWriter(cs, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("NewDecryptWriter: %v", err)
	}
	if _, err := dw.Write(truncated); err != nil {
		t.Fatalf("dw.Write: %v", err)
	}
	if err := dw.Close(); err == nil {
		t.Fatal("Close on mid-frame state returned nil, expected an error")
	}
}

// errSentinel is used by the failing-writer / failing-reader helpers.
var errSentinel = errors.New("parallax-test: sentinel io error")

// failingWriter writes the first allowedBytes bytes successfully, then
// returns errSentinel on every subsequent Write call.
type failingWriter struct {
	inner        *bytes.Buffer
	allowedBytes int
	wrote        int
	calls        int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	w.calls++
	room := w.allowedBytes - w.wrote
	if room <= 0 {
		return 0, errSentinel
	}
	take := len(p)
	if take > room {
		take = room
	}
	n, err := w.inner.Write(p[:take])
	w.wrote += n
	if err != nil {
		return n, err
	}
	if take < len(p) {
		return n, errSentinel
	}
	return n, nil
}

// failingReader returns the first allowedBytes bytes from src
// successfully, then returns errSentinel (not io.EOF).
type failingReader struct {
	inner        *bytes.Reader
	allowedBytes int
	read         int
	calls        int
}

func (r *failingReader) Read(p []byte) (int, error) {
	r.calls++
	room := r.allowedBytes - r.read
	if room <= 0 {
		return 0, errSentinel
	}
	take := len(p)
	if take > room {
		take = room
	}
	n, err := r.inner.Read(p[:take])
	r.read += n
	if err != nil {
		return n, err
	}
	if r.read >= r.allowedBytes {
		return n, errSentinel
	}
	return n, nil
}

// TestStreamWriterCloseDstError confirms a dst.Write failure during
// Close surfaces as the Close error, and a second Close is idempotent
// (returns nil, does not re-trigger dst.Write).
func TestStreamWriterCloseDstError(t *testing.T) {
	s := mustScheduleWithChunk(t, streamPaletteCases[2].palette, testChunkSize)
	cs := mustCipherset(t, mustMaster(t), s)
	// Allow just enough bytes for one full chunk frame to land; the
	// trailing partial-chunk flush on Close lands after the budget
	// and triggers the sentinel.
	allowed := frameLenSize + NonceSize + testChunkSize
	fw := &failingWriter{inner: &bytes.Buffer{}, allowedBytes: allowed}
	ew, err := s.NewEncryptWriter(cs, fw)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	pt := randomPlaintext(t, testChunkSize+5)
	if _, err := ew.Write(pt); err != nil && !errors.Is(err, errSentinel) {
		t.Fatalf("Write: %v", err)
	}
	closeErr := ew.Close()
	if closeErr == nil {
		t.Logf("first Close returned nil (Write drained past boundary)")
	}
	// Second Close: idempotent, no error, no further dst.Write.
	callsBefore := fw.calls
	if err := ew.Close(); err != nil {
		t.Fatalf("second Close (should be idempotent): %v", err)
	}
	if fw.calls != callsBefore {
		t.Fatalf("second Close issued %d additional dst.Write calls, want 0", fw.calls-callsBefore)
	}
}

// TestStreamReaderUpstreamError confirms a mid-stream non-EOF read
// error surfaces to the caller, and Close after the error releases
// pool buffers exactly once.
func TestStreamReaderUpstreamError(t *testing.T) {
	s := mustScheduleWithChunk(t, streamPaletteCases[2].palette, testChunkSize)
	cs := mustCipherset(t, mustMaster(t), s)
	pt := randomPlaintext(t, 10*testChunkSize)

	t.Run("encrypt-reader", func(t *testing.T) {
		fr := &failingReader{inner: bytes.NewReader(pt), allowedBytes: 3 * testChunkSize}
		er, err := s.NewEncryptReader(cs, fr)
		if err != nil {
			t.Fatalf("NewEncryptReader: %v", err)
		}
		// Drain everything possible until the error trips.
		buf := make([]byte, 256)
		var rerr error
		for rerr == nil {
			_, rerr = er.Read(buf)
		}
		if rerr == io.EOF {
			t.Fatal("expected sentinel error, got EOF")
		}
		if !errors.Is(rerr, errSentinel) {
			t.Fatalf("expected errSentinel, got %v", rerr)
		}
		if err := er.Close(); err != nil {
			t.Fatalf("Close after error: %v", err)
		}
		if err := er.Close(); err != nil {
			t.Fatalf("second Close (idempotent): %v", err)
		}
	})

	t.Run("decrypt-reader", func(t *testing.T) {
		// Build a real wire, then truncate the source mid-stream.
		wireBuf := &bytes.Buffer{}
		ew, err := s.NewEncryptWriter(cs, wireBuf)
		if err != nil {
			t.Fatalf("NewEncryptWriter: %v", err)
		}
		if _, err := ew.Write(pt); err != nil {
			t.Fatalf("ew.Write: %v", err)
		}
		if err := ew.Close(); err != nil {
			t.Fatalf("ew.Close: %v", err)
		}
		wire := wireBuf.Bytes()
		fr := &failingReader{inner: bytes.NewReader(wire), allowedBytes: len(wire) / 2}
		dr, err := s.NewDecryptReader(cs, fr)
		if err != nil {
			t.Fatalf("NewDecryptReader: %v", err)
		}
		buf := make([]byte, 256)
		var rerr error
		for rerr == nil {
			_, rerr = dr.Read(buf)
		}
		if rerr == io.EOF {
			t.Fatal("expected sentinel error, got EOF")
		}
		if !errors.Is(rerr, errSentinel) {
			t.Fatalf("expected errSentinel, got %v", rerr)
		}
		if err := dr.Close(); err != nil {
			t.Fatalf("Close after error: %v", err)
		}
		if err := dr.Close(); err != nil {
			t.Fatalf("second Close (idempotent): %v", err)
		}
	})
}

// TestStreamHugeSingleWrite drives a multi-MiB plaintext through a
// single Write call into NewEncryptWriter; the per-Write loop must
// flush chunk after chunk as the accumulator fills.
func TestStreamHugeSingleWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("huge-Write test skipped in -short mode")
	}
	s := mustScheduleWithChunk(t, streamPaletteCases[2].palette, 64*1024)
	cs := mustCipherset(t, mustMaster(t), s)
	pt := make([]byte, 1024*1024)
	if _, err := rand.Read(pt); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	wireBuf := &bytes.Buffer{}
	ew, err := s.NewEncryptWriter(cs, wireBuf)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	n, err := ew.Write(pt)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(pt) {
		t.Fatalf("Write n: got %d, want %d", n, len(pt))
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	dr, err := s.NewDecryptReader(cs, bytes.NewReader(wireBuf.Bytes()))
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if err := dr.Close(); err != nil {
		t.Fatalf("Close dr: %v", err)
	}
	if !bytes.Equal(pt, got) {
		t.Fatalf("huge-Write round-trip mismatch")
	}
}

// TestStreamChunkSizeFrozenMidStream confirms a mid-stream
// SetChunkSize call does not perturb an in-flight stream. The
// in-flight stream uses the chunk size captured at construction.
func TestStreamChunkSizeFrozenMidStream(t *testing.T) {
	master := mustMaster(t)
	pp := streamPaletteCases[2]
	pt := randomPlaintext(t, 100*testChunkSize+11)

	s := mustScheduleWithChunk(t, pp.palette, testChunkSize)
	cs := mustCipherset(t, master, s)
	wireBuf := &bytes.Buffer{}
	ew, err := s.NewEncryptWriter(cs, wireBuf)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	half := len(pt) / 2
	if _, err := ew.Write(pt[:half]); err != nil {
		t.Fatalf("Write(half): %v", err)
	}
	// Mid-stream: change chunk size; the in-flight writer must keep
	// its constructor-time value, otherwise the next chunk boundary
	// drifts and the decrypt-side frame parser desyncs.
	if err := s.SetChunkSize(testChunkSize * 7); err != nil {
		t.Fatalf("SetChunkSize: %v", err)
	}
	if _, err := ew.Write(pt[half:]); err != nil {
		t.Fatalf("Write(rest): %v", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Decrypt under a fresh Schedule whose chunk size was never
	// touched (DefaultChunkSize). Frame parsing is chunk-size-agnostic
	// on the decrypt side (each frame self-describes via the u32
	// prefix), so the wire round-trips regardless.
	sRef := mustSchedule(t, pp.palette, DefaultSegmentSize)
	csRef := mustCipherset(t, master, sRef)
	dr, err := sRef.NewDecryptReader(csRef, bytes.NewReader(wireBuf.Bytes()))
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(pt, got) {
		t.Fatalf("mid-stream chunk-size mutation perturbed the in-flight stream")
	}
}

// TestStreamChunkSizeBoundary round-trips at chunk-size-aligned and
// chunk-size-adjacent payload lengths to exercise the boundary
// transitions in the chunked Writer / Reader hot loops.
func TestStreamChunkSizeBoundary(t *testing.T) {
	master := mustMaster(t)
	pp := streamPaletteCases[2]
	chunkCases := []int{17, 257, 4093}
	for _, ck := range chunkCases {
		s := mustScheduleWithChunk(t, pp.palette, ck)
		cs := mustCipherset(t, master, s)
		for _, ptLen := range []int{ck - 1, ck, ck + 1, 2*ck - 1, 2 * ck, 2*ck + 1} {
			ptLen := ptLen
			t.Run("ck"+itoa(ck)+"/n"+itoa(ptLen), func(t *testing.T) {
				pt := randomPlaintext(t, ptLen)
				wireBuf := &bytes.Buffer{}
				ew, err := s.NewEncryptWriter(cs, wireBuf)
				if err != nil {
					t.Fatalf("NewEncryptWriter: %v", err)
				}
				if _, err := ew.Write(pt); err != nil {
					t.Fatalf("Write: %v", err)
				}
				if err := ew.Close(); err != nil {
					t.Fatalf("Close: %v", err)
				}
				dr, err := s.NewDecryptReader(cs, bytes.NewReader(wireBuf.Bytes()))
				if err != nil {
					t.Fatalf("NewDecryptReader: %v", err)
				}
				got, err := io.ReadAll(dr)
				if err != nil {
					t.Fatalf("ReadAll: %v", err)
				}
				if !bytes.Equal(pt, got) {
					t.Fatalf("chunk-boundary round-trip mismatch (ck=%d ptLen=%d)", ck, ptLen)
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Test helpers.
// ---------------------------------------------------------------------------

// writeInChunks writes pt to dst in randomly-sized chunks to exercise
// the accumulator across many Write boundaries.
func writeInChunks(dst io.Writer, pt []byte) error {
	rng := mrand.New(mrand.NewPCG(11, 17))
	cursor := 0
	for cursor < len(pt) {
		n := 1 + rng.IntN(257)
		if cursor+n > len(pt) {
			n = len(pt) - cursor
		}
		if _, err := dst.Write(pt[cursor : cursor+n]); err != nil {
			return err
		}
		cursor += n
	}
	return nil
}

// itoa renders n as a decimal sub-test suffix without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// TestStreamWriterStickyAfterWriteFailure confirms that once Write
// surfaces an error from a dst.Write failure, every subsequent Write
// returns the same sticky error without issuing further dst.Write
// calls.
func TestStreamWriterStickyAfterWriteFailure(t *testing.T) {
	s := mustScheduleWithChunk(t, streamPaletteCases[2].palette, testChunkSize)
	cs := mustCipherset(t, mustMaster(t), s)
	// Allow only the bytes for a length prefix; the chunk-body write
	// then triggers the sentinel mid-stream.
	allowed := frameLenSize - 1
	fw := &failingWriter{inner: &bytes.Buffer{}, allowedBytes: allowed}
	ew, err := s.NewEncryptWriter(cs, fw)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	pt := randomPlaintext(t, testChunkSize*2)
	if _, err := ew.Write(pt); !errors.Is(err, errSentinel) {
		t.Fatalf("first Write: err=%v, want errSentinel", err)
	}
	callsAfterFirst := fw.calls
	if _, err := ew.Write(pt); !errors.Is(err, errSentinel) {
		t.Fatalf("second Write: err=%v, want sticky errSentinel", err)
	}
	if fw.calls != callsAfterFirst {
		t.Fatalf("second Write triggered %d additional dst.Write calls, want 0", fw.calls-callsAfterFirst)
	}
	// Close after sticky surfaces the same error.
	if err := ew.Close(); !errors.Is(err, errSentinel) {
		t.Fatalf("Close after sticky: err=%v, want errSentinel", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("second Close: err=%v, want nil (idempotent)", err)
	}
}

// TestStreamDecryptWriterStickyAfterDstWriteFailure confirms the
// decrypt writer enters sticky state on dst.Write failure and rejects
// every subsequent Write with the same error.
func TestStreamDecryptWriterStickyAfterDstWriteFailure(t *testing.T) {
	s := mustScheduleWithChunk(t, streamPaletteCases[2].palette, testChunkSize)
	cs := mustCipherset(t, mustMaster(t), s)
	// Build a valid wire of two chunks to drive Decrypt.
	pt := randomPlaintext(t, testChunkSize*2)
	wireBuf := &bytes.Buffer{}
	ew, err := s.NewEncryptWriter(cs, wireBuf)
	if err != nil {
		t.Fatalf("NewEncryptWriter: %v", err)
	}
	if _, err := ew.Write(pt); err != nil {
		t.Fatalf("encrypt Write: %v", err)
	}
	if err := ew.Close(); err != nil {
		t.Fatalf("encrypt Close: %v", err)
	}
	wire := wireBuf.Bytes()
	// failingWriter rejects every dst.Write — the very first decrypted
	// chunk triggers the sentinel.
	fw := &failingWriter{inner: &bytes.Buffer{}, allowedBytes: 0}
	dw, err := s.NewDecryptWriter(cs, fw)
	if err != nil {
		t.Fatalf("NewDecryptWriter: %v", err)
	}
	if _, err := dw.Write(wire); !errors.Is(err, errSentinel) {
		t.Fatalf("first Write: err=%v, want errSentinel", err)
	}
	if _, err := dw.Write(wire); !errors.Is(err, errSentinel) {
		t.Fatalf("second Write: err=%v, want sticky errSentinel", err)
	}
	if err := dw.Close(); !errors.Is(err, errSentinel) {
		t.Fatalf("Close after sticky: err=%v, want errSentinel", err)
	}
}

// TestStreamDecryptOversizedBodyLenRejected confirms a frame whose
// length prefix exceeds MaxChunkSize is rejected by both decoder
// shapes (writer and reader) before allocation, so a hostile or
// corrupted wire cannot drive an unbounded body buffer.
func TestStreamDecryptOversizedBodyLenRejected(t *testing.T) {
	s := mustScheduleWithChunk(t, streamPaletteCases[2].palette, testChunkSize)
	cs := mustCipherset(t, mustMaster(t), s)
	var prefix [frameLenSize]byte
	binary.LittleEndian.PutUint32(prefix[:], uint32(MaxChunkSize)+1)
	// Writer shape: feed the oversize prefix.
	dw, err := s.NewDecryptWriter(cs, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("NewDecryptWriter: %v", err)
	}
	if _, err := dw.Write(prefix[:]); err == nil || !strings.Contains(err.Error(), "outside [0,") {
		t.Fatalf("writer Write(oversize prefix): err=%v, want \"outside [0, ...]\" rejection", err)
	}
	// Sticky: the second Write returns the same error.
	if _, err := dw.Write(prefix[:]); err == nil || !strings.Contains(err.Error(), "outside [0,") {
		t.Fatalf("writer second Write: err=%v, want sticky rejection", err)
	}
	// Reader shape: feed the oversize prefix as the upstream payload.
	dr, err := s.NewDecryptReader(cs, bytes.NewReader(prefix[:]))
	if err != nil {
		t.Fatalf("NewDecryptReader: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := dr.Read(buf); err == nil || !strings.Contains(err.Error(), "outside [0,") {
		t.Fatalf("reader Read(oversize prefix): err=%v, want \"outside [0, ...]\" rejection", err)
	}
}
