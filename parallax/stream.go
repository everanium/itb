package parallax

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Streaming surface for parallax.
//
// Four entry points mirror the wrapper's io.Reader / io.Writer shape
// so the package composes with ITB's Streaming AEAD path. The
// Reader-shape variants encrypt / decrypt as bytes are pulled from
// upstream; the Writer-shape variants encrypt / decrypt as bytes are
// pushed by the caller.
//
// The streaming surface is a per-chunk loop over the single-message
// EncryptInPlace / DecryptInPlace path. Each chunk is one independent
// message with its own freshly drawn nonce, framed on the wire as a
// u32 little-endian body length followed by the nonce-prefixed body.
// The chunk size is read once at stream construction from the
// Schedule's ChunkSize and is fixed for that stream's lifetime;
// subsequent SetChunkSize calls affect only streams constructed after.
//
// Wire layout (one frame per chunk; the stream is the concatenation
// of frames):
//
//	frame: u32_LE(body_len) || nonce(NonceSize) || encrypted_body(body_len)
//	stream: frame_1 || frame_2 || ... || frame_N
//
// The plaintext length is recoverable as the sum of body_len across
// frames. A non-zero plaintext shorter than ChunkSize emits a single
// frame; an empty plaintext emits no frames at all. The decoder
// rejects any frame whose body length exceeds MaxChunkSize so a
// truncated or corrupted prefix cannot drive an unbounded allocation.
//
// The streaming surface is Non-AEAD by design. The 4-byte frame
// length prefix is unauthenticated, so a single-bit modification to
// any prefix on the wire desynchronises every subsequent frame, not
// only the frame whose prefix was modified. Callers who need wire
// integrity compose parallax under ITB's authenticated transport
// (Easy Mode or Streaming AEAD); standalone use of the parallax
// streaming surface assumes integrity is provided by the surrounding
// channel.
//
// Writer-shape variants return io.WriteCloser. Close flushes the
// pending partial chunk (if any) and releases pooled scratch space.
// Close MUST be called whenever the total plaintext is not a multiple
// of the chunk size; omitting it leaves the trailing partial chunk
// unsent. Close is idempotent — a second call returns nil. Once a
// Writer surfaces an error (encrypt failure, length-prefix outside
// the accepted range, dst.Write failure), it enters a sticky-failed
// state: every subsequent Write returns the same error, the first
// Close returns the same error, and no further frames are emitted.
//
// Reader-shape variants return io.ReadCloser. Close releases pool
// buffers; the same release happens automatically when upstream Read
// returns io.EOF and the final partial chunk has been served, so
// callers that always read to io.EOF may omit Close. Early-termination
// callers must call Close to avoid pool-buffer pressure. Close is
// idempotent.

// streamChunkPool stores accumulator buffers reused across stream
// lifetimes. The pool stores *[]byte to keep Get/Put pointer-shaped
// (avoids the slice-header re-boxing sync.Pool would otherwise perform
// on every call).
var streamChunkPool = &sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

// acquireChunkBuffer borrows a *[]byte sized for capBytes from the
// pool. The returned slice has length 0 and capacity at least capBytes.
func acquireChunkBuffer(capBytes int) (*[]byte, []byte) {
	ptr := streamChunkPool.Get().(*[]byte)
	buf := *ptr
	if cap(buf) < capBytes {
		buf = make([]byte, 0, capBytes)
	} else {
		buf = buf[:0]
	}
	return ptr, buf
}

// releaseChunkBuffer wipes buf and returns it to the pool.
func releaseChunkBuffer(ptr *[]byte, buf []byte) {
	if ptr == nil {
		return
	}
	full := buf[:cap(buf)]
	clear(full)
	*ptr = buf[:0]
	streamChunkPool.Put(ptr)
}

// frameLenSize is the byte width of the on-wire body-length prefix.
const frameLenSize = 4

// ---------------------------------------------------------------------------
// Writer-shape — Encrypt.
// ---------------------------------------------------------------------------

// chunkedEncryptWriter accumulates plaintext bytes up to the
// per-stream chunkCap, then emits one frame per full chunk through
// EncryptInPlace. Close flushes any pending partial chunk and
// releases the pooled accumulator. Once any underlying error has
// surfaced (encrypt failure, dst.Write failure), the writer enters a
// sticky-failed state: every subsequent Write returns the same error,
// Close returns the same error, and no further frames are emitted.
// The sticky state guards against re-entry that would otherwise emit
// a malformed continuation onto a partially-written wire.
type chunkedEncryptWriter struct {
	schedule *Schedule
	cs       *Cipherset
	dst      io.Writer
	chunkCap int
	bufPtr   *[]byte
	buf      []byte
	closed   bool
	err      error
}

func (w *chunkedEncryptWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, errors.New("parallax: write on closed stream")
	}
	total := 0
	for len(p) > 0 {
		free := w.chunkCap - len(w.buf)
		take := free
		if take > len(p) {
			take = len(p)
		}
		w.buf = append(w.buf, p[:take]...)
		p = p[take:]
		total += take
		if len(w.buf) == w.chunkCap {
			if err := w.flushChunk(); err != nil {
				w.err = err
				return total, err
			}
		}
	}
	return total, nil
}

// flushChunk encrypts w.buf via EncryptInPlace and emits the frame
// (u32_LE length, then nonce-prefixed body) to dst. Resets the
// accumulator to length 0 on success; on failure leaves w.buf
// unchanged and returns the error. Caller (Write / Close) is
// responsible for promoting the error to sticky state.
func (w *chunkedEncryptWriter) flushChunk() error {
	if len(w.buf) == 0 {
		return nil
	}
	wire, err := w.schedule.EncryptInPlace(w.buf, w.cs)
	if err != nil {
		return err
	}
	bodyLen := uint32(len(wire) - NonceSize)
	var prefix [frameLenSize]byte
	binary.LittleEndian.PutUint32(prefix[:], bodyLen)
	if _, err := w.dst.Write(prefix[:]); err != nil {
		return err
	}
	if _, err := w.dst.Write(wire); err != nil {
		return err
	}
	w.buf = w.buf[:0]
	return nil
}

func (w *chunkedEncryptWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	var err error
	if w.err == nil {
		err = w.flushChunk()
		if err != nil {
			w.err = err
		}
	} else {
		err = w.err
	}
	if w.bufPtr != nil {
		releaseChunkBuffer(w.bufPtr, w.buf)
		w.bufPtr = nil
		w.buf = nil
	}
	return err
}

// NewEncryptWriter returns an io.WriteCloser that encrypts every byte
// written through it onto dst as a stream of per-chunk frames. Each
// frame is one EncryptInPlace call's output: a 4-byte little-endian
// body-length prefix followed by a 16-byte CSPRNG nonce and the
// encrypted body. The chunk size is taken from the Schedule's
// ChunkSize at construction time; the writer accumulates until that
// many plaintext bytes have been gathered, then emits one frame and
// resets. Close MUST be called to flush the trailing partial chunk
// (if any) and to release pool scratch. Close is idempotent.
//
// A plaintext shorter than the chunk size emits one frame on Close.
// An empty plaintext (no Write calls, or only zero-length Writes)
// emits no frames at all and produces a zero-length wire.
//
// An error is returned when cs is nil or does not match this schedule,
// or when dst is nil.
func (s *Schedule) NewEncryptWriter(cs *Cipherset, dst io.Writer) (io.WriteCloser, error) {
	if err := s.checkCipherset(cs); err != nil {
		return nil, err
	}
	if dst == nil {
		return nil, fmt.Errorf("parallax: nil writer")
	}
	chunkCap := s.ChunkSize()
	bufPtr, buf := acquireChunkBuffer(chunkCap)
	return &chunkedEncryptWriter{
		schedule: s,
		cs:       cs,
		dst:      dst,
		chunkCap: chunkCap,
		bufPtr:   bufPtr,
		buf:      buf,
	}, nil
}

// ---------------------------------------------------------------------------
// Writer-shape — Decrypt.
// ---------------------------------------------------------------------------

// chunkedDecryptWriter accumulates wire bytes, parses one frame at a
// time, and writes the recovered plaintext to dst. The on-wire layout
// is exactly the layout chunkedEncryptWriter emits.
//
// State machine: when bodyLen is -1 the writer is reading the 4-byte
// length prefix into lenBuf; otherwise it is reading bodyLen + NonceSize
// frame bytes into bodyBuf. On a completed frame, DecryptInPlace
// recovers the plaintext and the writer transitions back to length-prefix
// reading mode.
//
// Once any underlying error has surfaced (length-prefix outside the
// accepted range, decrypt failure, dst.Write failure), the writer
// enters a sticky-failed state: every subsequent Write returns the
// same error and Close returns the same error.
type chunkedDecryptWriter struct {
	schedule *Schedule
	cs       *Cipherset
	dst      io.Writer
	bufPtr   *[]byte
	bodyBuf  []byte
	lenBuf   []byte
	bodyLen  int // -1 when waiting on length prefix
	closed   bool
	err      error
}

func (w *chunkedDecryptWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.closed {
		return 0, errors.New("parallax: write on closed stream")
	}
	total := 0
	for len(p) > 0 {
		if w.bodyLen < 0 {
			// Accumulate the 4-byte length prefix.
			need := frameLenSize - len(w.lenBuf)
			take := need
			if take > len(p) {
				take = len(p)
			}
			w.lenBuf = append(w.lenBuf, p[:take]...)
			p = p[take:]
			total += take
			if len(w.lenBuf) < frameLenSize {
				return total, nil
			}
			w.bodyLen = int(binary.LittleEndian.Uint32(w.lenBuf))
			w.lenBuf = w.lenBuf[:0]
			if w.bodyLen < 0 || w.bodyLen > MaxChunkSize {
				w.err = fmt.Errorf("parallax: frame body length %d outside [0, %d]", w.bodyLen, MaxChunkSize)
				return total, w.err
			}
			frameSize := w.bodyLen + NonceSize
			if cap(w.bodyBuf) < frameSize {
				if w.bufPtr != nil {
					releaseChunkBuffer(w.bufPtr, w.bodyBuf)
				}
				w.bufPtr, w.bodyBuf = acquireChunkBuffer(frameSize)
			} else {
				w.bodyBuf = w.bodyBuf[:0]
			}
			continue
		}
		// Accumulate the frame body.
		frameSize := w.bodyLen + NonceSize
		need := frameSize - len(w.bodyBuf)
		take := need
		if take > len(p) {
			take = len(p)
		}
		w.bodyBuf = append(w.bodyBuf, p[:take]...)
		p = p[take:]
		total += take
		if len(w.bodyBuf) < frameSize {
			return total, nil
		}
		plain, err := w.schedule.DecryptInPlace(w.bodyBuf, w.cs)
		if err != nil {
			w.err = err
			return total, err
		}
		if _, err := w.dst.Write(plain); err != nil {
			w.err = err
			return total, err
		}
		w.bodyBuf = w.bodyBuf[:0]
		w.bodyLen = -1
	}
	return total, nil
}

func (w *chunkedDecryptWriter) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	bodyBytes := len(w.bodyBuf)
	prefixBytes := len(w.lenBuf)
	if w.bufPtr != nil {
		releaseChunkBuffer(w.bufPtr, w.bodyBuf)
		w.bufPtr = nil
		w.bodyBuf = nil
	}
	if w.err != nil {
		return w.err
	}
	if w.bodyLen >= 0 || prefixBytes > 0 {
		w.err = fmt.Errorf("parallax: decrypt-writer closed mid-frame (have %d body bytes, %d prefix bytes)", bodyBytes, prefixBytes)
		return w.err
	}
	return nil
}

// NewDecryptWriter returns an io.WriteCloser that reverses the
// per-chunk encrypt stream. The caller writes wire bytes (the
// concatenation of frames emitted by NewEncryptWriter or
// NewEncryptReader); dst receives the recovered plaintext, one chunk
// at a time as each frame is fully accumulated. Close MUST be called
// to release pool scratch; a Close issued mid-frame returns an error
// reporting the partial-frame state.
//
// An empty wire (no Write calls) closes successfully and writes
// nothing to dst.
//
// An error is returned when cs is nil or does not match this schedule,
// or when dst is nil.
func (s *Schedule) NewDecryptWriter(cs *Cipherset, dst io.Writer) (io.WriteCloser, error) {
	if err := s.checkCipherset(cs); err != nil {
		return nil, err
	}
	if dst == nil {
		return nil, fmt.Errorf("parallax: nil writer")
	}
	return &chunkedDecryptWriter{
		schedule: s,
		cs:       cs,
		dst:      dst,
		lenBuf:   make([]byte, 0, frameLenSize),
		bodyLen:  -1,
	}, nil
}

// ---------------------------------------------------------------------------
// Reader-shape — Encrypt.
// ---------------------------------------------------------------------------

// chunkedEncryptReader pulls plaintext from src in chunkCap-sized
// reads, encrypts each chunk via EncryptInPlace, and serves the
// resulting frame (length prefix, nonce, body) to the caller's p. The
// outBuf holds the in-flight frame; outOff bracket the
// already-served prefix.
type chunkedEncryptReader struct {
	schedule    *Schedule
	cs          *Cipherset
	src         io.Reader
	chunkCap    int
	plainBufPtr *[]byte
	plainBuf    []byte
	outBufPtr   *[]byte
	outBuf      []byte
	outOff      int
	upstreamEOF bool
	released    bool
}

func (r *chunkedEncryptReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for len(p) > 0 {
		// Serve any pending frame bytes first.
		if r.outOff < len(r.outBuf) {
			n := copy(p, r.outBuf[r.outOff:])
			r.outOff += n
			total += n
			p = p[n:]
			continue
		}
		if r.upstreamEOF {
			r.release()
			if total > 0 {
				return total, nil
			}
			return 0, io.EOF
		}
		// Pull up to chunkCap bytes from src into the plaintext buffer.
		r.plainBuf = r.plainBuf[:r.chunkCap]
		n, err := io.ReadFull(r.src, r.plainBuf)
		switch {
		case err == nil:
			r.plainBuf = r.plainBuf[:n]
		case errors.Is(err, io.EOF):
			r.upstreamEOF = true
			r.plainBuf = r.plainBuf[:0]
		case errors.Is(err, io.ErrUnexpectedEOF):
			r.upstreamEOF = true
			r.plainBuf = r.plainBuf[:n]
		default:
			return total, err
		}
		if len(r.plainBuf) == 0 {
			continue
		}
		if err := r.encodeFrame(); err != nil {
			return total, err
		}
	}
	return total, nil
}

// encodeFrame encrypts r.plainBuf via EncryptInPlace and packs the
// resulting frame (length prefix + nonce + body) into r.outBuf.
func (r *chunkedEncryptReader) encodeFrame() error {
	wire, err := r.schedule.EncryptInPlace(r.plainBuf, r.cs)
	if err != nil {
		return err
	}
	frameSize := frameLenSize + len(wire)
	if cap(r.outBuf) < frameSize {
		if r.outBufPtr != nil {
			releaseChunkBuffer(r.outBufPtr, r.outBuf)
		}
		r.outBufPtr, r.outBuf = acquireChunkBuffer(frameSize)
	}
	r.outBuf = r.outBuf[:frameSize]
	binary.LittleEndian.PutUint32(r.outBuf[:frameLenSize], uint32(len(wire)-NonceSize))
	copy(r.outBuf[frameLenSize:], wire)
	r.outOff = 0
	return nil
}

func (r *chunkedEncryptReader) Close() error {
	r.release()
	return nil
}

func (r *chunkedEncryptReader) release() {
	if r.released {
		return
	}
	r.released = true
	if r.plainBufPtr != nil {
		releaseChunkBuffer(r.plainBufPtr, r.plainBuf)
		r.plainBufPtr = nil
		r.plainBuf = nil
	}
	if r.outBufPtr != nil {
		releaseChunkBuffer(r.outBufPtr, r.outBuf)
		r.outBufPtr = nil
		r.outBuf = nil
	}
}

// NewEncryptReader returns an io.ReadCloser that draws plaintext from
// src in chunkCap-sized reads, encrypts each chunk via EncryptInPlace,
// and emits one frame per chunk through the returned Reader. When src
// returns io.EOF the trailing partial chunk (if any) is encoded as a
// final frame and served before the Reader returns io.EOF. Callers
// that always read to io.EOF may omit Close; pool buffers are
// released automatically at EOF. Early-termination callers should
// call Close to avoid pool-buffer pressure. Close is idempotent.
//
// An error is returned when cs is nil or does not match this schedule,
// or when src is nil.
func (s *Schedule) NewEncryptReader(cs *Cipherset, src io.Reader) (io.ReadCloser, error) {
	if err := s.checkCipherset(cs); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("parallax: nil reader")
	}
	chunkCap := s.ChunkSize()
	plainPtr, plainBuf := acquireChunkBuffer(chunkCap)
	return &chunkedEncryptReader{
		schedule:    s,
		cs:          cs,
		src:         src,
		chunkCap:    chunkCap,
		plainBufPtr: plainPtr,
		plainBuf:    plainBuf,
	}, nil
}

// ---------------------------------------------------------------------------
// Reader-shape — Decrypt.
// ---------------------------------------------------------------------------

// chunkedDecryptReader pulls wire bytes from src, parses one frame at
// a time, and serves the recovered plaintext to the caller's p. The
// plainBuf holds the in-flight plaintext chunk; plainOff brackets the
// already-served prefix.
type chunkedDecryptReader struct {
	schedule *Schedule
	cs       *Cipherset
	src      io.Reader
	bodyPtr  *[]byte
	bodyBuf  []byte
	plainBuf []byte
	plainOff int
	released bool
	srcAtEOF bool
}

func (r *chunkedDecryptReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	for len(p) > 0 {
		// Serve any pending plaintext first.
		if r.plainOff < len(r.plainBuf) {
			n := copy(p, r.plainBuf[r.plainOff:])
			r.plainOff += n
			total += n
			p = p[n:]
			continue
		}
		if r.srcAtEOF {
			r.release()
			if total > 0 {
				return total, nil
			}
			return 0, io.EOF
		}
		if err := r.readFrame(); err != nil {
			if errors.Is(err, io.EOF) {
				r.srcAtEOF = true
				continue
			}
			return total, err
		}
	}
	return total, nil
}

// readFrame consumes one frame from src: the 4-byte body length, then
// the nonce-prefixed body. Decrypts the body in place and stores the
// recovered plaintext in r.plainBuf. A clean io.EOF on the length
// prefix (zero bytes read) signals end of stream; a partial-prefix EOF
// is reported as ErrUnexpectedEOF.
func (r *chunkedDecryptReader) readFrame() error {
	var lenBuf [frameLenSize]byte
	n, err := io.ReadFull(r.src, lenBuf[:])
	if err != nil {
		if errors.Is(err, io.EOF) && n == 0 {
			return io.EOF
		}
		return err
	}
	bodyLen := int(binary.LittleEndian.Uint32(lenBuf[:]))
	if bodyLen < 0 || bodyLen > MaxChunkSize {
		return fmt.Errorf("parallax: frame body length %d outside [0, %d]", bodyLen, MaxChunkSize)
	}
	frameSize := bodyLen + NonceSize
	if cap(r.bodyBuf) < frameSize {
		if r.bodyPtr != nil {
			releaseChunkBuffer(r.bodyPtr, r.bodyBuf)
		}
		r.bodyPtr, r.bodyBuf = acquireChunkBuffer(frameSize)
	}
	r.bodyBuf = r.bodyBuf[:frameSize]
	if _, err := io.ReadFull(r.src, r.bodyBuf); err != nil {
		return err
	}
	plain, err := r.schedule.DecryptInPlace(r.bodyBuf, r.cs)
	if err != nil {
		return err
	}
	r.plainBuf = plain
	r.plainOff = 0
	return nil
}

func (r *chunkedDecryptReader) Close() error {
	r.release()
	return nil
}

func (r *chunkedDecryptReader) release() {
	if r.released {
		return
	}
	r.released = true
	if r.bodyPtr != nil {
		releaseChunkBuffer(r.bodyPtr, r.bodyBuf)
		r.bodyPtr = nil
		r.bodyBuf = nil
	}
	r.plainBuf = nil
}

// NewDecryptReader returns an io.ReadCloser that draws wire bytes
// from src (the concatenation of frames emitted by NewEncryptWriter
// or NewEncryptReader) and serves the recovered plaintext to the
// caller. Frames are pulled from src one at a time; a clean io.EOF on
// a frame boundary terminates the stream. Callers that always read to
// io.EOF may omit Close; pool buffers are released automatically at
// EOF. Early-termination callers should call Close to avoid
// pool-buffer pressure. Close is idempotent.
//
// An error is returned when cs is nil or does not match this schedule,
// or when src is nil.
func (s *Schedule) NewDecryptReader(cs *Cipherset, src io.Reader) (io.ReadCloser, error) {
	if err := s.checkCipherset(cs); err != nil {
		return nil, err
	}
	if src == nil {
		return nil, fmt.Errorf("parallax: nil reader")
	}
	return &chunkedDecryptReader{
		schedule: s,
		cs:       cs,
		src:      src,
	}, nil
}
