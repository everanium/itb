package easy

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/everanium/itb"
)

// EncryptStreamAuth encrypts plaintext as a Streaming AEAD transcript
// under the encryptor's bound seeds + MAC. The helper generates a
// fresh 32-byte stream anchor at stream start, emits it as the first
// wire chunk through emit, then walks plaintext in chunks of the
// encryptor's chunk override (set via [Encryptor.SetChunkSize]; 0 =
// auto-detect via [itb.ChunkSize]) calling
// [Encryptor.EncryptStreamAuthenticated] per chunk with the running
// cumulative pixel offset and finalFlag = true on the last chunk.
//
// Empty plaintext is permitted: emit receives the 32-byte stream
// prefix followed by a single terminating chunk built from a 0-byte
// payload with finalFlag = true.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns the first non-nil error from the chunk emitter or from
// the underlying [itb.EncryptStreamAuth{N}Cfg] /
// [itb.EncryptStreamAuth3x{N}Cfg] entry point.
func (e *Encryptor) EncryptStreamAuth(plaintext []byte, emit ChunkFunc) error {
	if e.closed {
		panic(ErrClosed)
	}
	e.firstEncryptCalled = true

	switch e.width {
	case 128:
		if e.Mode == 1 {
			return itb.EncryptStreamAuth128Cfg(e.cfg,
				e.seeds[0].(*itb.Seed128), e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128),
				plaintext, e.chunk, e.macFunc, emit)
		}
		return itb.EncryptStreamAuth3x128Cfg(e.cfg,
			e.seeds[0].(*itb.Seed128),
			e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128), e.seeds[3].(*itb.Seed128),
			e.seeds[4].(*itb.Seed128), e.seeds[5].(*itb.Seed128), e.seeds[6].(*itb.Seed128),
			plaintext, e.chunk, e.macFunc, emit)
	case 256:
		if e.Mode == 1 {
			return itb.EncryptStreamAuth256Cfg(e.cfg,
				e.seeds[0].(*itb.Seed256), e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256),
				plaintext, e.chunk, e.macFunc, emit)
		}
		return itb.EncryptStreamAuth3x256Cfg(e.cfg,
			e.seeds[0].(*itb.Seed256),
			e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256), e.seeds[3].(*itb.Seed256),
			e.seeds[4].(*itb.Seed256), e.seeds[5].(*itb.Seed256), e.seeds[6].(*itb.Seed256),
			plaintext, e.chunk, e.macFunc, emit)
	case 512:
		if e.Mode == 1 {
			return itb.EncryptStreamAuth512Cfg(e.cfg,
				e.seeds[0].(*itb.Seed512), e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512),
				plaintext, e.chunk, e.macFunc, emit)
		}
		return itb.EncryptStreamAuth3x512Cfg(e.cfg,
			e.seeds[0].(*itb.Seed512),
			e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512), e.seeds[3].(*itb.Seed512),
			e.seeds[4].(*itb.Seed512), e.seeds[5].(*itb.Seed512), e.seeds[6].(*itb.Seed512),
			plaintext, e.chunk, e.macFunc, emit)
	}
	panic(fmt.Sprintf("itb/easy: unsupported primitive width %d", e.width))
}

// DecryptStreamAuth walks a Streaming AEAD transcript produced by
// [Encryptor.EncryptStreamAuth], reading the leading 32-byte stream
// anchor and verifying every following chunk under the encryptor's
// bound MAC closure with the running cumulative pixel offset.
// Recovered plaintext is delivered through emit once per chunk in
// stream order. Returns [itb.ErrStreamTruncated] when the transcript
// exhausts without observing a chunk whose finalFlag is true and
// [itb.ErrStreamAfterFinal] when additional chunk bytes follow the
// terminator.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns the first non-nil error from the chunk emitter, a MAC
// verification failure, or any structural error reported by the
// underlying [itb.DecryptStreamAuth{N}Cfg] /
// [itb.DecryptStreamAuth3x{N}Cfg] entry point.
func (e *Encryptor) DecryptStreamAuth(ciphertext []byte, emit ChunkFunc) error {
	if e.closed {
		panic(ErrClosed)
	}

	switch e.width {
	case 128:
		if e.Mode == 1 {
			return itb.DecryptStreamAuth128Cfg(e.cfg,
				e.seeds[0].(*itb.Seed128), e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128),
				ciphertext, e.macFunc, emit)
		}
		return itb.DecryptStreamAuth3x128Cfg(e.cfg,
			e.seeds[0].(*itb.Seed128),
			e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128), e.seeds[3].(*itb.Seed128),
			e.seeds[4].(*itb.Seed128), e.seeds[5].(*itb.Seed128), e.seeds[6].(*itb.Seed128),
			ciphertext, e.macFunc, emit)
	case 256:
		if e.Mode == 1 {
			return itb.DecryptStreamAuth256Cfg(e.cfg,
				e.seeds[0].(*itb.Seed256), e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256),
				ciphertext, e.macFunc, emit)
		}
		return itb.DecryptStreamAuth3x256Cfg(e.cfg,
			e.seeds[0].(*itb.Seed256),
			e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256), e.seeds[3].(*itb.Seed256),
			e.seeds[4].(*itb.Seed256), e.seeds[5].(*itb.Seed256), e.seeds[6].(*itb.Seed256),
			ciphertext, e.macFunc, emit)
	case 512:
		if e.Mode == 1 {
			return itb.DecryptStreamAuth512Cfg(e.cfg,
				e.seeds[0].(*itb.Seed512), e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512),
				ciphertext, e.macFunc, emit)
		}
		return itb.DecryptStreamAuth3x512Cfg(e.cfg,
			e.seeds[0].(*itb.Seed512),
			e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512), e.seeds[3].(*itb.Seed512),
			e.seeds[4].(*itb.Seed512), e.seeds[5].(*itb.Seed512), e.seeds[6].(*itb.Seed512),
			ciphertext, e.macFunc, emit)
	}
	panic(fmt.Sprintf("itb/easy: unsupported primitive width %d", e.width))
}

// streamChunkPixels parses the per-instance W and H header fields out
// of a wire chunk and returns the cumulative-offset advance W * H. The
// header layout is governed by [Encryptor.NonceBits]; a chunk produced
// under a non-default nonce size resolves correctly because the nonce
// length is read from the encryptor's own per-instance configuration
// rather than the process-wide [itb.GetNonceBits] state.
func (e *Encryptor) streamChunkPixels(chunk []byte) (uint64, error) {
	headerSz := e.HeaderSize()
	if len(chunk) < headerSz {
		return 0, fmt.Errorf("itb/easy: chunk too short for header")
	}
	nonceLen := headerSz - 4
	width := uint64(binary.BigEndian.Uint16(chunk[nonceLen:]))
	height := uint64(binary.BigEndian.Uint16(chunk[nonceLen+2:]))
	if width == 0 || height == 0 {
		return 0, fmt.Errorf("itb/easy: invalid dimensions %dx%d", width, height)
	}
	return width * height, nil
}

// readStreamChunk pulls one complete wire chunk from r. The fixed
// header is read first; W * H is parsed via [Encryptor.ParseChunkLen]
// to learn the chunk's total length, and the body is then drawn to
// match. Returns [io.EOF] on a clean end-of-stream when no header
// bytes are available, and an error on partial-header / partial-body
// truncation.
func (e *Encryptor) readStreamChunk(r io.Reader) ([]byte, error) {
	headerSz := e.HeaderSize()
	header := make([]byte, headerSz)
	n, err := io.ReadFull(r, header)
	if err == io.EOF && n == 0 {
		return nil, io.EOF
	}
	if err == io.ErrUnexpectedEOF {
		return nil, fmt.Errorf("itb/easy: short header read: %d of %d bytes", n, headerSz)
	}
	if err != nil {
		return nil, err
	}
	chunkLen, lerr := e.ParseChunkLen(header)
	if lerr != nil {
		return nil, lerr
	}
	full := make([]byte, chunkLen)
	copy(full, header)
	body := full[headerSz:]
	if _, berr := io.ReadFull(r, body); berr != nil {
		if berr == io.EOF || berr == io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("itb/easy: short body read: %d of %d bytes", len(body), len(body))
		}
		return nil, berr
	}
	return full, nil
}

// EncryptStreamAuthIO encrypts a Streaming AEAD transcript driven by
// io.Reader / io.Writer. The helper generates a fresh 32-byte stream
// anchor at stream start, writes it as the wire prefix, then drains
// src in chunkSize-byte windows and emits each per-chunk wire payload
// through dst. The terminating chunk carries finalFlag = true; an
// empty src draws and emits the streamID prefix followed by a single
// zero-length terminating chunk.
//
// chunkSize must be > 0; a zero or negative value falls back to the
// encryptor's [Encryptor.SetChunkSize] override (or
// [itb.DefaultChunkSize] when unset). Plaintext is read from src in
// streaming windows of the resolved chunk size, so callers can
// process inputs that exceed available RAM.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns the first non-nil error from the underlying per-chunk
// [Encryptor.EncryptStreamAuthenticated] call, the writer's Write,
// or the reader's Read.
func (e *Encryptor) EncryptStreamAuthIO(src io.Reader, dst io.Writer, chunkSize int) error {
	if e.closed {
		panic(ErrClosed)
	}
	if chunkSize <= 0 {
		return fmt.Errorf("itb/easy: chunkSize must be > 0")
	}
	cs := chunkSize
	e.firstEncryptCalled = true

	var streamID [32]byte
	if _, err := rand.Read(streamID[:]); err != nil {
		return fmt.Errorf("itb/easy: crypto/rand: %w", err)
	}
	if _, err := dst.Write(streamID[:]); err != nil {
		return err
	}

	stage := make([]byte, cs)
	var pending []byte
	var cumulative uint64

	for {
		n, rerr := io.ReadFull(src, stage)
		if rerr == io.EOF {
			break
		}
		shortRead := false
		if rerr == io.ErrUnexpectedEOF {
			// Final partial window — accept the bytes drawn and treat
			// the next iteration's read as EOF.
			shortRead = true
		} else if rerr != nil {
			return rerr
		}

		if pending != nil {
			chunk, encErr := e.EncryptStreamAuthenticated(pending, streamID, cumulative, false)
			if encErr != nil {
				return encErr
			}
			pixels, pxErr := e.streamChunkPixels(chunk)
			if pxErr != nil {
				return pxErr
			}
			if _, werr := dst.Write(chunk); werr != nil {
				return werr
			}
			cumulative += pixels
		}
		held := make([]byte, n)
		copy(held, stage[:n])
		pending = held

		if shortRead {
			break
		}
	}

	if pending == nil {
		// Empty input — emit the single zero-length terminating chunk.
		chunk, encErr := e.EncryptStreamAuthenticated(nil, streamID, 0, true)
		if encErr != nil {
			return encErr
		}
		if _, werr := dst.Write(chunk); werr != nil {
			return werr
		}
		return nil
	}
	chunk, encErr := e.EncryptStreamAuthenticated(pending, streamID, cumulative, true)
	if encErr != nil {
		return encErr
	}
	if _, werr := dst.Write(chunk); werr != nil {
		return werr
	}
	return nil
}

// DecryptStreamAuthIO decrypts a Streaming AEAD transcript driven by
// io.Reader / io.Writer. Reads the leading 32-byte stream anchor from
// src, walks the remaining bytes one chunk at a time using the
// per-instance header size, dispatches each chunk through
// [Encryptor.DecryptStreamAuthenticated] with the running cumulative
// pixel offset, and writes recovered plaintext to dst. Returns
// [itb.ErrStreamTruncated] when the transcript exhausts without a
// terminating chunk and [itb.ErrStreamAfterFinal] when chunks follow
// a terminator.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns the first non-nil error from the underlying per-chunk
// [Encryptor.DecryptStreamAuthenticated] call, the writer's Write,
// or the reader's Read.
func (e *Encryptor) DecryptStreamAuthIO(src io.Reader, dst io.Writer) error {
	if e.closed {
		panic(ErrClosed)
	}

	var streamID [32]byte
	if _, err := io.ReadFull(src, streamID[:]); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return fmt.Errorf("itb/easy: stream too short for stream prefix")
		}
		return err
	}

	var cumulative uint64
	seenFinal := false
	for {
		chunk, cerr := e.readStreamChunk(src)
		if cerr == io.EOF {
			break
		}
		if cerr != nil {
			return cerr
		}
		if seenFinal {
			return itb.ErrStreamAfterFinal
		}
		plain, finalFlag, decErr := e.DecryptStreamAuthenticated(chunk, streamID, cumulative)
		if decErr != nil {
			return decErr
		}
		pixels, pxErr := e.streamChunkPixels(chunk)
		if pxErr != nil {
			return pxErr
		}
		if _, werr := dst.Write(plain); werr != nil {
			return werr
		}
		cumulative += pixels
		if finalFlag {
			seenFinal = true
		}
	}
	if !seenFinal {
		return itb.ErrStreamTruncated
	}
	return nil
}
