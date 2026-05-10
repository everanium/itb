package easy

import (
	"fmt"
	"io"

	"github.com/everanium/itb"
)

// ChunkFunc is the per-chunk callback driven by [Encryptor.EncryptStream]
// and [Encryptor.DecryptStream]. The encryptor invokes ChunkFunc once
// per output chunk in stream order; returning a non-nil error from the
// callback aborts the stream and propagates the error to the caller.
type ChunkFunc func(chunk []byte) error

// EncryptStream encrypts plaintext in chunks, invoking emit once per
// output chunk in stream order. The chunk-size override is the
// encryptor's chunk field (set via [Encryptor.SetChunkSize]; 0 =
// auto-detect via [itb.ChunkSize]).
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns the first non-nil error from the chunk emitter or from
// the underlying [itb.EncryptStream{N}Cfg] /
// [itb.EncryptStream3x{N}Cfg] entry point.
func (e *Encryptor) EncryptStream(plaintext []byte, emit ChunkFunc) error {
	if e.closed {
		panic(ErrClosed)
	}
	e.firstEncryptCalled = true

	switch e.width {
	case 128:
		if e.Mode == 1 {
			return itb.EncryptStream128Cfg(e.cfg,
				e.seeds[0].(*itb.Seed128), e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128),
				plaintext, e.chunk, emit)
		}
		return itb.EncryptStream3x128Cfg(e.cfg,
			e.seeds[0].(*itb.Seed128),
			e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128), e.seeds[3].(*itb.Seed128),
			e.seeds[4].(*itb.Seed128), e.seeds[5].(*itb.Seed128), e.seeds[6].(*itb.Seed128),
			plaintext, e.chunk, emit)
	case 256:
		if e.Mode == 1 {
			return itb.EncryptStream256Cfg(e.cfg,
				e.seeds[0].(*itb.Seed256), e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256),
				plaintext, e.chunk, emit)
		}
		return itb.EncryptStream3x256Cfg(e.cfg,
			e.seeds[0].(*itb.Seed256),
			e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256), e.seeds[3].(*itb.Seed256),
			e.seeds[4].(*itb.Seed256), e.seeds[5].(*itb.Seed256), e.seeds[6].(*itb.Seed256),
			plaintext, e.chunk, emit)
	case 512:
		if e.Mode == 1 {
			return itb.EncryptStream512Cfg(e.cfg,
				e.seeds[0].(*itb.Seed512), e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512),
				plaintext, e.chunk, emit)
		}
		return itb.EncryptStream3x512Cfg(e.cfg,
			e.seeds[0].(*itb.Seed512),
			e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512), e.seeds[3].(*itb.Seed512),
			e.seeds[4].(*itb.Seed512), e.seeds[5].(*itb.Seed512), e.seeds[6].(*itb.Seed512),
			plaintext, e.chunk, emit)
	}
	panic(fmt.Sprintf("itb/easy: unsupported primitive width %d", e.width))
}

// DecryptStream walks a concatenated stream of ciphertext chunks
// produced by [Encryptor.EncryptStream], invoking emit once per
// recovered plaintext chunk in stream order. The chunk-size override
// does not apply on the decrypt side — chunk extents are recovered
// from the wire-format header per chunk.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns the first non-nil error from the chunk emitter or from
// the underlying [itb.DecryptStream{N}Cfg] /
// [itb.DecryptStream3x{N}Cfg] entry point. Wrong-seed input on
// non-authenticated streams produces random-looking plaintext per
// chunk rather than an error — non-Auth mode has no failure signal
// by design.
func (e *Encryptor) DecryptStream(ciphertext []byte, emit ChunkFunc) error {
	if e.closed {
		panic(ErrClosed)
	}

	switch e.width {
	case 128:
		if e.Mode == 1 {
			return itb.DecryptStream128Cfg(e.cfg,
				e.seeds[0].(*itb.Seed128), e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128),
				ciphertext, emit)
		}
		return itb.DecryptStream3x128Cfg(e.cfg,
			e.seeds[0].(*itb.Seed128),
			e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128), e.seeds[3].(*itb.Seed128),
			e.seeds[4].(*itb.Seed128), e.seeds[5].(*itb.Seed128), e.seeds[6].(*itb.Seed128),
			ciphertext, emit)
	case 256:
		if e.Mode == 1 {
			return itb.DecryptStream256Cfg(e.cfg,
				e.seeds[0].(*itb.Seed256), e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256),
				ciphertext, emit)
		}
		return itb.DecryptStream3x256Cfg(e.cfg,
			e.seeds[0].(*itb.Seed256),
			e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256), e.seeds[3].(*itb.Seed256),
			e.seeds[4].(*itb.Seed256), e.seeds[5].(*itb.Seed256), e.seeds[6].(*itb.Seed256),
			ciphertext, emit)
	case 512:
		if e.Mode == 1 {
			return itb.DecryptStream512Cfg(e.cfg,
				e.seeds[0].(*itb.Seed512), e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512),
				ciphertext, emit)
		}
		return itb.DecryptStream3x512Cfg(e.cfg,
			e.seeds[0].(*itb.Seed512),
			e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512), e.seeds[3].(*itb.Seed512),
			e.seeds[4].(*itb.Seed512), e.seeds[5].(*itb.Seed512), e.seeds[6].(*itb.Seed512),
			ciphertext, emit)
	}
	panic(fmt.Sprintf("itb/easy: unsupported primitive width %d", e.width))
}

// EncryptStreamIO encrypts a plain (non-authenticated) stream driven
// by io.Reader / io.Writer. Reads up-to-chunkSize-byte windows from
// src, encrypts each non-empty window through the matching
// width-suffixed per-chunk path on the encryptor, and writes the
// resulting wire chunk to dst. Empty src input emits nothing — the
// underlying Single Message path rejects empty plaintext, and the
// streaming helper preserves that semantic by simply not emitting any
// chunk.
//
// chunkSize must be > 0; a zero or negative value yields a BadInput-
// equivalent error before any byte is consumed from src. Plaintext is
// read in streaming windows of the supplied chunk size, so callers
// can process inputs that exceed available RAM.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns the first non-nil error from the underlying per-chunk
// [Encryptor.Encrypt] call, the writer's Write, or the reader's Read.
func (e *Encryptor) EncryptStreamIO(src io.Reader, dst io.Writer, chunkSize int) error {
	if e.closed {
		panic(ErrClosed)
	}
	if chunkSize <= 0 {
		return fmt.Errorf("itb/easy: chunkSize must be > 0")
	}
	e.firstEncryptCalled = true

	stage := make([]byte, chunkSize)
	for {
		n, rerr := io.ReadFull(src, stage)
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil && rerr != io.ErrUnexpectedEOF {
			return rerr
		}
		if n == 0 {
			return nil
		}
		ct, encErr := e.Encrypt(stage[:n])
		if encErr != nil {
			return encErr
		}
		if _, werr := dst.Write(ct); werr != nil {
			return werr
		}
		if rerr == io.ErrUnexpectedEOF {
			return nil
		}
	}
}

// DecryptStreamIO decrypts a plain stream produced by
// [Encryptor.EncryptStreamIO] (or any wire-format-compatible producer
// such as [Encryptor.EncryptStream] / the top-level [itb.EncryptStream]
// family). Reads one chunk at a time using the per-instance header
// size, dispatches the chunk through the matching width-suffixed
// per-chunk decrypt path, and writes the recovered plaintext to dst.
//
// Wrong-seed input on plain (non-authenticated) streams produces
// random-looking plaintext per chunk rather than an error — plain
// mode has no failure signal by design.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns the first non-nil error from the underlying per-chunk
// [Encryptor.Decrypt] call, the writer's Write, or the reader's Read.
func (e *Encryptor) DecryptStreamIO(src io.Reader, dst io.Writer) error {
	if e.closed {
		panic(ErrClosed)
	}

	for {
		chunk, cerr := e.readStreamChunk(src)
		if cerr == io.EOF {
			return nil
		}
		if cerr != nil {
			return cerr
		}
		plain, decErr := e.Decrypt(chunk)
		if decErr != nil {
			return decErr
		}
		if _, werr := dst.Write(plain); werr != nil {
			return werr
		}
	}
}
