package easy

import (
	"fmt"

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

// EncryptStreamAuth is the authenticated streaming counterpart to
// [Encryptor.EncryptStream]. The signature is reserved so v1 callers
// can interface-detect availability; the body returns
// [ErrStreamAuthNotImplemented] until the streaming-AEAD design
// ships.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) EncryptStreamAuth(plaintext []byte, emit ChunkFunc) error {
	if e.closed {
		panic(ErrClosed)
	}
	return ErrStreamAuthNotImplemented
}

// DecryptStreamAuth is the authenticated streaming counterpart to
// [Encryptor.DecryptStream]. The signature is reserved so v1 callers
// can interface-detect availability; the body returns
// [ErrStreamAuthNotImplemented] until the streaming-AEAD design
// ships.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) DecryptStreamAuth(ciphertext []byte, emit ChunkFunc) error {
	if e.closed {
		panic(ErrClosed)
	}
	return ErrStreamAuthNotImplemented
}
