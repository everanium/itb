package easy

import (
	"fmt"

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
