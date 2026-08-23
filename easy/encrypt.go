package easy

import (
	"fmt"

	"github.com/everanium/itb"
)

// Encrypt encrypts plaintext using the configured primitive /
// key_bits / per-instance Config snapshot. Plain mode — does NOT
// compute or attach a MAC tag; for authenticated encryption use
// [Encryptor.EncryptAuth].
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns an error for all other failure paths (CSPRNG failure,
// data too large, internal sizing error) — same error shape as the
// underlying [itb.Encrypt3x{N}] entry points.
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if e.closed {
		panic(ErrClosed)
	}

	switch e.width {
	case 128:
		return itb.Encrypt3x128Cfg(e.cfg,
			e.seeds[0].(*itb.Seed128), e.seeds[1].(*itb.Seed128),
			e.seeds[2].(*itb.Seed128), e.seeds[3].(*itb.Seed128), e.seeds[4].(*itb.Seed128),
			e.seeds[5].(*itb.Seed128), e.seeds[6].(*itb.Seed128), e.seeds[7].(*itb.Seed128),
			plaintext)
	case 256:
		return itb.Encrypt3x256Cfg(e.cfg,
			e.seeds[0].(*itb.Seed256), e.seeds[1].(*itb.Seed256),
			e.seeds[2].(*itb.Seed256), e.seeds[3].(*itb.Seed256), e.seeds[4].(*itb.Seed256),
			e.seeds[5].(*itb.Seed256), e.seeds[6].(*itb.Seed256), e.seeds[7].(*itb.Seed256),
			plaintext)
	case 512:
		return itb.Encrypt3x512Cfg(e.cfg,
			e.seeds[0].(*itb.Seed512), e.seeds[1].(*itb.Seed512),
			e.seeds[2].(*itb.Seed512), e.seeds[3].(*itb.Seed512), e.seeds[4].(*itb.Seed512),
			e.seeds[5].(*itb.Seed512), e.seeds[6].(*itb.Seed512), e.seeds[7].(*itb.Seed512),
			plaintext)
	}
	panic(fmt.Sprintf("itb/easy: unsupported primitive width %d", e.width))
}

// EncryptAuth encrypts plaintext and attaches a MAC tag using the
// encryptor's per-instance Config snapshot and the MAC closure
// bound at construction. Authenticated mode — produces a ciphertext
// the receiver must validate via [Encryptor.DecryptAuth] before
// trusting the recovered plaintext.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns an error for the same failure paths as
// [itb.EncryptAuthenticated3x{N}].
func (e *Encryptor) EncryptAuth(plaintext []byte) ([]byte, error) {
	if e.closed {
		panic(ErrClosed)
	}

	switch e.width {
	case 128:
		return itb.EncryptAuthenticated3x128Cfg(e.cfg,
			e.seeds[0].(*itb.Seed128), e.seeds[1].(*itb.Seed128),
			e.seeds[2].(*itb.Seed128), e.seeds[3].(*itb.Seed128), e.seeds[4].(*itb.Seed128),
			e.seeds[5].(*itb.Seed128), e.seeds[6].(*itb.Seed128), e.seeds[7].(*itb.Seed128),
			plaintext, e.macFunc)
	case 256:
		return itb.EncryptAuthenticated3x256Cfg(e.cfg,
			e.seeds[0].(*itb.Seed256), e.seeds[1].(*itb.Seed256),
			e.seeds[2].(*itb.Seed256), e.seeds[3].(*itb.Seed256), e.seeds[4].(*itb.Seed256),
			e.seeds[5].(*itb.Seed256), e.seeds[6].(*itb.Seed256), e.seeds[7].(*itb.Seed256),
			plaintext, e.macFunc)
	case 512:
		return itb.EncryptAuthenticated3x512Cfg(e.cfg,
			e.seeds[0].(*itb.Seed512), e.seeds[1].(*itb.Seed512),
			e.seeds[2].(*itb.Seed512), e.seeds[3].(*itb.Seed512), e.seeds[4].(*itb.Seed512),
			e.seeds[5].(*itb.Seed512), e.seeds[6].(*itb.Seed512), e.seeds[7].(*itb.Seed512),
			plaintext, e.macFunc)
	}
	panic(fmt.Sprintf("itb/easy: unsupported primitive width %d", e.width))
}

// EncryptStreamAuthenticated encrypts a single Streaming AEAD chunk
// under the encryptor's bound seeds + MAC, with the streaming binding
// components (streamID, cumulativePixelOffset, finalFlag) included in
// the per-chunk MAC input. The returned chunk is one self-contained
// authenticated wire chunk; the caller composes streams by writing a
// 32-byte CSPRNG streamID prefix once at stream start, then invoking
// this method per chunk with the running cumulativePixelOffset and
// finalFlag = true on the terminating chunk only.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns an error for the same failure paths as
// [itb.EncryptStreamAuthenticated3x{N}].
func (e *Encryptor) EncryptStreamAuthenticated(
	plaintext []byte,
	streamID [32]byte,
	cumulativePixelOffset uint64,
	finalFlag bool,
) ([]byte, error) {
	if e.closed {
		panic(ErrClosed)
	}

	switch e.width {
	case 128:
		return itb.EncryptStreamAuthenticated3x128Cfg(e.cfg,
			e.seeds[0].(*itb.Seed128), e.seeds[1].(*itb.Seed128),
			e.seeds[2].(*itb.Seed128), e.seeds[3].(*itb.Seed128), e.seeds[4].(*itb.Seed128),
			e.seeds[5].(*itb.Seed128), e.seeds[6].(*itb.Seed128), e.seeds[7].(*itb.Seed128),
			plaintext, e.macFunc, streamID, cumulativePixelOffset, finalFlag)
	case 256:
		return itb.EncryptStreamAuthenticated3x256Cfg(e.cfg,
			e.seeds[0].(*itb.Seed256), e.seeds[1].(*itb.Seed256),
			e.seeds[2].(*itb.Seed256), e.seeds[3].(*itb.Seed256), e.seeds[4].(*itb.Seed256),
			e.seeds[5].(*itb.Seed256), e.seeds[6].(*itb.Seed256), e.seeds[7].(*itb.Seed256),
			plaintext, e.macFunc, streamID, cumulativePixelOffset, finalFlag)
	case 512:
		return itb.EncryptStreamAuthenticated3x512Cfg(e.cfg,
			e.seeds[0].(*itb.Seed512), e.seeds[1].(*itb.Seed512),
			e.seeds[2].(*itb.Seed512), e.seeds[3].(*itb.Seed512), e.seeds[4].(*itb.Seed512),
			e.seeds[5].(*itb.Seed512), e.seeds[6].(*itb.Seed512), e.seeds[7].(*itb.Seed512),
			plaintext, e.macFunc, streamID, cumulativePixelOffset, finalFlag)
	}
	panic(fmt.Sprintf("itb/easy: unsupported primitive width %d", e.width))
}
