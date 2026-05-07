package easy

import (
	"fmt"

	"github.com/everanium/itb"
)

// Decrypt decrypts ciphertext produced by [Encryptor.Encrypt] using
// the encryptor's per-instance Config snapshot. Plain mode — never
// performs MAC verification; for authenticated decryption use
// [Encryptor.DecryptAuth].
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns an error only on structural issues (header parse,
// dimension validation); a wrong-seed input produces random-looking
// plaintext rather than an error — non-Auth mode has no failure
// signal by design.
func (e *Encryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	if e.closed {
		panic(ErrClosed)
	}

	switch e.width {
	case 128:
		if e.Mode == 1 {
			return itb.Decrypt128Cfg(e.cfg,
				e.seeds[0].(*itb.Seed128), e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128),
				ciphertext)
		}
		return itb.Decrypt3x128Cfg(e.cfg,
			e.seeds[0].(*itb.Seed128),
			e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128), e.seeds[3].(*itb.Seed128),
			e.seeds[4].(*itb.Seed128), e.seeds[5].(*itb.Seed128), e.seeds[6].(*itb.Seed128),
			ciphertext)
	case 256:
		if e.Mode == 1 {
			return itb.Decrypt256Cfg(e.cfg,
				e.seeds[0].(*itb.Seed256), e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256),
				ciphertext)
		}
		return itb.Decrypt3x256Cfg(e.cfg,
			e.seeds[0].(*itb.Seed256),
			e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256), e.seeds[3].(*itb.Seed256),
			e.seeds[4].(*itb.Seed256), e.seeds[5].(*itb.Seed256), e.seeds[6].(*itb.Seed256),
			ciphertext)
	case 512:
		if e.Mode == 1 {
			return itb.Decrypt512Cfg(e.cfg,
				e.seeds[0].(*itb.Seed512), e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512),
				ciphertext)
		}
		return itb.Decrypt3x512Cfg(e.cfg,
			e.seeds[0].(*itb.Seed512),
			e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512), e.seeds[3].(*itb.Seed512),
			e.seeds[4].(*itb.Seed512), e.seeds[5].(*itb.Seed512), e.seeds[6].(*itb.Seed512),
			ciphertext)
	}
	panic(fmt.Sprintf("itb/easy: unsupported primitive width %d", e.width))
}

// DecryptAuth verifies and decrypts ciphertext produced by
// [Encryptor.EncryptAuth]. The MAC tag is checked against the
// encryptor's bound MAC closure; mismatch yields the standard
// "MAC verification failed" error from the underlying
// [itb.DecryptAuthenticated{N}] / [itb.DecryptAuthenticated3x{N}]
// entry point.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) DecryptAuth(ciphertext []byte) ([]byte, error) {
	if e.closed {
		panic(ErrClosed)
	}

	switch e.width {
	case 128:
		if e.Mode == 1 {
			return itb.DecryptAuthenticated128Cfg(e.cfg,
				e.seeds[0].(*itb.Seed128), e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128),
				ciphertext, e.macFunc)
		}
		return itb.DecryptAuthenticated3x128Cfg(e.cfg,
			e.seeds[0].(*itb.Seed128),
			e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128), e.seeds[3].(*itb.Seed128),
			e.seeds[4].(*itb.Seed128), e.seeds[5].(*itb.Seed128), e.seeds[6].(*itb.Seed128),
			ciphertext, e.macFunc)
	case 256:
		if e.Mode == 1 {
			return itb.DecryptAuthenticated256Cfg(e.cfg,
				e.seeds[0].(*itb.Seed256), e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256),
				ciphertext, e.macFunc)
		}
		return itb.DecryptAuthenticated3x256Cfg(e.cfg,
			e.seeds[0].(*itb.Seed256),
			e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256), e.seeds[3].(*itb.Seed256),
			e.seeds[4].(*itb.Seed256), e.seeds[5].(*itb.Seed256), e.seeds[6].(*itb.Seed256),
			ciphertext, e.macFunc)
	case 512:
		if e.Mode == 1 {
			return itb.DecryptAuthenticated512Cfg(e.cfg,
				e.seeds[0].(*itb.Seed512), e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512),
				ciphertext, e.macFunc)
		}
		return itb.DecryptAuthenticated3x512Cfg(e.cfg,
			e.seeds[0].(*itb.Seed512),
			e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512), e.seeds[3].(*itb.Seed512),
			e.seeds[4].(*itb.Seed512), e.seeds[5].(*itb.Seed512), e.seeds[6].(*itb.Seed512),
			ciphertext, e.macFunc)
	}
	panic(fmt.Sprintf("itb/easy: unsupported primitive width %d", e.width))
}

// DecryptStreamAuthenticated decrypts a single Streaming AEAD chunk
// under the encryptor's bound seeds + MAC. The caller supplies the
// streamID (extracted from the 32-byte stream prefix at the start of
// the wire transcript) and the running cumulativePixelOffset
// (recomputed from the W*H header of every preceding chunk). The
// recovered finalFlag indicates whether this chunk is the
// terminator (true) or a non-terminal chunk (false).
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns an error on MAC verification failure or the same failure
// paths as [itb.DecryptStreamAuthenticated{N}] /
// [itb.DecryptStreamAuthenticated3x{N}].
func (e *Encryptor) DecryptStreamAuthenticated(
	chunkData []byte,
	streamID [32]byte,
	cumulativePixelOffset uint64,
) (plaintext []byte, finalFlag bool, err error) {
	if e.closed {
		panic(ErrClosed)
	}

	switch e.width {
	case 128:
		if e.Mode == 1 {
			return itb.DecryptStreamAuthenticated128Cfg(e.cfg,
				e.seeds[0].(*itb.Seed128), e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128),
				chunkData, e.macFunc, streamID, cumulativePixelOffset)
		}
		return itb.DecryptStreamAuthenticated3x128Cfg(e.cfg,
			e.seeds[0].(*itb.Seed128),
			e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128), e.seeds[3].(*itb.Seed128),
			e.seeds[4].(*itb.Seed128), e.seeds[5].(*itb.Seed128), e.seeds[6].(*itb.Seed128),
			chunkData, e.macFunc, streamID, cumulativePixelOffset)
	case 256:
		if e.Mode == 1 {
			return itb.DecryptStreamAuthenticated256Cfg(e.cfg,
				e.seeds[0].(*itb.Seed256), e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256),
				chunkData, e.macFunc, streamID, cumulativePixelOffset)
		}
		return itb.DecryptStreamAuthenticated3x256Cfg(e.cfg,
			e.seeds[0].(*itb.Seed256),
			e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256), e.seeds[3].(*itb.Seed256),
			e.seeds[4].(*itb.Seed256), e.seeds[5].(*itb.Seed256), e.seeds[6].(*itb.Seed256),
			chunkData, e.macFunc, streamID, cumulativePixelOffset)
	case 512:
		if e.Mode == 1 {
			return itb.DecryptStreamAuthenticated512Cfg(e.cfg,
				e.seeds[0].(*itb.Seed512), e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512),
				chunkData, e.macFunc, streamID, cumulativePixelOffset)
		}
		return itb.DecryptStreamAuthenticated3x512Cfg(e.cfg,
			e.seeds[0].(*itb.Seed512),
			e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512), e.seeds[3].(*itb.Seed512),
			e.seeds[4].(*itb.Seed512), e.seeds[5].(*itb.Seed512), e.seeds[6].(*itb.Seed512),
			chunkData, e.macFunc, streamID, cumulativePixelOffset)
	}
	panic(fmt.Sprintf("itb/easy: unsupported primitive width %d", e.width))
}
