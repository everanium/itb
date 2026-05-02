package easy

import (
	"fmt"

	"github.com/everanium/itb"
)

// Encrypt encrypts plaintext using the configured primitive /
// key_bits / Mode and the encryptor's per-instance Config snapshot.
// Plain mode — does NOT compute or attach a MAC tag; for
// authenticated encryption use [Encryptor.EncryptAuth].
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
// Returns an error for all other failure paths (CSPRNG failure,
// data too large, internal sizing error) — same error shape as the
// underlying [itb.Encrypt128] / [itb.Encrypt256] / [itb.Encrypt512] /
// [itb.Encrypt3x{N}] entry points.
//
// Marks the encryptor as having produced ciphertext on the first
// successful call, after which [Encryptor.SetLockSeed] is rejected
// (the bit-permutation derivation path cannot change mid-session
// without breaking decryptability of pre-switch ciphertext).
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, error) {
	if e.closed {
		panic(ErrClosed)
	}
	e.firstEncryptCalled = true

	switch e.width {
	case 128:
		if e.Mode == 1 {
			return itb.Encrypt128Cfg(e.cfg,
				e.seeds[0].(*itb.Seed128), e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128),
				plaintext)
		}
		return itb.Encrypt3x128Cfg(e.cfg,
			e.seeds[0].(*itb.Seed128),
			e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128), e.seeds[3].(*itb.Seed128),
			e.seeds[4].(*itb.Seed128), e.seeds[5].(*itb.Seed128), e.seeds[6].(*itb.Seed128),
			plaintext)
	case 256:
		if e.Mode == 1 {
			return itb.Encrypt256Cfg(e.cfg,
				e.seeds[0].(*itb.Seed256), e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256),
				plaintext)
		}
		return itb.Encrypt3x256Cfg(e.cfg,
			e.seeds[0].(*itb.Seed256),
			e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256), e.seeds[3].(*itb.Seed256),
			e.seeds[4].(*itb.Seed256), e.seeds[5].(*itb.Seed256), e.seeds[6].(*itb.Seed256),
			plaintext)
	case 512:
		if e.Mode == 1 {
			return itb.Encrypt512Cfg(e.cfg,
				e.seeds[0].(*itb.Seed512), e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512),
				plaintext)
		}
		return itb.Encrypt3x512Cfg(e.cfg,
			e.seeds[0].(*itb.Seed512),
			e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512), e.seeds[3].(*itb.Seed512),
			e.seeds[4].(*itb.Seed512), e.seeds[5].(*itb.Seed512), e.seeds[6].(*itb.Seed512),
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
// [itb.EncryptAuthenticated128] / [itb.EncryptAuthenticated256] /
// [itb.EncryptAuthenticated512] / [itb.EncryptAuthenticated3x{N}].
func (e *Encryptor) EncryptAuth(plaintext []byte) ([]byte, error) {
	if e.closed {
		panic(ErrClosed)
	}
	e.firstEncryptCalled = true

	switch e.width {
	case 128:
		if e.Mode == 1 {
			return itb.EncryptAuthenticated128Cfg(e.cfg,
				e.seeds[0].(*itb.Seed128), e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128),
				plaintext, e.macFunc)
		}
		return itb.EncryptAuthenticated3x128Cfg(e.cfg,
			e.seeds[0].(*itb.Seed128),
			e.seeds[1].(*itb.Seed128), e.seeds[2].(*itb.Seed128), e.seeds[3].(*itb.Seed128),
			e.seeds[4].(*itb.Seed128), e.seeds[5].(*itb.Seed128), e.seeds[6].(*itb.Seed128),
			plaintext, e.macFunc)
	case 256:
		if e.Mode == 1 {
			return itb.EncryptAuthenticated256Cfg(e.cfg,
				e.seeds[0].(*itb.Seed256), e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256),
				plaintext, e.macFunc)
		}
		return itb.EncryptAuthenticated3x256Cfg(e.cfg,
			e.seeds[0].(*itb.Seed256),
			e.seeds[1].(*itb.Seed256), e.seeds[2].(*itb.Seed256), e.seeds[3].(*itb.Seed256),
			e.seeds[4].(*itb.Seed256), e.seeds[5].(*itb.Seed256), e.seeds[6].(*itb.Seed256),
			plaintext, e.macFunc)
	case 512:
		if e.Mode == 1 {
			return itb.EncryptAuthenticated512Cfg(e.cfg,
				e.seeds[0].(*itb.Seed512), e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512),
				plaintext, e.macFunc)
		}
		return itb.EncryptAuthenticated3x512Cfg(e.cfg,
			e.seeds[0].(*itb.Seed512),
			e.seeds[1].(*itb.Seed512), e.seeds[2].(*itb.Seed512), e.seeds[3].(*itb.Seed512),
			e.seeds[4].(*itb.Seed512), e.seeds[5].(*itb.Seed512), e.seeds[6].(*itb.Seed512),
			plaintext, e.macFunc)
	}
	panic(fmt.Sprintf("itb/easy: unsupported primitive width %d", e.width))
}
