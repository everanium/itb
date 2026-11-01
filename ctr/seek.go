package ctr

import (
	"fmt"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/hashprf"
)

// streamBlockSize returns the keystream block granularity of the named cipher,
// the unit the counter advances by. Used to split a byte offset into a whole-
// block counter jump plus an intra-block remainder.
func streamBlockSize(name string) (int, error) {
	switch name {
	case hashes.CipherAES128CTR, hashes.CipherSipHash24:
		return 16, nil
	case hashes.CipherChaCha20:
		return 64, nil
	case hashes.CipherAreion256, hashes.CipherAreion512, hashes.CipherBLAKE2b256, hashes.CipherBLAKE2b512, hashes.CipherBLAKE2s, hashes.CipherBLAKE3:
		return hashprf.BlockSize(name)
	default:
		return 0, fmt.Errorf("ctr: unknown cipher %q", name)
	}
}

// NewAt returns a keystream positioned so its first output byte is the byte at
// byteOffset of the (name, key, nonce) stream produced by New. It lets one
// logical stream be XORed in parallel: each worker seeks to its chunk's byte
// offset and emits only its slice. The seek is O(1) — a whole-block counter
// jump plus an intra-block remainder skip of fewer than one block's bytes —
// never an O(byteOffset) discard.
//
// byteOffset must be >= 0; byteOffset == 0 is exactly New.
func NewAt(name string, key, nonce []byte, byteOffset int) (Keystream, error) {
	if byteOffset < 0 {
		return nil, fmt.Errorf("ctr: negative byteOffset %d", byteOffset)
	}
	if byteOffset == 0 {
		return New(name, key, nonce)
	}
	if _, err := streamBlockSize(name); err != nil {
		return nil, err
	}

	if name == hashes.CipherAES128CTR {
		ks, err := newAESResettableAt(key, nonce, byteOffset)
		if err != nil {
			return nil, err
		}
		return ks, nil
	}

	// All other ciphers expose a counter the constructor leaves at 0; jump it
	// to blockOff, then skip the intra-block remainder.
	ks, err := New(name, key, nonce)
	if err != nil {
		return nil, err
	}
	switch c := ks.(type) {
	case *sipCTR:
		if err := c.ResetCounter(byteOffset); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	case *prfHashCTR:
		if err := c.ResetCounter(byteOffset); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	case *prfHashCTRBatch:
		if err := c.ResetCounter(byteOffset); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	case *chaCha20Resettable:
		if err := c.ResetCounter(byteOffset); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	default:
		return nil, fmt.Errorf("ctr: %s keystream is not seekable", name)
	}
}
