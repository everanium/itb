package ctr

import (
	"fmt"
	"runtime"

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

// ivAtInto writes into iv the 16-byte AES-CTR IV positioned blockOff blocks
// past nonce, i.e. nonce interpreted as a big-endian 128-bit counter plus
// blockOff. This matches crypto/cipher CTR's whole-IV big-endian increment, so
// the keystream from cipher.NewCTR(block, iv[:]) equals the original stream's
// block b.
func ivAtInto(iv *[16]byte, nonce []byte, blockOff uint64) {
	copy(iv[:], nonce)
	carry := blockOff
	for i := 15; i >= 0 && carry > 0; i-- {
		sum := uint64(iv[i]) + (carry & 0xff)
		iv[i] = byte(sum)
		carry = (carry >> 8) + (sum >> 8)
	}
}

// discard advances a keystream by n bytes by XORing a stack scratch buffer
// through it and wiping the buffer before return.
func discard(ks Keystream, n int) {
	if n <= 0 {
		return
	}
	var zBuf [256]byte
	for n > 0 {
		step := n
		if step > len(zBuf) {
			step = len(zBuf)
		}
		z := zBuf[:step]
		ks.XORKeyStream(z, z)
		n -= step
	}
	clear(zBuf[:])
	runtime.KeepAlive(&zBuf)
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
	bs, err := streamBlockSize(name)
	if err != nil {
		return nil, err
	}
	blockOff := uint64(byteOffset / bs)
	intra := byteOffset % bs

	// AES-CTR cannot be re-seeked after construction; build it with an
	// offset IV instead via newAESResettableAt so the returned Keystream
	// also implements io.Closer.
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
	case *chaCha20CTR:
		// ChaCha20's block counter is a uint32 (RFC 8439); a silent
		// uint32(blockOff) truncation past 2^32 would reuse keystream
		// bytes, weakening the wrapper's outer-layer format-deniability
		// past ~256 GiB of stream under a single (key, nonce). Inner
		// ITB confidentiality is unaffected by such reuse — the outer
		// cipher is a format-deniability whitener, not the layer that
		// carries confidentiality — but the caller must be told
		// explicitly rather than getting a silently-corrupt keystream.
		// For streams that need to exceed this, choose an outer cipher
		// with a wider counter (AES-128-CTR uses a 128-bit big-endian
		// counter and is practically unlimited for random nonces).
		const chacha20MaxBlock = uint64(1) << 32
		if blockOff >= chacha20MaxBlock {
			_ = c.Close()
			return nil, fmt.Errorf("ctr: chacha20 counter overflow — byteOffset %d requires block index %d ≥ 2^32 (~256 GiB per (key, nonce)); outer-layer format deniability weakens past this seek point, inner ITB confidentiality unaffected. Choose AES-128-CTR outer cipher for streams above this cap", byteOffset, blockOff)
		}
		c.c.SetCounter(uint32(blockOff))
	default:
		return nil, fmt.Errorf("ctr: %s keystream is not seekable", name)
	}
	discard(ks, intra)
	return ks, nil
}
