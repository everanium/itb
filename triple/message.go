package triple

import (
	"bytes"
	"errors"

	"github.com/everanium/itb"
)

// ErrProfileNoCipher is returned by [Pipeline.EncryptMessage] /
// [Pipeline.DecryptMessage] when the [Pipeline]'s resolved profile
// mode does not expose ANY cipher surface — the shipped blob-only
// profile ([ProfileBlobTripleMACV1]) is the current sole trigger:
// its role is to bundle session state on the wire, not to encrypt or
// decrypt payload bytes.
//
// Distinct from [ErrProfileNotStreaming]: the streaming guard rejects
// Single Message + blob-only profiles from [Pipeline.EncryptStream] /
// [Pipeline.DecryptStream] because those profiles surface their cipher
// path through [Pipeline.EncryptMessage] / [Pipeline.DecryptMessage]
// instead (or through nothing at all, for blob-only). The message
// guard rejects only the blob-only profile — Single Message and
// Streaming profiles both accept message-shape calls, since the byte
// shape produced by [Pipeline.EncryptStream] on a Streaming profile is
// identical to the byte shape produced by [Pipeline.EncryptMessage]
// when the plaintext fits in one chunk.
//
// The sentinel lives beside its check site here rather than in
// [pipeline.go]'s sentinel block since it is scoped to the message
// surface — colocates a guard's error with the guard itself.
var ErrProfileNoCipher = errors.New("triple: profile does not expose any cipher surface")

// EncryptMessage encrypts a single message and returns its wire bytes.
// Convenience wrapper around the same underlying cipher path
// [Pipeline.EncryptStream] uses: the plaintext feeds a
// [bytes.Reader], the wire accumulates in a [bytes.Buffer], and the
// full triple chain (parallax encrypt-Reader → itb Triple 8-seed
// Streaming AEAD (or Non-AEAD) → wrapper wrap-Writer) runs against
// those two ends. The Single Message vs Streaming distinction is a
// naming / UX choice — the byte shape is a stream that happens to fit
// in a single chunk when the plaintext is short.
//
// Accepted profile modes: Streaming AEAD, Streaming Non-AEAD, Single
// Message MAC, Single Message No MAC. The blob-only profile has no
// cipher surface and returns [ErrProfileNoCipher].
//
// Concurrent-safe on one [*Pipeline]: per-call state (the reader, the
// buffer, per-chunk scratch inside the itb IO entry) lives on the
// caller's stack, and the Pipeline's post-[Init] cipher-relevant state
// is read-only. Multiple goroutines may call EncryptMessage against
// the same [*Pipeline] simultaneously.
//
// Empty plaintext is accepted: the returned wire is the envelope +
// container floor size for the Pipeline's width and nonce width.
//
// Returns [ErrClosed] when [Pipeline.Close] has already run;
// [ErrProfileNoCipher] when the resolved profile mode is blob-only.
func (p *Pipeline) EncryptMessage(plaintext []byte) ([]byte, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	if hasNoCipherSurface(p.resolved.mode) {
		return nil, ErrProfileNoCipher
	}

	var wire bytes.Buffer
	// Pre-size to the ciphertext-expansion upper bound so the wire
	// accumulation never re-grows mid-encrypt; growth from zero
	// capacity costs several allocation+copy cycles at MiB payloads.
	wire.Grow(len(plaintext) + len(plaintext)/4 + 65536)
	innerSrc, innerDst, closeFn, err := buildEncryptChain(p, bytes.NewReader(plaintext), &wire)
	if err != nil {
		return nil, err
	}

	var cipherErr error
	if p.macFunc != nil {
		cipherErr = itb.EncryptStreamAuth3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			innerSrc, innerDst, p.macFunc, p.resolved.chunkSize,
		)
	} else {
		cipherErr = itb.EncryptStream3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			innerSrc, innerDst, p.resolved.chunkSize,
		)
	}
	if err := joinCloseError(cipherErr, closeFn()); err != nil {
		return nil, err
	}
	return wire.Bytes(), nil
}

// DecryptMessage is the receive-side counterpart of
// [Pipeline.EncryptMessage]. Feeds the wire bytes through a
// [bytes.Reader] into the reverse triple chain (wrapper
// unwrap-Reader → itb Triple 8-seed Streaming AEAD (or Non-AEAD)
// decrypt → parallax decrypt-Writer) and returns the accumulated
// plaintext.
//
// Same concurrency posture as [Pipeline.EncryptMessage]: safe for
// concurrent invocation on one [*Pipeline]. Wire bytes produced by
// [Pipeline.EncryptStream] on a Streaming profile are consumable here
// as long as the profile mode matches (identical byte shape); wire
// bytes produced by EncryptMessage are consumable by
// [Pipeline.DecryptStream] on the same profile provided the profile
// is a Streaming profile (Single Message profiles reject
// [Pipeline.DecryptStream] with [ErrProfileNotStreaming]).
//
// Returns [ErrClosed] when [Pipeline.Close] has already run;
// [ErrProfileNoCipher] when the resolved profile mode is blob-only.
func (p *Pipeline) DecryptMessage(wire []byte) ([]byte, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	if hasNoCipherSurface(p.resolved.mode) {
		return nil, ErrProfileNoCipher
	}

	var plain bytes.Buffer
	// Pre-size to the wire length — plaintext is always ≤ wire and
	// the small overshoot avoids the bytes.Buffer doubling chain on
	// MiB payloads.
	plain.Grow(len(wire))
	innerSrc, innerDst, closeFn, err := buildDecryptChain(p, bytes.NewReader(wire), &plain)
	if err != nil {
		return nil, err
	}

	var cipherErr error
	if p.macFunc != nil {
		cipherErr = itb.DecryptStreamAuth3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			innerSrc, innerDst, p.macFunc,
		)
	} else {
		cipherErr = itb.DecryptStream3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			innerSrc, innerDst,
		)
	}
	if err := joinCloseError(cipherErr, closeFn()); err != nil {
		return nil, err
	}
	return plain.Bytes(), nil
}

// hasNoCipherSurface reports whether the resolved profile mode
// exposes no cipher path at all. The blob-only profile is the sole
// trigger today; kept as a helper so [EncryptMessage] and
// [DecryptMessage] share one guard branch verbatim, parallel to
// [isStreamingMode]'s role for the streaming guard.
func hasNoCipherSurface(mode string) bool {
	return mode == modeBlobOnly
}
