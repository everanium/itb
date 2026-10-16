package triple

import (
	"bytes"
	"errors"
	"io"

	"github.com/everanium/itb"
	"github.com/everanium/itb/wrapper"
)

// ErrProfileNotStreaming is returned by [Pipeline.EncryptStream] /
// [Pipeline.DecryptStream] when the [Pipeline]'s resolved profile
// mode does not expose a streaming cipher surface — Single Message
// and blob-only profiles both surface this error, since their
// intended surfaces are [Pipeline.EncryptMessage] /
// [Pipeline.DecryptMessage] and no cipher surface at all, respectively.
//
// The sentinel lives beside its check site here rather than in
// [pipeline.go]'s sentinel block since it is scoped to the streaming
// surface — colocates a guard's error with the guard itself.
var ErrProfileNotStreaming = errors.New("triple: profile does not expose a streaming cipher surface")

// EncryptStream reads plaintext bytes from plainSrc, runs them through
// the full Triple chain (parallax encrypt-Reader → itb Triple
// Streaming AEAD (or Non-AEAD) → wrapper wrap-Writer), and writes the
// wire bytes to wireDst. Blocks until plainSrc returns [io.EOF] or an
// error surfaces.
//
// Disabled layers are identity substitutions with no wrapper
// [io.Reader] / [io.Writer] allocated. On completion the parallax
// reader is closed (releasing pool scratch) and the wrapper writer is
// finalized via [wrapper.FinishWrapStream]. Concurrent-safe:
// post-[Init] Pipeline state is read-only and per-call state lives on
// this call's stack, so multiple goroutines may call EncryptStream
// against the same [*Pipeline] simultaneously.
//
// An empty plaintext stream (plainSrc yields [io.EOF] before any
// byte) is rejected upfront with [ErrEmptyInput] via a first-byte
// probe and re-chain before any wire byte is written.
//
// Returns [ErrClosed] when [Pipeline.Close] has already run;
// [ErrProfileNotStreaming] when the resolved profile mode is Single
// Message or blob-only; [ErrEmptyInput] on an empty plaintext stream.
func (p *Pipeline) EncryptStream(plainSrc io.Reader, wireDst io.Writer) error {
	if p.isClosed() {
		return ErrClosed
	}
	if !isStreamingMode(p.resolved.Mode) {
		return ErrProfileNotStreaming
	}
	plainSrc, err := rejectEmptySource(plainSrc)
	if err != nil {
		return err
	}

	innerSrc, innerDst, closeFn, err := buildEncryptChain(p, plainSrc, wireDst)
	if err != nil {
		return err
	}

	// No MAC path — pipeline.macFunc is nil by construction on a
	// Streaming Non-AEAD profile; the No MAC dispatcher never
	// consumes it.
	var cipherErr error
	if p.macFunc != nil {
		cipherErr = itb.EncryptStreamAuth3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			innerSrc, innerDst, p.macFunc, p.resolved.ChunkSize,
		)
	} else {
		cipherErr = itb.EncryptStream3xCfg(
			p.cfg,
			p.seeds[0], p.seeds[1],
			p.seeds[2], p.seeds[3], p.seeds[4],
			p.seeds[5], p.seeds[6], p.seeds[7],
			innerSrc, innerDst, p.resolved.ChunkSize,
		)
	}
	if err := joinCloseError(cipherErr, closeFn()); err != nil {
		return err
	}
	// Public entry points reject empty input with ErrEmptyInput
	// upfront; FinishWrapStream flushes any pending wrapper state on
	// close (no-op when wrapper is disengaged or body bytes were
	// already emitted).
	return wrapper.FinishWrapStream(innerDst)
}

// DecryptStream is the receive-side counterpart of
// [Pipeline.EncryptStream]. Reads wire bytes from wireSrc, reverses
// the Triple chain (wrapper unwrap-Reader → itb Triple
// Streaming AEAD (or Non-AEAD) decrypt → parallax decrypt-Writer),
// and writes plaintext bytes to plainDst. Blocks until wireSrc
// returns [io.EOF] or an error surfaces.
//
// On completion the parallax writer is closed to flush the trailing
// partial chunk and release pool scratch. An empty wire stream
// (wireSrc yields [io.EOF] before any byte) is rejected upfront with
// [ErrEmptyInput] via the same first-byte probe and re-chain as
// [Pipeline.EncryptStream].
//
// Same concurrency posture as [Pipeline.EncryptStream]: safe for
// concurrent invocation on one [*Pipeline]. Returns [ErrClosed] when
// [Pipeline.Close] has already run; [ErrProfileNotStreaming] when the
// resolved profile mode is Single Message or blob-only;
// [ErrEmptyInput] on an empty wire stream.
func (p *Pipeline) DecryptStream(wireSrc io.Reader, plainDst io.Writer) error {
	if p.isClosed() {
		return ErrClosed
	}
	if !isStreamingMode(p.resolved.Mode) {
		return ErrProfileNotStreaming
	}
	wireSrc, err := rejectEmptySource(wireSrc)
	if err != nil {
		return err
	}

	innerSrc, innerDst, closeFn, err := buildDecryptChain(p, wireSrc, plainDst)
	if err != nil {
		return err
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
	return joinCloseError(cipherErr, closeFn())
}

// isStreamingMode reports whether the resolved profile mode is one of
// the two streaming surfaces ([modeStreamingAEAD] or
// [modeStreamingNoAEAD]). Kept as a small helper so [EncryptStream]
// and [DecryptStream] share the guard branch verbatim.
func isStreamingMode(mode string) bool {
	return mode == modeStreamingAEAD || mode == modeStreamingNoAEAD
}

// rejectEmptySource probes src for its first byte. An immediate
// [io.EOF] maps to [ErrEmptyInput]; any other read error is returned
// as-is. On a successful probe the byte is re-chained ahead of the
// remaining reader via [io.MultiReader], so the returned reader
// yields exactly the bytes src would have yielded. Shared by
// [Pipeline.EncryptStream] and [Pipeline.DecryptStream] so both IO
// entry points enforce the empty-input rejection contract before any
// chain layer is composed.
func rejectEmptySource(src io.Reader) (io.Reader, error) {
	var first [1]byte
	if _, err := io.ReadFull(src, first[:]); err != nil {
		if err == io.EOF {
			return nil, ErrEmptyInput
		}
		return nil, err
	}
	return io.MultiReader(bytes.NewReader(first[:]), src), nil
}
