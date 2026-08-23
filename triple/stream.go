package triple

import (
	"errors"
	"io"

	"github.com/everanium/itb"
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
// the full triple chain (parallax encrypt-Reader → itb Triple 8-seed
// Streaming AEAD (or Non-AEAD) → wrapper wrap-Writer), and writes the
// wire bytes to wireDst. Blocks until plainSrc returns [io.EOF] or an
// error surfaces.
//
// Chain composition:
//
//  1. plainSrc → [parallax.NewEncryptReader when parallax on] → innerSrc
//  2. wireDst  ← [wrapper.NewWrapWriter    when wrapper  on] ← innerDst
//  3. Dispatch on MAC presence:
//     MAC     → itb.EncryptStreamAuth3xCfg(cfg, seeds, innerSrc, innerDst, mac, chunkSize)
//     No-MAC  → itb.EncryptStream3xCfg    (cfg, seeds, innerSrc, innerDst,      chunkSize)
//  4. Close parallax reader (releases pool scratch); wrapper writer
//     has no per-call state that needs an explicit flush.
//
// When a layer is disabled the corresponding boundary is an identity
// substitution — no wrapper [io.Reader] / [io.Writer] allocated on
// the disabled side. Concurrent-safe: post-[Init] Pipeline state is
// read-only from the cipher-path perspective; per-call state (the
// parallax reader, the wrapper writer, per-chunk scratch inside the
// itb IO entry) lives on this call's stack. Multiple goroutines may
// call EncryptStream against the same [*Pipeline] simultaneously.
//
// Returns [ErrClosed] when [Pipeline.Close] has already run;
// [ErrProfileNotStreaming] when the resolved profile mode is Single
// Message or blob-only.
func (p *Pipeline) EncryptStream(plainSrc io.Reader, wireDst io.Writer) error {
	if p.isClosed() {
		return ErrClosed
	}
	if !isStreamingMode(p.resolved.mode) {
		return ErrProfileNotStreaming
	}

	innerSrc, innerDst, closeFn, err := buildEncryptChain(p, plainSrc, wireDst)
	if err != nil {
		return err
	}

	// No-MAC path — pipeline.macFunc is nil by construction on a
	// Streaming Non-AEAD profile; the No-MAC dispatcher never
	// consumes it.
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
	return joinCloseError(cipherErr, closeFn())
}

// DecryptStream is the receive-side counterpart of
// [Pipeline.EncryptStream]. Reads wire bytes from wireSrc, reverses
// the triple chain (wrapper unwrap-Reader → itb Triple 8-seed
// Streaming AEAD (or Non-AEAD) decrypt → parallax decrypt-Writer),
// and writes plaintext bytes to plainDst. Blocks until wireSrc
// returns [io.EOF] or an error surfaces.
//
// Chain composition (mirror of [Pipeline.EncryptStream]):
//
//  1. wireSrc  → [wrapper.NewUnwrapReader when wrapper  on] → innerSrc
//  2. plainDst ← [parallax.NewDecryptWriter when parallax on] ← innerDst
//  3. Dispatch on MAC presence:
//     MAC     → itb.DecryptStreamAuth3xCfg(cfg, seeds, innerSrc, innerDst, mac)
//     No-MAC  → itb.DecryptStream3xCfg    (cfg, seeds, innerSrc, innerDst)
//  4. Close parallax writer (flushes the trailing partial chunk +
//     releases pool scratch); wrapper reader has no per-call state
//     that needs an explicit close.
//
// Same concurrency posture as [Pipeline.EncryptStream]: safe for
// concurrent invocation on one [*Pipeline]. Returns [ErrClosed] when
// [Pipeline.Close] has already run; [ErrProfileNotStreaming] when the
// resolved profile mode is Single Message or blob-only.
func (p *Pipeline) DecryptStream(wireSrc io.Reader, plainDst io.Writer) error {
	if p.isClosed() {
		return ErrClosed
	}
	if !isStreamingMode(p.resolved.mode) {
		return ErrProfileNotStreaming
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
