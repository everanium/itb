package triple

import (
	"fmt"
	"io"

	"github.com/everanium/itb/wrapper"
)

// buildEncryptChain composes the caller-supplied plainSrc and wireDst
// into the (inner reader, inner writer, close-fn) triple actually
// handed to the itb-root IO-Driven Cfg entry.
//
// Chain shape (per `.TRIPLE.md` Streaming chain composition):
//
//	plainSrc → [parallax.NewEncryptReader when parallax on] → innerSrc
//	wireDst  ← [wrapper.NewWrapWriter    when wrapper  on] ← innerDst
//
// When a layer is disabled the corresponding boundary is an identity
// substitution — the caller's plainSrc / wireDst reaches the itb IO
// entry unchanged, no [io.Reader] / [io.Writer] wrapper allocated.
//
// closeFn returns nil when there is no per-call state to release
// (e.g. parallax off). When parallax is on it closes the
// [parallax.NewEncryptReader]'s [io.ReadCloser] so the pool scratch
// returns cleanly. The caller must invoke closeFn on every exit path,
// including error returns from the itb IO entry; the returned error
// (if any) is joined into the caller's return status via a
// close-error-preferred-when-clean policy.
//
// The wrapper writer is not an [io.Closer]; its per-call state is a
// single keystream and per-stream nonce, both fully drained on every
// Write call. No flush is required post-encrypt.
func buildEncryptChain(p *Pipeline, plainSrc io.Reader, wireDst io.Writer) (innerSrc io.Reader, innerDst io.Writer, closeFn func() error, err error) {
	innerDst = wireDst
	if p.resolved.wrapperOn {
		w, werr := wrapper.NewWrapWriter(p.wrapperCipher, p.wrapperKey, wireDst)
		if werr != nil {
			return nil, nil, nil, fmt.Errorf("triple: wrapper.NewWrapWriter: %w", werr)
		}
		innerDst = w
	}

	innerSrc = plainSrc
	closeFn = func() error { return nil }
	if p.resolved.parallaxOn {
		r, rerr := p.parallaxSched.NewEncryptReader(p.parallaxCS, plainSrc)
		if rerr != nil {
			return nil, nil, nil, fmt.Errorf("triple: parallax.NewEncryptReader: %w", rerr)
		}
		innerSrc = r
		closeFn = r.Close
	}
	return innerSrc, innerDst, closeFn, nil
}

// buildDecryptChain composes the caller-supplied wireSrc and plainDst
// into the (inner reader, inner writer, close-fn) triple actually
// handed to the itb-root IO-Driven Cfg entry.
//
// Chain shape — mirror image of [buildEncryptChain]:
//
//	wireSrc  → [wrapper.NewUnwrapReader when wrapper  on] → innerSrc
//	plainDst ← [parallax.NewDecryptWriter when parallax on] ← innerDst
//
// closeFn returns nil when parallax is off. When parallax is on it
// closes the [parallax.NewDecryptWriter]'s [io.WriteCloser] so the
// trailing partial chunk (if any) is flushed and pool scratch returns
// cleanly. As with the encrypt side the caller must invoke closeFn on
// every exit path.
func buildDecryptChain(p *Pipeline, wireSrc io.Reader, plainDst io.Writer) (innerSrc io.Reader, innerDst io.Writer, closeFn func() error, err error) {
	innerSrc = wireSrc
	if p.resolved.wrapperOn {
		r, rerr := wrapper.NewUnwrapReader(p.wrapperCipher, p.wrapperKey, wireSrc)
		if rerr != nil {
			return nil, nil, nil, fmt.Errorf("triple: wrapper.NewUnwrapReader: %w", rerr)
		}
		innerSrc = r
	}

	innerDst = plainDst
	closeFn = func() error { return nil }
	if p.resolved.parallaxOn {
		w, werr := p.parallaxSched.NewDecryptWriter(p.parallaxCS, plainDst)
		if werr != nil {
			return nil, nil, nil, fmt.Errorf("triple: parallax.NewDecryptWriter: %w", werr)
		}
		innerDst = w
		closeFn = w.Close
	}
	return innerSrc, innerDst, closeFn, nil
}

// joinCloseError folds a closeFn error into the primary cipher-path
// error. When the primary error is non-nil it wins (the caller learns
// about the cipher-side failure); when the primary is nil and the
// close-fn surfaces a non-nil error, the close error is returned. This
// matches the [io.Copy]-shaped "clean-primary-first" convention.
//
// Kept small so both [Pipeline.EncryptStream] and
// [Pipeline.DecryptStream] can share one join site without duplicating
// the branch structure.
//
// A dedicated helper avoids the surrounding functions ever forgetting
// to consult the close-fn on an error exit — every exit path calls
// this exactly once at the tail.
var _ = joinCloseError

func joinCloseError(primary error, closeErr error) error {
	if primary != nil {
		return primary
	}
	return closeErr
}
