package wrapper

import "io"

// FinishWrapStream finalizes a writer returned by [NewWrapWriter]
// after the inner encoder has completed. [NewWrapWriter] batches the
// per-stream nonce into the first non-empty Write, so an inner stream
// that produced no bytes would otherwise leave dst without the outer
// cipher envelope; FinishWrapStream emits the pending nonce as a
// single standalone dst.Write in that case, so an empty inner stream
// still yields a parseable wire (the nonce alone). [NewUnwrapReader]
// and [UnwrapInPlace] both decode a nonce-only wire to an empty inner
// stream.
//
// A writer whose nonce has already left (batched with the first body
// write) is left untouched, as is any writer not produced by
// [NewWrapWriter] — both cases return nil without writing, so callers
// composing an optional wrapper layer can invoke FinishWrapStream
// unconditionally on their inner destination.
//
// Call only after the inner encoder has finished successfully. The
// concurrent-drain hazard that motivates the first-Write batching does
// not arise here: with no body bytes following, the nonce leaves as
// the wire's only write.
func FinishWrapStream(w io.Writer) error {
	kw, ok := w.(*keystreamWriter)
	if !ok || !kw.noncePending {
		return nil
	}
	kw.noncePending = false
	_, err := kw.w.Write(kw.nonce)
	return err
}
