package triple

import "io"

// EncryptStream reads plaintext bytes from plainSrc, runs them
// through the full triple chain (parallax encrypt-Reader → itb Triple
// 8-seed streaming AEAD (or Non-AEAD) → wrapper wrap-Writer), and
// writes the wire bytes to wireDst. Blocks until plainSrc returns
// [io.EOF] or an error surfaces.
//
// Phase 4 skeleton: this cipher path is stubbed and returns
// [ErrNotYetImplemented] regardless of arguments. The full
// implementation lands in Phase 5.
func (p *Pipeline) EncryptStream(plainSrc io.Reader, wireDst io.Writer) error {
	if p.isClosed() {
		return ErrClosed
	}
	_ = plainSrc
	_ = wireDst
	return ErrNotYetImplemented
}

// DecryptStream is the receive-side counterpart of
// [Pipeline.EncryptStream]. Reads wire bytes from wireSrc, reverses
// the triple chain (wrapper unwrap-Reader → itb Triple 8-seed
// streaming decrypt → parallax decrypt-Writer), and writes plaintext
// bytes to plainDst. Blocks until wireSrc returns [io.EOF] or an
// error surfaces.
//
// Phase 4 skeleton: this cipher path is stubbed and returns
// [ErrNotYetImplemented] regardless of arguments. The full
// implementation lands in Phase 5.
func (p *Pipeline) DecryptStream(wireSrc io.Reader, plainDst io.Writer) error {
	if p.isClosed() {
		return ErrClosed
	}
	_ = wireSrc
	_ = plainDst
	return ErrNotYetImplemented
}
