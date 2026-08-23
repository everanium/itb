package triple

// EncryptMessage is the Single Message counterpart of
// [Pipeline.EncryptStream]. Encrypts plaintext bytes through the full
// triple chain and returns the wire bytes.
//
// Phase 4 skeleton: this cipher path is stubbed and returns
// [ErrNotYetImplemented] regardless of arguments. The full
// implementation lands in Phase 6 as a thin convenience wrapper
// around [Pipeline.EncryptStream] + [bytes.Buffer].
func (p *Pipeline) EncryptMessage(plaintext []byte) ([]byte, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	_ = plaintext
	return nil, ErrNotYetImplemented
}

// DecryptMessage is the receive-side counterpart of
// [Pipeline.EncryptMessage]. Decrypts wire bytes back to plaintext
// through the full triple chain.
//
// Phase 4 skeleton: this cipher path is stubbed and returns
// [ErrNotYetImplemented] regardless of arguments. The full
// implementation lands in Phase 6 as a thin convenience wrapper
// around [Pipeline.DecryptStream] + [bytes.Buffer].
func (p *Pipeline) DecryptMessage(wire []byte) ([]byte, error) {
	if p.isClosed() {
		return nil, ErrClosed
	}
	_ = wire
	return nil, ErrNotYetImplemented
}
