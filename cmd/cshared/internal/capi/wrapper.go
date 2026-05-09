package capi

import (
	"crypto/rand"

	"github.com/everanium/itb/wrapper"
)

// wrapper.go — single-shot format-deniability helpers.
//
// These entry points expose the four single-shot variants from
// github.com/everanium/itb/wrapper (Wrap, Unwrap, WrapInPlace,
// UnwrapInPlace) plus the two sizing lookups (KeySize, NonceSize)
// across the FFI surface.
//
// Memcpy avoidance. The FFI dispatcher in cmd/cshared/main.go
// presents caller-allocated C buffers to these helpers as Go
// []byte aliases via goBytesView / goBytesViewMut. The helpers
// pass those aliases directly to the wrapper package; the
// keystream XOR mutates the C-side buffer in place. The single
// allocation in the path is the per-call nonce (16 bytes for
// AES / SipHash, 12 bytes for ChaCha20) plus, on the allocating
// Wrap / Unwrap variants, the wrapper package's own output slice.
// The InPlace variants avoid both — only the nonce is allocated,
// and on the encrypt side the nonce lands in a caller-supplied
// out buffer rather than being heap-allocated and copied.

// WrapperKeySize reports the byte length of the keystream-cipher
// key for the named outer cipher. Returns StatusBadInput on an
// unknown cipher name.
func WrapperKeySize(name string) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)
	sz, err := wrapper.KeySize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	return sz, StatusOK
}

// WrapperNonceSize reports the on-wire nonce length the named
// outer cipher emits per stream. Returns StatusBadInput on an
// unknown cipher name.
func WrapperNonceSize(name string) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)
	sz, err := wrapper.NonceSize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	return sz, StatusOK
}

// Wrap seals one ITB ciphertext blob under the named outer cipher.
// The wire form is `nonce || keystream-XOR(blob)` where the nonce
// is freshly drawn from crypto/rand per call. Same caller-
// allocated-buffer convention as Encrypt: returned n carries the
// bytes written on success or the required capacity on
// StatusBufferTooSmall.
func Wrap(name string, key, blob, out []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	nonceSz, err := wrapper.NonceSize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	keySz, err := wrapper.KeySize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	if len(key) != keySz {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}

	need := nonceSz + len(blob)
	if len(out) < need {
		setLastErr(StatusBufferTooSmall)
		return need, StatusBufferTooSmall
	}

	// Generate the per-stream nonce directly into the caller
	// buffer's prefix region — saves one nonceSz-byte allocation
	// versus calling the wrapper.Wrap allocating helper.
	nonce := out[:nonceSz]
	if _, err := rand.Read(nonce); err != nil {
		setLastErr(StatusInternal)
		return 0, StatusInternal
	}
	ks, err := wrapper.MakeKeystream(name, key, nonce)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	body := out[nonceSz : nonceSz+len(blob)]
	ks.XORKeyStream(body, blob)
	return need, StatusOK
}

// Unwrap reverses Wrap. The leading nonce is read from wire; the
// remaining bytes are XOR-decrypted under (key, nonce) into out.
// Same caller-allocated-buffer convention as Wrap; the recovered
// payload size is len(wire) - NonceSize(name).
func Unwrap(name string, key, wire, out []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	nonceSz, err := wrapper.NonceSize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	keySz, err := wrapper.KeySize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	if len(key) != keySz {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	if len(wire) < nonceSz {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}

	bodyLen := len(wire) - nonceSz
	if len(out) < bodyLen {
		setLastErr(StatusBufferTooSmall)
		return bodyLen, StatusBufferTooSmall
	}

	nonce := wire[:nonceSz]
	body := wire[nonceSz:]
	ks, err := wrapper.MakeKeystream(name, key, nonce)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	ks.XORKeyStream(out[:bodyLen], body)
	return bodyLen, StatusOK
}

// WrapInPlace XORs blob in place under a freshly-drawn outer
// keystream and writes the per-stream nonce into outNonce. The
// caller is expected to emit nonce || blob to the wire (or carry
// both fragments separately). blob is MUTATED.
//
// outNonce capacity must be at least NonceSize(name). On success
// n carries NonceSize(name) (the bytes written into outNonce).
// On StatusBufferTooSmall n carries the required nonce capacity.
func WrapInPlace(name string, key, blob, outNonce []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	nonceSz, err := wrapper.NonceSize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	keySz, err := wrapper.KeySize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	if len(key) != keySz {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	if len(outNonce) < nonceSz {
		setLastErr(StatusBufferTooSmall)
		return nonceSz, StatusBufferTooSmall
	}

	nonce := outNonce[:nonceSz]
	if _, err := rand.Read(nonce); err != nil {
		setLastErr(StatusInternal)
		return 0, StatusInternal
	}
	ks, err := wrapper.MakeKeystream(name, key, nonce)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	ks.XORKeyStream(blob, blob)
	return nonceSz, StatusOK
}

// UnwrapInPlace strips the leading nonce from wire and XORs the
// remainder in place. wire is MUTATED. Returns the body length
// (len(wire) - NonceSize(name)) on success.
func UnwrapInPlace(name string, key, wire []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	nonceSz, err := wrapper.NonceSize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	keySz, err := wrapper.KeySize(name)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	if len(key) != keySz {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	if len(wire) < nonceSz {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}

	nonce := wire[:nonceSz]
	body := wire[nonceSz:]
	ks, err := wrapper.MakeKeystream(name, key, nonce)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	ks.XORKeyStream(body, body)
	return len(body), StatusOK
}
