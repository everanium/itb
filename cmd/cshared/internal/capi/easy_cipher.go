package capi

import (
	"strings"
)

// EasyEncrypt encrypts plaintext through the encryptor handle. Plain
// mode — no MAC tag attached; for authenticated encryption use
// EasyEncryptAuth. Same caller-allocated-buffer convention as the
// low-level Encrypt: out is the destination buffer, the returned n
// reports bytes written on success or required capacity on
// StatusBufferTooSmall.
//
// The encryptor's per-instance Config snapshot (BitSoup, LockSoup,
// LockSeed, NonceBits, BarrierFill, ChunkSize) is consumed
// automatically — process-wide setters do not affect a constructed
// encryptor, which is the whole point of the easy package.
func EasyEncrypt(id EasyHandleID, plaintext, out []byte) (n int, st Status) {
	defer recoverEasyPanic(&st, StatusEncryptFailed)

	h, st := resolveEasy(id)
	if st != StatusOK {
		return 0, st
	}
	enc, err := h.enc.Encrypt(plaintext)
	if err != nil {
		setLastErr(StatusEncryptFailed)
		return 0, StatusEncryptFailed
	}
	if len(enc) > len(out) {
		setLastErr(StatusBufferTooSmall)
		return len(enc), StatusBufferTooSmall
	}
	copy(out, enc)
	return len(enc), StatusOK
}

// EasyDecrypt is the inverse of EasyEncrypt. Same buffer convention.
// Wrong-seed input on non-authenticated mode produces random-looking
// plaintext rather than a status; the easy package matches the
// underlying itb.Decrypt* contract — non-Auth mode has no failure
// signal by design. For integrity-protected decryption use
// EasyDecryptAuth, which classifies the MAC failure as a distinct
// StatusMACFailure.
func EasyDecrypt(id EasyHandleID, ciphertext, out []byte) (n int, st Status) {
	defer recoverEasyPanic(&st, StatusDecryptFailed)

	h, st := resolveEasy(id)
	if st != StatusOK {
		return 0, st
	}
	plain, err := h.enc.Decrypt(ciphertext)
	if err != nil {
		setLastErr(StatusDecryptFailed)
		return 0, StatusDecryptFailed
	}
	if len(plain) > len(out) {
		setLastErr(StatusBufferTooSmall)
		return len(plain), StatusBufferTooSmall
	}
	copy(out, plain)
	return len(plain), StatusOK
}

// EasyEncryptAuth encrypts plaintext and attaches a MAC tag using the
// encryptor's bound MAC closure. Same buffer convention as
// EasyEncrypt.
func EasyEncryptAuth(id EasyHandleID, plaintext, out []byte) (n int, st Status) {
	defer recoverEasyPanic(&st, StatusEncryptFailed)

	h, st := resolveEasy(id)
	if st != StatusOK {
		return 0, st
	}
	enc, err := h.enc.EncryptAuth(plaintext)
	if err != nil {
		setLastErr(StatusEncryptFailed)
		return 0, StatusEncryptFailed
	}
	if len(enc) > len(out) {
		setLastErr(StatusBufferTooSmall)
		return len(enc), StatusBufferTooSmall
	}
	copy(out, enc)
	return len(enc), StatusOK
}

// EasyDecryptAuth verifies and decrypts an authenticated ciphertext
// produced by EasyEncryptAuth. On MAC verification failure (tampered
// ciphertext, wrong MAC key, mismatched MAC primitive across sender
// and receiver) returns StatusMACFailure; structural / dispatch
// errors return StatusDecryptFailed. The MAC-failure path is
// distinguished so bindings can present it as a typed integrity
// violation rather than generic decrypt failure.
func EasyDecryptAuth(id EasyHandleID, ciphertext, out []byte) (n int, st Status) {
	defer recoverEasyPanic(&st, StatusDecryptFailed)

	h, st := resolveEasy(id)
	if st != StatusOK {
		return 0, st
	}
	plain, err := h.enc.DecryptAuth(ciphertext)
	if err != nil {
		// Pattern match on the underlying itb.DecryptAuthenticated*
		// error message — same approach as classifyAuthError in
		// cipher_auth.go. The error string is fixed in itb/auth*.go
		// as "itb: MAC verification failed (tampered or wrong key)".
		if strings.Contains(err.Error(), "MAC verification failed") {
			setLastErr(StatusMACFailure)
			return 0, StatusMACFailure
		}
		setLastErr(StatusDecryptFailed)
		return 0, StatusDecryptFailed
	}
	if len(plain) > len(out) {
		setLastErr(StatusBufferTooSmall)
		return len(plain), StatusBufferTooSmall
	}
	copy(out, plain)
	return len(plain), StatusOK
}
