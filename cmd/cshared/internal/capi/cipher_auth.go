package capi

import (
	"errors"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// EncryptAuth3 is the eight-seed Triple Ouroboros + Auth variant.
// Takes 8 seed handles (1 shared noise + 1 lockSeed + 3 data + 3
// start) plus a MAC handle; the underlying
// itb.EncryptAuthenticated3x* computes a MAC tag over the encrypted
// payload (under the barrier but inside the container, mirroring
// ITB's MAC-Inside-Encrypt construction) and embeds the tag into
// the ciphertext alongside the data. All eight seeds must share the
// same native hash width. Same caller-allocated-buffer convention
// as Encrypt3.
func EncryptAuth3(
	noise, lock, data1, data2, data3, start1, start2, start3 HandleID,
	mac MACHandleID, plaintext, out []byte,
) (n int, st Status) {
	defer recoverPanic(&st, StatusEncryptFailed)

	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, st := resolveEight(
		noise, lock, data1, data2, data3, start1, start2, start3,
	)
	if st != StatusOK {
		return 0, st
	}
	mh, st := resolveMAC(mac)
	if st != StatusOK {
		return 0, st
	}
	enc, err := encryptAuthTripleDispatch(ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, mh.fn, plaintext)
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

// DecryptAuth3 is the inverse of EncryptAuth3.
func DecryptAuth3(
	noise, lock, data1, data2, data3, start1, start2, start3 HandleID,
	mac MACHandleID, ciphertext, out []byte,
) (n int, st Status) {
	defer recoverPanic(&st, StatusDecryptFailed)

	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, st := resolveEight(
		noise, lock, data1, data2, data3, start1, start2, start3,
	)
	if st != StatusOK {
		return 0, st
	}
	mh, st := resolveMAC(mac)
	if st != StatusOK {
		return 0, st
	}
	plain, err := decryptAuthTripleDispatch(ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, mh.fn, ciphertext)
	if err != nil {
		st := classifyAuthError(err)
		setLastErr(st)
		return 0, st
	}
	if len(plain) > len(out) {
		setLastErr(StatusBufferTooSmall)
		return len(plain), StatusBufferTooSmall
	}
	copy(out, plain)
	return len(plain), StatusOK
}

func encryptAuthTripleDispatch(
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *SeedHandle,
	mac itb.MACFunc, plaintext []byte,
) ([]byte, error) {
	switch ns.width {
	case hashes.W128:
		return itb.EncryptAuthenticated3x128(
			ns.seed128, ls.seed128, ds1.seed128, ds2.seed128, ds3.seed128,
			ss1.seed128, ss2.seed128, ss3.seed128, plaintext, mac)
	case hashes.W256:
		return itb.EncryptAuthenticated3x256(
			ns.seed256, ls.seed256, ds1.seed256, ds2.seed256, ds3.seed256,
			ss1.seed256, ss2.seed256, ss3.seed256, plaintext, mac)
	case hashes.W512:
		return itb.EncryptAuthenticated3x512(
			ns.seed512, ls.seed512, ds1.seed512, ds2.seed512, ds3.seed512,
			ss1.seed512, ss2.seed512, ss3.seed512, plaintext, mac)
	}
	return nil, errInternal
}

func decryptAuthTripleDispatch(
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *SeedHandle,
	mac itb.MACFunc, ciphertext []byte,
) ([]byte, error) {
	switch ns.width {
	case hashes.W128:
		return itb.DecryptAuthenticated3x128(
			ns.seed128, ls.seed128, ds1.seed128, ds2.seed128, ds3.seed128,
			ss1.seed128, ss2.seed128, ss3.seed128, ciphertext, mac)
	case hashes.W256:
		return itb.DecryptAuthenticated3x256(
			ns.seed256, ls.seed256, ds1.seed256, ds2.seed256, ds3.seed256,
			ss1.seed256, ss2.seed256, ss3.seed256, ciphertext, mac)
	case hashes.W512:
		return itb.DecryptAuthenticated3x512(
			ns.seed512, ls.seed512, ds1.seed512, ds2.seed512, ds3.seed512,
			ss1.seed512, ss2.seed512, ss3.seed512, ciphertext, mac)
	}
	return nil, errInternal
}

// classifyAuthError maps an itb.DecryptAuthenticated* error onto the
// FFI status code. The underlying API exposes [itb.ErrMACFailure] as
// the typed sentinel for MAC-verification failure, so the
// classification is errors.Is-driven rather than a substring match
// on the error message — the sentinel survives any future
// rewording of the diagnostic text. Generic decrypt errors fall
// through to StatusDecryptFailed.
func classifyAuthError(err error) Status {
	if err == nil {
		return StatusOK
	}
	if errors.Is(err, itb.ErrMACFailure) {
		return StatusMACFailure
	}
	return StatusDecryptFailed
}

// EncryptStreamAuth3 is the eight-seed Triple Ouroboros + Streaming
// AEAD variant. Takes 8 seed handles plus a MAC handle plus the
// streaming-binding components (a 32-byte streamID, the running
// cumulativePixelOffset, and the finalFlag byte); the per-chunk MAC
// is computed over the encoded payload extended with those bindings.
// All eight seeds must share the same native hash width. Same
// caller-allocated-buffer convention as Encrypt3.
func EncryptStreamAuth3(
	noise, lock, data1, data2, data3, start1, start2, start3 HandleID,
	mac MACHandleID, plaintext, out []byte,
	streamID [32]byte, cumulativePixelOffset uint64, finalFlag bool,
) (n int, st Status) {
	defer recoverPanic(&st, StatusEncryptFailed)

	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, st := resolveEight(
		noise, lock, data1, data2, data3, start1, start2, start3,
	)
	if st != StatusOK {
		return 0, st
	}
	mh, st := resolveMAC(mac)
	if st != StatusOK {
		return 0, st
	}
	enc, err := encryptStreamAuthTripleDispatch(ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, mh.fn, plaintext, streamID, cumulativePixelOffset, finalFlag)
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

// DecryptStreamAuth3 is the inverse of EncryptStreamAuth3.
func DecryptStreamAuth3(
	noise, lock, data1, data2, data3, start1, start2, start3 HandleID,
	mac MACHandleID, ciphertext, out []byte,
	streamID [32]byte, cumulativePixelOffset uint64,
) (n int, finalFlag bool, st Status) {
	defer recoverPanic(&st, StatusDecryptFailed)

	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, st := resolveEight(
		noise, lock, data1, data2, data3, start1, start2, start3,
	)
	if st != StatusOK {
		return 0, false, st
	}
	mh, st := resolveMAC(mac)
	if st != StatusOK {
		return 0, false, st
	}
	plain, ff, err := decryptStreamAuthTripleDispatch(ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, mh.fn, ciphertext, streamID, cumulativePixelOffset)
	if err != nil {
		st := classifyAuthError(err)
		setLastErr(st)
		return 0, false, st
	}
	if len(plain) > len(out) {
		setLastErr(StatusBufferTooSmall)
		return len(plain), ff, StatusBufferTooSmall
	}
	copy(out, plain)
	return len(plain), ff, StatusOK
}

func encryptStreamAuthTripleDispatch(
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *SeedHandle,
	mac itb.MACFunc, plaintext []byte,
	streamID [32]byte, cumulativePixelOffset uint64, finalFlag bool,
) ([]byte, error) {
	switch ns.width {
	case hashes.W128:
		return itb.EncryptStreamAuthenticated3x128(
			ns.seed128, ls.seed128, ds1.seed128, ds2.seed128, ds3.seed128,
			ss1.seed128, ss2.seed128, ss3.seed128, plaintext, mac,
			streamID, cumulativePixelOffset, finalFlag)
	case hashes.W256:
		return itb.EncryptStreamAuthenticated3x256(
			ns.seed256, ls.seed256, ds1.seed256, ds2.seed256, ds3.seed256,
			ss1.seed256, ss2.seed256, ss3.seed256, plaintext, mac,
			streamID, cumulativePixelOffset, finalFlag)
	case hashes.W512:
		return itb.EncryptStreamAuthenticated3x512(
			ns.seed512, ls.seed512, ds1.seed512, ds2.seed512, ds3.seed512,
			ss1.seed512, ss2.seed512, ss3.seed512, plaintext, mac,
			streamID, cumulativePixelOffset, finalFlag)
	}
	return nil, errInternal
}

func decryptStreamAuthTripleDispatch(
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *SeedHandle,
	mac itb.MACFunc, ciphertext []byte,
	streamID [32]byte, cumulativePixelOffset uint64,
) ([]byte, bool, error) {
	switch ns.width {
	case hashes.W128:
		return itb.DecryptStreamAuthenticated3x128(
			ns.seed128, ls.seed128, ds1.seed128, ds2.seed128, ds3.seed128,
			ss1.seed128, ss2.seed128, ss3.seed128, ciphertext, mac,
			streamID, cumulativePixelOffset)
	case hashes.W256:
		return itb.DecryptStreamAuthenticated3x256(
			ns.seed256, ls.seed256, ds1.seed256, ds2.seed256, ds3.seed256,
			ss1.seed256, ss2.seed256, ss3.seed256, ciphertext, mac,
			streamID, cumulativePixelOffset)
	case hashes.W512:
		return itb.DecryptStreamAuthenticated3x512(
			ns.seed512, ls.seed512, ds1.seed512, ds2.seed512, ds3.seed512,
			ss1.seed512, ss2.seed512, ss3.seed512, ciphertext, mac,
			streamID, cumulativePixelOffset)
	}
	return nil, false, errInternal
}
