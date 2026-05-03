package capi

import (
	"errors"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// EncryptAuth is the Authenticated counterpart of Encrypt: it
// computes a MAC tag over the encrypted payload (under the barrier
// but inside the container, mirroring ITB's MAC-Inside-Encrypt
// construction) and embeds the tag into the ciphertext alongside
// the data. Same caller-allocated-buffer convention as Encrypt;
// returned n is the bytes written on success or required capacity
// on StatusBufferTooSmall.
func EncryptAuth(
	noise, data, start HandleID, mac MACHandleID,
	plaintext, out []byte,
) (n int, st Status) {
	defer recoverPanic(&st, StatusEncryptFailed)

	ns, ds, ss, st := resolveTriple(noise, data, start)
	if st != StatusOK {
		return 0, st
	}
	mh, st := resolveMAC(mac)
	if st != StatusOK {
		return 0, st
	}
	enc, err := encryptAuthDispatch(ns, ds, ss, mh.fn, plaintext)
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

// DecryptAuth is the inverse of EncryptAuth. On MAC verification
// failure (tampered ciphertext, wrong key, mismatched MAC primitive)
// returns StatusMACFailure; on structural / dispatch errors returns
// the matching status. The MAC-failure path is distinguished from
// generic decrypt failure to give bindings a precise error code for
// integrity-violation reporting.
func DecryptAuth(
	noise, data, start HandleID, mac MACHandleID,
	ciphertext, out []byte,
) (n int, st Status) {
	defer recoverPanic(&st, StatusDecryptFailed)

	ns, ds, ss, st := resolveTriple(noise, data, start)
	if st != StatusOK {
		return 0, st
	}
	mh, st := resolveMAC(mac)
	if st != StatusOK {
		return 0, st
	}
	plain, err := decryptAuthDispatch(ns, ds, ss, mh.fn, ciphertext)
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

// EncryptAuth3 is the seven-seed Triple Ouroboros + Auth variant.
// Same convention as Encrypt3 plus a MAC handle. All seven seeds
// must share the same native hash width.
func EncryptAuth3(
	noise, data1, data2, data3, start1, start2, start3 HandleID,
	mac MACHandleID, plaintext, out []byte,
) (n int, st Status) {
	defer recoverPanic(&st, StatusEncryptFailed)

	ns, ds1, ds2, ds3, ss1, ss2, ss3, st := resolveSeven(
		noise, data1, data2, data3, start1, start2, start3,
	)
	if st != StatusOK {
		return 0, st
	}
	mh, st := resolveMAC(mac)
	if st != StatusOK {
		return 0, st
	}
	enc, err := encryptAuthTripleDispatch(ns, ds1, ds2, ds3, ss1, ss2, ss3, mh.fn, plaintext)
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
	noise, data1, data2, data3, start1, start2, start3 HandleID,
	mac MACHandleID, ciphertext, out []byte,
) (n int, st Status) {
	defer recoverPanic(&st, StatusDecryptFailed)

	ns, ds1, ds2, ds3, ss1, ss2, ss3, st := resolveSeven(
		noise, data1, data2, data3, start1, start2, start3,
	)
	if st != StatusOK {
		return 0, st
	}
	mh, st := resolveMAC(mac)
	if st != StatusOK {
		return 0, st
	}
	plain, err := decryptAuthTripleDispatch(ns, ds1, ds2, ds3, ss1, ss2, ss3, mh.fn, ciphertext)
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

func encryptAuthDispatch(
	ns, ds, ss *SeedHandle, mac itb.MACFunc, plaintext []byte,
) ([]byte, error) {
	switch ns.width {
	case hashes.W128:
		return itb.EncryptAuthenticated128(ns.seed128, ds.seed128, ss.seed128, plaintext, mac)
	case hashes.W256:
		return itb.EncryptAuthenticated256(ns.seed256, ds.seed256, ss.seed256, plaintext, mac)
	case hashes.W512:
		return itb.EncryptAuthenticated512(ns.seed512, ds.seed512, ss.seed512, plaintext, mac)
	}
	return nil, errInternal
}

func decryptAuthDispatch(
	ns, ds, ss *SeedHandle, mac itb.MACFunc, ciphertext []byte,
) ([]byte, error) {
	switch ns.width {
	case hashes.W128:
		return itb.DecryptAuthenticated128(ns.seed128, ds.seed128, ss.seed128, ciphertext, mac)
	case hashes.W256:
		return itb.DecryptAuthenticated256(ns.seed256, ds.seed256, ss.seed256, ciphertext, mac)
	case hashes.W512:
		return itb.DecryptAuthenticated512(ns.seed512, ds.seed512, ss.seed512, ciphertext, mac)
	}
	return nil, errInternal
}

func encryptAuthTripleDispatch(
	ns, ds1, ds2, ds3, ss1, ss2, ss3 *SeedHandle,
	mac itb.MACFunc, plaintext []byte,
) ([]byte, error) {
	switch ns.width {
	case hashes.W128:
		return itb.EncryptAuthenticated3x128(
			ns.seed128, ds1.seed128, ds2.seed128, ds3.seed128,
			ss1.seed128, ss2.seed128, ss3.seed128, plaintext, mac)
	case hashes.W256:
		return itb.EncryptAuthenticated3x256(
			ns.seed256, ds1.seed256, ds2.seed256, ds3.seed256,
			ss1.seed256, ss2.seed256, ss3.seed256, plaintext, mac)
	case hashes.W512:
		return itb.EncryptAuthenticated3x512(
			ns.seed512, ds1.seed512, ds2.seed512, ds3.seed512,
			ss1.seed512, ss2.seed512, ss3.seed512, plaintext, mac)
	}
	return nil, errInternal
}

func decryptAuthTripleDispatch(
	ns, ds1, ds2, ds3, ss1, ss2, ss3 *SeedHandle,
	mac itb.MACFunc, ciphertext []byte,
) ([]byte, error) {
	switch ns.width {
	case hashes.W128:
		return itb.DecryptAuthenticated3x128(
			ns.seed128, ds1.seed128, ds2.seed128, ds3.seed128,
			ss1.seed128, ss2.seed128, ss3.seed128, ciphertext, mac)
	case hashes.W256:
		return itb.DecryptAuthenticated3x256(
			ns.seed256, ds1.seed256, ds2.seed256, ds3.seed256,
			ss1.seed256, ss2.seed256, ss3.seed256, ciphertext, mac)
	case hashes.W512:
		return itb.DecryptAuthenticated3x512(
			ns.seed512, ds1.seed512, ds2.seed512, ds3.seed512,
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
