package capi

import (
	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// Encrypt encrypts plaintext using the (noise, data, start) seed
// trio. All three handles must wrap seeds of the same native hash
// width; otherwise StatusSeedWidthMix is returned.
//
// out is caller-allocated. On success the encrypted payload is
// written to out[:n] and n is reported back through outLen.
// If cap(out) is too small, StatusBufferTooSmall is returned and
// outLen is set to the size that would have been written so the
// caller can resize and retry.
func Encrypt(noise, data, start HandleID, plaintext, out []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusEncryptFailed)

	ns, ds, ss, st := resolveTriple(noise, data, start)
	if st != StatusOK {
		return 0, st
	}
	enc, err := encryptDispatch(ns, ds, ss, plaintext)
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

// Decrypt is the inverse of Encrypt. Same caller-allocated-buffer
// convention; outLen receives the recovered plaintext length on
// success or the required capacity on StatusBufferTooSmall.
func Decrypt(noise, data, start HandleID, ciphertext, out []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusDecryptFailed)

	ns, ds, ss, st := resolveTriple(noise, data, start)
	if st != StatusOK {
		return 0, st
	}
	plain, err := decryptDispatch(ns, ds, ss, ciphertext)
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

func resolveTriple(noise, data, start HandleID) (ns, ds, ss *SeedHandle, st Status) {
	ns, st = resolve(noise)
	if st != StatusOK {
		return nil, nil, nil, st
	}
	ds, st = resolve(data)
	if st != StatusOK {
		return nil, nil, nil, st
	}
	ss, st = resolve(start)
	if st != StatusOK {
		return nil, nil, nil, st
	}
	if ns.width != ds.width || ds.width != ss.width {
		setLastErr(StatusSeedWidthMix)
		return nil, nil, nil, StatusSeedWidthMix
	}
	return ns, ds, ss, StatusOK
}

func encryptDispatch(ns, ds, ss *SeedHandle, plaintext []byte) ([]byte, error) {
	switch ns.width {
	case hashes.W128:
		return itb.Encrypt128(ns.seed128, ds.seed128, ss.seed128, plaintext)
	case hashes.W256:
		return itb.Encrypt256(ns.seed256, ds.seed256, ss.seed256, plaintext)
	case hashes.W512:
		return itb.Encrypt512(ns.seed512, ds.seed512, ss.seed512, plaintext)
	}
	return nil, errInternal
}

func decryptDispatch(ns, ds, ss *SeedHandle, ciphertext []byte) ([]byte, error) {
	switch ns.width {
	case hashes.W128:
		return itb.Decrypt128(ns.seed128, ds.seed128, ss.seed128, ciphertext)
	case hashes.W256:
		return itb.Decrypt256(ns.seed256, ds.seed256, ss.seed256, ciphertext)
	case hashes.W512:
		return itb.Decrypt512(ns.seed512, ds.seed512, ss.seed512, ciphertext)
	}
	return nil, errInternal
}

// errInternal is the sentinel returned by dispatch helpers when the
// cached width on a handle does not match any known case (should be
// unreachable; kept as a defensive placeholder).
var errInternal = capiError("capi: internal width mismatch")

type capiError string

func (e capiError) Error() string { return string(e) }

// Encrypt3 is the Triple Ouroboros counterpart of Encrypt. It takes
// 7 seed handles (1 shared noise + 3 data + 3 start) and produces
// one ciphertext that splits the plaintext into three interleaved
// snake payloads. The on-wire format is the same shape as the
// non-Triple ciphertext (same nonce + dimensions header + raw
// container) — only the internal split / interleave differs.
//
// All 7 handles must share the same native hash width and must be
// pairwise distinct (the underlying itb.Encrypt3x* enforces the
// seven-seed isolation invariant). Same caller-allocated-buffer
// convention as Encrypt: returned n carries the bytes written on
// success or the required capacity on StatusBufferTooSmall.
func Encrypt3(
	noise, data1, data2, data3, start1, start2, start3 HandleID,
	plaintext, out []byte,
) (n int, st Status) {
	defer recoverPanic(&st, StatusEncryptFailed)

	ns, ds1, ds2, ds3, ss1, ss2, ss3, st := resolveSeven(
		noise, data1, data2, data3, start1, start2, start3,
	)
	if st != StatusOK {
		return 0, st
	}
	enc, err := encryptTripleDispatch(ns, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
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

// Decrypt3 is the inverse of Encrypt3. Same convention.
func Decrypt3(
	noise, data1, data2, data3, start1, start2, start3 HandleID,
	ciphertext, out []byte,
) (n int, st Status) {
	defer recoverPanic(&st, StatusDecryptFailed)

	ns, ds1, ds2, ds3, ss1, ss2, ss3, st := resolveSeven(
		noise, data1, data2, data3, start1, start2, start3,
	)
	if st != StatusOK {
		return 0, st
	}
	plain, err := decryptTripleDispatch(ns, ds1, ds2, ds3, ss1, ss2, ss3, ciphertext)
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

func resolveSeven(
	noise, data1, data2, data3, start1, start2, start3 HandleID,
) (ns, ds1, ds2, ds3, ss1, ss2, ss3 *SeedHandle, st Status) {
	ids := [7]HandleID{noise, data1, data2, data3, start1, start2, start3}
	resolved := [7]*SeedHandle{}
	for i, id := range ids {
		h, s := resolve(id)
		if s != StatusOK {
			return nil, nil, nil, nil, nil, nil, nil, s
		}
		resolved[i] = h
	}
	w := resolved[0].width
	for _, h := range resolved[1:] {
		if h.width != w {
			setLastErr(StatusSeedWidthMix)
			return nil, nil, nil, nil, nil, nil, nil, StatusSeedWidthMix
		}
	}
	return resolved[0], resolved[1], resolved[2], resolved[3],
		resolved[4], resolved[5], resolved[6], StatusOK
}

func encryptTripleDispatch(
	ns, ds1, ds2, ds3, ss1, ss2, ss3 *SeedHandle, plaintext []byte,
) ([]byte, error) {
	switch ns.width {
	case hashes.W128:
		return itb.Encrypt3x128(
			ns.seed128, ds1.seed128, ds2.seed128, ds3.seed128,
			ss1.seed128, ss2.seed128, ss3.seed128, plaintext)
	case hashes.W256:
		return itb.Encrypt3x256(
			ns.seed256, ds1.seed256, ds2.seed256, ds3.seed256,
			ss1.seed256, ss2.seed256, ss3.seed256, plaintext)
	case hashes.W512:
		return itb.Encrypt3x512(
			ns.seed512, ds1.seed512, ds2.seed512, ds3.seed512,
			ss1.seed512, ss2.seed512, ss3.seed512, plaintext)
	}
	return nil, errInternal
}

func decryptTripleDispatch(
	ns, ds1, ds2, ds3, ss1, ss2, ss3 *SeedHandle, ciphertext []byte,
) ([]byte, error) {
	switch ns.width {
	case hashes.W128:
		return itb.Decrypt3x128(
			ns.seed128, ds1.seed128, ds2.seed128, ds3.seed128,
			ss1.seed128, ss2.seed128, ss3.seed128, ciphertext)
	case hashes.W256:
		return itb.Decrypt3x256(
			ns.seed256, ds1.seed256, ds2.seed256, ds3.seed256,
			ss1.seed256, ss2.seed256, ss3.seed256, ciphertext)
	case hashes.W512:
		return itb.Decrypt3x512(
			ns.seed512, ds1.seed512, ds2.seed512, ds3.seed512,
			ss1.seed512, ss2.seed512, ss3.seed512, ciphertext)
	}
	return nil, errInternal
}
