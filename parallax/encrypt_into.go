package parallax

import (
	"crypto/rand"
	"fmt"
)

// EncryptInto encrypts src under a freshly drawn per-message 16-byte
// nonce, writing the ciphertext body into the caller-supplied dst and
// returning the nonce. dst must be exactly len(src) bytes. The wire
// form consumed by Decrypt / DecryptInPlace / DecryptInto is
// `nonce || dst`; the caller assembles it (or a framing of it) at a
// destination of its choosing, which is the point of this entry: no
// intermediate wire buffer is allocated and no copy-back into src is
// performed. Use this on hot paths that stage ciphertext directly
// into a larger output buffer; EncryptInPlace is the
// contiguous-wire-allocating variant and Encrypt the fully
// allocate-fresh variant.
//
// dst and src may coincide exactly (dst[0] == src[0], equal length),
// in which case the call encrypts in place; partially overlapping
// dst/src is not supported. On error dst is unchanged unless the
// per-segment keystream construction fails mid-transform, in which
// case dst may hold a partially transformed body — the returned error
// tells the caller to discard it.
//
// An error is returned when cs is nil or does not match this schedule,
// when dst and src differ in length, when crypto/rand fails to supply
// nonce bytes, or when the per-segment keystream construction fails
// for any palette slot.
func (s *Schedule) EncryptInto(dst, src []byte, cs *Cipherset) ([]byte, error) {
	if err := s.checkCipherset(cs); err != nil {
		return nil, err
	}
	if len(dst) != len(src) {
		return nil, fmt.Errorf("parallax: dst/src length mismatch (%d != %d)", len(dst), len(src))
	}
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if len(src) > 0 {
		if err := transformInto(s, cs, nonce, dst, src); err != nil {
			return nil, err
		}
	}
	return nonce, nil
}

// DecryptInto strips the leading 16-byte nonce from wire and decrypts
// the body into the caller-supplied dst, returning dst. dst must be
// exactly len(wire)-NonceSize bytes; a nonce-only wire returns the
// empty dst. wire is not mutated unless dst aliases it.
//
// dst and the body region wire[NonceSize:] may coincide exactly, in
// which case the call is equivalent to DecryptInPlace; partially
// overlapping dst/body is not supported. On a transform error dst may
// hold a partially decrypted body; the Non-AEAD contract makes this
// state observationally equivalent to the "wire produced under a
// different palette or master" failure mode described on Decrypt.
//
// An error is returned when cs is nil or does not match this schedule,
// when wire is shorter than NonceSize, when dst and the wire body
// differ in length, or when the per-segment keystream construction
// fails for any palette slot.
func (s *Schedule) DecryptInto(dst, wire []byte, cs *Cipherset) ([]byte, error) {
	if err := s.checkCipherset(cs); err != nil {
		return nil, err
	}
	if len(wire) < NonceSize {
		return nil, fmt.Errorf("parallax: wire shorter than nonce (%d < %d)", len(wire), NonceSize)
	}
	body := wire[NonceSize:]
	if len(dst) != len(body) {
		return nil, fmt.Errorf("parallax: dst/body length mismatch (%d != %d)", len(dst), len(body))
	}
	if len(body) == 0 {
		return dst, nil
	}
	if err := transformInto(s, cs, wire[:NonceSize], dst, body); err != nil {
		return nil, err
	}
	return dst, nil
}
