// Package wrapper provides format-deniability envelopes for ITB ciphertext.
//
// ITB encrypts content into RGBWYOPA pixel containers and provides
// content-deniability unconditionally — no plaintext bit can be extracted from
// the wire. However, the ITB wire is parseable by an observer who knows the
// format: nonce / W / H / container layout for Non-AEAD mode; 32-byte streamID
// prefix + per-chunk metadata for Streaming AEAD. This package hides the ITB
// wire pattern under a generic-cipher-looking envelope ("CTR cipher style
// stream"), so an observer cannot pattern-match ITB-specific signatures
// (W/H bounds, container layout, streamID prefix for AEAD streaming mode).
//
// This is NOT a random-oracle indistinguishability claim — it is "looks like
// some other well-known cipher's ciphertext, not specifically ITB". The outer
// cipher exists for format-deniability ONLY, not for confidentiality (ITB
// already provides that) and not for integrity (the ITB AEAD path already
// provides that per chunk and per stream; the ITB Non-AEAD streaming path
// intentionally has none).
//
// Three outer ciphers are supplied via the Keystream interface:
//
//   - AES-128-CTR (16-byte nonce) — stdlib, AES-NI accelerated.
//   - ChaCha20 (RFC8439) (12-byte nonce) — golang.org/x/crypto/chacha20.
//   - SipHash-2-4 in CTR mode (16-byte nonce) — small custom PRF construction
//     using github.com/dchest/siphash, sound under the standard PRF
//     assumption SipHash-2-4 already satisfies as a 128-bit-keyed PRF/MAC.
//
// Per-stream nonce hygiene: every Wrap entry point generates a fresh CSPRNG
// nonce and emits it once at stream start. Within a stream the keystream
// advances monotonically (CTR counter or ChaCha20 internal counter). This is
// standard CTR mode usage — not nonce-reuse. Nonce-reuse means two distinct
// streams using the SAME (key, nonce); avoid that by using a fresh CSPRNG
// nonce per stream, which every entry point in this package does.
package wrapper
