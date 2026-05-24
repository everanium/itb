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
// Nine outer ciphers are supplied via the Keystream interface, one per
// PRF-grade ITB registry primitive. The keystream construction is delegated to
// the ctr/ package, the single source of truth for cipher key / nonce sizes:
//
//   - Areion-SoEM-256 / Areion-SoEM-512 (16-byte nonce) — AES-round permutation
//     keyed-PRF driving a PRF-CTR keystream via the ITB registry HashFunc
//     factories.
//   - SipHash-2-4 in CTR mode (16-byte nonce) — github.com/dchest/siphash PRF
//     with a custom counter loop, sound under the standard PRF assumption
//     SipHash-2-4 already satisfies as a 128-bit-keyed PRF/MAC.
//   - AES-128-CTR (16-byte nonce) — stdlib, AES-NI accelerated.
//   - BLAKE2b-256 / BLAKE2b-512 / BLAKE2s / BLAKE3 (16-byte nonce) — upstream
//     keyed-hash mode driving a PRF-CTR keystream.
//   - ChaCha20 (RFC8439) (12-byte nonce) — golang.org/x/crypto/chacha20.
//
// Per-stream nonce hygiene: every Wrap entry point generates a fresh CSPRNG
// nonce and emits it once at stream start. Each byte position of a stream maps
// to a unique counter value, so the logical keystream is one monotonic CTR
// sequence per (key, nonce). The blob Wrap / Unwrap paths may evaluate disjoint
// byte ranges of that single sequence concurrently — each worker seeks its own
// keystream to its chunk offset (via ctr.NewAt) and emits a byte-identical
// result, so parallelism changes neither the output nor reuses any counter.
// This is standard CTR mode usage — not nonce-reuse. Nonce-reuse means two
// distinct streams using the SAME (key, nonce); avoid that by using a fresh
// CSPRNG nonce per stream, which every entry point in this package does.
package wrapper
