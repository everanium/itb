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
// The outer ciphers are supplied via the Keystream interface, one per
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
//   - ChaCha20 (RFC 8439) (12-byte nonce) — golang.org/x/crypto/chacha20.
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
//
// # API surface
//
// One-shot blob envelopes: [Wrap] and [Unwrap] take an allocation-friendly
// key + input pair and return a fresh output slice; [WrapInPlace] and
// [UnwrapInPlace] transform the input buffer in place for callers who
// want zero-allocation on the hot path (the caller supplies a buffer
// large enough for the nonce prefix + payload; the return slice
// references the same underlying storage).
//
// Streaming envelopes: [NewWrapWriter] wraps an [io.Writer] so bytes
// written to the returned writer are XORed with the keystream and
// flushed downstream; [FinishWrapStream] signals end-of-stream on that
// writer. [NewUnwrapReader] is the inverse — reading from the returned
// reader consumes wrapped bytes off an upstream [io.Reader] and yields
// the plaintext.
//
// Parallel byte-range XOR: [XORParallel] and [XORParallelAt] drive
// worker goroutines seeking disjoint keystream ranges via ctr.NewAt;
// used by the Wrap/Unwrap blob paths when the input exceeds
// [ParallelThreshold]. Callers who want serial-only behaviour set an
// input smaller than that threshold or use the [NewWrapWriter] /
// [NewUnwrapReader] streaming shape which is single-goroutine.
//
// Registry access: [CipherNames] enumerates the canonical outer-cipher
// alphabet in the same order the shared library's ITB_CipherName
// iteration surface exposes; each entry appears as a matching
// [CipherAreion256] / [CipherAreion512] / [CipherBLAKE2b256] /
// [CipherBLAKE2b512] / [CipherBLAKE2s] / [CipherBLAKE3] /
// [CipherAES128CTR] / [CipherSipHash24] / [CipherChaCha20] name
// constant. [KeySize] and [NonceSize] delegate to the ctr package for
// per-primitive byte lengths.
//
// Key management: [GenerateKey] draws a fresh CSPRNG key of the
// primitive's canonical size; [DeriveKey] runs the [github.com/everanium/itb/kdf]
// counter-mode KDF over a supplied master with a fixed domain label
// so wrapper keys stay orthogonal to other subkeys derived from the
// same master.
package wrapper
