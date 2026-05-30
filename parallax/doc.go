// Package parallax implements horizontal cipher multiplexing over a
// user-configured palette of counter-mode primitives. Plaintext is split
// into fixed-size segments; each segment is encrypted under one cipher
// chosen from the palette by a per-message keyed schedule.
//
// Honest framing. The construction does NOT strengthen any individual
// cipher's per-segment keystream: where slot-k is the assigned
// keystream for a segment, the adversary's task on that segment is no
// harder than breaking cipher k in isolation. The value is vendor and
// jurisdictional diversity — keying material flows through more than
// one algorithm family per message, so a deployed pipeline can avoid
// baking in a single foreign primitive — and multiplicative
// defense-in-depth across the palette: recovery of one slot's subkey
// through a key-recovery attack on the corresponding cipher does NOT
// yield the master, the scheduling subkey, or any other slot's
// subkey under the PRF assumption on the anchor primitive's KDF.
// Plaintext recovery from a single recovered slot subkey is therefore
// bounded by the schedule permutation entropy (log_2(N!) bits)
// combined with the attacker's plaintext-validity oracle, and even
// then exposes only the segments that fall on the recovered slot.
// Treat parallax as a transparent envelope that dilutes exposure to a
// single primitive's catastrophic break across the full palette, not
// as a cryptographic upgrade over a single strong primitive.
//
// The keystream layer routes through the registry primitives exposed by
// the ctr and kdf packages; any name accepted by ctr.NewResettable is a
// valid palette entry, and palette entries may repeat (a duplicate name
// in a different slot draws an independently-keyed instance).
//
// Surfaces. The package exposes a single-message API (Encrypt, Decrypt,
// EncryptInPlace, DecryptInPlace) and a streaming API (NewEncryptWriter,
// NewDecryptWriter, NewEncryptReader, NewDecryptReader). The
// single-message wire is `nonce(16) || ciphertext_body`. The streaming
// wire is a concatenation of per-chunk frames, each shaped as
// `u32_LE(body_len) || nonce(16) || encrypted_body(body_len)`, where
// the chunk size is read once at stream construction from the
// Schedule's ChunkSize and is fixed for that stream's lifetime. Every
// chunk draws an independent CSPRNG nonce.
//
// The streaming Writers carry sticky-failure semantics: once any
// underlying error has surfaced (encrypt failure, length-prefix outside
// the accepted range, dst.Write failure), every subsequent Write and
// the first Close return the same error and no further frames are
// emitted; a second Close returns nil. The streaming decoder rejects
// any frame whose parsed body length is negative or exceeds
// MaxChunkSize before allocating the body buffer.
//
// The wire is Non-AEAD by design. The single-message wire performs no
// integrity check on the ciphertext body; the streaming wire's 4-byte
// length prefix is unauthenticated, so a single-bit modification to
// any prefix desynchronises every subsequent frame on the stream.
// parallax composes under ITB's authenticated transport (Easy Mode or
// Streaming AEAD) when wire integrity is required; standalone use
// assumes integrity is provided by the surrounding channel.
package parallax
