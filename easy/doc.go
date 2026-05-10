// Package easy — streaming surface and bindings asymmetry.
//
// [Encryptor] exposes two parallel streaming surfaces. The
// callback-driven family ([Encryptor.EncryptStream] /
// [Encryptor.DecryptStream] and the authenticated counterparts
// [Encryptor.EncryptStreamAuth] / [Encryptor.DecryptStreamAuth])
// invokes a [ChunkFunc] once per output chunk in stream order and
// is the natural fit when the caller already holds the full
// plaintext (or full ciphertext) in memory and prefers per-chunk
// control over emission. The IO-Driven family
// ([Encryptor.EncryptStreamIO] / [Encryptor.DecryptStreamIO] and
// the authenticated counterparts [Encryptor.EncryptStreamAuthIO] /
// [Encryptor.DecryptStreamAuthIO]) consumes [io.Reader] / writes
// [io.Writer] and drives the read/write loop internally — suited
// to inputs that exceed RAM. The two surfaces produce identical
// on-wire bytes for matching configurations.
//
// Streaming AEAD per-chunk primitives.
// [Encryptor.EncryptStreamAuthenticated] and
// [Encryptor.DecryptStreamAuthenticated] are the per-chunk
// primitives at the Easy Mode surface. The caller supplies the
// 32-byte streamID (CSPRNG-fresh per stream, written once as the
// wire prefix preceding chunk 0), the running cumulative pixel
// offset of all preceding chunks, and the finalFlag (true on the
// terminating chunk only). Each call returns one self-contained
// authenticated wire chunk. [Encryptor.HeaderSize] and
// [Encryptor.ParseChunkLen] expose the per-instance header parsers
// used to walk a concatenated transcript without reading whole
// chunks into memory.
//
// Bindings asymmetry. The [Encryptor.EncryptStreamIO] /
// [Encryptor.DecryptStreamIO] methods drive the No-MAC plain-stream
// loop internally over [io.Reader] / [io.Writer]. The official
// language bindings expose the No-MAC stream surface as per-chunk
// free functions only and let the caller drive the read/write loop.
// Both patterns produce identical on-wire bytes; the IO-method form
// is a Go-side convenience.
package easy
