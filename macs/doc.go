// Package macs provides cached, pre-keyed wrappers around the
// PRF-grade Message Authentication Codes that ITB ships with as
// built-in factories for the C / FFI / mobile shared-library
// distribution.
//
// Every shipped MAC produces a 32-byte tag and accepts a 32-byte
// (or longer in the HMAC case) key. The shared 32-byte tag size
// means consumers do not have to vary their authenticated-payload
// layout based on which MAC was selected — a binding-friendly
// invariant.
//
// Canonical names (FFI-stable iteration order, exposed via the
// shared library's ITB_MACName entry point):
//
//	kmac256, hmac-sha256, hmac-blake3
//
// Every factory takes a key byte slice and returns a closure
// matching itb.MACFunc (`func(data []byte) []byte`). The closure
// pre-keys its primitive once (cached cSHAKE256 absorb-state for
// KMAC256, sync.Pool of pre-keyed hmac.Hash instances for
// HMAC-SHA256, blake3.Hasher template for HMAC-BLAKE3) so per-call
// invocation carries no key-derivation overhead.
//
// # Runtime dispatch
//
// The shipped set is discoverable at runtime via [Registry] — an
// immutable array of [Spec] entries in canonical iteration order.
// [Find] resolves a canonical name to its [Spec]; [Make] and
// [MakeIncremental] dispatch by name to the appropriate
// one-shot / incremental factory closure. A caller that wants
// runtime primitive selection (per-configuration MAC choice from a
// user string) reaches for [Make]; a caller that ships a fixed MAC
// per profile constructs the factory closure directly (e.g.
// [HMACBLAKE3], [KMAC256], [HMACSHA256]).
//
// The incremental variants ([HMACBLAKE3Incremental],
// [HMACSHA256Incremental], [KMAC256Incremental],
// [KMAC256IncrementalWithCustomization]) return an
// [itb.MACIncrementalFunc] closure — a Writer-shaped MAC that
// absorbs successive chunks and finalises to the 32-byte tag on
// demand. Used by [github.com/everanium/itb.EncryptStreamAuth3xCfg]
// so a Streaming AEAD wire authenticates without buffering the
// whole plaintext.
//
// The KMAC256-With-Customization pair ([KMAC256WithCustomization],
// [KMAC256IncrementalWithCustomization]) exposes the NIST SP 800-185
// customization-string parameter for callers who want per-application
// domain separation baked into the MAC rather than injected via a
// per-call label; the customization byte string is public and pinned
// per profile / per session.
//
// Standards conformance:
//   - kmac256       — NIST SP 800-185 Section 4.3.1, output L = 256
//     bits; bit-exact KAT cross-checked against
//     pycryptodome's KMAC256 implementation.
//   - hmac-sha256   — RFC 2104 / FIPS 198-1 with SHA-256;
//     bit-exact KAT against RFC 4231 vectors.
//   - hmac-blake3   — BLAKE3 native keyed mode (BLAKE3 spec §6),
//     covered by upstream zeebo/blake3 keyed-mode
//     KAT and the ITB Auth round-trip integration
//     test in this package.
//
// Rationale for the shipped set. ITB's MAC-Inside-Encrypt construction
// places the 32-byte tag inside the encrypted container, where the ITB
// barrier dispersal already destroys any plaintext / tag boundary the
// attacker could see, and the Triple Ouroboros 48-bit interlock overlay
// further obscures the payload region. Combined, this means the MAC
// primitive itself only has to be a sound keyed PRF — the surrounding
// ITB construction takes care of placement-hiding, replay-resistance
// (via the per-message nonce), and CCA-resistance.
//
// Every shipped factory is PRF-grade and stateless across the FFI
// boundary; concurrent goroutines may call the returned closure in
// parallel.
package macs
