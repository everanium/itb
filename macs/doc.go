// Package macs provides cached, pre-keyed wrappers around the three
// PRF-grade Message Authentication Codes that ITB ships with as
// built-in factories for the C / FFI / mobile shared-library
// distribution.
//
// All three primitives produce a 32-byte tag and accept a 32-byte
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
// Standards conformance:
//   - kmac256       — NIST SP 800-185 Section 4.3.1, output L = 256
//                     bits; bit-exact KAT cross-checked against
//                     pycryptodome's KMAC256 implementation.
//   - hmac-sha256   — RFC 2104 / FIPS 198-1 with SHA-256;
//                     bit-exact KAT against RFC 4231 vectors.
//   - hmac-blake3   — BLAKE3 native keyed mode (BLAKE3 spec §6),
//                     covered by upstream zeebo/blake3 keyed-mode
//                     KAT and the ITB Auth round-trip integration
//                     test in this package.
//
// Why these three. ITB's MAC-Inside-Encrypt construction places the
// 32-byte tag inside the encrypted container, where the barrier
// dispersal (process256 / process128 / process512) already destroys
// any plaintext / tag boundary the attacker could see; under
// SetLockSoup(1) the bit-permutation layer further obscures the
// payload region. Combined, this means the MAC primitive itself
// only has to be a sound keyed PRF — the surrounding ITB
// construction takes care of placement-hiding, replay-resistance
// (via the per-message nonce), and CCA-resistance.
//
// All three factories are PRF-grade and stateless across the FFI
// boundary; concurrent goroutines may call the returned closure in
// parallel.
package macs
