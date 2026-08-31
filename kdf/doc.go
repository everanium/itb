// Package kdf derives length-flexible subkeys from a key-derivation
// key using a per-primitive construction selected by registry cipher
// name.
//
// The intended source of the master key-derivation key is a
// high-entropy, uniformly distributed secret such as an ML-KEM
// shared secret. Each supported registry primitive maps to a
// standard, separately analysable construction:
//
//   - "areion256", "areion512" — SP 800-108 KDF in Counter Mode,
//     PRF = the registry Areion-SoEM keyed hash. areion512 needs a
//     64-byte PRF key; a 32-byte master is deterministically stretched
//     to 64 bytes via areion256 first.
//   - "siphash24" — NIST SP 800-108 KDF in Counter Mode, PRF =
//     SipHash-2-4 with 128-bit output.
//   - "aescmac"   — NIST SP 800-108 KDF in Counter Mode, PRF =
//     AES-CMAC over AES-128.
//   - "blake2b256", "blake2b512", "blake2s", "blake3" — SP 800-108
//     KDF in Counter Mode, PRF = the primitive's native keyed hash.
//   - "chacha20"  — XChaCha20 keystream KDF with the public label as
//     the 24-byte nonce.
//
// [Derive] returns an error for any other name.
//
// A public domain-separation label keeps independent derivations
// from the same master distinct. Labels need only be unique per
// intended subkey; they carry no secrecy requirement.
package kdf
