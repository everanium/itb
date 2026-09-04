// Package ctr provides counter-mode keystream constructions over
// PRF-grade ITB registry primitives. Supports primitives with native
// cipher mode (AES-CTR, ChaCha20) and PRF-counter mode, where a
// keystream block is the primitive's keyed-PRF output over the nonce
// concatenated with the block counter.
//
// The package is the single source of truth for cipher key and nonce
// sizes. [KeySize] and [NonceSize] report the per-primitive byte
// lengths a caller must allocate before invoking [New] / [NewAt] /
// [NewResettable] / [NewResettableAt]. Callers who need to enumerate
// the registry consult the shipped [github.com/everanium/itb/hashes.Registry]
// — [github.com/everanium/itb/hashes.Names] returns its names in canonical
// order and the [github.com/everanium/itb/hashes.CipherAES128CTR] family of
// constants names each entry; every name resolves via the registry
// look-up embedded in the constructor call.
//
// Each keystream satisfies the [Keystream] interface, whose
// XORKeyStream method matches the [crypto/cipher.Stream] contract:
// the keystream segment is XORed over src into dst while the internal
// counter advances. Callers who need to rewind or re-seek to a
// specific byte offset within a keystream draw the
// [ResettableKeystream] variant instead — its Reset / Seek methods
// realign the internal counter without redrawing the key.
package ctr
