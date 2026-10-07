// Package aesitb is an audit-oriented pure-Go reference implementation of
// the AES-ITB primitive. The production inner-Barrier path does not use
// this package — the shipping implementation lives in the itb root
// package (aesitb.go), which wires the nonce-free generic hash
// (HashGeneric here) into the ChainHash dispatch and the
// per-architecture SIMD kernels of internal/aesitbasm. The session-keyed
// shapes ([SessionInit], [Session.HashPixel]) are reference-only and have
// no shipped counterpart. The reference exists to cross-check the
// shipping implementation via KAT vectors and the root prod-vs-reference
// parity tests.
//
// ITB uses this package only as the "aesitb128" DRBG noise-fill arm,
// [FillNoise], its blocks defined by [HashGeneric] so the same vectors
// pin it. Carrier noise needs uniform bytes rather than PRF security,
// which the primitive's measured output uniformity (HARNESS.md § 3.10)
// supports.
//
// # Warning
//
// AES-ITB is not a PRF standalone (Non-PRF, ClassNPRF in the hashes
// registry): the seed enters once, by XOR, ahead of a fixed public
// permutation, so one full 16-byte output inverts to the seed. Outside
// ITB's inner-Barrier compositions its only sanctioned use is
// [FillNoise], under a key and nonce drawn inside the call and never
// exposed. FillNoise must not be used to encrypt data, to derive keys,
// nonces or seed components, or as a general-purpose random source; a
// keystream over data takes a PRF-grade registry primitive through the
// ctr package.
package aesitb
