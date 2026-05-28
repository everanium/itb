// Package hashes provides cached, pre-keyed wrappers around
// PRF-grade hash primitives that ITB ships with as built-in factories
// for the C / FFI / mobile shared-library distribution.
//
// Every factory in this package returns a function value compatible
// with one of itb.HashFunc128 / itb.HashFunc256 / itb.HashFunc512
// (matching the primitive's native intermediate-state width). The
// returned closure carries a per-instance random fixed key plus
// pre-computed primitive state (an AES cipher.Block, a BLAKE3 keyed
// template, a sync.Pool of scratch buffers); subsequent invocations
// allocate nothing on the heap.
//
// Without these cached wrappers per-pixel hashing would re-derive
// every primitive's keyed state on every call, which is the dominant
// cost in ITB's encrypt / decrypt path. The factories are taken
// directly from the bench-validated reference wrappers — see BENCH.md
// for measured throughput across all primitives × three ITB key
// widths (512 / 1024 / 2048).
//
// Canonical names and ordering (used by [Registry], [Find], [Make128],
// [Make256], [Make512] and exposed through the FFI surface as the
// public hash identifier.
//
// Each factory has an optional WithKey variant accepting a fixed key
// of the primitive's native key length, intended for serialization /
// deserialization of long-lived seeds across processes (Encrypt today,
// Decrypt tomorrow). SipHash-2-4 has no WithKey variant — the seed
// components themselves are the entire SipHash key, and no fixed-key
// state lives in the factory closure.
//
// All primitives in this package are PRF-grade. The below-spec lab
// stress controls (CRC128, FNV-1a, MD5) used in REDTEAM.md / SCIENCE.md
// are intentionally absent here — they are research instruments, not
// shippable cipher primitives.
//
// # Custom-primitive builders
//
// Beyond shipped primitives, the package exposes three
// builder families for safely wrapping user-supplied PRFs:
//
//   - [BuildCBCMACChainAbsorb128] / [BuildCBCMACChainAbsorb256] /
//     [BuildCBCMACChainAbsorb512] — wrap a keyed block cipher into a
//     CBC-MAC chain-absorb HashFunc closure.
//   - [BuildSpongeChainAbsorb128] / [BuildSpongeChainAbsorb256] /
//     [BuildSpongeChainAbsorb512] — wrap an unkeyed permutation +
//     fixed-key into a keyed-sponge HashFunc closure.
//   - [BuildARXChainAbsorb128] / [BuildARXChainAbsorb256] /
//     [BuildARXChainAbsorb512] — wrap a full hash function (such as
//     [crypto/sha256.Sum256]) + fixed-key into a Merkle-Damgard-style
//     HashFunc closure.
//
// These builders exist primarily to close the silent-nonce-truncation
// trap that a naive user wrapper falls into. A user who writes
//
//	func(data []byte, seed [8]uint64) [8]uint64 {
//	    h := sha256.Sum256(data)
//	    // ... zero-pad upper 32 bytes ... return [8]uint64{...}
//	}
//
// silently truncates the upper half of ITB's 512-bit intermediate
// state to a constant value, destroying half the entropy of
// ChainHash's per-call XOR chain. The builders absorb the full ITB
// nonce width into the digest through the appropriate chain pattern;
// the user only writes a primitive call.
//
// Performance trade-off: the builders dispatch through interface
// callbacks and []byte state buffers, losing 5-15% throughput vs the
// inline per-primitive closures shipped in this package. The trade
// is correctness-by-construction for any user primitive vs peak
// throughput for built-in primitives. See [CONSTRUCTIONS.md]
// "Why use builders for custom user primitives" for the silent-
// truncation failure modes the builders prevent.
package hashes
