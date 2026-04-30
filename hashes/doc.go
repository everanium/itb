// Package hashes provides cached, pre-keyed wrappers around the nine
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
// for measured throughput across all nine primitives × three ITB key
// widths (512 / 1024 / 2048).
//
// Canonical names and ordering (used by [Registry], [Find], [Make128],
// [Make256], [Make512] and exposed through the FFI surface as the
// public hash identifier):
//
//	areion256, areion512, siphash24, aescmac,
//	blake2b256, blake2b512, blake2s, blake3, chacha20
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
package hashes
