package hashes

import "github.com/everanium/itb"

// Areion256Pair returns a fresh (single, batched) Areion-SoEM-256 hash
// pair for itb.Seed256 integration. The two arms share the same
// internally-generated random fixed key so that per-pixel hashes
// computed via the batched dispatch match the single-call path
// bit-exact (the parity invariant required by itb.BatchHashFunc256).
//
// On amd64 with VAES + AVX-512 the batched arm routes per-pixel
// hashing four pixels per call through AreionSoEM256x4, yielding ~2×
// throughput over the single-call path. On hosts without those
// extensions the batched arm falls back to four single-call
// invocations and remains bit-exact.
//
// This is a thin wrapper over the in-package itb.MakeAreionSoEM256Hash
// helper; it exists so that Areion-SoEM-256 fits the same name-keyed
// factory shape as the rest of the hashes/ package.
//
// With no argument a fresh 32-byte fixed key is generated via
// crypto/rand; passing a single caller-supplied [32]byte uses that
// key instead. The returned key (random or supplied) is always
// emitted as the third return value — save it for cross-process
// persistence.
func Areion256Pair(key ...[32]byte) (itb.HashFunc256, itb.BatchHashFunc256, [32]byte) {
	return itb.MakeAreionSoEM256Hash(key...)
}

// Areion256PairWithKey returns the (single, batched) Areion-SoEM-256
// pair built around a caller-supplied 32-byte fixed key. Same role as
// the WithKey variants on the other hashes/ primitives — meant for the
// persistence-restore path where the original fixed key has been saved
// across processes (encrypt today, decrypt tomorrow).
//
// Thin wrapper over itb.MakeAreionSoEM256HashWithKey for symmetry with
// the rest of the hashes/ package's WithKey factories.
func Areion256PairWithKey(fixedKey [32]byte) (itb.HashFunc256, itb.BatchHashFunc256) {
	return itb.MakeAreionSoEM256HashWithKey(fixedKey)
}
