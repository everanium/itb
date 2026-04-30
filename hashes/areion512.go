package hashes

import "github.com/everanium/itb"

// Areion512Pair returns a fresh (single, batched) Areion-SoEM-512 hash
// pair for itb.Seed512 integration. Same construction principle as
// Areion256Pair: a fresh random 64-byte fixed key shared between the
// single-call and batched arms, ensuring bit-exact agreement between
// the two dispatch paths.
//
// On amd64 with VAES + AVX-512 the batched arm uses the
// AreionSoEM512x4 ASM kernel; on other hosts both arms degrade to the
// portable Go fallback while remaining bit-identical.
// With no argument a fresh 64-byte fixed key is generated via
// crypto/rand; passing a single caller-supplied [64]byte uses that
// key instead. The returned key (random or supplied) is always
// emitted as the third return value — save it for cross-process
// persistence.
func Areion512Pair(key ...[64]byte) (itb.HashFunc512, itb.BatchHashFunc512, [64]byte) {
	return itb.MakeAreionSoEM512Hash(key...)
}

// Areion512PairWithKey returns the (single, batched) Areion-SoEM-512
// pair built around a caller-supplied 64-byte fixed key. Same role as
// the WithKey variants on the other hashes/ primitives — meant for the
// persistence-restore path where the original fixed key has been saved
// across processes (encrypt today, decrypt tomorrow).
//
// Thin wrapper over itb.MakeAreionSoEM512HashWithKey.
func Areion512PairWithKey(fixedKey [64]byte) (itb.HashFunc512, itb.BatchHashFunc512) {
	return itb.MakeAreionSoEM512HashWithKey(fixedKey)
}
