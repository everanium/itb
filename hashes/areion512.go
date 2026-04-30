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
func Areion512Pair() (itb.HashFunc512, itb.BatchHashFunc512) {
	return itb.MakeAreionSoEM512Hash()
}
