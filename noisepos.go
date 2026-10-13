package itb

import "math/bits"

// noiseFold3 reduces a 64-bit hash word to a 3-bit noise position.
// The fold is GF(2)-linear and every input bit reaches exactly one
// output bit (32, 16 and 16 input bits respectively), so no fixed
// bit position of the hash output decides the position on its own.
func noiseFold3(w uint64) uint {
	w ^= w >> 32
	w ^= w >> 16
	w ^= w >> 8
	w ^= w >> 4
	n := w & 15
	return uint((n ^ n>>3) & 7)
}

// noiseMix combines words 0 and 1 of the noise hash into the word that
// noiseFold3 reduces: word 0 plus word 1 rotated by one bit, modulo
// 2^64. For independent uniform words the sum is uniform. A primitive
// whose two words are related by identity, complement or a constant
// XOR does not cancel to a constant or to a reduced set of positions:
// a XOR of the two words cancels under each of those relations, and a
// bit permutation of word 1 alone still leaves the fold's output parity
// fixed, while the carries of the addition break both.
func noiseMix(word0, word1 uint64) uint64 {
	return word0 + bits.RotateLeft64(word1, 1)
}

// noisePosition derives the per-pixel noise bit position from words 0
// and 1 of the noise hash, so all 128 bits of those two words reach
// the position and the position stays a function of the noise seed
// alone.
func noisePosition(word0, word1 uint64) uint {
	return noiseFold3(noiseMix(word0, word1))
}

// noiseCounterBase returns the noise-hash counter offset of region i.
// The noise seed is shared by the three regions, so the noise hash runs
// one counter across the whole container: region i hashes the counter
// values [i*third, i*third + regionPixels). The regions therefore read
// disjoint stretches of a single position sequence, and no relative
// shift lines the position sequence of one region up with another's.
// The data hash keeps the per-region counter starting at 0, since each
// region's data seed is its own.
func noiseCounterBase(region, third int) int {
	return region * third
}

// noiseIdx4 and noiseIdx8 shift a batch of per-region pixel indices to
// the noise-hash counter values of [noiseCounterBase].
func noiseIdx4(idx [4]int, base int) [4]int {
	for i := range idx {
		idx[i] += base
	}
	return idx
}

func noiseIdx8(idx [8]int, base int) [8]int {
	for i := range idx {
		idx[i] += base
	}
	return idx
}
