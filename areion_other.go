//go:build !amd64 || purego

package itb

// On non-amd64 platforms (or under the `purego` build tag) there is no
// VAES assembly; the 4-way batched permutations dispatch directly to
// the portable Go fallback.

func areion256Permutex4(states *[4][32]byte) {
	areion256Permutex4Default(states)
}

func areion512Permutex4(states *[4][64]byte) {
	areion512Permutex4Default(states)
}
