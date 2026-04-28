//go:build amd64 && !purego

package itb

import "github.com/everanium/itb/internal/areionasm"

// areion256Permutex4 dispatches between three implementations of the
// 4-way Areion256 permutation, in throughput order:
//
//  1. VAES + AVX-512 assembly (`internal/areionasm/areion_amd64.s`,
//     `Areion256Permutex4`) — single VAES instruction processes 4 AES
//     blocks per call on ZMM registers. Selected when
//     `aes.CPU.HasVAES && aes.CPU.HasAVX512` is true.
//  2. VAES + AVX2 assembly (`Areion256Permutex4Avx2`) — VAES on YMM,
//     2 AES blocks per VAES instruction, each round body runs twice
//     (one per lane pair). Selected on x86_64 CPUs that have VAES but
//     lack AVX-512 (some hybrid Intel Alder Lake / Raptor Lake
//     configurations, certain AMD Zen 3 SKUs).
//  3. Portable Go fallback (`areion256Permutex4Default`) — uses
//     `aes.Round4HW(state, zeroKey)` which itself dispatches
//     internally to per-block AES-NI on hardware without VAES, or to
//     ARM crypto extensions on arm64.
//
// All three paths produce bit-exact identical output (the
// `BatchHashFunc256` parity invariant); only throughput differs.
func areion256Permutex4(states *[4][32]byte) {
	switch {
	case areionasm.HasVAESAVX512:
		x0, x1 := pack256x4SoA(states)
		areionasm.Areion256Permutex4(&x0, &x1)
		unpack256x4SoA(&x0, &x1, states)
	case areionasm.HasVAESAVX2NoAVX512:
		x0, x1 := pack256x4SoA(states)
		areionasm.Areion256Permutex4Avx2(&x0, &x1)
		unpack256x4SoA(&x0, &x1, states)
	default:
		areion256Permutex4Default(states)
	}
}

// areion512Permutex4 mirrors areion256Permutex4's three-way dispatch
// for the 15-round Areion512 permutation.
func areion512Permutex4(states *[4][64]byte) {
	switch {
	case areionasm.HasVAESAVX512:
		x0, x1, x2, x3 := pack512x4SoA(states)
		areionasm.Areion512Permutex4(&x0, &x1, &x2, &x3)
		unpack512x4SoA(&x0, &x1, &x2, &x3, states)
	case areionasm.HasVAESAVX2NoAVX512:
		x0, x1, x2, x3 := pack512x4SoA(states)
		areionasm.Areion512Permutex4Avx2(&x0, &x1, &x2, &x3)
		unpack512x4SoA(&x0, &x1, &x2, &x3, states)
	default:
		areion512Permutex4Default(states)
	}
}
