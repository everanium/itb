//go:build !amd64 || purego || noitbasm

// Stub package on platforms where the AVX-512 + VL chain-absorb
// kernels do not apply. The parent hashes/ package falls back to
// github.com/dchest/siphash directly in this case; nothing here is
// exercised.
package siphashasm

// HasAVX512Fused is always false on non-amd64 / purego builds.
var HasAVX512Fused = false
