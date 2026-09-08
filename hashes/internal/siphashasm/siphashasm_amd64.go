//go:build amd64 && !purego && !noitbasm

package siphashasm

import "golang.org/x/sys/cpu"

// Batch-16 tier flags: auto-select the AVX-512 tier when the host offers
// it, else the AVX2 tier. The flags are package variables so the
// forcetier init and the in-package dispatch tests can override the
// auto-selection. Only one flag is true; the family keeps the "one
// consistent set" invariant the forcetier init relies on. The flags
// select the arm of FusedChain13x16 (siphashasm_fused_amd64.go), the
// Interlocked Barrier fill kernel: the ZMM kernel under HasAVX512X16,
// four AVX2 x4 calls over Go-synthesised blocks under HasAVX2X16.
var (
	HasAVX512X16 = cpu.X86.HasAVX512F
	HasAVX2X16   = cpu.X86.HasAVX2 && !HasAVX512X16

	// HasNEONX16 is always false on amd64 builds.
	HasNEONX16 = false
)
