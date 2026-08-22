//go:build amd64 && !purego && !noitbasm

// Package interlock holds the BMI2 PEXTQ / PDEPQ assembly implementation
// of the per-chunk 48-bit interlock keyed bit-permutation kernels. It
// lives in an internal subpackage by the same convention as
// `internal/locksoupasm/` because the parent `itb` package uses CGO
// (Go's build system does not allow Go assembly files in CGO-using
// packages).
//
// Only the assembly entry points and the runtime BMI2 capability flag
// are exported. The parent package `itb` dispatches between the BMI2
// path and the pure-Go softPEXT48 / softPDEP48 fallback based on
// HasBMI2.
package interlock

import "golang.org/x/sys/cpu"

// HasBMI2 caches whether the runtime CPU supports BMI2 (PEXT, PDEP).
// Resolved once at init time from the upstream cpu package's
// CPUID-driven detection. Available on Intel Haswell+ and AMD
// Excavator+ (Zen 1+); essentially every modern x86 SKU shipped after
// 2013.
var HasBMI2 = cpu.X86.HasBMI2

// Chunk48Lock applies the 48-bit interlock keyed bit-permutation to
// an input x (low 48 bits carry six chunk bytes in little-endian
// order) under three balanced 16-of-48 masks (m0, m1, m2) and returns
// the three lane outputs in the low 16 bits of (l0, l1, l2). The
// caller is responsible for packing the input bytes — typically
// `x = uint64(b0) | uint64(b1)<<8 | ... | uint64(b5)<<40` — and for
// truncating each lane via `uint16(...)`.
//
// The assembly body issues three BMI2 PEXTQ instructions, one per
// lane, ~3 cycles each on modern x86 — total ~10 cycles including
// argument loads. Upper 48 bits of each returned uint64 are zero
// (PEXTQ zero-extends unselected positions), so truncation is a
// no-op on the payload bits.
//
// Caller must supply popcount(m_i) == 16 with m0|m1|m2 == 2^48-1 and
// pairwise-disjoint masks. Behaviour is undefined for malformed mask
// triples, matching the existing chunk48lock contract.
//
//go:noescape
func Chunk48Lock(x, m0, m1, m2 uint64) (l0, l1, l2 uint64)

// Unchunk48Lock is the inverse of Chunk48Lock. Given three 16-bit
// lane values (in the low 16 bits of each uint64) and the same mask
// triple, returns the original 48-bit input packed into the low 48
// bits of a uint64. Three BMI2 PDEPQ instructions plus two ORs.
//
//go:noescape
func Unchunk48Lock(l0, l1, l2, m0, m1, m2 uint64) (x uint64)
