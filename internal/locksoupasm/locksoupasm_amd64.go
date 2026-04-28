//go:build amd64 && !purego

// Package locksoupasm holds the BMI2 PEXT/PDEP assembly implementation
// of the per-chunk LockSoup keyed bit-permutation kernels. It lives in
// an internal subpackage by the same convention as `internal/areionasm/`
// because the parent `itb` package uses CGO (Go's build system does not
// allow Go assembly files in CGO-using packages).
//
// Only the assembly entry points and the runtime BMI2 capability flag
// are exported. The parent package `itb` dispatches between the BMI2
// path and the pure-Go softPEXT24 / softPDEP24 fallback based on
// HasBMI2.
package locksoupasm

import "golang.org/x/sys/cpu"

// HasBMI2 caches whether the runtime CPU supports BMI2 (PEXT, PDEP).
// Resolved once at init time from the upstream cpu package's
// CPUID-driven detection. Available on Intel Haswell+ and AMD Excavator+
// (Zen 1+); essentially every modern x86 SKU shipped after 2013.
var HasBMI2 = cpu.X86.HasBMI2

// Chunk24Lock applies the LockSoup keyed bit-permutation to a 24-bit
// input x under three balanced 8-of-24 masks (m0, m1, m2) and returns
// the three 8-bit lane outputs in the low byte of (l0, l1, l2). The
// caller is responsible for packing the input bytes — typically
// `x = uint32(a) | uint32(b)<<8 | uint32(c)<<16` — and for unpacking
// the lane bytes via `byte(...)`.
//
// The assembly body issues three BMI2 PEXTL instructions, one per
// lane, ~3 cycles each on modern x86. Total ~10 cycles including
// argument loads — vs ~450 cycles for three pure-Go softPEXT24 calls.
//
// Caller must supply popcount(m_i) == 8 with m0|m1|m2 == 0xFFFFFF and
// pairwise-disjoint masks (the LockSoup balanced-triple invariant).
// Behaviour is undefined for malformed mask triples, matching the
// existing chunk24lock contract.
//
//go:noescape
func Chunk24Lock(x, m0, m1, m2 uint32) (l0, l1, l2 uint32)

// Unchunk24Lock is the inverse of Chunk24Lock. Given three lane bytes
// (l0, l1, l2 in the low byte of each uint32) and the same mask triple,
// returns the original packed 24-bit input. Three BMI2 PDEPL
// instructions plus two ORs.
//
//go:noescape
func Unchunk24Lock(l0, l1, l2, m0, m1, m2 uint32) (x uint32)
