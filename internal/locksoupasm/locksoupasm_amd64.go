//go:build amd64 && !purego && !noitbasm

// Package locksoupasm holds the BMI2 PEXT/PDEP assembly implementation
// of the per-chunk Lock Soup keyed bit-permutation kernels. It lives in
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

// Chunk24Lock applies the Lock Soup keyed bit-permutation to a 24-bit
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
// pairwise-disjoint masks (the Lock Soup balanced-triple invariant).
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

// HasAVX512Permute caches whether the runtime CPU supports the
// AVX-512 feature set required by Permute24Avx512:
//
//   - AVX-512 F  — base 512-bit infrastructure
//   - AVX-512 BW — byte-wise mask ops (VPMOVM2B, VPABSB, VPTESTMB)
//   - AVX-512 VL — 256-bit (YMM) variants of those instructions
//   - AVX-512 VBMI — VPERMB byte-shuffle
//
// Resolved once at init time from golang.org/x/sys/cpu's CPUID-driven
// detection. Available on Intel Ice Lake / Tiger Lake / Rocket Lake /
// Sapphire Rapids+, AMD Zen 4 / Zen 5. Same gate as the Tier A
// per-pixel kernel in process_pixels.c.
var HasAVX512Permute = cpu.X86.HasAVX512F &&
	cpu.X86.HasAVX512BW &&
	cpu.X86.HasAVX512VL &&
	cpu.X86.HasAVX512VBMI

// Permute24Avx512 applies an arbitrary bit permutation π: {0..23} →
// {0..23} to the low 24 bits of x and returns the permuted result.
// perm must be a stack-resident 32-byte buffer; perm[0..23] are the
// source bit positions for output bits 0..23 (output[i] = bit perm[i]
// of x), perm[24..31] must be zero (they are not consumed but VPERMB
// uses them as gather indices into the bit-spread of x; nonzero values
// would contaminate the result before the final 24-bit mask).
//
// The assembly body is ~7 vector instructions plus argument loads,
// totalling ~30–40 cycles per call including Go ABI overhead — vs
// ~80–100 cycles for the pure-Go softPermute24 fallback.
//
// Caller is responsible for the AVX-512 VBMI runtime gate via
// HasAVX512Permute. Calling on a host without VBMI raises #UD.
//
//go:noescape
func Permute24Avx512(x uint32, perm *[32]byte) (y uint32)
