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

// HasAVX512RankMask caches whether the runtime CPU supports the AVX-512F
// feature set used by the batched Lock Soup Triple mask-derivation kernel
// (VPERMD / VPCMPUD / VPSRLVD / mask-merged VPSUBD on ZMM). Resolved once at
// init time from CPUID. Available on Intel Skylake-X / Ice Lake / Rocket
// Lake / Sapphire Rapids+, AMD Zen 4 / Zen 5. Broader than the VBMI gate of
// HasAVX512Permute — only base AVX-512F is required.
var HasAVX512RankMask = cpu.X86.HasAVX512F

// cRowTable[p] holds C(p, 0..8) in dword lanes 0..8 (lanes 9..15 zero) — the
// per-position binomial row the kernel selects from by remaining-count. The
// combinatorial-number-system unrank reads C(p, krem) at descending position
// p; krem in [0,8] indexes within the row via VPERMD (register permute, no
// secret-indexed memory).
var cRowTable [25][16]uint32

func init() {
	var c [25][9]uint64
	for n := 0; n <= 24; n++ {
		c[n][0] = 1
		for k := 1; k <= 8 && k <= n; k++ {
			c[n][k] = c[n-1][k-1] + c[n-1][k]
		}
	}
	for p := 0; p <= 24; p++ {
		for k := 0; k <= 8; k++ {
			cRowTable[p][k] = uint32(c[p][k])
		}
	}
}

// RankToMaskTripleUnrankBatch derives 8 balanced (m0, m1, m2) 24-bit mask
// triples in parallel from 8 precomputed combinadic index pairs. idx0[j] in
// [0, C(24,8)) selects the 8-of-24 mask m0; idx1[j] in [0, C(16,8)) selects
// the 8-of-16 mask remapped onto the positions m0 leaves free, giving m1; m2
// is the complement. The index split (the division) is computed caller-side
// in Go; this kernel does only the two unranks and the remap. Output:
// out[0]=m0 lanes, out[1]=m1, out[2]=m2.
//
// Constant-time: C(p, krem) is selected by VPERMD (register permute, no
// secret-indexed memory) and the per-position pick is applied via mask
// registers, so neither the memory-access pattern nor the control flow
// depends on the secret indices. Caller gates on [HasAVX512RankMask].
func RankToMaskTripleUnrankBatch(idx0, idx1 *[8]uint32, out *[3][8]uint32) {
	rankToMaskTripleUnrankAVX512(idx0, idx1, &cRowTable, out)
}

//go:noescape
func rankToMaskTripleUnrankAVX512(idx0, idx1 *[8]uint32, crow *[25][16]uint32, out *[3][8]uint32)

// HasAVX512RankPerm caches whether the runtime CPU supports the feature set
// used by the batched Single Lock Soup permutation-derivation kernel: base
// AVX-512F plus AVX-512 VPOPCNTDQ (per-lane VPOPCNTD for the d-th-free-slot
// binary search). Narrower than HasAVX512RankMask — available on Intel Ice
// Lake / Tiger Lake / Rocket Lake / Sapphire Rapids+, AMD Zen 4 / Zen 5;
// absent on Skylake-X / Cascade Lake (which carry AVX-512F but not
// VPOPCNTDQ). Caller falls back to the scalar derivePermutation otherwise.
var HasAVX512RankPerm = cpu.X86.HasAVX512F && cpu.X86.HasAVX512VPOPCNTDQ

// DerivePermPositions computes, for 8 lanes in parallel, the 24-element Lehmer
// expansion of precomputed factoradic digit columns. digits[i] holds the
// i-th Lehmer digit of all 8 lanes (digit i in [0, 24-i)); out[i] receives
// the chosen 0..23 position for output index i of each lane. The factoradic
// digit extraction (the division) is done caller-side in Go; this kernel does
// the free-slot expansion: at each step the d-th still-free position is found
// by a 5-level VPOPCNTD binary search and then cleared from the free mask.
// The caller marshals out[i][lane] into per-lane perm/invPerm byte arrays.
//
// Constant-time: the search reads no secret-indexed memory and branches only
// via mask registers. Caller gates on [HasAVX512RankPerm].
func DerivePermPositions(digits, out *[24][8]uint32) {
	derivePermPosAVX512(digits, out)
}

//go:noescape
func derivePermPosAVX512(digits, out *[24][8]uint32)
