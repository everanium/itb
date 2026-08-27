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

// HasAVX512RankMask caches whether the runtime CPU supports the AVX-512F
// feature set used by the batched 48-bit interlock mask-derivation
// kernel (VPERMI2Q, VPCMPUQ, VPSRLVQ, mask-merged VPSUBQ on ZMM).
// Resolved once at init time from CPUID. Available on Intel
// Skylake-X / Ice Lake / Rocket Lake / Sapphire Rapids+, AMD Zen 4 /
// Zen 5. Only base AVX-512F is required.
var HasAVX512RankMask = cpu.X86.HasAVX512F

// crow48Table holds C(p, 0..16) in qword lanes 0..16 (lane 16 stored
// separately after the two-ZMM header) — the per-position binomial row
// the kernel selects from by remaining-count. The combinatorial-number-
// system unrank reads C(p, krem) at descending position p; krem in
// [0, 16] addresses the row via VPERMI2Q on the first 16 lanes with a
// mask-merged broadcast of the 17-th value when krem == 16.
//
// Row layout: [17]uint64 in memory, 136 bytes per row. Total table
// size = 49 * 136 = 6664 bytes, fits L1.
var crow48Table [49][17]uint64

func init() {
	var c [49][17]uint64
	for n := 0; n <= 48; n++ {
		c[n][0] = 1
		for k := 1; k <= 16 && k <= n; k++ {
			c[n][k] = c[n-1][k-1] + c[n-1][k]
		}
	}
	crow48Table = c
}

// RankToMaskTripleUnrank48 derives 8 balanced (m0, m1, m2) 48-bit mask
// triples in parallel from 8 precomputed combinadic index pairs.
// idx0[j] in [0, C(48,16)) selects the 16-of-48 mask m0; idx1[j] in
// [0, C(32,16)) selects the 16-of-32 mask remapped onto the positions
// m0 leaves free, giving m1; m2 is the complement (m0|m1|m2 == 2^48-1).
// The index split (the 128-bit rank divmod) is computed caller-side in
// Go; this kernel does only the two unranks and the remap. Output:
// out[0] = m0 lanes, out[1] = m1, out[2] = m2.
//
// Constant-time: C(p, krem) is selected by VPERMI2Q from a two-ZMM
// row window (register permute, no secret-indexed memory) with a
// scalar-broadcast mask-merge for the krem == 16 spillover lane, and
// the per-position pick is applied via mask registers, so neither the
// memory-access pattern nor the control flow depends on the secret
// indices. Caller gates on [HasAVX512RankMask].
func RankToMaskTripleUnrank48(idx0 *[8]uint64, idx1 *[8]uint32, out *[3][8]uint64) {
	rankToMaskTripleUnrank48AVX512(idx0, idx1, &crow48Table, out)
}

//go:noescape
func rankToMaskTripleUnrank48AVX512(idx0 *[8]uint64, idx1 *[8]uint32, crow *[49][17]uint64, out *[3][8]uint64)

// HasAVX2RankMask caches whether the runtime CPU should use the AVX2
// 4-lane batched rank-unrank kernel: AVX2 present, BMI2 present (the
// kernel's remap tail issues scalar PDEPQ), and AVX-512F absent (an
// AVX-512F CPU takes the wider 8-lane ZMM kernel instead). Covers
// AVX2-only silicon such as AMD Zen 1-3, Intel Haswell through Comet
// Lake, and AVX2-only cloud VMs.
var HasAVX2RankMask = cpu.X86.HasAVX2 && cpu.X86.HasBMI2 && !cpu.X86.HasAVX512F

// RankToMaskTripleUnrank48AVX2 derives 8 balanced (m0, m1, m2) 48-bit
// mask triples from 8 precomputed combinadic index pairs — the same
// contract as [RankToMaskTripleUnrank48] — via the AVX2 4-lane batched
// kernel (two YMM halves per invocation). Caller gates on
// [HasAVX2RankMask].
//
// Constant-time: the crow row address depends only on the public loop
// position; the secret per-lane remaining-count index is consumed by
// register-only, data-oblivious operations (VPERMD register permute and
// VPCMPEQQ / VPCMPGTQ predicates), so neither the memory-access pattern
// nor the control flow depends on the secret indices — the same
// invariant the AVX-512 kernel establishes for VPERMI2Q.
func RankToMaskTripleUnrank48AVX2(idx0 *[8]uint64, idx1 *[8]uint32, out *[3][8]uint64) {
	rankToMaskTripleUnrank48AVX2(idx0, idx1, &crow48Table, out)
}

//go:noescape
func rankToMaskTripleUnrank48AVX2(idx0 *[8]uint64, idx1 *[8]uint32, crow *[49][17]uint64, out *[3][8]uint64)
