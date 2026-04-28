package itb

import (
	"encoding/binary"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/everanium/itb/internal/locksoupasm"
)

// bitSoupEnabled controls Triple Ouroboros plaintext split granularity for the
// whole process. Default 0 = byte-level split (shipped behaviour). Non-zero =
// bit-level "bit-soup" split — each snake's payload becomes a fixed public
// permutation of 8 bits drawn from 3 consecutive real plaintext bytes, with
// a 4-byte length prefix prepended to the plaintext before the split so the
// decrypt side can recover the exact byte length without widening the wire
// header.
//
// Stored in an atomic.Int32 so concurrent reads from parallel encrypt /
// decrypt goroutines are race-free. Each Encrypt3x* / Decrypt3x* call performs
// a single load at dispatch and uses that captured value for the entire
// operation.
var bitSoupEnabled atomic.Int32

// SetBitSoup configures Triple Ouroboros split granularity for the whole
// process.
//
//	mode == 0 → byte-level split (default, shipped behaviour).
//	mode != 0 → bit-level split ("bit-soup"; opt-in reserve mode).
//
// Applies uniformly to every Triple Ouroboros variant — [Encrypt3x128] /
// [Decrypt3x128], the 256- / 512-bit mirrors, [EncryptAuthenticated3x128] /
// [DecryptAuthenticated3x128] and their mirrors, and the streaming variants
// [EncryptStream3x128] / [DecryptStream3x128] and mirrors. The ciphertext
// wire format is identical in both modes: [nonce][W][H][pixels].
//
// Deployment discipline: set the mode once at process startup before any
// encrypt or decrypt call; callers must agree on the mode across both sides
// of the channel. Encrypt-decrypt with mismatched modes produces either a
// length-prefix error or byte-level garbage (detectable via authenticated
// variants' MAC check or caller-side integrity validation).
//
// Bit-soup relocates the SAT-cryptanalysis barrier from the
// computational layer to the instance-formulation layer. Under Partial KPA +
// realistic protocol traffic, the joint per-snake SAT instance is
// information-theoretically under-determined at the crib coverage realistic
// protocols supply — a property of the observations available to the
// attacker, not of the solver applied to them. Improvements in solver
// performance do not convert an under-determined instance into a determined
// one. This is orthogonal to, not stronger than, computational hardness.
func SetBitSoup(mode int32) { bitSoupEnabled.Store(mode) }

// GetBitSoup returns the current Triple Ouroboros split mode
// (0 = byte-level, non-zero = bit-level). See [SetBitSoup].
func GetBitSoup() int32 { return bitSoupEnabled.Load() }

// isBitSoupEnabled is the internal dispatch check used by splitForTriple /
// interleaveForTriple.
func isBitSoupEnabled() bool { return bitSoupEnabled.Load() != 0 }

// prependTripleLen returns [uint32_BE(len(data)):4] || data. The 4-byte big-
// endian length prefix is carried inside the plaintext across the bit-level
// split; after decrypt-side interleave, the first 4 bytes of the recovered
// stream give the exact plaintext length, enabling deterministic slicing
// without a separate header widening.
func prependTripleLen(data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(out[:4], uint32(len(data)))
	copy(out[4:], data)
	return out
}

// splitForTriple dispatches between byte-level [splitTriple] and bit-level
// [splitTripleBits] based on the current [SetBitSoup] mode. Reads the atomic
// flag once; the captured value governs this call entirely.
func splitForTriple(data []byte) (p0, p1, p2 []byte) {
	if isBitSoupEnabled() {
		p0, p1, p2, _ = splitTripleBits(prependTripleLen(data))
		return
	}
	return splitTriple(data)
}

// recoverTripleBitsLen returns the largest totalBits value consistent with
// the observed part byte-length triple produced by [splitTripleBits].
//
// Sizing formulas of splitTripleBits:
//
//	n0_bits = (totalBits + 2) / 3, packed into n0_bytes = ceil(n0_bits / 8)
//	n1_bits = (totalBits + 1) / 3, packed into n1_bytes
//	n2_bits = totalBits / 3,       packed into n2_bytes
//
// Inverting with the integer-division identity floor((a+k)/3) <= m  iff
// a <= 3m + 2 - k yields the per-part upper bounds:
//
//	totalBits <= 24*n0            (from n0_bits bound)
//	totalBits <= 24*n1 + 1        (from n1_bits bound)
//	totalBits <= 24*n2 + 2        (from n2_bits bound)
//
// The minimum of the three bounds is the tightest totalBits consistent with
// the byte-length triple. [interleaveTripleBits] called with this value
// produces output whose prefix up to the true plaintext length is identical
// to the true output (prefix-identity property), so reading the 4-byte BE
// length prefix and slicing to exact length recovers the plaintext
// deterministically.
func recoverTripleBitsLen(n0, n1, n2 int) int {
	b0 := 24 * n0
	b1 := 24*n1 + 1
	b2 := 24*n2 + 2
	m := b0
	if b1 < m {
		m = b1
	}
	if b2 < m {
		m = b2
	}
	if m < 0 {
		return 0
	}
	return m
}

// interleaveForTriple dispatches between byte-level [interleaveTriple] and
// bit-level [interleaveTripleBits] based on the current [SetBitSoup] mode.
// On the bit-soup path, strips the 4-byte length prefix and returns only
// the original plaintext bytes. Plausible-decryption invariant: never
// errors. Wrong-seed brute-force feeds garbage `p0/p1/p2` here; the
// function returns garbage bytes (clamped to the recovered payload
// extent) instead of distinguishing wrong-seed attempts from valid ones
// via an error oracle.
func interleaveForTriple(p0, p1, p2 []byte) []byte {
	if !isBitSoupEnabled() {
		return interleaveTriple(p0, p1, p2)
	}
	totalBits := recoverTripleBitsLen(len(p0), len(p1), len(p2))
	framed := interleaveTripleBits(p0, p1, p2, totalBits)
	if len(framed) < 4 {
		// Wrong-seed garbage: return whatever bits exist. Right-seed
		// path always produces framed ≥ 4 bytes by encoder invariant.
		return framed
	}
	length := binary.BigEndian.Uint32(framed[:4])
	end := uint64(length) + 4
	if end > uint64(len(framed)) {
		// Wrong-seed garbage: clamp to payload extent. Right-seed path
		// always produces a valid length prefix.
		end = uint64(len(framed))
	}
	return framed[4:int(end)]
}

// splitTripleBits splits data into 3 parts at the bit level: bits[0::3], bits[1::3], bits[2::3].
// Each part is packed into bytes. Returns parts and totalBits for reassembly.
func splitTripleBits(data []byte) (p0, p1, p2 []byte, totalBits int) {
	totalBits = len(data) * 8
	n0 := (totalBits + 2) / 3
	n1 := (totalBits + 1) / 3
	n2 := totalBits / 3
	p0 = make([]byte, (n0+7)/8)
	p1 = make([]byte, (n1+7)/8)
	p2 = make([]byte, (n2+7)/8)

	for i := 0; i < totalBits; i++ {
		srcByte := i / 8
		srcBit := uint(i % 8)
		bit := (data[srcByte] >> srcBit) & 1

		part := i % 3
		idx := i / 3
		dstByte := idx / 8
		dstBit := uint(idx % 8)

		switch part {
		case 0:
			p0[dstByte] |= bit << dstBit
		case 1:
			p1[dstByte] |= bit << dstBit
		case 2:
			p2[dstByte] |= bit << dstBit
		}
	}
	return
}

// interleaveTripleBits reassembles 3 bit-level parts into original data.
func interleaveTripleBits(p0, p1, p2 []byte, totalBits int) []byte {
	result := make([]byte, (totalBits+7)/8)

	for i := 0; i < totalBits; i++ {
		part := i % 3
		idx := i / 3
		srcByte := idx / 8
		srcBit := uint(idx % 8)

		var bit byte
		switch part {
		case 0:
			bit = (p0[srcByte] >> srcBit) & 1
		case 1:
			bit = (p1[srcByte] >> srcBit) & 1
		case 2:
			bit = (p2[srcByte] >> srcBit) & 1
		}

		dstByte := i / 8
		dstBit := uint(i % 8)
		result[dstByte] |= bit << dstBit
	}
	return result
}

// splitTripleBitsParallel produces output bit-identical to [splitTripleBits]
// via period-3-byte chunking. Each 24-bit chunk is independent - chunk k
// reads input bytes [3k, 3k+2] and writes byte k of every lane buffer.
// Disjoint output indices across chunks → workers run without locks.
// Tail bits (when len(data) is not divisible by 3) processed sequentially
// after the parallel pass; the tail spans at most 16 bits across at most
// one byte per lane.
func splitTripleBitsParallel(data []byte) (p0, p1, p2 []byte, totalBits int) {
	totalBits = len(data) * 8
	n0 := (totalBits + 2) / 3
	n1 := (totalBits + 1) / 3
	n2 := totalBits / 3
	p0 = make([]byte, (n0+7)/8)
	p1 = make([]byte, (n1+7)/8)
	p2 = make([]byte, (n2+7)/8)

	M := len(data) / 3

	if M > 0 {
		G := runtime.NumCPU()
		if G > M {
			G = M
		}
		chunksPerWorker := (M + G - 1) / G
		var wg sync.WaitGroup
		for w := 0; w < G; w++ {
			start := w * chunksPerWorker
			end := start + chunksPerWorker
			if end > M {
				end = M
			}
			if start >= end {
				continue
			}
			wg.Add(1)
			go func(s, e int) {
				defer wg.Done()
				for k := s; k < e; k++ {
					l0, l1, l2 := chunk24(data[3*k], data[3*k+1], data[3*k+2])
					p0[k] = l0
					p1[k] = l1
					p2[k] = l2
				}
			}(start, end)
		}
		wg.Wait()
	}

	tailStart := 24 * M
	for i := tailStart; i < totalBits; i++ {
		srcByte := i / 8
		srcBit := uint(i % 8)
		bit := (data[srcByte] >> srcBit) & 1

		part := i % 3
		idx := i / 3
		dstByte := idx / 8
		dstBit := uint(idx % 8)

		switch part {
		case 0:
			p0[dstByte] |= bit << dstBit
		case 1:
			p1[dstByte] |= bit << dstBit
		case 2:
			p2[dstByte] |= bit << dstBit
		}
	}
	return
}

// interleaveTripleBitsParallel produces output bit-identical to
// [interleaveTripleBits] via the inverse 24-bit chunk kernel. Chunk k
// reads byte k of every lane and writes output bytes [3k, 3k+2]. Tail
// bits handled sequentially after the parallel pass.
func interleaveTripleBitsParallel(p0, p1, p2 []byte, totalBits int) []byte {
	result := make([]byte, (totalBits+7)/8)
	M := totalBits / 24

	if M > 0 {
		G := runtime.NumCPU()
		if G > M {
			G = M
		}
		chunksPerWorker := (M + G - 1) / G
		var wg sync.WaitGroup
		for w := 0; w < G; w++ {
			start := w * chunksPerWorker
			end := start + chunksPerWorker
			if end > M {
				end = M
			}
			if start >= end {
				continue
			}
			wg.Add(1)
			go func(s, e int) {
				defer wg.Done()
				for k := s; k < e; k++ {
					a, b, c := unchunk24(p0[k], p1[k], p2[k])
					result[3*k] = a
					result[3*k+1] = b
					result[3*k+2] = c
				}
			}(start, end)
		}
		wg.Wait()
	}

	for i := 24 * M; i < totalBits; i++ {
		part := i % 3
		idx := i / 3
		srcByte := idx / 8
		srcBit := uint(idx % 8)

		var bit byte
		switch part {
		case 0:
			bit = (p0[srcByte] >> srcBit) & 1
		case 1:
			bit = (p1[srcByte] >> srcBit) & 1
		case 2:
			bit = (p2[srcByte] >> srcBit) & 1
		}

		dstByte := i / 8
		dstBit := uint(i % 8)
		result[dstByte] |= bit << dstBit
	}
	return result
}

// chunk24 is the forward 24-bit-permutation kernel - splits 3 input bytes
// into 3 lane bytes per the (i mod 3) round-robin distribution starting
// at phase 0. Output positions are derived from the per-byte fill table:
// byte a contributes (3, 3, 2) bits to lanes (0, 1, 2); byte b adds
// (3, 2, 3); byte c adds (2, 3, 3).
func chunk24(a, b, c byte) (l0, l1, l2 byte) {
	l0 = (a & 1) |
		(((a >> 3) & 1) << 1) |
		(((a >> 6) & 1) << 2) |
		(((b >> 1) & 1) << 3) |
		(((b >> 4) & 1) << 4) |
		(((b >> 7) & 1) << 5) |
		(((c >> 2) & 1) << 6) |
		(((c >> 5) & 1) << 7)
	l1 = ((a >> 1) & 1) |
		(((a >> 4) & 1) << 1) |
		(((a >> 7) & 1) << 2) |
		(((b >> 2) & 1) << 3) |
		(((b >> 5) & 1) << 4) |
		((c & 1) << 5) |
		(((c >> 3) & 1) << 6) |
		(((c >> 6) & 1) << 7)
	l2 = ((a >> 2) & 1) |
		(((a >> 5) & 1) << 1) |
		((b & 1) << 2) |
		(((b >> 3) & 1) << 3) |
		(((b >> 6) & 1) << 4) |
		(((c >> 1) & 1) << 5) |
		(((c >> 4) & 1) << 6) |
		(((c >> 7) & 1) << 7)
	return
}

// unchunk24 is the inverse of [chunk24] - reassembles 3 lane bytes back
// into the original 3-byte input chunk.
func unchunk24(l0, l1, l2 byte) (a, b, c byte) {
	a = (l0 & 1) |
		((l1 & 1) << 1) |
		((l2 & 1) << 2) |
		(((l0 >> 1) & 1) << 3) |
		(((l1 >> 1) & 1) << 4) |
		(((l2 >> 1) & 1) << 5) |
		(((l0 >> 2) & 1) << 6) |
		(((l1 >> 2) & 1) << 7)
	b = ((l2 >> 2) & 1) |
		(((l0 >> 3) & 1) << 1) |
		(((l1 >> 3) & 1) << 2) |
		(((l2 >> 3) & 1) << 3) |
		(((l0 >> 4) & 1) << 4) |
		(((l1 >> 4) & 1) << 5) |
		(((l2 >> 4) & 1) << 6) |
		(((l0 >> 5) & 1) << 7)
	c = ((l1 >> 5) & 1) |
		(((l2 >> 5) & 1) << 1) |
		(((l0 >> 6) & 1) << 2) |
		(((l1 >> 6) & 1) << 3) |
		(((l2 >> 6) & 1) << 4) |
		(((l0 >> 7) & 1) << 5) |
		(((l1 >> 7) & 1) << 6) |
		(((l2 >> 7) & 1) << 7)
	return
}

// lockSoupEnabled controls the LockSoup keyed-permutation overlay on top of
// the Triple Ouroboros bit-soup path. Default 0 = off (chunk24 / unchunk24
// fixed permutation, ciphertext bit-identical to plain bit-soup). Non-zero =
// on (chunk24lock / unchunk24lock per-chunk PRF-keyed permutation, ~33 bits
// of keyed entropy per 24-bit chunk).
//
// Stored in an atomic.Int32 so concurrent reads from parallel encrypt /
// decrypt goroutines are race-free. Each Encrypt3x* / Decrypt3x* call
// performs a single load at dispatch and uses that captured value for the
// entire operation.
var lockSoupEnabled atomic.Int32

// SetLockSoup configures the LockSoup keyed-permutation overlay for the
// whole process.
//
//	mode == 0 → off (default; ciphertext bit-identical to plain bit-soup).
//	mode != 0 → on (per-chunk PRF-keyed bit-permutation; requires
//	            SetBitSoup(1) — silent no-op when bit-soup is off).
//
// Applies uniformly to every Triple Ouroboros variant — [Encrypt3x128] /
// [Decrypt3x128], the 256- / 512-bit mirrors, [EncryptAuthenticated3x128] /
// [DecryptAuthenticated3x128] and their mirrors. Both sides of the channel
// must use the same mode; mismatched modes produce wrong-seed-style garbage
// (no error oracle, plausible-decryption invariant preserved).
//
// Deployment discipline: set the mode once at process startup before any
// encrypt or decrypt call; callers must agree on the mode across both sides
// of the channel.
//
// LockSoup raises the Triple bit-soup attacker-enumeration cost from the
// public-encoding +18.1 bits (startPixel triple) to +33 bits per crib chunk
// of additional keyed permutation entropy, making any SAT-tractable
// recovery path infeasible even for below-spec primitives. This is an
// opt-in defense-reserve mode layered on top of [SetBitSoup], itself
// opt-in.
func SetLockSoup(mode int32) { lockSoupEnabled.Store(mode) }

// GetLockSoup returns the current LockSoup overlay mode (0 = off, non-zero
// = on). See [SetLockSoup].
func GetLockSoup() int32 { return lockSoupEnabled.Load() }

// isLockSoupEnabled is the internal dispatch check used by
// [splitForTripleParallelLocked] / [interleaveForTripleParallelLocked].
// Single atomic load. Called exactly once at entry of the locked
// dispatchers; the returned bool is captured in a local and the
// per-chunk loop branches on the local, not on this function.
func isLockSoupEnabled() bool { return lockSoupEnabled.Load() != 0 }

// binomialC holds C(n, k) for n in [0, 24], k in [0, 8] — the table needed
// for combinatorial unrank in [rankToMaskTriple]. Computed once at package
// init time via Pascal's recurrence.
var binomialC [25][9]uint64

func init() {
	for n := 0; n <= 24; n++ {
		binomialC[n][0] = 1
		for k := 1; k <= 8 && k <= n; k++ {
			binomialC[n][k] = binomialC[n-1][k-1] + binomialC[n-1][k]
		}
	}
}

// unrankCombination converts a rank in [0, C(n,k)) into a 32-bit mask of
// exactly k set bits drawn from positions [0, n). Standard combinadic
// decomposition: rank = C(c_k, k) + C(c_{k-1}, k-1) + ... + C(c_1, 1) with
// c_k > c_{k-1} > ... > c_1 >= 0; each c_i identifies a set bit position.
//
// Caller must supply rank < C(n, k); behaviour is undefined for out-of-range
// rank. n must be ≤ 24 (binomialC table extent).
func unrankCombination(rank uint64, k, n int) uint32 {
	var mask uint32
	for k > 0 {
		c := k - 1
		for c+1 <= n-1 && binomialC[c+1][k] <= rank {
			c++
		}
		mask |= uint32(1) << uint(c)
		rank -= binomialC[c][k]
		k--
	}
	return mask
}

// maskSpaceProduct is C(24,8) × C(16,8) = 735471 × 12870 = 9,465,511,770,
// the count of balanced (m0, m1, m2) partitions of 24 bits into 3 disjoint
// 8-bit groups (m2 is the complement of m0|m1, hence not independently
// chosen). log2(maskSpaceProduct) ≈ 33.14 bits.
const maskSpaceProduct uint64 = 735471 * 12870

// rankToMaskTriple maps a 64-bit PRF output to a balanced (m0, m1, m2)
// 24-bit mask triple where popcount(m_i) == 8, m0|m1|m2 == 0xFFFFFF, and
// pairwise intersections are empty. Modulo bias to maskSpaceProduct is
// negligible: 2^64 / maskSpaceProduct ≈ 1.95 × 10^9 with bias factor
// ~(2^64 mod product) / 2^64 < 2^-30, well below any cryptographic concern
// for the mask-selection role.
func rankToMaskTriple(prf uint64) (m0, m1, m2 uint32) {
	const c168 uint64 = 12870

	idx := prf % maskSpaceProduct
	idx0 := idx / c168 // ∈ [0, 735471) — selects m0 from C(24,8)
	idx1 := idx % c168 // ∈ [0, 12870)  — selects m1 from C(16,8)

	m0 = unrankCombination(idx0, 8, 24)

	// m1Local: 8-of-16 mask in the local indexing of remaining positions.
	m1Local := unrankCombination(idx1, 8, 16)

	// Map m1Local positions onto the actual remaining bit positions
	// (bits where m0 is zero).
	remaining := uint32(0xFFFFFF) & ^m0
	var posIdx uint
	for bit := uint(0); bit < 24; bit++ {
		if (remaining>>bit)&1 == 1 {
			if (m1Local>>posIdx)&1 == 1 {
				m1 |= uint32(1) << bit
			}
			posIdx++
		}
	}
	m2 = remaining & ^m1
	return
}

// softPEXT24 compresses bits of x selected by mask into a contiguous
// low-order byte result. Pure-Go portable equivalent of the x86 BMI2 PEXT
// instruction restricted to 24-bit width. Caller must supply popcount(mask)
// ≤ 8 — exactly 8 in the LockSoup balanced-mask path. ~50 cycles bit-by-bit
// loop; acceptable for opt-in defense-reserve mode.
func softPEXT24(x, mask uint32) byte {
	var result byte
	var outBit uint
	for i := uint(0); i < 24; i++ {
		if (mask>>i)&1 == 1 {
			if (x>>i)&1 == 1 {
				result |= 1 << outBit
			}
			outBit++
		}
	}
	return result
}

// softPDEP24 expands the low-order popcount(mask) bits of v into the
// positions selected by mask, producing a 24-bit value. Pure-Go portable
// equivalent of the x86 BMI2 PDEP instruction restricted to 24-bit width.
// Inverse of [softPEXT24] under matching mask: softPEXT24(softPDEP24(v,
// mask), mask) == v for popcount(mask) == 8 and v < 256.
func softPDEP24(v byte, mask uint32) uint32 {
	var result uint32
	var inBit uint
	for i := uint(0); i < 24; i++ {
		if (mask>>i)&1 == 1 {
			if (v>>inBit)&1 == 1 {
				result |= uint32(1) << i
			}
			inBit++
		}
	}
	return result
}

// chunk24lock is the LockSoup-on counterpart of [chunk24]. Applies a
// PRF-keyed bit-permutation to a 3-byte input chunk under mask triple
// (m0, m1, m2) supplied by the caller (typically derived via [lockPRF]).
// Each lane gets exactly 8 bits compressed by its mask.
//
// On amd64 with BMI2 (Haswell+, Excavator+), dispatches to the
// [locksoupasm.Chunk24Lock] hardware path — three PEXT instructions
// total, ~10 cycles per chunk. On other platforms or when BMI2 is
// unavailable, falls back to three [softPEXT24] calls (~450 cycles per
// chunk). The branch predicts perfectly because [locksoupasm.HasBMI2]
// is a process-lifetime constant.
func chunk24lock(a, b, c byte, m0, m1, m2 uint32) (l0, l1, l2 byte) {
	x := uint32(a) | uint32(b)<<8 | uint32(c)<<16
	if locksoupasm.HasBMI2 {
		L0, L1, L2 := locksoupasm.Chunk24Lock(x, m0, m1, m2)
		return byte(L0), byte(L1), byte(L2)
	}
	l0 = softPEXT24(x, m0)
	l1 = softPEXT24(x, m1)
	l2 = softPEXT24(x, m2)
	return
}

// unchunk24lock is the inverse of [chunk24lock]. Reassembles 3 lane bytes
// into the original 3-byte input chunk under the same (m0, m1, m2) mask
// triple. Caller must supply the same masks used by chunk24lock — encoder
// and decoder agree by deriving identical masks from the shared lockSeed
// and chunk index.
//
// On amd64 with BMI2, dispatches to the [locksoupasm.Unchunk24Lock]
// hardware path (three PDEP plus two ORs); otherwise falls back to
// three [softPDEP24] calls.
func unchunk24lock(l0, l1, l2 byte, m0, m1, m2 uint32) (a, b, c byte) {
	var x uint32
	if locksoupasm.HasBMI2 {
		x = locksoupasm.Unchunk24Lock(uint32(l0), uint32(l1), uint32(l2), m0, m1, m2)
	} else {
		x = softPDEP24(l0, m0) | softPDEP24(l1, m1) | softPDEP24(l2, m2)
	}
	a = byte(x)
	b = byte(x >> 8)
	c = byte(x >> 16)
	return
}

// lockPRF is the closure-form interface used by LockSoup parallel kernels
// to obtain a per-chunk mask triple. The closure captures the lockSeed
// material and Hash function for the appropriate Seed width (built via
// [buildLockPRF128] / [buildLockPRF256] / [buildLockPRF512] from the
// caller's noiseSeed and nonce); kernels invoke it with a caller-owned
// 13-byte scratch buffer (reused across chunks within a worker
// goroutine) and the global chunk index to obtain (m0, m1, m2) for that
// chunk.
//
// The buf parameter exists to avoid per-chunk heap allocations: passing
// the closure's own [13]byte stack array to the variadic Hash function
// causes Go's escape analysis to allocate per call (the Hash function
// type is interface-like at the call site so the compiler conservatively
// heap-allocates). Caller goroutines stack-allocate buf once and pass
// it to every prf invocation; the buf escape happens at most once per
// goroutine, not once per chunk. Buffer layout:
//
//	buf[0]    = 0x03   (LockSoup keystream domain tag)
//	buf[1:9]  = uint64-LE(globalChunkIdx)
//	buf[9:13] = (unused; reserved for future bound nonce / variant tag)
type lockPRF func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint32)

// splitTripleBitsParallelLocked is the LockSoup-on counterpart of
// [splitTripleBitsParallel]. Pads the input up to a multiple of 3 bytes
// (zero-fill) and processes every 24-bit chunk via [chunk24lock] with a
// per-chunk mask triple obtained from prf(k). No tail handling — padding
// guarantees encoder and decoder agree on the chunk count, which keyed
// permutation requires (the existing fixed-pattern bit-soup tail trick
// relies on chunk24 being equivalent to bit-by-bit round-robin, an
// equivalence that breaks for keyed permutations).
//
// Padding bytes are recovered as garbage by the decoder and discarded by
// the length-prefix slice in [interleaveForTripleParallelLocked]; the
// 4-byte length prefix prepended by the caller [splitForTripleParallelLocked]
// (via [prependTripleLen]) is the source of truth for actual plaintext
// extent.
func splitTripleBitsParallelLocked(data []byte, prf lockPRF) (p0, p1, p2 []byte, totalBits int) {
	L := len(data)
	LPad := ((L + 2) / 3) * 3
	var padded []byte
	if LPad == L {
		padded = data
	} else {
		padded = make([]byte, LPad)
		copy(padded, data)
	}

	totalBits = LPad * 8
	M := LPad / 3

	p0 = make([]byte, M)
	p1 = make([]byte, M)
	p2 = make([]byte, M)

	if M == 0 {
		return
	}

	G := runtime.NumCPU()
	if G > M {
		G = M
	}
	chunksPerWorker := (M + G - 1) / G
	var wg sync.WaitGroup
	for w := 0; w < G; w++ {
		start := w * chunksPerWorker
		end := start + chunksPerWorker
		if end > M {
			end = M
		}
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			var buf [13]byte
			for k := s; k < e; k++ {
				m0, m1, m2 := prf(buf[:], uint64(k))
				l0, l1, l2 := chunk24lock(padded[3*k], padded[3*k+1], padded[3*k+2], m0, m1, m2)
				p0[k] = l0
				p1[k] = l1
				p2[k] = l2
			}
		}(start, end)
	}
	wg.Wait()
	return
}

// interleaveTripleBitsParallelLocked is the inverse of
// [splitTripleBitsParallelLocked]. Processes every 24-bit chunk via
// [unchunk24lock]; no tail handling, mirroring the encoder's
// padding-only design. The result includes any padding bytes the
// encoder added; the caller [interleaveForTripleParallelLocked] strips
// them via the 4-byte length prefix.
func interleaveTripleBitsParallelLocked(p0, p1, p2 []byte, totalBits int, prf lockPRF) []byte {
	M := totalBits / 24
	result := make([]byte, M*3)

	if M == 0 {
		return result
	}

	G := runtime.NumCPU()
	if G > M {
		G = M
	}
	chunksPerWorker := (M + G - 1) / G
	var wg sync.WaitGroup
	for w := 0; w < G; w++ {
		start := w * chunksPerWorker
		end := start + chunksPerWorker
		if end > M {
			end = M
		}
		if start >= end {
			continue
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			var buf [13]byte
			for k := s; k < e; k++ {
				m0, m1, m2 := prf(buf[:], uint64(k))
				a, b, c := unchunk24lock(p0[k], p1[k], p2[k], m0, m1, m2)
				result[3*k] = a
				result[3*k+1] = b
				result[3*k+2] = c
			}
		}(start, end)
	}
	wg.Wait()
	return result
}

// splitForTripleParallelLocked is the LockSoup-aware top-level dispatcher
// for plaintext splitting. The prf argument is always supplied by the
// caller (built once per Encrypt3x* invocation); it is consumed only on
// the locked bit-soup branch. Other branches ignore prf and behave
// identically to [splitForTripleParallel].
//
// Dispatch order: byte-level (bit-soup off) → plain bit-soup (bit-soup on
// + lock-soup off) → locked bit-soup (bit-soup on + lock-soup on).
func splitForTripleParallelLocked(data []byte, prf lockPRF) (p0, p1, p2 []byte) {
	if !isBitSoupEnabled() {
		return splitTripleParallel(data)
	}
	if !isLockSoupEnabled() {
		p0, p1, p2, _ = splitTripleBitsParallel(prependTripleLen(data))
		return
	}
	p0, p1, p2, _ = splitTripleBitsParallelLocked(prependTripleLen(data), prf)
	return
}

// interleaveForTripleParallelLocked is the LockSoup-aware top-level
// dispatcher for plaintext reassembly, mirror of
// [splitForTripleParallelLocked]. Same plausible-decryption invariant as
// [interleaveForTripleParallel] — never errors, returns wrong-seed-style
// garbage clamped to the recovered payload extent on mismatched-mode
// decrypt or wrong-seed brute-force.
func interleaveForTripleParallelLocked(p0, p1, p2 []byte, prf lockPRF) []byte {
	if !isBitSoupEnabled() {
		return interleaveTripleParallel(p0, p1, p2)
	}
	totalBits := recoverTripleBitsLen(len(p0), len(p1), len(p2))
	var framed []byte
	if !isLockSoupEnabled() {
		framed = interleaveTripleBitsParallel(p0, p1, p2, totalBits)
	} else {
		framed = interleaveTripleBitsParallelLocked(p0, p1, p2, totalBits, prf)
	}
	if len(framed) < 4 {
		return framed
	}
	length := binary.BigEndian.Uint32(framed[:4])
	end := uint64(length) + 4
	if end > uint64(len(framed)) {
		end = uint64(len(framed))
	}
	return framed[4:int(end)]
}

// buildLockPRF128 constructs a [lockPRF] closure for the 128-bit Triple
// Ouroboros context. Captures the noiseSeed-derived 128-bit lockSeed and
// the Hash function; per-chunk invocations use a single PRF call (not
// ChainHash) keyed by lockSeed with the chunk index as input, taking 33
// bits of the output as the mask-space rank passed to [rankToMaskTriple].
//
// Caller must supply a non-nil noiseSeed; the closure is always built
// (cheap, ~ns), but it is consumed only on the locked bit-soup branch in
// [splitForTripleParallelLocked].
func buildLockPRF128(noiseSeed *Seed128, nonce []byte) lockPRF {
	lockLo, lockHi := noiseSeed.deriveNoiseSeed(nonce)
	h := noiseSeed.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint32) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		hLo, _ := h(buf, lockLo, lockHi)
		return rankToMaskTriple(hLo)
	}
}

// buildLockPRF256 constructs a [lockPRF] closure for the 256-bit Triple
// Ouroboros context. Captures the full 256-bit noiseSeed-derived lockSeed
// (4 × uint64) and the Hash function; per-chunk PRF call uses native 256-
// bit keying material with the chunk index as input. The 33-bit
// mask-space rank is taken from the first uint64 of the output.
func buildLockPRF256(noiseSeed *Seed256, nonce []byte) lockPRF {
	lockSeed := noiseSeed.deriveNoiseSeed(nonce)
	h := noiseSeed.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint32) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		out := h(buf, lockSeed)
		return rankToMaskTriple(out[0])
	}
}

// buildLockPRF512 constructs a [lockPRF] closure for the 512-bit Triple
// Ouroboros context. Captures the full 512-bit noiseSeed-derived lockSeed
// (8 × uint64) and the Hash function; per-chunk PRF call uses native 512-
// bit keying material with the chunk index as input. The 33-bit
// mask-space rank is taken from the first uint64 of the output.
func buildLockPRF512(noiseSeed *Seed512, nonce []byte) lockPRF {
	lockSeed := noiseSeed.deriveNoiseSeed(nonce)
	h := noiseSeed.Hash
	return func(buf []byte, globalChunkIdx uint64) (m0, m1, m2 uint32) {
		buf[0] = 0x03
		binary.LittleEndian.PutUint64(buf[1:9], globalChunkIdx)
		out := h(buf, lockSeed)
		return rankToMaskTriple(out[0])
	}
}
