package itb

import (
	"encoding/binary"
	"runtime"
	"sync"
	"sync/atomic"
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
