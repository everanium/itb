package itb

import (
	"encoding/binary"
	"fmt"
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
//   mode == 0 → byte-level split (default, shipped behaviour).
//   mode != 0 → bit-level split ("bit-soup"; opt-in reserve mode).
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
// the original plaintext bytes. Reports a length-prefix validation error
// if the prefix does not fit within the recovered payload (indicates
// corrupted ciphertext or mode mismatch between encrypt and decrypt).
func interleaveForTriple(p0, p1, p2 []byte) ([]byte, error) {
	if !isBitSoupEnabled() {
		return interleaveTriple(p0, p1, p2), nil
	}
	totalBits := recoverTripleBitsLen(len(p0), len(p1), len(p2))
	framed := interleaveTripleBits(p0, p1, p2, totalBits)
	if len(framed) < 4 {
		return nil, fmt.Errorf("itb: bit-soup payload too small for length prefix: %d bytes", len(framed))
	}
	length := binary.BigEndian.Uint32(framed[:4])
	if uint64(length)+4 > uint64(len(framed)) {
		return nil, fmt.Errorf("itb: bit-soup length prefix exceeds payload: length=%d, payload=%d", length, len(framed))
	}
	return framed[4 : 4+int(length)], nil
}
