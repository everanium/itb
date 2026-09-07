package itb

import (
	"bytes"
	"encoding/binary"
	"math/bits"
)

// cobsEncode transforms arbitrary binary data so that 0x00 never appears in output.
//
// COBS (Consistent Overhead Byte Stuffing) encodes data by replacing 0x00 bytes
// with run-length codes. Overhead is at most 1 byte per 254 input bytes (~0.4%).
//
// This implementation follows the algorithm from the original paper exactly:
// each output group starts with a code byte indicating how many non-zero data
// bytes follow. Code < 0xFF means a 0x00 follows the data bytes (implicit).
// Code = 0xFF means 254 non-zero bytes follow with no implicit 0x00.
// A final code byte always terminates the encoding.
//
// The scan finds the next 0x00 with an 8-byte word-trick peek followed by
// [bytes.IndexByte] over the tail — the latter's amd64 / arm64 runtime
// assembly reaches the next zero at memory-bandwidth speed on random-uniform
// input. Runs are emitted in one [copy] per 254-byte group into a
// preallocated output whose sentinel code-byte slots are left as the
// spec-guaranteed zero fill of [make] until the group closes and the code
// byte is written in place.
//
// Reference: Cheshire & Baker, "Consistent Overhead Byte Stuffing",
// IEEE/ACM Transactions on Networking, 1999.
func cobsEncode(src []byte) []byte {
	n := len(src)
	out := make([]byte, n+n/254+2)
	pos, codeIdx, fill := 1, 0, 0
	i := 0
	for i < n {
		// Scan for the next 0x00. An 8-byte word-trick peek catches
		// zero-dense inputs without paying an IndexByte call per byte;
		// otherwise IndexByte finds the next zero via the runtime's
		// amd64 / arm64 assembly (portable Go loop on other arches).
		var j int
		if n-i >= 8 {
			v := binary.LittleEndian.Uint64(src[i : i+8])
			if m := (v - 0x0101010101010101) &^ v & 0x8080808080808080; m != 0 {
				j = i + bits.TrailingZeros64(m)>>3
			} else if k := bytes.IndexByte(src[i+8:], 0); k < 0 {
				j = n
			} else {
				j = i + 8 + k
			}
		} else if k := bytes.IndexByte(src[i:], 0); k < 0 {
			j = n
		} else {
			j = i + k
		}
		// Emit the zero-free run src[i:j], splitting at every 254-byte
		// group boundary. The placeholder code byte at codeIdx is zeroed
		// by make; only the finalised 0xFF is written back explicitly.
		for i < j {
			take := j - i
			if room := 254 - fill; take > room {
				take = room
			}
			copy(out[pos:pos+take], src[i:i+take])
			pos += take
			fill += take
			i += take
			if fill == 254 {
				out[codeIdx] = 0xFF
				codeIdx = pos
				pos++
				fill = 0
			}
		}
		if j < n {
			// Zero found: close the group with the fill+1 code, open a
			// new group starting at pos, skip past the source zero.
			out[codeIdx] = byte(fill + 1)
			codeIdx = pos
			pos++
			fill = 0
			i = j + 1
		}
	}
	out[codeIdx] = byte(fill + 1)
	return out[:pos]
}

// cobsDecode reverses COBS encoding, restoring original binary data including 0x00 bytes.
//
// Returns nil if src is empty.
//
// Each group is copied in one [copy] into a preallocated output; the implicit
// trailing 0x00 after a short group is a bare position increment on the
// spec-zeroed buffer of [make], so the inner loop performs one bulk copy per
// group instead of one append per byte.
func cobsDecode(src []byte) []byte {
	n := len(src)
	if n == 0 {
		return nil
	}
	out := make([]byte, n)
	pos, idx := 0, 0
	for idx < n {
		code := src[idx]
		idx++
		if code == 0 {
			break
		}
		end := idx + int(code) - 1
		if end > n {
			end = n
		}
		pos += copy(out[pos:], src[idx:end])
		idx = end
		// Implicit 0x00 after each group with code < 0xFF, except the
		// last group (no more encoded data follows). The output slot is
		// already zero from make, so advance the position only.
		if code < 0xFF && idx < n {
			pos++
		}
	}
	return out[:pos]
}
