package capi

import (
	"encoding/binary"
	"math"

	"github.com/everanium/itb"
)

// ParseChunkLen reports the total wire size of a chunk after
// inspecting only the fixed-size header at the front of the buffer.
//
// The header layout is [nonce || width(2) || height(2)] where the
// nonce length comes from the caller-supplied nonceBytes (16 / 32 /
// 64 for 128 / 256 / 512-bit nonces). chunk_total = headerSize +
// width * height * itb.Channels.
//
// Unlike itb.ParseChunkLenCfg, this helper requires only the header
// bytes to be present — it does not insist that the entire chunk
// body already sit in the buffer. That is the semantic streaming
// FFI consumers want: read `nonceBytes+4` bytes from disk → ask for
// chunk_len → read the remaining (chunk_len - (nonceBytes+4)) bytes
// → hand the full chunk to Decrypt. The body-length check at decrypt
// time stays inside the cipher entry points where it belongs.
//
// Returns StatusBadInput when nonceBytes is not one of {16, 32, 64},
// the buffer is shorter than the header, the dimensions are zero /
// overflow, or the announced pixel count exceeds the container pixel
// cap.
func ParseChunkLen(header []byte, nonceBytes int) (int, Status) {
	switch nonceBytes {
	case 16, 32, 64:
	default:
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	headerSz := nonceBytes + 4
	if len(header) < headerSz {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	width := int(binary.BigEndian.Uint16(header[nonceBytes:]))
	height := int(binary.BigEndian.Uint16(header[nonceBytes+2:]))
	if width == 0 || height == 0 {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	if width > math.MaxInt/height {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	totalPixels := width * height
	if totalPixels > math.MaxInt/itb.Channels {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	// Container pixel-count cap mirrors the upstream itb.ParseChunkLenCfg
	// limit. Without this cap a hostile chunk header announcing
	// width × height ≈ 7 GB could drive a binding to allocate that
	// much before the underlying Decrypt rejects.
	if totalPixels > maxTotalPixels {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	return headerSz + totalPixels*itb.Channels, StatusOK
}

// maxTotalPixels mirrors the unexported itb constant of the same
// name. Bindings that drive the streaming decrypt path size their
// per-chunk buffer by ParseChunkLen's return value, and the cap
// keeps a maliciously-large announced size from landing as a
// gigabyte allocation on the binding side.
const maxTotalPixels = 10_000_000
