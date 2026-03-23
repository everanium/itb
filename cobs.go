package itb

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
// Reference: Cheshire & Baker, "Consistent Overhead Byte Stuffing",
// IEEE/ACM Transactions on Networking, 1999.
func cobsEncode(src []byte) []byte {
	out := make([]byte, 0, len(src)+len(src)/254+2)

	// Reserve first code byte slot
	out = append(out, 0)
	codeIdx := 0
	code := byte(1)

	for _, b := range src {
		if b == 0 {
			out[codeIdx] = code
			codeIdx = len(out)
			out = append(out, 0) // placeholder for next code
			code = 1
		} else {
			out = append(out, b)
			code++
			if code == 0xFF {
				out[codeIdx] = code
				codeIdx = len(out)
				out = append(out, 0) // placeholder
				code = 1
			}
		}
	}

	// Write final code byte
	out[codeIdx] = code

	return out
}

// cobsDecode reverses COBS encoding, restoring original binary data including 0x00 bytes.
//
// Returns nil if src is empty.
func cobsDecode(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	out := make([]byte, 0, len(src))
	idx := 0
	for idx < len(src) {
		code := src[idx]
		idx++
		if code == 0 {
			break
		}
		for i := byte(1); i < code && idx < len(src); i++ {
			out = append(out, src[idx])
			idx++
		}
		// Implicit 0x00 after each group with code < 0xFF,
		// except the last group (no more encoded data follows).
		if code < 0xFF && idx < len(src) {
			out = append(out, 0x00)
		}
	}
	return out
}
