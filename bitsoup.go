package itb

import (
	"encoding/binary"
)

// prependTripleLen returns [uint32_BE(len(data)):4] || data. The 4-byte
// big-endian length prefix is carried inside the plaintext across the
// bit-level split; after decrypt-side interleave, the first 4 bytes of
// the recovered stream give the exact plaintext length, enabling
// deterministic slicing without a separate header widening.
func prependTripleLen(data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(out[:4], uint32(len(data)))
	copy(out[4:], data)
	return out
}
