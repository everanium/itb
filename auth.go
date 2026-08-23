package itb

// MACFunc is the pluggable MAC function interface.
//
// The function must accept a byte slice and return a fixed-size tag.
// The MAC key management is the caller's responsibility — the MACFunc
// closure should capture the key.
//
// The tag is computed over the entire encrypted payload (COBS + null
// terminator + random padding), not just the plaintext. Given a secure
// MAC function, flipping any data bit in the container causes MAC failure,
// preventing the CCA spatial pattern that would otherwise distinguish
// padding from data regions (see SCIENCE.md Section 4.3).
//
// Example wrappers:
//
//	// HMAC-SHA256 (crypto/hmac + crypto/sha256)
//	func hmacSHA256(key []byte) itb.MACFunc {
//	    return func(data []byte) []byte {
//	        h := hmac.New(sha256.New, key)
//	        h.Write(data)
//	        return h.Sum(nil)
//	    }
//	}
//
//	// BLAKE3 MAC (github.com/zeebo/blake3)
//	func blake3MAC(key []byte) itb.MACFunc {
//	    return func(data []byte) []byte {
//	        h := blake3.DeriveKey(key, data)
//	        return h[:32]
//	    }
//	}
type MACFunc func(data []byte) []byte

// constantTimeEqual compares two byte slices in constant time.
func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
