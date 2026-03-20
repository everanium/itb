package itb

import (
	"encoding/binary"
	"fmt"
	"math"
)

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

// EncryptAuthenticated encrypts data with integrity protection.
//
// Pipeline: data → COBS encode → build payload [COBS][0x00][padding]
// → MAC(payload) → append tag → embed [payload][tag] into container.
//
// The MAC covers the entire payload including COBS framing, null
// terminator, and random padding. This makes every data bit in the
// container "meaningful" to the MAC — flipping any data bit causes
// verification failure, preventing CCA spatial patterns.
//
// The macFunc must return a fixed-size tag for any input.
//
// Example:
//
//	macFn := hmacSHA256(macKey)
//	encrypted, err := itb.EncryptAuthenticated(noiseSeed, dataSeed, startSeed, data, macFn)
func EncryptAuthenticated(noiseSeed, dataSeed, startSeed *Seed, data []byte, macFunc MACFunc) ([]byte, error) {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return nil, fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("itb: empty data")
	}
	if macFunc == nil {
		return nil, fmt.Errorf("itb: macFunc must not be nil")
	}

	tagSize := len(macFunc([]byte{}))
	if tagSize == 0 {
		return nil, fmt.Errorf("itb: macFunc returned empty tag")
	}

	encoded := cobsEncode(data)

	// Container must fit COBS + null + tag.
	width, height := containerSize(noiseSeed, dataSeed, startSeed, len(encoded)+tagSize)
	totalPixels := width * height
	capacity := (totalPixels * DataBitsPerPixel) / 8

	if len(encoded)+1+tagSize > capacity {
		return nil, fmt.Errorf("itb: internal error: container too small")
	}

	// Build payload: [COBS][0x00][fill] → capacity - tagSize bytes.
	payloadLen := capacity - tagSize
	payload := make([]byte, payloadLen)
	copy(payload, encoded)
	payload[len(encoded)] = 0x00
	fillStart := len(encoded) + 1
	if fillStart < payloadLen {
		fillBytes, err := generateRandomBytes(payloadLen - fillStart)
		if err != nil {
			return nil, err
		}
		copy(payload[fillStart:], fillBytes)
	}

	// MAC covers entire payload (COBS + null + fill).
	tag := macFunc(payload)

	// Full capacity: [payload][tag].
	full := make([]byte, capacity)
	copy(full, payload)
	copy(full[payloadLen:], tag)

	// Generate random container and embed.
	container, err := generateRandomBytes(totalPixels * Channels)
	if err != nil {
		return nil, err
	}
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	process(noiseSeed, dataSeed, startSeed, nonce, container, width, height, full, true)
	secureWipe(payload)
	secureWipe(full)

	out := make([]byte, 0, headerSize+len(container))
	out = append(out, nonce...)
	var dim [4]byte
	binary.BigEndian.PutUint16(dim[0:], uint16(width))
	binary.BigEndian.PutUint16(dim[2:], uint16(height))
	out = append(out, dim[:]...)
	out = append(out, container...)

	return out, nil
}

// DecryptAuthenticated decrypts and verifies integrity.
//
// Pipeline: decrypt full capacity → split [payload][tag] → verify
// MAC(payload) → find null in payload → COBS decode → plaintext.
//
// Returns error if decryption fails or MAC verification fails.
//
// Example:
//
//	macFn := hmacSHA256(macKey)
//	original, err := itb.DecryptAuthenticated(seed, encrypted, macFn)
func DecryptAuthenticated(noiseSeed, dataSeed, startSeed *Seed, fileData []byte, macFunc MACFunc) ([]byte, error) {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return nil, fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return nil, fmt.Errorf("itb: macFunc must not be nil")
	}

	tagSize := len(macFunc([]byte{}))
	if tagSize == 0 {
		return nil, fmt.Errorf("itb: macFunc returned empty tag")
	}

	if len(fileData) < headerSize+Channels {
		return nil, fmt.Errorf("itb: data too short")
	}

	nonce := fileData[:NonceSize]
	width := int(binary.BigEndian.Uint16(fileData[NonceSize:]))
	height := int(binary.BigEndian.Uint16(fileData[NonceSize+2:]))
	container := fileData[headerSize:]

	if width == 0 || height == 0 {
		return nil, fmt.Errorf("itb: invalid dimensions %dx%d", width, height)
	}
	if width > math.MaxInt/height {
		return nil, fmt.Errorf("itb: container dimensions %dx%d overflow int", width, height)
	}
	totalPixels := width * height
	if totalPixels > math.MaxInt/Channels {
		return nil, fmt.Errorf("itb: container too large for this platform: %d pixels", totalPixels)
	}
	expectedSize := totalPixels * Channels
	if len(container) < expectedSize {
		return nil, fmt.Errorf("itb: container too short: got %d, need %d", len(container), expectedSize)
	}

	capacity := (totalPixels * DataBitsPerPixel) / 8
	if capacity <= tagSize {
		return nil, fmt.Errorf("itb: container too small for MAC tag")
	}

	// Decrypt entire capacity.
	decoded := make([]byte, capacity)
	process(noiseSeed, dataSeed, startSeed, nonce, container, width, height, decoded, false)
	defer secureWipe(decoded)

	// Split payload and tag.
	payloadLen := capacity - tagSize
	payload := decoded[:payloadLen]
	tag := decoded[payloadLen:]

	// Verify MAC over entire payload (COBS + null + fill).
	expected := macFunc(payload)
	if !constantTimeEqual(tag, expected) {
		return nil, fmt.Errorf("itb: MAC verification failed (tampered or wrong key)")
	}

	// Constant-time null search (side-channel resistance).
	nullPos := -1
	for i := 0; i < len(payload); i++ {
		if payload[i] == 0x00 && nullPos == -1 {
			nullPos = i
		}
	}
	if nullPos < 0 {
		return nil, fmt.Errorf("itb: no terminator found")
	}
	if nullPos == 0 {
		return nil, fmt.Errorf("itb: empty payload")
	}

	original := cobsDecode(payload[:nullPos])
	if len(original) == 0 {
		return nil, fmt.Errorf("itb: COBS decode produced empty output")
	}

	return original, nil
}

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
