package itb

import (
	"encoding/binary"
	"fmt"
	"math"
)

// EncryptAuthenticated128 encrypts data with integrity protection using 128-bit hash.
//
// Pipeline: data → COBS encode → build payload [COBS][0x00][fill]
// → MAC(payload) → append tag → embed [payload][tag] into container.
//
// The MAC covers the entire payload including fill bytes.
func EncryptAuthenticated128(noiseSeed, dataSeed, startSeed *Seed128, data []byte, macFunc MACFunc) ([]byte, error) {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return nil, fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("itb: empty data")
	}
	if macFunc == nil {
		return nil, fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) > maxDataSize {
		return nil, fmt.Errorf("itb: data too large: %d bytes (max %d)", len(data), maxDataSize)
	}

	tagSize := len(macFunc([]byte{}))
	if tagSize == 0 {
		return nil, fmt.Errorf("itb: macFunc returned empty tag")
	}

	encoded := cobsEncode(data)

	width, height := containerSizeAuth128(noiseSeed, dataSeed, startSeed, len(encoded)+tagSize)
	totalPixels := width * height
	capacity := (totalPixels * DataBitsPerPixel) / 8

	if len(encoded)+1+tagSize > capacity {
		return nil, fmt.Errorf("itb: internal error: container too small")
	}

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

	tag := macFunc(payload)

	full := make([]byte, capacity)
	copy(full, payload)
	copy(full[payloadLen:], tag)

	container, err := generateRandomBytes(totalPixels * Channels)
	if err != nil {
		return nil, err
	}
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	process128(noiseSeed, dataSeed, startSeed, nonce, container, width, height, full, true)
	secureWipe(payload)
	secureWipe(full)

	out := make([]byte, 0, headerSize()+len(container))
	out = append(out, nonce...)
	var dim [4]byte
	binary.BigEndian.PutUint16(dim[0:], uint16(width))
	binary.BigEndian.PutUint16(dim[2:], uint16(height))
	out = append(out, dim[:]...)
	out = append(out, container...)

	return out, nil
}

// DecryptAuthenticated128 decrypts and verifies integrity using 128-bit hash.
func DecryptAuthenticated128(noiseSeed, dataSeed, startSeed *Seed128, fileData []byte, macFunc MACFunc) ([]byte, error) {
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

	if len(fileData) < headerSize()+Channels {
		return nil, fmt.Errorf("itb: data too short")
	}

	nonce := fileData[:currentNonceSize()]
	width := int(binary.BigEndian.Uint16(fileData[currentNonceSize():]))
	height := int(binary.BigEndian.Uint16(fileData[currentNonceSize()+2:]))
	container := fileData[headerSize():]

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
	if totalPixels > maxTotalPixels {
		return nil, fmt.Errorf("itb: container too large: %d pixels exceeds maximum %d", totalPixels, maxTotalPixels)
	}
	expectedSize := totalPixels * Channels
	if len(container) < expectedSize {
		return nil, fmt.Errorf("itb: container too short: got %d, need %d", len(container), expectedSize)
	}

	capacity := (totalPixels * DataBitsPerPixel) / 8
	if capacity <= tagSize {
		return nil, fmt.Errorf("itb: container too small for MAC tag")
	}

	decoded := make([]byte, capacity)
	process128(noiseSeed, dataSeed, startSeed, nonce, container, width, height, decoded, false)
	defer secureWipe(decoded)

	payloadLen := capacity - tagSize
	payload := decoded[:payloadLen]
	tag := decoded[payloadLen:]

	expected := macFunc(payload)
	if !constantTimeEqual(tag, expected) {
		return nil, fmt.Errorf("itb: MAC verification failed (tampered or wrong key)")
	}

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
