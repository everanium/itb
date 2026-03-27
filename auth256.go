package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"sync"
)

// EncryptAuthenticated256 encrypts data with integrity protection using 256-bit hash.
//
// Pipeline: data → COBS encode → build payload [COBS][0x00][fill]
// → MAC(payload) → append tag → embed [payload][tag] into container.
//
// The MAC covers the entire payload including fill bytes.
func EncryptAuthenticated256(noiseSeed, dataSeed, startSeed *Seed256, data []byte, macFunc MACFunc) ([]byte, error) {
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

	width, height := containerSizeAuth256(noiseSeed, dataSeed, startSeed, len(encoded)+tagSize)
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

	process256(noiseSeed, dataSeed, startSeed, nonce, container, width, height, full, true, 0)
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

// DecryptAuthenticated256 decrypts and verifies integrity using 256-bit hash.
func DecryptAuthenticated256(noiseSeed, dataSeed, startSeed *Seed256, fileData []byte, macFunc MACFunc) ([]byte, error) {
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
	process256(noiseSeed, dataSeed, startSeed, nonce, container, width, height, decoded, false, 0)
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

// EncryptAuthenticated3x256 encrypts data with integrity using Triple Ouroboros (256-bit variant).
func EncryptAuthenticated3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, macFunc MACFunc) ([]byte, error) {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return nil, err
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

	p0, p1, p2 := splitTriple(data)
	enc0, enc1, enc2 := cobsEncode(p0), cobsEncode(p1), cobsEncode(p2)

	cobsLens := [3]int{len(enc0), len(enc1), len(enc2) + tagSize}
	width, height := containerSizeAuth3_256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, cobsLens)
	totalPixels := width * height
	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third
	caps := [3]int{(third * DataBitsPerPixel) / 8, (third * DataBitsPerPixel) / 8, (thirdPixels2 * DataBitsPerPixel) / 8}

	payloads := [3][]byte{}
	for i, enc := range [3][]byte{enc0, enc1, enc2} {
		payloadLen := caps[i]
		if i == 2 {
			payloadLen = caps[i] - tagSize
		}
		if len(enc)+1 > payloadLen {
			return nil, fmt.Errorf("itb: internal error: container third %d too small", i)
		}
		payload := make([]byte, payloadLen)
		copy(payload, enc)
		payload[len(enc)] = 0x00
		fillStart := len(enc) + 1
		if fillStart < payloadLen {
			fb, err := generateRandomBytes(payloadLen - fillStart)
			if err != nil {
				return nil, err
			}
			copy(payload[fillStart:], fb)
		}
		payloads[i] = payload
	}

	macInput := make([]byte, 0, len(payloads[0])+len(payloads[1])+len(payloads[2]))
	macInput = append(macInput, payloads[0]...)
	macInput = append(macInput, payloads[1]...)
	macInput = append(macInput, payloads[2]...)
	tag := macFunc(macInput)

	full2 := make([]byte, caps[2])
	copy(full2, payloads[2])
	copy(full2[len(payloads[2]):], tag)

	container := make([]byte, totalPixels*Channels)
	var wg sync.WaitGroup
	var randErr [3]error
	wg.Add(3)
	go func() { _, randErr[0] = rand.Read(container[0 : third*Channels]); wg.Done() }()
	go func() { _, randErr[1] = rand.Read(container[third*Channels : 2*third*Channels]); wg.Done() }()
	go func() { _, randErr[2] = rand.Read(container[2*third*Channels : totalPixels*Channels]); wg.Done() }()
	wg.Wait()
	for _, err := range randErr {
		if err != nil {
			return nil, fmt.Errorf("itb: crypto/rand: %w", err)
		}
	}

	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	perThird := runtime.NumCPU() / 3
	if perThird < 1 {
		perThird = 1
	}
	o1, o2 := third*Channels, 2*third*Channels
	wg.Add(3)
	go func() { process256(noiseSeed, dataSeed1, startSeed1, nonce, container[0:o1], third, 1, payloads[0], true, perThird); wg.Done() }()
	go func() { process256(noiseSeed, dataSeed2, startSeed2, nonce, container[o1:o2], third, 1, payloads[1], true, perThird); wg.Done() }()
	go func() {
		process256(noiseSeed, dataSeed3, startSeed3, nonce, container[o2:totalPixels*Channels], thirdPixels2, 1, full2, true, perThird)
		wg.Done()
	}()
	wg.Wait()

	secureWipe(payloads[0]); secureWipe(payloads[1]); secureWipe(payloads[2])
	secureWipe(full2); secureWipe(macInput)

	out := make([]byte, 0, headerSize()+len(container))
	out = append(out, nonce...)
	var dim [4]byte
	binary.BigEndian.PutUint16(dim[0:], uint16(width))
	binary.BigEndian.PutUint16(dim[2:], uint16(height))
	out = append(out, dim[:]...)
	out = append(out, container...)
	return out, nil
}

// DecryptAuthenticated3x256 decrypts and verifies integrity using Triple Ouroboros (256-bit variant).
func DecryptAuthenticated3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, fileData []byte, macFunc MACFunc) ([]byte, error) {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return nil, err
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
	if len(container) < totalPixels*Channels {
		return nil, fmt.Errorf("itb: container too short")
	}

	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third
	caps := [3]int{(third * DataBitsPerPixel) / 8, (third * DataBitsPerPixel) / 8, (thirdPixels2 * DataBitsPerPixel) / 8}
	if caps[2] <= tagSize {
		return nil, fmt.Errorf("itb: container too small for MAC tag")
	}

	decoded := [3][]byte{make([]byte, caps[0]), make([]byte, caps[1]), make([]byte, caps[2])}
	perThird := runtime.NumCPU() / 3
	if perThird < 1 {
		perThird = 1
	}
	o1, o2 := third*Channels, 2*third*Channels

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { process256(noiseSeed, dataSeed1, startSeed1, nonce, container[0:o1], third, 1, decoded[0], false, perThird); wg.Done() }()
	go func() { process256(noiseSeed, dataSeed2, startSeed2, nonce, container[o1:o2], third, 1, decoded[1], false, perThird); wg.Done() }()
	go func() {
		process256(noiseSeed, dataSeed3, startSeed3, nonce, container[o2:totalPixels*Channels], thirdPixels2, 1, decoded[2], false, perThird)
		wg.Done()
	}()
	wg.Wait()

	defer secureWipe(decoded[0]); defer secureWipe(decoded[1]); defer secureWipe(decoded[2])

	payloadLen2 := caps[2] - tagSize
	macInput := make([]byte, 0, len(decoded[0])+len(decoded[1])+payloadLen2)
	macInput = append(macInput, decoded[0]...)
	macInput = append(macInput, decoded[1]...)
	macInput = append(macInput, decoded[2][:payloadLen2]...)
	expected := macFunc(macInput)
	secureWipe(macInput)

	if !constantTimeEqual(decoded[2][payloadLen2:], expected) {
		return nil, fmt.Errorf("itb: MAC verification failed (tampered or wrong key)")
	}

	parts := [3][]byte{}
	for i, dec := range [][]byte{decoded[0], decoded[1], decoded[2][:payloadLen2]} {
		nullPos := -1
		for j := 0; j < len(dec); j++ {
			if dec[j] == 0x00 && nullPos == -1 {
				nullPos = j
			}
		}
		if nullPos < 0 {
			return nil, fmt.Errorf("itb: no terminator found in third %d", i)
		}
		if nullPos == 0 {
			parts[i] = []byte{}
		} else {
			parts[i] = cobsDecode(dec[:nullPos])
		}
	}
	return interleaveTriple(parts[0], parts[1], parts[2]), nil
}
