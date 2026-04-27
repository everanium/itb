package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"sync"
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
	payloadPtr, payload := acquireBuffer(payloadLen)
	defer releaseBuffer(payloadPtr, payload)
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

	fullPtr, full := acquireBuffer(capacity)
	defer releaseBuffer(fullPtr, full)
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

	process128(noiseSeed, dataSeed, startSeed, nonce, container, width, height, full, true, 0)

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

	decodedPtr, decoded := acquireBuffer(capacity)
	defer releaseBuffer(decodedPtr, decoded)
	process128(noiseSeed, dataSeed, startSeed, nonce, container, width, height, decoded, false, 0)

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
	if nullPos <= 0 {
		return nil, fmt.Errorf("itb: no terminator found")
	}

	original := cobsDecode(payload[:nullPos])
	if len(original) == 0 {
		return nil, fmt.Errorf("itb: COBS decode produced empty output")
	}

	return original, nil
}

// EncryptAuthenticated3x128 encrypts data with integrity using Triple Ouroboros (128-bit variant).
func EncryptAuthenticated3x128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, macFunc MACFunc) ([]byte, error) {
	if err := checkSevenSeeds128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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

	p0, p1, p2 := splitForTripleParallel(data)

	// Phase 1: 3 parallel cobsEncode
	var encs [3][]byte
	{
		parts := [3][]byte{p0, p1, p2}
		var wg sync.WaitGroup
		wg.Add(3)
		for i := 0; i < 3; i++ {
			go func(i int) {
				defer wg.Done()
				encs[i] = cobsEncode(parts[i])
			}(i)
		}
		wg.Wait()
	}

	// part2 COBS length increased by tagSize for container sizing
	cobsLens := [3]int{len(encs[0]), len(encs[1]), len(encs[2]) + tagSize}
	width, height := containerSizeAuth3_128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, cobsLens)
	totalPixels := width * height
	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third

	caps := [3]int{
		(third * DataBitsPerPixel) / 8,
		(third * DataBitsPerPixel) / 8,
		(thirdPixels2 * DataBitsPerPixel) / 8,
	}
	payloadLens := [3]int{caps[0], caps[1], caps[2] - tagSize}
	for i := 0; i < 3; i++ {
		if len(encs[i])+1 > payloadLens[i] {
			return nil, fmt.Errorf("itb: internal error: container third %d too small", i)
		}
	}

	// Build payloads: part0 and part1 full capacity, part2 reserves tagSize
	// Phase 2: 3 parallel payload-build
	var payloadPtrs [3]*[]byte
	payloads := [3][]byte{}
	defer func() {
		for i := range payloadPtrs {
			if payloadPtrs[i] != nil {
				releaseBuffer(payloadPtrs[i], payloads[i])
			}
		}
	}()
	{
		var errs [3]error
		var wg sync.WaitGroup
		wg.Add(3)
		for i := 0; i < 3; i++ {
			go func(i int) {
				defer wg.Done()
				payloadPtrs[i], payloads[i] = acquireBuffer(payloadLens[i])
				copy(payloads[i], encs[i])
				payloads[i][len(encs[i])] = 0x00
				fillStart := len(encs[i]) + 1
				if fillStart < payloadLens[i] {
					fillBytes, err := generateRandomBytes(payloadLens[i] - fillStart)
					if err != nil {
						errs[i] = err
						return
					}
					copy(payloads[i][fillStart:], fillBytes)
				}
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				return nil, err
			}
		}
	}

	// MAC over concatenated payloads (covers all fill bytes)
	macInputLen := len(payloads[0]) + len(payloads[1]) + len(payloads[2])
	macInputPtr, macInput := acquireBuffer(macInputLen)
	defer releaseBuffer(macInputPtr, macInput)
	copy(macInput, payloads[0])
	copy(macInput[len(payloads[0]):], payloads[1])
	copy(macInput[len(payloads[0])+len(payloads[1]):], payloads[2])
	tag := macFunc(macInput)

	// full2 = payload2 + tag
	full2Ptr, full2 := acquireBuffer(caps[2])
	defer releaseBuffer(full2Ptr, full2)
	copy(full2, payloads[2])
	copy(full2[len(payloads[2]):], tag)

	// 3×CSPRNG parallel generation
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
	offset1 := third * Channels
	offset2 := 2 * third * Channels
	wg.Add(3)
	go func() {
		process128(noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, payloads[0], true, perThird)
		wg.Done()
	}()
	go func() {
		process128(noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, payloads[1], true, perThird)
		wg.Done()
	}()
	go func() {
		process128(noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, full2, true, perThird)
		wg.Done()
	}()
	wg.Wait()

	out := make([]byte, 0, headerSize()+len(container))
	out = append(out, nonce...)
	var dim [4]byte
	binary.BigEndian.PutUint16(dim[0:], uint16(width))
	binary.BigEndian.PutUint16(dim[2:], uint16(height))
	out = append(out, dim[:]...)
	out = append(out, container...)

	return out, nil
}

// DecryptAuthenticated3x128 decrypts and verifies integrity using Triple Ouroboros (128-bit variant).
func DecryptAuthenticated3x128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, fileData []byte, macFunc MACFunc) ([]byte, error) {
	if err := checkSevenSeeds128(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
	expectedSize := totalPixels * Channels
	if len(container) < expectedSize {
		return nil, fmt.Errorf("itb: container too short: got %d, need %d", len(container), expectedSize)
	}

	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third

	caps := [3]int{
		(third * DataBitsPerPixel) / 8,
		(third * DataBitsPerPixel) / 8,
		(thirdPixels2 * DataBitsPerPixel) / 8,
	}
	if caps[2] <= tagSize {
		return nil, fmt.Errorf("itb: container too small for MAC tag")
	}

	var decodedPtrs [3]*[]byte
	decoded := [3][]byte{}
	defer func() {
		for i := range decodedPtrs {
			if decodedPtrs[i] != nil {
				releaseBuffer(decodedPtrs[i], decoded[i])
			}
		}
	}()
	for i := 0; i < 3; i++ {
		decodedPtrs[i], decoded[i] = acquireBuffer(caps[i])
	}

	perThird := runtime.NumCPU() / 3
	if perThird < 1 {
		perThird = 1
	}
	offset1 := third * Channels
	offset2 := 2 * third * Channels

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		process128(noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, decoded[0], false, perThird)
		wg.Done()
	}()
	go func() {
		process128(noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, decoded[1], false, perThird)
		wg.Done()
	}()
	go func() {
		process128(noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, decoded[2], false, perThird)
		wg.Done()
	}()
	wg.Wait()

	// Split part2 into payload + tag
	payloadLen2 := caps[2] - tagSize
	payload2 := decoded[2][:payloadLen2]
	tag := decoded[2][payloadLen2:]

	// Verify MAC over concatenated payloads
	macInputLen := len(decoded[0]) + len(decoded[1]) + payloadLen2
	macInputPtr, macInput := acquireBuffer(macInputLen)
	copy(macInput, decoded[0])
	copy(macInput[len(decoded[0]):], decoded[1])
	copy(macInput[len(decoded[0])+len(decoded[1]):], payload2)
	expected := macFunc(macInput)
	releaseBuffer(macInputPtr, macInput)

	if !constantTimeEqual(tag, expected) {
		return nil, fmt.Errorf("itb: MAC verification failed (tampered or wrong key)")
	}

	// 3 parallel null-search + cobsDecode (MAC already verified data integrity)
	parts := [3][]byte{}
	{
		decs := [][]byte{decoded[0], decoded[1], payload2}
		var errs [3]error
		var wg sync.WaitGroup
		wg.Add(3)
		for i := 0; i < 3; i++ {
			go func(i int) {
				defer wg.Done()
				dec := decs[i]
				nullPos := -1
				for j := 0; j < len(dec); j++ {
					if dec[j] == 0x00 && nullPos == -1 {
						nullPos = j
					}
				}
				if nullPos <= 0 {
					errs[i] = fmt.Errorf("itb: no terminator found in third %d", i)
					return
				}
				parts[i] = cobsDecode(dec[:nullPos])
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				return nil, err
			}
		}
	}

	return interleaveForTripleParallel(parts[0], parts[1], parts[2]), nil
}
