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

	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	encoded := cobsEncode(splitForSingle(data, buildPermutePRF256(noiseSeed, nonce)))

	width, height := containerSizeAuth256(noiseSeed, dataSeed, startSeed, len(encoded)+tagSize)
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

	process256(noiseSeed, dataSeed, startSeed, nonce, container, width, height, full, true, 0)

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

	decodedPtr, decoded := acquireBuffer(capacity)
	defer releaseBuffer(decodedPtr, decoded)
	process256(noiseSeed, dataSeed, startSeed, nonce, container, width, height, decoded, false, 0)

	payloadLen := capacity - tagSize
	payload := decoded[:payloadLen]
	tag := decoded[payloadLen:]

	expected := macFunc(payload)
	if !constantTimeEqual(tag, expected) {
		return nil, ErrMACFailure
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

	return interleaveForSingle(original, buildPermutePRF256(noiseSeed, nonce)), nil
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

	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	p0, p1, p2 := splitForTripleParallelLocked(data, buildLockPRF256(noiseSeed, nonce))

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
	width, height := containerSizeAuth3_256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, cobsLens)
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

	perThird := runtime.NumCPU() / 3
	if perThird < 1 {
		perThird = 1
	}
	offset1 := third * Channels
	offset2 := 2 * third * Channels
	wg.Add(3)
	go func() {
		process256(noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, payloads[0], true, perThird)
		wg.Done()
	}()
	go func() {
		process256(noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, payloads[1], true, perThird)
		wg.Done()
	}()
	go func() {
		process256(noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, full2, true, perThird)
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
		process256(noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, decoded[0], false, perThird)
		wg.Done()
	}()
	go func() {
		process256(noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, decoded[1], false, perThird)
		wg.Done()
	}()
	go func() {
		process256(noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, decoded[2], false, perThird)
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
		return nil, ErrMACFailure
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

	return interleaveForTripleParallelLocked(parts[0], parts[1], parts[2], buildLockPRF256(noiseSeed, nonce)), nil
}

// EncryptAuthenticated256Cfg is the Cfg variant of
// [EncryptAuthenticated256]: threads cfg through every Cfg-aware
// accessor in the Single Ouroboros authenticated pipeline. Body
// otherwise identical to EncryptAuthenticated256, including the MAC-
// over-payload-with-fill-bytes layout and the appended-tag wire shape.
func EncryptAuthenticated256Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed256, data []byte, macFunc MACFunc) ([]byte, error) {
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

	nonce, err := generateNonceCfg(cfg)
	if err != nil {
		return nil, err
	}

	encoded := cobsEncode(splitForSingleCfg(cfg, data, buildPermutePRF256Cfg(cfg, noiseSeed, nonce)))

	width, height := containerSizeAuth256Cfg(cfg, noiseSeed, dataSeed, startSeed, len(encoded)+tagSize)
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

	process256Cfg(cfg, noiseSeed, dataSeed, startSeed, nonce, container, width, height, full, true, 0)

	out := make([]byte, 0, headerSizeCfg(cfg)+len(container))
	out = append(out, nonce...)
	var dim [4]byte
	binary.BigEndian.PutUint16(dim[0:], uint16(width))
	binary.BigEndian.PutUint16(dim[2:], uint16(height))
	out = append(out, dim[:]...)
	out = append(out, container...)

	return out, nil
}

// DecryptAuthenticated256Cfg is the Cfg variant of
// [DecryptAuthenticated256].
func DecryptAuthenticated256Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed256, fileData []byte, macFunc MACFunc) ([]byte, error) {
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

	if len(fileData) < headerSizeCfg(cfg)+Channels {
		return nil, fmt.Errorf("itb: data too short")
	}

	nonceLen := currentNonceSizeCfg(cfg)
	nonce := fileData[:nonceLen]
	width := int(binary.BigEndian.Uint16(fileData[nonceLen:]))
	height := int(binary.BigEndian.Uint16(fileData[nonceLen+2:]))
	container := fileData[headerSizeCfg(cfg):]

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
	process256Cfg(cfg, noiseSeed, dataSeed, startSeed, nonce, container, width, height, decoded, false, 0)

	payloadLen := capacity - tagSize
	payload := decoded[:payloadLen]
	tag := decoded[payloadLen:]

	expected := macFunc(payload)
	if !constantTimeEqual(tag, expected) {
		return nil, ErrMACFailure
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

	return interleaveForSingleCfg(cfg, original, buildPermutePRF256Cfg(cfg, noiseSeed, nonce)), nil
}

// EncryptAuthenticated3x256Cfg is the Cfg variant of
// [EncryptAuthenticated3x256]: threads cfg through every Cfg-aware
// accessor in the Triple Ouroboros authenticated pipeline. Body
// otherwise identical to EncryptAuthenticated3x256, including the
// part2-reserves-tag layout and the MAC-over-concatenated-payloads
// invariant.
func EncryptAuthenticated3x256Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, macFunc MACFunc) ([]byte, error) {
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

	nonce, err := generateNonceCfg(cfg)
	if err != nil {
		return nil, err
	}

	p0, p1, p2 := splitForTripleParallelLockedCfg(cfg, data, buildLockPRF256Cfg(cfg, noiseSeed, nonce))

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
	width, height := containerSizeAuth3_256Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, cobsLens)
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

	perThird := runtime.NumCPU() / 3
	if perThird < 1 {
		perThird = 1
	}
	offset1 := third * Channels
	offset2 := 2 * third * Channels
	wg.Add(3)
	go func() {
		process256Cfg(cfg, noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, payloads[0], true, perThird)
		wg.Done()
	}()
	go func() {
		process256Cfg(cfg, noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, payloads[1], true, perThird)
		wg.Done()
	}()
	go func() {
		process256Cfg(cfg, noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, full2, true, perThird)
		wg.Done()
	}()
	wg.Wait()

	out := make([]byte, 0, headerSizeCfg(cfg)+len(container))
	out = append(out, nonce...)
	var dim [4]byte
	binary.BigEndian.PutUint16(dim[0:], uint16(width))
	binary.BigEndian.PutUint16(dim[2:], uint16(height))
	out = append(out, dim[:]...)
	out = append(out, container...)

	return out, nil
}

// DecryptAuthenticated3x256Cfg is the Cfg variant of
// [DecryptAuthenticated3x256].
func DecryptAuthenticated3x256Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, fileData []byte, macFunc MACFunc) ([]byte, error) {
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

	if len(fileData) < headerSizeCfg(cfg)+Channels {
		return nil, fmt.Errorf("itb: data too short")
	}

	nonceLen := currentNonceSizeCfg(cfg)
	nonce := fileData[:nonceLen]
	width := int(binary.BigEndian.Uint16(fileData[nonceLen:]))
	height := int(binary.BigEndian.Uint16(fileData[nonceLen+2:]))
	container := fileData[headerSizeCfg(cfg):]

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
		process256Cfg(cfg, noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, decoded[0], false, perThird)
		wg.Done()
	}()
	go func() {
		process256Cfg(cfg, noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, decoded[1], false, perThird)
		wg.Done()
	}()
	go func() {
		process256Cfg(cfg, noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, decoded[2], false, perThird)
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
		return nil, ErrMACFailure
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

	return interleaveForTripleParallelLockedCfg(cfg, parts[0], parts[1], parts[2], buildLockPRF256Cfg(cfg, noiseSeed, nonce)), nil
}

// EncryptStreamAuthenticated256 encrypts a single Streaming AEAD chunk
// with integrity protection using 256-bit hash seeds.
//
// Pipeline: data → COBS encode → build payload [COBS][0x00][fill]
// → MAC(payload || streamID || uint64_le(cumulativePixelOffset) || flag)
// → embed [payload][tag][flag] into container.
//
// streamID is the 32-byte CSPRNG-fresh anchor generated once per stream
// by the caller and reused across every chunk's MAC input.
// cumulativePixelOffset is the running sum Σ(W_j × H_j) over chunks
// j < i; the first chunk uses 0. finalFlag is true on the terminating
// chunk and false otherwise; the decoder recovers the flag byte before
// MAC verification and signals end-of-stream when it matches 0xFF.
//
// Empty plaintext is permitted only when finalFlag is true (the
// empty-stream terminating chunk case); empty plaintext with
// finalFlag = false is rejected with the same shape as the single-shot
// authenticated path.
func EncryptStreamAuthenticated256(noiseSeed, dataSeed, startSeed *Seed256, data []byte, macFunc MACFunc, streamID [32]byte, cumulativePixelOffset uint64, finalFlag bool) ([]byte, error) {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return nil, fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if len(data) == 0 && !finalFlag {
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

	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	encoded := cobsEncode(splitForSingle(data, buildPermutePRF256(noiseSeed, nonce)))

	width, height := containerSizeAuth256(noiseSeed, dataSeed, startSeed, len(encoded)+tagSize+1)
	totalPixels := width * height
	capacity := (totalPixels * DataBitsPerPixel) / 8

	if len(encoded)+1+tagSize+1 > capacity {
		return nil, fmt.Errorf("itb: internal error: container too small")
	}

	payloadLen := capacity - tagSize - 1
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

	flag := streamFlagByte(finalFlag)
	macInputLen := payloadLen + 32 + 8 + 1
	macInputPtr, macInput := acquireBuffer(macInputLen)
	copy(macInput, payload)
	copy(macInput[payloadLen:], streamID[:])
	binary.LittleEndian.PutUint64(macInput[payloadLen+32:], cumulativePixelOffset)
	macInput[payloadLen+32+8] = flag
	tag := macFunc(macInput[:macInputLen])
	releaseBuffer(macInputPtr, macInput)

	fullPtr, full := acquireBuffer(capacity)
	defer releaseBuffer(fullPtr, full)
	copy(full, payload)
	copy(full[payloadLen:], tag)
	full[payloadLen+tagSize] = flag

	container, err := generateRandomBytes(totalPixels * Channels)
	if err != nil {
		return nil, err
	}

	process256(noiseSeed, dataSeed, startSeed, nonce, container, width, height, full, true, 0)

	out := make([]byte, 0, headerSize()+len(container))
	out = append(out, nonce...)
	var dim [4]byte
	binary.BigEndian.PutUint16(dim[0:], uint16(width))
	binary.BigEndian.PutUint16(dim[2:], uint16(height))
	out = append(out, dim[:]...)
	out = append(out, container...)

	return out, nil
}

// DecryptStreamAuthenticated256 decrypts and verifies a single
// Streaming AEAD chunk using 256-bit hash seeds. Returns the recovered
// plaintext, the recovered finalFlag indicating whether this chunk
// terminates the stream, and any error from the cipher / MAC layer.
//
// streamID and cumulativePixelOffset must match the encoder's values
// for chunk i; reorder, replay, or cross-stream splice attempts cause
// MAC mismatch and return [ErrMACFailure]. The recovered flag byte
// is extracted before MAC verification by splitting the decrypted
// container body at the known offsets.
func DecryptStreamAuthenticated256(noiseSeed, dataSeed, startSeed *Seed256, chunkData []byte, macFunc MACFunc, streamID [32]byte, cumulativePixelOffset uint64) ([]byte, bool, error) {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return nil, false, fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return nil, false, fmt.Errorf("itb: macFunc must not be nil")
	}

	tagSize := len(macFunc([]byte{}))
	if tagSize == 0 {
		return nil, false, fmt.Errorf("itb: macFunc returned empty tag")
	}

	if len(chunkData) < headerSize()+Channels {
		return nil, false, fmt.Errorf("itb: data too short")
	}

	nonce := chunkData[:currentNonceSize()]
	width := int(binary.BigEndian.Uint16(chunkData[currentNonceSize():]))
	height := int(binary.BigEndian.Uint16(chunkData[currentNonceSize()+2:]))
	container := chunkData[headerSize():]

	if width == 0 || height == 0 {
		return nil, false, fmt.Errorf("itb: invalid dimensions %dx%d", width, height)
	}
	if width > math.MaxInt/height {
		return nil, false, fmt.Errorf("itb: container dimensions %dx%d overflow int", width, height)
	}
	totalPixels := width * height
	if totalPixels > math.MaxInt/Channels {
		return nil, false, fmt.Errorf("itb: container too large for this platform: %d pixels", totalPixels)
	}
	if totalPixels > maxTotalPixels {
		return nil, false, fmt.Errorf("itb: container too large: %d pixels exceeds maximum %d", totalPixels, maxTotalPixels)
	}
	expectedSize := totalPixels * Channels
	if len(container) < expectedSize {
		return nil, false, fmt.Errorf("itb: container too short: got %d, need %d", len(container), expectedSize)
	}

	capacity := (totalPixels * DataBitsPerPixel) / 8
	if capacity <= tagSize+1 {
		return nil, false, fmt.Errorf("itb: container too small for MAC tag")
	}

	decodedPtr, decoded := acquireBuffer(capacity)
	defer releaseBuffer(decodedPtr, decoded)
	process256(noiseSeed, dataSeed, startSeed, nonce, container, width, height, decoded, false, 0)

	payloadLen := capacity - tagSize - 1
	payload := decoded[:payloadLen]
	tag := decoded[payloadLen : payloadLen+tagSize]
	flag := decoded[payloadLen+tagSize]

	macInputLen := payloadLen + 32 + 8 + 1
	macInputPtr, macInput := acquireBuffer(macInputLen)
	copy(macInput, payload)
	copy(macInput[payloadLen:], streamID[:])
	binary.LittleEndian.PutUint64(macInput[payloadLen+32:], cumulativePixelOffset)
	macInput[payloadLen+32+8] = flag
	expected := macFunc(macInput[:macInputLen])
	releaseBuffer(macInputPtr, macInput)

	if !constantTimeEqual(tag, expected) {
		return nil, false, ErrMACFailure
	}

	nullPos := -1
	for i := 0; i < len(payload); i++ {
		if payload[i] == 0x00 && nullPos == -1 {
			nullPos = i
		}
	}
	finalFlag := flag == 0xFF
	if nullPos < 0 {
		return nil, false, fmt.Errorf("itb: no terminator found")
	}
	if nullPos == 0 {
		// Empty plaintext: permitted only on the terminating chunk.
		if !finalFlag {
			return nil, false, fmt.Errorf("itb: no terminator found")
		}
		return []byte{}, true, nil
	}

	original := cobsDecode(payload[:nullPos])
	if len(original) == 0 {
		// Empty COBS output is the legitimate encoding of empty
		// plaintext on the terminating chunk; reject otherwise.
		if !finalFlag {
			return nil, false, fmt.Errorf("itb: COBS decode produced empty output")
		}
		return []byte{}, true, nil
	}

	return interleaveForSingle(original, buildPermutePRF256(noiseSeed, nonce)), finalFlag, nil
}

// EncryptStreamAuthenticated3x256 encrypts a single Streaming AEAD
// chunk using Triple Ouroboros (256-bit variant). Streaming-binding
// components mirror [EncryptStreamAuthenticated256]: streamID,
// cumulativePixelOffset, and finalFlag enter the MAC input alongside
// the concatenated thirds; the flag byte rides on wire as the last
// byte inside third 2 of the encrypted container.
func EncryptStreamAuthenticated3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, macFunc MACFunc, streamID [32]byte, cumulativePixelOffset uint64, finalFlag bool) ([]byte, error) {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return nil, err
	}
	if len(data) == 0 && !finalFlag {
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

	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	p0, p1, p2 := splitForTripleParallelLocked(data, buildLockPRF256(noiseSeed, nonce))

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

	// part2 COBS length increased by tagSize + 1 (flag byte) for container sizing
	cobsLens := [3]int{len(encs[0]), len(encs[1]), len(encs[2]) + tagSize + 1}
	width, height := containerSizeAuth3_256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, cobsLens)
	totalPixels := width * height
	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third

	caps := [3]int{
		(third * DataBitsPerPixel) / 8,
		(third * DataBitsPerPixel) / 8,
		(thirdPixels2 * DataBitsPerPixel) / 8,
	}
	payloadLens := [3]int{caps[0], caps[1], caps[2] - tagSize - 1}
	for i := 0; i < 3; i++ {
		if len(encs[i])+1 > payloadLens[i] {
			return nil, fmt.Errorf("itb: internal error: container third %d too small", i)
		}
	}

	// Build payloads: part0 and part1 full capacity, part2 reserves tagSize + 1 (flag)
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

	// MAC over concatenated payloads || streamID || uint64_le(offset) || flag
	flag := streamFlagByte(finalFlag)
	macInputLen := len(payloads[0]) + len(payloads[1]) + len(payloads[2]) + 32 + 8 + 1
	macInputPtr, macInput := acquireBuffer(macInputLen)
	defer releaseBuffer(macInputPtr, macInput)
	off := 0
	copy(macInput[off:], payloads[0])
	off += len(payloads[0])
	copy(macInput[off:], payloads[1])
	off += len(payloads[1])
	copy(macInput[off:], payloads[2])
	off += len(payloads[2])
	copy(macInput[off:], streamID[:])
	off += 32
	binary.LittleEndian.PutUint64(macInput[off:], cumulativePixelOffset)
	off += 8
	macInput[off] = flag
	tag := macFunc(macInput[:macInputLen])

	// full2 = payload2 || tag || flag
	full2Ptr, full2 := acquireBuffer(caps[2])
	defer releaseBuffer(full2Ptr, full2)
	copy(full2, payloads[2])
	copy(full2[len(payloads[2]):], tag)
	full2[len(payloads[2])+tagSize] = flag

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

	perThird := runtime.NumCPU() / 3
	if perThird < 1 {
		perThird = 1
	}
	offset1 := third * Channels
	offset2 := 2 * third * Channels
	wg.Add(3)
	go func() {
		process256(noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, payloads[0], true, perThird)
		wg.Done()
	}()
	go func() {
		process256(noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, payloads[1], true, perThird)
		wg.Done()
	}()
	go func() {
		process256(noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, full2, true, perThird)
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

// DecryptStreamAuthenticated3x256 decrypts and verifies a single
// Streaming AEAD chunk using Triple Ouroboros (256-bit variant).
// Returns the recovered plaintext, the recovered finalFlag, and any
// error from the cipher / MAC layer.
func DecryptStreamAuthenticated3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, chunkData []byte, macFunc MACFunc, streamID [32]byte, cumulativePixelOffset uint64) ([]byte, bool, error) {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return nil, false, err
	}
	if macFunc == nil {
		return nil, false, fmt.Errorf("itb: macFunc must not be nil")
	}

	tagSize := len(macFunc([]byte{}))
	if tagSize == 0 {
		return nil, false, fmt.Errorf("itb: macFunc returned empty tag")
	}

	if len(chunkData) < headerSize()+Channels {
		return nil, false, fmt.Errorf("itb: data too short")
	}

	nonce := chunkData[:currentNonceSize()]
	width := int(binary.BigEndian.Uint16(chunkData[currentNonceSize():]))
	height := int(binary.BigEndian.Uint16(chunkData[currentNonceSize()+2:]))
	container := chunkData[headerSize():]

	if width == 0 || height == 0 {
		return nil, false, fmt.Errorf("itb: invalid dimensions %dx%d", width, height)
	}
	if width > math.MaxInt/height {
		return nil, false, fmt.Errorf("itb: container dimensions %dx%d overflow int", width, height)
	}
	totalPixels := width * height
	if totalPixels > math.MaxInt/Channels {
		return nil, false, fmt.Errorf("itb: container too large for this platform: %d pixels", totalPixels)
	}
	if totalPixels > maxTotalPixels {
		return nil, false, fmt.Errorf("itb: container too large: %d pixels exceeds maximum %d", totalPixels, maxTotalPixels)
	}
	expectedSize := totalPixels * Channels
	if len(container) < expectedSize {
		return nil, false, fmt.Errorf("itb: container too short: got %d, need %d", len(container), expectedSize)
	}

	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third

	caps := [3]int{
		(third * DataBitsPerPixel) / 8,
		(third * DataBitsPerPixel) / 8,
		(thirdPixels2 * DataBitsPerPixel) / 8,
	}
	if caps[2] <= tagSize+1 {
		return nil, false, fmt.Errorf("itb: container too small for MAC tag")
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
		process256(noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, decoded[0], false, perThird)
		wg.Done()
	}()
	go func() {
		process256(noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, decoded[1], false, perThird)
		wg.Done()
	}()
	go func() {
		process256(noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, decoded[2], false, perThird)
		wg.Done()
	}()
	wg.Wait()

	// Split part2 into payload || tag || flag
	payloadLen2 := caps[2] - tagSize - 1
	payload2 := decoded[2][:payloadLen2]
	tag := decoded[2][payloadLen2 : payloadLen2+tagSize]
	flag := decoded[2][payloadLen2+tagSize]

	// Verify MAC over concatenated payloads || streamID || uint64_le(offset) || flag
	macInputLen := len(decoded[0]) + len(decoded[1]) + payloadLen2 + 32 + 8 + 1
	macInputPtr, macInput := acquireBuffer(macInputLen)
	off := 0
	copy(macInput[off:], decoded[0])
	off += len(decoded[0])
	copy(macInput[off:], decoded[1])
	off += len(decoded[1])
	copy(macInput[off:], payload2)
	off += payloadLen2
	copy(macInput[off:], streamID[:])
	off += 32
	binary.LittleEndian.PutUint64(macInput[off:], cumulativePixelOffset)
	off += 8
	macInput[off] = flag
	expected := macFunc(macInput[:macInputLen])
	releaseBuffer(macInputPtr, macInput)

	if !constantTimeEqual(tag, expected) {
		return nil, false, ErrMACFailure
	}

	finalFlag := flag == 0xFF

	// 3 parallel null-search + cobsDecode (MAC already verified data integrity)
	parts := [3][]byte{}
	emptyThird := [3]bool{}
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
				if nullPos < 0 {
					errs[i] = fmt.Errorf("itb: no terminator found in third %d", i)
					return
				}
				if nullPos == 0 {
					// Empty third: only legal on the terminating chunk
					// (empty stream / empty tail thirds in single-byte
					// final-chunk plaintext that splits to 0 bytes per third).
					if !finalFlag {
						errs[i] = fmt.Errorf("itb: no terminator found in third %d", i)
						return
					}
					emptyThird[i] = true
					return
				}
				parts[i] = cobsDecode(dec[:nullPos])
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				return nil, false, err
			}
		}
	}

	if emptyThird[0] && emptyThird[1] && emptyThird[2] {
		return []byte{}, true, nil
	}

	return interleaveForTripleParallelLocked(parts[0], parts[1], parts[2], buildLockPRF256(noiseSeed, nonce)), finalFlag, nil
}

// EncryptStreamAuthenticated256Cfg is the Cfg variant of
// [EncryptStreamAuthenticated256]: threads cfg through every Cfg-aware
// accessor in the Single Ouroboros Streaming AEAD pipeline. Body
// otherwise identical, including the MAC-input layout
// (payload || streamID || uint64_le(cumulativePixelOffset) || flag)
// and the on-wire [payload][tag][flag] container body.
func EncryptStreamAuthenticated256Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed256, data []byte, macFunc MACFunc, streamID [32]byte, cumulativePixelOffset uint64, finalFlag bool) ([]byte, error) {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return nil, fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if len(data) == 0 && !finalFlag {
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

	nonce, err := generateNonceCfg(cfg)
	if err != nil {
		return nil, err
	}

	encoded := cobsEncode(splitForSingleCfg(cfg, data, buildPermutePRF256Cfg(cfg, noiseSeed, nonce)))

	width, height := containerSizeAuth256Cfg(cfg, noiseSeed, dataSeed, startSeed, len(encoded)+tagSize+1)
	totalPixels := width * height
	capacity := (totalPixels * DataBitsPerPixel) / 8

	if len(encoded)+1+tagSize+1 > capacity {
		return nil, fmt.Errorf("itb: internal error: container too small")
	}

	payloadLen := capacity - tagSize - 1
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

	flag := streamFlagByte(finalFlag)
	macInputLen := payloadLen + 32 + 8 + 1
	macInputPtr, macInput := acquireBuffer(macInputLen)
	copy(macInput, payload)
	copy(macInput[payloadLen:], streamID[:])
	binary.LittleEndian.PutUint64(macInput[payloadLen+32:], cumulativePixelOffset)
	macInput[payloadLen+32+8] = flag
	tag := macFunc(macInput[:macInputLen])
	releaseBuffer(macInputPtr, macInput)

	fullPtr, full := acquireBuffer(capacity)
	defer releaseBuffer(fullPtr, full)
	copy(full, payload)
	copy(full[payloadLen:], tag)
	full[payloadLen+tagSize] = flag

	container, err := generateRandomBytes(totalPixels * Channels)
	if err != nil {
		return nil, err
	}

	process256Cfg(cfg, noiseSeed, dataSeed, startSeed, nonce, container, width, height, full, true, 0)

	out := make([]byte, 0, headerSizeCfg(cfg)+len(container))
	out = append(out, nonce...)
	var dim [4]byte
	binary.BigEndian.PutUint16(dim[0:], uint16(width))
	binary.BigEndian.PutUint16(dim[2:], uint16(height))
	out = append(out, dim[:]...)
	out = append(out, container...)

	return out, nil
}

// DecryptStreamAuthenticated256Cfg is the Cfg variant of
// [DecryptStreamAuthenticated256].
func DecryptStreamAuthenticated256Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed256, chunkData []byte, macFunc MACFunc, streamID [32]byte, cumulativePixelOffset uint64) ([]byte, bool, error) {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return nil, false, fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if macFunc == nil {
		return nil, false, fmt.Errorf("itb: macFunc must not be nil")
	}

	tagSize := len(macFunc([]byte{}))
	if tagSize == 0 {
		return nil, false, fmt.Errorf("itb: macFunc returned empty tag")
	}

	if len(chunkData) < headerSizeCfg(cfg)+Channels {
		return nil, false, fmt.Errorf("itb: data too short")
	}

	nonceLen := currentNonceSizeCfg(cfg)
	nonce := chunkData[:nonceLen]
	width := int(binary.BigEndian.Uint16(chunkData[nonceLen:]))
	height := int(binary.BigEndian.Uint16(chunkData[nonceLen+2:]))
	container := chunkData[headerSizeCfg(cfg):]

	if width == 0 || height == 0 {
		return nil, false, fmt.Errorf("itb: invalid dimensions %dx%d", width, height)
	}
	if width > math.MaxInt/height {
		return nil, false, fmt.Errorf("itb: container dimensions %dx%d overflow int", width, height)
	}
	totalPixels := width * height
	if totalPixels > math.MaxInt/Channels {
		return nil, false, fmt.Errorf("itb: container too large for this platform: %d pixels", totalPixels)
	}
	if totalPixels > maxTotalPixels {
		return nil, false, fmt.Errorf("itb: container too large: %d pixels exceeds maximum %d", totalPixels, maxTotalPixels)
	}
	expectedSize := totalPixels * Channels
	if len(container) < expectedSize {
		return nil, false, fmt.Errorf("itb: container too short: got %d, need %d", len(container), expectedSize)
	}

	capacity := (totalPixels * DataBitsPerPixel) / 8
	if capacity <= tagSize+1 {
		return nil, false, fmt.Errorf("itb: container too small for MAC tag")
	}

	decodedPtr, decoded := acquireBuffer(capacity)
	defer releaseBuffer(decodedPtr, decoded)
	process256Cfg(cfg, noiseSeed, dataSeed, startSeed, nonce, container, width, height, decoded, false, 0)

	payloadLen := capacity - tagSize - 1
	payload := decoded[:payloadLen]
	tag := decoded[payloadLen : payloadLen+tagSize]
	flag := decoded[payloadLen+tagSize]

	macInputLen := payloadLen + 32 + 8 + 1
	macInputPtr, macInput := acquireBuffer(macInputLen)
	copy(macInput, payload)
	copy(macInput[payloadLen:], streamID[:])
	binary.LittleEndian.PutUint64(macInput[payloadLen+32:], cumulativePixelOffset)
	macInput[payloadLen+32+8] = flag
	expected := macFunc(macInput[:macInputLen])
	releaseBuffer(macInputPtr, macInput)

	if !constantTimeEqual(tag, expected) {
		return nil, false, ErrMACFailure
	}

	nullPos := -1
	for i := 0; i < len(payload); i++ {
		if payload[i] == 0x00 && nullPos == -1 {
			nullPos = i
		}
	}
	finalFlag := flag == 0xFF
	if nullPos < 0 {
		return nil, false, fmt.Errorf("itb: no terminator found")
	}
	if nullPos == 0 {
		if !finalFlag {
			return nil, false, fmt.Errorf("itb: no terminator found")
		}
		return []byte{}, true, nil
	}

	original := cobsDecode(payload[:nullPos])
	if len(original) == 0 {
		// Empty COBS output is the legitimate encoding of empty
		// plaintext on the terminating chunk; reject otherwise.
		if !finalFlag {
			return nil, false, fmt.Errorf("itb: COBS decode produced empty output")
		}
		return []byte{}, true, nil
	}

	return interleaveForSingleCfg(cfg, original, buildPermutePRF256Cfg(cfg, noiseSeed, nonce)), finalFlag, nil
}

// EncryptStreamAuthenticated3x256Cfg is the Cfg variant of
// [EncryptStreamAuthenticated3x256]: threads cfg through every
// Cfg-aware accessor in the Triple Ouroboros Streaming AEAD pipeline.
// Body otherwise identical, including the part2-reserves-tag-and-flag
// layout and the MAC-over-concatenated-payloads-plus-binding invariant.
func EncryptStreamAuthenticated3x256Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte, macFunc MACFunc, streamID [32]byte, cumulativePixelOffset uint64, finalFlag bool) ([]byte, error) {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return nil, err
	}
	if len(data) == 0 && !finalFlag {
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

	nonce, err := generateNonceCfg(cfg)
	if err != nil {
		return nil, err
	}

	p0, p1, p2 := splitForTripleParallelLockedCfg(cfg, data, buildLockPRF256Cfg(cfg, noiseSeed, nonce))

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

	// part2 COBS length increased by tagSize + 1 (flag byte) for container sizing
	cobsLens := [3]int{len(encs[0]), len(encs[1]), len(encs[2]) + tagSize + 1}
	width, height := containerSizeAuth3_256Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, cobsLens)
	totalPixels := width * height
	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third

	caps := [3]int{
		(third * DataBitsPerPixel) / 8,
		(third * DataBitsPerPixel) / 8,
		(thirdPixels2 * DataBitsPerPixel) / 8,
	}
	payloadLens := [3]int{caps[0], caps[1], caps[2] - tagSize - 1}
	for i := 0; i < 3; i++ {
		if len(encs[i])+1 > payloadLens[i] {
			return nil, fmt.Errorf("itb: internal error: container third %d too small", i)
		}
	}

	// Build payloads: part0 and part1 full capacity, part2 reserves tagSize + 1 (flag)
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

	// MAC over concatenated payloads || streamID || uint64_le(offset) || flag
	flag := streamFlagByte(finalFlag)
	macInputLen := len(payloads[0]) + len(payloads[1]) + len(payloads[2]) + 32 + 8 + 1
	macInputPtr, macInput := acquireBuffer(macInputLen)
	defer releaseBuffer(macInputPtr, macInput)
	off := 0
	copy(macInput[off:], payloads[0])
	off += len(payloads[0])
	copy(macInput[off:], payloads[1])
	off += len(payloads[1])
	copy(macInput[off:], payloads[2])
	off += len(payloads[2])
	copy(macInput[off:], streamID[:])
	off += 32
	binary.LittleEndian.PutUint64(macInput[off:], cumulativePixelOffset)
	off += 8
	macInput[off] = flag
	tag := macFunc(macInput[:macInputLen])

	// full2 = payload2 || tag || flag
	full2Ptr, full2 := acquireBuffer(caps[2])
	defer releaseBuffer(full2Ptr, full2)
	copy(full2, payloads[2])
	copy(full2[len(payloads[2]):], tag)
	full2[len(payloads[2])+tagSize] = flag

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

	perThird := runtime.NumCPU() / 3
	if perThird < 1 {
		perThird = 1
	}
	offset1 := third * Channels
	offset2 := 2 * third * Channels
	wg.Add(3)
	go func() {
		process256Cfg(cfg, noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, payloads[0], true, perThird)
		wg.Done()
	}()
	go func() {
		process256Cfg(cfg, noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, payloads[1], true, perThird)
		wg.Done()
	}()
	go func() {
		process256Cfg(cfg, noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, full2, true, perThird)
		wg.Done()
	}()
	wg.Wait()

	out := make([]byte, 0, headerSizeCfg(cfg)+len(container))
	out = append(out, nonce...)
	var dim [4]byte
	binary.BigEndian.PutUint16(dim[0:], uint16(width))
	binary.BigEndian.PutUint16(dim[2:], uint16(height))
	out = append(out, dim[:]...)
	out = append(out, container...)

	return out, nil
}

// DecryptStreamAuthenticated3x256Cfg is the Cfg variant of
// [DecryptStreamAuthenticated3x256].
func DecryptStreamAuthenticated3x256Cfg(cfg *Config, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, chunkData []byte, macFunc MACFunc, streamID [32]byte, cumulativePixelOffset uint64) ([]byte, bool, error) {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return nil, false, err
	}
	if macFunc == nil {
		return nil, false, fmt.Errorf("itb: macFunc must not be nil")
	}

	tagSize := len(macFunc([]byte{}))
	if tagSize == 0 {
		return nil, false, fmt.Errorf("itb: macFunc returned empty tag")
	}

	if len(chunkData) < headerSizeCfg(cfg)+Channels {
		return nil, false, fmt.Errorf("itb: data too short")
	}

	nonceLen := currentNonceSizeCfg(cfg)
	nonce := chunkData[:nonceLen]
	width := int(binary.BigEndian.Uint16(chunkData[nonceLen:]))
	height := int(binary.BigEndian.Uint16(chunkData[nonceLen+2:]))
	container := chunkData[headerSizeCfg(cfg):]

	if width == 0 || height == 0 {
		return nil, false, fmt.Errorf("itb: invalid dimensions %dx%d", width, height)
	}
	if width > math.MaxInt/height {
		return nil, false, fmt.Errorf("itb: container dimensions %dx%d overflow int", width, height)
	}
	totalPixels := width * height
	if totalPixels > math.MaxInt/Channels {
		return nil, false, fmt.Errorf("itb: container too large for this platform: %d pixels", totalPixels)
	}
	if totalPixels > maxTotalPixels {
		return nil, false, fmt.Errorf("itb: container too large: %d pixels exceeds maximum %d", totalPixels, maxTotalPixels)
	}
	expectedSize := totalPixels * Channels
	if len(container) < expectedSize {
		return nil, false, fmt.Errorf("itb: container too short: got %d, need %d", len(container), expectedSize)
	}

	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third

	caps := [3]int{
		(third * DataBitsPerPixel) / 8,
		(third * DataBitsPerPixel) / 8,
		(thirdPixels2 * DataBitsPerPixel) / 8,
	}
	if caps[2] <= tagSize+1 {
		return nil, false, fmt.Errorf("itb: container too small for MAC tag")
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
		process256Cfg(cfg, noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, decoded[0], false, perThird)
		wg.Done()
	}()
	go func() {
		process256Cfg(cfg, noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, decoded[1], false, perThird)
		wg.Done()
	}()
	go func() {
		process256Cfg(cfg, noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, decoded[2], false, perThird)
		wg.Done()
	}()
	wg.Wait()

	// Split part2 into payload || tag || flag
	payloadLen2 := caps[2] - tagSize - 1
	payload2 := decoded[2][:payloadLen2]
	tag := decoded[2][payloadLen2 : payloadLen2+tagSize]
	flag := decoded[2][payloadLen2+tagSize]

	// Verify MAC over concatenated payloads || streamID || uint64_le(offset) || flag
	macInputLen := len(decoded[0]) + len(decoded[1]) + payloadLen2 + 32 + 8 + 1
	macInputPtr, macInput := acquireBuffer(macInputLen)
	off := 0
	copy(macInput[off:], decoded[0])
	off += len(decoded[0])
	copy(macInput[off:], decoded[1])
	off += len(decoded[1])
	copy(macInput[off:], payload2)
	off += payloadLen2
	copy(macInput[off:], streamID[:])
	off += 32
	binary.LittleEndian.PutUint64(macInput[off:], cumulativePixelOffset)
	off += 8
	macInput[off] = flag
	expected := macFunc(macInput[:macInputLen])
	releaseBuffer(macInputPtr, macInput)

	if !constantTimeEqual(tag, expected) {
		return nil, false, ErrMACFailure
	}

	finalFlag := flag == 0xFF

	// 3 parallel null-search + cobsDecode (MAC already verified data integrity)
	parts := [3][]byte{}
	emptyThird := [3]bool{}
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
				if nullPos < 0 {
					errs[i] = fmt.Errorf("itb: no terminator found in third %d", i)
					return
				}
				if nullPos == 0 {
					if !finalFlag {
						errs[i] = fmt.Errorf("itb: no terminator found in third %d", i)
						return
					}
					emptyThird[i] = true
					return
				}
				parts[i] = cobsDecode(dec[:nullPos])
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				return nil, false, err
			}
		}
	}

	if emptyThird[0] && emptyThird[1] && emptyThird[2] {
		return []byte{}, true, nil
	}

	return interleaveForTripleParallelLockedCfg(cfg, parts[0], parts[1], parts[2], buildLockPRF256Cfg(cfg, noiseSeed, nonce)), finalFlag, nil
}
