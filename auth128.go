package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"sync"
)

// EncryptAuthenticated3x128Cfg encrypts data with integrity using
// Triple Ouroboros (128-bit variant). Threads cfg through every
// Cfg-aware accessor in the authenticated pipeline. Includes the
// part2-reserves-tag layout and the MAC-over-concatenated-payloads
// invariant. nil cfg falls back to the compile-in defaults.
func EncryptAuthenticated3x128Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, macFunc MACFunc) ([]byte, error) {
	if err := checkEightSeeds128(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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

	p0, p1, p2 := splitForTriple48LockedCfg(cfg, data, buildLockBatchPRF48_128Cfg(cfg, lockSeed, nonce))

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

	// part2 COBS length increased by tagSize + 1 for container sizing:
	// the +1 mirrors the Streaming AEAD flag-byte slot so the single
	// message wire envelope matches the No-MAC Encrypt3x envelope
	// (which reserves nomacTagStubSize = tagSize + 1 for the same
	// mode-ambiguity reason). Single messages carry a fixed 0x00 in
	// that slot — there is no finalFlag semantic on this path.
	cobsLens := [3]int{len(encs[0]), len(encs[1]), len(encs[2]) + tagSize + 1}
	width, height := containerSizeAuth3_128Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, cobsLens)
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

	// Build payloads: part0 and part1 full capacity, part2 reserves
	// tagSize + 1 (tag slot + fixed 0x00 dummy flag slot).
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

	// full2 = payload2 || tag || 0x00 (single-message dummy flag slot)
	full2Ptr, full2 := acquireBuffer(caps[2])
	defer releaseBuffer(full2Ptr, full2)
	copy(full2, payloads[2])
	copy(full2[len(payloads[2]):], tag)
	full2[len(payloads[2])+tagSize] = 0x00

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
		process128Cfg(cfg, noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, payloads[0], true, perThird)
		wg.Done()
	}()
	go func() {
		process128Cfg(cfg, noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, payloads[1], true, perThird)
		wg.Done()
	}()
	go func() {
		process128Cfg(cfg, noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, full2, true, perThird)
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

// DecryptAuthenticated3x128Cfg is the inverse of
// [EncryptAuthenticated3x128Cfg]. nil cfg falls back to the
// compile-in defaults.
func DecryptAuthenticated3x128Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, fileData []byte, macFunc MACFunc) ([]byte, error) {
	if err := checkEightSeeds128(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
	if caps[2] <= tagSize+1 {
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
		process128Cfg(cfg, noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, decoded[0], false, perThird)
		wg.Done()
	}()
	go func() {
		process128Cfg(cfg, noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, decoded[1], false, perThird)
		wg.Done()
	}()
	go func() {
		process128Cfg(cfg, noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, decoded[2], false, perThird)
		wg.Done()
	}()
	wg.Wait()

	// Split part2 into payload || tag || dummy-flag-byte. The trailing
	// byte carries a fixed 0x00 on the encrypt side and is discarded
	// here; the null-search skips well before it (the COBS terminator
	// lives ahead of the tag region).
	payloadLen2 := caps[2] - tagSize - 1
	payload2 := decoded[2][:payloadLen2]
	tag := decoded[2][payloadLen2 : payloadLen2+tagSize]

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

	return interleaveForTriple48LockedCfg(cfg, parts[0], parts[1], parts[2], buildLockBatchPRF48_128Cfg(cfg, lockSeed, nonce)), nil
}

// EncryptStreamAuthenticated3x128Cfg encrypts a single Streaming AEAD
// chunk under Triple Ouroboros with 8 seeds (128-bit variant).
// Threads cfg through every
// Cfg-aware accessor in the Triple Ouroboros Streaming AEAD pipeline.
// Body otherwise identical, including the part2-reserves-tag-and-flag
// layout and the MAC-over-concatenated-payloads-plus-binding invariant.
func EncryptStreamAuthenticated3x128Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, macFunc MACFunc, streamID [32]byte, cumulativePixelOffset uint64, finalFlag bool) ([]byte, error) {
	if err := checkEightSeeds128(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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

	p0, p1, p2 := splitForTriple48LockedCfg(cfg, data, buildLockBatchPRF48_128Cfg(cfg, lockSeed, nonce))

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
	width, height := containerSizeAuth3_128Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, cobsLens)
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
		process128Cfg(cfg, noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, payloads[0], true, perThird)
		wg.Done()
	}()
	go func() {
		process128Cfg(cfg, noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, payloads[1], true, perThird)
		wg.Done()
	}()
	go func() {
		process128Cfg(cfg, noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, full2, true, perThird)
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

// DecryptStreamAuthenticated3x128Cfg is the inverse of
// [EncryptStreamAuthenticated3x128Cfg]. nil cfg falls back to the
// compile-in defaults.
func DecryptStreamAuthenticated3x128Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, chunkData []byte, macFunc MACFunc, streamID [32]byte, cumulativePixelOffset uint64) ([]byte, bool, error) {
	if err := checkEightSeeds128(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
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
		process128Cfg(cfg, noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, decoded[0], false, perThird)
		wg.Done()
	}()
	go func() {
		process128Cfg(cfg, noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, decoded[1], false, perThird)
		wg.Done()
	}()
	go func() {
		process128Cfg(cfg, noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, decoded[2], false, perThird)
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

	return interleaveForTriple48LockedCfg(cfg, parts[0], parts[1], parts[2], buildLockBatchPRF48_128Cfg(cfg, lockSeed, nonce)), finalFlag, nil
}
