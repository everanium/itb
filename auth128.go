package itb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
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
		return nil, ErrEmptyInput
	}
	if macFunc == nil {
		return nil, fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) > maxDataSize {
		return nil, fmt.Errorf("itb: data too large: %d bytes (max %d)", len(data), maxDataSize)
	}
	if err := validateConfigCfg(cfg); err != nil {
		return nil, err
	}

	tagSize := len(macFunc([]byte{}))
	if tagSize == 0 {
		return nil, fmt.Errorf("itb: macFunc returned empty tag")
	}

	nonce, ilNonce, err := generateNoncePairCfg(cfg)
	if err != nil {
		return nil, err
	}

	// Interlock split, COBS and payload assembly (see triplepayload.go).
	// part2 COBS length increased by tagSize + 1 for container sizing:
	// the +1 mirrors the Streaming AEAD flag-byte slot so the single
	// message wire envelope matches the No MAC Encrypt3x envelope
	// (which reserves nomacTagStubSizeCfg(cfg) = tagSize + 1 for the
	// same mode-ambiguity reason — the zero-value default covers the
	// shipped 32-byte tags, and Config.TagStubSize carries a
	// custom MAC's tag length). Single messages carry a fixed 0x00 in
	// that slot — there is no finalFlag semantic on this path. part0
	// and part1 are filled to full capacity, part2 reserves tagSize + 1
	// (tag slot + fixed 0x00 dummy flag slot) that is written below.
	tp, width, height, err := buildTriplePayloads(cfg, data, buildLockBatchPRF48_128Cfg(cfg, lockSeed, ilNonce), tagSize+1, false,
		func(cobsLens [3]int) (int, int) {
			return containerSizeAuth3_128Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, cobsLens)
		})
	if err != nil {
		return nil, err
	}
	defer tp.release()
	payloads := [3][]byte{tp.bufs[0], tp.bufs[1], tp.bufs[2][:tp.payloadLen[2]]}
	totalPixels := width * height
	third, thirdPixels2, _ := tripleThirdCaps(totalPixels)

	// MAC over concatenated payloads (covers all fill bytes)
	tag := macTagCfg(cfg, macFunc, payloads[0], payloads[1], payloads[2])

	// full2 = payload2 || tag || 0x00 (single-message dummy flag slot),
	// assembled in place in the third payload buffer.
	full2 := tp.bufs[2]
	copy(full2[len(payloads[2]):], tag)
	full2[len(payloads[2])+tagSize] = 0x00

	// Wire buffer: header followed by the CSPRNG-filled container.
	out, container, err := newTripleWire(cfg, nonce, ilNonce, width, height)
	if err != nil {
		return nil, err
	}

	perThird := configuredWorkerCount(cfg) / 3
	if perThird < 1 {
		perThird = 1
	}
	offset1 := third * Channels
	offset2 := 2 * third * Channels
	var wg sync.WaitGroup
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

	if len(fileData) == 0 {
		return nil, ErrEmptyInput
	}
	if len(fileData) < headerSizeCfg(cfg)+Channels {
		return nil, fmt.Errorf("itb: data too short")
	}

	nonceLen := currentNonceSizeCfg(cfg)
	nonce := fileData[:nonceLen]
	ilNonce := fileData[nonceLen : 2*nonceLen]
	width := int(binary.BigEndian.Uint16(fileData[2*nonceLen:]))
	height := int(binary.BigEndian.Uint16(fileData[2*nonceLen+2:]))
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

	third, thirdPixels2, caps := tripleThirdCaps(totalPixels)
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

	perThird := configuredWorkerCount(cfg) / 3
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
	expected := macTagCfg(cfg, macFunc, decoded[0], decoded[1], payload2)

	if !constantTimeEqual(tag, expected) {
		return nil, ErrMACFailure
	}

	// 3 parallel null-search + in-place cobsDecode (MAC already verified
	// data integrity; each decoded lane overwrites its own COBS bytes
	// inside the pooled buffer, wiped on release after the interleave)
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
				nullPos := bytes.IndexByte(dec, 0x00)
				if nullPos <= 0 {
					errs[i] = fmt.Errorf("itb: no terminator found in third %d", i)
					return
				}
				parts[i] = cobsDecodeInto(dec, dec[:nullPos])
			}(i)
		}
		wg.Wait()
		for _, err := range errs {
			if err != nil {
				return nil, err
			}
		}
	}

	return interleaveForTriple48LockedCfg(cfg, parts[0], parts[1], parts[2], buildLockBatchPRF48_128Cfg(cfg, lockSeed, ilNonce)), nil
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
		return nil, ErrEmptyInput
	}
	if macFunc == nil {
		return nil, fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(data) > maxDataSize {
		return nil, fmt.Errorf("itb: data too large: %d bytes (max %d)", len(data), maxDataSize)
	}
	if err := validateConfigCfg(cfg); err != nil {
		return nil, err
	}

	tagSize := len(macFunc([]byte{}))
	if tagSize == 0 {
		return nil, fmt.Errorf("itb: macFunc returned empty tag")
	}

	nonce, ilNonce, err := generateNoncePairCfg(cfg)
	if err != nil {
		return nil, err
	}

	// Interlock split, COBS and payload assembly (see triplepayload.go).
	// part2 COBS length increased by tagSize + 1 (flag byte) for
	// container sizing; part0 and part1 are filled to full capacity,
	// part2 reserves tagSize + 1 (tag slot + flag) that is written below.
	tp, width, height, err := buildTriplePayloads(cfg, data, buildLockBatchPRF48_128Cfg(cfg, lockSeed, ilNonce), tagSize+1, false,
		func(cobsLens [3]int) (int, int) {
			return containerSizeAuth3_128Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, cobsLens)
		})
	if err != nil {
		return nil, err
	}
	defer tp.release()
	payloads := [3][]byte{tp.bufs[0], tp.bufs[1], tp.bufs[2][:tp.payloadLen[2]]}
	totalPixels := width * height
	third, thirdPixels2, _ := tripleThirdCaps(totalPixels)

	// MAC over concatenated payloads || streamID || uint64_le(offset) || flag
	flag := streamFlagByte(finalFlag)
	var offsetLE [8]byte
	binary.LittleEndian.PutUint64(offsetLE[:], cumulativePixelOffset)
	tag := macTagCfg(cfg, macFunc,
		payloads[0], payloads[1], payloads[2], streamID[:], offsetLE[:], []byte{flag})

	// full2 = payload2 || tag || flag, assembled in place in the third
	// payload buffer.
	full2 := tp.bufs[2]
	copy(full2[len(payloads[2]):], tag)
	full2[len(payloads[2])+tagSize] = flag

	// Wire buffer: header followed by the CSPRNG-filled container.
	out, container, err := newTripleWire(cfg, nonce, ilNonce, width, height)
	if err != nil {
		return nil, err
	}

	perThird := configuredWorkerCount(cfg) / 3
	if perThird < 1 {
		perThird = 1
	}
	offset1 := third * Channels
	offset2 := 2 * third * Channels
	var wg sync.WaitGroup
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

	if len(chunkData) == 0 {
		return nil, false, ErrEmptyInput
	}
	if len(chunkData) < headerSizeCfg(cfg)+Channels {
		return nil, false, fmt.Errorf("itb: data too short")
	}

	nonceLen := currentNonceSizeCfg(cfg)
	nonce := chunkData[:nonceLen]
	ilNonce := chunkData[nonceLen : 2*nonceLen]
	width := int(binary.BigEndian.Uint16(chunkData[2*nonceLen:]))
	height := int(binary.BigEndian.Uint16(chunkData[2*nonceLen+2:]))
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

	third, thirdPixels2, caps := tripleThirdCaps(totalPixels)
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

	perThird := configuredWorkerCount(cfg) / 3
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
	var offsetLE [8]byte
	binary.LittleEndian.PutUint64(offsetLE[:], cumulativePixelOffset)
	expected := macTagCfg(cfg, macFunc,
		decoded[0], decoded[1], payload2, streamID[:], offsetLE[:], []byte{flag})

	if !constantTimeEqual(tag, expected) {
		return nil, false, ErrMACFailure
	}

	finalFlag := flag == 0xFF

	// 3 parallel null-search + in-place cobsDecode (MAC already verified
	// data integrity; each decoded lane overwrites its own COBS bytes
	// inside the pooled buffer, wiped on release after the interleave)
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
				nullPos := bytes.IndexByte(dec, 0x00)
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
				parts[i] = cobsDecodeInto(dec, dec[:nullPos])
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

	return interleaveForTriple48LockedCfg(cfg, parts[0], parts[1], parts[2], buildLockBatchPRF48_128Cfg(cfg, lockSeed, ilNonce)), finalFlag, nil
}
