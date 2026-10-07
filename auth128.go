package itb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
)

// EncryptAuthenticated3x128Cfg encrypts data as one MAC Authenticated
// Single Message using Triple Ouroboros (128-bit variant). The wire is
//
//	[streamID(32)][main nonce][W][H][W×H×8 pixels]
//
// where the chunk behind the 32-byte prefix is what
// [EncryptStreamAuthenticated3x128Cfg] produces for a terminating
// first chunk: the CSPRNG streamID, cumulative pixel offset 0 and the
// final flag are bound into the MAC alongside the three payloads, so
// the prefix is authenticated and the wire is byte-shape identical to
// a one-chunk Streaming AEAD transcript. The No MAC counterpart
// [Encrypt3x128Cfg] carries a dummy of the same length in the same
// place, so the two Single Message wires share one shape. Threads cfg
// through every Cfg-aware accessor in the authenticated pipeline; nil
// cfg falls back to the compile-in defaults.
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
	// The streamID is drawn only once the inputs have passed the checks
	// above; the chunk body re-runs them, which is cheap.
	streamID, err := generateStreamID()
	if err != nil {
		return nil, err
	}
	out, err := encryptStreamAuthenticated3x128Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data, macFunc, streamID, 0, true, streamIDPrefixLen)
	if err != nil {
		return nil, err
	}
	copy(out[:streamIDPrefixLen], streamID[:])
	return out, nil
}

// DecryptAuthenticated3x128Cfg is the inverse of
// [EncryptAuthenticated3x128Cfg]: it reads the streamID prefix, verifies
// and decodes the chunk behind it through
// [DecryptStreamAuthenticated3x128Cfg] at cumulative pixel offset 0, and
// requires the chunk to carry the final flag — a non-terminating chunk
// is rejected with [ErrStreamTruncated], exactly as the streaming
// decoders reject a transcript that ends before its terminator. The
// wire must be exactly the prefix plus that one chunk — trailing
// bytes and multi-chunk streams are rejected before the MAC runs. nil
// cfg falls back to the compile-in defaults.
func DecryptAuthenticated3x128Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, fileData []byte, macFunc MACFunc) ([]byte, error) {
	if err := checkEightSeeds128(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return nil, err
	}
	if macFunc == nil {
		return nil, fmt.Errorf("itb: macFunc must not be nil")
	}
	if len(fileData) == 0 {
		return nil, ErrEmptyInput
	}
	if len(fileData) < streamIDPrefixLen+headerSizeCfg(cfg)+Channels {
		return nil, fmt.Errorf("itb: data too short")
	}
	// The header behind the prefix announces the one chunk, and nothing
	// may follow it. The check reads only the public W and H and the
	// wire length, so it is key-independent and precedes the MAC. A
	// header that does not parse falls through to the chunk decoder,
	// which reports the malformed field itself.
	if chunkLen, perr := ParseChunkLenCfg(cfg, fileData[streamIDPrefixLen:]); perr == nil && streamIDPrefixLen+chunkLen != len(fileData) {
		return nil, fmt.Errorf("itb: wire is %d bytes, want %d for prefix + one chunk (trailing bytes or a multi-chunk stream)", len(fileData), streamIDPrefixLen+chunkLen)
	}
	var streamID [streamIDPrefixLen]byte
	copy(streamID[:], fileData[:streamIDPrefixLen])
	plain, finalFlag, err := DecryptStreamAuthenticated3x128Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, fileData[streamIDPrefixLen:], macFunc, streamID, 0)
	if err != nil {
		return nil, err
	}
	if !finalFlag {
		return nil, ErrStreamTruncated
	}
	return plain, nil
}

// EncryptStreamAuthenticated3x128Cfg encrypts a single Streaming AEAD
// chunk under Triple Ouroboros with 8 seeds (128-bit variant).
// Threads cfg through every
// Cfg-aware accessor in the Triple Ouroboros Streaming AEAD pipeline.
// The third region reserves tagSize + 1 bytes for the tag and the
// flag byte; the MAC covers the three payloads ‖ streamID ‖ LE64
// cumulative pixel offset ‖ flag. The chunk carries no prefix of its
// own: the streamID travels once, ahead of the first chunk, and is
// bound into every chunk's MAC.
func EncryptStreamAuthenticated3x128Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, macFunc MACFunc, streamID [32]byte, cumulativePixelOffset uint64, finalFlag bool) ([]byte, error) {
	return encryptStreamAuthenticated3x128Cfg(cfg, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, data, macFunc, streamID, cumulativePixelOffset, finalFlag, 0)
}

// encryptStreamAuthenticated3x128Cfg is the body of
// [EncryptStreamAuthenticated3x128Cfg] with lead zero bytes reserved
// ahead of the chunk in the returned buffer. The streaming encoders
// pass 0; [EncryptAuthenticated3x128Cfg] passes [streamIDPrefixLen] and
// writes the streamID into the reserved bytes, so the Single Message
// wire is a single allocation.
func encryptStreamAuthenticated3x128Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed128, data []byte, macFunc MACFunc, streamID [32]byte, cumulativePixelOffset uint64, finalFlag bool, lead int) ([]byte, error) {
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

	// Interlock split, COBS, payload assembly and wire allocation with
	// overlapped container + payload-tail DRBG fill (see
	// triplepayload.go). part2 COBS length increased by tagSize + 1
	// (flag byte) for container sizing; part0 and part1 are filled to
	// full capacity, part2 reserves tagSize + 1 (tag slot + flag) that
	// is written below.
	tp, out, container, width, height, err := buildTripleWire3(cfg, data, buildLockBatchPRF48_128Cfg(cfg, lockSeed, ilNonce), tagSize+1, false, lead, nonce, ilNonce,
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
// [EncryptStreamAuthenticated3x128Cfg]. chunkData must be exactly one
// chunk — the length its header announces; trailing bytes are rejected
// before the MAC. nil cfg falls back to the compile-in defaults.
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
	width := int(binary.BigEndian.Uint16(chunkData[nonceLen:]))
	height := int(binary.BigEndian.Uint16(chunkData[nonceLen+2:]))
	container := chunkData[headerSizeCfg(cfg):]

	if width == 0 || height == 0 {
		return nil, false, fmt.Errorf("itb: invalid dimensions %dx%d", width, height)
	}
	// The encoder only emits square containers; a non-square header
	// with the same W·H would otherwise decode to the same plaintext.
	if width != height {
		return nil, false, fmt.Errorf("itb: non-square container %dx%d", width, height)
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
	if len(container) > expectedSize {
		return nil, false, fmt.Errorf("itb: chunk is %d bytes, want %d (trailing bytes after the container)", len(chunkData), headerSizeCfg(cfg)+expectedSize)
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

	// The interlock nonce is carried split across the three lane
	// prefixes; lanes[i] is what follows fragment i.
	ilNonce, lanes := recoverInterlockNonce(nonceLen, parts)
	return interleaveForTriple48LockedCfg(cfg, lanes[0], lanes[1], lanes[2], buildLockBatchPRF48_128Cfg(cfg, lockSeed, ilNonce)), finalFlag, nil
}
