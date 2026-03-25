package itb

import (
	"encoding/binary"
	"fmt"
	"math"
	"sync"
)

// containerSize128 calculates RGBWYOPA container dimensions for given payload (128-bit variant).
// Uses max(noiseSeed, dataSeed, startSeed) MinPixels to ensure all seeds are fully utilized.
func containerSize128(noiseSeed, dataSeed, startSeed *Seed128, payloadCOBSLen int) (width, height int) {
	needed := payloadCOBSLen + 1 // +1 for null terminator
	pixels := (needed*8 + DataBitsPerPixel - 1) / DataBitsPerPixel

	minPx := noiseSeed.MinPixels()
	if dp := dataSeed.MinPixels(); dp > minPx {
		minPx = dp
	}
	if sp := startSeed.MinPixels(); sp > minPx {
		minPx = sp
	}
	if pixels < minPx {
		pixels = minPx
	}

	side := 1
	for side*side < pixels {
		side++
	}
	return side, side
}

// process128 is the triple-seed encode/decode engine (128-bit variant).
//
// Three independent 128-bit seeds provide separate configuration domains:
//
//   - noiseSeed → noise position (0-7): which bit in each channel is noise.
//   - dataSeed → data rotation (0-6) + per-bit XOR masks (56 bits).
//   - startSeed → pixel start offset.
//
// Uses blockHash128 (128-bit hash) per pixel, taking the low 64-bit half
// for noise/data configuration. Otherwise identical to process.
func process128(noiseSeed, dataSeed, startSeed *Seed128, nonce []byte, container []byte, width, height int, data []byte, encode bool) {
	totalPixels := width * height
	startPixel := startSeed.deriveStartPixel(nonce, totalPixels)
	totalBits := len(data) * 8

	// Determine pixel count that carries data.
	dataPixels := totalPixels
	if maxPx := (totalBits + DataBitsPerPixel - 1) / DataBitsPerPixel; maxPx < dataPixels {
		dataPixels = maxPx
	}

	// Parallel encode and decode. Encode reads data[] (read-only) and
	// writes to non-overlapping pixel regions in container[]. Decode
	// accumulates all channels into a uint64 and writes 7 complete bytes
	// per pixel — no byte-boundary overlap between adjacent pixels.
	numWorkers := effectiveWorkers(dataPixels)

	if numWorkers == 1 {
		processChunk128(noiseSeed, dataSeed, nonce, container, data, startPixel, totalPixels, 0, dataPixels, totalBits, encode)
		return
	}

	var wg sync.WaitGroup
	pixelsPerWorker := dataPixels / numWorkers

	for w := 0; w < numWorkers; w++ {
		startP := w * pixelsPerWorker
		endP := startP + pixelsPerWorker
		if w == numWorkers-1 {
			endP = dataPixels
		}

		wg.Add(1)
		go func(startP, endP int) {
			defer wg.Done()
			processChunk128(noiseSeed, dataSeed, nonce, container, data, startPixel, totalPixels, startP, endP, totalBits, encode)
		}(startP, endP)
	}
	wg.Wait()
}

// Encrypt128 encrypts arbitrary binary data into a raw RGBWYOPA pixel container
// using 128-bit seeds.
//
// Uses triple-seed architecture with Seed128: noiseSeed controls noise bit
// placement, dataSeed controls data rotation and XOR masks, startSeed controls
// pixel start offset. All three seeds are independent — compromise of one does
// not reveal the others.
//
// Pipeline: data → COBS encode → [0x00 terminator] → embed into
// crypto/rand RGBWYOPA container with per-bit XOR, data rotation,
// and dynamic noise position.
//
// Output format: [16-byte nonce][2-byte width BE][2-byte height BE][W×H×8 raw RGBWYOPA].
func Encrypt128(noiseSeed, dataSeed, startSeed *Seed128, data []byte) ([]byte, error) {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return nil, fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("itb: empty data")
	}
	if len(data) > maxDataSize {
		return nil, fmt.Errorf("itb: data too large: %d bytes (max %d)", len(data), maxDataSize)
	}

	encoded := cobsEncode(data)

	width, height := containerSize128(noiseSeed, dataSeed, startSeed, len(encoded))
	totalPixels := width * height
	capacity := (totalPixels * DataBitsPerPixel) / 8

	if len(encoded)+1 > capacity {
		return nil, fmt.Errorf("itb: internal error: container too small")
	}

	payload := make([]byte, capacity)
	copy(payload, encoded)
	payload[len(encoded)] = 0x00
	// Remaining capacity after COBS + null filled with crypto/rand.
	fillStart := len(encoded) + 1
	if fillStart < capacity {
		fillBytes, err := generateRandomBytes(capacity - fillStart)
		if err != nil {
			return nil, err
		}
		copy(payload[fillStart:], fillBytes)
	}

	container, err := generateRandomBytes(totalPixels * Channels)
	if err != nil {
		return nil, err
	}
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	process128(noiseSeed, dataSeed, startSeed, nonce, container, width, height, payload, true)
	secureWipe(payload) // minimize plaintext exposure in heap

	out := make([]byte, 0, headerSize+len(container))
	out = append(out, nonce...)
	var dim [4]byte
	binary.BigEndian.PutUint16(dim[0:], uint16(width))
	binary.BigEndian.PutUint16(dim[2:], uint16(height))
	out = append(out, dim[:]...)
	out = append(out, container...)

	return out, nil
}

// Decrypt128 extracts data hidden by [Encrypt128] using 128-bit seeds.
//
// Parses [nonce][width][height][RGBWYOPA] format, applies the reverse
// extraction with triple-seed decryption, finds the null terminator,
// and COBS-decodes the original data.
//
// Returns error if seeds are wrong (no valid terminator found) or
// data is corrupted.
func Decrypt128(noiseSeed, dataSeed, startSeed *Seed128, fileData []byte) ([]byte, error) {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return nil, fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if len(fileData) < headerSize+Channels {
		return nil, fmt.Errorf("itb: data too short")
	}

	nonce := fileData[:NonceSize]
	width := int(binary.BigEndian.Uint16(fileData[NonceSize:]))
	height := int(binary.BigEndian.Uint16(fileData[NonceSize+2:]))
	container := fileData[headerSize:]

	// Overflow-safe multiplication: check before computing to prevent
	// integer overflow on 32-bit platforms decrypting containers from 64-bit.
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
	if capacity < 1 {
		return nil, fmt.Errorf("itb: container too small")
	}

	decoded := make([]byte, capacity)

	process128(noiseSeed, dataSeed, startSeed, nonce, container, width, height, decoded, false)
	defer secureWipe(decoded) // wipe after extracting plaintext

	// Constant-iteration null search: always scans entire capacity (no early break)
	// to avoid timing leak of terminator position. Note: branch prediction may still
	// differ before/after the first null byte; this leaks COBS-encoded message length.
	nullPos := -1
	for i := 0; i < len(decoded); i++ {
		if decoded[i] == 0x00 && nullPos == -1 {
			nullPos = i
		}
	}
	if nullPos < 0 {
		return nil, fmt.Errorf("itb: no terminator found (wrong seed?)")
	}
	if nullPos == 0 {
		return nil, fmt.Errorf("itb: empty payload")
	}

	original := cobsDecode(decoded[:nullPos])
	if len(original) == 0 {
		return nil, fmt.Errorf("itb: COBS decode produced empty output")
	}

	return original, nil
}
