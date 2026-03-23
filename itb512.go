package itb

import (
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"sync"
)

// containerSize512 calculates RGBWYOPA container dimensions for given payload (512-bit variant).
// Uses max(noiseSeed, dataSeed, startSeed) MinPixels to ensure all seeds are fully utilized.
func containerSize512(noiseSeed, dataSeed, startSeed *Seed512, payloadCOBSLen int) (width, height int) {
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

// process512 is the triple-seed encode/decode engine (512-bit variant).
func process512(noiseSeed, dataSeed, startSeed *Seed512, nonce []byte, container []byte, width, height int, data []byte, encode bool) {
	totalPixels := width * height
	startPixel := startSeed.deriveStartPixel(nonce, totalPixels)
	totalBits := len(data) * 8

	dataPixels := totalPixels
	if maxPx := (totalBits + DataBitsPerPixel - 1) / DataBitsPerPixel; maxPx < dataPixels {
		dataPixels = maxPx
	}

	numWorkers := 1
	if dataPixels >= minParallelPixels {
		numWorkers = runtime.NumCPU()
		if numWorkers > dataPixels/64 {
			numWorkers = dataPixels / 64
		}
		if numWorkers < 1 {
			numWorkers = 1
		}
	}

	if numWorkers == 1 {
		processChunk512(noiseSeed, dataSeed, nonce, container, data, startPixel, totalPixels, 0, dataPixels, totalBits, encode)
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
			processChunk512(noiseSeed, dataSeed, nonce, container, data, startPixel, totalPixels, startP, endP, totalBits, encode)
		}(startP, endP)
	}
	wg.Wait()
}

// Encrypt512 encrypts arbitrary binary data into a raw RGBWYOPA pixel container (512-bit variant).
//
// Uses triple-seed architecture with Seed512: noiseSeed controls noise bit placement,
// dataSeed controls data rotation and XOR masks, startSeed controls
// pixel start offset. All three seeds are independent.
//
// Output format: [16-byte nonce][2-byte width BE][2-byte height BE][W*H*8 raw RGBWYOPA].
func Encrypt512(noiseSeed, dataSeed, startSeed *Seed512, data []byte) ([]byte, error) {
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

	width, height := containerSize512(noiseSeed, dataSeed, startSeed, len(encoded))
	totalPixels := width * height
	capacity := (totalPixels * DataBitsPerPixel) / 8

	if len(encoded)+1 > capacity {
		return nil, fmt.Errorf("itb: internal error: container too small")
	}

	payload := make([]byte, capacity)
	copy(payload, encoded)
	payload[len(encoded)] = 0x00
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

	process512(noiseSeed, dataSeed, startSeed, nonce, container, width, height, payload, true)
	secureWipe(payload)

	out := make([]byte, 0, headerSize+len(container))
	out = append(out, nonce...)
	var dim [4]byte
	binary.BigEndian.PutUint16(dim[0:], uint16(width))
	binary.BigEndian.PutUint16(dim[2:], uint16(height))
	out = append(out, dim[:]...)
	out = append(out, container...)

	return out, nil
}

// Decrypt512 extracts data hidden by [Encrypt512] (512-bit variant).
func Decrypt512(noiseSeed, dataSeed, startSeed *Seed512, fileData []byte) ([]byte, error) {
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
	if capacity < 1 {
		return nil, fmt.Errorf("itb: container too small")
	}

	decoded := make([]byte, capacity)

	process512(noiseSeed, dataSeed, startSeed, nonce, container, width, height, decoded, false)
	defer secureWipe(decoded)

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
