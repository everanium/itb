package itb

import (
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"sync"
)

const headerSize = NonceSize + 4 // nonce(16) + width(2) + height(2)

const (
	// Channels is the number of channels per pixel (RGBWYOPA:
	// Red, Green, Blue, White, Yellow, Orange, Purple, Alpha).
	// 8 channels ensures DataBitsPerPixel (56) is byte-aligned,
	// enabling race-free parallel decode.
	Channels = 8

	// DataBitsPerChannel is the data bits per channel.
	// Each 8-bit channel carries 7 data bits and 1 noise bit.
	DataBitsPerChannel = 7

	// DataBitsPerPixel is the total data bits per pixel.
	DataBitsPerPixel = Channels * DataBitsPerChannel // 56

	// NoisePosRange is the number of possible noise bit positions (0-7).
	NoisePosRange = 8

	// NoisePosConfigBits is the config bits for noise position selection.
	NoisePosConfigBits = 3 // ceil(log2(NoisePosRange))

	// DataRotationBits is the config bits for data rotation within non-noise positions.
	DataRotationBits = 3 // ceil(log2(7)) — rotation 0-6 within 7 data positions

	// NoiseConfigBits is the config bits from the noise seed per pixel.
	NoiseConfigBits = NoisePosConfigBits // 3 — noise position only

	// DataConfigBits is the config bits from the data seed per pixel.
	DataConfigBits = DataRotationBits + DataBitsPerPixel // 59 — rotation + per-bit XOR
)


// blockHash computes hash for a single pixel using a pre-allocated buffer.
// buf must be 20 bytes with nonce pre-filled at offset 4.
// Only bytes 0-3 (pixel index) are overwritten per call.
func (s *Seed) blockHash(buf []byte, blockIdx int) uint64 {
	binary.LittleEndian.PutUint32(buf, uint32(blockIdx))
	return s.ChainHash(buf)
}

// deriveStartPixel computes seed+nonce-dependent pixel offset.
// Data embedding begins at this pixel and wraps around the container.
// Without the seed, the start position is unknown.
func (s *Seed) deriveStartPixel(nonce []byte, totalPixels int) int {
	var buf [17]byte
	buf[0] = 0x02
	copy(buf[1:], nonce)
	h := s.ChainHash(buf[:])
	return int(h % uint64(totalPixels))
}

// containerSize calculates RGBWYOPA container dimensions for given payload.
// Uses max(noiseSeed, dataSeed, startSeed) MinPixels to ensure all seeds are fully utilized.
func containerSize(noiseSeed, dataSeed, startSeed *Seed, payloadCOBSLen int) (width, height int) {
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

// process is the triple-seed encode/decode engine.
//
// Three independent seeds provide separate configuration domains:
//
//   - noiseSeed → noise position (0-7): which bit in each channel is noise.
//     CCA can reveal this, but it tells nothing about data arrangement.
//
//   - dataSeed → data rotation (0-6) + per-bit XOR masks (56 bits):
//     how data bits are arranged within the 7 non-noise positions, and
//     the XOR mask for each data bit. Independent of noiseSeed — CCA
//     compromise of noise positions does not reveal data configuration.
//
// Two ChainHash calls per pixel (noise + data) plus one per message
// (start pixel from startSeed). Data rotation is designed to prevent
// the attacker from mapping plaintext bits to physical channel positions
// even with known noise positions (CCA) and known plaintext (KPA).
//
// When encode=true, data bits are rotated, XOR'd, and written.
// When encode=false, bits are read, XOR-decrypted, and un-rotated.
// minParallelPixels is the threshold for parallel processing.
// Below this, goroutine overhead exceeds the benefit.
const minParallelPixels = 256

func process(noiseSeed, dataSeed, startSeed *Seed, nonce []byte, container []byte, width, height int, data []byte, encode bool) {
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
		processChunk(noiseSeed, dataSeed, nonce, container, data, startPixel, totalPixels, 0, dataPixels, totalBits, encode)
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
			processChunk(noiseSeed, dataSeed, nonce, container, data, startPixel, totalPixels, startP, endP, totalBits, encode)
		}(startP, endP)
	}
	wg.Wait()
}

// rotateBits7 rotates a 7-bit value left by r positions.
// Uses register-only operations (no memory access) to avoid
// cache timing side-channels in SEV/SGX/TDX environments.
func rotateBits7(v byte, r uint) byte {
	r = r % 7
	return ((v << r) | (v >> (7 - r))) & 0x7F
}

// Encrypt encrypts arbitrary binary data into a raw RGBWYOPA pixel container.
//
// Uses triple-seed architecture: noiseSeed controls noise bit placement,
// dataSeed controls data rotation and XOR masks, startSeed controls
// pixel start offset. All three seeds are independent — compromise of
// one does not reveal the others.
//
// Pipeline: data → COBS encode → [0x00 terminator] → embed into
// crypto/rand RGBWYOPA container with per-bit XOR, data rotation,
// and dynamic noise position.
//
// Output format: [16-byte nonce][2-byte width BE][2-byte height BE][W×H×8 raw RGBWYOPA].
//
// Example:
//
//	noiseSeed, _ := itb.NewSeed(512, xxh3.HashSeed)
//	dataSeed, _ := itb.NewSeed(512, xxh3.HashSeed)
//
//	encrypted, err := itb.Encrypt(noiseSeed, dataSeed, startSeed, data)
// maxDataSize is the maximum plaintext size to prevent integer overflow
// in pixel/bit calculations. Automatically scales with platform int size:
// ~256 MB on 32-bit, ~1 EB on 64-bit (limited by available RAM).
const maxDataSize = math.MaxInt / 16

func Encrypt(noiseSeed, dataSeed, startSeed *Seed, data []byte) ([]byte, error) {
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

	width, height := containerSize(noiseSeed, dataSeed, startSeed, len(encoded))
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

	process(noiseSeed, dataSeed, startSeed, nonce, container, width, height, payload, true)
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

// Decrypt extracts data hidden by [Encrypt].
//
// Parses [nonce][width][height][RGBWYOPA] format, applies the reverse
// extraction with triple-seed decryption, finds the null terminator,
// and COBS-decodes the original data.
//
// Returns error if seeds are wrong (no valid terminator found) or
// data is corrupted.
//
// Example:
//
//	original, err := itb.Decrypt(noiseSeed, dataSeed, startSeed, encrypted)
func Decrypt(noiseSeed, dataSeed, startSeed *Seed, fileData []byte) ([]byte, error) {
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
	expectedSize := totalPixels * Channels
	if len(container) < expectedSize {
		return nil, fmt.Errorf("itb: container too short: got %d, need %d", len(container), expectedSize)
	}

	capacity := (totalPixels * DataBitsPerPixel) / 8
	if capacity < 1 {
		return nil, fmt.Errorf("itb: container too small")
	}

	decoded := make([]byte, capacity)

	process(noiseSeed, dataSeed, startSeed, nonce, container, width, height, decoded, false)
	defer secureWipe(decoded) // wipe after extracting plaintext

	// Constant-time null search: always scans entire capacity to avoid
	// timing leak of terminator position (side-channel resistance).
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
