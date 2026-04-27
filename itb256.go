package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"sync"
)

// containerSize256 calculates RGBWYOPA container dimensions for given payload (256-bit variant).
// Uses max(noiseSeed, dataSeed, startSeed) MinPixels (56^P ambiguity dominance).
func containerSize256(noiseSeed, dataSeed, startSeed *Seed256, payloadCOBSLen int) (width, height int) {
	return calcContainerSize(payloadCOBSLen,
		noiseSeed.MinPixels(), dataSeed.MinPixels(), startSeed.MinPixels())
}

// containerSizeAuth256 calculates container dimensions for authenticated encryption.
// Uses MinPixelsAuth (7^P ambiguity dominance — CCA-resistant).
func containerSizeAuth256(noiseSeed, dataSeed, startSeed *Seed256, payloadCOBSLen int) (width, height int) {
	return calcContainerSize(payloadCOBSLen,
		noiseSeed.MinPixelsAuth(), dataSeed.MinPixelsAuth(), startSeed.MinPixelsAuth())
}

// process256 is the triple-seed encode/decode engine (256-bit variant).
//
// Three independent 256-bit seeds provide separate configuration domains:
//
//   - noiseSeed → noise position (0-7): which bit in each channel is noise.
//   - dataSeed → data rotation (0-6) + per-bit XOR masks (56 bits).
//   - startSeed → pixel start offset.
//
// Uses blockHash256 (256-bit hash) per pixel, taking the low 64-bit half
// for noise/data configuration. Otherwise identical to process.
func process256(noiseSeed, dataSeed, startSeed *Seed256, nonce []byte, container []byte, width, height int, data []byte, encode bool, maxW int) {
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
	if maxW > 0 && numWorkers > maxW {
		numWorkers = maxW
	}

	if numWorkers == 1 {
		processChunk256(noiseSeed, dataSeed, nonce, container, data, startPixel, totalPixels, 0, dataPixels, totalBits, encode)
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
			processChunk256(noiseSeed, dataSeed, nonce, container, data, startPixel, totalPixels, startP, endP, totalBits, encode)
		}(startP, endP)
	}
	wg.Wait()
}

// Encrypt256 encrypts arbitrary binary data into a raw RGBWYOPA pixel container
// using 256-bit seeds.
//
// Uses triple-seed architecture with Seed256: noiseSeed controls noise bit
// placement, dataSeed controls data rotation and XOR masks, startSeed controls
// pixel start offset. All three seeds are independent — compromise of one does
// not reveal the others.
//
// Pipeline: data → COBS encode → [0x00 terminator] → embed into
// crypto/rand RGBWYOPA container with per-bit XOR, data rotation,
// and dynamic noise position.
//
// Output format: [16-byte nonce][2-byte width BE][2-byte height BE][W×H×8 raw RGBWYOPA].
func Encrypt256(noiseSeed, dataSeed, startSeed *Seed256, data []byte) ([]byte, error) {
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

	width, height := containerSize256(noiseSeed, dataSeed, startSeed, len(encoded))
	totalPixels := width * height
	capacity := (totalPixels * DataBitsPerPixel) / 8

	if len(encoded)+1 > capacity {
		return nil, fmt.Errorf("itb: internal error: container too small")
	}

	payloadPtr, payload := acquireBuffer(capacity)
	defer releaseBuffer(payloadPtr, payload)
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

	process256(noiseSeed, dataSeed, startSeed, nonce, container, width, height, payload, true, 0)

	out := make([]byte, 0, headerSize()+len(container))
	out = append(out, nonce...)
	var dim [4]byte
	binary.BigEndian.PutUint16(dim[0:], uint16(width))
	binary.BigEndian.PutUint16(dim[2:], uint16(height))
	out = append(out, dim[:]...)
	out = append(out, container...)

	return out, nil
}

// Decrypt256 extracts data hidden by [Encrypt256] using 256-bit seeds.
//
// Parses [nonce][width][height][RGBWYOPA] format, applies the reverse
// extraction with triple-seed decryption, and COBS-decodes the result.
//
// Errors only on structural issues (header parsing, dimension validation).
// Wrong seeds produce random-looking output, never error — non-Auth mode
// has no failure signal by design.
func Decrypt256(noiseSeed, dataSeed, startSeed *Seed256, fileData []byte) ([]byte, error) {
	if noiseSeed == dataSeed || noiseSeed == startSeed || dataSeed == startSeed {
		return nil, fmt.Errorf("itb: all three seeds must be different (triple-seed isolation)")
	}
	if len(fileData) < headerSize()+Channels {
		return nil, fmt.Errorf("itb: data too short")
	}

	nonce := fileData[:currentNonceSize()]
	width := int(binary.BigEndian.Uint16(fileData[currentNonceSize():]))
	height := int(binary.BigEndian.Uint16(fileData[currentNonceSize()+2:]))
	container := fileData[headerSize():]

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

	decodedPtr, decoded := acquireBuffer(capacity)
	defer releaseBuffer(decodedPtr, decoded)

	process256(noiseSeed, dataSeed, startSeed, nonce, container, width, height, decoded, false, 0)

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
		nullPos = len(decoded)
	}
	return cobsDecode(decoded[:nullPos]), nil
}

// checkSevenSeeds256 verifies all 7 seeds are distinct pointers (seven-seed isolation).
func checkSevenSeeds256(ns, ds1, ds2, ds3, ss1, ss2, ss3 *Seed256) error {
	seeds := [7]*Seed256{ns, ds1, ds2, ds3, ss1, ss2, ss3}
	for i := 0; i < len(seeds); i++ {
		for j := i + 1; j < len(seeds); j++ {
			if seeds[i] == seeds[j] {
				return fmt.Errorf("itb: all seven seeds must be different (seven-seed isolation)")
			}
		}
	}
	return nil
}

// containerSize3_256 calculates container dimensions for Triple Ouroboros (256-bit variant).
func containerSize3_256(noiseSeed *Seed256, dataSeed1, dataSeed2, dataSeed3 *Seed256, startSeed1, startSeed2, startSeed3 *Seed256, cobsLens [3]int) (width, height int) {
	return calcContainerSize3(cobsLens,
		noiseSeed.MinPixels(),
		[3]int{dataSeed1.MinPixels(), dataSeed2.MinPixels(), dataSeed3.MinPixels()},
		[3]int{startSeed1.MinPixels(), startSeed2.MinPixels(), startSeed3.MinPixels()})
}

// containerSizeAuth3_256 calculates container dimensions for authenticated Triple Ouroboros (256-bit variant).
func containerSizeAuth3_256(noiseSeed *Seed256, dataSeed1, dataSeed2, dataSeed3 *Seed256, startSeed1, startSeed2, startSeed3 *Seed256, cobsLens [3]int) (width, height int) {
	return calcContainerSize3(cobsLens,
		noiseSeed.MinPixelsAuth(),
		[3]int{dataSeed1.MinPixelsAuth(), dataSeed2.MinPixelsAuth(), dataSeed3.MinPixelsAuth()},
		[3]int{startSeed1.MinPixelsAuth(), startSeed2.MinPixelsAuth(), startSeed3.MinPixelsAuth()})
}

// Encrypt3x256 encrypts data using Triple Ouroboros with 7 seeds (256-bit variant).
// Plaintext is split into 3 parts (every 3rd byte), each encrypted into 1/3 of the
// pixel data with independent dataSeed and startSeed, sharing noiseSeed.
// Output format is identical to standard ITB: [nonce][W][H][W×H×8 pixels].
func Encrypt3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, data []byte) ([]byte, error) {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("itb: empty data")
	}
	if len(data) > maxDataSize {
		return nil, fmt.Errorf("itb: data too large: %d bytes (max %d)", len(data), maxDataSize)
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

	width, height := containerSize3_256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, [3]int{len(encs[0]), len(encs[1]), len(encs[2])})
	totalPixels := width * height
	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third

	caps := [3]int{
		(third * DataBitsPerPixel) / 8,
		(third * DataBitsPerPixel) / 8,
		(thirdPixels2 * DataBitsPerPixel) / 8,
	}
	for i := 0; i < 3; i++ {
		if len(encs[i])+1 > caps[i] {
			return nil, fmt.Errorf("itb: internal error: container third %d too small", i)
		}
	}

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
				payloadPtrs[i], payloads[i] = acquireBuffer(caps[i])
				copy(payloads[i], encs[i])
				payloads[i][len(encs[i])] = 0x00
				fillStart := len(encs[i]) + 1
				if fillStart < caps[i] {
					fillBytes, err := generateRandomBytes(caps[i] - fillStart)
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

	// 3×CSPRNG parallel generation into one pre-allocated buffer
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

	// 3 parallel goroutines for pixel processing, each limited to 1/3 of CPU cores
	offset1 := third * Channels
	offset2 := 2 * third * Channels
	perThird := runtime.NumCPU() / 3
	if perThird < 1 {
		perThird = 1
	}
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
		process256(noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, payloads[2], true, perThird)
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

// Decrypt3x256 decrypts data encrypted by [Encrypt3x256] (Triple Ouroboros, 256-bit variant).
func Decrypt3x256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed256, fileData []byte) ([]byte, error) {
	if err := checkSevenSeeds256(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return nil, err
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

	offset1 := third * Channels
	offset2 := 2 * third * Channels
	perThird := runtime.NumCPU() / 3
	if perThird < 1 {
		perThird = 1
	}

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

	// 3 parallel null-search + cobsDecode
	parts := [3][]byte{}
	{
		var wg sync.WaitGroup
		wg.Add(3)
		for i := 0; i < 3; i++ {
			go func(i int) {
				defer wg.Done()
				nullPos := -1
				for j := 0; j < len(decoded[i]); j++ {
					if decoded[i][j] == 0x00 && nullPos == -1 {
						nullPos = j
					}
				}
				if nullPos < 0 {
					nullPos = len(decoded[i])
				}
				parts[i] = cobsDecode(decoded[i][:nullPos])
			}(i)
		}
		wg.Wait()
	}

	return interleaveForTripleParallel(parts[0], parts[1], parts[2]), nil
}
