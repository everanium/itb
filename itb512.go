package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"sync"
)

// process512Cfg is the triple-seed encode/decode engine (512-bit variant).
//
// Three independent 512-bit seeds provide separate configuration domains:
//
//   - noiseSeed → noise position (0-7): which bit in each channel is noise.
//   - dataSeed → data rotation (0-6) + per-bit XOR masks (56 bits).
//   - startSeed → pixel start offset.
//
// Uses blockHash512 (512-bit hash) per pixel, taking the low 64-bit half
// for noise/data configuration. Threads cfg through to [processChunk512]
// so a non-nil cfg with an explicit NonceBits override is honoured at
// the per-pixel buffer-allocation site.
func process512Cfg(cfg *Config, noiseSeed, dataSeed, startSeed *Seed512, nonce []byte, container []byte, width, height int, data []byte, encode bool, maxW int) {
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
	numWorkers := effectiveWorkersCfg(cfg, dataPixels)
	if maxW > 0 && numWorkers > maxW {
		numWorkers = maxW
	}

	if numWorkers == 1 {
		processChunk512(cfg, noiseSeed, dataSeed, nonce, container, data, startPixel, totalPixels, 0, dataPixels, totalBits, encode)
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
			processChunk512(cfg, noiseSeed, dataSeed, nonce, container, data, startPixel, totalPixels, startP, endP, totalBits, encode)
		}(startP, endP)
	}
	wg.Wait()
}

// checkEightSeeds512 verifies all 8 seeds are distinct pointers (eight-seed isolation).
func checkEightSeeds512(ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *Seed512) error {
	seeds := [8]*Seed512{ns, ls, ds1, ds2, ds3, ss1, ss2, ss3}
	for i := 0; i < len(seeds); i++ {
		for j := i + 1; j < len(seeds); j++ {
			if seeds[i] == seeds[j] {
				return fmt.Errorf("itb: all eight seeds must be different (eight-seed isolation)")
			}
		}
	}
	return nil
}

// containerSize3_512Cfg calculates container dimensions for Triple
// Ouroboros (512-bit variant), threading cfg through
// [calcContainerSize3Cfg] so a non-nil cfg with an explicit
// BarrierFill override is honoured.
func containerSize3_512Cfg(cfg *Config, noiseSeed *Seed512, dataSeed1, dataSeed2, dataSeed3 *Seed512, startSeed1, startSeed2, startSeed3 *Seed512, cobsLens [3]int) (width, height int) {
	return calcContainerSize3Cfg(cfg, cobsLens,
		noiseSeed.MinPixels(),
		[3]int{dataSeed1.MinPixels(), dataSeed2.MinPixels(), dataSeed3.MinPixels()},
		[3]int{startSeed1.MinPixels(), startSeed2.MinPixels(), startSeed3.MinPixels()})
}

// containerSizeAuth3_512Cfg is the Cfg variant of
// [containerSize3_512Cfg] using the auth-mode container floor
// (7^P ambiguity dominance for CCA-resistant AEAD paths).
func containerSizeAuth3_512Cfg(cfg *Config, noiseSeed *Seed512, dataSeed1, dataSeed2, dataSeed3 *Seed512, startSeed1, startSeed2, startSeed3 *Seed512, cobsLens [3]int) (width, height int) {
	return calcContainerSize3Cfg(cfg, cobsLens,
		noiseSeed.MinPixelsAuth(),
		[3]int{dataSeed1.MinPixelsAuth(), dataSeed2.MinPixelsAuth(), dataSeed3.MinPixelsAuth()},
		[3]int{startSeed1.MinPixelsAuth(), startSeed2.MinPixelsAuth(), startSeed3.MinPixelsAuth()})
}

// Encrypt3x512Cfg encrypts data using Triple Ouroboros with 8 seeds
// (512-bit variant). Plaintext is split into 3 parts (every 3rd byte),
// each encrypted into 1/3 of the pixel data with independent dataSeed
// and startSeed, sharing noiseSeed. The lockSeed keys the 48-bit
// interlock overlay's per-chunk bit-permutation derivation. Output
// format is identical to standard ITB: [nonce][W][H][W×H×8 pixels].
//
// cfg threads per-encryptor overrides through every Cfg-aware
// accessor in the pipeline; nil cfg falls back to [DefaultNonceBits] /
// [DefaultBarrierFill] / runtime.NumCPU.
func Encrypt3x512Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, data []byte) ([]byte, error) {
	if err := checkEightSeeds512(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("itb: empty data")
	}
	if len(data) > maxDataSize {
		return nil, fmt.Errorf("itb: data too large: %d bytes (max %d)", len(data), maxDataSize)
	}

	nonce, err := generateNonceCfg(cfg)
	if err != nil {
		return nil, err
	}

	p0, p1, p2 := splitForTriple48LockedCfg(cfg, data, buildLockBatchPRF48_512Cfg(cfg, lockSeed, nonce))

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

	// Reserve nomacTagStubSize bytes in the third snake's container
	// capacity so a wire observer cannot distinguish this No-MAC chunk
	// from the Streaming AEAD chunk (whose third snake carries
	// payload || tag(32) || flag(1)). The reserved bytes are pure
	// CSPRNG on the No-MAC side.
	cobsLens := [3]int{len(encs[0]), len(encs[1]), len(encs[2]) + nomacTagStubSize}
	width, height := containerSize3_512Cfg(cfg, noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3, cobsLens)
	totalPixels := width * height
	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third

	caps := [3]int{
		(third * DataBitsPerPixel) / 8,
		(third * DataBitsPerPixel) / 8,
		(thirdPixels2 * DataBitsPerPixel) / 8,
	}
	fitLimits := [3]int{caps[0], caps[1], caps[2] - nomacTagStubSize}
	for i := 0; i < 3; i++ {
		if len(encs[i])+1 > fitLimits[i] {
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

	// 3 parallel goroutines for pixel processing, each limited to 1/3 of CPU cores
	offset1 := third * Channels
	offset2 := 2 * third * Channels
	perThird := runtime.NumCPU() / 3
	if perThird < 1 {
		perThird = 1
	}
	wg.Add(3)
	go func() {
		process512Cfg(cfg, noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, payloads[0], true, perThird)
		wg.Done()
	}()
	go func() {
		process512Cfg(cfg, noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, payloads[1], true, perThird)
		wg.Done()
	}()
	go func() {
		process512Cfg(cfg, noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, payloads[2], true, perThird)
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

// Decrypt3x512Cfg is the inverse of [Encrypt3x512Cfg]. nil cfg falls
// back to the compile-in defaults.
func Decrypt3x512Cfg(cfg *Config, noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 *Seed512, fileData []byte) ([]byte, error) {
	if err := checkEightSeeds512(noiseSeed, lockSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3); err != nil {
		return nil, err
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
		process512Cfg(cfg, noiseSeed, dataSeed1, startSeed1, nonce, container[0:offset1], third, 1, decoded[0], false, perThird)
		wg.Done()
	}()
	go func() {
		process512Cfg(cfg, noiseSeed, dataSeed2, startSeed2, nonce, container[offset1:offset2], third, 1, decoded[1], false, perThird)
		wg.Done()
	}()
	go func() {
		process512Cfg(cfg, noiseSeed, dataSeed3, startSeed3, nonce, container[offset2:totalPixels*Channels], thirdPixels2, 1, decoded[2], false, perThird)
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

	return interleaveForTriple48LockedCfg(cfg, parts[0], parts[1], parts[2], buildLockBatchPRF48_512Cfg(cfg, lockSeed, nonce)), nil
}
