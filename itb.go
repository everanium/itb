package itb

import (
	"fmt"
	"runtime"
	"sync/atomic"
)

// headerSize returns the container header size: nonce + width(2) + height(2).
func headerSize() int { return currentNonceSize() + 4 }

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

// minPixelsDivisor56 and minPixelsDivisor7 are scaled integer divisors for
// ceil(keyBits / log2(56)) and ceil(keyBits / log2(7)) respectively.
// log2(56) ≈ 5.8074, log2(7) ≈ 2.8074. Scaled by 10000 for integer arithmetic.
const (
	minPixelsDivisor56 = 58074 // log2(56) * 10000, rounded up
	minPixelsDivisor7  = 28074 // log2(7) * 10000, rounded up
	minPixelsScale     = 10000
)

// calcContainerSize computes square container dimensions from payload and minimum pixel counts.
func calcContainerSize(payloadCOBSLen, minPxNoise, minPxData, minPxStart int) (width, height int) {
	needed := payloadCOBSLen + 1 // +1 for null terminator
	pixels := (needed*8 + DataBitsPerPixel - 1) / DataBitsPerPixel

	minPx := minPxNoise
	if minPxData > minPx {
		minPx = minPxData
	}
	if minPxStart > minPx {
		minPx = minPxStart
	}
	if pixels < minPx {
		pixels = minPx
	}

	side := 1
	for side*side < pixels {
		side++
	}
	side += currentBarrierFill() // guaranteed CSPRNG fill (Proof 10)
	return side, side
}

// minParallelPixels is the threshold for parallel processing.
// Below this, goroutine overhead exceeds the benefit.
const minParallelPixels = 256

// rotateBits7 rotates a 7-bit value left by r positions.
// Uses register-only operations (no memory access) to avoid
// cache timing side-channels in SEV/SGX/TDX environments.
func rotateBits7(v byte, r uint) byte {
	r = r % 7
	return ((v << r) | (v >> (7 - r))) & 0x7F
}

// maxDataSize is the maximum plaintext size for a single message or chunk (64 MB).
// This limit prevents uint32 pixel-index overflow in blockHash (counter is uint32)
// and aligns with the maximum streaming chunk size.
const maxDataSize = 64 << 20

// calcContainerSize3 computes square container dimensions for Triple Ouroboros.
// Each third must hold its part's COBS data and satisfy MinPixels independently.
func calcContainerSize3(cobsLens [3]int, minPxNoise int, minPxData [3]int, minPxStart [3]int) (width, height int) {
	maxThirdPixels := 0
	for i := 0; i < 3; i++ {
		needed := cobsLens[i] + 1 // +1 for null terminator
		pixels := (needed*8 + DataBitsPerPixel - 1) / DataBitsPerPixel

		minPx := minPxNoise
		if minPxData[i] > minPx {
			minPx = minPxData[i]
		}
		if minPxStart[i] > minPx {
			minPx = minPxStart[i]
		}
		if pixels < minPx {
			pixels = minPx
		}
		if pixels > maxThirdPixels {
			maxThirdPixels = pixels
		}
	}

	totalPixels := 3 * maxThirdPixels

	side := 1
	for side*side < totalPixels {
		side++
	}
	side += currentBarrierFill()
	return side, side
}

// maxTotalPixels is the maximum container pixel count for decrypt validation.
// Covers maxDataSize + COBS overhead + square rounding (~9.6M pixels for 64 MB).
// Well below uint32 max (4.3B) with 429× headroom.
const maxTotalPixels = 10_000_000

// maxWorkers controls the maximum number of parallel workers for pixel processing.
// 0 means use runtime.NumCPU() (default). Valid range: 1-256.
var maxWorkers atomic.Int32

// SetMaxWorkers sets the maximum number of parallel workers for pixel processing.
// Pass 0 to use all available CPUs (default). Valid range: 0 to 256.
// Values above 256 are clamped. Negative values are treated as 0 (all CPUs).
// This affects all subsequent Encrypt/Decrypt calls across all hash widths.
func SetMaxWorkers(n int) {
	if n < 0 {
		n = 0
	}
	if n > 256 {
		n = 256
	}
	maxWorkers.Store(int32(n))
}

// GetMaxWorkers returns the current maximum worker limit.
// Returns 0 if no limit is set (default: uses all available CPUs).
func GetMaxWorkers() int {
	return int(maxWorkers.Load())
}

// effectiveWorkers returns the number of workers to use for parallel processing.
func effectiveWorkers(dataPixels int) int {
	if dataPixels < minParallelPixels {
		return 1
	}
	numWorkers := runtime.NumCPU()
	if limit := int(maxWorkers.Load()); limit > 0 {
		if numWorkers > limit {
			numWorkers = limit
		}
	}
	if numWorkers > dataPixels/64 {
		numWorkers = dataPixels / 64
	}
	if numWorkers < 1 {
		numWorkers = 1
	}
	return numWorkers
}

// headerSizeCfg is the Cfg variant of [headerSize]: consults
// [currentNonceSizeCfg] so a non-nil cfg with an explicit NonceBits
// override is honoured at the header-layout site.
func headerSizeCfg(cfg *Config) int { return currentNonceSizeCfg(cfg) + 4 }

// calcContainerSizeCfg is the Cfg variant of [calcContainerSize]:
// consults [currentBarrierFillCfg] for the CSPRNG barrier margin so
// a non-nil cfg with an explicit BarrierFill override is honoured at
// the container-sizing site. Body otherwise identical.
func calcContainerSizeCfg(cfg *Config, payloadCOBSLen, minPxNoise, minPxData, minPxStart int) (width, height int) {
	needed := payloadCOBSLen + 1 // +1 for null terminator
	pixels := (needed*8 + DataBitsPerPixel - 1) / DataBitsPerPixel

	minPx := minPxNoise
	if minPxData > minPx {
		minPx = minPxData
	}
	if minPxStart > minPx {
		minPx = minPxStart
	}
	if pixels < minPx {
		pixels = minPx
	}

	side := 1
	for side*side < pixels {
		side++
	}
	side += currentBarrierFillCfg(cfg)
	return side, side
}

// calcContainerSize3Cfg is the Cfg variant of [calcContainerSize3]:
// consults [currentBarrierFillCfg] for the CSPRNG barrier margin.
// Body otherwise identical.
func calcContainerSize3Cfg(cfg *Config, cobsLens [3]int, minPxNoise int, minPxData [3]int, minPxStart [3]int) (width, height int) {
	maxThirdPixels := 0
	for i := 0; i < 3; i++ {
		needed := cobsLens[i] + 1 // +1 for null terminator
		pixels := (needed*8 + DataBitsPerPixel - 1) / DataBitsPerPixel

		minPx := minPxNoise
		if minPxData[i] > minPx {
			minPx = minPxData[i]
		}
		if minPxStart[i] > minPx {
			minPx = minPxStart[i]
		}
		if pixels < minPx {
			pixels = minPx
		}
		if pixels > maxThirdPixels {
			maxThirdPixels = pixels
		}
	}

	totalPixels := 3 * maxThirdPixels

	side := 1
	for side*side < totalPixels {
		side++
	}
	side += currentBarrierFillCfg(cfg)
	return side, side
}

// errSeedWidthMix is returned by the width-less Encrypt / Decrypt /
// Encrypt3x / Decrypt3x dispatchers (and their authenticated /
// streaming counterparts) when the supplied seeds do not share a
// single concrete width. Mixing a *Seed128 with a *Seed256 cannot be
// resolved to one of the width-suffixed implementations, so the
// helper rejects the call rather than guessing a width.
var errSeedWidthMix = fmt.Errorf("itb: seed width mix")

// seedWidth returns 128 / 256 / 512 for *Seed128 / *Seed256 / *Seed512
// inputs and 0 for any other type. The width-less dispatch helpers
// use it to confirm that every seed argument carries the same
// concrete pointer type before forwarding.
func seedWidth(s any) int {
	switch s.(type) {
	case *Seed128:
		return 128
	case *Seed256:
		return 256
	case *Seed512:
		return 512
	default:
		return 0
	}
}

// dispatchWidthSingle confirms that noise / data / start carry the
// same concrete *SeedN pointer type and returns the resolved width.
// Returns 0 + errSeedWidthMix on any type mismatch or an unsupported
// pointer type.
func dispatchWidthSingle(noise, data, start any) (int, error) {
	w := seedWidth(noise)
	if w == 0 || seedWidth(data) != w || seedWidth(start) != w {
		return 0, errSeedWidthMix
	}
	return w, nil
}

// dispatchWidthTriple confirms that all seven Triple-Ouroboros seeds
// (noise, three data, three start) share one concrete pointer type
// and returns the resolved width. Same error semantics as
// [dispatchWidthSingle].
func dispatchWidthTriple(noise, data1, data2, data3, start1, start2, start3 any) (int, error) {
	w := seedWidth(noise)
	if w == 0 {
		return 0, errSeedWidthMix
	}
	if seedWidth(data1) != w || seedWidth(data2) != w || seedWidth(data3) != w {
		return 0, errSeedWidthMix
	}
	if seedWidth(start1) != w || seedWidth(start2) != w || seedWidth(start3) != w {
		return 0, errSeedWidthMix
	}
	return w, nil
}

// Encrypt is the width-less single-shot plain Encrypt entry point.
// Dispatches to [Encrypt128] / [Encrypt256] / [Encrypt512] based on
// the concrete pointer type of the supplied seeds. Every seed must
// carry the same concrete *SeedN type; mixing widths returns an
// itb-wrapped error matching the existing low-level error shape.
//
// Accepts seeds typed as any (interface{}) so a single signature
// covers all three primitive widths. The internal type-switch
// resolves the width once and forwards verbatim — the helper is
// allocation-free beyond the dispatch overhead and the underlying
// width-suffixed call's return slice.
func Encrypt(noiseSeed, dataSeed, startSeed any, data []byte) ([]byte, error) {
	w, err := dispatchWidthSingle(noiseSeed, dataSeed, startSeed)
	if err != nil {
		return nil, err
	}
	switch w {
	case 128:
		return Encrypt128(noiseSeed.(*Seed128), dataSeed.(*Seed128), startSeed.(*Seed128), data)
	case 256:
		return Encrypt256(noiseSeed.(*Seed256), dataSeed.(*Seed256), startSeed.(*Seed256), data)
	case 512:
		return Encrypt512(noiseSeed.(*Seed512), dataSeed.(*Seed512), startSeed.(*Seed512), data)
	}
	return nil, errSeedWidthMix
}

// Decrypt is the width-less single-shot plain Decrypt entry point.
// Mirrors [Encrypt]; dispatches to [Decrypt128] / [Decrypt256] /
// [Decrypt512].
func Decrypt(noiseSeed, dataSeed, startSeed any, fileData []byte) ([]byte, error) {
	w, err := dispatchWidthSingle(noiseSeed, dataSeed, startSeed)
	if err != nil {
		return nil, err
	}
	switch w {
	case 128:
		return Decrypt128(noiseSeed.(*Seed128), dataSeed.(*Seed128), startSeed.(*Seed128), fileData)
	case 256:
		return Decrypt256(noiseSeed.(*Seed256), dataSeed.(*Seed256), startSeed.(*Seed256), fileData)
	case 512:
		return Decrypt512(noiseSeed.(*Seed512), dataSeed.(*Seed512), startSeed.(*Seed512), fileData)
	}
	return nil, errSeedWidthMix
}

// Encrypt3x is the width-less single-shot Triple-Ouroboros Encrypt
// entry point. Dispatches to [Encrypt3x128] / [Encrypt3x256] /
// [Encrypt3x512] based on the concrete pointer type of the supplied
// seeds. All seven seeds must share one concrete *SeedN type; mixing
// widths returns an itb-wrapped error.
func Encrypt3x(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, data []byte) ([]byte, error) {
	w, err := dispatchWidthTriple(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3)
	if err != nil {
		return nil, err
	}
	switch w {
	case 128:
		return Encrypt3x128(noiseSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), data)
	case 256:
		return Encrypt3x256(noiseSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), data)
	case 512:
		return Encrypt3x512(noiseSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), data)
	}
	return nil, errSeedWidthMix
}

// Decrypt3x is the width-less single-shot Triple-Ouroboros Decrypt
// entry point. Mirrors [Encrypt3x]; dispatches to [Decrypt3x128] /
// [Decrypt3x256] / [Decrypt3x512].
func Decrypt3x(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3 any, fileData []byte) ([]byte, error) {
	w, err := dispatchWidthTriple(noiseSeed, dataSeed1, dataSeed2, dataSeed3, startSeed1, startSeed2, startSeed3)
	if err != nil {
		return nil, err
	}
	switch w {
	case 128:
		return Decrypt3x128(noiseSeed.(*Seed128), dataSeed1.(*Seed128), dataSeed2.(*Seed128), dataSeed3.(*Seed128), startSeed1.(*Seed128), startSeed2.(*Seed128), startSeed3.(*Seed128), fileData)
	case 256:
		return Decrypt3x256(noiseSeed.(*Seed256), dataSeed1.(*Seed256), dataSeed2.(*Seed256), dataSeed3.(*Seed256), startSeed1.(*Seed256), startSeed2.(*Seed256), startSeed3.(*Seed256), fileData)
	case 512:
		return Decrypt3x512(noiseSeed.(*Seed512), dataSeed1.(*Seed512), dataSeed2.(*Seed512), dataSeed3.(*Seed512), startSeed1.(*Seed512), startSeed2.(*Seed512), startSeed3.(*Seed512), fileData)
	}
	return nil, errSeedWidthMix
}
