package itb

import (
	"fmt"
	"runtime"
)

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

// minPixelsDivisor7 is the scaled integer divisor for
// ceil(keyBits / log2(7)) — the CCA-resistant container floor used by
// both plain and MAC-authenticated modes since the small-message
// envelope was unified across the two. log2(7) ≈ 2.8074, scaled by
// 10000 for integer arithmetic.
const (
	minPixelsDivisor7 = 28074 // log2(7) * 10000, rounded up
	minPixelsScale    = 10000
)

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

// maxDataSize is the maximum plaintext size for a Single Message or chunk (64 MB).
// This limit prevents uint32 pixel-index overflow in blockHash (counter is uint32)
// and aligns with the maximum streaming chunk size.
const maxDataSize = 64 << 20

// maxTotalPixels is the maximum container pixel count for decrypt validation.
// Covers maxDataSize + COBS overhead + square rounding (~9.6M pixels for 64 MB).
// Well below uint32 max (4.3B) with 429× headroom.
const maxTotalPixels = 10_000_000

// effectiveWorkersCfg is the per-instance worker-count resolver.
// Consults cfg.MaxWorkers when cfg is non-nil and the field carries a
// non-zero value; otherwise falls back to runtime.NumCPU. Values above
// 256 are clamped. A per-instance cap of 1 forces the serial path in
// [process128Cfg] / [process256Cfg] / [process512Cfg].
//
// nil cfg is permitted — every Cfg-suffixed entry point accepts nil
// and resolves to the runtime.NumCPU fallback via this path.
func effectiveWorkersCfg(cfg *Config, dataPixels int) int {
	if dataPixels < minParallelPixels {
		return 1
	}
	limit := 0
	if cfg != nil && cfg.MaxWorkers > 0 {
		limit = cfg.MaxWorkers
		if limit > 256 {
			limit = 256
		}
	}
	numWorkers := runtime.NumCPU()
	if limit > 0 && numWorkers > limit {
		numWorkers = limit
	}
	if numWorkers > dataPixels/64 {
		numWorkers = dataPixels / 64
	}
	if numWorkers < 1 {
		numWorkers = 1
	}
	return numWorkers
}

// headerSizeCfg returns the container header size for the given cfg:
// main nonce + interlock nonce + width(2) + height(2). Both nonces are
// symmetric in width. Consults [currentNonceSizeCfg] so a non-nil cfg
// with an explicit NonceBits override is honoured at the header-layout
// site.
func headerSizeCfg(cfg *Config) int { return 2*currentNonceSizeCfg(cfg) + 4 }

// calcContainerSize3Cfg computes square container dimensions for
// Triple Ouroboros. Each third must hold its part's COBS data and
// satisfy MinPixels independently. Consults [currentBarrierFillCfg]
// for the CSPRNG barrier margin.
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

// errSeedWidthMix is returned by the width-less streaming Cfg
// dispatchers when the supplied seeds do not share a single concrete
// width. Mixing a *Seed128 with a *Seed256 cannot be resolved to one of
// the width-suffixed implementations, so the helper rejects the call
// rather than guessing a width.
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

// dispatchWidthTriple confirms that all eight Triple-Ouroboros seeds
// (noise, lock, three data, three start) share one concrete pointer type
// and returns the resolved width. Returns 0 + errSeedWidthMix on any
// type mismatch or an unsupported pointer type.
func dispatchWidthTriple(noise, lock, data1, data2, data3, start1, start2, start3 any) (int, error) {
	w := seedWidth(noise)
	if w == 0 {
		return 0, errSeedWidthMix
	}
	if seedWidth(lock) != w {
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
