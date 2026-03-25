package itb

import (
	"runtime"
	"sync/atomic"
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

// maxTotalPixels is the maximum container pixel count for decrypt validation.
// Covers maxDataSize + COBS overhead + square rounding (~9.6M pixels for 64 MB).
// Well below uint32 max (4.3B) with 429× headroom.
const maxTotalPixels = 10_000_000

// maxWorkers controls the maximum number of parallel workers for pixel processing.
// 0 means use runtime.NumCPU() (default). Valid range: 1-256.
var maxWorkers atomic.Int32

// SetMaxWorkers sets the maximum number of parallel workers for pixel processing.
// Valid range: 1 to 256. Values outside this range are clamped.
// This affects all subsequent Encrypt/Decrypt calls across all hash widths.
func SetMaxWorkers(n int) {
	if n < 1 {
		n = 1
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
