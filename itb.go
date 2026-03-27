package itb

import (
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

// splitTriple splits data into 3 parts: bytes[0::3], bytes[1::3], bytes[2::3].
func splitTriple(data []byte) (p0, p1, p2 []byte) {
	n := len(data)
	s0 := (n + 2) / 3
	s1 := (n + 1) / 3
	s2 := n / 3
	p0 = make([]byte, s0)
	p1 = make([]byte, s1)
	p2 = make([]byte, s2)
	for i, b := range data {
		switch i % 3 {
		case 0:
			p0[i/3] = b
		case 1:
			p1[i/3] = b
		case 2:
			p2[i/3] = b
		}
	}
	return
}

// interleaveTriple reassembles 3 parts into original byte order.
func interleaveTriple(p0, p1, p2 []byte) []byte {
	total := len(p0) + len(p1) + len(p2)
	result := make([]byte, total)
	for i := 0; i < len(p0); i++ {
		idx := i * 3
		if idx < total {
			result[idx] = p0[i]
		}
	}
	for i := 0; i < len(p1); i++ {
		idx := i*3 + 1
		if idx < total {
			result[idx] = p1[i]
		}
	}
	for i := 0; i < len(p2); i++ {
		idx := i*3 + 2
		if idx < total {
			result[idx] = p2[i]
		}
	}
	return result
}

// splitTripleBits splits data into 3 parts at the bit level: bits[0::3], bits[1::3], bits[2::3].
// Each part is packed into bytes. Returns parts and totalBits for reassembly.
func splitTripleBits(data []byte) (p0, p1, p2 []byte, totalBits int) {
	totalBits = len(data) * 8
	n0 := (totalBits + 2) / 3
	n1 := (totalBits + 1) / 3
	n2 := totalBits / 3
	p0 = make([]byte, (n0+7)/8)
	p1 = make([]byte, (n1+7)/8)
	p2 = make([]byte, (n2+7)/8)

	for i := 0; i < totalBits; i++ {
		srcByte := i / 8
		srcBit := uint(i % 8)
		bit := (data[srcByte] >> srcBit) & 1

		part := i % 3
		idx := i / 3
		dstByte := idx / 8
		dstBit := uint(idx % 8)

		switch part {
		case 0:
			p0[dstByte] |= bit << dstBit
		case 1:
			p1[dstByte] |= bit << dstBit
		case 2:
			p2[dstByte] |= bit << dstBit
		}
	}
	return
}

// interleaveTripleBits reassembles 3 bit-level parts into original data.
func interleaveTripleBits(p0, p1, p2 []byte, totalBits int) []byte {
	result := make([]byte, (totalBits+7)/8)

	for i := 0; i < totalBits; i++ {
		part := i % 3
		idx := i / 3
		srcByte := idx / 8
		srcBit := uint(idx % 8)

		var bit byte
		switch part {
		case 0:
			bit = (p0[srcByte] >> srcBit) & 1
		case 1:
			bit = (p1[srcByte] >> srcBit) & 1
		case 2:
			bit = (p2[srcByte] >> srcBit) & 1
		}

		dstByte := i / 8
		dstBit := uint(i % 8)
		result[dstByte] |= bit << dstBit
	}
	return result
}

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
