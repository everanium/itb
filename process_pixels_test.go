//go:build cgo

package itb

import (
	"bytes"
	"math/rand"
	"testing"
)

// refPixelsScalar is a scalar Go reference model of the C pixel kernel
// (itb_process_pixels) operating on pre-computed hash arrays. It mirrors
// the serial per-pixel loop of the pure-Go backend (process_generic.go)
// with hashing factored out, providing a path-independent ground truth
// against which every batched C path — Tier A 8-pixel, Tier B 4-pixel,
// plain-C 4-pixel, scalar tail, and both the consecutive fast path and
// the wrap-crossing slow path within the batched helpers — must agree
// byte-for-byte.
//
// noiseHashes / dataHashes are indexed by absolute pixel index p in
// [0, len(noiseHashes)); the walk always starts at startP = 0.
func refPixelsScalar(noiseHashes, dataHashes []uint64, container, data []byte, startPixel, totalPixels, totalBits int, encode bool) {
	bitIndex := 0
	for p := 0; p < len(noiseHashes) && bitIndex < totalBits; p++ {
		linearIdx := (startPixel + p) % totalPixels
		pixelOffset := linearIdx * Channels

		noiseHash := noiseHashes[p]
		dataHash := dataHashes[p]

		noisePos := uint(noiseHash & 7)
		noiseMask := byte(1 << noisePos)

		dataRotation := uint(dataHash % 7)
		xorMask := dataHash >> DataRotationBits

		if encode {
			for ch := 0; ch < Channels && bitIndex < totalBits; ch++ {
				channelXOR := byte((xorMask >> uint(ch*DataBitsPerChannel)) & 0x7F)

				byteIdx := bitIndex / 8
				bitOff := uint(bitIndex % 8)

				raw := uint16(data[byteIdx])
				if byteIdx+1 < len(data) {
					raw |= uint16(data[byteIdx+1]) << 8
				}
				dataBits := byte((raw >> bitOff) & 0x7F)

				dataBits ^= channelXOR
				dataBits = rotateBits7(dataBits, dataRotation)

				orig := container[pixelOffset+ch]
				low := dataBits & (noiseMask - 1)
				high := dataBits >> noisePos
				container[pixelOffset+ch] = low | (orig & noiseMask) | (high << (noisePos + 1))

				bitIndex += DataBitsPerChannel
				if bitIndex > totalBits {
					bitIndex = totalBits
				}
			}
		} else {
			var packed uint64
			chCount := Channels
			if bitsLeft := totalBits - bitIndex; bitsLeft < DataBitsPerPixel {
				chCount = (bitsLeft + DataBitsPerChannel - 1) / DataBitsPerChannel
			}

			for ch := 0; ch < chCount; ch++ {
				channelXOR := byte((xorMask >> uint(ch*DataBitsPerChannel)) & 0x7F)

				channelByte := container[pixelOffset+ch]
				low := channelByte & (noiseMask - 1)
				high := channelByte >> (noisePos + 1)
				dataBits := low | (high << noisePos)

				dataBits = rotateBits7(dataBits, 7-dataRotation)
				dataBits ^= channelXOR

				packed |= uint64(dataBits) << uint(ch*DataBitsPerChannel)
			}

			byteStart := bitIndex / 8
			bytesToWrite := (chCount*DataBitsPerChannel + 7) / 8
			for i := 0; i < bytesToWrite && byteStart+i < len(data); i++ {
				data[byteStart+i] = byte(packed >> uint(i*8))
			}

			bitIndex += chCount * DataBitsPerChannel
		}
	}
}

// TestProcessPixelsWrapBoundary drives the batched C pixel kernel across
// container geometries where pixel batches straddle the totalPixels wrap
// boundary. The startPixel sweep places the wrap at every lane offset
// within an 8-pixel (Tier A) and 4-pixel (Tier B / plain-C) batch —
// startPixel = totalPixels - k for k in 1..12 makes the first batch wrap
// with minimal excess k — alongside no-wrap (startPixel = 0) and
// mid-container controls where every batch is consecutive.
//
// Three encode paths and three decode paths are compared byte-for-byte
// on identical inputs:
//
//  1. the scalar Go reference model (refPixelsScalar),
//  2. one whole-range C call (batched kernels fire, mixing the
//     consecutive fast path with the wrap-crossing slow path at the
//     boundary batch),
//  3. per-pixel C calls (startP = k, endP = k+1 — only the scalar tail
//     fires, no batched path).
//
// Any divergence between the consecutive fast path and the wrap-handling
// arithmetic surfaces as a mismatch between (2) and the other two.
// Round-trip equality (decode(encode(plain)) == plain) is asserted on
// top. Geometry mirrors production callers: dataLen = totalPixels * 7,
// totalBits = dataLen * 8, dataPixels = totalPixels.
func TestProcessPixelsWrapBoundary(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1b48))

	for _, totalPixels := range []int{96, 41, 20, 11} {
		dataLen := totalPixels * (DataBitsPerPixel / 8)
		totalBits := dataLen * 8

		starts := []int{0, totalPixels / 2}
		for k := 1; k <= 12 && k < totalPixels; k++ {
			starts = append(starts, totalPixels-k)
		}

		for _, startPixel := range starts {
			noiseHashes := make([]uint64, totalPixels)
			dataHashes := make([]uint64, totalPixels)
			for i := range noiseHashes {
				noiseHashes[i] = rng.Uint64()
				dataHashes[i] = rng.Uint64()
			}
			baseContainer := make([]byte, totalPixels*Channels)
			rng.Read(baseContainer)
			plain := make([]byte, dataLen)
			rng.Read(plain)

			// Encode: reference model.
			refCont := append([]byte(nil), baseContainer...)
			refPixelsScalar(noiseHashes, dataHashes, refCont, plain, startPixel, totalPixels, totalBits, true)

			// Encode: whole-range C call (batched paths, fast + slow mix).
			cCont := append([]byte(nil), baseContainer...)
			callC(noiseHashes, dataHashes, cCont, plain, startPixel, totalPixels, 0, totalPixels, totalBits, true)
			if !bytes.Equal(cCont, refCont) {
				t.Fatalf("encode mismatch (batched C vs reference): totalPixels=%d startPixel=%d", totalPixels, startPixel)
			}

			// Encode: per-pixel C calls (scalar tail only).
			pCont := append([]byte(nil), baseContainer...)
			for k := 0; k < totalPixels; k++ {
				callC(noiseHashes[k:k+1], dataHashes[k:k+1], pCont, plain, startPixel, totalPixels, k, k+1, totalBits, true)
			}
			if !bytes.Equal(pCont, refCont) {
				t.Fatalf("encode mismatch (per-pixel C vs reference): totalPixels=%d startPixel=%d", totalPixels, startPixel)
			}

			// Decode: reference model from the encoded container.
			refData := make([]byte, dataLen)
			refPixelsScalar(noiseHashes, dataHashes, cCont, refData, startPixel, totalPixels, totalBits, false)

			// Decode: whole-range C call.
			cData := make([]byte, dataLen)
			callC(noiseHashes, dataHashes, cCont, cData, startPixel, totalPixels, 0, totalPixels, totalBits, false)
			if !bytes.Equal(cData, refData) {
				t.Fatalf("decode mismatch (batched C vs reference): totalPixels=%d startPixel=%d", totalPixels, startPixel)
			}

			// Decode: per-pixel C calls.
			pData := make([]byte, dataLen)
			for k := 0; k < totalPixels; k++ {
				callC(noiseHashes[k:k+1], dataHashes[k:k+1], cCont, pData, startPixel, totalPixels, k, k+1, totalBits, false)
			}
			if !bytes.Equal(pData, refData) {
				t.Fatalf("decode mismatch (per-pixel C vs reference): totalPixels=%d startPixel=%d", totalPixels, startPixel)
			}

			// Round trip: the decoded stream must equal the original data.
			if !bytes.Equal(cData, plain) {
				t.Fatalf("round-trip mismatch: totalPixels=%d startPixel=%d", totalPixels, startPixel)
			}
		}
	}
}
