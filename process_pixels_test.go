//go:build cgo

package itb

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

// TestProcessPixelsScratchReuseAndSubranges exercises itb_process_pixels
// across batch-width transitions (8-pixel batch, 4-pixel leftover batch,
// and 1..3-pixel scalar tail), worker sub-range splits, and wrap-crossing
// startPixel offsets, verifying byte-for-byte parity with refPixelsScalar
// on both encode and decode.
func TestProcessPixelsScratchReuseAndSubranges(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5eedc0de))

	for _, totalPixels := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 15, 16, 17, 23, 31, 32, 33, 41, 64} {
		dataPixelCounts := []int{totalPixels}
		if totalPixels > 1 {
			dataPixelCounts = append(dataPixelCounts, totalPixels-1)
		}
		if totalPixels > 4 {
			dataPixelCounts = append(dataPixelCounts, totalPixels/2)
		}

		for _, dataPixels := range dataPixelCounts {
			dataLen := dataPixels * (DataBitsPerPixel / 8)
			totalBits := dataLen * 8

			starts := []int{0}
			if totalPixels > 1 {
				starts = append(starts, totalPixels/2, totalPixels-1)
			}
			if totalPixels > 5 {
				starts = append(starts, totalPixels-3, totalPixels-5)
			}
			if totalPixels > 9 {
				starts = append(starts, totalPixels-7, totalPixels-9)
			}

			for _, startPixel := range starts {
				noiseHashes := make([]uint64, dataPixels)
				dataHashes := make([]uint64, dataPixels)
				for i := range noiseHashes {
					noiseHashes[i] = rng.Uint64()
					dataHashes[i] = rng.Uint64()
				}
				baseContainer := make([]byte, totalPixels*Channels)
				rng.Read(baseContainer)
				plain := make([]byte, dataLen)
				rng.Read(plain)

				refCont := append([]byte(nil), baseContainer...)
				refPixelsScalar(noiseHashes, dataHashes, refCont, plain, startPixel, totalPixels, totalBits, true)

				cCont := append([]byte(nil), baseContainer...)
				callC(noiseHashes, dataHashes, cCont, plain, startPixel, totalPixels, 0, dataPixels, totalBits, true)
				if !bytes.Equal(cCont, refCont) {
					t.Fatalf("encode mismatch: totalPixels=%d dataPixels=%d startPixel=%d", totalPixels, dataPixels, startPixel)
				}

				if dataPixels >= 3 {
					split := dataPixels / 2
					sCont := append([]byte(nil), baseContainer...)
					callC(noiseHashes[:split], dataHashes[:split], sCont, plain, startPixel, totalPixels, 0, split, totalBits, true)
					callC(noiseHashes[split:], dataHashes[split:], sCont, plain, startPixel, totalPixels, split, dataPixels, totalBits, true)
					if !bytes.Equal(sCont, refCont) {
						t.Fatalf("split encode mismatch: totalPixels=%d dataPixels=%d startPixel=%d", totalPixels, dataPixels, startPixel)
					}
				}

				refData := make([]byte, dataLen)
				refPixelsScalar(noiseHashes, dataHashes, cCont, refData, startPixel, totalPixels, totalBits, false)

				cData := make([]byte, dataLen)
				callC(noiseHashes, dataHashes, cCont, cData, startPixel, totalPixels, 0, dataPixels, totalBits, false)
				if !bytes.Equal(cData, refData) {
					t.Fatalf("decode mismatch: totalPixels=%d dataPixels=%d startPixel=%d", totalPixels, dataPixels, startPixel)
				}
				if !bytes.Equal(cData, plain) {
					t.Fatalf("round-trip mismatch: totalPixels=%d dataPixels=%d startPixel=%d", totalPixels, dataPixels, startPixel)
				}
			}
		}
	}
}

const cStackProbeWords = 512
const cStackSentinel = uint64(0x5A5A5A5A5A5A5A5A)

// TestProcessPixelsCStackZeroization verifies that itb_process_pixels leaves
// zero secret residue (dataHashes, xorMask, per-channel xors/vals, and
// extracted/packed plaintext words) on the C stack across every forced SIMD
// tier (AUTO, A, A_NOGFNI, B, B_NOGFNI, C), both directions (encode and
// decode), and both consecutive and wrap-crossing container geometries.
//
// Negative controls verify:
//  1. mode=1 (skipping both sc wipe and itb_wipe_c_stack) deterministically
//     leaves secret words on the C stack for every (tier, encode, wrap) cell.
//  2. mode=2 (wiping sc only, skipping itb_wipe_c_stack) catches compiler
//     stack spills outside sc on the C stack.
func TestProcessPixelsCStackZeroization(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC57AC01))

	const (
		nPixels     = 13 // 8 + 4 + 1 exercises 8-pixel ZMM, 4-pixel YMM/C, and 1-pixel tail (avail = 7 < 8)
		totalPixels = 16
		dataLen     = nPixels * (DataBitsPerPixel / 8)
		totalBits   = dataLen * 8
	)

	noiseHashes := make([]uint64, nPixels)
	dataHashes := make([]uint64, nPixels)
	for i := 0; i < nPixels; i++ {
		noiseHashes[i] = rng.Uint64() | 1
		dataHashes[i] = rng.Uint64() | 1
	}

	plain := make([]byte, dataLen)
	for i := range plain {
		plain[i] = byte(rng.Intn(254) + 1)
	}

	secrets := make(map[uint64]string)
	for p := 0; p < nPixels; p++ {
		dh := dataHashes[p]
		xm := dh >> DataRotationBits
		dr := uint(dh % 7)
		secrets[dh] = fmt.Sprintf("dataHashes[%d]", p)
		secrets[xm] = fmt.Sprintf("xorMask[%d]", p)

		var xorsQ, valsRawQ, valsXorQ, valsRotQ uint64
		bitBase := p * DataBitsPerPixel
		for ch := 0; ch < Channels; ch++ {
			xb := byte((xm >> uint(ch*DataBitsPerChannel)) & 0x7F)
			xorsQ |= uint64(xb) << uint(ch*8)

			bIdx := (bitBase + ch*DataBitsPerChannel) / 8
			bOff := uint((bitBase + ch*DataBitsPerChannel) % 8)
			raw16 := uint16(plain[bIdx])
			if bIdx+1 < len(plain) {
				raw16 |= uint16(plain[bIdx+1]) << 8
			}
			vb := byte((raw16 >> bOff) & 0x7F)
			valsRawQ |= uint64(vb) << uint(ch*8)

			vx := vb ^ xb
			valsXorQ |= uint64(vx) << uint(ch*8)

			vr := rotateBits7(vx, dr)
			valsRotQ |= uint64(vr) << uint(ch*8)
		}
		secrets[xorsQ] = fmt.Sprintf("xors[%d]", p)
		secrets[valsRawQ] = fmt.Sprintf("valsRaw[%d]", p)
		secrets[valsXorQ] = fmt.Sprintf("valsXor[%d]", p)
		secrets[valsRotQ] = fmt.Sprintf("valsRot[%d]", p)
	}
	for off := 0; off+8 <= len(plain); off++ {
		w := binary.LittleEndian.Uint64(plain[off : off+8])
		if w != 0 && w != cStackSentinel {
			secrets[w] = fmt.Sprintf("plain64[off=%d]", off)
		}
	}
	// Tail 7-byte partial word at pixel 12 (byteIdx = 84, avail = 7).
	{
		var tailRaw uint64
		for i := 0; i < 7; i++ {
			tailRaw |= uint64(plain[84+i]) << uint(i*8)
		}
		secrets[tailRaw] = "plainTail56[pixel=12]"
	}

	tiers := []struct {
		id   int
		name string
	}{
		{0, "AUTO"},
		{1, "A"},
		{2, "A_NOGFNI"},
		{3, "B"},
		{4, "B_NOGFNI"},
		{5, "C"},
	}

	startPixels := []struct {
		sp   int
		name string
	}{
		{0, "consecutive"},
		{totalPixels - 3, "wrap"},
	}

	spillHitsMode2 := 0
	win := make([]uint64, cStackProbeWords)

	for _, tr := range tiers {
		for _, sp := range startPixels {
			baseCont := make([]byte, totalPixels*Channels)
			rng.Read(baseCont)

			// Pre-encode a reference container for the decode tests.
			encodedCont := append([]byte(nil), baseCont...)
			refPixelsScalar(noiseHashes, dataHashes, encodedCont, plain, sp.sp, totalPixels, totalBits, true)

			for _, encode := range []bool{true, false} {
				dir := "decode"
				if encode {
					dir = "encode"
				}
				caseName := fmt.Sprintf("tier=%s/%s/%s", tr.name, sp.name, dir)

				runProbe := func(mode int) []uint64 {
					for i := range win {
						win[i] = 0
					}
					if encode {
						cont := append([]byte(nil), baseCont...)
						inData := append([]byte(nil), plain...)
						probePixelsCStack(noiseHashes, dataHashes, cont, inData, sp.sp, totalPixels, 0, nPixels, totalBits, true, mode, tr.id, win)
					} else {
						cont := append([]byte(nil), encodedCont...)
						outData := make([]byte, dataLen)
						probePixelsCStack(noiseHashes, dataHashes, cont, outData, sp.sp, totalPixels, 0, nPixels, totalBits, false, mode, tr.id, win)
						if !bytes.Equal(outData, plain) {
							t.Fatalf("%s (mode=%d): decode output mismatch", caseName, mode)
						}
					}
					return win
				}

				// Negative control 1 (mode=1): no sc wipe, no C-stack wipe.
				resNeg := runProbe(1)
				negHits := 0
				for _, w := range resNeg {
					if _, ok := secrets[w]; ok {
						negHits++
					}
				}
				if negHits == 0 {
					t.Fatalf("%s: negative control (mode=1) failed to detect unwiped secrets on C stack", caseName)
				}

				// Negative control 2 (mode=2): sc wiped, C-stack spill wipe skipped.
				resSpill := runProbe(2)
				for _, w := range resSpill {
					if _, ok := secrets[w]; ok {
						spillHitsMode2++
					}
				}

				// Positive assertion (mode=0): full itb_process_pixels.
				resPos := runProbe(0)
				written := 0
				for i, w := range resPos {
					if w != cStackSentinel {
						written++
					}
					if what, ok := secrets[w]; ok {
						t.Errorf("%s: secret %s (0x%016x) left on C stack at word %d", caseName, what, w, i)
					}
				}
				if written == 0 {
					t.Fatalf("%s: C stack probe window did not overlap active frame", caseName)
				}
			}
		}
	}

	if spillHitsMode2 == 0 {
		t.Logf("note: mode=2 had 0 spill hits outside sc on this compiler/target")
	}
}
