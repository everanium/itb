package itb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"runtime/debug"
	"strings"
	"testing"
	"unsafe"
)

const (
	pxResidueGap      = 1 << 10
	pxResiduePad      = 2 << 10
	pxResidueWindow   = 16 << 10
	pxResidueSentinel = 0x5A5A5A5A5A5A5A5A
)

func pxStackResidue(fn func()) []uint64 {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	res := make([]uint64, pxResidueWindow/8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pxResidueGrow(0)
		pxResidueProbe(fn, res)
	}()
	<-done
	return res
}

//go:noinline
func pxResidueGrow(i int) byte {
	var pad [4 * pxResidueWindow]byte
	pad[i] = 1
	return pad[(i+1)%len(pad)]
}

//go:noinline
func pxResidueProbe(fn func(), res []uint64) {
	var anchor uint64
	top := unsafe.Add(unsafe.Pointer(&anchor), -pxResidueGap)
	for i := range res {
		*(*uint64)(unsafe.Add(top, -8*(i+1))) = pxResidueSentinel
	}
	pxResidueDeep(fn, 0)
	for i := range res {
		res[i] = *(*uint64)(unsafe.Add(top, -8*(i+1)))
	}
}

//go:noinline
func pxResidueDeep(fn func(), i int) byte {
	var pad [pxResiduePad]byte
	pad[i] = 1
	fn()
	return pad[(i+7)%len(pad)]
}

var pxResidueSink uint64

//go:noinline
func simHash128Stack(r0, r1 uint64) (uint64, uint64) {
	var frame [32]uint64
	idx := int(r0&7) + 16
	frame[idx] = r0
	frame[idx+1] = r1
	return frame[idx], frame[idx+1]
}

//go:noinline
func simHash256Stack(r [4]uint64) [4]uint64 {
	var frame [32]uint64
	idx := int(r[0]&7) + 16
	copy(frame[idx:idx+4], r[:])
	var out [4]uint64
	copy(out[:], frame[idx:idx+4])
	return out
}

//go:noinline
func simHash512Stack(r [8]uint64) [8]uint64 {
	var frame [32]uint64
	idx := int(r[0]&7) + 16
	copy(frame[idx:idx+8], r[:])
	var out [8]uint64
	copy(out[:], frame[idx:idx+8])
	return out
}

// leakyChunkHashes128 is the negative control for the stack-residue
// probe on processChunk128: it runs blockHash128x8, blockHash128x4, and
// blockHash128 into local stack variables without clearing them or
// wiping the child call stack before return.
//
//go:noinline
func leakyChunkHashes128(cfg *Config, noiseSeed, dataSeed *Seed128, nonce []byte) {
	ls := newLaneScratch(nonce, currentNonceSizeCfg(cfg))
	defer ls.wipe()
	idx8 := [8]int{0, 1, 2, 3, 4, 5, 6, 7}
	noiseHs8 := noiseSeed.blockHash128x8(&ls.noise, noiseIdx8(idx8, 0))
	dataHs8 := dataSeed.blockHash128x8(&ls.data, idx8)
	idx4 := [4]int{8, 9, 10, 11}
	noiseHs4 := noiseSeed.blockHash128x4(&ls.noise4, noiseIdx4(idx4, 0))
	dataHs4 := dataSeed.blockHash128x4(&ls.data4, idx4)
	nLo, nHi := noiseSeed.blockHash128(ls.noise[0], 12)
	dLo, dHi := dataSeed.blockHash128(ls.data[0], 12)
	pxResidueSink = noiseHs8[0][1] ^ dataHs8[7][1] ^ noiseHs4[0][1] ^ dataHs4[3][1] ^ nLo ^ nHi ^ dLo ^ dHi
}

//go:noinline
func leakyChunkHashes256(cfg *Config, noiseSeed, dataSeed *Seed256, nonce []byte) {
	ls := newLaneScratch(nonce, currentNonceSizeCfg(cfg))
	defer ls.wipe()
	idx8 := [8]int{0, 1, 2, 3, 4, 5, 6, 7}
	noiseHs8 := noiseSeed.blockHash256x8(&ls.noise, noiseIdx8(idx8, 0))
	dataHs8 := dataSeed.blockHash256x8(&ls.data, idx8)
	idx4 := [4]int{8, 9, 10, 11}
	noiseHs4 := noiseSeed.blockHash256x4(&ls.noise4, noiseIdx4(idx4, 0))
	dataHs4 := dataSeed.blockHash256x4(&ls.data4, idx4)
	nH := noiseSeed.blockHash256(ls.noise[0], 12)
	dH := dataSeed.blockHash256(ls.data[0], 12)
	pxResidueSink = noiseHs8[0][3] ^ dataHs8[7][3] ^ noiseHs4[0][3] ^ dataHs4[3][3] ^ nH[3] ^ dH[3]
}

//go:noinline
func leakyChunkHashes512(cfg *Config, noiseSeed, dataSeed *Seed512, nonce []byte) {
	ls := newLaneScratch(nonce, currentNonceSizeCfg(cfg))
	defer ls.wipe()
	idx8 := [8]int{0, 1, 2, 3, 4, 5, 6, 7}
	noiseHs8 := noiseSeed.blockHash512x8(&ls.noise, noiseIdx8(idx8, 0))
	dataHs8 := dataSeed.blockHash512x8(&ls.data, idx8)
	idx4 := [4]int{8, 9, 10, 11}
	noiseHs4 := noiseSeed.blockHash512x4(&ls.noise4, noiseIdx4(idx4, 0))
	dataHs4 := dataSeed.blockHash512x4(&ls.data4, idx4)
	nH := noiseSeed.blockHash512(ls.noise[0], 12)
	dH := dataSeed.blockHash512(ls.data[0], 12)
	pxResidueSink = noiseHs8[0][7] ^ dataHs8[7][7] ^ noiseHs4[0][7] ^ dataHs4[3][7] ^ nH[7] ^ dH[7]
}

func pxResidueHits(res []uint64, secrets map[uint64]string) int {
	hits := 0
	for _, w := range res {
		if _, ok := secrets[w]; ok {
			hits++
		}
	}
	return hits
}

func assertNoPixelSecretResidue(t *testing.T, name string, res []uint64, secrets map[uint64]string) {
	t.Helper()
	written := 0
	for i, w := range res {
		if w != pxResidueSentinel {
			written++
		}
		if what, ok := secrets[w]; ok {
			t.Errorf("%s: %s left on stack %d bytes below window top", name, what, 8*(i+1))
		}
	}
	if written == 0 {
		t.Fatalf("%s: probe window did not overlap call stack frame", name)
	}
}

// TestPixelBarrierZeroization verifies with negative controls under both
// CGO_ENABLED=1 (process_cgo.go) and CGO_ENABLED=0 (process_generic.go) that:
//  1. The stack-residue probe deterministically catches unwiped blockHash*x8,
//     blockHash*x4, and blockHash* output words left in a caller stack frame
//     (leakyChunkHashes{128,256,512}).
//  2. processChunk{128,256,512} exercises all three batch rungs (x8 on pixels
//     0..7, x4 on pixels 8..11, and x1 on pixel 12 with startP=0, endP=13)
//     and wipes its local ChainHash output arrays (noiseHs8, dataHs8, noiseHs4,
//     dataHs4, noiseH, dataH), derived per-pixel state, and child call stack
//     before returning across both encode and decode directions.
//  3. lockBatchPRF48.wipe() (and buildTripleWire3 / interleaveForTriple48LockedCfg)
//     zeroes the captured lockComps slice in place across 128/256/512-bit widths,
//     with a pre-wipe negative control confirming lockComps holds live key
//     material prior to wipe().
func TestPixelBarrierZeroization(t *testing.T) {
	rng := rand.New(rand.NewSource(0x7e4012e))

	makeSeed128 := func(tag uint64) *Seed128 {
		comps := make([]uint64, 4)
		for i := range comps {
			comps[i] = rng.Uint64() | 1
		}
		hash1 := func(data []byte, s0, s1 uint64) (uint64, uint64) {
			d := uint64(binary.LittleEndian.Uint32(data[:4]))
			r0 := (s0 ^ d ^ tag) * 0x9E3779B97F4A7C15
			r1 := (s1 ^ d ^ tag) * 0xBF58476D1CE4E5B9
			return simHash128Stack(r0, r1)
		}
		s := &Seed128{
			Components: comps,
			Hash:       hash1,
			BatchHash: func(data *[4][]byte, seeds [4][2]uint64) [4][2]uint64 {
				var out [4][2]uint64
				for l := 0; l < 4; l++ {
					out[l][0], out[l][1] = hash1(data[l], seeds[l][0], seeds[l][1])
				}
				return out
			},
			BatchFusedChain: func(components []uint64, data *[4][]byte) ([4][2]uint64, bool) {
				var out [4][2]uint64
				for l := 0; l < 4; l++ {
					h0, h1 := hash1(data[l], components[0], components[1])
					for i := 2; i < len(components); i += 2 {
						h0, h1 = hash1(data[l], components[i]^h0, components[i+1]^h1)
					}
					out[l] = [2]uint64{h0, h1}
				}
				return out, true
			},
		}
		// Arm SetBatchFusedChain8 returning (_, false) so useBatch8Seeds(noiseSeed, dataSeed)
		// is true and blockHash128x8 executes its 8-lane batchChainHash128x8 path.
		s.SetBatchFusedChain8(func(components []uint64, data *[8][]byte) ([8][2]uint64, bool) {
			return [8][2]uint64{}, false
		})
		return s
	}

	makeSeed256 := func(tag uint64) *Seed256 {
		comps := make([]uint64, 8)
		for i := range comps {
			comps[i] = rng.Uint64() | 1
		}
		hash1 := func(data []byte, s [4]uint64) [4]uint64 {
			d := uint64(binary.LittleEndian.Uint32(data[:4]))
			var out [4]uint64
			for j := 0; j < 4; j++ {
				out[j] = (s[j] ^ d ^ tag) * (0x9E3779B97F4A7C15 + uint64(j)*2)
			}
			return simHash256Stack(out)
		}
		s := &Seed256{
			Components: comps,
			Hash:       hash1,
			BatchHash: func(data *[4][]byte, seeds [4][4]uint64) [4][4]uint64 {
				var out [4][4]uint64
				for l := 0; l < 4; l++ {
					out[l] = hash1(data[l], seeds[l])
				}
				return out
			},
		}
		s.SetBatchFusedChain8(func(components []uint64, data *[8][]byte) ([8][4]uint64, bool) {
			return [8][4]uint64{}, false
		})
		return s
	}

	makeSeed512 := func(tag uint64) *Seed512 {
		comps := make([]uint64, 16)
		for i := range comps {
			comps[i] = rng.Uint64() | 1
		}
		hash1 := func(data []byte, s [8]uint64) [8]uint64 {
			d := uint64(binary.LittleEndian.Uint32(data[:4]))
			var out [8]uint64
			for j := 0; j < 8; j++ {
				out[j] = (s[j] ^ d ^ tag) * (0xBF58476D1CE4E5B9 + uint64(j)*2)
			}
			return simHash512Stack(out)
		}
		s := &Seed512{
			Components: comps,
			Hash:       hash1,
			BatchHash: func(data *[4][]byte, seeds [4][8]uint64) [4][8]uint64 {
				var out [4][8]uint64
				for l := 0; l < 4; l++ {
					out[l] = hash1(data[l], seeds[l])
				}
				return out
			},
		}
		s.SetBatchFusedChain8(func(components []uint64, data *[8][]byte) ([8][8]uint64, bool) {
			return [8][8]uint64{}, false
		})
		return s
	}

	const (
		nPixels     = 13 // 8 (x8) + 4 (x4) + 1 (x1) = 13 pixels
		totalPixels = 16
		dataLen     = nPixels * (DataBitsPerPixel / 8)
		totalBits   = dataLen * 8
	)

	nonce := make([]byte, DefaultNonceBits/8)
	rng.Read(nonce)
	container := make([]byte, totalPixels*Channels)
	plain := make([]byte, dataLen)
	rng.Read(container)
	rng.Read(plain)

	refIdx8 := [8]int{0, 1, 2, 3, 4, 5, 6, 7}
	refIdx4 := [4]int{8, 9, 10, 11}

	// 128-bit negative control + positive assertions (encode & decode) across x8 + x4 + x1:
	{
		noiseSeed := makeSeed128(0x1111)
		dataSeed := makeSeed128(0x2222)

		lsRef := newLaneScratch(nonce, len(nonce))
		rN8 := noiseSeed.blockHash128x8(&lsRef.noise, noiseIdx8(refIdx8, 0))
		rD8 := dataSeed.blockHash128x8(&lsRef.data, refIdx8)
		rN4 := noiseSeed.blockHash128x4(&lsRef.noise4, noiseIdx4(refIdx4, 0))
		rD4 := dataSeed.blockHash128x4(&lsRef.data4, refIdx4)
		rN1Lo, rN1Hi := noiseSeed.blockHash128(lsRef.noise[0], 12)
		rD1Lo, rD1Hi := dataSeed.blockHash128(lsRef.data[0], 12)
		lsRef.wipe()

		secrets128 := make(map[uint64]string)
		for l := 0; l < 8; l++ {
			for w := 0; w < 2; w++ {
				secrets128[rN8[l][w]] = fmt.Sprintf("noiseHs8_128[%d][%d]", l, w)
				secrets128[rD8[l][w]] = fmt.Sprintf("dataHs8_128[%d][%d]", l, w)
			}
			secrets128[rD8[l][0]>>DataRotationBits] = fmt.Sprintf("xorMask8_128[%d]", l)
		}
		for l := 0; l < 4; l++ {
			for w := 0; w < 2; w++ {
				secrets128[rN4[l][w]] = fmt.Sprintf("noiseHs4_128[%d][%d]", l, w)
				secrets128[rD4[l][w]] = fmt.Sprintf("dataHs4_128[%d][%d]", l, w)
			}
			secrets128[rD4[l][0]>>DataRotationBits] = fmt.Sprintf("xorMask4_128[%d]", l)
		}
		secrets128[rN1Lo] = "noiseH1_128[0]"
		secrets128[rN1Hi] = "noiseH1_128[1]"
		secrets128[rD1Lo] = "dataH1_128[0]"
		secrets128[rD1Hi] = "dataH1_128[1]"
		secrets128[rD1Lo>>DataRotationBits] = "xorMask1_128"

		resNeg := pxStackResidue(func() {
			leakyChunkHashes128(nil, noiseSeed, dataSeed, nonce)
		})
		if pxResidueHits(resNeg, secrets128) == 0 {
			t.Fatal("negative control failed: pxStackResidue did not detect unwiped hashes in leakyChunkHashes128")
		}

		resEnc := pxStackResidue(func() {
			processChunk128(nil, noiseSeed, dataSeed, nonce, container, plain, 0, totalPixels, 0, nPixels, totalBits, 512, true, 0)
		})
		assertNoPixelSecretResidue(t, "processChunk128/encode", resEnc, secrets128)

		outDec := make([]byte, dataLen)
		resDec := pxStackResidue(func() {
			processChunk128(nil, noiseSeed, dataSeed, nonce, container, outDec, 0, totalPixels, 0, nPixels, totalBits, 512, false, 0)
		})
		assertNoPixelSecretResidue(t, "processChunk128/decode", resDec, secrets128)
	}

	// 256-bit negative control + positive assertions (encode & decode) across x8 + x4 + x1:
	{
		ns256 := makeSeed256(0x4444)
		ds256 := makeSeed256(0x5555)
		ls256 := newLaneScratch(nonce, len(nonce))
		rN8 := ns256.blockHash256x8(&ls256.noise, noiseIdx8(refIdx8, 0))
		rD8 := ds256.blockHash256x8(&ls256.data, refIdx8)
		rN4 := ns256.blockHash256x4(&ls256.noise4, noiseIdx4(refIdx4, 0))
		rD4 := ds256.blockHash256x4(&ls256.data4, refIdx4)
		rN1 := ns256.blockHash256(ls256.noise[0], 12)
		rD1 := ds256.blockHash256(ls256.data[0], 12)
		ls256.wipe()

		secrets256 := make(map[uint64]string)
		for l := 0; l < 8; l++ {
			for w := 0; w < 4; w++ {
				secrets256[rN8[l][w]] = fmt.Sprintf("noiseHs8_256[%d][%d]", l, w)
				secrets256[rD8[l][w]] = fmt.Sprintf("dataHs8_256[%d][%d]", l, w)
			}
			secrets256[rD8[l][0]>>DataRotationBits] = fmt.Sprintf("xorMask8_256[%d]", l)
		}
		for l := 0; l < 4; l++ {
			for w := 0; w < 4; w++ {
				secrets256[rN4[l][w]] = fmt.Sprintf("noiseHs4_256[%d][%d]", l, w)
				secrets256[rD4[l][w]] = fmt.Sprintf("dataHs4_256[%d][%d]", l, w)
			}
			secrets256[rD4[l][0]>>DataRotationBits] = fmt.Sprintf("xorMask4_256[%d]", l)
		}
		for w := 0; w < 4; w++ {
			secrets256[rN1[w]] = fmt.Sprintf("noiseH1_256[%d]", w)
			secrets256[rD1[w]] = fmt.Sprintf("dataH1_256[%d]", w)
		}
		secrets256[rD1[0]>>DataRotationBits] = "xorMask1_256"

		resNeg := pxStackResidue(func() {
			leakyChunkHashes256(nil, ns256, ds256, nonce)
		})
		if pxResidueHits(resNeg, secrets256) == 0 {
			t.Fatal("negative control failed: pxStackResidue did not detect unwiped hashes in leakyChunkHashes256")
		}

		resEnc := pxStackResidue(func() {
			processChunk256(nil, ns256, ds256, nonce, container, plain, 0, totalPixels, 0, nPixels, totalBits, 512, true, 0)
		})
		assertNoPixelSecretResidue(t, "processChunk256/encode", resEnc, secrets256)

		outDec := make([]byte, dataLen)
		resDec := pxStackResidue(func() {
			processChunk256(nil, ns256, ds256, nonce, container, outDec, 0, totalPixels, 0, nPixels, totalBits, 512, false, 0)
		})
		assertNoPixelSecretResidue(t, "processChunk256/decode", resDec, secrets256)
	}

	// 512-bit negative control + positive assertions (encode & decode) across x8 + x4 + x1:
	{
		ns512 := makeSeed512(0x6666)
		ds512 := makeSeed512(0x7777)
		ls512 := newLaneScratch(nonce, len(nonce))
		rN8 := ns512.blockHash512x8(&ls512.noise, noiseIdx8(refIdx8, 0))
		rD8 := ds512.blockHash512x8(&ls512.data, refIdx8)
		rN4 := ns512.blockHash512x4(&ls512.noise4, noiseIdx4(refIdx4, 0))
		rD4 := ds512.blockHash512x4(&ls512.data4, refIdx4)
		rN1 := ns512.blockHash512(ls512.noise[0], 12)
		rD1 := ds512.blockHash512(ls512.data[0], 12)
		ls512.wipe()

		secrets512 := make(map[uint64]string)
		for l := 0; l < 8; l++ {
			for w := 0; w < 8; w++ {
				secrets512[rN8[l][w]] = fmt.Sprintf("noiseHs8_512[%d][%d]", l, w)
				secrets512[rD8[l][w]] = fmt.Sprintf("dataHs8_512[%d][%d]", l, w)
			}
			secrets512[rD8[l][0]>>DataRotationBits] = fmt.Sprintf("xorMask8_512[%d]", l)
		}
		for l := 0; l < 4; l++ {
			for w := 0; w < 8; w++ {
				secrets512[rN4[l][w]] = fmt.Sprintf("noiseHs4_512[%d][%d]", l, w)
				secrets512[rD4[l][w]] = fmt.Sprintf("dataHs4_512[%d][%d]", l, w)
			}
			secrets512[rD4[l][0]>>DataRotationBits] = fmt.Sprintf("xorMask4_512[%d]", l)
		}
		for w := 0; w < 8; w++ {
			secrets512[rN1[w]] = fmt.Sprintf("noiseH1_512[%d]", w)
			secrets512[rD1[w]] = fmt.Sprintf("dataH1_512[%d]", w)
		}
		secrets512[rD1[0]>>DataRotationBits] = "xorMask1_512"

		resNeg := pxStackResidue(func() {
			leakyChunkHashes512(nil, ns512, ds512, nonce)
		})
		if pxResidueHits(resNeg, secrets512) == 0 {
			t.Fatal("negative control failed: pxStackResidue did not detect unwiped hashes in leakyChunkHashes512")
		}

		resEnc := pxStackResidue(func() {
			processChunk512(nil, ns512, ds512, nonce, container, plain, 0, totalPixels, 0, nPixels, totalBits, 512, true, 0)
		})
		assertNoPixelSecretResidue(t, "processChunk512/encode", resEnc, secrets512)

		outDec := make([]byte, dataLen)
		resDec := pxStackResidue(func() {
			processChunk512(nil, ns512, ds512, nonce, container, outDec, 0, totalPixels, 0, nPixels, totalBits, 512, false, 0)
		})
		assertNoPixelSecretResidue(t, "processChunk512/decode", resDec, secrets512)
	}

	// Verify deriveStartPixel leaves no ChainHash output residue on the caller stack across 128/256/512
	// (with deriveStartPixelBody as the negative control):
	{
		spBuf := make([]byte, 1+len(nonce))
		spBuf[0] = 0x02
		copy(spBuf[1:], nonce)

		s128 := makeSeed128(0x8888)
		h128Lo, h128Hi := s128.ChainHash128(spBuf)
		secSP128 := map[uint64]string{h128Lo: "sp128[0]", h128Hi: "sp128[1]"}
		resSP128Neg := pxStackResidue(func() {
			pxResidueSink = uint64(s128.deriveStartPixelBody(nonce, totalPixels))
		})
		if pxResidueHits(resSP128Neg, secSP128) == 0 {
			t.Fatal("negative control failed: pxStackResidue did not detect unwiped ChainHash128 in Seed128.deriveStartPixelBody")
		}
		resSP128 := pxStackResidue(func() {
			_ = s128.deriveStartPixel(nonce, totalPixels)
		})
		assertNoPixelSecretResidue(t, "Seed128.deriveStartPixel", resSP128, secSP128)

		s256 := makeSeed256(0x9999)
		h256 := s256.ChainHash256(spBuf)
		secSP256 := make(map[uint64]string)
		for w := 0; w < 4; w++ {
			secSP256[h256[w]] = fmt.Sprintf("sp256[%d]", w)
		}
		resSP256Neg := pxStackResidue(func() {
			pxResidueSink = uint64(s256.deriveStartPixelBody(nonce, totalPixels))
		})
		if pxResidueHits(resSP256Neg, secSP256) == 0 {
			t.Fatal("negative control failed: pxStackResidue did not detect unwiped ChainHash256 in Seed256.deriveStartPixelBody")
		}
		resSP256 := pxStackResidue(func() {
			_ = s256.deriveStartPixel(nonce, totalPixels)
		})
		assertNoPixelSecretResidue(t, "Seed256.deriveStartPixel", resSP256, secSP256)

		s512 := makeSeed512(0xAAAA)
		h512 := s512.ChainHash512(spBuf)
		secSP512 := make(map[uint64]string)
		for w := 0; w < 8; w++ {
			secSP512[h512[w]] = fmt.Sprintf("sp512[%d]", w)
		}
		resSP512Neg := pxStackResidue(func() {
			pxResidueSink = uint64(s512.deriveStartPixelBody(nonce, totalPixels))
		})
		if pxResidueHits(resSP512Neg, secSP512) == 0 {
			t.Fatal("negative control failed: pxStackResidue did not detect unwiped ChainHash512 in Seed512.deriveStartPixelBody")
		}
		resSP512 := pxStackResidue(func() {
			_ = s512.deriveStartPixel(nonce, totalPixels)
		})
		assertNoPixelSecretResidue(t, "Seed512.deriveStartPixel", resSP512, secSP512)
	}

	// Negative + positive controls for buildLockBatchPRF48_{128,256,512} stack residue
	// AND lockBatchPRF48.wipe() heap zeroization across 128, 256, 512.
	{
		ilNonce := make([]byte, 32)
		rng.Read(ilNonce)
		var buf [13]byte

		// 128-bit lockBatchPRF48
		s128 := makeSeed128(0x3333)
		il128Lo, il128Hi := s128.deriveInterLockSeed(ilNonce)
		secIL128 := map[uint64]string{
			il128Lo: "il128[0]",
			il128Hi: "il128[1]",
		}
		var bp128Neg lockBatchPRF48
		resIL128Neg := pxStackResidue(func() {
			bp128Neg = buildLockBatchPRF48_128Body(s128, ilNonce)
		})
		bp128Neg.wipe()
		if pxResidueHits(resIL128Neg, secIL128) == 0 {
			t.Fatal("negative control failed: pxStackResidue did not detect unwiped deriveInterLockSeed in buildLockBatchPRF48_128Body")
		}
		var bp128 lockBatchPRF48
		resIL128 := pxStackResidue(func() {
			bp128 = buildLockBatchPRF48_128(s128, ilNonce)
		})
		assertNoPixelSecretResidue(t, "buildLockBatchPRF48_128", resIL128, secIL128)
		var live128, wiped128, zero128 [2]uint64
		bp128.fillRanks(buf[:], 7, live128[:])
		zSeed128 := &Seed128{Components: make([]uint64, 6), Hash: s128.Hash}
		z128Lo, z128Hi := zSeed128.ChainHash128(buf[:])
		zero128 = [2]uint64{z128Lo, z128Hi}
		if live128 == zero128 {
			t.Fatal("negative control failed: lockBatchPRF48_128 matched zeroed lockComps before wipe()")
		}
		bp128.wipe()
		bp128.fillRanks(buf[:], 7, wiped128[:])
		if wiped128 != zero128 {
			t.Fatalf("lockBatchPRF48_128.wipe() did not zero lockComps: got %x, want %x", wiped128, zero128)
		}

		// 256-bit lockBatchPRF48
		s256 := makeSeed256(0xBBBB)
		ilComps256 := s256.deriveInterLockSeed(ilNonce)
		secIL256 := make(map[uint64]string)
		for w := 0; w < 4; w++ {
			secIL256[ilComps256[w]] = fmt.Sprintf("il256[%d]", w)
		}
		clear(ilComps256[:])
		var bp256Neg lockBatchPRF48
		resIL256Neg := pxStackResidue(func() {
			bp256Neg = buildLockBatchPRF48_256Body(s256, ilNonce)
		})
		bp256Neg.wipe()
		if pxResidueHits(resIL256Neg, secIL256) == 0 {
			t.Fatal("negative control failed: pxStackResidue did not detect unwiped deriveInterLockSeed in buildLockBatchPRF48_256Body")
		}
		var bp256 lockBatchPRF48
		resIL256 := pxStackResidue(func() {
			bp256 = buildLockBatchPRF48_256(s256, ilNonce)
		})
		assertNoPixelSecretResidue(t, "buildLockBatchPRF48_256", resIL256, secIL256)
		var live256, wiped256 [4]uint64
		bp256.fillRanks(buf[:], 7, live256[:])
		zSeed256 := &Seed256{Components: make([]uint64, 12), Hash: s256.Hash}
		zero256 := zSeed256.ChainHash256(buf[:])
		if live256 == zero256 {
			t.Fatal("negative control failed: lockBatchPRF48_256 matched zeroed lockComps before wipe()")
		}
		bp256.wipe()
		bp256.fillRanks(buf[:], 7, wiped256[:])
		if wiped256 != zero256 {
			t.Fatalf("lockBatchPRF48_256.wipe() did not zero lockComps: got %x, want %x", wiped256, zero256)
		}

		// 512-bit lockBatchPRF48
		s512 := makeSeed512(0xCCCC)
		ilComps512 := s512.deriveInterLockSeed(ilNonce)
		secIL512 := make(map[uint64]string)
		for w := 0; w < 8; w++ {
			secIL512[ilComps512[w]] = fmt.Sprintf("il512[%d]", w)
		}
		clear(ilComps512[:])
		var bp512Neg lockBatchPRF48
		resIL512Neg := pxStackResidue(func() {
			bp512Neg = buildLockBatchPRF48_512Body(s512, ilNonce)
		})
		bp512Neg.wipe()
		if pxResidueHits(resIL512Neg, secIL512) == 0 {
			t.Fatal("negative control failed: pxStackResidue did not detect unwiped deriveInterLockSeed in buildLockBatchPRF48_512Body")
		}
		var bp512 lockBatchPRF48
		resIL512 := pxStackResidue(func() {
			bp512 = buildLockBatchPRF48_512(s512, ilNonce)
		})
		assertNoPixelSecretResidue(t, "buildLockBatchPRF48_512", resIL512, secIL512)
		var live512, wiped512 [8]uint64
		bp512.fillRanks(buf[:], 7, live512[:])
		zSeed512 := &Seed512{Components: make([]uint64, 24), Hash: s512.Hash}
		zero512 := zSeed512.ChainHash512(buf[:])
		if live512 == zero512 {
			t.Fatal("negative control failed: lockBatchPRF48_512 matched zeroed lockComps before wipe()")
		}
		bp512.wipe()
		bp512.fillRanks(buf[:], 7, wiped512[:])
		if wiped512 != zero512 {
			t.Fatalf("lockBatchPRF48_512.wipe() did not zero lockComps: got %x, want %x", wiped512, zero512)
		}
	}
}

// TestFreshGoroutineStackNoSplitDuringWipe verifies on a fresh 2 KiB goroutine
// (with NO prior pxResidueGrow) that the pre-Body wipePixelCallStack call
// pre-grows the goroutine stack before any *Body function executes, so the
// pre-Body and post-Body wipePixelCallStack calls land at the exact same stack
// address (confirming runtime.morestack_noctxt never splits/copies the stack
// inside *Body before the post-Body wipe).
func TestFreshGoroutineStackNoSplitDuringWipe(t *testing.T) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	defer pixelWipeObserver.Store(nil)

	rng := rand.New(rand.NewSource(0x57ac4))
	nonce := make([]byte, DefaultNonceBits/8)
	rng.Read(nonce)
	container := make([]byte, 16*Channels)
	plain := make([]byte, 13*(DataBitsPerPixel/8))
	rng.Read(container)
	rng.Read(plain)

	s128 := &Seed128{
		Components: []uint64{1, 2, 3, 4},
		Hash: func(data []byte, s0, s1 uint64) (uint64, uint64) {
			return s0 ^ 0x1111, s1 ^ 0x2222
		},
	}
	s256 := &Seed256{
		Components: []uint64{1, 2, 3, 4, 5, 6, 7, 8},
		Hash: func(data []byte, s [4]uint64) [4]uint64 {
			return [4]uint64{s[0] ^ 1, s[1] ^ 2, s[2] ^ 3, s[3] ^ 4}
		},
	}
	s512 := &Seed512{
		Components: []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Hash: func(data []byte, s [8]uint64) [8]uint64 {
			return [8]uint64{s[0] ^ 1, s[1] ^ 2, s[2] ^ 3, s[3] ^ 4, s[4] ^ 5, s[5] ^ 6, s[6] ^ 7, s[7] ^ 8}
		},
	}

	// Negative control: on a fresh 2 KiB goroutine WITHOUT a pre-Body
	// wipePixelCallStack call, processChunk512Body + post-Body wipePixelCallStack
	// exceeds the initial 2 KiB stack and forces runtime.morestack_noctxt to
	// reallocate the stack onto a different segment.
	{
		var spBefore, spAfter uintptr
		cb := func(sp uintptr) {
			spAfter = sp
		}
		pixelWipeObserver.Store(&cb)
		done := make(chan struct{})
		go func() {
			defer close(done)
			var anchor uint64
			spBefore = uintptr(unsafe.Pointer(&anchor))
			processChunk512Body(nil, s512, s512, nonce, container, plain, 0, 16, 0, 13, len(plain)*8, 512, true, 0)
			wipePixelCallStack([9][8]uint64{})
		}()
		<-done
		const initialGoroutineStack = 2 << 10
		sameStack := spBefore > spAfter && (spBefore-spAfter) < initialGoroutineStack
		if sameStack {
			t.Fatalf("negative control failed: expected fresh 2 KiB goroutine without pre-Body wipePixelCallStack to split stack (spBefore=%#x, spAfter=%#x)", spBefore, spAfter)
		}
	}

	cases := []struct {
		name string
		fn   func()
	}{
		{"Seed128.deriveStartPixel", func() { _ = s128.deriveStartPixel(nonce, 16) }},
		{"Seed256.deriveStartPixel", func() { _ = s256.deriveStartPixel(nonce, 16) }},
		{"Seed512.deriveStartPixel", func() { _ = s512.deriveStartPixel(nonce, 16) }},
		{"processChunk128", func() {
			processChunk128(nil, s128, s128, nonce, container, plain, 0, 16, 0, 13, len(plain)*8, 512, true, 0)
		}},
		{"processChunk256", func() {
			processChunk256(nil, s256, s256, nonce, container, plain, 0, 16, 0, 13, len(plain)*8, 512, true, 0)
		}},
		{"processChunk512", func() {
			processChunk512(nil, s512, s512, nonce, container, plain, 0, 16, 0, 13, len(plain)*8, 512, true, 0)
		}},
		{"buildLockBatchPRF48_128", func() {
			bp := buildLockBatchPRF48_128(s128, nonce)
			bp.wipe()
		}},
		{"buildLockBatchPRF48_256", func() {
			bp := buildLockBatchPRF48_256(s256, nonce)
			bp.wipe()
		}},
		{"buildLockBatchPRF48_512", func() {
			bp := buildLockBatchPRF48_512(s512, nonce)
			bp.wipe()
		}},
	}

	for _, tc := range cases {
		var sps []uintptr
		cb := func(sp uintptr) {
			sps = append(sps, sp)
		}
		pixelWipeObserver.Store(&cb)
		done := make(chan struct{})
		go func() {
			defer close(done)
			tc.fn()
		}()
		<-done
		if len(sps) != 2 {
			t.Fatalf("%s: expected 2 wipePixelCallStack invocations (pre-Body and post-Body), got %d", tc.name, len(sps))
		}
		if sps[0] != sps[1] {
			t.Fatalf("%s: goroutine stack split between pre-Body wipe (%#x) and post-Body wipe (%#x)", tc.name, sps[0], sps[1])
		}
	}
}

func TestBlobExportImportZeroization(t *testing.T) {
	rng := rand.New(rand.NewSource(0xB10B2E50))

	// 1. Verify decodeHexBounded decodes valid hex and scrubs partially decoded prefix on malformed tail.
	var macSecret [32]byte
	rng.Read(macSecret[:])
	macHex := hex.EncodeToString(macSecret[:])
	b, err := decodeHexBounded(macHex, 64)
	if err != nil {
		t.Fatalf("decodeHexBounded: %v", err)
	}
	if cap(b) != len(b) || len(b) != 32 {
		t.Fatalf("decodeHexBounded len/cap = %d/%d, want 32/32", len(b), cap(b))
	}
	clear(b)

	// Negative control: hex.DecodeString on a string with a valid 32-byte secret prefix followed by
	// an invalid hex byte returns the decoded 32-byte secret prefix in the error slice.
	malformedHex := macHex + "zz"
	negPartial, negErr := hex.DecodeString(malformedHex)
	if negErr == nil || len(negPartial) != 32 {
		t.Fatalf("hex.DecodeString malformed: len=%d, err=%v", len(negPartial), negErr)
	}
	clear(negPartial)
	if badOut, badErr := decodeHexBounded(malformedHex, 128); badErr == nil || badOut != nil {
		t.Fatalf("decodeHexBounded malformed: got (%v, %v), want (nil, ErrBlobMalformed)", badOut, badErr)
	}

	// 2. Verify (*Blob512).Export3Cfg and (*Blob512).Import3Cfg leave no key or component residue on the stack.
	cfg512 := &Config{NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill}
	makeSeed := func() *Seed512 {
		c := make([]uint64, 16)
		for i := range c {
			c[i] = rng.Uint64() | 1
		}
		return &Seed512{Components: c}
	}
	ns := makeSeed()
	ds1, ds2, ds3 := makeSeed(), makeSeed(), makeSeed()
	ss1, ss2, ss3 := makeSeed(), makeSeed(), makeSeed()
	ls := makeSeed()

	var keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3, keyL [64]byte
	for _, kp := range []*[64]byte{&keyN, &keyD1, &keyD2, &keyD3, &keyS1, &keyS2, &keyS3, &keyL} {
		rng.Read(kp[:])
	}

	secrets512 := make(map[uint64]string)
	for _, s := range []*Seed512{ns, ds1, ds2, ds3, ss1, ss2, ss3, ls} {
		for _, w := range s.Components {
			if w != 0 {
				secrets512[w] = "seed512.Component"
			}
		}
	}
	for _, k := range [][64]byte{keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3, keyL} {
		for off := 0; off < 64; off += 8 {
			w := binary.LittleEndian.Uint64(k[off : off+8])
			if w != 0 {
				secrets512[w] = "key512Word"
			}
		}
	}

	var b512 Blob512
	var rawBlob []byte
	resExp := pxStackResidue(func() {
		var expErr error
		rawBlob, expErr = b512.Export3Cfg(
			cfg512,
			keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
			ns, ds1, ds2, ds3, ss1, ss2, ss3,
			Blob512Opts{KeyL: keyL, LS: ls},
		)
		if expErr != nil {
			t.Errorf("Blob512.Export3Cfg: %v", expErr)
		}
	})
	assertNoPixelSecretResidue(t, "Blob512.Export3Cfg", resExp, secrets512)

	// Error path on Export3Cfg (nil seed): must also leave no stack residue.
	resExpErr := pxStackResidue(func() {
		_, _ = b512.Export3Cfg(
			cfg512,
			keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
			nil, ds1, ds2, ds3, ss1, ss2, ss3,
			Blob512Opts{KeyL: keyL, LS: ls},
		)
	})
	assertNoPixelSecretResidue(t, "Blob512.Export3Cfg/error", resExpErr, secrets512)

	// 3. Verify Import3Cfg leaves no component or key residue on the stack on error.
	corruptRaw := strings.Replace(string(rawBlob), `"ss3":[`, `"ss3":["not_a_decimal_uint64",`, 1)
	resImpErr := pxStackResidue(func() {
		var imp Blob512
		_ = imp.Import3Cfg([]byte(corruptRaw), cfg512)
	})
	assertNoPixelSecretResidue(t, "Blob512.Import3Cfg/error", resImpErr, secrets512)

	// 4. Verify caller's own keyL [64]byte variable is untouched after Export3Cfg, while the variadic temporary is wiped.
	origKeyL := keyL
	if _, err := b512.Export3Cfg(
		cfg512,
		keyN, keyD1, keyD2, keyD3, keyS1, keyS2, keyS3,
		ns, ds1, ds2, ds3, ss1, ss2, ss3,
		Blob512Opts{KeyL: keyL, LS: ls},
	); err != nil {
		t.Fatalf("Blob512.Export3Cfg: %v", err)
	}
	if keyL != origKeyL {
		t.Fatal("Blob512.Export3Cfg mutated caller's keyL value")
	}
}

//go:noinline
func simInterlockHash512DeepStack(r [8]uint64) [8]uint64 {
	var frame [96]uint64
	idx := int(r[0]&7) + 64
	copy(frame[idx:idx+8], r[:])
	var out [8]uint64
	copy(out[:], frame[idx:idx+8])
	return out
}

func TestInterlock48SplitInterleaveStackZeroization(t *testing.T) {
	rng := rand.New(rand.NewSource(0x484848))
	s512 := &Seed512{
		Components: make([]uint64, 16),
		Hash: func(data []byte, s [8]uint64) [8]uint64 {
			d := uint64(binary.LittleEndian.Uint64(data[:8]))
			var out [8]uint64
			for j := 0; j < 8; j++ {
				out[j] = (s[j] ^ d ^ 0xA5A5A5A55A5A5A5A) * (0x9E3779B97F4A7C15 + uint64(j)*2)
			}
			return simInterlockHash512DeepStack(out)
		},
	}
	for i := range s512.Components {
		s512.Components[i] = rng.Uint64() | 1
	}
	ilNonce := make([]byte, 32)
	rng.Read(ilNonce)

	plain := make([]byte, 9*6) // 9 chunks of 48 bits
	rng.Read(plain)
	laneLen := tripleLaneLen(len(plain))
	r1 := make([]byte, laneLen)
	r2 := make([]byte, laneLen)
	r3 := make([]byte, laneLen)
	src := framedSrc48{body: plain}
	M := src.chunkCount()

	bpRef := buildLockBatchPRF48_512(s512, ilNonce)
	numGroups := (M + bpRef.factor - 1) / bpRef.factor
	secrets := make(map[uint64]string)
	for g := 0; g < numGroups; g++ {
		var rankWords [8]uint64
		var buf [13]byte
		bpRef.fillRanks(buf[:], uint64(g), rankWords[:])
		for i, w := range rankWords {
			if w != 0 {
				secrets[w] = fmt.Sprintf("rankWords[g=%d,i=%d]", g, i)
			}
		}
	}
	bpRef.wipe()

	// Negative control: calling splitTriple48WorkerBody directly without wipePixelCallStack leaves rankWords on the stack.
	bpNeg := buildLockBatchPRF48_512(s512, ilNonce)
	resNeg := pxStackResidue(func() {
		splitTriple48WorkerBody(0, numGroups, M, bpNeg.factor, src, r1, r2, r3, bpNeg)
	})
	bpNeg.wipe()
	if pxResidueHits(resNeg, secrets) == 0 {
		t.Fatal("negative control failed: pxStackResidue did not detect unwiped rankWords in splitTriple48WorkerBody")
	}

	for _, workers := range []int{1, 4} {
		cfg := &Config{NonceBits: DefaultNonceBits, BarrierFill: DefaultBarrierFill, MaxWorkers: workers}
		bpSplit := buildLockBatchPRF48_512(s512, ilNonce)
		resSplit := pxStackResidue(func() {
			splitForTriple48LockedInto(cfg, plain, bpSplit, r1, r2, r3)
		})
		assertNoPixelSecretResidue(t, fmt.Sprintf("splitForTriple48LockedInto/W=%d", workers), resSplit, secrets)

		bpJoin := buildLockBatchPRF48_512(s512, ilNonce)
		resJoin := pxStackResidue(func() {
			out := interleaveForTriple48LockedCfg(cfg, r1, r2, r3, bpJoin)
			clear(out)
		})
		assertNoPixelSecretResidue(t, fmt.Sprintf("interleaveForTriple48LockedCfg/W=%d", workers), resJoin, secrets)
	}
}

func TestAreionAndAESITBClosureStackZeroization(t *testing.T) {
	rng := rand.New(rand.NewSource(0xA9E104))
	var k16 [16]byte
	var k32 [32]byte
	var k64 [64]byte
	rng.Read(k16[:])
	rng.Read(k32[:])
	rng.Read(k64[:])
	secrets := make(map[uint64]string)
	for off := 0; off < 16; off += 8 {
		w := binary.LittleEndian.Uint64(k16[off : off+8])
		if w != 0 {
			secrets[w] = fmt.Sprintf("k16Word[%d]", off/8)
		}
	}
	for off := 0; off < 32; off += 8 {
		w := binary.LittleEndian.Uint64(k32[off : off+8])
		if w != 0 {
			secrets[w] = fmt.Sprintf("k32Word[%d]", off/8)
		}
	}
	for off := 0; off < 64; off += 8 {
		w := binary.LittleEndian.Uint64(k64[off : off+8])
		if w != 0 {
			secrets[w] = fmt.Sprintf("k64Word[%d]", off/8)
		}
	}

	var seed4 [4]uint64
	var seed8 [8]uint64
	for i := range seed4 {
		seed4[i] = rng.Uint64() | 1
		secrets[seed4[i]] = fmt.Sprintf("seed4[%d]", i)
	}
	for i := range seed8 {
		seed8[i] = rng.Uint64() | 1
		secrets[seed8[i]] = fmt.Sprintf("seed8[%d]", i)
	}

	msg20 := make([]byte, 20)
	msg47 := make([]byte, 47)
	rng.Read(msg20)
	rng.Read(msg47)
	msgs20 := [4][]byte{msg20, msg20, msg20, msg20}
	msgs47 := [4][]byte{msg47, msg47, msg47, msg47}
	seed2 := [2]uint64{seed4[0], seed4[1]}
	seeds2 := [4][2]uint64{seed2, seed2, seed2, seed2}
	seeds4 := [4][4]uint64{seed4, seed4, seed4, seed4}
	seeds8 := [4][8]uint64{seed8, seed8, seed8, seed8}

	h256, b256 := MakeAreionSoEM256HashWithKey(k32)
	h512, b512 := MakeAreionSoEM512HashWithKey(k64)
	h128, b128 := makeAESITB128HashWithKey(k16)

	for _, tc := range []struct {
		name string
		fn   func()
	}{
		{"Areion256/1lane/20B", func() {
			r := h256(msg20, seed4)
			pxResidueSink = r[0]
			clear(r[:])
		}},
		{"Areion256/1lane/47B", func() {
			r := h256(msg47, seed4)
			pxResidueSink = r[0]
			clear(r[:])
		}},
		{"Areion256/4lane/20B", func() {
			r := b256(&msgs20, seeds4)
			pxResidueSink = r[0][0]
			clear(r[:])
		}},
		{"Areion256/4lane/47B", func() {
			r := b256(&msgs47, seeds4)
			pxResidueSink = r[0][0]
			clear(r[:])
		}},
		{"Areion512/1lane/20B", func() {
			r := h512(msg20, seed8)
			pxResidueSink = r[0]
			clear(r[:])
		}},
		{"Areion512/1lane/47B", func() {
			r := h512(msg47, seed8)
			pxResidueSink = r[0]
			clear(r[:])
		}},
		{"Areion512/4lane/20B", func() {
			r := b512(&msgs20, seeds8)
			pxResidueSink = r[0][0]
			clear(r[:])
		}},
		{"Areion512/4lane/47B", func() {
			r := b512(&msgs47, seeds8)
			pxResidueSink = r[0][0]
			clear(r[:])
		}},
		{"AESITB128/1lane/20B", func() {
			lo, hi := h128(msg20, seed4[0], seed4[1])
			pxResidueSink = lo ^ hi
		}},
		{"AESITB128/1lane/47B", func() {
			lo, hi := h128(msg47, seed4[0], seed4[1])
			pxResidueSink = lo ^ hi
		}},
		{"AESITB128/4lane/20B", func() {
			r := b128(&msgs20, seeds2)
			pxResidueSink = r[0][0]
			clear(r[:])
		}},
	} {
		res := pxStackResidue(tc.fn)
		assertNoPixelSecretResidue(t, tc.name, res, secrets)
	}
}
