//go:build !cgo

package itb

// processChunk128 processes pixels [startP, endP) of the data stream (128-bit variant).
//
// When both noiseSeed.BatchHash and dataSeed.BatchHash are non-nil the
// inner loop dispatches per-pixel hashing four pixels at a time through
// the batched ChainHash path; the per-pixel encoding/decoding work is
// identical to the serial path. Non-batched primitives (BatchHash nil)
// route directly to the legacy serial loop. The pure-Go counterpart of
// the batched dispatch in process_cgo.go.
func processChunk128(cfg *Config, noiseSeed, dataSeed *Seed128, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool) {
	bitIndex := startP * DataBitsPerPixel

	noiseBuf := make([]byte, 4+currentNonceSizeCfg(cfg))
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 4+currentNonceSizeCfg(cfg))
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	p := startP

	if noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil {
		var noiseBufs, dataBufs [4][]byte
		var noiseBufPtrs, dataBufPtrs [4]*[]byte
		noiseBufs[0] = noiseBuf
		dataBufs[0] = dataBuf
		for lane := 1; lane < 4; lane++ {
			noiseBufPtrs[lane], noiseBufs[lane] = acquireBuffer(4 + currentNonceSizeCfg(cfg))
			copy(noiseBufs[lane][4:], nonce)
			dataBufPtrs[lane], dataBufs[lane] = acquireBuffer(4 + currentNonceSizeCfg(cfg))
			copy(dataBufs[lane][4:], nonce)
			defer releaseBuffer(noiseBufPtrs[lane], noiseBufs[lane])
			defer releaseBuffer(dataBufPtrs[lane], dataBufs[lane])
		}

		for ; p+4 <= endP && bitIndex < totalBits; p += 4 {
			pixelIndices := [4]int{p, p + 1, p + 2, p + 3}
			noiseHashes := noiseSeed.blockHash128x4(&noiseBufs, pixelIndices)
			dataHashes := dataSeed.blockHash128x4(&dataBufs, pixelIndices)

			for lane := 0; lane < 4 && bitIndex < totalBits; lane++ {
				pp := p + lane
				linearIdx := (startPixel + pp) % totalPixels
				pixelOffset := linearIdx * Channels

				noiseHash := noiseHashes[lane][0]
				dataHash := dataHashes[lane][0]

				noisePos := uint(noiseHash & 7)
				noiseMask := byte(1 << noisePos)

				dataRotation := uint(dataHash % 7)
				xorMask := dataHash >> DataRotationBits

				if encode {
					for ch := 0; ch < Channels && bitIndex < totalBits; ch++ {
						channelXOR := byte((xorMask >> uint(ch*DataBitsPerChannel)) & 0x7F)

						byteIdx := bitIndex / 8
						bitOff := uint(bitIndex % 8)

						var raw uint16
						raw = uint16(data[byteIdx])
						if byteIdx+1 < len(data) {
							raw |= uint16(data[byteIdx+1]) << 8
						}
						dataBits := byte((raw >> bitOff) & 0x7F)

						dataBits ^= channelXOR
						dataBits = rotateBits7(dataBits, dataRotation)

						orig := container[pixelOffset+ch]
						low := dataBits & byte(noiseMask-1)
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
						low := channelByte & byte(noiseMask-1)
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
	}

	for ; p < endP && bitIndex < totalBits; p++ {
		linearIdx := (startPixel + p) % totalPixels
		pixelOffset := linearIdx * Channels

		noiseHash, _ := noiseSeed.blockHash128(noiseBuf, p)
		dataHash, _ := dataSeed.blockHash128(dataBuf, p)

		noisePos := uint(noiseHash & 7)
		noiseMask := byte(1 << noisePos)

		dataRotation := uint(dataHash % 7)
		xorMask := dataHash >> DataRotationBits

		if encode {
			for ch := 0; ch < Channels && bitIndex < totalBits; ch++ {
				channelXOR := byte((xorMask >> uint(ch*DataBitsPerChannel)) & 0x7F)

				byteIdx := bitIndex / 8
				bitOff := uint(bitIndex % 8)

				var raw uint16
				raw = uint16(data[byteIdx])
				if byteIdx+1 < len(data) {
					raw |= uint16(data[byteIdx+1]) << 8
				}
				dataBits := byte((raw >> bitOff) & 0x7F)

				dataBits ^= channelXOR
				dataBits = rotateBits7(dataBits, dataRotation)

				orig := container[pixelOffset+ch]
				low := dataBits & byte(noiseMask-1)
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
				low := channelByte & byte(noiseMask-1)
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

// processChunk256 processes pixels [startP, endP) of the data stream (256-bit variant).
//
// When both noiseSeed.BatchHash and dataSeed.BatchHash are non-nil the
// inner loop dispatches per-pixel hashing four pixels at a time through
// the batched ChainHash path; the per-pixel encoding/decoding work is
// identical to the serial path. Non-batched primitives (BatchHash nil)
// route directly to the legacy serial loop. The pure-Go counterpart of
// the batched dispatch in process_cgo.go.
func processChunk256(cfg *Config, noiseSeed, dataSeed *Seed256, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool) {
	bitIndex := startP * DataBitsPerPixel

	noiseBuf := make([]byte, 4+currentNonceSizeCfg(cfg))
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 4+currentNonceSizeCfg(cfg))
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	p := startP

	if noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil {
		var noiseBufs, dataBufs [4][]byte
		var noiseBufPtrs, dataBufPtrs [4]*[]byte
		noiseBufs[0] = noiseBuf
		dataBufs[0] = dataBuf
		for lane := 1; lane < 4; lane++ {
			noiseBufPtrs[lane], noiseBufs[lane] = acquireBuffer(4 + currentNonceSizeCfg(cfg))
			copy(noiseBufs[lane][4:], nonce)
			dataBufPtrs[lane], dataBufs[lane] = acquireBuffer(4 + currentNonceSizeCfg(cfg))
			copy(dataBufs[lane][4:], nonce)
			defer releaseBuffer(noiseBufPtrs[lane], noiseBufs[lane])
			defer releaseBuffer(dataBufPtrs[lane], dataBufs[lane])
		}

		for ; p+4 <= endP && bitIndex < totalBits; p += 4 {
			pixelIndices := [4]int{p, p + 1, p + 2, p + 3}
			noiseHashes := noiseSeed.blockHash256x4(&noiseBufs, pixelIndices)
			dataHashes := dataSeed.blockHash256x4(&dataBufs, pixelIndices)

			for lane := 0; lane < 4 && bitIndex < totalBits; lane++ {
				pp := p + lane
				linearIdx := (startPixel + pp) % totalPixels
				pixelOffset := linearIdx * Channels

				noiseHash := noiseHashes[lane][0]
				dataHash := dataHashes[lane][0]

				noisePos := uint(noiseHash & 7)
				noiseMask := byte(1 << noisePos)

				dataRotation := uint(dataHash % 7)
				xorMask := dataHash >> DataRotationBits

				if encode {
					for ch := 0; ch < Channels && bitIndex < totalBits; ch++ {
						channelXOR := byte((xorMask >> uint(ch*DataBitsPerChannel)) & 0x7F)

						byteIdx := bitIndex / 8
						bitOff := uint(bitIndex % 8)

						var raw uint16
						raw = uint16(data[byteIdx])
						if byteIdx+1 < len(data) {
							raw |= uint16(data[byteIdx+1]) << 8
						}
						dataBits := byte((raw >> bitOff) & 0x7F)

						dataBits ^= channelXOR
						dataBits = rotateBits7(dataBits, dataRotation)

						orig := container[pixelOffset+ch]
						low := dataBits & byte(noiseMask-1)
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
						low := channelByte & byte(noiseMask-1)
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
	}

	for ; p < endP && bitIndex < totalBits; p++ {
		linearIdx := (startPixel + p) % totalPixels
		pixelOffset := linearIdx * Channels

		noiseH := noiseSeed.blockHash256(noiseBuf, p)
		dataH := dataSeed.blockHash256(dataBuf, p)
		noiseHash := noiseH[0]
		dataHash := dataH[0]

		noisePos := uint(noiseHash & 7)
		noiseMask := byte(1 << noisePos)

		dataRotation := uint(dataHash % 7)
		xorMask := dataHash >> DataRotationBits

		if encode {
			for ch := 0; ch < Channels && bitIndex < totalBits; ch++ {
				channelXOR := byte((xorMask >> uint(ch*DataBitsPerChannel)) & 0x7F)

				byteIdx := bitIndex / 8
				bitOff := uint(bitIndex % 8)

				var raw uint16
				raw = uint16(data[byteIdx])
				if byteIdx+1 < len(data) {
					raw |= uint16(data[byteIdx+1]) << 8
				}
				dataBits := byte((raw >> bitOff) & 0x7F)

				dataBits ^= channelXOR
				dataBits = rotateBits7(dataBits, dataRotation)

				orig := container[pixelOffset+ch]
				low := dataBits & byte(noiseMask-1)
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
				low := channelByte & byte(noiseMask-1)
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

// processChunk512 processes pixels [startP, endP) of the data stream (512-bit variant).
//
// Batched dispatch when both seeds expose BatchHash; structurally
// identical to processChunk256 with 8-uint64 hash outputs in place of
// 4-uint64 ones. Pure Go counterpart of the 512-bit batched path in
// process_cgo.go.
func processChunk512(cfg *Config, noiseSeed, dataSeed *Seed512, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool) {
	bitIndex := startP * DataBitsPerPixel

	noiseBuf := make([]byte, 4+currentNonceSizeCfg(cfg))
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 4+currentNonceSizeCfg(cfg))
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	p := startP

	if noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil {
		var noiseBufs, dataBufs [4][]byte
		var noiseBufPtrs, dataBufPtrs [4]*[]byte
		noiseBufs[0] = noiseBuf
		dataBufs[0] = dataBuf
		for lane := 1; lane < 4; lane++ {
			noiseBufPtrs[lane], noiseBufs[lane] = acquireBuffer(4 + currentNonceSizeCfg(cfg))
			copy(noiseBufs[lane][4:], nonce)
			dataBufPtrs[lane], dataBufs[lane] = acquireBuffer(4 + currentNonceSizeCfg(cfg))
			copy(dataBufs[lane][4:], nonce)
			defer releaseBuffer(noiseBufPtrs[lane], noiseBufs[lane])
			defer releaseBuffer(dataBufPtrs[lane], dataBufs[lane])
		}

		for ; p+4 <= endP && bitIndex < totalBits; p += 4 {
			pixelIndices := [4]int{p, p + 1, p + 2, p + 3}
			noiseHashes := noiseSeed.blockHash512x4(&noiseBufs, pixelIndices)
			dataHashes := dataSeed.blockHash512x4(&dataBufs, pixelIndices)

			for lane := 0; lane < 4 && bitIndex < totalBits; lane++ {
				pp := p + lane
				linearIdx := (startPixel + pp) % totalPixels
				pixelOffset := linearIdx * Channels

				noiseHash := noiseHashes[lane][0]
				dataHash := dataHashes[lane][0]

				noisePos := uint(noiseHash & 7)
				noiseMask := byte(1 << noisePos)

				dataRotation := uint(dataHash % 7)
				xorMask := dataHash >> DataRotationBits

				if encode {
					for ch := 0; ch < Channels && bitIndex < totalBits; ch++ {
						channelXOR := byte((xorMask >> uint(ch*DataBitsPerChannel)) & 0x7F)

						byteIdx := bitIndex / 8
						bitOff := uint(bitIndex % 8)

						var raw uint16
						raw = uint16(data[byteIdx])
						if byteIdx+1 < len(data) {
							raw |= uint16(data[byteIdx+1]) << 8
						}
						dataBits := byte((raw >> bitOff) & 0x7F)

						dataBits ^= channelXOR
						dataBits = rotateBits7(dataBits, dataRotation)

						orig := container[pixelOffset+ch]
						low := dataBits & byte(noiseMask-1)
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
						low := channelByte & byte(noiseMask-1)
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
	}

	for ; p < endP && bitIndex < totalBits; p++ {
		linearIdx := (startPixel + p) % totalPixels
		pixelOffset := linearIdx * Channels

		noiseH := noiseSeed.blockHash512(noiseBuf, p)
		dataH := dataSeed.blockHash512(dataBuf, p)
		noiseHash := noiseH[0]
		dataHash := dataH[0]

		noisePos := uint(noiseHash & 7)
		noiseMask := byte(1 << noisePos)

		dataRotation := uint(dataHash % 7)
		xorMask := dataHash >> DataRotationBits

		if encode {
			for ch := 0; ch < Channels && bitIndex < totalBits; ch++ {
				channelXOR := byte((xorMask >> uint(ch*DataBitsPerChannel)) & 0x7F)

				byteIdx := bitIndex / 8
				bitOff := uint(bitIndex % 8)

				var raw uint16
				raw = uint16(data[byteIdx])
				if byteIdx+1 < len(data) {
					raw |= uint16(data[byteIdx+1]) << 8
				}
				dataBits := byte((raw >> bitOff) & 0x7F)

				dataBits ^= channelXOR
				dataBits = rotateBits7(dataBits, dataRotation)

				orig := container[pixelOffset+ch]
				low := dataBits & byte(noiseMask-1)
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
				low := channelByte & byte(noiseMask-1)
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
