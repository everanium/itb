//go:build !cgo

package itb

// processChunk processes pixels [startP, endP) of the data stream.
// Each chunk operates on independent bit ranges — no synchronization needed.
func processChunk(noiseSeed, dataSeed *Seed, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool) {
	bitIndex := startP * DataBitsPerPixel

	noiseBuf := make([]byte, 20)
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 20)
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	for p := startP; p < endP && bitIndex < totalBits; p++ {
		linearIdx := (startPixel + p) % totalPixels
		pixelOffset := linearIdx * Channels

		noiseHash := noiseSeed.blockHash(noiseBuf, p)
		dataHash := dataSeed.blockHash(dataBuf, p)

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

// processChunk128 processes pixels [startP, endP) of the data stream (128-bit variant).
func processChunk128(noiseSeed, dataSeed *Seed128, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool) {
	bitIndex := startP * DataBitsPerPixel

	noiseBuf := make([]byte, 20)
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 20)
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	for p := startP; p < endP && bitIndex < totalBits; p++ {
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

// processChunk512 processes pixels [startP, endP) of the data stream (512-bit variant).
func processChunk512(noiseSeed, dataSeed *Seed512, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool) {
	bitIndex := startP * DataBitsPerPixel

	noiseBuf := make([]byte, 20)
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 20)
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	for p := startP; p < endP && bitIndex < totalBits; p++ {
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

// processChunk256 processes pixels [startP, endP) of the data stream (256-bit variant).
func processChunk256(noiseSeed, dataSeed *Seed256, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool) {
	bitIndex := startP * DataBitsPerPixel

	noiseBuf := make([]byte, 20)
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 20)
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	for p := startP; p < endP && bitIndex < totalBits; p++ {
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
