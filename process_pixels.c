#include <stdint.h>
#include <string.h>

// AVX2 auto-vectorization is enabled via cgo CFLAGS (-mavx2 on amd64).
// No platform-specific intrinsics are used — all SIMD comes from GCC -O3.

// rotateBits7 rotates a 7-bit value left by rotation positions.
static inline uint8_t rotateBits7(uint8_t val, unsigned int rotation) {
    val &= 0x7F;
    return ((val << rotation) | (val >> (7 - rotation))) & 0x7F;
}

// extract56bits reads 56 contiguous bits from data starting at bitIndex
// and unpacks them into 8×7-bit values in vals[0..7].
// Uses bulk 64-bit read + shift for the bit-stream extraction,
// then 8 individual shifts for 7-bit field separation.
static inline void extract56bits(const uint8_t *data, int dataLen, int bitIndex, uint8_t *vals) {
    int byteIdx = bitIndex / 8;
    unsigned int bitOff = (unsigned int)(bitIndex % 8);

    // Read up to 8 bytes (64 bits) to cover 56 bits at arbitrary offset.
    uint64_t raw = 0;
    int avail = dataLen - byteIdx;
    if (avail >= 8) {
        memcpy(&raw, &data[byteIdx], 8);
    } else if (avail > 0) {
        memcpy(&raw, &data[byteIdx], avail);
    }
    raw >>= bitOff;

    // Unrolled extraction: 8×7-bit fields from contiguous 56-bit word.
    vals[0] = (uint8_t)( raw        & 0x7F);
    vals[1] = (uint8_t)((raw >>  7) & 0x7F);
    vals[2] = (uint8_t)((raw >> 14) & 0x7F);
    vals[3] = (uint8_t)((raw >> 21) & 0x7F);
    vals[4] = (uint8_t)((raw >> 28) & 0x7F);
    vals[5] = (uint8_t)((raw >> 35) & 0x7F);
    vals[6] = (uint8_t)((raw >> 42) & 0x7F);
    vals[7] = (uint8_t)((raw >> 49) & 0x7F);
}

// pack56bits packs 8×7-bit values into a 56-bit word and writes to data.
static inline void pack56bits(uint8_t *data, int dataLen, int bitIndex, const uint8_t *vals, int chCount) {
    uint64_t packed = 0;
    for (int ch = 0; ch < chCount; ch++) {
        packed |= (uint64_t)(vals[ch] & 0x7F) << (unsigned)(ch * 7);
    }

    int byteStart = bitIndex / 8;
    int bytesToWrite = (chCount * 7 + 7) / 8;
    // Write up to 7 bytes. Use memcpy for unaligned write when possible.
    if (bytesToWrite <= 7 && byteStart + bytesToWrite <= dataLen) {
        // Direct write — safe because 56 bits = 7 bytes max.
        for (int i = 0; i < bytesToWrite; i++) {
            data[byteStart + i] = (uint8_t)(packed >> (unsigned)(i * 8));
        }
    }
}

// itb_process_pixels performs per-pixel encode/decode using pre-computed hashes.
// Structured for SIMD auto-vectorization: all 8 channels per pixel processed
// in separate phases (extract → XOR → rotate → insert), enabling GCC -O3 -mavx2
// to vectorize each phase independently.
// GCC -O3 auto-vectorizes the per-channel loops (XOR, rotate, insert/extract).
void itb_process_pixels(
    const uint64_t *noiseHashes,
    const uint64_t *dataHashes,
    uint8_t *container,
    uint8_t *data,
    int dataLen,
    int startPixel,
    int totalPixels,
    int startP,
    int endP,
    int totalBits,
    int encode
) {
    const int Channels = 8;
    const int DataBitsPerChannel = 7;
    const int DataBitsPerPixel = 56;
    const int DataRotationBits = 3;

    int bitIndex = startP * DataBitsPerPixel;

    for (int p = 0; p < endP - startP && bitIndex < totalBits; p++) {
        int linearIdx = (startPixel + startP + p) % totalPixels;
        int pixelOffset = linearIdx * Channels;

        uint64_t noiseHash = noiseHashes[p];
        uint64_t dataHash = dataHashes[p];

        unsigned int noisePos = (unsigned int)(noiseHash & 7);
        uint8_t noiseMask = (uint8_t)(1 << noisePos);
        uint8_t noiseMaskBelow = noiseMask - 1;

        unsigned int dataRotation = (unsigned int)(dataHash % 7);
        unsigned int dataRotationInv = 7 - dataRotation;
        uint64_t xorMask = dataHash >> DataRotationBits;

        // Determine how many channels carry data in this pixel.
        int chCount = Channels;
        int bitsLeft = totalBits - bitIndex;
        if (bitsLeft < DataBitsPerPixel) {
            chCount = (bitsLeft + DataBitsPerChannel - 1) / DataBitsPerChannel;
        }

        if (encode) {
            // Phase 1: Bulk extract 56 bits into 8×7-bit values.
            uint8_t vals[8];
            extract56bits(data, dataLen, bitIndex, vals);

            // Phase 2: Extract XOR masks from xorMask uint64.
            uint8_t xors[8];
            for (int ch = 0; ch < chCount; ch++) {
                xors[ch] = (uint8_t)((xorMask >> (unsigned)(ch * DataBitsPerChannel)) & 0x7F);
            }

            // Phase 3: XOR — 8 independent values, auto-vectorizable.
            for (int ch = 0; ch < chCount; ch++) {
                vals[ch] ^= xors[ch];
            }

            // Phase 4: Rotate — same rotation for all channels, auto-vectorizable.
            for (int ch = 0; ch < chCount; ch++) {
                vals[ch] = rotateBits7(vals[ch], dataRotation);
            }

            // Phase 5: Insert into container around noise bit.
            for (int ch = 0; ch < chCount; ch++) {
                uint8_t orig = container[pixelOffset + ch];
                uint8_t low = vals[ch] & noiseMaskBelow;
                uint8_t high = vals[ch] >> noisePos;
                container[pixelOffset + ch] = low | (orig & noiseMask) | (high << (noisePos + 1));
            }

            bitIndex += chCount * DataBitsPerChannel;
            if (bitIndex > totalBits) bitIndex = totalBits;
        } else {
            // Phase 1: Load container bytes, extract data bits (remove noise).
            uint8_t vals[8];
            for (int ch = 0; ch < chCount; ch++) {
                uint8_t channelByte = container[pixelOffset + ch];
                uint8_t low = channelByte & noiseMaskBelow;
                uint8_t high = channelByte >> (noisePos + 1);
                vals[ch] = low | (high << noisePos);
            }

            // Phase 2: Reverse rotate — same inverse rotation, auto-vectorizable.
            for (int ch = 0; ch < chCount; ch++) {
                vals[ch] = rotateBits7(vals[ch], dataRotationInv);
            }

            // Phase 3: XOR — 8 independent values, auto-vectorizable.
            for (int ch = 0; ch < chCount; ch++) {
                vals[ch] ^= (uint8_t)((xorMask >> (unsigned)(ch * DataBitsPerChannel)) & 0x7F);
            }

            // Phase 4: Pack 8×7-bit values into data byte stream.
            pack56bits(data, dataLen, bitIndex, vals, chCount);

            bitIndex += chCount * DataBitsPerChannel;
        }
    }
}
