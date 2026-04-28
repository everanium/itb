#include <stdint.h>
#include <string.h>

// AVX2 auto-vectorization is enabled via cgo CFLAGS (-mavx2 on amd64).
// On x86_64 with GFNI present, the per-pixel kernel additionally dispatches
// to a 4-pixel SIMD batch using vgf2p8affineqb for Phase 4 rotation and
// Phase 5 noise-bit insertion — two of the per-pixel operations that GCC
// auto-vectorisation cannot widen because there is no AVX2 8-bit variable
// shift. GFNI's per-byte 8x8 GF(2) affine transform replaces both with a
// single instruction parameterised by a precomputed 64-bit matrix per pixel.

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

// =============================================================================
// AVX2 + GFNI 4-pixel SIMD batch (Tier B)
//
// Builds a per-pixel 8x8 GF(2) matrix that, when fed through vgf2p8affineqb,
// implements the per-pixel variable shift directly. With the matrix layout
// Intel specifies — byte j of the qword encodes output bit j as a linear
// combination of the source byte's input bits — rotateBits7 and the
// noise-bit insert/extract become single-instruction transforms.
//
// Runtime CPU dispatch via __builtin_cpu_supports("gfni") inside the main
// function — non-GFNI hosts continue down the plain-C path verbatim.
// =============================================================================

#if defined(__GNUC__) && defined(__x86_64__)

#pragma GCC push_options
#pragma GCC target("avx2,gfni")
#include <immintrin.h>

// gfniRotMatrix builds the 8x8 GF(2) matrix that maps a 7-bit input value to
// rotateBits7(value, r). Output bit j (j in [0..6]) takes input bit
// (j - r) mod 7; output bit 7 is zero so bit 7 of the result is always
// cleared.
//
// Intel encoding (vgf2p8affineqb): output bit k of each result byte uses
// matrix qword byte (7 - k); the bit index within that matrix byte selects
// which input bit contributes to output bit k.
static inline uint64_t gfniRotMatrix(unsigned int r) {
    uint64_t m = 0;
    for (unsigned int j = 0; j < 7; j++) {
        unsigned int srcBit = (j + 7u - r) % 7u;
        m |= (uint64_t)1 << ((7u - j) * 8u + srcBit);
    }
    return m;
}

// gfniSpreadMatrix maps the 7-bit data value to the encode-side noise-bit
// insertion: output bits below noisePos copy input bits 0..(noisePos-1)
// directly; output bit at noisePos is zero (noise bit OR'd in afterwards);
// output bits above noisePos copy input bits (noisePos..6) shifted up by one.
static inline uint64_t gfniSpreadMatrix(unsigned int noisePos) {
    uint64_t m = 0;
    for (unsigned int j = 0; j < 8; j++) {
        if (j == noisePos) {
            continue;
        }
        unsigned int srcBit;
        if (j < noisePos) {
            srcBit = j;
        } else {
            srcBit = j - 1u;
        }
        m |= (uint64_t)1 << ((7u - j) * 8u + srcBit);
    }
    return m;
}

// gfniGatherMatrix is the decode-side counterpart of gfniSpreadMatrix:
// removes the noise bit at noisePos and packs the remaining 7 bits into
// the bottom 7 output bits. Output bit 7 is zero.
static inline uint64_t gfniGatherMatrix(unsigned int noisePos) {
    uint64_t m = 0;
    for (unsigned int j = 0; j < 7; j++) {
        unsigned int srcBit;
        if (j < noisePos) {
            srcBit = j;
        } else {
            srcBit = j + 1u;
        }
        m |= (uint64_t)1 << ((7u - j) * 8u + srcBit);
    }
    return m;
}

// process4PixelsEncodeAVX2GFNI processes one 4-pixel batch in encode direction.
__attribute__((target("avx2,gfni")))
static inline void process4PixelsEncodeAVX2GFNI(
    const uint64_t *noiseHashes,
    const uint64_t *dataHashes,
    uint8_t *container,
    const uint8_t *data,
    int dataLen,
    int startPixel,
    int totalPixels,
    int p,
    int bitIndex,
    int startP
) {
    const int Channels = 8;
    const int DataBitsPerChannel = 7;
    const int DataBitsPerPixel = 56;
    const int DataRotationBits = 3;

    int pixelOffset[4];
    uint8_t noiseMaskArr[4];
    uint64_t rotMatrices[4] __attribute__((aligned(32)));
    uint64_t spreadMatrices[4] __attribute__((aligned(32)));
    uint64_t xorMaskArr[4];

    for (int b = 0; b < 4; b++) {
        int linearIdx = (startPixel + startP + p + b) % totalPixels;
        pixelOffset[b] = linearIdx * Channels;
        uint64_t nh = noiseHashes[p + b];
        uint64_t dh = dataHashes[p + b];
        unsigned int np = (unsigned int)(nh & 7u);
        unsigned int dr = (unsigned int)(dh % 7u);
        noiseMaskArr[b] = (uint8_t)(1u << np);
        rotMatrices[b] = gfniRotMatrix(dr);
        spreadMatrices[b] = gfniSpreadMatrix(np);
        xorMaskArr[b] = dh >> DataRotationBits;
    }

    // Phase 1: extract 4×56 bits into 32-byte buffer.
    uint8_t valsBuf[32] __attribute__((aligned(32)));
    for (int b = 0; b < 4; b++) {
        extract56bits(data, dataLen, bitIndex + b * DataBitsPerPixel, &valsBuf[b * Channels]);
    }
    __m256i vals = _mm256_load_si256((const __m256i *)valsBuf);

    // Phase 2: derive per-pixel xor masks (8 bytes per pixel).
    uint8_t xorsBuf[32] __attribute__((aligned(32)));
    for (int b = 0; b < 4; b++) {
        for (int ch = 0; ch < Channels; ch++) {
            xorsBuf[b * Channels + ch] = (uint8_t)((xorMaskArr[b] >> (unsigned)(ch * DataBitsPerChannel)) & 0x7F);
        }
    }
    __m256i xors = _mm256_load_si256((const __m256i *)xorsBuf);

    // Phase 3: XOR (single VPXOR ymm).
    vals = _mm256_xor_si256(vals, xors);

    // Phase 4: rotate via GFNI affine transform — one VGF2P8AFFINEQB.
    __m256i rotMat = _mm256_load_si256((const __m256i *)rotMatrices);
    vals = _mm256_gf2p8affine_epi64_epi8(vals, rotMat, 0);

    // Phase 5: spread bits around per-pixel noisePos via GFNI, then OR with the
    // preserved noise bit from the original container byte.
    __m256i spreadMat = _mm256_load_si256((const __m256i *)spreadMatrices);
    __m256i spreadVals = _mm256_gf2p8affine_epi64_epi8(vals, spreadMat, 0);

    uint8_t origBuf[32] __attribute__((aligned(32)));
    for (int b = 0; b < 4; b++) {
        memcpy(&origBuf[b * Channels], &container[pixelOffset[b]], Channels);
    }
    __m256i orig = _mm256_load_si256((const __m256i *)origBuf);

    // Broadcast per-pixel noiseMask byte to all 8 lanes within each pixel.
    __m256i noiseMaskV = _mm256_set_epi64x(
        (int64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[3],
        (int64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[2],
        (int64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[1],
        (int64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[0]);

    __m256i result = _mm256_or_si256(spreadVals, _mm256_and_si256(orig, noiseMaskV));

    uint8_t outBuf[32] __attribute__((aligned(32)));
    _mm256_store_si256((__m256i *)outBuf, result);
    for (int b = 0; b < 4; b++) {
        memcpy(&container[pixelOffset[b]], &outBuf[b * Channels], Channels);
    }
}

// process4PixelsDecodeAVX2GFNI processes one 4-pixel batch in decode direction.
__attribute__((target("avx2,gfni")))
static inline void process4PixelsDecodeAVX2GFNI(
    const uint64_t *noiseHashes,
    const uint64_t *dataHashes,
    const uint8_t *container,
    uint8_t *data,
    int dataLen,
    int startPixel,
    int totalPixels,
    int p,
    int bitIndex,
    int startP
) {
    const int Channels = 8;
    const int DataBitsPerChannel = 7;
    const int DataBitsPerPixel = 56;
    const int DataRotationBits = 3;

    int pixelOffset[4];
    uint64_t invRotMatrices[4] __attribute__((aligned(32)));
    uint64_t gatherMatrices[4] __attribute__((aligned(32)));
    uint64_t xorMaskArr[4];

    for (int b = 0; b < 4; b++) {
        int linearIdx = (startPixel + startP + p + b) % totalPixels;
        pixelOffset[b] = linearIdx * Channels;
        uint64_t nh = noiseHashes[p + b];
        uint64_t dh = dataHashes[p + b];
        unsigned int np = (unsigned int)(nh & 7u);
        unsigned int dr = (unsigned int)(dh % 7u);
        // Inverse rotation amount for decode: 7 - r (mod 7).
        unsigned int dri = (7u - dr) % 7u;
        invRotMatrices[b] = gfniRotMatrix(dri);
        gatherMatrices[b] = gfniGatherMatrix(np);
        xorMaskArr[b] = dh >> DataRotationBits;
    }

    // Phase 1: load 4 pixels' container bytes, gather data bits via GFNI.
    uint8_t origBuf[32] __attribute__((aligned(32)));
    for (int b = 0; b < 4; b++) {
        memcpy(&origBuf[b * Channels], &container[pixelOffset[b]], Channels);
    }
    __m256i orig = _mm256_load_si256((const __m256i *)origBuf);
    __m256i gatherMat = _mm256_load_si256((const __m256i *)gatherMatrices);
    __m256i vals = _mm256_gf2p8affine_epi64_epi8(orig, gatherMat, 0);

    // Phase 2: reverse rotate via GFNI.
    __m256i invRotMat = _mm256_load_si256((const __m256i *)invRotMatrices);
    vals = _mm256_gf2p8affine_epi64_epi8(vals, invRotMat, 0);

    // Phase 3: XOR with per-pixel xor masks.
    uint8_t xorsBuf[32] __attribute__((aligned(32)));
    for (int b = 0; b < 4; b++) {
        for (int ch = 0; ch < Channels; ch++) {
            xorsBuf[b * Channels + ch] = (uint8_t)((xorMaskArr[b] >> (unsigned)(ch * DataBitsPerChannel)) & 0x7F);
        }
    }
    __m256i xors = _mm256_load_si256((const __m256i *)xorsBuf);
    vals = _mm256_xor_si256(vals, xors);

    // Phase 4: pack 8×7-bit values per pixel back into the data byte stream.
    uint8_t valsBuf[32] __attribute__((aligned(32)));
    _mm256_store_si256((__m256i *)valsBuf, vals);
    for (int b = 0; b < 4; b++) {
        pack56bits(data, dataLen, bitIndex + b * DataBitsPerPixel, &valsBuf[b * Channels], Channels);
    }
}

// itb_simd_avx2_gfni_supported caches the runtime CPU feature detection so the
// hot loop reads a hoisted flag rather than calling __builtin_cpu_supports per
// chunk. -1 means uninitialised; resolved on first call.
static int itb_simd_avx2_gfni_supported = -1;

static inline int itb_check_avx2_gfni(void) {
    int v = itb_simd_avx2_gfni_supported;
    if (v < 0) {
        v = __builtin_cpu_supports("avx2") && __builtin_cpu_supports("gfni") ? 1 : 0;
        itb_simd_avx2_gfni_supported = v;
    }
    return v;
}

#pragma GCC pop_options

// =============================================================================
// AVX-512 + GFNI 8-pixel SIMD batch (Tier A)
//
// Doubles the batch width to 8 pixels (= 64 bytes = one ZMM register). The
// GFNI 8x8 GF(2) matrices encoded by gfniRotMatrix / gfniSpreadMatrix /
// gfniGatherMatrix are reused verbatim — vgf2p8affineqb operates per qword
// regardless of register width, so the same per-pixel matrix layout extends
// to ZMM unchanged.
// =============================================================================

#pragma GCC push_options
#pragma GCC target("avx512f,avx512bw,avx512vl,gfni,avx512vbmi")

// Field-extraction shift control for VPMULTISHIFTQB. Each byte j of the qword
// holds the bit offset for output byte j: { 0, 7, 14, 21, 28, 35, 42, 49 }.
// In little-endian uint64 layout: byte 0 = 0x00 (LSB), byte 7 = 0x31 (MSB).
#define ITB_VBMI_FIELD_SHIFTS 0x312A231C150E0700ULL

// extract56bitsX8AVX512VBMI reads 64 contiguous bytes starting at
// (data + baseByteIdx), realigns them so each ZMM lane holds one pixel's
// 8-byte source uint64, applies the per-batch right shift bitOff, and
// extracts 8×7-bit fields per pixel via VPMULTISHIFTQB. Output is one ZMM
// register laid out as [pixel 0..7] × [field 0..7], 64 bytes total.
//
// Caller responsibility: data must have at least baseByteIdx + 64 bytes
// readable. The encode dispatch falls back to the scalar tail when the
// remaining data is shorter than 64 bytes, so this constraint is
// satisfied by construction inside the 8-pixel batched while loop.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni,avx512vbmi")))
static inline __m512i extract56bitsX8AVX512VBMI(const uint8_t *data, int baseByteIdx, unsigned int bitOff) {
    // Permutation control: output byte i = source byte (i / 8) * 7 + (i % 8).
    // Pixel b spans source bytes [b*7 .. b*7 + 7]; pixel 7 ends at byte 56,
    // so the full 64-byte permutation index fits within the 64-byte load.
    static const uint8_t permBytes[64] __attribute__((aligned(64))) = {
        0,  1,  2,  3,  4,  5,  6,  7,
        7,  8,  9, 10, 11, 12, 13, 14,
       14, 15, 16, 17, 18, 19, 20, 21,
       21, 22, 23, 24, 25, 26, 27, 28,
       28, 29, 30, 31, 32, 33, 34, 35,
       35, 36, 37, 38, 39, 40, 41, 42,
       42, 43, 44, 45, 46, 47, 48, 49,
       49, 50, 51, 52, 53, 54, 55, 56,
    };
    __m512i bigload = _mm512_loadu_si512((const void *)(data + baseByteIdx));
    __m512i permIdx = _mm512_load_si512((const void *)permBytes);
    __m512i arranged = _mm512_permutexvar_epi8(permIdx, bigload);
    // bitOff is identical for all 8 pixels in a batch because 56 bits per
    // pixel is divisible by 8 — only baseBitIndex % 8 matters.
    __m512i shifted = _mm512_srli_epi64(arranged, bitOff);
    __m512i shifts = _mm512_set1_epi64((long long)ITB_VBMI_FIELD_SHIFTS);
    __m512i extracted = _mm512_multishift_epi64_epi8(shifts, shifted);
    return _mm512_and_si512(extracted, _mm512_set1_epi8(0x7F));
}

// deriveXorsX8AVX512VBMI extracts 8×7-bit fields from each of 8 per-pixel
// xorMask uint64 values (one per ZMM lane) via VPMULTISHIFTQB. Output layout
// matches extract56bitsX8AVX512VBMI: 64 bytes = 8 pixels × 8 channel-bytes.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni,avx512vbmi")))
static inline __m512i deriveXorsX8AVX512VBMI(const uint64_t *xorMaskArr) {
    __m512i xorMaskV = _mm512_loadu_si512((const void *)xorMaskArr);
    __m512i shifts = _mm512_set1_epi64((long long)ITB_VBMI_FIELD_SHIFTS);
    __m512i extracted = _mm512_multishift_epi64_epi8(shifts, xorMaskV);
    return _mm512_and_si512(extracted, _mm512_set1_epi8(0x7F));
}

// process8PixelsEncodeAVX512GFNI processes one 8-pixel batch in encode direction.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni,avx512vbmi")))
static inline void process8PixelsEncodeAVX512GFNI(
    const uint64_t *noiseHashes,
    const uint64_t *dataHashes,
    uint8_t *container,
    const uint8_t *data,
    int dataLen,
    int startPixel,
    int totalPixels,
    int p,
    int bitIndex,
    int startP
) {
    const int Channels = 8;
    const int DataBitsPerChannel = 7;
    const int DataBitsPerPixel = 56;
    const int DataRotationBits = 3;

    int pixelOffset[8];
    uint8_t noiseMaskArr[8];
    uint64_t rotMatrices[8] __attribute__((aligned(64)));
    uint64_t spreadMatrices[8] __attribute__((aligned(64)));
    uint64_t xorMaskArr[8];

    for (int b = 0; b < 8; b++) {
        int linearIdx = (startPixel + startP + p + b) % totalPixels;
        pixelOffset[b] = linearIdx * Channels;
        uint64_t nh = noiseHashes[p + b];
        uint64_t dh = dataHashes[p + b];
        unsigned int np = (unsigned int)(nh & 7u);
        unsigned int dr = (unsigned int)(dh % 7u);
        noiseMaskArr[b] = (uint8_t)(1u << np);
        rotMatrices[b] = gfniRotMatrix(dr);
        spreadMatrices[b] = gfniSpreadMatrix(np);
        xorMaskArr[b] = dh >> DataRotationBits;
    }

    // Phase 1: extract 8×56 bits via VPERMB + variable-shift + VPMULTISHIFTQB.
    // Replaces 8 scalar extract56bits calls (~88 ops) with 5 ZMM ops. Bounds
    // are guaranteed by the dispatch in itb_process_pixels — the AVX-512+VBMI
    // 8-pixel loop only fires while baseByteIdx + 64 <= dataLen (see the
    // dataLen guard in the while condition there).
    int baseByteIdx = bitIndex / 8;
    unsigned int bitOff = (unsigned int)(bitIndex % 8);
    __m512i vals = extract56bitsX8AVX512VBMI(data, baseByteIdx, bitOff);

    // Phase 2: derive per-pixel xor masks via VPMULTISHIFTQB on the 8 uint64s.
    // Replaces 8×8 scalar shift+mask (128 ops) with 3 ZMM ops.
    __m512i xors = deriveXorsX8AVX512VBMI(xorMaskArr);

    // Phase 3: XOR (single VPXORQ zmm).
    vals = _mm512_xor_si512(vals, xors);

    // Phase 4: rotate via GFNI affine transform — one VGF2P8AFFINEQB on ZMM.
    __m512i rotMat = _mm512_loadu_si512((const void *)rotMatrices);
    vals = _mm512_gf2p8affine_epi64_epi8(vals, rotMat, 0);

    // Phase 5: spread bits around per-pixel noisePos via GFNI, then OR with
    // the preserved noise bit from each pixel's original container byte.
    __m512i spreadMat = _mm512_loadu_si512((const void *)spreadMatrices);
    __m512i spreadVals = _mm512_gf2p8affine_epi64_epi8(vals, spreadMat, 0);

    uint8_t origBuf[64] __attribute__((aligned(64)));
    for (int b = 0; b < 8; b++) {
        memcpy(&origBuf[b * Channels], &container[pixelOffset[b]], Channels);
    }
    __m512i orig = _mm512_loadu_si512((const void *)origBuf);

    __m512i noiseMaskV = _mm512_set_epi64(
        (long long)((uint64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[7]),
        (long long)((uint64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[6]),
        (long long)((uint64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[5]),
        (long long)((uint64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[4]),
        (long long)((uint64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[3]),
        (long long)((uint64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[2]),
        (long long)((uint64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[1]),
        (long long)((uint64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[0]));

    __m512i result = _mm512_or_si512(spreadVals, _mm512_and_si512(orig, noiseMaskV));

    uint8_t outBuf[64] __attribute__((aligned(64)));
    _mm512_storeu_si512((void *)outBuf, result);
    for (int b = 0; b < 8; b++) {
        memcpy(&container[pixelOffset[b]], &outBuf[b * Channels], Channels);
    }
}

// process8PixelsDecodeAVX512GFNI processes one 8-pixel batch in decode direction.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni,avx512vbmi")))
static inline void process8PixelsDecodeAVX512GFNI(
    const uint64_t *noiseHashes,
    const uint64_t *dataHashes,
    const uint8_t *container,
    uint8_t *data,
    int dataLen,
    int startPixel,
    int totalPixels,
    int p,
    int bitIndex,
    int startP
) {
    const int Channels = 8;
    const int DataBitsPerChannel = 7;
    const int DataBitsPerPixel = 56;
    const int DataRotationBits = 3;

    int pixelOffset[8];
    uint64_t invRotMatrices[8] __attribute__((aligned(64)));
    uint64_t gatherMatrices[8] __attribute__((aligned(64)));
    uint64_t xorMaskArr[8];

    for (int b = 0; b < 8; b++) {
        int linearIdx = (startPixel + startP + p + b) % totalPixels;
        pixelOffset[b] = linearIdx * Channels;
        uint64_t nh = noiseHashes[p + b];
        uint64_t dh = dataHashes[p + b];
        unsigned int np = (unsigned int)(nh & 7u);
        unsigned int dr = (unsigned int)(dh % 7u);
        unsigned int dri = (7u - dr) % 7u;
        invRotMatrices[b] = gfniRotMatrix(dri);
        gatherMatrices[b] = gfniGatherMatrix(np);
        xorMaskArr[b] = dh >> DataRotationBits;
    }

    // Phase 1: load 8 pixels' container bytes, gather data bits via GFNI.
    uint8_t origBuf[64] __attribute__((aligned(64)));
    for (int b = 0; b < 8; b++) {
        memcpy(&origBuf[b * Channels], &container[pixelOffset[b]], Channels);
    }
    __m512i orig = _mm512_loadu_si512((const void *)origBuf);
    __m512i gatherMat = _mm512_loadu_si512((const void *)gatherMatrices);
    __m512i vals = _mm512_gf2p8affine_epi64_epi8(orig, gatherMat, 0);

    // Phase 2: reverse rotate via GFNI.
    __m512i invRotMat = _mm512_loadu_si512((const void *)invRotMatrices);
    vals = _mm512_gf2p8affine_epi64_epi8(vals, invRotMat, 0);

    // Phase 3: XOR with per-pixel xor masks. Derive via VPMULTISHIFTQB
    // (3 ZMM ops vs 128 scalar shifts/masks) — same helper as encode.
    __m512i xors = deriveXorsX8AVX512VBMI(xorMaskArr);
    vals = _mm512_xor_si512(vals, xors);

    // Phase 4: pack 8×7-bit values per pixel back into the data byte stream.
    uint8_t valsBuf[64] __attribute__((aligned(64)));
    _mm512_storeu_si512((void *)valsBuf, vals);
    for (int b = 0; b < 8; b++) {
        pack56bits(data, dataLen, bitIndex + b * DataBitsPerPixel, &valsBuf[b * Channels], Channels);
    }
}

// itb_simd_avx512_gfni_supported caches the AVX-512+GFNI feature detection.
// -1 means uninitialised; resolved on first call.
static int itb_simd_avx512_gfni_supported = -1;

static inline int itb_check_avx512_gfni(void) {
    int v = itb_simd_avx512_gfni_supported;
    if (v < 0) {
        // Target attributes on the Tier A helpers list five features:
        //   avx512f      — base AVX-512 ZMM ops
        //   avx512bw     — byte+word ops on ZMM (GCC 12 strict requirement)
        //   avx512vl     — vector-length flexibility (GCC 12 strict requirement)
        //   gfni         — VGF2P8AFFINEQB for Phase 4/5 affine transforms
        //   avx512vbmi   — VPERMB / VPMULTISHIFTQB for Phase 1/2 field
        //                  extraction; see extract56bitsX8AVX512VBMI and
        //                  deriveXorsX8AVX512VBMI
        // Hosts missing any of these fall back to the Tier B AVX2+GFNI path
        // (or to plain-C if AVX2+GFNI also unavailable).
        v = __builtin_cpu_supports("avx512f")
            && __builtin_cpu_supports("avx512bw")
            && __builtin_cpu_supports("avx512vl")
            && __builtin_cpu_supports("gfni")
            && __builtin_cpu_supports("avx512vbmi") ? 1 : 0;
        itb_simd_avx512_gfni_supported = v;
    }
    return v;
}

#pragma GCC pop_options

#endif  // x86_64 with GFNI

// itb_process_pixels performs per-pixel encode/decode using pre-computed hashes.
// Two-stage layout: a 4-pixel batched outer loop runs while four full-chCount
// pixels still fit in the remaining bit budget, packing per-pixel data into
// vals[4][8] / xors[4][8] arrays (32 bytes each) so GCC -O3 -mavx2
// auto-vectorises the byte-parallel phases (Phase 3 XOR, the channel-byte
// load/store in extract/insert) to single YMM ops. Phases 4 (rotate) and 5
// (insert) stay scalar-unrolled because their per-pixel variable shifts have
// no AVX2 8-bit variable-shift primitive — explicit intrinsics for those land
// in a separate change. The scalar tail loop handles 0-3 leftover pixels and
// any pixel with partial chCount (last pixel of an underfull bit budget).
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstringop-overflow"
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
    // Prefetch distance — fetch upcoming pixels' container slots into L2
    // while current pixel is processed. 8 pixels ≈ 64 bytes (one cache
    // line) of container, hides ~30-50 ns of L2/L3 latency on Zen 5 and
    // Intel client/server alike. Independent of any future per-pixel
    // SIMD restructuring — the hint just preloads container[] memory.
    const int PrefetchDistance = 8;

    int bitIndex = startP * DataBitsPerPixel;
    int p = 0;
    const int totalP = endP - startP;

    // SIMD dispatch flags — hoisted once before the hot loop. On x86_64 with
    // GFNI the per-pixel kernel routes into the AVX-512+GFNI 8-pixel helpers
    // first (when available), then the AVX2+GFNI 4-pixel helpers for any
    // 4-7 leftover pixels, then the plain-C path for the final 0-3 tail.
    // Hosts without GFNI fall through to the plain-C path verbatim.
#if defined(__GNUC__) && defined(__x86_64__)
    const int useAVX512GFNI = itb_check_avx512_gfni();
    const int useAVX2GFNI = itb_check_avx2_gfni();
#else
    const int useAVX512GFNI = 0;
    const int useAVX2GFNI = 0;
#endif

#if defined(__GNUC__) && defined(__x86_64__)
    if (useAVX512GFNI) {
        // 8-pixel batched ZMM loop — runs while eight full-chCount pixels
        // still fit in the remaining bit budget. Leftover 0-7 pixels fall
        // through to the 4-pixel AVX2+GFNI loop and the scalar tail below.
        //
        // Encode-side additionally requires bitIndex/8 + 64 <= dataLen so
        // the VPERMB+VPMULTISHIFTQB extract56bitsX8 helper can do its
        // 64-byte unaligned load without overrunning data[]; the remaining
        // 0-7 (encode) or 0-7 (decode) pixels of the last batch fall to
        // the AVX2 4-pixel and scalar tails which carry their own narrow
        // bounds handling.
        if (encode) {
            while (p + 8 <= totalP && bitIndex + 8 * DataBitsPerPixel <= totalBits
                   && bitIndex / 8 + 64 <= dataLen) {
                if (p + PrefetchDistance < totalP) {
                    int prefetchIdx = (startPixel + startP + p + PrefetchDistance) % totalPixels;
                    __builtin_prefetch(&container[prefetchIdx * Channels], 1, 0);
                }
                process8PixelsEncodeAVX512GFNI(noiseHashes, dataHashes, container, data, dataLen,
                                                startPixel, totalPixels, p, bitIndex, startP);
                p += 8;
                bitIndex += 8 * DataBitsPerPixel;
            }
        } else {
            while (p + 8 <= totalP && bitIndex + 8 * DataBitsPerPixel <= totalBits) {
                if (p + PrefetchDistance < totalP) {
                    int prefetchIdx = (startPixel + startP + p + PrefetchDistance) % totalPixels;
                    __builtin_prefetch(&container[prefetchIdx * Channels], 1, 0);
                }
                process8PixelsDecodeAVX512GFNI(noiseHashes, dataHashes, container, data, dataLen,
                                                startPixel, totalPixels, p, bitIndex, startP);
                p += 8;
                bitIndex += 8 * DataBitsPerPixel;
            }
        }
    }
#endif

    // 4-pixel batched loop. Runs while four full-chCount pixels still fit in
    // the remaining bit budget; otherwise the scalar tail below picks up the
    // remainder. Packed vals[4][8] / xors[4][8] arrays expose 32 contiguous
    // bytes per phase, which GCC widens to YMM ops for the byte-parallel
    // phases on amd64+AVX2 (and to NEON on ARM via the same auto-vec path).
    while (p + 4 <= totalP && bitIndex + 4 * DataBitsPerPixel <= totalBits) {
        if (p + PrefetchDistance < totalP) {
            int prefetchIdx = (startPixel + startP + p + PrefetchDistance) % totalPixels;
            __builtin_prefetch(&container[prefetchIdx * Channels], 1, 0);
        }

#if defined(__GNUC__) && defined(__x86_64__)
        if (useAVX2GFNI) {
            if (encode) {
                process4PixelsEncodeAVX2GFNI(noiseHashes, dataHashes, container, data, dataLen,
                                              startPixel, totalPixels, p, bitIndex, startP);
            } else {
                process4PixelsDecodeAVX2GFNI(noiseHashes, dataHashes, container, data, dataLen,
                                              startPixel, totalPixels, p, bitIndex, startP);
            }
            p += 4;
            bitIndex += 4 * DataBitsPerPixel;
            continue;
        }
#endif

        int pixelOffset[4];
        unsigned int noisePos[4];
        uint8_t noiseMask[4];
        uint8_t noiseMaskBelow[4];
        unsigned int dataRotation[4];
        unsigned int dataRotationInv[4];
        uint64_t xorMask[4];

        for (int b = 0; b < 4; b++) {
            int linearIdx = (startPixel + startP + p + b) % totalPixels;
            pixelOffset[b] = linearIdx * Channels;
            uint64_t nh = noiseHashes[p + b];
            uint64_t dh = dataHashes[p + b];
            noisePos[b] = (unsigned int)(nh & 7);
            noiseMask[b] = (uint8_t)(1 << noisePos[b]);
            noiseMaskBelow[b] = noiseMask[b] - 1;
            dataRotation[b] = (unsigned int)(dh % 7);
            dataRotationInv[b] = 7 - dataRotation[b];
            xorMask[b] = dh >> DataRotationBits;
        }

        if (encode) {
            uint8_t vals[4][8];
            uint8_t xors[4][8];

            // Phase 1: extract 56 bits per pixel into 8×7-bit fields.
            for (int b = 0; b < 4; b++) {
                extract56bits(data, dataLen, bitIndex + b * DataBitsPerPixel, vals[b]);
            }

            // Phase 2: derive xor masks from each pixel's xorMask uint64.
            for (int b = 0; b < 4; b++) {
                for (int ch = 0; ch < Channels; ch++) {
                    xors[b][ch] = (uint8_t)((xorMask[b] >> (unsigned)(ch * DataBitsPerChannel)) & 0x7F);
                }
            }

            // Phase 3: XOR — 32 contiguous bytes accessed via flat-pointer
            // cast so GCC -O3 -mavx2 sees the linear iteration pattern and
            // widens the loop to a single VPXOR ymm. The nested-array form
            // looks equivalent at source level, but GCC declined to vectorise
            // it (verified via -fopt-info-vec-missed) — flat pointer over the
            // exact same memory removes the ambiguity.
            {
                uint8_t *valsFlat = &vals[0][0];
                const uint8_t *xorsFlat = &xors[0][0];
                for (int i = 0; i < 32; i++) {
                    valsFlat[i] ^= xorsFlat[i];
                }
            }

            // Phase 4: Rotate — per-pixel rotation amount, scalar-unrolled per byte.
            for (int b = 0; b < 4; b++) {
                for (int ch = 0; ch < Channels; ch++) {
                    vals[b][ch] = rotateBits7(vals[b][ch], dataRotation[b]);
                }
            }

            // Phase 5: Insert into container around per-pixel noise bit.
            // Pointer-per-pixel form with __restrict__ replaces the prior
            // container[pixelOffset[b]+ch] indexed access — that pattern
            // produced GCC "possible alias involving gather/scatter" misses
            // (verified via -fopt-info-vec-missed) and forced scalar code.
            // The restricted single-pixel pointer lets GCC vectorise each
            // inner 8-byte loop as an XMM op (same shape as the scalar tail).
            for (int b = 0; b < 4; b++) {
                uint8_t * __restrict__ pixelPtr = &container[pixelOffset[b]];
                const uint8_t nmb = noiseMaskBelow[b];
                const uint8_t nm = noiseMask[b];
                const unsigned int np = noisePos[b];
                for (int ch = 0; ch < Channels; ch++) {
                    uint8_t orig = pixelPtr[ch];
                    uint8_t low = vals[b][ch] & nmb;
                    uint8_t high = vals[b][ch] >> np;
                    pixelPtr[ch] = low | (orig & nm) | (high << (np + 1));
                }
            }
        } else {
            uint8_t vals[4][8];
            uint8_t xors[4][8];

            // Phase 1: Load container bytes, extract data bits (remove noise).
            // Pointer-per-pixel form mirrors encode Phase 5; lifts the inner
            // 8-byte loop out of the indexed gather pattern so GCC can keep
            // its XMM-vectorisation path on each pixel's contiguous bytes.
            for (int b = 0; b < 4; b++) {
                const uint8_t * __restrict__ pixelPtr = &container[pixelOffset[b]];
                const uint8_t nmb = noiseMaskBelow[b];
                const unsigned int np = noisePos[b];
                for (int ch = 0; ch < Channels; ch++) {
                    uint8_t channelByte = pixelPtr[ch];
                    uint8_t low = channelByte & nmb;
                    uint8_t high = channelByte >> (np + 1);
                    vals[b][ch] = low | (high << np);
                }
            }

            // Phase 2: Reverse rotate — per-pixel inverse rotation, scalar-unrolled.
            for (int b = 0; b < 4; b++) {
                for (int ch = 0; ch < Channels; ch++) {
                    vals[b][ch] = rotateBits7(vals[b][ch], dataRotationInv[b]);
                }
            }

            // Phase 3: derive xor masks from each pixel's xorMask uint64
            // (mirrors encode Phase 2; split out so the apply-XOR step below
            // collapses to a flat 32-byte loop GCC widens to a single YMM op).
            for (int b = 0; b < 4; b++) {
                for (int ch = 0; ch < Channels; ch++) {
                    xors[b][ch] = (uint8_t)((xorMask[b] >> (unsigned)(ch * DataBitsPerChannel)) & 0x7F);
                }
            }

            // Phase 3: XOR — 32 contiguous bytes via flat-pointer cast, single
            // VPXOR ymm under -O3 -mavx2. See encode-side note for why the
            // flat pointer is needed.
            {
                uint8_t *valsFlat = &vals[0][0];
                const uint8_t *xorsFlat = &xors[0][0];
                for (int i = 0; i < 32; i++) {
                    valsFlat[i] ^= xorsFlat[i];
                }
            }

            // Phase 4: Pack 8×7-bit values into the data byte stream.
            for (int b = 0; b < 4; b++) {
                pack56bits(data, dataLen, bitIndex + b * DataBitsPerPixel, vals[b], Channels);
            }
        }

        p += 4;
        bitIndex += 4 * DataBitsPerPixel;
    }

    // Tail: scalar per-pixel loop for the remaining 0-3 pixels (or pixels with
    // partial chCount). Verbatim copy of the historic per-pixel kernel.
    for (; p < totalP && bitIndex < totalBits; p++) {
        if (p + PrefetchDistance < totalP) {
            int prefetchIdx = (startPixel + startP + p + PrefetchDistance) % totalPixels;
            __builtin_prefetch(&container[prefetchIdx * Channels], 1, 0);
        }

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
        // Clamped to [0, Channels] to suppress GCC -Wstringop-overflow.
        int chCount = Channels;
        int bitsLeft = totalBits - bitIndex;
        if (bitsLeft < DataBitsPerPixel) {
            chCount = (bitsLeft + DataBitsPerChannel - 1) / DataBitsPerChannel;
        }
        if (chCount > Channels) chCount = Channels;
        if (chCount < 0) chCount = 0;

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
#pragma GCC diagnostic pop
