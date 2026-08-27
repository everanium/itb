#include <stdint.h>
#include <string.h>

#ifdef ITB_PARITY_TIER_OVERRIDE
#include <stdlib.h>
// Parity-only tier downgrade knob. Compiled in only when the parity
// helper is built with CGO_CFLAGS="-DITB_PARITY_TIER_OVERRIDE"; production
// builds compile it out entirely. Reads ITB_FORCE_PIXEL_TIER once at first
// dispatch resolve and returns a feature-suppression mask consumed by the
// cached support-flag resolvers. Each forced tag simulates a real fleet
// CPU class rather than capping a ladder — leftover sub-batch pixels
// route exactly as they would on the simulated silicon:
//   A        -> no suppression (full Tier A on capable hosts)
//   A_NOGFNI -> GFNI suppressed (AVX-512 no-GFNI host, e.g. Cascade Lake)
//   B        -> AVX-512 suppressed (AVX2 + GFNI host)
//   B_NOGFNI -> AVX-512 + GFNI suppressed (AVX2-only host, e.g. Zen 3)
//   C        -> all SIMD tiers suppressed (plain-C path)
// Downgrade-only by construction — the mask cannot enable a tier the
// CPU lacks.
#define ITB_TIER_SUPPRESS_AVX512 1
#define ITB_TIER_SUPPRESS_GFNI   2
#define ITB_TIER_SUPPRESS_AVX2   4
static int itb_parity_tier_cap(void) {
    const char *tier = getenv("ITB_FORCE_PIXEL_TIER");
    if (!tier || !*tier) return 0;
    char c = tier[0];
    int nogfni = (tier[1] == '_') ? ITB_TIER_SUPPRESS_GFNI : 0;
    if (c == 'a' || c == 'A') return nogfni;
    if (c == 'b' || c == 'B') return ITB_TIER_SUPPRESS_AVX512 | nogfni;
    if (c == 'c' || c == 'C')
        return ITB_TIER_SUPPRESS_AVX512 | ITB_TIER_SUPPRESS_GFNI | ITB_TIER_SUPPRESS_AVX2;
    return 0;
}
#endif

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

// GFNI matrix lookup tables. Every 8x8 GF(2) matrix consumed by
// vgf2p8affineqb in the batched kernels is a pure function of a 3-bit
// secret-derived selector (dataRotation for the rotation matrices,
// noisePos for the spread / gather matrices), so all possible matrices
// are materialised at compile time and each batched pixel fetches its
// matrices with a single indexed load instead of constructing them at
// runtime.
//
// Intel encoding (vgf2p8affineqb): output bit k of each result byte uses
// matrix qword byte (7 - k); the bit index within that matrix byte selects
// which input bit contributes to output bit k.
//
// Constant-time posture: each table occupies a single 64-byte cache line
// (aligned(64); the rotation table is 56 bytes, the spread / gather
// tables 64 bytes), so the secret-derived index selects within one line.
// The lookup is branch-free and its cache-line footprint is
// index-independent.

// ITB_GFNI_ROT(r): matrix mapping a 7-bit value v to rotateBits7(v, r).
// Output bit j (j in [0..6]) takes input bit (j - r) mod 7; output bit 7
// is zero so bit 7 of the result is always cleared.
#define ITB_GFNI_ROT_BIT(j, r) \
    ((uint64_t)1 << ((7u - (j)) * 8u + (((j) + 7u - (r)) % 7u)))
#define ITB_GFNI_ROT(r) \
    (ITB_GFNI_ROT_BIT(0u, r) | ITB_GFNI_ROT_BIT(1u, r) | \
     ITB_GFNI_ROT_BIT(2u, r) | ITB_GFNI_ROT_BIT(3u, r) | \
     ITB_GFNI_ROT_BIT(4u, r) | ITB_GFNI_ROT_BIT(5u, r) | \
     ITB_GFNI_ROT_BIT(6u, r))

// ITB_GFNI_SPREAD(np): encode-side noise-bit insertion matrix. Output
// bits below np copy input bits 0..(np-1) directly; output bit np is
// zero (the noise bit is OR'd in afterwards); output bits above np copy
// input bits (np..6) shifted up by one.
#define ITB_GFNI_SPREAD_BIT(j, np) \
    ((j) == (np) ? (uint64_t)0 \
                 : (uint64_t)1 << ((7u - (j)) * 8u + ((j) < (np) ? (j) : (j) - 1u)))
#define ITB_GFNI_SPREAD(np) \
    (ITB_GFNI_SPREAD_BIT(0u, np) | ITB_GFNI_SPREAD_BIT(1u, np) | \
     ITB_GFNI_SPREAD_BIT(2u, np) | ITB_GFNI_SPREAD_BIT(3u, np) | \
     ITB_GFNI_SPREAD_BIT(4u, np) | ITB_GFNI_SPREAD_BIT(5u, np) | \
     ITB_GFNI_SPREAD_BIT(6u, np) | ITB_GFNI_SPREAD_BIT(7u, np))

// ITB_GFNI_GATHER(np): decode-side counterpart of ITB_GFNI_SPREAD —
// removes the noise bit at np and packs the remaining 7 bits into the
// bottom 7 output bits. Output bit 7 is zero.
#define ITB_GFNI_GATHER_BIT(j, np) \
    ((uint64_t)1 << ((7u - (j)) * 8u + ((j) < (np) ? (j) : (j) + 1u)))
#define ITB_GFNI_GATHER(np) \
    (ITB_GFNI_GATHER_BIT(0u, np) | ITB_GFNI_GATHER_BIT(1u, np) | \
     ITB_GFNI_GATHER_BIT(2u, np) | ITB_GFNI_GATHER_BIT(3u, np) | \
     ITB_GFNI_GATHER_BIT(4u, np) | ITB_GFNI_GATHER_BIT(5u, np) | \
     ITB_GFNI_GATHER_BIT(6u, np))

// Indexed by dataRotation in [0, 7). The decode-side inverse rotation is
// served by the same table at index (7 - dataRotation) % 7.
static const uint64_t itb_gfni_rot_matrices[7] __attribute__((aligned(64))) = {
    ITB_GFNI_ROT(0u), ITB_GFNI_ROT(1u), ITB_GFNI_ROT(2u), ITB_GFNI_ROT(3u),
    ITB_GFNI_ROT(4u), ITB_GFNI_ROT(5u), ITB_GFNI_ROT(6u),
};

// Indexed by noisePos in [0, 8).
static const uint64_t itb_gfni_spread_matrices[8] __attribute__((aligned(64))) = {
    ITB_GFNI_SPREAD(0u), ITB_GFNI_SPREAD(1u), ITB_GFNI_SPREAD(2u), ITB_GFNI_SPREAD(3u),
    ITB_GFNI_SPREAD(4u), ITB_GFNI_SPREAD(5u), ITB_GFNI_SPREAD(6u), ITB_GFNI_SPREAD(7u),
};

// Indexed by noisePos in [0, 8).
static const uint64_t itb_gfni_gather_matrices[8] __attribute__((aligned(64))) = {
    ITB_GFNI_GATHER(0u), ITB_GFNI_GATHER(1u), ITB_GFNI_GATHER(2u), ITB_GFNI_GATHER(3u),
    ITB_GFNI_GATHER(4u), ITB_GFNI_GATHER(5u), ITB_GFNI_GATHER(6u), ITB_GFNI_GATHER(7u),
};

// process4PixelsEncodeAVX2GFNI processes one 4-pixel batch in encode direction.
//
// basePixel is the wrapped linear index of pixel p — the caller maintains
// (startPixel + startP + p) % totalPixels as a loop-carried counter, so
// basePixel is always in [0, totalPixels). Wrap handling is decided once
// at batch entry: when basePixel + 4 <= totalPixels the batch's 4 pixels
// occupy 32 consecutive container bytes, so the container load and store
// each collapse to a single unaligned YMM access (consecutive fast path).
// Otherwise the batch straddles the container end and the per-pixel wrap
// falls back to a branchless conditional subtract per lane plus 8-byte
// memcpys: the callers guarantee totalPixels >= totalP >= 4 whenever this
// helper runs, so basePixel + b < 2 * totalPixels and one subtract always
// lands in range. The fast-path predicate derives from basePixel (a
// startPixel-derived value) — the same state the container access pattern
// already exposes; see the wrap-handling note in HWTHREATS.md.
__attribute__((target("avx2,gfni")))
static inline void process4PixelsEncodeAVX2GFNI(
    const uint64_t *noiseHashes,
    const uint64_t *dataHashes,
    uint8_t *container,
    const uint8_t *data,
    int dataLen,
    int basePixel,
    int totalPixels,
    int p,
    int bitIndex
) {
    const int Channels = 8;
    const int DataBitsPerChannel = 7;
    const int DataBitsPerPixel = 56;
    const int DataRotationBits = 3;

    // Batch-entry wrap check. Consecutive batches skip the per-lane wrap
    // subtracts entirely and address the container linearly.
    const int consecutive = (basePixel + 4 <= totalPixels);
    int pixelOffset[4];
    if (!consecutive) {
        for (int b = 0; b < 4; b++) {
            int linearIdx = basePixel + b;
            linearIdx -= totalPixels & -(int)(linearIdx >= totalPixels);
            pixelOffset[b] = linearIdx * Channels;
        }
    }

    uint8_t noiseMaskArr[4];
    uint64_t rotMatrices[4] __attribute__((aligned(32)));
    uint64_t spreadMatrices[4] __attribute__((aligned(32)));
    uint64_t xorMaskArr[4];

    for (int b = 0; b < 4; b++) {
        uint64_t nh = noiseHashes[p + b];
        uint64_t dh = dataHashes[p + b];
        unsigned int np = (unsigned int)(nh & 7u);
        unsigned int dr = (unsigned int)(dh % 7u);
        noiseMaskArr[b] = (uint8_t)(1u << np);
        rotMatrices[b] = itb_gfni_rot_matrices[dr];
        spreadMatrices[b] = itb_gfni_spread_matrices[np];
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

    __m256i orig;
    if (consecutive) {
        orig = _mm256_loadu_si256((const __m256i *)&container[basePixel * Channels]);
    } else {
        uint8_t origBuf[32] __attribute__((aligned(32)));
        for (int b = 0; b < 4; b++) {
            memcpy(&origBuf[b * Channels], &container[pixelOffset[b]], Channels);
        }
        orig = _mm256_load_si256((const __m256i *)origBuf);
    }

    // Broadcast per-pixel noiseMask byte to all 8 lanes within each pixel.
    __m256i noiseMaskV = _mm256_set_epi64x(
        (int64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[3],
        (int64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[2],
        (int64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[1],
        (int64_t)0x0101010101010101ULL * (uint64_t)noiseMaskArr[0]);

    __m256i result = _mm256_or_si256(spreadVals, _mm256_and_si256(orig, noiseMaskV));

    if (consecutive) {
        _mm256_storeu_si256((__m256i *)&container[basePixel * Channels], result);
    } else {
        uint8_t outBuf[32] __attribute__((aligned(32)));
        _mm256_store_si256((__m256i *)outBuf, result);
        for (int b = 0; b < 4; b++) {
            memcpy(&container[pixelOffset[b]], &outBuf[b * Channels], Channels);
        }
    }
}

// pack56bitsX4AVX2 packs 4 pixels' 8x7-bit channel values (one YMM
// register laid out as [pixel 0..3] x [field 0..7] — the exact output
// layout of the decode phases) into 28 contiguous data bytes starting at
// data + bitIndex / 8. YMM-width counterpart of the Tier A
// pack56bitsX8AVX512VBMI helper; replaces 4 scalar pack56bits calls plus
// the store-forwarding-blocked YMM-to-stack round trip they required.
//
// Packing pipeline per qword lane (= pixel) mirrors the Tier A helper:
// VPMADDUBSW {1, 128} then VPMADDWD {1, 2^14} reduce the eight 7-bit
// channel bytes to two 28-bit dword halves, and a qword shift-OR joins
// them into a 56-bit packed value. AVX2 has no VPERMB or masked byte
// store, so the four packed qwords are extracted and written as four
// overlapping 8-byte stores: q0 at byteStart, q1 at +7, q2 at +14 (each
// store's top byte is zero — bits 56..63 of a packed qword — and is
// overwritten by the next store), and the final store at +20 carries
// ((q2 >> 48) | (q3 << 8)) so every write stays inside
// [byteStart, byteStart + 28) with no trailing-byte overrun past the
// batch span.
//
// The batched decode dispatch guarantees bitIndex + 4 * 56 <= totalBits =
// dataLen * 8, so the fast path always applies there; the scalar
// per-pixel calls remain as the bounds fallback to keep the semantics of
// 4 pack56bits calls exact for any caller without that guarantee. Like
// pack56bits, bitIndex % 8 is ignored — the batched loops advance
// bitIndex in 56-bit steps from a byte-aligned start, so bitIndex is
// always a multiple of 8 here.
//
// Constant-time posture: the store addresses derive only from public
// geometry (bitIndex, dataLen); the packed data values are secret but
// every instruction in the pipeline has data-independent latency.
__attribute__((target("avx2,gfni")))
static inline void pack56bitsX4AVX2(uint8_t *data, int dataLen, int bitIndex, __m256i vals) {
    int byteStart = bitIndex / 8;
    if (byteStart + 28 <= dataLen) {
        __m256i v = _mm256_and_si256(vals, _mm256_set1_epi8(0x7F));
        __m256i w = _mm256_maddubs_epi16(_mm256_set1_epi16((short)0x8001), v);
        __m256i d = _mm256_madd_epi16(w, _mm256_set1_epi32(0x40000001));
        __m256i lo = _mm256_and_si256(d, _mm256_set1_epi64x(0xFFFFFFFFLL));
        __m256i packed = _mm256_or_si256(lo,
            _mm256_slli_epi64(_mm256_srli_epi64(d, 32), 28));
        __m128i loLane = _mm256_castsi256_si128(packed);
        __m128i hiLane = _mm256_extracti128_si256(packed, 1);
        uint64_t q0 = (uint64_t)_mm_cvtsi128_si64(loLane);
        uint64_t q1 = (uint64_t)_mm_extract_epi64(loLane, 1);
        uint64_t q2 = (uint64_t)_mm_cvtsi128_si64(hiLane);
        uint64_t q3 = (uint64_t)_mm_extract_epi64(hiLane, 1);
        uint64_t last = (q2 >> 48) | (q3 << 8);
        memcpy(data + byteStart,      &q0, 8);
        memcpy(data + byteStart + 7,  &q1, 8);
        memcpy(data + byteStart + 14, &q2, 8);
        memcpy(data + byteStart + 20, &last, 8);
    } else {
        uint8_t valsBuf[32] __attribute__((aligned(32)));
        _mm256_store_si256((__m256i *)valsBuf, vals);
        for (int b = 0; b < 4; b++) {
            pack56bits(data, dataLen, bitIndex + b * 56, &valsBuf[b * 8], 8);
        }
    }
}

// process4PixelsDecodeAVX2GFNI processes one 4-pixel batch in decode direction.
// basePixel carries the same contract as in process4PixelsEncodeAVX2GFNI,
// including the batch-entry consecutive fast path for the container load.
__attribute__((target("avx2,gfni")))
static inline void process4PixelsDecodeAVX2GFNI(
    const uint64_t *noiseHashes,
    const uint64_t *dataHashes,
    const uint8_t *container,
    uint8_t *data,
    int dataLen,
    int basePixel,
    int totalPixels,
    int p,
    int bitIndex
) {
    const int Channels = 8;
    const int DataBitsPerChannel = 7;
    const int DataBitsPerPixel = 56;
    const int DataRotationBits = 3;

    // Batch-entry wrap check — same contract as the encode helper.
    const int consecutive = (basePixel + 4 <= totalPixels);

    uint64_t invRotMatrices[4] __attribute__((aligned(32)));
    uint64_t gatherMatrices[4] __attribute__((aligned(32)));
    uint64_t xorMaskArr[4];

    for (int b = 0; b < 4; b++) {
        uint64_t nh = noiseHashes[p + b];
        uint64_t dh = dataHashes[p + b];
        unsigned int np = (unsigned int)(nh & 7u);
        unsigned int dr = (unsigned int)(dh % 7u);
        // Inverse rotation amount for decode: 7 - r (mod 7).
        unsigned int dri = (7u - dr) % 7u;
        invRotMatrices[b] = itb_gfni_rot_matrices[dri];
        gatherMatrices[b] = itb_gfni_gather_matrices[np];
        xorMaskArr[b] = dh >> DataRotationBits;
    }

    // Phase 1: load 4 pixels' container bytes, gather data bits via GFNI.
    __m256i orig;
    if (consecutive) {
        orig = _mm256_loadu_si256((const __m256i *)&container[basePixel * Channels]);
    } else {
        uint8_t origBuf[32] __attribute__((aligned(32)));
        for (int b = 0; b < 4; b++) {
            int linearIdx = basePixel + b;
            linearIdx -= totalPixels & -(int)(linearIdx >= totalPixels);
            memcpy(&origBuf[b * Channels], &container[linearIdx * Channels], Channels);
        }
        orig = _mm256_load_si256((const __m256i *)origBuf);
    }
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
#ifdef ITB_PARITY_TIER_OVERRIDE
        if (itb_parity_tier_cap() & (ITB_TIER_SUPPRESS_AVX2 | ITB_TIER_SUPPRESS_GFNI)) v = 0;
#endif
        itb_simd_avx2_gfni_supported = v;
    }
    return v;
}

#pragma GCC pop_options

// =============================================================================
// AVX-512 + GFNI 8-pixel SIMD batch (Tier A)
//
// Doubles the batch width to 8 pixels (= 64 bytes = one ZMM register). The
// GFNI 8x8 GF(2) matrix tables (itb_gfni_rot_matrices /
// itb_gfni_spread_matrices / itb_gfni_gather_matrices) are reused verbatim —
// vgf2p8affineqb operates per qword regardless of register width, so the
// same per-pixel matrix layout extends to ZMM unchanged.
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

// pack56bitsX8AVX512VBMI packs 8 pixels' 8x7-bit channel values (one ZMM
// register laid out as [pixel 0..7] x [field 0..7] — the exact output
// layout of the decode phases) into 56 contiguous data bytes starting at
// data + bitIndex / 8. Store-side inverse of extract56bitsX8AVX512VBMI;
// replaces 8 scalar pack56bits calls plus the store-forwarding-blocked
// ZMM-to-stack round trip they required.
//
// Per qword lane (= pixel), input bytes v0..v7 each hold a 7-bit value.
// The GFNI gather and rotation matrices clear output bit 7 and the xor
// lanes are 0x7F-masked, so vals is 7-bit-clean by construction; the input
// is masked with 0x7F anyway to mirror the scalar pack56bits
// (vals[ch] & 0x7F) semantics exactly. Packing pipeline per lane:
//
//   VPMADDUBSW {1, 128}:     word_j  = v_{2j} + (v_{2j+1} << 7)   (14-bit)
//   VPMADDWD {1, 2^14}:      dword_k = w_{2k} + (w_{2k+1} << 14)  (28-bit)
//   qword shift-OR:          packed  = lo28 | (hi28 << 28)        (56-bit)
//   VPERMB compaction:       out byte i (0..55) = lane (i/7) byte (i%7)
//   one masked 56-byte store.
//
// VPMADDUBSW treats the second operand as signed bytes; 7-bit-clean values
// are <= 0x7F, so no saturation or sign issue arises. Bounds semantics
// match 8 scalar pack56bits calls: pixel b's 7 bytes are stored iff the
// full 7-byte span fits inside dataLen, expressed by clamping the store
// k-mask to the fitting prefix. The batched decode dispatch guarantees
// bitIndex + 8 * 56 <= totalBits = dataLen * 8, so the hot path always
// stores all 56 bytes. Like pack56bits, bitIndex % 8 is ignored — the
// batched loops advance bitIndex in 56-bit steps from a byte-aligned
// start, so bitIndex is always a multiple of 8 here.
//
// Constant-time posture: the store address and k-mask derive only from
// public geometry (bitIndex, dataLen); the packed data values are secret
// but every instruction in the pipeline has data-independent latency.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni,avx512vbmi")))
static inline void pack56bitsX8AVX512VBMI(uint8_t *data, int dataLen, int bitIndex, __m512i vals) {
    // Compaction control: output byte i = source byte (i / 7) * 8 + (i % 7)
    // — the low 7 bytes of each packed qword, concatenated. Bytes 56..63
    // are masked out of the store.
    static const uint8_t packCompactIdx[64] __attribute__((aligned(64))) = {
         0,  1,  2,  3,  4,  5,  6,
         8,  9, 10, 11, 12, 13, 14,
        16, 17, 18, 19, 20, 21, 22,
        24, 25, 26, 27, 28, 29, 30,
        32, 33, 34, 35, 36, 37, 38,
        40, 41, 42, 43, 44, 45, 46,
        48, 49, 50, 51, 52, 53, 54,
        56, 57, 58, 59, 60, 61, 62,
         0,  0,  0,  0,  0,  0,  0,  0,
    };
    int byteStart = bitIndex / 8;
    int nfit = (dataLen - byteStart) / 7;
    if (nfit <= 0) return;
    if (nfit > 8) nfit = 8;
    __mmask64 kmask = (nfit == 8) ? 0x00FFFFFFFFFFFFFFULL
                                  : (((__mmask64)1 << (nfit * 7)) - 1);

    __m512i v = _mm512_and_si512(vals, _mm512_set1_epi8(0x7F));
    __m512i w = _mm512_maddubs_epi16(_mm512_set1_epi16((short)0x8001), v);
    __m512i d = _mm512_madd_epi16(w, _mm512_set1_epi32(0x40000001));
    __m512i lo = _mm512_and_si512(d, _mm512_set1_epi64(0xFFFFFFFFLL));
    __m512i packed = _mm512_or_si512(lo, _mm512_slli_epi64(_mm512_srli_epi64(d, 32), 28));
    __m512i compact = _mm512_permutexvar_epi8(
        _mm512_load_si512((const void *)packCompactIdx), packed);
    _mm512_mask_storeu_epi8((void *)(data + byteStart), kmask, compact);
}

// process8PixelsEncodeAVX512GFNI processes one 8-pixel batch in encode direction.
//
// basePixel is the wrapped linear index of pixel p — the caller maintains
// (startPixel + startP + p) % totalPixels as a loop-carried counter, so
// basePixel is always in [0, totalPixels). Wrap handling is decided once
// at batch entry: when basePixel + 8 <= totalPixels the batch's 8 pixels
// occupy 64 consecutive container bytes, so the container load and store
// each collapse to a single unaligned ZMM access (consecutive fast path).
// Otherwise the batch straddles the container end and the per-pixel wrap
// falls back to a branchless conditional subtract per lane plus 8-byte
// memcpys: the callers guarantee totalPixels >= totalP >= 8 whenever this
// helper runs, so basePixel + b < 2 * totalPixels and one subtract always
// lands in range. The fast-path predicate derives from basePixel (a
// startPixel-derived value) — the same state the container access pattern
// already exposes; see the wrap-handling note in HWTHREATS.md.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni,avx512vbmi")))
static inline void process8PixelsEncodeAVX512GFNI(
    const uint64_t *noiseHashes,
    const uint64_t *dataHashes,
    uint8_t *container,
    const uint8_t *data,
    int dataLen,
    int basePixel,
    int totalPixels,
    int p,
    int bitIndex
) {
    const int Channels = 8;
    const int DataBitsPerChannel = 7;
    const int DataBitsPerPixel = 56;
    const int DataRotationBits = 3;

    // Batch-entry wrap check. Consecutive batches skip the per-lane wrap
    // subtracts entirely and address the container linearly.
    const int consecutive = (basePixel + 8 <= totalPixels);
    int pixelOffset[8];
    if (!consecutive) {
        for (int b = 0; b < 8; b++) {
            int linearIdx = basePixel + b;
            linearIdx -= totalPixels & -(int)(linearIdx >= totalPixels);
            pixelOffset[b] = linearIdx * Channels;
        }
    }

    uint8_t noiseMaskArr[8];
    uint64_t rotMatrices[8] __attribute__((aligned(64)));
    uint64_t spreadMatrices[8] __attribute__((aligned(64)));
    uint64_t xorMaskArr[8];

    for (int b = 0; b < 8; b++) {
        uint64_t nh = noiseHashes[p + b];
        uint64_t dh = dataHashes[p + b];
        unsigned int np = (unsigned int)(nh & 7u);
        unsigned int dr = (unsigned int)(dh % 7u);
        noiseMaskArr[b] = (uint8_t)(1u << np);
        rotMatrices[b] = itb_gfni_rot_matrices[dr];
        spreadMatrices[b] = itb_gfni_spread_matrices[np];
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

    __m512i orig;
    if (consecutive) {
        orig = _mm512_loadu_si512((const void *)&container[basePixel * Channels]);
    } else {
        uint8_t origBuf[64] __attribute__((aligned(64)));
        for (int b = 0; b < 8; b++) {
            memcpy(&origBuf[b * Channels], &container[pixelOffset[b]], Channels);
        }
        orig = _mm512_loadu_si512((const void *)origBuf);
    }

    // Broadcast each pixel's noiseMask byte across its 8-byte qword lane
    // with a single VPERMB: index byte i selects source byte (i / 8), so
    // qword b holds 8 copies of noiseMaskArr[b]. Replaces the scalar
    // _mm512_set_epi64 construction (8 multiplies + a register insert
    // chain) with one 8-byte load and one permute. The permutation
    // indices are public compile-time constants; only bytes 0..7 of the
    // source are referenced, so the undefined upper lanes of the
    // 128→512 cast are never selected.
    static const uint8_t noiseBcastIdx[64] __attribute__((aligned(64))) = {
        0, 0, 0, 0, 0, 0, 0, 0,
        1, 1, 1, 1, 1, 1, 1, 1,
        2, 2, 2, 2, 2, 2, 2, 2,
        3, 3, 3, 3, 3, 3, 3, 3,
        4, 4, 4, 4, 4, 4, 4, 4,
        5, 5, 5, 5, 5, 5, 5, 5,
        6, 6, 6, 6, 6, 6, 6, 6,
        7, 7, 7, 7, 7, 7, 7, 7,
    };
    __m128i noiseMasks8 = _mm_loadl_epi64((const __m128i *)noiseMaskArr);
    __m512i noiseMaskV = _mm512_permutexvar_epi8(
        _mm512_load_si512((const void *)noiseBcastIdx),
        _mm512_castsi128_si512(noiseMasks8));

    __m512i result = _mm512_or_si512(spreadVals, _mm512_and_si512(orig, noiseMaskV));

    if (consecutive) {
        _mm512_storeu_si512((void *)&container[basePixel * Channels], result);
    } else {
        uint8_t outBuf[64] __attribute__((aligned(64)));
        _mm512_storeu_si512((void *)outBuf, result);
        for (int b = 0; b < 8; b++) {
            memcpy(&container[pixelOffset[b]], &outBuf[b * Channels], Channels);
        }
    }
}

// process8PixelsDecodeAVX512GFNI processes one 8-pixel batch in decode direction.
// basePixel carries the same contract as in process8PixelsEncodeAVX512GFNI,
// including the batch-entry consecutive fast path for the container load.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni,avx512vbmi")))
static inline void process8PixelsDecodeAVX512GFNI(
    const uint64_t *noiseHashes,
    const uint64_t *dataHashes,
    const uint8_t *container,
    uint8_t *data,
    int dataLen,
    int basePixel,
    int totalPixels,
    int p,
    int bitIndex
) {
    const int Channels = 8;
    const int DataBitsPerChannel = 7;
    const int DataBitsPerPixel = 56;
    const int DataRotationBits = 3;

    // Batch-entry wrap check — same contract as the encode helper.
    const int consecutive = (basePixel + 8 <= totalPixels);

    uint64_t invRotMatrices[8] __attribute__((aligned(64)));
    uint64_t gatherMatrices[8] __attribute__((aligned(64)));
    uint64_t xorMaskArr[8];

    for (int b = 0; b < 8; b++) {
        uint64_t nh = noiseHashes[p + b];
        uint64_t dh = dataHashes[p + b];
        unsigned int np = (unsigned int)(nh & 7u);
        unsigned int dr = (unsigned int)(dh % 7u);
        unsigned int dri = (7u - dr) % 7u;
        invRotMatrices[b] = itb_gfni_rot_matrices[dri];
        gatherMatrices[b] = itb_gfni_gather_matrices[np];
        xorMaskArr[b] = dh >> DataRotationBits;
    }

    // Phase 1: load 8 pixels' container bytes, gather data bits via GFNI.
    __m512i orig;
    if (consecutive) {
        orig = _mm512_loadu_si512((const void *)&container[basePixel * Channels]);
    } else {
        uint8_t origBuf[64] __attribute__((aligned(64)));
        for (int b = 0; b < 8; b++) {
            int linearIdx = basePixel + b;
            linearIdx -= totalPixels & -(int)(linearIdx >= totalPixels);
            memcpy(&origBuf[b * Channels], &container[linearIdx * Channels], Channels);
        }
        orig = _mm512_loadu_si512((const void *)origBuf);
    }
    __m512i gatherMat = _mm512_loadu_si512((const void *)gatherMatrices);
    __m512i vals = _mm512_gf2p8affine_epi64_epi8(orig, gatherMat, 0);

    // Phase 2: reverse rotate via GFNI.
    __m512i invRotMat = _mm512_loadu_si512((const void *)invRotMatrices);
    vals = _mm512_gf2p8affine_epi64_epi8(vals, invRotMat, 0);

    // Phase 3: XOR with per-pixel xor masks. Derive via VPMULTISHIFTQB
    // (3 ZMM ops vs 128 scalar shifts/masks) — same helper as encode.
    __m512i xors = deriveXorsX8AVX512VBMI(xorMaskArr);
    vals = _mm512_xor_si512(vals, xors);

    // Phase 4: pack 8×7-bit values per pixel back into the data byte
    // stream — batched store-side inverse of extract56bitsX8AVX512VBMI.
    pack56bitsX8AVX512VBMI(data, dataLen, bitIndex, vals);
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
#ifdef ITB_PARITY_TIER_OVERRIDE
        if (itb_parity_tier_cap() & (ITB_TIER_SUPPRESS_AVX512 | ITB_TIER_SUPPRESS_GFNI)) v = 0;
#endif
        itb_simd_avx512_gfni_supported = v;
    }
    return v;
}

#pragma GCC pop_options

// =============================================================================
// AVX2 no-GFNI 4-pixel SIMD batch (Tier B')
//
// Same 4-pixel YMM batch structure as the AVX2+GFNI Tier B kernels, with
// every VGF2P8AFFINEQB replaced by an AVX2-only synthesis. Three
// structural properties make the synthesis cheap:
//
//   * Every secret-derived shift amount (dataRotation, noisePos) is
//     per-pixel, and each pixel occupies exactly one qword lane of the
//     batched byte layout — so the per-qword variable shift VPSLLVQ
//     covers the per-byte variable rotate once alternate bytes are
//     masked to zero (every 7-bit field then has >= 9 zeroed bits of
//     headroom above it, so a shift by r <= 6 cannot cross fields).
//   * rotateBits7(v, r) = ((v << r) | ((v << r) >> 7)) & 0x7F — the
//     (v >> (7 - r)) term equals (v << r) >> 7, so one variable shift
//     per byte half suffices; the >> 7 is the word-bounded VPSRLW.
//   * The noise-bit spread / gather transforms need no variable shift
//     at all: spread(v) = (v & nmb) | ((v & ~nmb) << 1) and
//     gather(c) = (c & nmb) | ((c >> 1) & (0x7F ^ nmb)) with
//     nmb = 2^noisePos - 1 a per-pixel byte mask. The constant per-byte
//     << 1 is VPADDB(x, x); the per-byte >> 1 is VPSRLW by 1 with the
//     0x7F factor of the second mask killing the cross-byte spill bit.
//
// Per-pixel byte masks and shift counts are built branch-free in the
// scalar per-batch setup loop via mask * 0x0101010101010101 (byte
// broadcast into a qword) into aligned stack buffers — the same pattern
// the Tier B noiseMask construction uses. No lookup tables are involved,
// so the constant-time posture needs no cache-line argument: every mask
// derives arithmetically from the per-pixel hash words.
//
// Serves AVX2 hosts without GFNI: AMD Zen 3 and earlier, Intel Haswell
// through Skylake-client / Comet Lake, and AVX2-only cloud VMs.
//
// Compile target note: the codegen feature set this tier actually needs
// is AVX2 alone — the runtime gate itb_check_avx2_nogfni() requires only
// AVX2, so a GFNI-less host selects this path. The target string carries
// "gfni" purely for the same GCC-16 toolchain artifact documented on the
// Tier A' section: <immintrin.h> is first included in this translation
// unit under `#pragma GCC target("avx2,gfni")`, which pins gfni into the
// option node of every always_inline intrinsic (AVX2 ones included), so
// a caller must carry gfni in its attribute for those intrinsics to
// inline. Adding gfni permits — but does not force — GFNI codegen; this
// tier uses no GFNI intrinsic, and the generated code is verified
// GFNI-free by objdump and by the perf-annotate firing proof (VPSLLVQ
// YMM signature, no vgf2p8affineqb, under ITB_FORCE_PIXEL_TIER=B_NOGFNI).
// =============================================================================

#pragma GCC push_options
#pragma GCC target("avx2,gfni")

// rotateBits7X4AVX2NoGFNI rotates each 7-bit byte lane of vals left by
// its pixel's rotation amount. rotQ holds the per-pixel rotation count
// (0..6) in each qword lane — VPSLLVQ consumes it directly. Even/odd
// byte halves are shifted separately so the per-qword shift cannot mix
// adjacent fields; see the section comment for the headroom argument.
__attribute__((target("avx2,gfni")))
static inline __m256i rotateBits7X4AVX2NoGFNI(__m256i vals, __m256i rotQ) {
    const __m256i maskLo = _mm256_set1_epi16(0x00FF);
    const __m256i mask7F = _mm256_set1_epi16(0x007F);
    __m256i e = _mm256_and_si256(vals, maskLo);
    __m256i o = _mm256_srli_epi16(vals, 8);
    __m256i te = _mm256_sllv_epi64(e, rotQ);
    __m256i to = _mm256_sllv_epi64(o, rotQ);
    __m256i re = _mm256_and_si256(_mm256_or_si256(te, _mm256_srli_epi16(te, 7)), mask7F);
    __m256i ro = _mm256_and_si256(_mm256_or_si256(to, _mm256_srli_epi16(to, 7)), mask7F);
    return _mm256_or_si256(re, _mm256_slli_epi16(ro, 8));
}

// pack56bitsX4AVX2NoGFNI is an attribute-only fork of pack56bitsX4AVX2
// for the Tier B' path. The body is identical — the original uses no
// GFNI intrinsic — but its target("avx2,gfni") attribute formally
// permits GFNI codegen, so calling it from a code path that runs on
// GFNI-less CPUs would not be ABI-safe. This copy compiles under
// target("avx2") only. See pack56bitsX4AVX2 for the packing-pipeline
// and bounds commentary.
__attribute__((target("avx2,gfni")))
static inline void pack56bitsX4AVX2NoGFNI(uint8_t *data, int dataLen, int bitIndex, __m256i vals) {
    int byteStart = bitIndex / 8;
    if (byteStart + 28 <= dataLen) {
        __m256i v = _mm256_and_si256(vals, _mm256_set1_epi8(0x7F));
        __m256i w = _mm256_maddubs_epi16(_mm256_set1_epi16((short)0x8001), v);
        __m256i d = _mm256_madd_epi16(w, _mm256_set1_epi32(0x40000001));
        __m256i lo = _mm256_and_si256(d, _mm256_set1_epi64x(0xFFFFFFFFLL));
        __m256i packed = _mm256_or_si256(lo,
            _mm256_slli_epi64(_mm256_srli_epi64(d, 32), 28));
        __m128i loLane = _mm256_castsi256_si128(packed);
        __m128i hiLane = _mm256_extracti128_si256(packed, 1);
        uint64_t q0 = (uint64_t)_mm_cvtsi128_si64(loLane);
        uint64_t q1 = (uint64_t)_mm_extract_epi64(loLane, 1);
        uint64_t q2 = (uint64_t)_mm_cvtsi128_si64(hiLane);
        uint64_t q3 = (uint64_t)_mm_extract_epi64(hiLane, 1);
        uint64_t last = (q2 >> 48) | (q3 << 8);
        memcpy(data + byteStart,      &q0, 8);
        memcpy(data + byteStart + 7,  &q1, 8);
        memcpy(data + byteStart + 14, &q2, 8);
        memcpy(data + byteStart + 20, &last, 8);
    } else {
        uint8_t valsBuf[32] __attribute__((aligned(32)));
        _mm256_store_si256((__m256i *)valsBuf, vals);
        for (int b = 0; b < 4; b++) {
            pack56bits(data, dataLen, bitIndex + b * 56, &valsBuf[b * 8], 8);
        }
    }
}

// process4PixelsEncodeAVX2NoGFNI processes one 4-pixel batch in encode
// direction on the Tier B' path. basePixel carries the same contract as
// in process4PixelsEncodeAVX2GFNI, including the batch-entry consecutive
// fast path for the container access.
__attribute__((target("avx2,gfni")))
static inline void process4PixelsEncodeAVX2NoGFNI(
    const uint64_t *noiseHashes,
    const uint64_t *dataHashes,
    uint8_t *container,
    const uint8_t *data,
    int dataLen,
    int basePixel,
    int totalPixels,
    int p,
    int bitIndex
) {
    const int Channels = 8;
    const int DataBitsPerChannel = 7;
    const int DataBitsPerPixel = 56;
    const int DataRotationBits = 3;

    const int consecutive = (basePixel + 4 <= totalPixels);
    int pixelOffset[4];
    if (!consecutive) {
        for (int b = 0; b < 4; b++) {
            int linearIdx = basePixel + b;
            linearIdx -= totalPixels & -(int)(linearIdx >= totalPixels);
            pixelOffset[b] = linearIdx * Channels;
        }
    }

    uint64_t rotQArr[4] __attribute__((aligned(32)));
    uint64_t nmQArr[4] __attribute__((aligned(32)));
    uint64_t nmbQArr[4] __attribute__((aligned(32)));
    uint64_t xorMaskArr[4];

    for (int b = 0; b < 4; b++) {
        uint64_t nh = noiseHashes[p + b];
        uint64_t dh = dataHashes[p + b];
        unsigned int np = (unsigned int)(nh & 7u);
        unsigned int dr = (unsigned int)(dh % 7u);
        rotQArr[b] = (uint64_t)dr;
        nmQArr[b] = 0x0101010101010101ULL * (uint64_t)(1u << np);
        nmbQArr[b] = 0x0101010101010101ULL * (uint64_t)((1u << np) - 1u);
        xorMaskArr[b] = dh >> DataRotationBits;
    }

    // Phase 1: extract 4x56 bits into 32-byte buffer.
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

    // Phase 4: rotate via the VPSLLVQ even/odd synthesis.
    __m256i rotQ = _mm256_load_si256((const __m256i *)rotQArr);
    vals = rotateBits7X4AVX2NoGFNI(vals, rotQ);

    // Phase 5: spread bits around per-pixel noisePos via the constant
    // per-byte << 1 identity, then OR with the preserved noise bit from
    // the original container byte.
    __m256i nmbV = _mm256_load_si256((const __m256i *)nmbQArr);
    __m256i nmV = _mm256_load_si256((const __m256i *)nmQArr);
    __m256i t = _mm256_andnot_si256(nmbV, vals);
    t = _mm256_add_epi8(t, t);
    __m256i spreadVals = _mm256_or_si256(t, _mm256_and_si256(vals, nmbV));

    __m256i orig;
    if (consecutive) {
        orig = _mm256_loadu_si256((const __m256i *)&container[basePixel * Channels]);
    } else {
        uint8_t origBuf[32] __attribute__((aligned(32)));
        for (int b = 0; b < 4; b++) {
            memcpy(&origBuf[b * Channels], &container[pixelOffset[b]], Channels);
        }
        orig = _mm256_load_si256((const __m256i *)origBuf);
    }

    __m256i result = _mm256_or_si256(spreadVals, _mm256_and_si256(orig, nmV));

    if (consecutive) {
        _mm256_storeu_si256((__m256i *)&container[basePixel * Channels], result);
    } else {
        uint8_t outBuf[32] __attribute__((aligned(32)));
        _mm256_store_si256((__m256i *)outBuf, result);
        for (int b = 0; b < 4; b++) {
            memcpy(&container[pixelOffset[b]], &outBuf[b * Channels], Channels);
        }
    }
}

// process4PixelsDecodeAVX2NoGFNI processes one 4-pixel batch in decode
// direction on the Tier B' path. basePixel carries the same contract as
// in process4PixelsEncodeAVX2NoGFNI.
__attribute__((target("avx2,gfni")))
static inline void process4PixelsDecodeAVX2NoGFNI(
    const uint64_t *noiseHashes,
    const uint64_t *dataHashes,
    const uint8_t *container,
    uint8_t *data,
    int dataLen,
    int basePixel,
    int totalPixels,
    int p,
    int bitIndex
) {
    const int Channels = 8;
    const int DataBitsPerChannel = 7;
    const int DataBitsPerPixel = 56;
    const int DataRotationBits = 3;

    const int consecutive = (basePixel + 4 <= totalPixels);

    uint64_t invRotQArr[4] __attribute__((aligned(32)));
    uint64_t nmbQArr[4] __attribute__((aligned(32)));
    uint64_t m2QArr[4] __attribute__((aligned(32)));
    uint64_t xorMaskArr[4];

    for (int b = 0; b < 4; b++) {
        uint64_t nh = noiseHashes[p + b];
        uint64_t dh = dataHashes[p + b];
        unsigned int np = (unsigned int)(nh & 7u);
        unsigned int dr = (unsigned int)(dh % 7u);
        unsigned int dri = (7u - dr) % 7u;
        invRotQArr[b] = (uint64_t)dri;
        nmbQArr[b] = 0x0101010101010101ULL * (uint64_t)((1u << np) - 1u);
        m2QArr[b] = 0x0101010101010101ULL * (uint64_t)(0x7Fu ^ ((1u << np) - 1u));
        xorMaskArr[b] = dh >> DataRotationBits;
    }

    // Phase 1: load 4 pixels' container bytes, gather data bits via the
    // constant per-byte >> 1 identity.
    __m256i orig;
    if (consecutive) {
        orig = _mm256_loadu_si256((const __m256i *)&container[basePixel * Channels]);
    } else {
        uint8_t origBuf[32] __attribute__((aligned(32)));
        for (int b = 0; b < 4; b++) {
            int linearIdx = basePixel + b;
            linearIdx -= totalPixels & -(int)(linearIdx >= totalPixels);
            memcpy(&origBuf[b * Channels], &container[linearIdx * Channels], Channels);
        }
        orig = _mm256_load_si256((const __m256i *)origBuf);
    }
    __m256i nmbV = _mm256_load_si256((const __m256i *)nmbQArr);
    __m256i m2V = _mm256_load_si256((const __m256i *)m2QArr);
    __m256i s = _mm256_srli_epi16(orig, 1);
    __m256i vals = _mm256_or_si256(_mm256_and_si256(orig, nmbV), _mm256_and_si256(s, m2V));

    // Phase 2: reverse rotate via the VPSLLVQ even/odd synthesis.
    __m256i invRotQ = _mm256_load_si256((const __m256i *)invRotQArr);
    vals = rotateBits7X4AVX2NoGFNI(vals, invRotQ);

    // Phase 3: XOR with per-pixel xor masks.
    uint8_t xorsBuf[32] __attribute__((aligned(32)));
    for (int b = 0; b < 4; b++) {
        for (int ch = 0; ch < Channels; ch++) {
            xorsBuf[b * Channels + ch] = (uint8_t)((xorMaskArr[b] >> (unsigned)(ch * DataBitsPerChannel)) & 0x7F);
        }
    }
    __m256i xors = _mm256_load_si256((const __m256i *)xorsBuf);
    vals = _mm256_xor_si256(vals, xors);

    // Phase 4: pack 8x7-bit values per pixel back into the data byte
    // stream.
    pack56bitsX4AVX2NoGFNI(data, dataLen, bitIndex, vals);
}

// itb_simd_avx2_nogfni_supported caches the AVX2 feature detection for
// the Tier B' path. -1 means uninitialised; resolved on first call.
static int itb_simd_avx2_nogfni_supported = -1;

static inline int itb_check_avx2_nogfni(void) {
    int v = itb_simd_avx2_nogfni_supported;
    if (v < 0) {
        v = __builtin_cpu_supports("avx2") ? 1 : 0;
#ifdef ITB_PARITY_TIER_OVERRIDE
        if (itb_parity_tier_cap() & ITB_TIER_SUPPRESS_AVX2) v = 0;
#endif
        itb_simd_avx2_nogfni_supported = v;
    }
    return v;
}

#pragma GCC pop_options

// =============================================================================
// AVX-512 no-GFNI no-VBMI 8-pixel SIMD batch (Tier A')
//
// Same 8-pixel ZMM batch structure as the AVX-512+GFNI Tier A kernels,
// gated on AVX-512 F + BW + VL only — no GFNI, no VBMI. Substitutions:
//
//   * VGF2P8AFFINEQB rotate     -> VPSLLVW even/odd synthesis (the
//     per-pixel rotation count is word-broadcast across the pixel's
//     qword) with VPTERNLOG folding the (t | t >> 7) & 0x7F reduction.
//   * VGF2P8AFFINEQB spread     -> (v & nmb) | ((v & ~nmb) << 1) with
//     the per-byte << 1 as VPADDB(x, x); no variable shift needed.
//   * VGF2P8AFFINEQB gather     -> (c & nmb) | ((c >> 1) & (0x7F ^ nmb))
//     with the per-byte >> 1 as the word-bounded VPSRLW.
//   * VPERMB byte-arrange       -> four unaligned 16-byte loads at
//     stride 14 + VINSERTI32X4 + one in-lane VPSHUFB.
//   * VPMULTISHIFTQB extraction -> qword-to-word expansion (VPERMQ dup,
//     in-lane VPSHUFB byte pairs), VPSRLVW by the constant per-word
//     shift pattern, VPACKUSWB + VPERMQ lane fixup.
//   * VPERMB pack compaction    -> in-lane VPSHUFB to 14 valid bytes
//     per lane + four 128-bit byte-masked stores (VL + BW) at stride 14.
//   * VPERMB noise broadcast    -> scalar qword construction in the
//     per-batch setup loop (mask * 0x0101010101010101).
//
// Constant-time posture matches the sibling tiers: no lookup tables
// (every mask and shift count derives arithmetically from the per-pixel
// hash words in the branch-free setup loop), store addresses and masks
// derive only from public geometry, and all immediate shift amounts are
// compile-time constants.
//
// Serves AVX-512 hosts without GFNI: Intel Cascade Lake / early
// Skylake-X Xeon and X-series parts.
// =============================================================================

// Compile target note: the codegen feature set this tier actually needs
// is AVX-512 F + BW + VL — the runtime gate itb_check_avx512_nogfni()
// requires exactly those three, so a GFNI-less Cascade Lake host selects
// this path. The target string nonetheless carries "gfni" for a GCC-16
// toolchain artifact only: <immintrin.h> is first included earlier in
// this translation unit under `#pragma GCC target("avx2,gfni")` (the
// Tier B section), which pins gfni into the option node of every
// AVX-512 always_inline intrinsic. A ZMM caller must then carry gfni in
// its own attribute for those intrinsics to inline; without it GCC 16
// rejects the build with "target specific option mismatch". Adding gfni
// permits — but does not force — GFNI codegen; this tier uses no GFNI
// intrinsic, and avx512vbmi is deliberately excluded so no VPERMB /
// VPMULTISHIFTQB can be emitted either. The generated code is verified
// GFNI-free by objdump and by the perf-annotate firing proof (zero
// vgf2p8affineqb under ITB_FORCE_PIXEL_TIER=A_NOGFNI).
#pragma GCC push_options
#pragma GCC target("avx512f,avx512bw,avx512vl,gfni")

// Per-word right-shift pattern for the 7-bit field extraction. Word j of
// each 128-bit lane (one lane = one pixel's 8 expanded 16-bit windows)
// holds shift 7*j - 8*k_j with k_j = floor(7*j / 8), i.e.
// {0, 7, 6, 5, 4, 3, 2, 1}.
static const uint64_t itb_a2_field_shifts[8] __attribute__((aligned(64))) = {
    0x0005000600070000ULL, 0x0001000200030004ULL,
    0x0005000600070000ULL, 0x0001000200030004ULL,
    0x0005000600070000ULL, 0x0001000200030004ULL,
    0x0005000600070000ULL, 0x0001000200030004ULL,
};

// Byte-pair expansion control (in-lane VPSHUFB): word j of each lane is
// built from source bytes {k_j, k_j + 1} of the pixel qword duplicated
// across the lane, k_j = {0, 0, 1, 2, 3, 4, 5, 6}.
static const uint8_t itb_a2_pair_idx[64] __attribute__((aligned(64))) = {
    0, 1, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7,
    0, 1, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7,
    0, 1, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7,
    0, 1, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7,
};

// In-lane arrange control for the 56-bit extraction: after the four
// 16-byte loads at stride 14, lane L holds source bytes
// [14L .. 14L + 15]; the shuffle places pixel 2L's qword at lane bytes
// 0-7 (lane bytes 0..7) and pixel 2L+1's qword at lane bytes 8-15
// (lane bytes 7..14).
static const uint8_t itb_a2_arrange_idx[64] __attribute__((aligned(64))) = {
    0, 1, 2, 3, 4, 5, 6, 7,  7,  8,  9, 10, 11, 12, 13, 14,
    0, 1, 2, 3, 4, 5, 6, 7,  7,  8,  9, 10, 11, 12, 13, 14,
    0, 1, 2, 3, 4, 5, 6, 7,  7,  8,  9, 10, 11, 12, 13, 14,
    0, 1, 2, 3, 4, 5, 6, 7,  7,  8,  9, 10, 11, 12, 13, 14,
};

// Pack compaction control (in-lane VPSHUFB): lane bytes 0-13 collect the
// low 7 bytes of the lane's two packed qwords; bytes 14-15 zero via the
// VPSHUFB high-bit convention.
static const uint8_t itb_a2_pack_idx[64] __attribute__((aligned(64))) = {
    0, 1, 2, 3, 4, 5, 6,  8,  9, 10, 11, 12, 13, 14, 0x80, 0x80,
    0, 1, 2, 3, 4, 5, 6,  8,  9, 10, 11, 12, 13, 14, 0x80, 0x80,
    0, 1, 2, 3, 4, 5, 6,  8,  9, 10, 11, 12, 13, 14, 0x80, 0x80,
    0, 1, 2, 3, 4, 5, 6,  8,  9, 10, 11, 12, 13, 14, 0x80, 0x80,
};

// itb_a2_fields_from_qwordsX8 extracts 8x7-bit fields from each of the
// 8 pixel qwords in q (field j = (qword >> 7j) & 0x7F). BW-only
// counterpart of the Tier A VPMULTISHIFTQB step: each qword is
// duplicated into a 128-bit lane, expanded to eight 16-bit windows via
// in-lane VPSHUFB, shifted per word by the constant pattern, masked,
// and re-packed to bytes with a VPERMQ fixup for VPACKUSWB's in-lane
// interleaving. Output layout matches the Tier A helpers:
// [pixel 0..7] x [field 0..7], 64 bytes.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni")))
static inline __m512i itb_a2_fields_from_qwordsX8(__m512i q) {
    __m512i lo = _mm512_permutexvar_epi64(_mm512_set_epi64(3, 3, 2, 2, 1, 1, 0, 0), q);
    __m512i hi = _mm512_permutexvar_epi64(_mm512_set_epi64(7, 7, 6, 6, 5, 5, 4, 4), q);
    __m512i pairIdx = _mm512_load_si512((const void *)itb_a2_pair_idx);
    lo = _mm512_shuffle_epi8(lo, pairIdx);
    hi = _mm512_shuffle_epi8(hi, pairIdx);
    __m512i sh = _mm512_load_si512((const void *)itb_a2_field_shifts);
    lo = _mm512_srlv_epi16(lo, sh);
    hi = _mm512_srlv_epi16(hi, sh);
    const __m512i m7F = _mm512_set1_epi16(0x007F);
    lo = _mm512_and_si512(lo, m7F);
    hi = _mm512_and_si512(hi, m7F);
    __m512i packed = _mm512_packus_epi16(lo, hi);
    return _mm512_permutexvar_epi64(_mm512_set_epi64(7, 5, 3, 1, 6, 4, 2, 0), packed);
}

// extract56bitsX8AVX512NoVBMI mirrors extract56bitsX8AVX512VBMI without
// VBMI: four unaligned 16-byte loads at stride 14 (max byte read is
// baseByteIdx + 57, within the caller-guaranteed baseByteIdx + 64
// bound), the in-lane arrange shuffle, the per-batch bitOff shift, and
// the BW field extraction helper.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni")))
static inline __m512i extract56bitsX8AVX512NoVBMI(const uint8_t *data, int baseByteIdx, unsigned int bitOff) {
    const uint8_t *base = data + baseByteIdx;
    __m512i v = _mm512_castsi128_si512(_mm_loadu_si128((const __m128i *)base));
    v = _mm512_inserti32x4(v, _mm_loadu_si128((const __m128i *)(base + 14)), 1);
    v = _mm512_inserti32x4(v, _mm_loadu_si128((const __m128i *)(base + 28)), 2);
    v = _mm512_inserti32x4(v, _mm_loadu_si128((const __m128i *)(base + 42)), 3);
    __m512i q = _mm512_shuffle_epi8(v, _mm512_load_si512((const void *)itb_a2_arrange_idx));
    q = _mm512_srli_epi64(q, bitOff);
    return itb_a2_fields_from_qwordsX8(q);
}

// deriveXorsX8AVX512NoVBMI mirrors deriveXorsX8AVX512VBMI without VBMI.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni")))
static inline __m512i deriveXorsX8AVX512NoVBMI(const uint64_t *xorMaskArr) {
    __m512i xorMaskV = _mm512_loadu_si512((const void *)xorMaskArr);
    return itb_a2_fields_from_qwordsX8(xorMaskV);
}

// rotateBits7X8AVX512NoGFNI rotates each 7-bit byte lane of vals left by
// its pixel's rotation amount. rotW holds the rotation count broadcast
// across the pixel qword's four words, so VPSLLVW applies the per-pixel
// count to both byte halves. VPTERNLOG imm 0xA8 computes (a | b) & c.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni")))
static inline __m512i rotateBits7X8AVX512NoGFNI(__m512i vals, __m512i rotW) {
    const __m512i maskLo = _mm512_set1_epi16(0x00FF);
    const __m512i mask7F = _mm512_set1_epi16(0x007F);
    __m512i e = _mm512_and_si512(vals, maskLo);
    __m512i o = _mm512_srli_epi16(vals, 8);
    __m512i te = _mm512_sllv_epi16(e, rotW);
    __m512i to = _mm512_sllv_epi16(o, rotW);
    __m512i re = _mm512_ternarylogic_epi64(te, _mm512_srli_epi16(te, 7), mask7F, 0xA8);
    __m512i ro = _mm512_ternarylogic_epi64(to, _mm512_srli_epi16(to, 7), mask7F, 0xA8);
    return _mm512_or_si512(re, _mm512_slli_epi16(ro, 8));
}

// pack56bitsX8AVX512NoVBMI packs 8 pixels' 8x7-bit channel values into
// 56 contiguous data bytes — BW/VL-only counterpart of
// pack56bitsX8AVX512VBMI. The maddubs/madd/shift-OR packing pipeline is
// identical; the VPERMB compaction + single masked 56-byte store are
// replaced by an in-lane VPSHUFB (14 valid bytes per lane) and four
// 128-bit byte-masked stores at stride 14 (mask 0x3FFF; the last store
// touches bytes byteStart + 42 .. byteStart + 55, inside the checked
// bound). The bounds fallback keeps the semantics of 8 scalar
// pack56bits calls for any caller without the hot-path guarantee.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni")))
static inline void pack56bitsX8AVX512NoVBMI(uint8_t *data, int dataLen, int bitIndex, __m512i vals) {
    int byteStart = bitIndex / 8;
    if (byteStart + 56 <= dataLen) {
        __m512i v = _mm512_and_si512(vals, _mm512_set1_epi8(0x7F));
        __m512i w = _mm512_maddubs_epi16(_mm512_set1_epi16((short)0x8001), v);
        __m512i d = _mm512_madd_epi16(w, _mm512_set1_epi32(0x40000001));
        __m512i lo = _mm512_and_si512(d, _mm512_set1_epi64(0xFFFFFFFFLL));
        __m512i packed = _mm512_or_si512(lo, _mm512_slli_epi64(_mm512_srli_epi64(d, 32), 28));
        __m512i compact = _mm512_shuffle_epi8(packed,
            _mm512_load_si512((const void *)itb_a2_pack_idx));
        _mm_mask_storeu_epi8((void *)(data + byteStart), 0x3FFF,
            _mm512_castsi512_si128(compact));
        _mm_mask_storeu_epi8((void *)(data + byteStart + 14), 0x3FFF,
            _mm512_extracti32x4_epi32(compact, 1));
        _mm_mask_storeu_epi8((void *)(data + byteStart + 28), 0x3FFF,
            _mm512_extracti32x4_epi32(compact, 2));
        _mm_mask_storeu_epi8((void *)(data + byteStart + 42), 0x3FFF,
            _mm512_extracti32x4_epi32(compact, 3));
    } else {
        uint8_t valsBuf[64] __attribute__((aligned(64)));
        _mm512_storeu_si512((void *)valsBuf, vals);
        for (int b = 0; b < 8; b++) {
            pack56bits(data, dataLen, bitIndex + b * 56, &valsBuf[b * 8], 8);
        }
    }
}

// process8PixelsEncodeAVX512NoGFNI processes one 8-pixel batch in encode
// direction on the Tier A' path. basePixel carries the same contract as
// in process8PixelsEncodeAVX512GFNI, including the batch-entry
// consecutive fast path and the caller-side bitIndex/8 + 64 <= dataLen
// guard for the 56-bit extraction loads.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni")))
static inline void process8PixelsEncodeAVX512NoGFNI(
    const uint64_t *noiseHashes,
    const uint64_t *dataHashes,
    uint8_t *container,
    const uint8_t *data,
    int dataLen,
    int basePixel,
    int totalPixels,
    int p,
    int bitIndex
) {
    const int Channels = 8;
    const int DataBitsPerChannel = 7;
    const int DataBitsPerPixel = 56;
    const int DataRotationBits = 3;
    (void)DataBitsPerChannel;

    const int consecutive = (basePixel + 8 <= totalPixels);
    int pixelOffset[8];
    if (!consecutive) {
        for (int b = 0; b < 8; b++) {
            int linearIdx = basePixel + b;
            linearIdx -= totalPixels & -(int)(linearIdx >= totalPixels);
            pixelOffset[b] = linearIdx * Channels;
        }
    }

    uint64_t rotWArr[8] __attribute__((aligned(64)));
    uint64_t nmQArr[8] __attribute__((aligned(64)));
    uint64_t nmbQArr[8] __attribute__((aligned(64)));
    uint64_t xorMaskArr[8] __attribute__((aligned(64)));

    for (int b = 0; b < 8; b++) {
        uint64_t nh = noiseHashes[p + b];
        uint64_t dh = dataHashes[p + b];
        unsigned int np = (unsigned int)(nh & 7u);
        unsigned int dr = (unsigned int)(dh % 7u);
        rotWArr[b] = (uint64_t)dr * 0x0001000100010001ULL;
        nmQArr[b] = 0x0101010101010101ULL * (uint64_t)(1u << np);
        nmbQArr[b] = 0x0101010101010101ULL * (uint64_t)((1u << np) - 1u);
        xorMaskArr[b] = dh >> DataRotationBits;
    }

    // Phase 1: extract 8x56 bits via the BW arrange + field-extraction
    // pipeline. Bounds are guaranteed by the dispatch guard.
    int baseByteIdx = bitIndex / 8;
    unsigned int bitOff = (unsigned int)(bitIndex % 8);
    __m512i vals = extract56bitsX8AVX512NoVBMI(data, baseByteIdx, bitOff);

    // Phase 2: derive per-pixel xor masks.
    __m512i xors = deriveXorsX8AVX512NoVBMI(xorMaskArr);

    // Phase 3: XOR (single VPXORQ zmm).
    vals = _mm512_xor_si512(vals, xors);

    // Phase 4: rotate via the VPSLLVW even/odd synthesis.
    __m512i rotW = _mm512_load_si512((const void *)rotWArr);
    vals = rotateBits7X8AVX512NoGFNI(vals, rotW);

    // Phase 5: spread bits around per-pixel noisePos via the constant
    // per-byte << 1 identity, then merge the preserved noise bit from
    // each pixel's original container byte. VPTERNLOG imm 0xF8 computes
    // a | (b & c).
    __m512i nmbV = _mm512_load_si512((const void *)nmbQArr);
    __m512i nmV = _mm512_load_si512((const void *)nmQArr);
    __m512i t = _mm512_andnot_si512(nmbV, vals);
    t = _mm512_add_epi8(t, t);
    __m512i spreadVals = _mm512_ternarylogic_epi64(t, vals, nmbV, 0xF8);

    __m512i orig;
    if (consecutive) {
        orig = _mm512_loadu_si512((const void *)&container[basePixel * Channels]);
    } else {
        uint8_t origBuf[64] __attribute__((aligned(64)));
        for (int b = 0; b < 8; b++) {
            memcpy(&origBuf[b * Channels], &container[pixelOffset[b]], Channels);
        }
        orig = _mm512_loadu_si512((const void *)origBuf);
    }

    __m512i result = _mm512_ternarylogic_epi64(spreadVals, orig, nmV, 0xF8);

    if (consecutive) {
        _mm512_storeu_si512((void *)&container[basePixel * Channels], result);
    } else {
        uint8_t outBuf[64] __attribute__((aligned(64)));
        _mm512_storeu_si512((void *)outBuf, result);
        for (int b = 0; b < 8; b++) {
            memcpy(&container[pixelOffset[b]], &outBuf[b * Channels], Channels);
        }
    }
}

// process8PixelsDecodeAVX512NoGFNI processes one 8-pixel batch in decode
// direction on the Tier A' path. basePixel carries the same contract as
// in process8PixelsEncodeAVX512NoGFNI.
__attribute__((target("avx512f,avx512bw,avx512vl,gfni")))
static inline void process8PixelsDecodeAVX512NoGFNI(
    const uint64_t *noiseHashes,
    const uint64_t *dataHashes,
    const uint8_t *container,
    uint8_t *data,
    int dataLen,
    int basePixel,
    int totalPixels,
    int p,
    int bitIndex
) {
    const int Channels = 8;
    const int DataBitsPerChannel = 7;
    const int DataBitsPerPixel = 56;
    const int DataRotationBits = 3;
    (void)DataBitsPerChannel;
    (void)DataBitsPerPixel;

    const int consecutive = (basePixel + 8 <= totalPixels);

    uint64_t invRotWArr[8] __attribute__((aligned(64)));
    uint64_t nmbQArr[8] __attribute__((aligned(64)));
    uint64_t m2QArr[8] __attribute__((aligned(64)));
    uint64_t xorMaskArr[8] __attribute__((aligned(64)));

    for (int b = 0; b < 8; b++) {
        uint64_t nh = noiseHashes[p + b];
        uint64_t dh = dataHashes[p + b];
        unsigned int np = (unsigned int)(nh & 7u);
        unsigned int dr = (unsigned int)(dh % 7u);
        unsigned int dri = (7u - dr) % 7u;
        invRotWArr[b] = (uint64_t)dri * 0x0001000100010001ULL;
        nmbQArr[b] = 0x0101010101010101ULL * (uint64_t)((1u << np) - 1u);
        m2QArr[b] = 0x0101010101010101ULL * (uint64_t)(0x7Fu ^ ((1u << np) - 1u));
        xorMaskArr[b] = dh >> DataRotationBits;
    }

    // Phase 1: load 8 pixels' container bytes, gather data bits via the
    // constant per-byte >> 1 identity. VPTERNLOG imm 0xF8 computes
    // a | (b & c).
    __m512i orig;
    if (consecutive) {
        orig = _mm512_loadu_si512((const void *)&container[basePixel * Channels]);
    } else {
        uint8_t origBuf[64] __attribute__((aligned(64)));
        for (int b = 0; b < 8; b++) {
            int linearIdx = basePixel + b;
            linearIdx -= totalPixels & -(int)(linearIdx >= totalPixels);
            memcpy(&origBuf[b * Channels], &container[linearIdx * Channels], Channels);
        }
        orig = _mm512_loadu_si512((const void *)origBuf);
    }
    __m512i nmbV = _mm512_load_si512((const void *)nmbQArr);
    __m512i m2V = _mm512_load_si512((const void *)m2QArr);
    __m512i s = _mm512_srli_epi16(orig, 1);
    __m512i low = _mm512_and_si512(orig, nmbV);
    __m512i vals = _mm512_ternarylogic_epi64(low, s, m2V, 0xF8);

    // Phase 2: reverse rotate via the VPSLLVW even/odd synthesis.
    __m512i invRotW = _mm512_load_si512((const void *)invRotWArr);
    vals = rotateBits7X8AVX512NoGFNI(vals, invRotW);

    // Phase 3: XOR with per-pixel xor masks.
    __m512i xors = deriveXorsX8AVX512NoVBMI(xorMaskArr);
    vals = _mm512_xor_si512(vals, xors);

    // Phase 4: pack 8x7-bit values per pixel back into the data byte
    // stream.
    pack56bitsX8AVX512NoVBMI(data, dataLen, bitIndex, vals);
}

// itb_simd_avx512_nogfni_supported caches the AVX-512 F+BW+VL feature
// detection for the Tier A' path. -1 means uninitialised; resolved on
// first call.
static int itb_simd_avx512_nogfni_supported = -1;

static inline int itb_check_avx512_nogfni(void) {
    int v = itb_simd_avx512_nogfni_supported;
    if (v < 0) {
        v = __builtin_cpu_supports("avx512f")
            && __builtin_cpu_supports("avx512bw")
            && __builtin_cpu_supports("avx512vl") ? 1 : 0;
#ifdef ITB_PARITY_TIER_OVERRIDE
        if (itb_parity_tier_cap() & ITB_TIER_SUPPRESS_AVX512) v = 0;
#endif
        itb_simd_avx512_nogfni_supported = v;
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
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
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
    // while current pixel is processed. 64 pixels ≈ 8 cache lines of
    // container, hides deeper L2/L3 miss latency on Zen 5 and Intel
    // Rocket Lake alike; the wider window matches the actual sustained
    // pixel-consumption throughput of the batched hash producer above.
    // Independent of any future per-pixel SIMD restructuring — the hint
    // just preloads container[] memory.
    const int PrefetchDistance = 64;

    int bitIndex = startP * DataBitsPerPixel;
    int p = 0;
    const int totalP = endP - startP;

    // Loop-carried linear pixel index. basePixel tracks
    // (startPixel + startP + p) % totalPixels across every loop below with
    // a single division at function entry; each subsequent wrap is a
    // branchless conditional subtract. Exactness of the single subtract:
    // the Go callers guarantee totalPixels >= endP - startP (dataPixels
    // never exceeds totalPixels), each batched loop requires totalP >= its
    // batch width, and the prefetch increment is guarded by
    // p + PrefetchDistance < totalP, so every increment added to a value
    // in [0, totalPixels) stays below 2 * totalPixels.
    int basePixel = (startPixel + startP) % totalPixels;

    // SIMD dispatch flags — hoisted once before the hot loop. On x86_64 with
    // GFNI the per-pixel kernel routes into the AVX-512+GFNI 8-pixel helpers
    // first (when available), then the AVX2+GFNI 4-pixel helpers for any
    // 4-7 leftover pixels, then the plain-C path for the final 0-3 tail.
    // Hosts without GFNI fall through to the plain-C path verbatim.
#if defined(__GNUC__) && defined(__x86_64__)
    const int useAVX512GFNI = itb_check_avx512_gfni();
    const int useAVX2GFNI = itb_check_avx2_gfni();
    const int useAVX512NoGFNI = itb_check_avx512_nogfni();
    const int useAVX2NoGFNI = itb_check_avx2_nogfni();
#else
    const int useAVX512GFNI = 0;
    const int useAVX2GFNI = 0;
    const int useAVX512NoGFNI = 0;
    const int useAVX2NoGFNI = 0;
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
                    int prefetchIdx = basePixel + PrefetchDistance;
                    prefetchIdx -= totalPixels & -(int)(prefetchIdx >= totalPixels);
                    __builtin_prefetch(&container[prefetchIdx * Channels], 1, 0);
                }
                process8PixelsEncodeAVX512GFNI(noiseHashes, dataHashes, container, data, dataLen,
                                                basePixel, totalPixels, p, bitIndex);
                p += 8;
                bitIndex += 8 * DataBitsPerPixel;
                basePixel += 8;
                basePixel -= totalPixels & -(int)(basePixel >= totalPixels);
            }
        } else {
            while (p + 8 <= totalP && bitIndex + 8 * DataBitsPerPixel <= totalBits) {
                if (p + PrefetchDistance < totalP) {
                    int prefetchIdx = basePixel + PrefetchDistance;
                    prefetchIdx -= totalPixels & -(int)(prefetchIdx >= totalPixels);
                    __builtin_prefetch(&container[prefetchIdx * Channels], 1, 0);
                }
                process8PixelsDecodeAVX512GFNI(noiseHashes, dataHashes, container, data, dataLen,
                                                basePixel, totalPixels, p, bitIndex);
                p += 8;
                bitIndex += 8 * DataBitsPerPixel;
                basePixel += 8;
                basePixel -= totalPixels & -(int)(basePixel >= totalPixels);
            }
        }
    } else if (useAVX512NoGFNI) {
        // Tier A' 8-pixel batched ZMM loop — AVX-512 F+BW+VL hosts
        // without GFNI (Cascade Lake class). Same loop contract as the
        // Tier A block above, including the encode-side
        // bitIndex/8 + 64 <= dataLen guard for the batched 56-bit
        // extraction loads. Leftover 0-7 pixels fall through to the
        // 4-pixel loops and the scalar tail below.
        if (encode) {
            while (p + 8 <= totalP && bitIndex + 8 * DataBitsPerPixel <= totalBits
                   && bitIndex / 8 + 64 <= dataLen) {
                if (p + PrefetchDistance < totalP) {
                    int prefetchIdx = basePixel + PrefetchDistance;
                    prefetchIdx -= totalPixels & -(int)(prefetchIdx >= totalPixels);
                    __builtin_prefetch(&container[prefetchIdx * Channels], 1, 0);
                }
                process8PixelsEncodeAVX512NoGFNI(noiseHashes, dataHashes, container, data, dataLen,
                                                  basePixel, totalPixels, p, bitIndex);
                p += 8;
                bitIndex += 8 * DataBitsPerPixel;
                basePixel += 8;
                basePixel -= totalPixels & -(int)(basePixel >= totalPixels);
            }
        } else {
            while (p + 8 <= totalP && bitIndex + 8 * DataBitsPerPixel <= totalBits) {
                if (p + PrefetchDistance < totalP) {
                    int prefetchIdx = basePixel + PrefetchDistance;
                    prefetchIdx -= totalPixels & -(int)(prefetchIdx >= totalPixels);
                    __builtin_prefetch(&container[prefetchIdx * Channels], 1, 0);
                }
                process8PixelsDecodeAVX512NoGFNI(noiseHashes, dataHashes, container, data, dataLen,
                                                  basePixel, totalPixels, p, bitIndex);
                p += 8;
                bitIndex += 8 * DataBitsPerPixel;
                basePixel += 8;
                basePixel -= totalPixels & -(int)(basePixel >= totalPixels);
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
            int prefetchIdx = basePixel + PrefetchDistance;
            prefetchIdx -= totalPixels & -(int)(prefetchIdx >= totalPixels);
            __builtin_prefetch(&container[prefetchIdx * Channels], 1, 0);
        }

#if defined(__GNUC__) && defined(__x86_64__)
        if (useAVX2GFNI) {
            if (encode) {
                process4PixelsEncodeAVX2GFNI(noiseHashes, dataHashes, container, data, dataLen,
                                              basePixel, totalPixels, p, bitIndex);
            } else {
                process4PixelsDecodeAVX2GFNI(noiseHashes, dataHashes, container, data, dataLen,
                                              basePixel, totalPixels, p, bitIndex);
            }
            p += 4;
            bitIndex += 4 * DataBitsPerPixel;
            basePixel += 4;
            basePixel -= totalPixels & -(int)(basePixel >= totalPixels);
            continue;
        }
        if (useAVX2NoGFNI) {
            // Tier B' 4-pixel batched YMM loop body — AVX2 hosts
            // without GFNI (Zen 3 / Haswell class), and the 4-7-pixel
            // leftover handler under the Tier A' 8-pixel loop above.
            if (encode) {
                process4PixelsEncodeAVX2NoGFNI(noiseHashes, dataHashes, container, data, dataLen,
                                                basePixel, totalPixels, p, bitIndex);
            } else {
                process4PixelsDecodeAVX2NoGFNI(noiseHashes, dataHashes, container, data, dataLen,
                                                basePixel, totalPixels, p, bitIndex);
            }
            p += 4;
            bitIndex += 4 * DataBitsPerPixel;
            basePixel += 4;
            basePixel -= totalPixels & -(int)(basePixel >= totalPixels);
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
            int linearIdx = basePixel + b;
            linearIdx -= totalPixels & -(int)(linearIdx >= totalPixels);
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
        basePixel += 4;
        basePixel -= totalPixels & -(int)(basePixel >= totalPixels);
    }

    // Tail: scalar per-pixel loop for the remaining 0-3 pixels (or pixels with
    // partial chCount). Same phase structure as the batched kernels, one
    // pixel at a time; the linear index comes from the shared loop-carried
    // basePixel counter.
    for (; p < totalP && bitIndex < totalBits; p++) {
        if (p + PrefetchDistance < totalP) {
            int prefetchIdx = basePixel + PrefetchDistance;
            prefetchIdx -= totalPixels & -(int)(prefetchIdx >= totalPixels);
            __builtin_prefetch(&container[prefetchIdx * Channels], 1, 0);
        }

        int pixelOffset = basePixel * Channels;

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

        basePixel += 1;
        basePixel -= totalPixels & -(int)(basePixel >= totalPixels);
    }
}
#pragma GCC diagnostic pop
