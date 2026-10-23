//go:build cgo

package itb

/*
#cgo CFLAGS: -O3

#include <stdint.h>

extern void itb_process_pixels(
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
);

extern void itb_process_pixels_batch(
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
    int encode,
    int wipeOnExit
);

extern void itb_test_probe_pixels_c_stack(
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
    int encode,
    int mode,
    int tier,
    uint64_t *outWindow,
    int windowWords
);
*/
import "C"
import (
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/everanium/itb/internal/poolstats"
)

// defaultHashPoolStarters is the shipped hash-array sync.Pool starter
// ladder. Two tiers so an adaptive batch stride does not force the
// small tier to grow into the large one on every call while sync.Pool
// is dropping items across GC cycles:
//
//   - 512 elements × 8 bytes × 2 arrays = 8 KiB per item: serves callers
//     whose adaptive stride stays at the baseline 512 (very small and
//     very large payloads).
//   - 262144 elements × 8 bytes × 2 arrays = 4 MiB per item: serves
//     callers whose adaptive stride opens up to the high-tier value
//     (mid-band payloads). Fresh items already carry the widest
//     realistic batch capacity, so no per-call regrow.
//
// Starter-width items are deliberately not sized lazily to the width a
// worker requests: the pooled full-width arrays raise the live heap
// between calls, which under a constrained GOGC widens the collector's
// heap goal and spaces collections (and the pool evictions they cause)
// further apart. Lazy sizing lowers bytes per call but measurably
// lowers throughput at GOGC=100 on the 1 MB message cells.
//
// The ITB_HASHPOOL_STARTERS env var overrides this ladder for the
// microBatch-sweep test harness. Format: comma-separated int list, e.g.
// "512,65536,262144". Values below 1 are dropped, duplicates removed,
// list sorted ascending. Malformed value falls back to defaults.
var defaultHashPoolStarters = []int{512, 262144}

var (
	hashPoolStarters []int
	hashPools        []*sync.Pool
)

func init() {
	hashPoolStarters, hashPools = buildHashPools(loadHashPoolStarters())
}

func loadHashPoolStarters() []int {
	if s := strings.TrimSpace(os.Getenv("ITB_HASHPOOL_STARTERS")); s != "" {
		if parsed, ok := parseHashPoolStarters(s); ok {
			return parsed
		}
	}
	return append([]int(nil), defaultHashPoolStarters...)
}

func parseHashPoolStarters(s string) ([]int, bool) {
	seen := map[int]struct{}{}
	var out []int
	for _, part := range strings.Split(s, ",") {
		v, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || v <= 0 {
			return nil, false
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, false
	}
	sort.Ints(out)
	return out, true
}

func buildHashPools(starters []int) ([]int, []*sync.Pool) {
	pools := make([]*sync.Pool, len(starters))
	for i, starter := range starters {
		size := starter
		tier := i
		if tier < poolstats.MaxHashTiers {
			poolstats.HashStarter[tier].Store(int64(starter))
		}
		pools[i] = &sync.Pool{
			New: func() any {
				if tier < poolstats.MaxHashTiers {
					poolstats.HashNew[tier].Add(1)
					poolstats.HashNewBytes[tier].Add(int64(2 * 8 * size))
				}
				return &hashArrays{
					noise: make([]uint64, size),
					data:  make([]uint64, size),
				}
			},
		}
	}
	return starters, pools
}

type hashArrays struct {
	noise   []uint64 // per-pixel noise positions ([noisePosition]); C reads the low 3 bits
	data    []uint64 // per-pixel data hash word 0 (rotation + XOR masks)
	poolIdx int      // tier index so putHashArrays returns to the matching pool
}

// getHashArraysFor picks the smallest sync.Pool whose starter size is
// >= microBatch; falls back to the largest tier when microBatch exceeds
// every configured starter. Returned arrays have length exactly n
// (grown on demand if the pool item does not already carry the width).
func getHashArraysFor(microBatch, n int) *hashArrays {
	poolIdx := len(hashPoolStarters) - 1
	for i, starter := range hashPoolStarters {
		if starter >= microBatch {
			poolIdx = i
			break
		}
	}
	ha := hashPools[poolIdx].Get().(*hashArrays)
	ha.poolIdx = poolIdx
	if poolIdx < poolstats.MaxHashTiers {
		poolstats.HashGet[poolIdx].Add(1)
	}
	if cap(ha.noise) < n {
		if poolIdx < poolstats.MaxHashTiers {
			poolstats.HashRegrow[poolIdx].Add(1)
			poolstats.HashNewBytes[poolIdx].Add(int64(2 * 8 * n))
		}
		ha.noise = make([]uint64, n)
		ha.data = make([]uint64, n)
	} else {
		ha.noise = ha.noise[:n]
		ha.data = ha.data[:n]
	}
	return ha
}

func putHashArrays(ha *hashArrays) {
	// Wipe ChainHash outputs before returning to pool. clear() lowers to
	// runtime.memclrNoHeapPointers — an observable side-effect that the
	// compiler cannot elide, widening to vector stores on amd64.
	clear(ha.noise)
	clear(ha.data)
	hashPools[ha.poolIdx].Put(ha)
}

// callC sends the per-pixel noise positions and data hash words to C for
// pixel bit manipulation, wiping C stack and SIMD state before returning.
func callC(noiseHashes, dataHashes []uint64, container, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool) {
	callCBatch(noiseHashes, dataHashes, container, data, startPixel, totalPixels, startP, endP, totalBits, encode, true)
}

// callCBatch sends one microbatch of pixels to C, running the C stack and
// register scrubber when wipeOnExit is true (the final microbatch of a worker).
func callCBatch(noiseHashes, dataHashes []uint64, container, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode, wipeOnExit bool) {
	enc := C.int(0)
	if encode {
		enc = 1
	}
	wipe := C.int(0)
	if wipeOnExit {
		wipe = 1
	}
	C.itb_process_pixels_batch(
		(*C.uint64_t)(unsafe.Pointer(&noiseHashes[0])),
		(*C.uint64_t)(unsafe.Pointer(&dataHashes[0])),
		(*C.uint8_t)(unsafe.Pointer(&container[0])),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.int(len(data)),
		C.int(startPixel),
		C.int(totalPixels),
		C.int(startP),
		C.int(endP),
		C.int(totalBits),
		enc,
		wipe,
	)
}

func probePixelsCStack(noiseHashes, dataHashes []uint64, container, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool, mode, tier int, window []uint64) {
	enc := C.int(0)
	if encode {
		enc = 1
	}
	C.itb_test_probe_pixels_c_stack(
		(*C.uint64_t)(unsafe.Pointer(&noiseHashes[0])),
		(*C.uint64_t)(unsafe.Pointer(&dataHashes[0])),
		(*C.uint8_t)(unsafe.Pointer(&container[0])),
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		C.int(len(data)),
		C.int(startPixel),
		C.int(totalPixels),
		C.int(startP),
		C.int(endP),
		C.int(totalBits),
		enc,
		C.int(mode),
		C.int(tier),
		(*C.uint64_t)(unsafe.Pointer(&window[0])),
		C.int(len(window)),
	)
}

// processChunk128 processes pixels using 128-bit hash seeds + C pixel processing.
//
// Two dispatch paths in the inner per-pixel hash loop:
//
//   - If both noiseSeed.BatchHash and dataSeed.BatchHash are non-nil,
//     hashing dispatches four pixels at a time through the batched
//     ChainHash path (blockHash128x4). Per-pixel encoding remains
//     unchanged — the batched path only changes how hashes are
//     produced, not how container bytes are touched. Tail of 0–3
//     leftover pixels falls back to single-call blockHash128.
//   - Otherwise the serial single-call blockHash128 loop is used
//     verbatim. Backward compatible with all existing primitives that
//     do not provide a BatchHash field.
func processChunk128(cfg *Config, noiseSeed, dataSeed *Seed128, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits, microBatch int, encode bool, noiseBase int) {
	if endP <= startP {
		return
	}
	wipePixelCallStack([9][8]uint64{})
	processChunk128Body(cfg, noiseSeed, dataSeed, nonce, container, data, startPixel, totalPixels, startP, endP, totalBits, microBatch, encode, noiseBase)
	wipePixelCallStack([9][8]uint64{})
}

//go:noinline
func processChunk128Body(cfg *Config, noiseSeed, dataSeed *Seed128, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits, microBatch int, encode bool, noiseBase int) {
	n := endP - startP

	batchSz := microBatch
	if batchSz > n {
		batchSz = n
	}
	ha := getHashArraysFor(microBatch, batchSz)
	defer putHashArrays(ha)

	useBatch := noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil

	// Per-worker hash-input lanes (see lanescratch.go): lane 0 is the
	// serial single-call buffer, lanes 0..3 feed the four-pixel batched
	// path and lanes 0..7 the eight-pixel stride, all in one block.
	ls := newLaneScratch(nonce, currentNonceSizeCfg(cfg))
	defer ls.wipe()
	noiseBuf, dataBuf := ls.noise[0], ls.data[0]
	noiseBufs, dataBufs := &ls.noise4, &ls.data4

	// Eight-pixel stride (see process_x8.go): lanes 4..7 extend the
	// four-lane buffers when both seeds carry the eight-lane fused hook.
	useBatch8 := useBatch8Seeds(noiseSeed, dataSeed)
	noiseBufs8, dataBufs8 := &ls.noise, &ls.data

	var (
		noiseHs8, dataHs8 [8][2]uint64
		noiseHs4, dataHs4 [4][2]uint64
	)

	for batchStart := startP; batchStart < endP; batchStart += batchSz {
		batchEnd := batchStart + batchSz
		if batchEnd > endP {
			batchEnd = endP
		}
		bn := batchEnd - batchStart

		if useBatch {
			i := 0
			if useBatch8 {
				for ; i+8 <= bn; i += 8 {
					base := batchStart + i
					pixelIndices := [8]int{base, base + 1, base + 2, base + 3, base + 4, base + 5, base + 6, base + 7}
					noiseHs8 = noiseSeed.blockHash128x8(noiseBufs8, noiseIdx8(pixelIndices, noiseBase))
					dataHs8 = dataSeed.blockHash128x8(dataBufs8, pixelIndices)
					for lane := 0; lane < 8; lane++ {
						ha.noise[i+lane] = uint64(noisePosition(noiseHs8[lane][0], noiseHs8[lane][1]))
						ha.data[i+lane] = dataHs8[lane][0]
					}
				}
			}
			for ; i+4 <= bn; i += 4 {
				pixelIndices := [4]int{batchStart + i, batchStart + i + 1, batchStart + i + 2, batchStart + i + 3}
				noiseHs4 = noiseSeed.blockHash128x4(noiseBufs, noiseIdx4(pixelIndices, noiseBase))
				dataHs4 = dataSeed.blockHash128x4(dataBufs, pixelIndices)
				ha.noise[i+0] = uint64(noisePosition(noiseHs4[0][0], noiseHs4[0][1]))
				ha.noise[i+1] = uint64(noisePosition(noiseHs4[1][0], noiseHs4[1][1]))
				ha.noise[i+2] = uint64(noisePosition(noiseHs4[2][0], noiseHs4[2][1]))
				ha.noise[i+3] = uint64(noisePosition(noiseHs4[3][0], noiseHs4[3][1]))
				ha.data[i+0] = dataHs4[0][0]
				ha.data[i+1] = dataHs4[1][0]
				ha.data[i+2] = dataHs4[2][0]
				ha.data[i+3] = dataHs4[3][0]
			}
			for ; i < bn; i++ {
				noiseLo, noiseHi := noiseSeed.blockHash128(noiseBuf, noiseBase+batchStart+i)
				ha.noise[i] = uint64(noisePosition(noiseLo, noiseHi))
				ha.data[i], _ = dataSeed.blockHash128(dataBuf, batchStart+i)
			}
		} else {
			for i := 0; i < bn; i++ {
				noiseLo, noiseHi := noiseSeed.blockHash128(noiseBuf, noiseBase+batchStart+i)
				ha.noise[i] = uint64(noisePosition(noiseLo, noiseHi))
				ha.data[i], _ = dataSeed.blockHash128(dataBuf, batchStart+i)
			}
		}

		callCBatch(ha.noise[:bn], ha.data[:bn], container, data,
			startPixel, totalPixels, batchStart, batchEnd, totalBits, encode, batchEnd >= endP)
	}

	clear(noiseHs8[:])
	clear(dataHs8[:])
	clear(noiseHs4[:])
	clear(dataHs4[:])
	runtime.KeepAlive(&noiseHs8)
	runtime.KeepAlive(&dataHs8)
	runtime.KeepAlive(&noiseHs4)
	runtime.KeepAlive(&dataHs4)
}

// processChunk256 processes pixels using 256-bit hash seeds + C pixel processing.
//
// Two dispatch paths in the inner per-pixel hash loop:
//
//   - If both noiseSeed.BatchHash and dataSeed.BatchHash are non-nil,
//     hashing dispatches four pixels at a time through the batched
//     ChainHash path (blockHash256x4). Per-pixel encoding remains
//     unchanged — the batched path only changes how hashes are
//     produced, not how container bytes are touched. Tail of 0–3
//     leftover pixels falls back to single-call blockHash256.
//   - Otherwise the serial single-call blockHash256 loop is used
//     verbatim. Backward compatible with all existing primitives that
//     do not provide a BatchHash field.
func processChunk256(cfg *Config, noiseSeed, dataSeed *Seed256, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits, microBatch int, encode bool, noiseBase int) {
	if endP <= startP {
		return
	}
	wipePixelCallStack256([9][8]uint64{})
	processChunk256Body(cfg, noiseSeed, dataSeed, nonce, container, data, startPixel, totalPixels, startP, endP, totalBits, microBatch, encode, noiseBase)
	wipePixelCallStack256([9][8]uint64{})
}

//go:noinline
func processChunk256Body(cfg *Config, noiseSeed, dataSeed *Seed256, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits, microBatch int, encode bool, noiseBase int) {
	n := endP - startP

	batchSz := microBatch
	if batchSz > n {
		batchSz = n
	}
	ha := getHashArraysFor(microBatch, batchSz)
	defer putHashArrays(ha)

	useBatch := noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil

	// Per-worker hash-input lanes (see lanescratch.go): lane 0 is the
	// serial single-call buffer, lanes 0..3 feed the four-pixel batched
	// path and lanes 0..7 the eight-pixel stride, all in one block.
	ls := newLaneScratch(nonce, currentNonceSizeCfg(cfg))
	defer ls.wipe()
	noiseBuf, dataBuf := ls.noise[0], ls.data[0]
	noiseBufs, dataBufs := &ls.noise4, &ls.data4

	// Eight-pixel stride (see process_x8.go): lanes 4..7 extend the
	// four-lane buffers when both seeds carry the eight-lane fused hook.
	useBatch8 := useBatch8Seeds256(noiseSeed, dataSeed)
	noiseBufs8, dataBufs8 := &ls.noise, &ls.data

	var (
		noiseHs8, dataHs8 [8][4]uint64
		noiseHs4, dataHs4 [4][4]uint64
		noiseH, dataH     [4]uint64
	)

	for batchStart := startP; batchStart < endP; batchStart += batchSz {
		batchEnd := batchStart + batchSz
		if batchEnd > endP {
			batchEnd = endP
		}
		bn := batchEnd - batchStart

		if useBatch {
			i := 0
			if useBatch8 {
				for ; i+8 <= bn; i += 8 {
					base := batchStart + i
					pixelIndices := [8]int{base, base + 1, base + 2, base + 3, base + 4, base + 5, base + 6, base + 7}
					noiseHs8 = noiseSeed.blockHash256x8(noiseBufs8, noiseIdx8(pixelIndices, noiseBase))
					dataHs8 = dataSeed.blockHash256x8(dataBufs8, pixelIndices)
					for lane := 0; lane < 8; lane++ {
						ha.noise[i+lane] = uint64(noisePosition(noiseHs8[lane][0], noiseHs8[lane][1]))
						ha.data[i+lane] = dataHs8[lane][0]
					}
				}
			}
			for ; i+4 <= bn; i += 4 {
				pixelIndices := [4]int{batchStart + i, batchStart + i + 1, batchStart + i + 2, batchStart + i + 3}
				noiseHs4 = noiseSeed.blockHash256x4(noiseBufs, noiseIdx4(pixelIndices, noiseBase))
				dataHs4 = dataSeed.blockHash256x4(dataBufs, pixelIndices)
				ha.noise[i+0] = uint64(noisePosition(noiseHs4[0][0], noiseHs4[0][1]))
				ha.noise[i+1] = uint64(noisePosition(noiseHs4[1][0], noiseHs4[1][1]))
				ha.noise[i+2] = uint64(noisePosition(noiseHs4[2][0], noiseHs4[2][1]))
				ha.noise[i+3] = uint64(noisePosition(noiseHs4[3][0], noiseHs4[3][1]))
				ha.data[i+0] = dataHs4[0][0]
				ha.data[i+1] = dataHs4[1][0]
				ha.data[i+2] = dataHs4[2][0]
				ha.data[i+3] = dataHs4[3][0]
			}
			for ; i < bn; i++ {
				noiseH = noiseSeed.blockHash256(noiseBuf, noiseBase+batchStart+i)
				dataH = dataSeed.blockHash256(dataBuf, batchStart+i)
				ha.noise[i] = uint64(noisePosition(noiseH[0], noiseH[1]))
				ha.data[i] = dataH[0]
			}
		} else {
			for i := 0; i < bn; i++ {
				noiseH = noiseSeed.blockHash256(noiseBuf, noiseBase+batchStart+i)
				dataH = dataSeed.blockHash256(dataBuf, batchStart+i)
				ha.noise[i] = uint64(noisePosition(noiseH[0], noiseH[1]))
				ha.data[i] = dataH[0]
			}
		}

		callCBatch(ha.noise[:bn], ha.data[:bn], container, data,
			startPixel, totalPixels, batchStart, batchEnd, totalBits, encode, batchEnd >= endP)
	}

	clear(noiseHs8[:])
	clear(dataHs8[:])
	clear(noiseHs4[:])
	clear(dataHs4[:])
	clear(noiseH[:])
	clear(dataH[:])
	runtime.KeepAlive(&noiseHs8)
	runtime.KeepAlive(&dataHs8)
	runtime.KeepAlive(&noiseHs4)
	runtime.KeepAlive(&dataHs4)
	runtime.KeepAlive(&noiseH)
	runtime.KeepAlive(&dataH)
}

// processChunk512 processes pixels using 512-bit hash seeds + C pixel processing.
//
// Batched dispatch when both seeds expose BatchHash; see processChunk256
// for the per-lane buffer layout and tail-handling rationale (the 512
// path mirrors that structure with 8-uint64 hash outputs).
func processChunk512(cfg *Config, noiseSeed, dataSeed *Seed512, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits, microBatch int, encode bool, noiseBase int) {
	if endP <= startP {
		return
	}
	wipePixelCallStack512([9][8]uint64{})
	processChunk512Body(cfg, noiseSeed, dataSeed, nonce, container, data, startPixel, totalPixels, startP, endP, totalBits, microBatch, encode, noiseBase)
	wipePixelCallStack512([9][8]uint64{})
}

//go:noinline
func processChunk512Body(cfg *Config, noiseSeed, dataSeed *Seed512, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits, microBatch int, encode bool, noiseBase int) {
	n := endP - startP

	batchSz := microBatch
	if batchSz > n {
		batchSz = n
	}
	ha := getHashArraysFor(microBatch, batchSz)
	defer putHashArrays(ha)

	useBatch := noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil

	// Per-worker hash-input lanes (see lanescratch.go): same layout as
	// processChunk256.
	ls := newLaneScratch(nonce, currentNonceSizeCfg(cfg))
	defer ls.wipe()
	noiseBuf, dataBuf := ls.noise[0], ls.data[0]
	noiseBufs, dataBufs := &ls.noise4, &ls.data4

	// Eight-pixel stride (see process_x8.go): lanes 4..7 extend the
	// four-lane buffers when both seeds carry the eight-lane fused hook.
	useBatch8 := useBatch8Seeds512(noiseSeed, dataSeed)
	noiseBufs8, dataBufs8 := &ls.noise, &ls.data

	var (
		noiseHs8, dataHs8 [8][8]uint64
		noiseHs4, dataHs4 [4][8]uint64
		noiseH, dataH     [8]uint64
	)

	for batchStart := startP; batchStart < endP; batchStart += batchSz {
		batchEnd := batchStart + batchSz
		if batchEnd > endP {
			batchEnd = endP
		}
		bn := batchEnd - batchStart

		if useBatch {
			i := 0
			if useBatch8 {
				for ; i+8 <= bn; i += 8 {
					base := batchStart + i
					pixelIndices := [8]int{base, base + 1, base + 2, base + 3, base + 4, base + 5, base + 6, base + 7}
					noiseHs8 = noiseSeed.blockHash512x8(noiseBufs8, noiseIdx8(pixelIndices, noiseBase))
					dataHs8 = dataSeed.blockHash512x8(dataBufs8, pixelIndices)
					for lane := 0; lane < 8; lane++ {
						ha.noise[i+lane] = uint64(noisePosition(noiseHs8[lane][0], noiseHs8[lane][1]))
						ha.data[i+lane] = dataHs8[lane][0]
					}
				}
			}
			for ; i+4 <= bn; i += 4 {
				pixelIndices := [4]int{batchStart + i, batchStart + i + 1, batchStart + i + 2, batchStart + i + 3}
				noiseHs4 = noiseSeed.blockHash512x4(noiseBufs, noiseIdx4(pixelIndices, noiseBase))
				dataHs4 = dataSeed.blockHash512x4(dataBufs, pixelIndices)
				ha.noise[i+0] = uint64(noisePosition(noiseHs4[0][0], noiseHs4[0][1]))
				ha.noise[i+1] = uint64(noisePosition(noiseHs4[1][0], noiseHs4[1][1]))
				ha.noise[i+2] = uint64(noisePosition(noiseHs4[2][0], noiseHs4[2][1]))
				ha.noise[i+3] = uint64(noisePosition(noiseHs4[3][0], noiseHs4[3][1]))
				ha.data[i+0] = dataHs4[0][0]
				ha.data[i+1] = dataHs4[1][0]
				ha.data[i+2] = dataHs4[2][0]
				ha.data[i+3] = dataHs4[3][0]
			}
			for ; i < bn; i++ {
				noiseH = noiseSeed.blockHash512(noiseBuf, noiseBase+batchStart+i)
				dataH = dataSeed.blockHash512(dataBuf, batchStart+i)
				ha.noise[i] = uint64(noisePosition(noiseH[0], noiseH[1]))
				ha.data[i] = dataH[0]
			}
		} else {
			for i := 0; i < bn; i++ {
				noiseH = noiseSeed.blockHash512(noiseBuf, noiseBase+batchStart+i)
				dataH = dataSeed.blockHash512(dataBuf, batchStart+i)
				ha.noise[i] = uint64(noisePosition(noiseH[0], noiseH[1]))
				ha.data[i] = dataH[0]
			}
		}

		callCBatch(ha.noise[:bn], ha.data[:bn], container, data,
			startPixel, totalPixels, batchStart, batchEnd, totalBits, encode, batchEnd >= endP)
	}

	clear(noiseHs8[:])
	clear(dataHs8[:])
	clear(noiseHs4[:])
	clear(dataHs4[:])
	clear(noiseH[:])
	clear(dataH[:])
	runtime.KeepAlive(&noiseHs8)
	runtime.KeepAlive(&dataHs8)
	runtime.KeepAlive(&noiseHs4)
	runtime.KeepAlive(&dataHs4)
	runtime.KeepAlive(&noiseH)
	runtime.KeepAlive(&dataH)
}
