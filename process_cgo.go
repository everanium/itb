//go:build cgo

package itb

/*
#cgo CFLAGS: -O3
#cgo amd64 CFLAGS: -mavx2

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
*/
import "C"
import (
	"sync"
	"unsafe"
)

// microBatchSize is the number of pixels processed per C call.
// Sized to keep hash arrays in L1 cache: 512 × 2 × 8 = 8KB << 48KB L1.
const microBatchSize = 512

// hashPool reuses hash arrays to avoid allocation per processChunk call.
var hashPool = sync.Pool{
	New: func() any {
		return &hashArrays{
			noise: make([]uint64, microBatchSize),
			data:  make([]uint64, microBatchSize),
		}
	},
}

type hashArrays struct {
	noise []uint64
	data  []uint64
}

func getHashArrays(n int) *hashArrays {
	ha := hashPool.Get().(*hashArrays)
	if cap(ha.noise) < n {
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
	// runtime.memclrNoHeapPointers — observable side-effect that the
	// compiler cannot elide, replacing the prior manual-loop + KeepAlive
	// pattern with a single intrinsic that the runtime widens to vector
	// stores on amd64.
	clear(ha.noise)
	clear(ha.data)
	hashPool.Put(ha)
}

// callC sends pre-computed hash arrays to C for pixel bit manipulation.
func callC(noiseHashes, dataHashes []uint64, container, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool) {
	enc := C.int(0)
	if encode {
		enc = 1
	}
	C.itb_process_pixels(
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
//   - Otherwise the legacy single-call blockHash128 loop is used
//     verbatim. Backward compatible with all existing primitives that
//     do not provide a BatchHash field.
func processChunk128(noiseSeed, dataSeed *Seed128, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool) {
	n := endP - startP
	if n <= 0 {
		return
	}

	batchSz := microBatchSize
	if batchSz > n {
		batchSz = n
	}
	ha := getHashArrays(batchSz)
	defer putHashArrays(ha)

	useBatch := noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil
	nonceLen := currentNonceSize()

	noiseBuf := make([]byte, 4+nonceLen)
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 4+nonceLen)
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	// Per-lane scratch buffers used only when the batched path is
	// active. Lane 0 aliases the serial single-call buffer for tail
	// fallback handling within the same iteration; lanes 1..3 are
	// pulled from the shared bufferPool to avoid per-worker heap
	// allocations on high-core-count hosts.
	var noiseBufs, dataBufs [4][]byte
	var noiseBufPtrs, dataBufPtrs [4]*[]byte
	if useBatch {
		noiseBufs[0] = noiseBuf
		dataBufs[0] = dataBuf
		for lane := 1; lane < 4; lane++ {
			noiseBufPtrs[lane], noiseBufs[lane] = acquireBuffer(4 + nonceLen)
			copy(noiseBufs[lane][4:], nonce)
			dataBufPtrs[lane], dataBufs[lane] = acquireBuffer(4 + nonceLen)
			copy(dataBufs[lane][4:], nonce)
			defer releaseBuffer(noiseBufPtrs[lane], noiseBufs[lane])
			defer releaseBuffer(dataBufPtrs[lane], dataBufs[lane])
		}
	}

	for batchStart := startP; batchStart < endP; batchStart += batchSz {
		batchEnd := batchStart + batchSz
		if batchEnd > endP {
			batchEnd = endP
		}
		bn := batchEnd - batchStart

		if useBatch {
			i := 0
			for ; i+4 <= bn; i += 4 {
				pixelIndices := [4]int{batchStart + i, batchStart + i + 1, batchStart + i + 2, batchStart + i + 3}
				noiseHs := noiseSeed.blockHash128x4(&noiseBufs, pixelIndices)
				dataHs := dataSeed.blockHash128x4(&dataBufs, pixelIndices)
				ha.noise[i+0] = noiseHs[0][0]
				ha.noise[i+1] = noiseHs[1][0]
				ha.noise[i+2] = noiseHs[2][0]
				ha.noise[i+3] = noiseHs[3][0]
				ha.data[i+0] = dataHs[0][0]
				ha.data[i+1] = dataHs[1][0]
				ha.data[i+2] = dataHs[2][0]
				ha.data[i+3] = dataHs[3][0]
			}
			for ; i < bn; i++ {
				ha.noise[i], _ = noiseSeed.blockHash128(noiseBuf, batchStart+i)
				ha.data[i], _ = dataSeed.blockHash128(dataBuf, batchStart+i)
			}
		} else {
			for i := 0; i < bn; i++ {
				ha.noise[i], _ = noiseSeed.blockHash128(noiseBuf, batchStart+i)
				ha.data[i], _ = dataSeed.blockHash128(dataBuf, batchStart+i)
			}
		}

		callC(ha.noise[:bn], ha.data[:bn], container, data,
			startPixel, totalPixels, batchStart, batchEnd, totalBits, encode)
	}
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
//   - Otherwise the legacy single-call blockHash256 loop is used
//     verbatim. Backward compatible with all existing primitives that
//     do not provide a BatchHash field.
func processChunk256(noiseSeed, dataSeed *Seed256, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool) {
	n := endP - startP
	if n <= 0 {
		return
	}

	batchSz := microBatchSize
	if batchSz > n {
		batchSz = n
	}
	ha := getHashArrays(batchSz)
	defer putHashArrays(ha)

	useBatch := noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil
	nonceLen := currentNonceSize()

	noiseBuf := make([]byte, 4+nonceLen)
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 4+nonceLen)
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	// Per-lane scratch buffers used only when the batched path is
	// active. Lane 0 aliases the serial single-call buffer for tail
	// fallback handling within the same iteration; lanes 1..3 are
	// pulled from the shared bufferPool to avoid per-worker heap
	// allocations on high-core-count hosts.
	var noiseBufs, dataBufs [4][]byte
	var noiseBufPtrs, dataBufPtrs [4]*[]byte
	if useBatch {
		noiseBufs[0] = noiseBuf
		dataBufs[0] = dataBuf
		for lane := 1; lane < 4; lane++ {
			noiseBufPtrs[lane], noiseBufs[lane] = acquireBuffer(4 + nonceLen)
			copy(noiseBufs[lane][4:], nonce)
			dataBufPtrs[lane], dataBufs[lane] = acquireBuffer(4 + nonceLen)
			copy(dataBufs[lane][4:], nonce)
			defer releaseBuffer(noiseBufPtrs[lane], noiseBufs[lane])
			defer releaseBuffer(dataBufPtrs[lane], dataBufs[lane])
		}
	}

	for batchStart := startP; batchStart < endP; batchStart += batchSz {
		batchEnd := batchStart + batchSz
		if batchEnd > endP {
			batchEnd = endP
		}
		bn := batchEnd - batchStart

		if useBatch {
			i := 0
			for ; i+4 <= bn; i += 4 {
				pixelIndices := [4]int{batchStart + i, batchStart + i + 1, batchStart + i + 2, batchStart + i + 3}
				noiseHs := noiseSeed.blockHash256x4(&noiseBufs, pixelIndices)
				dataHs := dataSeed.blockHash256x4(&dataBufs, pixelIndices)
				ha.noise[i+0] = noiseHs[0][0]
				ha.noise[i+1] = noiseHs[1][0]
				ha.noise[i+2] = noiseHs[2][0]
				ha.noise[i+3] = noiseHs[3][0]
				ha.data[i+0] = dataHs[0][0]
				ha.data[i+1] = dataHs[1][0]
				ha.data[i+2] = dataHs[2][0]
				ha.data[i+3] = dataHs[3][0]
			}
			for ; i < bn; i++ {
				noiseH := noiseSeed.blockHash256(noiseBuf, batchStart+i)
				dataH := dataSeed.blockHash256(dataBuf, batchStart+i)
				ha.noise[i] = noiseH[0]
				ha.data[i] = dataH[0]
			}
		} else {
			for i := 0; i < bn; i++ {
				noiseH := noiseSeed.blockHash256(noiseBuf, batchStart+i)
				dataH := dataSeed.blockHash256(dataBuf, batchStart+i)
				ha.noise[i] = noiseH[0]
				ha.data[i] = dataH[0]
			}
		}

		callC(ha.noise[:bn], ha.data[:bn], container, data,
			startPixel, totalPixels, batchStart, batchEnd, totalBits, encode)
	}
}

// processChunk512 processes pixels using 512-bit hash seeds + C pixel processing.
//
// Batched dispatch when both seeds expose BatchHash; see processChunk256
// for the per-lane buffer layout and tail-handling rationale (the 512
// path mirrors that structure with 8-uint64 hash outputs).
func processChunk512(noiseSeed, dataSeed *Seed512, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool) {
	n := endP - startP
	if n <= 0 {
		return
	}

	batchSz := microBatchSize
	if batchSz > n {
		batchSz = n
	}
	ha := getHashArrays(batchSz)
	defer putHashArrays(ha)

	useBatch := noiseSeed.BatchHash != nil && dataSeed.BatchHash != nil
	nonceLen := currentNonceSize()

	noiseBuf := make([]byte, 4+nonceLen)
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 4+nonceLen)
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	// Per-lane scratch buffers used only when the batched path is
	// active. Same bufferPool reuse as processChunk256.
	var noiseBufs, dataBufs [4][]byte
	var noiseBufPtrs, dataBufPtrs [4]*[]byte
	if useBatch {
		noiseBufs[0] = noiseBuf
		dataBufs[0] = dataBuf
		for lane := 1; lane < 4; lane++ {
			noiseBufPtrs[lane], noiseBufs[lane] = acquireBuffer(4 + nonceLen)
			copy(noiseBufs[lane][4:], nonce)
			dataBufPtrs[lane], dataBufs[lane] = acquireBuffer(4 + nonceLen)
			copy(dataBufs[lane][4:], nonce)
			defer releaseBuffer(noiseBufPtrs[lane], noiseBufs[lane])
			defer releaseBuffer(dataBufPtrs[lane], dataBufs[lane])
		}
	}

	for batchStart := startP; batchStart < endP; batchStart += batchSz {
		batchEnd := batchStart + batchSz
		if batchEnd > endP {
			batchEnd = endP
		}
		bn := batchEnd - batchStart

		if useBatch {
			i := 0
			for ; i+4 <= bn; i += 4 {
				pixelIndices := [4]int{batchStart + i, batchStart + i + 1, batchStart + i + 2, batchStart + i + 3}
				noiseHs := noiseSeed.blockHash512x4(&noiseBufs, pixelIndices)
				dataHs := dataSeed.blockHash512x4(&dataBufs, pixelIndices)
				ha.noise[i+0] = noiseHs[0][0]
				ha.noise[i+1] = noiseHs[1][0]
				ha.noise[i+2] = noiseHs[2][0]
				ha.noise[i+3] = noiseHs[3][0]
				ha.data[i+0] = dataHs[0][0]
				ha.data[i+1] = dataHs[1][0]
				ha.data[i+2] = dataHs[2][0]
				ha.data[i+3] = dataHs[3][0]
			}
			for ; i < bn; i++ {
				noiseH := noiseSeed.blockHash512(noiseBuf, batchStart+i)
				dataH := dataSeed.blockHash512(dataBuf, batchStart+i)
				ha.noise[i] = noiseH[0]
				ha.data[i] = dataH[0]
			}
		} else {
			for i := 0; i < bn; i++ {
				noiseH := noiseSeed.blockHash512(noiseBuf, batchStart+i)
				dataH := dataSeed.blockHash512(dataBuf, batchStart+i)
				ha.noise[i] = noiseH[0]
				ha.data[i] = dataH[0]
			}
		}

		callC(ha.noise[:bn], ha.data[:bn], container, data,
			startPixel, totalPixels, batchStart, batchEnd, totalBits, encode)
	}
}
