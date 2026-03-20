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
	"runtime"
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
	// Wipe ChainHash outputs before returning to pool.
	// runtime.KeepAlive prevents compiler from optimizing away the zero-fill.
	for i := range ha.noise {
		ha.noise[i] = 0
	}
	for i := range ha.data {
		ha.data[i] = 0
	}
	runtime.KeepAlive(ha.noise)
	runtime.KeepAlive(ha.data)
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

// processChunk processes pixels [startP, endP) using C pixel processing.
// Hash computation stays in Go (pluggable). Noise and data hashes are
// computed in parallel (independent seeds, independent buffers).
// Pixel bit manipulation runs in C (one cgo call per chunk).
func processChunk(noiseSeed, dataSeed *Seed, nonce []byte, container []byte, data []byte, startPixel, totalPixels, startP, endP, totalBits int, encode bool) {
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

	noiseBuf := make([]byte, 20)
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 20)
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	// Micro-batching: hash + C call in L1-cache-sized chunks.
	for batchStart := startP; batchStart < endP; batchStart += batchSz {
		batchEnd := batchStart + batchSz
		if batchEnd > endP {
			batchEnd = endP
		}
		bn := batchEnd - batchStart

		for i := 0; i < bn; i++ {
			ha.noise[i] = noiseSeed.blockHash(noiseBuf, batchStart+i)
			ha.data[i] = dataSeed.blockHash(dataBuf, batchStart+i)
		}

		callC(ha.noise[:bn], ha.data[:bn], container, data,
			startPixel, totalPixels, batchStart, batchEnd, totalBits, encode)
	}
}

// processChunk128 processes pixels using 128-bit hash seeds + C pixel processing.
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

	noiseBuf := make([]byte, 20)
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 20)
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	for batchStart := startP; batchStart < endP; batchStart += batchSz {
		batchEnd := batchStart + batchSz
		if batchEnd > endP {
			batchEnd = endP
		}
		bn := batchEnd - batchStart

		for i := 0; i < bn; i++ {
			ha.noise[i], _ = noiseSeed.blockHash128(noiseBuf, batchStart+i)
			ha.data[i], _ = dataSeed.blockHash128(dataBuf, batchStart+i)
		}

		callC(ha.noise[:bn], ha.data[:bn], container, data,
			startPixel, totalPixels, batchStart, batchEnd, totalBits, encode)
	}
}

// processChunk256 processes pixels using 256-bit hash seeds + C pixel processing.
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

	noiseBuf := make([]byte, 20)
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 20)
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	for batchStart := startP; batchStart < endP; batchStart += batchSz {
		batchEnd := batchStart + batchSz
		if batchEnd > endP {
			batchEnd = endP
		}
		bn := batchEnd - batchStart

		for i := 0; i < bn; i++ {
			noiseH := noiseSeed.blockHash256(noiseBuf, batchStart+i)
			dataH := dataSeed.blockHash256(dataBuf, batchStart+i)
			ha.noise[i] = noiseH[0]
			ha.data[i] = dataH[0]
		}

		callC(ha.noise[:bn], ha.data[:bn], container, data,
			startPixel, totalPixels, batchStart, batchEnd, totalBits, encode)
	}
}

// processChunk512 processes pixels using 512-bit hash seeds + C pixel processing.
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

	noiseBuf := make([]byte, 20)
	copy(noiseBuf[4:], nonce)
	dataBuf := make([]byte, 20)
	copy(dataBuf[4:], nonce)
	defer secureWipe(noiseBuf)
	defer secureWipe(dataBuf)

	for batchStart := startP; batchStart < endP; batchStart += batchSz {
		batchEnd := batchStart + batchSz
		if batchEnd > endP {
			batchEnd = endP
		}
		bn := batchEnd - batchStart

		for i := 0; i < bn; i++ {
			noiseH := noiseSeed.blockHash512(noiseBuf, batchStart+i)
			dataH := dataSeed.blockHash512(dataBuf, batchStart+i)
			ha.noise[i] = noiseH[0]
			ha.data[i] = dataH[0]
		}

		callC(ha.noise[:bn], ha.data[:bn], container, data,
			startPixel, totalPixels, batchStart, batchEnd, totalBits, encode)
	}
}
