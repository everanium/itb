package itb

import (
	"encoding/binary"
	"sync"
)

// splitForTripleParallel is the parallel counterpart of [splitForTriple].
// Both branches run 3-way parallel kernels - byte-level via
// [splitTripleParallel] (3 strided goroutines, one per lane), bit-soup via
// [splitTripleBitsParallel] (period-3-byte chunks across CPU cores).
func splitForTripleParallel(data []byte) (p0, p1, p2 []byte) {
	if isBitSoupEnabled() {
		p0, p1, p2, _ = splitTripleBitsParallel(prependTripleLen(data))
		return
	}
	return splitTripleParallel(data)
}

// interleaveForTripleParallel is the parallel counterpart of
// [interleaveForTriple]. Same plausible-decryption invariant - never errors,
// returns wrong-seed garbage clamped to the recovered payload extent.
// Both branches run 3-way parallel kernels - byte-level via
// [interleaveTripleParallel], bit-soup via [interleaveTripleBitsParallel].
func interleaveForTripleParallel(p0, p1, p2 []byte) []byte {
	if !isBitSoupEnabled() {
		return interleaveTripleParallel(p0, p1, p2)
	}
	totalBits := recoverTripleBitsLen(len(p0), len(p1), len(p2))
	framed := interleaveTripleBitsParallel(p0, p1, p2, totalBits)
	if len(framed) < 4 {
		return framed
	}
	length := binary.BigEndian.Uint32(framed[:4])
	end := uint64(length) + 4
	if end > uint64(len(framed)) {
		end = uint64(len(framed))
	}
	return framed[4:int(end)]
}

// splitTriple splits data into 3 parts: bytes[0::3], bytes[1::3], bytes[2::3].
func splitTriple(data []byte) (p0, p1, p2 []byte) {
	n := len(data)
	s0 := (n + 2) / 3
	s1 := (n + 1) / 3
	s2 := n / 3
	p0 = make([]byte, s0)
	p1 = make([]byte, s1)
	p2 = make([]byte, s2)
	for i, b := range data {
		switch i % 3 {
		case 0:
			p0[i/3] = b
		case 1:
			p1[i/3] = b
		case 2:
			p2[i/3] = b
		}
	}
	return
}

// interleaveTriple reassembles 3 parts into original byte order.
func interleaveTriple(p0, p1, p2 []byte) []byte {
	total := len(p0) + len(p1) + len(p2)
	result := make([]byte, total)
	for i := 0; i < len(p0); i++ {
		idx := i * 3
		if idx < total {
			result[idx] = p0[i]
		}
	}
	for i := 0; i < len(p1); i++ {
		idx := i*3 + 1
		if idx < total {
			result[idx] = p1[i]
		}
	}
	for i := 0; i < len(p2); i++ {
		idx := i*3 + 2
		if idx < total {
			result[idx] = p2[i]
		}
	}
	return result
}

// splitTripleParallel produces output bit-identical to [splitTriple] via
// 3 parallel goroutines. Each goroutine reads strided bytes from data
// (lane k reads data[k], data[k+3], data[k+6], ...) and writes to its
// own lane buffer. No synchronization beyond the final wg.Wait - each
// goroutine writes to a disjoint buffer.
func splitTripleParallel(data []byte) (p0, p1, p2 []byte) {
	n := len(data)
	p0 = make([]byte, (n+2)/3)
	p1 = make([]byte, (n+1)/3)
	p2 = make([]byte, n/3)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i += 3 {
			p0[i/3] = data[i]
		}
	}()
	go func() {
		defer wg.Done()
		for i := 1; i < n; i += 3 {
			p1[i/3] = data[i]
		}
	}()
	go func() {
		defer wg.Done()
		for i := 2; i < n; i += 3 {
			p2[i/3] = data[i]
		}
	}()
	wg.Wait()
	return
}

// interleaveTripleParallel produces output bit-identical to
// [interleaveTriple] via 3 parallel goroutines. Each goroutine writes to
// its own striped subset of the output (lane 0: indices 0, 3, 6, ...;
// lane 1: 1, 4, 7, ...; lane 2: 2, 5, 8, ...) - disjoint write set, no
// race between goroutines.
func interleaveTripleParallel(p0, p1, p2 []byte) []byte {
	total := len(p0) + len(p1) + len(p2)
	result := make([]byte, total)

	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < len(p0); i++ {
			idx := i * 3
			if idx < total {
				result[idx] = p0[i]
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < len(p1); i++ {
			idx := i*3 + 1
			if idx < total {
				result[idx] = p1[i]
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < len(p2); i++ {
			idx := i*3 + 2
			if idx < total {
				result[idx] = p2[i]
			}
		}
	}()
	wg.Wait()
	return result
}
