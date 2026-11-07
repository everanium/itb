package itb

import (
	"math/bits"
	"runtime"
	"sync"
)

const (
	// minDesyncRegionPixels is the minimum per-region pixel count for
	// Layer I (0x05) sub-region partitioning (k <= 10 with delta in {-1, 0}
	// requires base = totalPixels/k >= 3). Standard 1024-bit Mode 2 and Mode 1
	// containers have totalPixels >= 147 and >= 408 per region respectively,
	// while low-level 512-bit Mode 2 callers have totalPixels >= 75.
	minDesyncRegionPixels = 32

	// mode1DesyncRegionPixels is the per-region pixel threshold separating
	// compact Mode 2 containers (P_r < 365, K_r in [6, 10], deltaMax = 1)
	// from standard Mode 1 containers (P_r >= 365, K_r in [8, 16], deltaMax = 2).
	mode1DesyncRegionPixels = 365

	maxDesyncSubregions = 16
	maxDesyncLaneSubs   = 8
	maxDesyncNonceBytes = 64

	// minDesyncParallelLaneBytes is the per-lane byte threshold at which
	// Layer II encrypt, decrypt, and staging-buffer zeroization parallelize
	// across the three lanes (p0, p1, p2).
	minDesyncParallelLaneBytes = 16384

	desyncGoldenGamma uint64 = 0x9E3779B97F4A7C15
)

// fullWidthFold applies the bijective 128-bit Feistel fold over a ChainHash
// output pair (hLo, hHi) under domain tags 0x05 (Layer I sub-region schedule)
// and 0x06 (Layer II cross-lane chunk-slot desynchronization), matching
// fullWidthFold in lean/ITB/Desync.lean:
//
//	mixHi = rotl64(hHi, 25) + rotl64(hHi, 53)
//	w0    = hLo + mixHi
//	w1    = hHi ^ rotl64(w0, 19) ^ rotl64(w0, 41)
func fullWidthFold(hLo, hHi uint64) (w0, w1 uint64) {
	mixHi := bits.RotateLeft64(hHi, 25) + bits.RotateLeft64(hHi, 53)
	w0 = hLo + mixHi
	w1 = hHi ^ bits.RotateLeft64(w0, 19) ^ bits.RotateLeft64(w0, 41)
	return w0, w1
}

// effectiveStartPixel computes the effective startPixel parameter handed to
// processChunk{128,256,512} for a sub-region of physical size m, local start
// offset s in [0, m), and logical stream start offset p, matching
// effectiveStartPixel in lean/ITB/Desync.lean:
//
//	effectiveStartPixel(m, s, p) = (s + m - (p % m)) % m
//
// By effectiveStartPixel_compat, for any q in [0, m) with global logical pixel
// pp = p + q, (effectiveStartPixel(m, s, p) + pp) % m == (s + q) % m.
func effectiveStartPixel(m, s, p int) int {
	return (s + m - (p % m)) % m
}

// subregionSchedule holds the stack-allocated Layer I (0x05) sub-region
// trajectory schedule for one container region.
type subregionSchedule struct {
	k      int
	offset [maxDesyncSubregions]int     // physical pixel offset O_{tau[step]}
	size   [maxDesyncSubregions]int     // physical pixel length M_{tau[step]}
	start  [maxDesyncSubregions]int     // local cyclic start s_{step} in [0, M_{tau[step]})
	logOff [maxDesyncSubregions + 1]int // cumulative logical pixel offset P_{step}
}

// buildSubregionSchedule constructs the Layer I sub-region partition,
// telescopic boundary jitter, Fisher-Yates traversal order tau_r, and
// per-sub-region local starting pixels from the 8 folded 0x05 words w[0..7].
func buildSubregionSchedule(startPixel, totalPixels int, w [8]uint64) subregionSchedule {
	var k, deltaMax int
	if totalPixels < mode1DesyncRegionPixels {
		k = 6 + int(w[0]%5) // [6, 10]
		deltaMax = 1        // delta in {-1, 0}
	} else {
		k = 8 + int(w[0]%9) // [8, 16]
		deltaMax = 2        // delta in {-2, -1, 0, +1}
	}

	var physOff [maxDesyncSubregions + 1]int
	var physSize [maxDesyncSubregions]int
	base := totalPixels / k
	rem := totalPixels % k
	for j := 0; j < k; j++ {
		sz := base
		if j < rem {
			sz++
		}
		physOff[j+1] = physOff[j] + sz
	}

	for j := 1; j < k; j++ {
		var delta int
		if deltaMax == 1 {
			raw := int((w[0] >> uint(8+j)) & 1)
			delta = raw - 1
		} else {
			raw := int((w[0] >> uint(8+2*j)) & 3)
			delta = raw - 2
		}
		physOff[j] += delta
	}
	for j := 0; j < k; j++ {
		physSize[j] = physOff[j+1] - physOff[j]
	}

	var tau [maxDesyncSubregions]int
	for i := 0; i < k; i++ {
		tau[i] = i
	}
	u := w[1]
	for i := k - 1; i > 0; i-- {
		mod := uint64(i + 1)
		swapIdx := int(u % mod)
		u /= mod
		tau[i], tau[swapIdx] = tau[swapIdx], tau[i]
	}

	var sched subregionSchedule
	sched.k = k
	for step := 0; step < k; step++ {
		physIdx := tau[step]
		m := physSize[physIdx]
		sched.offset[step] = physOff[physIdx]
		sched.size[step] = m
		sched.logOff[step+1] = sched.logOff[step] + m
		mix := bits.RotateLeft64(w[2+(step%6)], 11*step) ^ (uint64(step+1) * desyncGoldenGamma)
		sched.start[step] = int((uint64(startPixel) + mix) % uint64(m))
	}
	return sched
}

// deriveSubregionSchedule derives the Layer I (0x05) sub-region schedule for
// a 128-bit startSeed over fixed-length buffers [0x05 || nonce] (with counter
// j in 0..3 XORed into the final byte of nonce).
func (s *Seed128) deriveSubregionSchedule(nonce []byte, startPixel, totalPixels int) subregionSchedule {
	wipePixelCallStack([9][8]uint64{})
	sched := s.deriveSubregionScheduleBody(nonce, startPixel, totalPixels)
	wipePixelCallStack([9][8]uint64{})
	return sched
}

//go:noinline
func (s *Seed128) deriveSubregionScheduleBody(nonce []byte, startPixel, totalPixels int) subregionSchedule {
	var stackBuf [1 + maxDesyncNonceBytes]byte
	buf := stackBuf[:1+len(nonce)]
	buf[0] = 0x05
	copy(buf[1:], nonce)
	last := len(buf) - 1
	baseByte := nonce[len(nonce)-1]
	var w [8]uint64
	for j := 0; j < 4; j++ {
		buf[last] = baseByte ^ byte(j)
		lo, hi := s.ChainHash128(buf)
		w[2*j], w[2*j+1] = fullWidthFold(lo, hi)
	}
	sched := buildSubregionSchedule(startPixel, totalPixels, w)
	clear(w[:])
	clear(stackBuf[:])
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&stackBuf)
	return sched
}

// deriveSubregionSchedule derives the Layer I (0x05) sub-region schedule for
// a 256-bit startSeed over fixed-length buffers [0x05 || nonce] (with counter
// j in 0..1 XORed into the final byte of nonce).
func (s *Seed256) deriveSubregionSchedule(nonce []byte, startPixel, totalPixels int) subregionSchedule {
	wipePixelCallStack256([9][8]uint64{})
	sched := s.deriveSubregionScheduleBody(nonce, startPixel, totalPixels)
	wipePixelCallStack256([9][8]uint64{})
	return sched
}

//go:noinline
func (s *Seed256) deriveSubregionScheduleBody(nonce []byte, startPixel, totalPixels int) subregionSchedule {
	var stackBuf [1 + maxDesyncNonceBytes]byte
	buf := stackBuf[:1+len(nonce)]
	buf[0] = 0x05
	copy(buf[1:], nonce)
	last := len(buf) - 1
	baseByte := nonce[len(nonce)-1]
	var w [8]uint64
	for j := 0; j < 2; j++ {
		buf[last] = baseByte ^ byte(j)
		h := s.ChainHash256(buf)
		w[4*j], w[4*j+1] = fullWidthFold(h[0], h[1])
		w[4*j+2], w[4*j+3] = fullWidthFold(h[2], h[3])
		clear(h[:])
		runtime.KeepAlive(&h)
	}
	sched := buildSubregionSchedule(startPixel, totalPixels, w)
	clear(w[:])
	clear(stackBuf[:])
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&stackBuf)
	return sched
}

// deriveSubregionSchedule derives the Layer I (0x05) sub-region schedule for
// a 512-bit startSeed over the fixed-length buffer [0x05 || nonce].
func (s *Seed512) deriveSubregionSchedule(nonce []byte, startPixel, totalPixels int) subregionSchedule {
	wipePixelCallStack512([9][8]uint64{})
	sched := s.deriveSubregionScheduleBody(nonce, startPixel, totalPixels)
	wipePixelCallStack512([9][8]uint64{})
	return sched
}

//go:noinline
func (s *Seed512) deriveSubregionScheduleBody(nonce []byte, startPixel, totalPixels int) subregionSchedule {
	var stackBuf [1 + maxDesyncNonceBytes]byte
	buf := stackBuf[:1+len(nonce)]
	buf[0] = 0x05
	copy(buf[1:], nonce)
	h := s.ChainHash512(buf)
	var w [8]uint64
	for i := 0; i < 4; i++ {
		w[2*i], w[2*i+1] = fullWidthFold(h[2*i], h[2*i+1])
	}
	clear(h[:])
	runtime.KeepAlive(&h)
	sched := buildSubregionSchedule(startPixel, totalPixels, w)
	clear(w[:])
	clear(stackBuf[:])
	runtime.KeepAlive(&w)
	runtime.KeepAlive(&stackBuf)
	return sched
}

func processSubregions128(cfg *Config, noiseSeed, dataSeed, startSeed *Seed128, nonce []byte, container []byte, data []byte, startPixel, totalPixels, dataPixels, totalBits, microBatch int, encode bool, numWorkers int, noiseBase int) {
	sched := startSeed.deriveSubregionSchedule(nonce, startPixel, totalPixels)
	defer func() {
		sched = subregionSchedule{}
		runtime.KeepAlive(&sched)
	}()

	if numWorkers <= 1 {
		processSubregionsRange128(cfg, noiseSeed, dataSeed, nonce, container, data, &sched, 0, dataPixels, totalBits, microBatch, encode, noiseBase)
		return
	}

	var wg sync.WaitGroup
	pixelsPerWorker := dataPixels / numWorkers
	for w := 0; w < numWorkers; w++ {
		startP := w * pixelsPerWorker
		endP := startP + pixelsPerWorker
		if w == numWorkers-1 {
			endP = dataPixels
		}

		wg.Add(1)
		go func(sP, eP int) {
			defer wg.Done()
			processSubregionsRange128(cfg, noiseSeed, dataSeed, nonce, container, data, &sched, sP, eP, totalBits, microBatch, encode, noiseBase)
		}(startP, endP)
	}
	wg.Wait()
}

func processSubregions256(cfg *Config, noiseSeed, dataSeed, startSeed *Seed256, nonce []byte, container []byte, data []byte, startPixel, totalPixels, dataPixels, totalBits, microBatch int, encode bool, numWorkers int, noiseBase int) {
	sched := startSeed.deriveSubregionSchedule(nonce, startPixel, totalPixels)
	defer func() {
		sched = subregionSchedule{}
		runtime.KeepAlive(&sched)
	}()

	if numWorkers <= 1 {
		processSubregionsRange256(cfg, noiseSeed, dataSeed, nonce, container, data, &sched, 0, dataPixels, totalBits, microBatch, encode, noiseBase)
		return
	}

	var wg sync.WaitGroup
	pixelsPerWorker := dataPixels / numWorkers
	for w := 0; w < numWorkers; w++ {
		startP := w * pixelsPerWorker
		endP := startP + pixelsPerWorker
		if w == numWorkers-1 {
			endP = dataPixels
		}

		wg.Add(1)
		go func(sP, eP int) {
			defer wg.Done()
			processSubregionsRange256(cfg, noiseSeed, dataSeed, nonce, container, data, &sched, sP, eP, totalBits, microBatch, encode, noiseBase)
		}(startP, endP)
	}
	wg.Wait()
}

func processSubregions512(cfg *Config, noiseSeed, dataSeed, startSeed *Seed512, nonce []byte, container []byte, data []byte, startPixel, totalPixels, dataPixels, totalBits, microBatch int, encode bool, numWorkers int, noiseBase int) {
	sched := startSeed.deriveSubregionSchedule(nonce, startPixel, totalPixels)
	defer func() {
		sched = subregionSchedule{}
		runtime.KeepAlive(&sched)
	}()

	if numWorkers <= 1 {
		processSubregionsRange512(cfg, noiseSeed, dataSeed, nonce, container, data, &sched, 0, dataPixels, totalBits, microBatch, encode, noiseBase)
		return
	}

	var wg sync.WaitGroup
	pixelsPerWorker := dataPixels / numWorkers
	for w := 0; w < numWorkers; w++ {
		startP := w * pixelsPerWorker
		endP := startP + pixelsPerWorker
		if w == numWorkers-1 {
			endP = dataPixels
		}

		wg.Add(1)
		go func(sP, eP int) {
			defer wg.Done()
			processSubregionsRange512(cfg, noiseSeed, dataSeed, nonce, container, data, &sched, sP, eP, totalBits, microBatch, encode, noiseBase)
		}(startP, endP)
	}
	wg.Wait()
}

// ============================================================================
// Layer II — Cross-Lane Chunk-Slot Desynchronization (domain tag 0x06)
// ============================================================================

type laneDesyncSchedule struct {
	m      int
	betas  [3]int
	kLane  int // 0 when 2 <= m < 16 (Pi_lane is identity)
	offset [maxDesyncLaneSubs]int
	size   [maxDesyncLaneSubs]int
	start  [maxDesyncLaneSubs]int
	logOff [maxDesyncLaneSubs + 1]int
}

func buildLaneDesyncSchedule(m int, w [4]uint64) laneDesyncSchedule {
	var sched laneDesyncSchedule
	sched.m = m
	beta0 := int(w[3] % uint64(m))
	beta1 := (beta0 + 1 + int((w[3]>>16)%uint64(m-1))) % m
	beta2 := int((w[3] >> 32) % uint64(m))
	sched.betas = [3]int{beta0, beta1, beta2}

	if m < 16 {
		return sched
	}

	kLane := 4 + int(w[0]%5) // [4, 8]
	sched.kLane = kLane

	var physOff [maxDesyncLaneSubs + 1]int
	var physSize [maxDesyncLaneSubs]int
	base := m / kLane
	rem := m % kLane
	for j := 0; j < kLane; j++ {
		sz := base
		if j < rem {
			sz++
		}
		physOff[j+1] = physOff[j] + sz
	}
	if base >= 4 {
		for j := 1; j < kLane; j++ {
			raw := int((w[0] >> uint(8+j)) & 1)
			delta := raw - 1 // in {-1, 0}
			physOff[j] += delta
		}
	}
	for j := 0; j < kLane; j++ {
		physSize[j] = physOff[j+1] - physOff[j]
	}

	var piLane [maxDesyncLaneSubs]int
	for i := 0; i < kLane; i++ {
		piLane[i] = i
	}
	u := w[1]
	for i := kLane - 1; i > 0; i-- {
		mod := uint64(i + 1)
		swapIdx := int(u % mod)
		u /= mod
		piLane[i], piLane[swapIdx] = piLane[swapIdx], piLane[i]
	}

	for step := 0; step < kLane; step++ {
		physIdx := piLane[step]
		mk := physSize[physIdx]
		sched.offset[step] = physOff[physIdx]
		sched.size[step] = mk
		sched.logOff[step+1] = sched.logOff[step] + mk
		sched.start[step] = int(bits.RotateLeft64(w[2], 9*step) % uint64(mk))
	}
	return sched
}

// shiftSlotsForward copies m slots (each of slotBytes bytes) from src to dst
// under the forward cyclic shift mu(j) = (j + beta) % m:
// dst[(j + beta) % m] = src[j].
func shiftSlotsForward(dst, src []byte, m, beta, slotBytes int) {
	if beta == 0 {
		copy(dst, src)
		return
	}
	bBytes := beta * slotBytes
	splitBytes := (m - beta) * slotBytes
	copy(dst[:bBytes], src[splitBytes:])
	copy(dst[bBytes:], src[:splitBytes])
}

// shiftSlotsInverse copies m slots (each of slotBytes bytes) from src to dst
// under the inverse cyclic shift mu^-1(y) = (y + m - beta) % m:
// dst[j] = src[(j + beta) % m].
func shiftSlotsInverse(dst, src []byte, m, beta, slotBytes int) {
	if beta == 0 {
		copy(dst, src)
		return
	}
	bBytes := beta * slotBytes
	splitBytes := (m - beta) * slotBytes
	copy(dst[:splitBytes], src[bBytes:])
	copy(dst[splitBytes:], src[:bBytes])
}

// copyToInverseShifted copies a contiguous segment of slots from src
// (corresponding to intermediate slots [uStart, uStart + len(src)/slotBytes))
// directly into dst at destination slot (u + m - beta) % m, wrapping at m
// at most once.
func copyToInverseShifted(dst []byte, uStart int, src []byte, m, beta, slotBytes int) {
	if len(src) == 0 {
		return
	}
	dStart := (uStart + m - beta) % m
	dByte := dStart * slotBytes
	totalBytes := m * slotBytes
	if dByte+len(src) <= totalBytes {
		copy(dst[dByte:dByte+len(src)], src)
		return
	}
	first := totalBytes - dByte
	copy(dst[dByte:totalBytes], src[:first])
	copy(dst[:len(src)-first], src[first:])
}

// copyFromForwardShifted copies len(dst)/slotBytes contiguous intermediate
// slots [uStart, uStart + len(dst)/slotBytes) directly from src into dst,
// where intermediate slot u is src[(u + m - beta) % m].
func copyFromForwardShifted(dst []byte, uStart int, src []byte, m, beta, slotBytes int) {
	if len(dst) == 0 {
		return
	}
	sStart := (uStart + m - beta) % m
	sByte := sStart * slotBytes
	totalBytes := m * slotBytes
	if sByte+len(dst) <= totalBytes {
		copy(dst, src[sByte:sByte+len(dst)])
		return
	}
	first := totalBytes - sByte
	copy(dst[:first], src[sByte:totalBytes])
	copy(dst[first:], src[:len(dst)-first])
}

// desyncLaneEncryptTo applies Sigma_l = Pi_lane o mu_l from src into dst in a
// single pass without mutating src.
func desyncLaneEncryptTo(dst, src []byte, sched *laneDesyncSchedule, l, slotBytes int) {
	m := sched.m
	beta := sched.betas[l]
	if sched.kLane == 0 {
		shiftSlotsForward(dst, src, m, beta, slotBytes)
		return
	}
	for step := 0; step < sched.kLane; step++ {
		mk := sched.size[step]
		uBase := sched.logOff[step]
		physOff := sched.offset[step]
		s := sched.start[step]
		if s == 0 {
			copyFromForwardShifted(dst[physOff*slotBytes:(physOff+mk)*slotBytes], uBase, src, m, beta, slotBytes)
			continue
		}
		copyFromForwardShifted(dst[physOff*slotBytes:(physOff+s)*slotBytes], uBase+mk-s, src, m, beta, slotBytes)
		copyFromForwardShifted(dst[(physOff+s)*slotBytes:(physOff+mk)*slotBytes], uBase, src, m, beta, slotBytes)
	}
}

func desyncLaneEncryptOne(lane, stage []byte, sched *laneDesyncSchedule, l, slotBytes int) {
	copy(stage, lane)
	desyncLaneEncryptTo(lane, stage, sched, l, slotBytes)
}

func desyncLaneDecryptOne(dst, src []byte, sched *laneDesyncSchedule, l, slotBytes int) {
	m := sched.m
	beta := sched.betas[l]
	if sched.kLane == 0 {
		shiftSlotsInverse(dst, src, m, beta, slotBytes)
		return
	}
	for step := 0; step < sched.kLane; step++ {
		mk := sched.size[step]
		uBase := sched.logOff[step]
		physOff := sched.offset[step]
		s := sched.start[step]
		if s == 0 {
			copyToInverseShifted(dst, uBase, src[physOff*slotBytes:(physOff+mk)*slotBytes], m, beta, slotBytes)
			continue
		}
		copyToInverseShifted(dst, uBase, src[(physOff+s)*slotBytes:(physOff+mk)*slotBytes], m, beta, slotBytes)
		copyToInverseShifted(dst, uBase+mk-s, src[physOff*slotBytes:(physOff+s)*slotBytes], m, beta, slotBytes)
	}
}

func evalDesyncWords(bp lockBatchPRF48) [4]uint64 {
	wipePixelCallStack512([9][8]uint64{})
	w := evalDesyncWordsBody(bp)
	wipePixelCallStack512([9][8]uint64{})
	return w
}

//go:noinline
func evalDesyncWordsBody(bp lockBatchPRF48) [4]uint64 {
	return bp.desyncWords()
}

// desyncLaneEncrypt applies the Layer II cross-lane chunk-slot permutation
// Sigma_l(j) = Pi_lane(mu_l(j)) in-place to each of p0, p1, p2 after PEXT
// chunk splitting.
func desyncLaneEncrypt(p0, p1, p2 []byte, slotBytes int, bp lockBatchPRF48) {
	if bp.desyncWords == nil {
		return
	}
	laneBytes := len(p0)
	m := laneBytes / slotBytes
	if m < 2 || len(p1) != laneBytes || len(p2) != laneBytes {
		return
	}

	w := evalDesyncWords(bp)
	sched := buildLaneDesyncSchedule(m, w)
	clear(w[:])
	runtime.KeepAlive(&w)
	defer func() {
		sched = laneDesyncSchedule{}
		runtime.KeepAlive(&sched)
	}()

	lanes := [3][]byte{p0, p1, p2}
	if laneBytes >= minDesyncParallelLaneBytes && runtime.GOMAXPROCS(0) > 1 {
		stagePtr, stage := acquireStage(3 * laneBytes)
		var wg sync.WaitGroup
		wg.Add(2)
		for l := 0; l < 2; l++ {
			go func(idx int) {
				defer wg.Done()
				stageL := stage[idx*laneBytes : (idx+1)*laneBytes]
				desyncLaneEncryptOne(lanes[idx], stageL, &sched, idx, slotBytes)
				secureWipe(stageL)
			}(l)
		}
		stage2 := stage[2*laneBytes : 3*laneBytes]
		desyncLaneEncryptOne(lanes[2], stage2, &sched, 2, slotBytes)
		secureWipe(stage2)
		wg.Wait()
		releaseStage(stagePtr, stage, 0)
		return
	}

	stagePtr, stage := acquireStage(laneBytes)
	defer releaseStage(stagePtr, stage, laneBytes)
	for l := 0; l < 3; l++ {
		desyncLaneEncryptOne(lanes[l], stage, &sched, l, slotBytes)
	}
}

// desyncLaneDecrypt applies the inverse Layer II cross-lane chunk-slot
// permutation Sigma_l^-1(y) = mu_l^-1(Pi_lane^-1(y)) to p0, p1, p2 before
// PDEP chunk interleaving, returning un-permuted views u0, u1, u2 backed by
// a pooled staging buffer without mutating the caller's p0, p1, p2 slices.
func desyncLaneDecrypt(p0, p1, p2 []byte, slotBytes int, bp lockBatchPRF48) (u0, u1, u2 []byte, stagePtr *[]byte, stageBuf []byte) {
	if bp.desyncWords == nil {
		return p0, p1, p2, nil, nil
	}
	laneBytes := len(p0)
	m := laneBytes / slotBytes
	if m < 2 || len(p1) != laneBytes || len(p2) != laneBytes {
		return p0, p1, p2, nil, nil
	}

	w := evalDesyncWords(bp)
	sched := buildLaneDesyncSchedule(m, w)
	clear(w[:])
	runtime.KeepAlive(&w)
	defer func() {
		sched = laneDesyncSchedule{}
		runtime.KeepAlive(&sched)
	}()

	stagePtr, stageBuf = acquireStage(3 * laneBytes)
	u0 = stageBuf[:laneBytes]
	u1 = stageBuf[laneBytes : 2*laneBytes]
	u2 = stageBuf[2*laneBytes : 3*laneBytes]

	inLanes := [3][]byte{p0, p1, p2}
	outLanes := [3][]byte{u0, u1, u2}
	if laneBytes >= minDesyncParallelLaneBytes && runtime.GOMAXPROCS(0) > 1 {
		var wg sync.WaitGroup
		wg.Add(2)
		for l := 0; l < 2; l++ {
			go func(idx int) {
				defer wg.Done()
				desyncLaneDecryptOne(outLanes[idx], inLanes[idx], &sched, idx, slotBytes)
			}(l)
		}
		desyncLaneDecryptOne(outLanes[2], inLanes[2], &sched, 2, slotBytes)
		wg.Wait()
		return u0, u1, u2, stagePtr, stageBuf
	}

	for l := 0; l < 3; l++ {
		desyncLaneDecryptOne(outLanes[l], inLanes[l], &sched, l, slotBytes)
	}
	return u0, u1, u2, stagePtr, stageBuf
}

// releaseDesyncStage wipes the 3-lane decrypt staging buffer (parallelizing
// across 3 goroutines for large payloads) and returns it to the stage pool.
func releaseDesyncStage(stagePtr *[]byte, stageBuf []byte) {
	if stagePtr == nil {
		return
	}
	n := len(stageBuf)
	if n >= 3*minDesyncParallelLaneBytes && n%3 == 0 && runtime.GOMAXPROCS(0) > 1 {
		laneBytes := n / 3
		var wg sync.WaitGroup
		wg.Add(2)
		for l := 0; l < 2; l++ {
			go func(idx int) {
				defer wg.Done()
				secureWipe(stageBuf[idx*laneBytes : (idx+1)*laneBytes])
			}(l)
		}
		secureWipe(stageBuf[2*laneBytes : 3*laneBytes])
		wg.Wait()
		releaseStage(stagePtr, stageBuf, 0)
		return
	}
	releaseStage(stagePtr, stageBuf, n)
}
