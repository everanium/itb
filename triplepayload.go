package itb

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/everanium/itb/internal/drbg"
)

// Shared encrypt-side stages of the Triple Ouroboros entry points
// (Encrypt3x*, EncryptAuthenticated3x*, EncryptStreamAuthenticated3x* at
// every hash width). The stages here are width-agnostic: the only
// width-specific input is the container-sizing callback, which closes
// over the caller's seeds.
//
// Scratch discipline. Every plaintext-derived intermediate — the three
// interlock lanes and the three per-third payloads — lives in
// bufferPool checkouts that are wiped on release. The lanes are held
// only across the COBS stage; the payloads survive until the pixel
// pipeline has consumed them. No intermediate is copied: the interlock
// split reads the caller's plaintext through a framed view, COBS
// encodes each lane straight into the buffer that becomes that third's
// payload, and the CSPRNG fill is drawn directly into the payload tail.

// tripleThirdCaps returns the per-third pixel counts and payload byte
// capacities of a container holding totalPixels pixels: the first two
// thirds take totalPixels / 3 pixels each, the last takes the remainder.
func tripleThirdCaps(totalPixels int) (third, thirdPixels2 int, caps [3]int) {
	third = totalPixels / 3
	thirdPixels2 = totalPixels - 2*third
	caps = [3]int{
		(third * DataBitsPerPixel) / 8,
		(third * DataBitsPerPixel) / 8,
		(thirdPixels2 * DataBitsPerPixel) / 8,
	}
	return
}

// triplePayloads carries the three per-third payload buffers of one
// encrypt call. bufs[i] spans the full capacity caps[i] of third i;
// payloadLen[i] is the extent ahead of the tail reserve on the last
// third (equal to caps[i] on the first two). encLen[i] is the COBS
// length of lane i, ahead of the 0x00 terminator.
type triplePayloads struct {
	ptrs       [3]*[]byte
	full       [3][]byte
	bufs       [3][]byte
	encLen     [3]int
	payloadLen [3]int
}

// release wipes and returns every payload buffer to bufferPool. Safe to
// call on a partially built set (nil entries are skipped).
func (tp *triplePayloads) release() {
	for i := range tp.ptrs {
		if tp.ptrs[i] != nil {
			releaseBuffer(tp.ptrs[i], tp.full[i])
			tp.ptrs[i] = nil
		}
	}
}

// buildTripleWire3 fuses payload assembly and wire allocation for one
// encrypt call. It runs the interlock split, the COBS stage, and the
// container sizing, then draws the container CSPRNG fill and the payload
// tail CSPRNG fill on independent goroutines organised as a classical
// producer-consumer pipeline.
//
// reserve is the byte count held back at the end of the last third
// (the No MAC tag stub, or tagSize + 1 for the authenticated shapes);
// it is added to the last third's COBS length for container sizing.
// When fillReserve is set the reserve bytes are CSPRNG-filled like the
// rest of the tail (No MAC); otherwise they are left for the caller to
// write (tag and flag). sizeFn maps the three COBS lengths to the
// container dimensions.
//
// Container dimensions are computed from the COBS upper bound
// ([cobsEncodeBound] of the lane length), not from the post-COBS
// actual lengths. Since calcContainerSize3Cfg is monotone
// non-decreasing in every COBS length, bound-based dimensions are ≥
// actual-length dimensions on any input; the wire inflation is at most
// the per-lane COBS overhead margin (n/254 + 2 bytes ≈ 0.4% of the
// lane) which the ceil-sqrt pixel roundup and the BarrierFill margin
// absorb — in practice the bound-based side matches the actual-length
// side on any non-trivial input.
//
// Choosing bound over actual breaks the sequential dependency between
// the COBS stage and the container CSPRNG fill. Container CSPRNG is
// spawned earliest possible — three background goroutines start filling
// the wire container from t=0, before interlock even runs — because
// container dimensions are known upfront from the bound and the wire
// buffer has no data dependency on any downstream stage. The main
// goroutine then advances through interlock (which uses its own G
// internal workers) and the three COBS-plus-tail lane goroutines. The
// wgContainer.Wait at the end typically returns instantly because
// container CSPRNG completed while interlock was still running.
//
// Timeline (typical, wall time per stage):
//
//	Main goroutine:  [interlock ─────][COBS+tail 3 × ─][wait bkg]
//	Background:      [container CSPRNG 3 × ────][idle]
//
// Wall = interlock_wall + cobs_tail_wall (container fill hides
// entirely inside interlock in the common case where interlock is the
// longest stage). On CPU-constrained hosts where container CSPRNG
// becomes the dominant stage, this pattern still achieves
// max(container, interlock+COBS) wall — never worse than the sequential
// alternative.
//
// Decrypt reads W, H from the header and finds the COBS 0x00
// terminator inside each third via bytes.IndexByte — the bytes between
// the terminator and the third boundary are CSPRNG residue that
// decrypt already tolerates for the BarrierFill margin, so
// bound-vs-actual padding is indistinguishable from that margin on the
// wire.
//
// On return: tp carries the three per-third payload buffers ready for
// pixel-encode; out is the wire buffer sized for
// [main nonce | interlock nonce | W | H | W·H·Ch container] with the
// header written and the container CSPRNG-filled; container aliases out
// past the header, so the pixel pipeline writes the wire in place and
// no final header-plus-container copy is made.
func buildTripleWire3(cfg *Config, data []byte, bp lockBatchPRF48, reserve int, fillReserve bool, nonce, ilNonce []byte, sizeFn func(cobsLens [3]int) (width, height int)) (tp *triplePayloads, out, container []byte, width, height int, err error) {
	laneLen := tripleLaneLen(len(data))

	// Container dimensions from the COBS upper bound. sizeFn, cfg and
	// its BarrierFill setting are all fixed here, so width, height and
	// the per-third capacities are known before interlock or COBS run.
	bound := cobsEncodeBound(laneLen)
	width, height = sizeFn([3]int{bound, bound, bound + reserve})
	totalPixels := width * height
	third, _, caps := tripleThirdCaps(totalPixels)

	// Allocate the wire and write the header on the calling goroutine.
	// The wire buffer has no data dependency on interlock or COBS, so
	// the three background container-fill goroutines can enter
	// drbg.Fill immediately after this point.
	hdr := headerSizeCfg(cfg)
	out = make([]byte, hdr+totalPixels*Channels)
	copy(out, nonce)
	copy(out[len(nonce):], ilNonce)
	binary.BigEndian.PutUint16(out[2*len(nonce):], uint16(width))
	binary.BigEndian.PutUint16(out[2*len(nonce)+2:], uint16(height))
	container = out[hdr:]

	// Producer stage — spawn three container CSPRNG fill workers as
	// early as the wire exists. They race the main goroutine's
	// interlock+COBS chain; in the common case they finish first and
	// the trailing wgContainer.Wait unblocks instantly.
	var (
		wgContainer sync.WaitGroup
		wireErr     [3]error
	)
	wgContainer.Add(3)
	go func() {
		defer wgContainer.Done()
		wireErr[0] = drbg.Fill(container[0 : third*Channels])
	}()
	go func() {
		defer wgContainer.Done()
		wireErr[1] = drbg.Fill(container[third*Channels : 2*third*Channels])
	}()
	go func() {
		defer wgContainer.Done()
		wireErr[2] = drbg.Fill(container[2*third*Channels : totalPixels*Channels])
	}()

	// Main goroutine — interlock split into three pooled lanes through
	// the framed view of data (no framed or padded plaintext copy),
	// then per-lane COBS + tail CSPRNG. splitForTriple48LockedInto uses
	// its own G internal workers, so it saturates the CPU; the
	// container CSPRNG goroutines above ride whatever headroom the
	// scheduler gives them.
	var lanePtrs [3]*[]byte
	var lanes [3][]byte
	for i := range lanes {
		lanePtrs[i], lanes[i] = acquireBuffer(laneLen)
	}
	releaseLanes := func() {
		for i := range lanes {
			releaseBuffer(lanePtrs[i], lanes[i])
		}
	}

	tp = &triplePayloads{}
	tp.payloadLen = [3]int{caps[0], caps[1], caps[2] - reserve}
	for i := range tp.full {
		tp.ptrs[i], tp.full[i] = acquireBuffer(caps[i])
		tp.bufs[i] = tp.full[i][:caps[i]]
	}

	splitForTriple48LockedInto(cfg, data, bp, lanes[0], lanes[1], lanes[2])

	// Consumer stage — three COBS + tail CSPRNG lane goroutines.
	// Each lane's tail depends on its own COBS length, so the fused
	// per-lane goroutine handles both in sequence for that lane while
	// the other lanes run concurrently.
	var (
		wgLanes sync.WaitGroup
		laneErr [3]error
	)
	wgLanes.Add(3)
	for i := 0; i < 3; i++ {
		i := i
		go func() {
			defer wgLanes.Done()
			tp.encLen[i] = len(cobsEncodeInto(tp.full[i], lanes[i]))
			if tp.encLen[i]+1 > tp.payloadLen[i] {
				laneErr[i] = fmt.Errorf("itb: internal error: container third %d too small", i)
				return
			}
			buf := tp.bufs[i]
			buf[tp.encLen[i]] = 0x00
			fillEnd := tp.payloadLen[i]
			if fillReserve {
				fillEnd = len(buf)
			}
			if fillStart := tp.encLen[i] + 1; fillStart < fillEnd {
				if e := drbg.Fill(buf[fillStart:fillEnd]); e != nil {
					laneErr[i] = fmt.Errorf("itb: crypto/rand: %w", e)
				}
			}
		}()
	}
	wgLanes.Wait()
	releaseLanes()

	// Container fill has been running since t=0; in the common case
	// this returns instantly because it completed while interlock and
	// COBS were on the main goroutine's critical path.
	wgContainer.Wait()

	for _, e := range wireErr {
		if e != nil {
			tp.release()
			return nil, nil, nil, 0, 0, fmt.Errorf("itb: crypto/rand: %w", e)
		}
	}
	for _, e := range laneErr {
		if e != nil {
			tp.release()
			return nil, nil, nil, 0, 0, e
		}
	}
	return tp, out, container, width, height, nil
}
