package itb

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
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

// buildTriplePayloads runs the interlock split, the COBS stage, the
// container sizing and the payload assembly for one encrypt call.
//
// reserve is the byte count held back at the end of the last third
// (the No MAC tag stub, or tagSize + 1 for the authenticated shapes);
// it is added to the last third's COBS length for container sizing.
// When fillReserve is set the reserve bytes are CSPRNG-filled like the
// rest of the tail (No MAC); otherwise they are left for the caller to
// write (tag and flag). sizeFn maps the three COBS lengths to the
// container dimensions.
//
// Container sizing is monotone non-decreasing in every COBS length, so
// the dimensions computed from the COBS upper bound
// ([cobsEncodeBound] of the lane length) yield a per-third capacity
// that is never smaller than the capacity computed from the actual
// lengths. Each payload buffer is acquired at that bound capacity, the
// lane is COBS-encoded into it in place, and the buffer is then
// resliced to the actual capacity — the encoded bytes are already where
// the pixel pipeline reads them.
func buildTriplePayloads(cfg *Config, data []byte, bp lockBatchPRF48, reserve int, fillReserve bool, sizeFn func(cobsLens [3]int) (width, height int)) (tp *triplePayloads, width, height int, err error) {
	// Interlock split into three pooled lanes through the framed view
	// of data (no framed or padded plaintext copy).
	laneLen := tripleLaneLen(len(data))
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
	splitForTriple48LockedInto(cfg, data, bp, lanes[0], lanes[1], lanes[2])

	// Payload buffers at the upper-bound capacity, then COBS in place.
	bound := cobsEncodeBound(laneLen)
	bw, bh := sizeFn([3]int{bound, bound, bound + reserve})
	_, _, capsBound := tripleThirdCaps(bw * bh)
	tp = &triplePayloads{}
	for i := range tp.full {
		tp.ptrs[i], tp.full[i] = acquireBuffer(capsBound[i])
	}
	{
		var wg sync.WaitGroup
		wg.Add(3)
		for i := 0; i < 3; i++ {
			go func(i int) {
				defer wg.Done()
				tp.encLen[i] = len(cobsEncodeInto(tp.full[i], lanes[i]))
			}(i)
		}
		wg.Wait()
	}
	releaseLanes()

	// Actual container dimensions and per-third capacities.
	width, height = sizeFn([3]int{tp.encLen[0], tp.encLen[1], tp.encLen[2] + reserve})
	_, _, caps := tripleThirdCaps(width * height)
	tp.payloadLen = [3]int{caps[0], caps[1], caps[2] - reserve}
	for i := 0; i < 3; i++ {
		if tp.encLen[i]+1 > tp.payloadLen[i] {
			tp.release()
			return nil, 0, 0, fmt.Errorf("itb: internal error: container third %d too small", i)
		}
		tp.bufs[i] = tp.full[i][:caps[i]]
	}

	// Terminator and CSPRNG tail fill, drawn straight into each payload.
	{
		var errs [3]error
		var wg sync.WaitGroup
		wg.Add(3)
		for i := 0; i < 3; i++ {
			go func(i int) {
				defer wg.Done()
				buf := tp.bufs[i]
				buf[tp.encLen[i]] = 0x00
				fillEnd := tp.payloadLen[i]
				if fillReserve {
					fillEnd = len(buf)
				}
				if fillStart := tp.encLen[i] + 1; fillStart < fillEnd {
					if _, e := rand.Read(buf[fillStart:fillEnd]); e != nil {
						errs[i] = fmt.Errorf("itb: crypto/rand: %w", e)
					}
				}
			}(i)
		}
		wg.Wait()
		for _, e := range errs {
			if e != nil {
				tp.release()
				return nil, 0, 0, e
			}
		}
	}
	return tp, width, height, nil
}

// newTripleWire allocates the output wire for a width × height
// container in one buffer — [main nonce][interlock nonce][W][H] followed
// by the container — writes the header, and fills the container with
// CSPRNG bytes in three parallel draws. container aliases out past the
// header, so the pixel pipeline writes the wire in place and no final
// header-plus-container copy is made.
func newTripleWire(cfg *Config, nonce, ilNonce []byte, width, height int) (out, container []byte, err error) {
	hdr := headerSizeCfg(cfg)
	totalPixels := width * height
	third := totalPixels / 3
	out = make([]byte, hdr+totalPixels*Channels)
	copy(out, nonce)
	copy(out[len(nonce):], ilNonce)
	binary.BigEndian.PutUint16(out[2*len(nonce):], uint16(width))
	binary.BigEndian.PutUint16(out[2*len(nonce)+2:], uint16(height))
	container = out[hdr:]

	var wg sync.WaitGroup
	var randErr [3]error
	wg.Add(3)
	go func() { _, randErr[0] = rand.Read(container[0 : third*Channels]); wg.Done() }()
	go func() { _, randErr[1] = rand.Read(container[third*Channels : 2*third*Channels]); wg.Done() }()
	go func() { _, randErr[2] = rand.Read(container[2*third*Channels : totalPixels*Channels]); wg.Done() }()
	wg.Wait()
	for _, e := range randErr {
		if e != nil {
			return nil, nil, fmt.Errorf("itb: crypto/rand: %w", e)
		}
	}
	return out, container, nil
}
