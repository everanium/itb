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
// tail CSPRNG fill as six independent parallel goroutines.
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
//
// On return: tp carries the three per-third payload buffers ready for
// pixel-encode (identical semantics to the pre-fused payload builder);
// out is the wire buffer sized for
// [main nonce | interlock nonce | W | H | W·H·Ch container] with the
// header written and the container CSPRNG-filled; container aliases out
// past the header, so the pixel pipeline writes the wire in place and
// no final header-plus-container copy is made.
//
// The wire produced is byte-identical under the same DRBG state to what
// a two-phase implementation (payload assembly followed by wire
// allocation and container fill) would produce; both paths draw the
// same total byte counts from drbg.Fill in the same lane partitioning.
// The only observable change is wall time on the encrypt critical path:
// the container CSPRNG fill overlaps with the payload tail CSPRNG fill
// instead of running after it.
func buildTripleWire3(cfg *Config, data []byte, bp lockBatchPRF48, reserve int, fillReserve bool, nonce, ilNonce []byte, sizeFn func(cobsLens [3]int) (width, height int)) (tp *triplePayloads, out, container []byte, width, height int, err error) {
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
			return nil, nil, nil, 0, 0, fmt.Errorf("itb: internal error: container third %d too small", i)
		}
		tp.bufs[i] = tp.full[i][:caps[i]]
	}

	// Allocate the wire and write the header on the calling goroutine —
	// the cheap prelude to the container CSPRNG fill runs inline to
	// avoid one indirection through a goroutine.
	hdr := headerSizeCfg(cfg)
	totalPixels := width * height
	third := totalPixels / 3
	out = make([]byte, hdr+totalPixels*Channels)
	copy(out, nonce)
	copy(out[len(nonce):], ilNonce)
	binary.BigEndian.PutUint16(out[2*len(nonce):], uint16(width))
	binary.BigEndian.PutUint16(out[2*len(nonce)+2:], uint16(height))
	container = out[hdr:]

	// Six independent CSPRNG draws in parallel: three container thirds
	// + three payload tails. Sharing one WaitGroup and one error slot
	// per group keeps error propagation cheap and preserves the
	// first-error-wins semantics of the pre-fused pipeline.
	var (
		wg      sync.WaitGroup
		wireErr [3]error
		tailErr [3]error
	)
	wg.Add(6)

	// Container CSPRNG fill × 3.
	go func() { defer wg.Done(); wireErr[0] = drbg.Fill(container[0 : third*Channels]) }()
	go func() { defer wg.Done(); wireErr[1] = drbg.Fill(container[third*Channels : 2*third*Channels]) }()
	go func() { defer wg.Done(); wireErr[2] = drbg.Fill(container[2*third*Channels : totalPixels*Channels]) }()

	// Payload tail CSPRNG × 3.
	for i := 0; i < 3; i++ {
		i := i
		go func() {
			defer wg.Done()
			buf := tp.bufs[i]
			buf[tp.encLen[i]] = 0x00
			fillEnd := tp.payloadLen[i]
			if fillReserve {
				fillEnd = len(buf)
			}
			if fillStart := tp.encLen[i] + 1; fillStart < fillEnd {
				if e := drbg.Fill(buf[fillStart:fillEnd]); e != nil {
					tailErr[i] = fmt.Errorf("itb: crypto/rand: %w", e)
				}
			}
		}()
	}
	wg.Wait()

	for _, e := range wireErr {
		if e != nil {
			tp.release()
			return nil, nil, nil, 0, 0, fmt.Errorf("itb: crypto/rand: %w", e)
		}
	}
	for _, e := range tailErr {
		if e != nil {
			tp.release()
			return nil, nil, nil, 0, 0, e
		}
	}
	return tp, out, container, width, height, nil
}
