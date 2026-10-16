//go:build redteam

package itb

// Universal single-message solver for the non-bijective squaring T-function
// quadHash under the shipped Triple Ouroboros barrier.
//
// Primitive definition:
//
//	l = ((l + b) * (l + b)) & 0xFF
//	h = (((h + b) * (h + b)) + 1) & 0xFF
//
// Because (x + b)^2 - (y + b)^2 = (x - y)(x + y + 2b), every step doubles the
// 2-adic valuation of any even state difference: if x == y (mod 2^k) for k >= 1,
// then (x + b)^2 == (y + b)^2 (mod 2^(k+1)). After 7 input bytes, bits 1..7 of
// the initial seed byte are erased modulo 256, leaving only bit 0 (since
// (x + b)^2 == x ^ b (mod 2)). Across the 4-round ChainHash128 cascade on any
// buffer of length >= 7 bytes (all ITB domain buffers are 13, 17, or 20 bytes),
// each 512-bit seed collapses to a single parity bit in lo and a single parity
// bit in hi.
//
// Every test below draws fresh 512-bit CSPRNG seeds per message, grants zero
// seeds and zero startPixels to the solver, and verifies full 512-byte
// plaintext recovery and SHA-256 checksums through Decrypt3x128Cfg.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func quadHash(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	l := seed0 & 0xFF
	h := seed1 & 0xFF
	for _, b := range data {
		l = ((l + uint64(b)) * (l + uint64(b))) & 0xFF
		h = (((h + uint64(b)) * (h + uint64(b))) + 1) & 0xFF
	}
	return l, h
}

func qhReadPixel(region []byte, linearIdx int, np, rot, xor uint) [7]byte {
	var packed uint64
	noiseMask := byte(1) << np
	for ch := 0; ch < Channels; ch++ {
		b := region[linearIdx*Channels+ch]
		low := b & (noiseMask - 1)
		high := b >> (np + 1)
		d := low | (high << np)
		d = rotateBits7(d, 7-rot)
		if ch == 0 {
			d ^= byte(xor)
		}
		packed |= uint64(d) << uint(ch*DataBitsPerChannel)
	}
	var out [7]byte
	for j := 0; j < 7; j++ {
		out[j] = byte(packed >> uint(8*j))
	}
	return out
}

// qhMakeTruncSeed constructs a valid 512-bit *Seed128 for slot in 0..7 with
// Components[6] = c6 and Components[7] = c7. Setting Components[0] = uint64(16*slot)
// keeps Components[0] even (parity 0) while ensuring all 8 seeds are pairwise
// distinct for checkEightSeeds128.
func qhMakeTruncSeed(slot int, c6, c7 byte) *Seed128 {
	s, err := SeedFromComponents128(quadHash,
		uint64(16*slot), 0,
		0, 0,
		0, 0,
		uint64(c6), uint64(c7),
	)
	if err != nil {
		panic(err)
	}
	return s
}

func qhCandidateS6ForStart(slot int, mainNonce []byte) []byte {
	sbuf := make([]byte, 1+len(mainNonce))
	sbuf[0] = 0x02
	copy(sbuf[1:], mainNonce)
	seen := map[uint64]bool{}
	var out []byte
	for x := 0; x < 256; x++ {
		s := qhMakeTruncSeed(slot, byte(x), 0)
		lo, _ := s.ChainHash128(sbuf)
		if !seen[lo] {
			seen[lo] = true
			out = append(out, byte(x))
		}
	}
	return out
}

func qhCandidatePixelLanes(slot int, mainNonce []byte, third int) (loReps, hiReps []byte) {
	pbuf := make([]byte, 4+len(mainNonce))
	copy(pbuf[4:], mainNonce)
	probes := [6]int{0, 1, 2, 3, 2*third + 0, 2*third + 1}
	seenLo := map[[6]byte]bool{}
	seenHi := map[[6]byte]bool{}
	for x := 0; x < 16; x++ {
		s := qhMakeTruncSeed(slot, byte(x), byte(x))
		var sigL, sigH [6]byte
		for i, c := range probes {
			binary.LittleEndian.PutUint32(pbuf[:4], uint32(c))
			l, h := s.ChainHash128(pbuf)
			sigL[i] = byte(l)
			sigH[i] = byte(h)
		}
		if !seenLo[sigL] {
			seenLo[sigL] = true
			loReps = append(loReps, byte(x))
		}
		if !seenHi[sigH] {
			seenHi[sigH] = true
			hiReps = append(hiReps, byte(x))
		}
	}
	return loReps, hiReps
}

func solveQuadHashSingleMessage(cfg *Config, ct, crib []byte) (dec []byte, seeds [8]*Seed128, trials int, ok bool) {
	nonceLen := currentNonceSizeCfg(cfg)
	lens, _ := nonceSplit(nonceLen)
	sm := parseSMWire(ct, nonceLen)
	mainNonce := sm.mainNonce
	totalPixels := sm.width * sm.height
	third, third2, caps := tripleThirdCaps(totalPixels)
	widths := [3]int{third, third, third2}
	regions := [3][]byte{
		sm.container[0 : third*Channels],
		sm.container[third*Channels : 2*third*Channels],
		sm.container[2*third*Channels : totalPixels*Channels],
	}

	sCands := [3][]byte{
		qhCandidateS6ForStart(5, mainNonce),
		qhCandidateS6ForStart(6, mainNonce),
		qhCandidateS6ForStart(7, mainNonce),
	}
	nsLoReps, nsHiReps := qhCandidatePixelLanes(0, mainNonce, third)
	dsLoReps, _ := qhCandidatePixelLanes(2, mainNonce, third)

	checkRegionCOBS := func(r int, ns, ds, ss *Seed128) (int, bool) {
		sbuf := make([]byte, 1+len(mainNonce))
		sbuf[0] = 0x02
		copy(sbuf[1:], mainNonce)
		spLo, _ := ss.ChainHash128(sbuf)
		sp := int(spLo % uint64(widths[r]))

		pbuf := make([]byte, 4+len(mainNonce))
		copy(pbuf[4:], mainNonce)

		raw := make([]byte, 0, widths[r]*7)
		zeroIdx := -1
		for p := 0; p < widths[r]; p++ {
			binary.LittleEndian.PutUint32(pbuf[:4], uint32(r*third+p))
			nLo, nHi := ns.ChainHash128(pbuf)
			np := noisePosition(nLo, nHi)

			binary.LittleEndian.PutUint32(pbuf[:4], uint32(p))
			dLo, _ := ds.ChainHash128(pbuf)
			rot := uint((dLo & 0xFF) % 7)
			xor := uint((dLo & 0xFF) >> DataRotationBits)

			lin := (sp + p) % widths[r]
			win := qhReadPixel(regions[r], lin, np, rot, xor)
			base := len(raw)
			raw = append(raw, win[:]...)
			if z := bytes.IndexByte(win[:], 0); z >= 0 {
				zeroIdx = base + z
				break
			}
		}
		if zeroIdx <= lens[r]+2 {
			return 0, false
		}
		idx, numFF := 0, 0
		var lastCode byte
		for idx < zeroIdx {
			code := raw[idx]
			lastCode = code
			if code == 0xFF {
				numFF++
			}
			idx += int(code)
		}
		if idx != zeroIdx || lastCode == 0xFF {
			return 0, false
		}
		decLen := zeroIdx - 1 - numFF
		laneLen := decLen - lens[r]
		if laneLen < caps[r]/12 || laneLen%2 != 0 {
			return 0, false
		}
		return laneLen, true
	}

	for _, ns6 := range nsLoReps {
		for _, ns7 := range nsHiReps {
			ns := qhMakeTruncSeed(0, ns6, ns7)

			type regPair struct {
				ds, ss  *Seed128
				laneLen int
			}
			var validReg [3][]regPair
			possible := true
			for r := 0; r < 3; r++ {
				for _, ds6 := range dsLoReps {
					ds := qhMakeTruncSeed(2+r, ds6, 0)
					for _, sc6 := range sCands[r] {
						ss := qhMakeTruncSeed(5+r, sc6, 0)
						if laneLen, ok := checkRegionCOBS(r, ns, ds, ss); ok {
							validReg[r] = append(validReg[r], regPair{ds, ss, laneLen})
						}
					}
				}
				if len(validReg[r]) == 0 {
					possible = false
					break
				}
			}
			if !possible {
				continue
			}

			for _, rp0 := range validReg[0] {
				for _, rp1 := range validReg[1] {
					if rp1.laneLen != rp0.laneLen {
						continue
					}
					for _, rp2 := range validReg[2] {
						if rp2.laneLen != rp0.laneLen {
							continue
						}
						for lsBits := 0; lsBits < 4; lsBits++ {
							ls := qhMakeTruncSeed(1, byte(lsBits&1), byte((lsBits>>1)&1))
							trials++
							got, err := Decrypt3x128Cfg(cfg, ns, ls, rp0.ds, rp1.ds, rp2.ds, rp0.ss, rp1.ss, rp2.ss, ct)
							if err == nil && len(got) >= len(crib) && bytes.Equal(got[:len(crib)], crib) {
								return got, [8]*Seed128{ns, ls, rp0.ds, rp1.ds, rp2.ds, rp0.ss, rp1.ss, rp2.ss}, trials, true
							}
						}
					}
				}
			}
		}
	}
	return nil, seeds, trials, false
}

func qhMakePlaintext(corpus string, ptSize, msgIdx int) []byte {
	pt := make([]byte, ptSize)
	if _, err := rand.Read(pt); err != nil {
		panic(err)
	}
	switch corpus {
	case "ascii":
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ,.:;-!?"
		for i := range pt {
			pt[i] = alphabet[int(pt[i])%len(alphabet)]
		}
	case "json":
		names := []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"}
		roles := []string{"admin", "editor", "viewer", "owner"}
		var b []byte
		b = append(b, '{', '"', 'r', 'e', 'c', 'o', 'r', 'd', 's', '"', ':', '[')
		for i := 0; len(b) < ptSize; i++ {
			if i > 0 {
				b = append(b, ',')
			}
			idx := int(pt[i%len(pt)])
			rec := fmt.Sprintf(`{"user_id":%d,"user_name":"%s","role":"%s","active":%v,"score":%d.%02d}`,
				1000+msgIdx*100+i, names[(idx+i)%len(names)], roles[(idx+i)%len(roles)], (idx+i)%2 == 0, 10+(idx*7+i)%90, (idx*13+i)%100)
			b = append(b, rec...)
		}
		copy(pt, b[:ptSize])
	}
	return pt
}

func qhReachableFoldClasses() (loClasses, hiClasses int) {
	loPairs := map[[2]byte]bool{[2]byte{0, 1}: true}
	hiPairs := map[[2]byte]bool{[2]byte{18, 165}: true}
	for step := 0; step < 4; step++ {
		nextLo := map[[2]byte]bool{}
		for p := range loPairs {
			for b := 0; b < 256; b++ {
				y0 := byte(((uint32(p[0]) + uint32(b)) * (uint32(p[0]) + uint32(b))) & 0xFF)
				y1 := byte(((uint32(p[1]) + uint32(b)) * (uint32(p[1]) + uint32(b))) & 0xFF)
				nextLo[[2]byte{y0, y1}] = true
			}
		}
		loPairs = nextLo

		nextHi := map[[2]byte]bool{}
		for p := range hiPairs {
			for b := 0; b < 256; b++ {
				y0 := byte((((uint32(p[0]) + uint32(b)) * (uint32(p[0]) + uint32(b))) + 1) & 0xFF)
				y1 := byte((((uint32(p[1]) + uint32(b)) * (uint32(p[1]) + uint32(b))) + 1) & 0xFF)
				nextHi[[2]byte{y0, y1}] = true
			}
		}
		hiPairs = nextHi
	}
	return len(loPairs), len(hiPairs)
}

func TestRedTeamQuadHashSingleMessage(t *testing.T) {
	cfg := &Config{NonceBits: 128, BarrierFill: 1}
	loFold, hiFold := qhReachableFoldClasses()
	inv := probeInterlockNonceInvariance128(cfg, quadHash, 512, 8, 8)
	t.Logf("quadHash reachable lockBuf fold classes at byte 9: lo=%d, hi=%d; deriveInterLockSeed distinct=%d, laneMatches=%d/%d",
		loFold, hiFold, inv.distinctKeys, inv.laneMatches, inv.laneTrials)

	const (
		N       = 1000
		ptSize  = 512
		cribLen = 48
	)

	for _, corpus := range []string{"ascii", "json", "binary"} {
		corpus := corpus
		t.Run(corpus, func(t *testing.T) {
			var solved int64
			var sha256Exact int64
			var totalTrials int64
			t0 := time.Now()

			var wg sync.WaitGroup
			ch := make(chan int, N)
			for i := 0; i < N; i++ {
				ch <- i
			}
			close(ch)

			for w := 0; w < 8; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for idx := range ch {
						pt := qhMakePlaintext(corpus, ptSize, idx)
						ns, _ := NewSeed128(512, quadHash)
						ls, _ := NewSeed128(512, quadHash)
						d1, _ := NewSeed128(512, quadHash)
						d2, _ := NewSeed128(512, quadHash)
						d3, _ := NewSeed128(512, quadHash)
						s1, _ := NewSeed128(512, quadHash)
						s2, _ := NewSeed128(512, quadHash)
						s3, _ := NewSeed128(512, quadHash)

						ct, err := Encrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, pt)
						if err != nil {
							t.Errorf("Encrypt3x128Cfg: %v", err)
							return
						}

						got, _, trials, ok := solveQuadHashSingleMessage(cfg, ct, pt[:cribLen])
						atomic.AddInt64(&totalTrials, int64(trials))
						if ok {
							atomic.AddInt64(&solved, 1)
							if len(got) == len(pt) && sha256.Sum256(got) == sha256.Sum256(pt) {
								atomic.AddInt64(&sha256Exact, 1)
							}
						}
					}
				}()
			}
			wg.Wait()
			elapsed := time.Since(t0)

			t.Logf("corpus=%-6s | N=%d | crib=%dB | solved=%d/%d (%.2f%%) | SHA-256 exact=%d/%d (%.2f%%) | mean Decrypt3x128Cfg trials=%.2f | wall=%v (%.2f ms/msg)",
				corpus, N, cribLen, solved, N, 100*float64(solved)/float64(N),
				sha256Exact, N, 100*float64(sha256Exact)/float64(N),
				float64(totalTrials)/float64(N), elapsed, float64(elapsed.Microseconds())/1000.0/float64(N))

			if solved != N || sha256Exact != N {
				t.Fatalf("corpus=%s: expected %d/%d SHA-256 exact recoveries, got solved=%d sha256Exact=%d",
					corpus, N, N, solved, sha256Exact)
			}
		})
	}
}
