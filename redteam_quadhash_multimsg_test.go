//go:build redteam

package itb

// Universal multi-message 8xEquivSeeds recovery under quadHash.
//
// Because every byte of input doubles the 2-adic valuation of any even state
// difference in quadHash, all 7 higher bits (bits 1..7) of every round's seed
// byte are erased after 7 buffer bytes. Over any ITB domain buffer (13, 17, or
// 20 bytes), each 512-bit seed collapses to at most 1 bit in lo
// ((s0 ^ s2 ^ s4 ^ s6) & 1) and 1 bit in hi ((s1 ^ s3 ^ s5 ^ s7) & 1).
//
// For lockSeed, the 4-round deriveInterLockSeed cascade followed by the 4
// component rounds of fillRanks XORs the seed parity twice, cancelling it
// identically to zero (0 effective bits). Consequently, the entire 8-seed
// session key under quadHash has only 8 universal bits across all 8 seeds:
//   - noiseSeed:    2 bits (lo parity, hi parity)
//   - lockSeed:     0 bits (cancels mod 2 across deriveInterLockSeed + fillRanks)
//   - dataSeed1..3: 1 bit each (lo parity)
//   - startSeed1..3: 1 bit each (lo parity)
//
// Pinning these 8 bits from messages 0..1 yields an 8-seed bundle of valid
// 512-bit *Seed128 instances that decrypts every message of the session via
// Decrypt3x128Cfg with 100% SHA-256 verification.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

// qhMakeUniversalEquivSeed builds a canonical 512-bit *Seed128 for slot in 0..7
// from its 1-bit lo parity and 1-bit hi parity. Setting Components[0] = uint64(2*slot)
// keeps Components[0] even (parity 0) while satisfying checkEightSeeds128.
func qhMakeUniversalEquivSeed(slot int, loBit, hiBit byte) *Seed128 {
	s, err := SeedFromComponents128(quadHash,
		uint64(2*slot), 0,
		0, 0,
		0, 0,
		uint64(loBit&1), uint64(hiBit&1),
	)
	if err != nil {
		panic(err)
	}
	return s
}

func recoverQuadHash8EquivSeeds(cfg *Config, cts, cribs [][]byte) (seeds [8]*Seed128, decryptTrials int, ok bool) {
	nonceLen := currentNonceSizeCfg(cfg)
	lens, _ := nonceSplit(nonceLen)

	checkRegionCOBS := func(ct []byte, r int, ns, ds, ss *Seed128) (int, bool) {
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

	ls := qhMakeUniversalEquivSeed(1, 0, 0)

	for nsBits := byte(0); nsBits < 4; nsBits++ {
		ns := qhMakeUniversalEquivSeed(0, nsBits&1, (nsBits>>1)&1)

		type regPair struct {
			ds, ss *Seed128
		}
		var validReg [3][]regPair
		possible := true
		for r := 0; r < 3; r++ {
			for dsBit := byte(0); dsBit < 2; dsBit++ {
				ds := qhMakeUniversalEquivSeed(2+r, dsBit, 0)
				for ssBit := byte(0); ssBit < 2; ssBit++ {
					ss := qhMakeUniversalEquivSeed(5+r, ssBit, 0)
					allCOBS := true
					for m := range cts {
						if _, ok := checkRegionCOBS(cts[m], r, ns, ds, ss); !ok {
							allCOBS = false
							break
						}
					}
					if allCOBS {
						validReg[r] = append(validReg[r], regPair{ds, ss})
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
				for _, rp2 := range validReg[2] {
					allMatch := true
					for m := range cts {
						decryptTrials++
						got, err := Decrypt3x128Cfg(cfg, ns, ls, rp0.ds, rp1.ds, rp2.ds, rp0.ss, rp1.ss, rp2.ss, cts[m])
						if err != nil || len(got) < len(cribs[m]) || !bytes.Equal(got[:len(cribs[m])], cribs[m]) {
							allMatch = false
							break
						}
					}
					if allMatch {
						return [8]*Seed128{ns, ls, rp0.ds, rp1.ds, rp2.ds, rp0.ss, rp1.ss, rp2.ss}, decryptTrials, true
					}
				}
			}
		}
	}
	return seeds, decryptTrials, false
}

func TestRedTeamQuadHashMultiMessage(t *testing.T) {
	cfg := &Config{NonceBits: 128, BarrierFill: 1}
	const (
		numSessions    = 20
		msgsPerSession = 50
		anchorMsgs     = 8
		ptSize         = 512
		cribLen        = 128
	)

	for _, corpus := range []string{"ascii", "json", "binary"} {
		corpus := corpus
		t.Run(corpus, func(t *testing.T) {
			t0 := time.Now()
			sessionsSolved := 0
			totalMsgs := 0
			totalMsgsSHA256Match := 0
			totalUnknownBytes := 0
			totalUnknownExact := 0
			totalTrials := 0

			for s := 0; s < numSessions; s++ {
				ns, _ := NewSeed128(512, quadHash)
				ls, _ := NewSeed128(512, quadHash)
				d1, _ := NewSeed128(512, quadHash)
				d2, _ := NewSeed128(512, quadHash)
				d3, _ := NewSeed128(512, quadHash)
				s1, _ := NewSeed128(512, quadHash)
				s2, _ := NewSeed128(512, quadHash)
				s3, _ := NewSeed128(512, quadHash)

				pts := make([][]byte, msgsPerSession)
				cts := make([][]byte, msgsPerSession)
				cribs := make([][]byte, anchorMsgs)
				for m := 0; m < msgsPerSession; m++ {
					pts[m] = qhMakePlaintext(corpus, ptSize, m)
					if m < anchorMsgs {
						cribs[m] = pts[m][:cribLen]
					}
					var err error
					cts[m], err = Encrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, pts[m])
					if err != nil {
						t.Fatalf("Encrypt3x128Cfg: %v", err)
					}
				}

				equiv, trials, ok := recoverQuadHash8EquivSeeds(cfg, cts[:anchorMsgs], cribs)
				totalTrials += trials
				if ok {
					sessionsSolved++
				}

				for m := 0; m < msgsPerSession; m++ {
					totalMsgs++
					totalUnknownBytes += ptSize - cribLen
					if !ok {
						continue
					}
					dec, err := Decrypt3x128Cfg(cfg, equiv[0], equiv[1], equiv[2], equiv[3], equiv[4], equiv[5], equiv[6], equiv[7], cts[m])
					if err == nil && len(dec) == ptSize {
						if sha256.Sum256(dec) == sha256.Sum256(pts[m]) {
							totalMsgsSHA256Match++
						}
						for i := cribLen; i < ptSize; i++ {
							if dec[i] == pts[m][i] {
								totalUnknownExact++
							}
						}
					}
				}
			}

			t.Logf("corpus=%-6s | sessions=%d x %d msgs (%d total) | crib=%dB on msg 0..%d | sessionsPinned=%d/%d (mean trials=%.2f) | SHA-256 exact=%d/%d (%.2f%%) | unknown 75%% exact=%d/%d (%.2f%%) | wall=%v",
				corpus, numSessions, msgsPerSession, totalMsgs, cribLen, anchorMsgs-1,
				sessionsSolved, numSessions, float64(totalTrials)/float64(numSessions),
				totalMsgsSHA256Match, totalMsgs, 100*float64(totalMsgsSHA256Match)/float64(totalMsgs),
				totalUnknownExact, totalUnknownBytes, 100*float64(totalUnknownExact)/float64(totalUnknownBytes),
				time.Since(t0))

			if sessionsSolved != numSessions || totalMsgsSHA256Match != totalMsgs || totalUnknownExact != totalUnknownBytes {
				t.Fatalf("corpus=%s: expected 100%% recovery across %d messages, got sessions=%d/%d sha256=%d/%d unknown=%d/%d",
					corpus, totalMsgs, sessionsSolved, numSessions, totalMsgsSHA256Match, totalMsgs, totalUnknownExact, totalUnknownBytes)
			}
		})
	}
}
