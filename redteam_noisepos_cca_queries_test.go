//go:build redteam

package itb

// Early-stop oracle query budget under MAC + Reveal (CCA) on authenticated
// wires.
//
// While noisePosCCAObserve in redteam_noisepos_cca_test.go flips all 8 bits
// of channel 0 in every pixel (8P = 9,800 queries on the 35x35 Mode 1 floor)
// to cross-check uniqueness (hits == 1), an adaptive attacker probing bits
// b = 0..6 of channel 0 per pixel stops at the first accepted flip and infers
// b = 7 by elimination after 7 rejections:
//
//   E[queries/pixel] = (1 + 2 + 3 + 4 + 5 + 6 + 7 + 7) / 8 = 35/8 = 4.375
//   (or 36/8 = 4.50 when also confirming b = 7).
//
// Across P = 1,225 pixels (Mode 1, 1024-bit keys), full extraction of all P
// physical noise positions requires ~5,359 queries on average (~5,513 with
// 8th-bit confirmation), verified against ground truth across N = 100 trials.
//
// Reproduction:
//
//	go test -tags redteam -run 'TestRedTeamNoisePosCCAQueryStats' -v -count=1 ./
//	ITB_REDTEAM_NOISEPOS_TRIALS=100 \
//	    go test -tags redteam -run 'TestRedTeamNoisePosCCAQueryStats' -v -count=1 ./

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"runtime"
	"sort"
	"sync"
	"testing"
)

type ccaQueryTrialStats struct {
	totalPixels      int
	elimQueries      int // b = 0..6, 8th bit inferred by elimination (1..7 queries/pixel)
	confirm8Queries  int // b = 0..7, stopping at first accept (1..8 queries/pixel)
	exhaustiveBound  int // 8 * P
	mismatchedPixels int
}

type ccaQuerySummary struct {
	Trials          int     `json:"trials"`
	MessageBytes    int     `json:"message_bytes"`
	PixelsPerWire   int     `json:"pixels_per_wire"`
	ExhaustiveBound int     `json:"exhaustive_bound_8p"`
	ElimMean        float64 `json:"elim_queries_mean"`
	ElimStdDev      float64 `json:"elim_queries_stddev"`
	ElimMin         int     `json:"elim_queries_min"`
	ElimP10         int     `json:"elim_queries_p10"`
	ElimMedian      int     `json:"elim_queries_median"`
	ElimP90         int     `json:"elim_queries_p90"`
	ElimMax         int     `json:"elim_queries_max"`
	Confirm8Mean    float64 `json:"confirm8_queries_mean"`
	Confirm8StdDev  float64 `json:"confirm8_queries_stddev"`
	Confirm8Min     int     `json:"confirm8_queries_min"`
	Confirm8Median  int     `json:"confirm8_queries_median"`
	Confirm8Max     int     `json:"confirm8_queries_max"`
	MismatchedTotal int     `json:"mismatched_pixels_total"`
}

func summarizeInts(vals []int) (min, p10, median, p90, max int, mean, stddev float64) {
	cp := append([]int(nil), vals...)
	sort.Ints(cp)
	n := len(cp)
	var sum float64
	for _, v := range cp {
		sum += float64(v)
	}
	mean = sum / float64(n)
	var vsum float64
	for _, v := range cp {
		d := float64(v) - mean
		vsum += d * d
	}
	stddev = math.Sqrt(vsum / float64(n))
	median = cp[n/2]
	if n%2 == 0 {
		median = (cp[n/2-1] + cp[n/2]) / 2
	}
	return cp[0], cp[n*10/100], median, cp[n*90/100], cp[n-1], mean, stddev
}

func TestRedTeamNoisePosCCAQueryStats(t *testing.T) {
	trials := noisePosEnvInt("ITB_REDTEAM_NOISEPOS_TRIALS", 100)
	size := noisePosEnvInt("ITB_REDTEAM_NOISEPOS_SIZE", 1500)

	results := make([]ccaQueryTrialStats, trials)
	var wg sync.WaitGroup
	jobs := make(chan int, trials)
	for tr := 0; tr < trials; tr++ {
		jobs <- tr
	}
	close(jobs)

	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for tr := range jobs {
				cfg := &Config{NonceBits: 128, BarrierFill: 1, MaxWorkers: 1}
				var s [8]*Seed128
				for i := range s {
					var err error
					if s[i], err = NewSeed128(1024, sipHash128); err != nil {
						t.Errorf("trial %d: %v", tr, err)
						return
					}
				}
				macKey := make([]byte, 32)
				rand.Read(macKey)
				mac := func(d []byte) []byte {
					m := hmac.New(sha256.New, macKey)
					m.Write(d)
					return m.Sum(nil)
				}
				msg := make([]byte, size)
				rand.Read(msg)
				wire, err := EncryptAuthenticated3x128Cfg(
					cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], msg, mac,
				)
				if err != nil {
					t.Errorf("trial %d encrypt: %v", tr, err)
					return
				}

				nlen := currentNonceSizeCfg(cfg)
				body := wire[streamIDPrefixLen:]
				nonce := body[:nlen]
				total := int(binary.BigEndian.Uint16(body[nlen:])) * int(binary.BigEndian.Uint16(body[nlen+2:]))
				third := total / 3
				sizes := [3]int{third, third, total - 2*third}
				base := [3]int{0, third, 2 * third}
				containerOff := streamIDPrefixLen + nlen + 4

				var truthSP [3]int
				for i := 0; i < 3; i++ {
					truthSP[i] = s[5+i].deriveStartPixel(nonce, sizes[i])
				}
				buf := make([]byte, 4+len(nonce))
				copy(buf[4:], nonce)

				tw := bytes.Clone(wire)
				st := ccaQueryTrialStats{
					totalPixels:     total,
					exhaustiveBound: 8 * total,
				}

				for i := 0; i < 3; i++ {
					T := sizes[i]
					for j := 0; j < T; j++ {
						off := containerOff + (base[i]+j)*Channels
						found := 7
						queries := 0
						for b := 0; b < 7; b++ {
							queries++
							tw[off] ^= 1 << b
							_, derr := DecryptAuthenticated3x128Cfg(
								cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], tw, mac,
							)
							tw[off] ^= 1 << b
							if derr == nil {
								found = b
								break
							}
						}
						st.elimQueries += queries
						if found == 7 {
							st.confirm8Queries += 8
						} else {
							st.confirm8Queries += queries
						}

						pStep := (j - truthSP[i] + T) % T
						lo, hi := s[0].blockHash128(buf, base[i]+pStep)
						if found != int(noisePosition(lo, hi)) {
							st.mismatchedPixels++
						}
					}
				}
				results[tr] = st
			}
		}()
	}
	wg.Wait()

	elimVals := make([]int, trials)
	confVals := make([]int, trials)
	totalMismatch := 0
	for tr, r := range results {
		elimVals[tr] = r.elimQueries
		confVals[tr] = r.confirm8Queries
		totalMismatch += r.mismatchedPixels
	}
	if totalMismatch != 0 {
		t.Fatalf("ground-truth noisePos mismatch on %d pixels", totalMismatch)
	}

	eMin, eP10, eMed, eP90, eMax, eMean, eStd := summarizeInts(elimVals)
	cMin, _, cMed, _, cMax, cMean, cStd := summarizeInts(confVals)
	totalPx := results[0].totalPixels

	summary := ccaQuerySummary{
		Trials:          trials,
		MessageBytes:    size,
		PixelsPerWire:   totalPx,
		ExhaustiveBound: 8 * totalPx,
		ElimMean:        eMean,
		ElimStdDev:      eStd,
		ElimMin:         eMin,
		ElimP10:         eP10,
		ElimMedian:      eMed,
		ElimP90:         eP90,
		ElimMax:         eMax,
		Confirm8Mean:    cMean,
		Confirm8StdDev:  cStd,
		Confirm8Min:     cMin,
		Confirm8Median:  cMed,
		Confirm8Max:     cMax,
		MismatchedTotal: totalMismatch,
	}

	t.Logf("trials=%d msg=%dB pixels=%d (exhaustive 8P=%d, mismatches=%d/%d)",
		trials, size, totalPx, 8*totalPx, totalMismatch, trials*totalPx)
	t.Logf("early-stop (b=0..6, 8th by elimination): mean=%.1f (±%.1f) [%.3f q/px, theory 4.375] | min=%d p10=%d med=%d p90=%d max=%d",
		eMean, eStd, eMean/float64(totalPx), eMin, eP10, eMed, eP90, eMax)
	t.Logf("early-stop (b=0..7, 8th confirmed):      mean=%.1f (±%.1f) [%.3f q/px, theory 4.500] | min=%d med=%d max=%d",
		cMean, cStd, cMean/float64(totalPx), cMin, cMed, cMax)

	noisePosEmit(t, "query_stats.json", summary)
}
