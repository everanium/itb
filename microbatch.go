package itb

import (
	"os"
	"strconv"
	"strings"
)

// chooseMicroBatch picks the CGO-batch stride for the pixel encoder inner
// loop based on the actual per-invocation payload size.
//
// The batch stride trades two competing costs. In the shipped default
// mid-band the dominant cost is the per-call CGO transition overhead, so
// a wide stride (fewer calls) wins. Above the mid-band the batched hash
// arrays exceed L2, cache-thrash cost overtakes CGO amortisation and the
// baseline stride wins again. Very small payloads do not have enough
// bytes to amortise the up-front hash-array growth to the wide stride,
// so those also fall back to the baseline.
//
// Constants calibrated on AMD EPYC 9655P (Zen 5, L2 = 1 MiB/core) and
// Intel i7-11700K (Rocket Lake, L2 = 512 KiB/core — worst-case modern
// Intel for this workload). Modern successors (Alder Lake+, Sapphire
// Rapids, Zen 4+) carry ≥ 1 MiB per-core L2, so the calibration point is
// a lower bound on the acceptable modern-CPU range.
//
// Called once per Encrypt/Decrypt invocation of process{128,256,512}Cfg
// (the same low-level entry both the Message and the Streaming surfaces
// funnel through — Streaming loops call the Single Message entry per
// chunk). Per-chunk payload length reaches this helper as the ordinary
// slice length so the stream shape gets the actual chunk size without
// separate plumbing.
//
// Under Triple Ouroboros the input `data` slice at this entry is one
// third of the user-visible plaintext, so a user X MB whole plaintext
// arrives here as X/3 MB per snake — every threshold below is stated
// against that per-snake byte count.
//
// The ITB_MICROBATCH_TIERS env var overrides the shipped ladder for the
// microBatch-sweep test harness. Format: comma-separated
// "upperBound:batchSize" pairs, terminated by a "-1:batchSize" fallback
// tier for payloads exceeding every prior upperBound. Example:
// "16384:512,131072:65536,8388608:262144,-1:512". Malformed value falls
// back to defaults.
type microBatchTier struct {
	upperBound int // -1 = fallback tier (matches every remaining payload)
	batchSize  int
}

var defaultMicroBatchTiers = []microBatchTier{
	{upperBound: 16 * 1024, batchSize: 512},
	{upperBound: 8 * 1024 * 1024, batchSize: 262144},
	{upperBound: -1, batchSize: 512},
}

var microBatchTiers = loadMicroBatchTiers()

func loadMicroBatchTiers() []microBatchTier {
	if s := strings.TrimSpace(os.Getenv("ITB_MICROBATCH_TIERS")); s != "" {
		if parsed, ok := parseMicroBatchTiers(s); ok {
			return parsed
		}
	}
	return append([]microBatchTier(nil), defaultMicroBatchTiers...)
}

func parseMicroBatchTiers(s string) ([]microBatchTier, bool) {
	var out []microBatchTier
	for _, part := range strings.Split(s, ",") {
		pair := strings.SplitN(part, ":", 2)
		if len(pair) != 2 {
			return nil, false
		}
		upper, err1 := strconv.Atoi(strings.TrimSpace(pair[0]))
		batch, err2 := strconv.Atoi(strings.TrimSpace(pair[1]))
		if err1 != nil || err2 != nil || batch <= 0 {
			return nil, false
		}
		out = append(out, microBatchTier{upperBound: upper, batchSize: batch})
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

func chooseMicroBatch(payloadBytes int) int {
	for _, t := range microBatchTiers {
		if t.upperBound < 0 || payloadBytes <= t.upperBound {
			return t.batchSize
		}
	}
	return 512
}
