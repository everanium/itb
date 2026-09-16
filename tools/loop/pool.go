package main

import (
	itb "github.com/everanium/itb"
)

// poolTier is one starter tier of the itb hash-array pool, differenced
// between two snapshots.
type poolTier struct {
	index    int
	starter  int64
	get      int64
	fresh    int64 // constructor misses
	regrow   int64
	newBytes int64
}

// poolBytePool is one single-size byte pool (the itb scratch pool or
// the parallax chunk pool), differenced between two snapshots.
type poolBytePool struct {
	get         int64
	fresh       int64
	regrow      int64
	regrowBytes int64
}

// poolFigures is the decoded difference of two pool-counter vectors.
type poolFigures struct {
	tiers []poolTier // only tiers with a non-zero starter width
	buf   poolBytePool
	chunk poolBytePool
}

// takePoolVector reads one pool-counter vector through the public
// [itb.PoolStats] entry — the same slot vector ITB_PoolStats hands a
// binding — so every run of this harness also exercises the path the
// binding-side utilities depend on.
func takePoolVector() []int64 {
	v := make([]int64, itb.PoolStatsLen())
	itb.PoolStats(v)
	return v
}

// Pool counters. diffPoolVectors differences the steady vector against
// the warmup vector under the slot layout [itb.PoolStats] documents:
// slot 0 carries the tier count T, tier i occupies the five slots at
// 1 + 5*i (starter, get, new, regrow, new bytes), and the two byte
// pools occupy the eight slots at 1 + 5*T (get, new, regrow, regrow
// bytes each). The counters are process-wide monotonic totals kept by
// the itb core at every sync.Pool checkout; two snapshots bracketing
// the main loop turn them into per-run hit / miss figures that tell
// whether a pool keeps its items warm between calls or evicts them
// across GC cycles. A tier is reported only when its starter width is
// non-zero (the ladder does not use it otherwise).
func diffPoolVectors(steady, warmup []int64) poolFigures {
	var f poolFigures
	if len(steady) < 9 || len(warmup) != len(steady) {
		return f
	}
	tiers := int(steady[0])
	if tiers < 0 || 1+5*tiers+8 > len(steady) {
		return f
	}
	for i := 0; i < tiers; i++ {
		base := 1 + 5*i
		if steady[base] == 0 {
			continue
		}
		f.tiers = append(f.tiers, poolTier{
			index:    i,
			starter:  steady[base],
			get:      steady[base+1] - warmup[base+1],
			fresh:    steady[base+2] - warmup[base+2],
			regrow:   steady[base+3] - warmup[base+3],
			newBytes: steady[base+4] - warmup[base+4],
		})
	}
	tail := 1 + 5*tiers
	f.buf = poolBytePool{
		get:         steady[tail+0] - warmup[tail+0],
		fresh:       steady[tail+1] - warmup[tail+1],
		regrow:      steady[tail+2] - warmup[tail+2],
		regrowBytes: steady[tail+3] - warmup[tail+3],
	}
	f.chunk = poolBytePool{
		get:         steady[tail+4] - warmup[tail+4],
		fresh:       steady[tail+5] - warmup[tail+5],
		regrow:      steady[tail+6] - warmup[tail+6],
		regrowBytes: steady[tail+7] - warmup[tail+7],
	}
	return f
}
