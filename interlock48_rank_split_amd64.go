//go:build amd64

package itb

// splitRank48 takes the reciprocal-multiply formulation on amd64:
// compile-time reciprocal constants turn every reduction step into
// fixed-latency MULQ instructions, avoiding variable-latency DIVQ on
// secret ranks.
func splitRank48(lane0, lane1 uint64) (idx0 uint64, idx1 uint32) {
	return splitRank48Recip(lane0, lane1)
}
