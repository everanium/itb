//go:build !amd64

package itb

// splitRank48 takes the reciprocal-multiply formulation on every
// architecture without a hardware 128-by-64 divide, where
// [math/bits.Div64] is a software routine (arm64 included).
func splitRank48(lane0, lane1 uint64) (idx0 uint64, idx1 uint32) {
	return splitRank48Recip(lane0, lane1)
}
