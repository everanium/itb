//go:build amd64

package itb

// splitRank48 takes the [math/bits.Div64] formulation on amd64: Div64
// compiles to the hardware 128-by-64 DIVQ, which measures well ahead
// of the reciprocal-multiply chain on this architecture.
func splitRank48(lane0, lane1 uint64) (idx0 uint64, idx1 uint32) {
	return splitRank48Div(lane0, lane1)
}
