//go:build amd64 && !purego && !noitbasm

package aesitbasm

import (
	"fmt"
	"testing"
)

// BenchmarkTier times every kernel tier the host can execute, per shape,
// by direct call (independent of the auto-selected dispatch).
func BenchmarkTier(b *testing.B) {
	for _, tier := range amd64Tiers() {
		if !tier.ok {
			continue
		}
		for _, n := range shapes {
			kernel := tier.k[n]
			b.Run(fmt.Sprintf("%s/shape%d", tier.name, n), func(b *testing.B) {
				benchKernel(b, n, kernel)
			})
		}
	}
}
