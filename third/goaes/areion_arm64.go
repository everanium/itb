//go:build !purego

package aes

//go:noescape
func areion256PermuteRCAsm(state *Areion256, rc *[15][16]byte)

// areion256PermuteAsm applies the Areion256 permutation in assembly.
func areion256PermuteAsm(state *Areion256) {
	areion256PermuteRCAsm(state, &areionRoundConstants)
}

//go:noescape
func areion256InversePermuteAsm(state *Areion256)

//go:noescape
func areion512PermuteRCAsm(state *Areion512, rc *[15][16]byte)

// areion512PermuteAsm applies the Areion512 permutation in assembly.
func areion512PermuteAsm(state *Areion512) {
	areion512PermuteRCAsm(state, &areionRoundConstants)
}

//go:noescape
func areion512InversePermuteAsm(state *Areion512)
