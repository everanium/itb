//go:build !purego

package aes

// areion256Permute dispatches to hardware or software implementation
func areion256Permute(state *Areion256) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		areion256PermuteAsm(state)
	} else {
		areion256PermuteSoftware(state)
	}
}

// areion256Permute2 applies the second Areion256 permutation (round constants
// areionRoundConstants2) used by AreionSoEM256.
func areion256Permute2(state *Areion256) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		areion256PermuteRCAsm(state, &areionRoundConstants2)
	} else {
		areion256PermuteSoftwareRC(state, &areionRoundConstants2)
	}
}

// areion256InversePermute dispatches to hardware or software implementation
func areion256InversePermute(state *Areion256) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		areion256InversePermuteAsm(state)
	} else {
		areion256InversePermuteSoftware(state)
	}
}

// areion512Permute dispatches to hardware or software implementation
func areion512Permute(state *Areion512) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		areion512PermuteAsm(state)
	} else {
		areion512PermuteSoftware(state)
	}
}

// areion512Permute2 applies the second Areion512 permutation (round constants
// areionRoundConstants2) used by AreionSoEM512.
func areion512Permute2(state *Areion512) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		areion512PermuteRCAsm(state, &areionRoundConstants2)
	} else {
		areion512PermuteSoftwareRC(state, &areionRoundConstants2)
	}
}

// areion512InversePermute dispatches to hardware or software implementation
func areion512InversePermute(state *Areion512) {
	if CPU.HasAESNI || CPU.HasARMCrypto {
		areion512InversePermuteAsm(state)
	} else {
		areion512InversePermuteSoftware(state)
	}
}
