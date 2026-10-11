//go:build (amd64 || arm64) && !purego

package aes

import (
	"bytes"
	"testing"
)

// Test hardware vs software implementation consistency
func TestAreion256HardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	var stateHW, stateSW Areion256
	for i := range stateHW {
		stateHW[i] = byte(i ^ 0xAA)
	}
	copy(stateSW[:], stateHW[:])

	// Hardware
	areion256PermuteAsm(&stateHW)

	// Software
	areion256PermuteSoftware(&stateSW)

	if !bytes.Equal(stateHW[:], stateSW[:]) {
		t.Errorf("Areion256 hardware/software mismatch\nHardware: %x\nSoftware: %x", stateHW[:], stateSW[:])
	}
}

func TestAreion512HardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	var stateHW, stateSW Areion512
	for i := range stateHW {
		stateHW[i] = byte(i ^ 0x55)
	}
	copy(stateSW[:], stateHW[:])

	// Hardware
	areion512PermuteAsm(&stateHW)

	// Software
	areion512PermuteSoftware(&stateSW)

	if !bytes.Equal(stateHW[:], stateSW[:]) {
		t.Errorf("Areion512 hardware/software mismatch\nHardware: %x\nSoftware: %x", stateHW[:], stateSW[:])
	}
}

func TestAreion256InverseHardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	var stateHW, stateSW Areion256
	for i := range stateHW {
		stateHW[i] = byte(i * 7)
	}
	copy(stateSW[:], stateHW[:])

	// Hardware
	areion256InversePermuteAsm(&stateHW)

	// Software
	areion256InversePermuteSoftware(&stateSW)

	if !bytes.Equal(stateHW[:], stateSW[:]) {
		t.Errorf("Areion256 inverse hardware/software mismatch\nHardware: %x\nSoftware: %x", stateHW[:], stateSW[:])
	}
}

func TestAreion512InverseHardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	var stateHW, stateSW Areion512
	for i := range stateHW {
		stateHW[i] = byte(i * 11)
	}
	copy(stateSW[:], stateHW[:])

	// Hardware
	areion512InversePermuteAsm(&stateHW)

	// Software
	areion512InversePermuteSoftware(&stateSW)

	if !bytes.Equal(stateHW[:], stateSW[:]) {
		t.Errorf("Areion512 inverse hardware/software mismatch\nHardware: %x\nSoftware: %x", stateHW[:], stateSW[:])
	}
}

// TestAreionPermute2HardwareSoftwareMatch checks the assembly path of the
// second Areion permutation against the software path.
func TestAreionPermute2HardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	for _, seed := range []byte{0x00, 0x5a, 0xa5, 0xff} {
		var hw256, sw256 Areion256
		for i := range hw256 {
			hw256[i] = byte(i*5) ^ seed
		}
		copy(sw256[:], hw256[:])
		areion256PermuteRCAsm(&hw256, &areionRoundConstants2)
		areion256PermuteSoftwareRC(&sw256, &areionRoundConstants2)
		if !bytes.Equal(hw256[:], sw256[:]) {
			t.Errorf("Areion256 second permutation hardware/software mismatch (seed %#x)\nHardware: %x\nSoftware: %x", seed, hw256[:], sw256[:])
		}

		var hw512, sw512 Areion512
		for i := range hw512 {
			hw512[i] = byte(i*5) ^ seed
		}
		copy(sw512[:], hw512[:])
		areion512PermuteRCAsm(&hw512, &areionRoundConstants2)
		areion512PermuteSoftwareRC(&sw512, &areionRoundConstants2)
		if !bytes.Equal(hw512[:], sw512[:]) {
			t.Errorf("Areion512 second permutation hardware/software mismatch (seed %#x)\nHardware: %x\nSoftware: %x", seed, hw512[:], sw512[:])
		}
	}
}
