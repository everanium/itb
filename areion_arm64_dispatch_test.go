//go:build arm64 && !purego && !noitbasm

package itb

import (
	"crypto/rand"
	"testing"

	"github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/areionasm"
)

// TestAreionArm64BatchedGate checks both arms of the arm64 batched
// permutation gate against serial go-aes calls: the ARM Crypto
// Extension kernel when [areionasm.HasARMAESBatched] is set, and the
// portable Go permutation when it is clear — the path a host without
// the extension, or ITB_FORCE_HASH_TIER=scalar, takes.
func TestAreionArm64BatchedGate(t *testing.T) {
	saved := areionasm.HasARMAESBatched
	t.Cleanup(func() { areionasm.HasARMAESBatched = saved })

	for _, gate := range []bool{false, true} {
		if gate && !saved {
			continue // no ARM Crypto Extension on this host
		}
		areionasm.HasARMAESBatched = gate
		for trial := 0; trial < 64; trial++ {
			var k256 [4][64]byte
			var in256 [4][32]byte
			var k512 [4][128]byte
			var in512 [4][64]byte
			for _, b := range [][]byte{k256[0][:], k256[1][:], k256[2][:], k256[3][:],
				in256[0][:], in256[1][:], in256[2][:], in256[3][:],
				k512[0][:], k512[1][:], k512[2][:], k512[3][:],
				in512[0][:], in512[1][:], in512[2][:], in512[3][:]} {
				if _, err := rand.Read(b); err != nil {
					t.Fatal(err)
				}
			}
			got256 := AreionSoEM256x4(&k256, &in256)
			got512 := AreionSoEM512x4(&k512, &in512)
			for lane := 0; lane < 4; lane++ {
				if want := aes.AreionSoEM256(&k256[lane], &in256[lane]); got256[lane] != want {
					t.Fatalf("gate=%v lane %d: AreionSoEM256x4 differs from serial go-aes", gate, lane)
				}
				if want := aes.AreionSoEM512(&k512[lane], &in512[lane]); got512[lane] != want {
					t.Fatalf("gate=%v lane %d: AreionSoEM512x4 differs from serial go-aes", gate, lane)
				}
			}
		}
	}
}
