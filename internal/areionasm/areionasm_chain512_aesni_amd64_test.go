//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
	"unsafe"

	goaes "github.com/jedisct1/go-aes"
)

// portableRefSoEM512ChainAbsorb is a per-lane portable reference for the
// Areion-SoEM-512 chained-absorb digest, replicating the `single`
// closure from itb/areion.go via goaes.AreionSoEM512 (auto-dispatch,
// valid on every host including AES-NI-only silicon).
func portableRefSoEM512ChainAbsorb(fixedKey *[64]byte, seed [8]uint64, data []byte) [8]uint64 {
	const chunkSize = 56
	var key [128]byte
	copy(key[:64], fixedKey[:])
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(key[64+i*8:], seed[i])
	}
	var state [64]byte
	binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))
	if len(data) <= chunkSize {
		copy(state[8:8+len(data)], data)
		state = goaes.AreionSoEM512(&key, &state)
	} else {
		copy(state[8:8+chunkSize], data[0:chunkSize])
		state = goaes.AreionSoEM512(&key, &state)
		off := chunkSize
		for off < len(data) {
			end := off + chunkSize
			if end > len(data) {
				end = len(data)
			}
			for i := 0; i < end-off; i++ {
				state[8+i] ^= data[off+i]
			}
			state = goaes.AreionSoEM512(&key, &state)
			off = end
		}
	}
	var out [8]uint64
	for i := 0; i < 8; i++ {
		out[i] = binary.LittleEndian.Uint64(state[i*8:])
	}
	return out
}

func runAesNi512Parity(
	t *testing.T,
	dataLen, trials int,
	kernel func(*[64]byte, *[4][8]uint64, *[4]*byte, *[4][8]uint64),
) {
	t.Helper()
	if !goaes.CPU.HasAESNI {
		t.Skip("requires AES-NI")
	}
	for trial := 0; trial < trials; trial++ {
		var fixedKey [64]byte
		if _, err := rand.Read(fixedKey[:]); err != nil {
			t.Fatal(err)
		}
		var seeds [4][8]uint64
		var seedBytes [256]byte
		if _, err := rand.Read(seedBytes[:]); err != nil {
			t.Fatal(err)
		}
		seedsBytes := (*[256]byte)(unsafe.Pointer(&seeds))
		copy(seedsBytes[:], seedBytes[:])

		laneData := make([][]byte, 4)
		var ptrs [4]*byte
		for lane := 0; lane < 4; lane++ {
			laneData[lane] = make([]byte, dataLen)
			if _, err := rand.Read(laneData[lane]); err != nil {
				t.Fatal(err)
			}
			ptrs[lane] = &laneData[lane][0]
		}
		var want [4][8]uint64
		for lane := 0; lane < 4; lane++ {
			want[lane] = portableRefSoEM512ChainAbsorb(&fixedKey, seeds[lane], laneData[lane])
		}
		var got [4][8]uint64
		kernel(&fixedKey, &seeds, &ptrs, &got)
		if got != want {
			t.Fatalf("dataLen=%d trial=%d mismatch\n got:  %v\n want: %v", dataLen, trial, got, want)
		}
	}
}

func TestAreion512ChainAbsorb13x4AesNi_Parity(t *testing.T) {
	runAesNi512Parity(t, 13, 200, Areion512ChainAbsorb13x4AesNi)
}

func TestAreion512ChainAbsorb20x4AesNi_Parity(t *testing.T) {
	runAesNi512Parity(t, 20, 200, Areion512ChainAbsorb20x4AesNi)
}

func TestAreion512ChainAbsorb36x4AesNi_Parity(t *testing.T) {
	runAesNi512Parity(t, 36, 200, Areion512ChainAbsorb36x4AesNi)
}

func TestAreion512ChainAbsorb68x4AesNi_Parity(t *testing.T) {
	runAesNi512Parity(t, 68, 200, Areion512ChainAbsorb68x4AesNi)
}

// TestAreion512ChainAbsorbAesNi_MatchesVAES cross-checks against the
// VAES kernels on hosts carrying both.
func TestAreion512ChainAbsorbAesNi_MatchesVAES(t *testing.T) {
	if !goaes.CPU.HasAESNI || !HasVAESAVX512 {
		t.Skip("requires AES-NI and VAES + AVX-512")
	}
	widths := []struct {
		n     int
		aesni func(*[64]byte, *[4][8]uint64, *[4]*byte, *[4][8]uint64)
		vaes  func(*[64]byte, *[4][8]uint64, *[4]*byte, *[4][8]uint64)
	}{
		{13, Areion512ChainAbsorb13x4AesNi, Areion512ChainAbsorb13x4},
		{20, Areion512ChainAbsorb20x4AesNi, Areion512ChainAbsorb20x4},
		{36, Areion512ChainAbsorb36x4AesNi, Areion512ChainAbsorb36x4},
		{68, Areion512ChainAbsorb68x4AesNi, Areion512ChainAbsorb68x4},
	}
	for _, w := range widths {
		for trial := 0; trial < 64; trial++ {
			var fixedKey [64]byte
			if _, err := rand.Read(fixedKey[:]); err != nil {
				t.Fatal(err)
			}
			var seeds [4][8]uint64
			var seedBytes [256]byte
			if _, err := rand.Read(seedBytes[:]); err != nil {
				t.Fatal(err)
			}
			seedsBytes := (*[256]byte)(unsafe.Pointer(&seeds))
			copy(seedsBytes[:], seedBytes[:])
			laneData := make([][]byte, 4)
			var ptrs [4]*byte
			for lane := 0; lane < 4; lane++ {
				laneData[lane] = make([]byte, w.n)
				if _, err := rand.Read(laneData[lane]); err != nil {
					t.Fatal(err)
				}
				ptrs[lane] = &laneData[lane][0]
			}
			var gotAesNi, gotVAES [4][8]uint64
			w.aesni(&fixedKey, &seeds, &ptrs, &gotAesNi)
			w.vaes(&fixedKey, &seeds, &ptrs, &gotVAES)
			if gotAesNi != gotVAES {
				t.Fatalf("width %d trial %d: AES-NI %v != VAES %v", w.n, trial, gotAesNi, gotVAES)
			}
		}
	}
}

// TestAreion512ChainAbsorb13x4AesNi_BitSensitivity flips every input
// bit (per lane) and requires that lane's digest to change.
func TestAreion512ChainAbsorb13x4AesNi_BitSensitivity(t *testing.T) {
	if !goaes.CPU.HasAESNI {
		t.Skip("requires AES-NI")
	}
	var fixedKey [64]byte
	if _, err := rand.Read(fixedKey[:]); err != nil {
		t.Fatal(err)
	}
	var seeds [4][8]uint64
	var seedBytes [256]byte
	if _, err := rand.Read(seedBytes[:]); err != nil {
		t.Fatal(err)
	}
	seedsBytes := (*[256]byte)(unsafe.Pointer(&seeds))
	copy(seedsBytes[:], seedBytes[:])
	base := make([][]byte, 4)
	for lane := 0; lane < 4; lane++ {
		base[lane] = make([]byte, 13)
		if _, err := rand.Read(base[lane]); err != nil {
			t.Fatal(err)
		}
	}
	run := func(d [][]byte) [4][8]uint64 {
		var ptrs [4]*byte
		for lane := 0; lane < 4; lane++ {
			ptrs[lane] = &d[lane][0]
		}
		var out [4][8]uint64
		Areion512ChainAbsorb13x4AesNi(&fixedKey, &seeds, &ptrs, &out)
		return out
	}
	baseOut := run(base)
	for lane := 0; lane < 4; lane++ {
		for bit := 0; bit < 13*8; bit++ {
			flipped := make([][]byte, 4)
			for i := 0; i < 4; i++ {
				flipped[i] = append([]byte(nil), base[i]...)
			}
			flipped[lane][bit/8] ^= 1 << (bit % 8)
			out := run(flipped)
			if out[lane] == baseOut[lane] {
				t.Fatalf("lane %d bit %d flip produced identical digest", lane, bit)
			}
		}
	}
}
