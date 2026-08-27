//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"crypto/rand"
	"encoding/binary"
	"testing"
	"unsafe"

	goaes "github.com/jedisct1/go-aes"
)

// portableRefSoEM256ChainAbsorb is a per-lane portable reference for the
// Areion-SoEM-256 chained-absorb digest. It replicates the `single`
// closure from itb/areion.go using goaes.AreionSoEM256, which
// auto-dispatches to AES-NI or the software fallback — so this
// reference is valid on every host (including AES-NI-only Zen 3 /
// Cascade Lake), unlike referenceAreionSoEM256ChainAbsorb which routes
// through the VAES Areion256Permutex4 kernel.
func portableRefSoEM256ChainAbsorb(fixedKey *[32]byte, seed [4]uint64, data []byte) [4]uint64 {
	const chunkSize = 24
	var key [64]byte
	copy(key[:32], fixedKey[:])
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(key[32+i*8:], seed[i])
	}
	var state [32]byte
	binary.LittleEndian.PutUint64(state[:8], uint64(len(data)))
	if len(data) <= chunkSize {
		copy(state[8:8+len(data)], data)
		state = goaes.AreionSoEM256(&key, &state)
	} else {
		copy(state[8:8+chunkSize], data[0:chunkSize])
		state = goaes.AreionSoEM256(&key, &state)
		off := chunkSize
		for off < len(data) {
			end := off + chunkSize
			if end > len(data) {
				end = len(data)
			}
			for i := 0; i < end-off; i++ {
				state[8+i] ^= data[off+i]
			}
			state = goaes.AreionSoEM256(&key, &state)
			off = end
		}
	}
	var out [4]uint64
	for i := 0; i < 4; i++ {
		out[i] = binary.LittleEndian.Uint64(state[i*8:])
	}
	return out
}

// runAesNi256Parity drives one (AES-NI kernel, length) pair through a
// random-fixture parity sweep against the portable reference.
func runAesNi256Parity(
	t *testing.T,
	dataLen, trials int,
	kernel func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64),
) {
	t.Helper()
	if !goaes.CPU.HasAESNI {
		t.Skip("requires AES-NI")
	}
	for trial := 0; trial < trials; trial++ {
		var fixedKey [32]byte
		if _, err := rand.Read(fixedKey[:]); err != nil {
			t.Fatal(err)
		}
		var seeds [4][4]uint64
		var seedBytes [128]byte
		if _, err := rand.Read(seedBytes[:]); err != nil {
			t.Fatal(err)
		}
		seedsBytes := (*[128]byte)(unsafe.Pointer(&seeds))
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
		var want [4][4]uint64
		for lane := 0; lane < 4; lane++ {
			want[lane] = portableRefSoEM256ChainAbsorb(&fixedKey, seeds[lane], laneData[lane])
		}
		var got [4][4]uint64
		kernel(&fixedKey, &seeds, &ptrs, &got)
		if got != want {
			t.Fatalf("dataLen=%d trial=%d mismatch\n got:  %v\n want: %v", dataLen, trial, got, want)
		}
	}
}

func TestAreion256ChainAbsorb13x4AesNi_Parity(t *testing.T) {
	runAesNi256Parity(t, 13, 200, Areion256ChainAbsorb13x4AesNi)
}

func TestAreion256ChainAbsorb20x4AesNi_Parity(t *testing.T) {
	runAesNi256Parity(t, 20, 200, Areion256ChainAbsorb20x4AesNi)
}

func TestAreion256ChainAbsorb36x4AesNi_Parity(t *testing.T) {
	runAesNi256Parity(t, 36, 200, Areion256ChainAbsorb36x4AesNi)
}

func TestAreion256ChainAbsorb68x4AesNi_Parity(t *testing.T) {
	runAesNi256Parity(t, 68, 200, Areion256ChainAbsorb68x4AesNi)
}

// TestAreion256ChainAbsorbAesNi_MatchesVAES cross-checks the AES-NI
// kernels against the VAES kernels on hosts that carry both (the
// maintainer's 11700K / Zen 5), guaranteeing the two production arms
// agree bit-for-bit.
func TestAreion256ChainAbsorbAesNi_MatchesVAES(t *testing.T) {
	if !goaes.CPU.HasAESNI || !HasVAESAVX512 {
		t.Skip("requires AES-NI and VAES + AVX-512")
	}
	widths := []struct {
		n     int
		aesni func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64)
		vaes  func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64)
	}{
		{13, Areion256ChainAbsorb13x4AesNi, Areion256ChainAbsorb13x4},
		{20, Areion256ChainAbsorb20x4AesNi, Areion256ChainAbsorb20x4},
		{36, Areion256ChainAbsorb36x4AesNi, Areion256ChainAbsorb36x4},
		{68, Areion256ChainAbsorb68x4AesNi, Areion256ChainAbsorb68x4},
	}
	for _, w := range widths {
		for trial := 0; trial < 64; trial++ {
			var fixedKey [32]byte
			if _, err := rand.Read(fixedKey[:]); err != nil {
				t.Fatal(err)
			}
			var seeds [4][4]uint64
			var seedBytes [128]byte
			if _, err := rand.Read(seedBytes[:]); err != nil {
				t.Fatal(err)
			}
			seedsBytes := (*[128]byte)(unsafe.Pointer(&seeds))
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
			var gotAesNi, gotVAES [4][4]uint64
			w.aesni(&fixedKey, &seeds, &ptrs, &gotAesNi)
			w.vaes(&fixedKey, &seeds, &ptrs, &gotVAES)
			if gotAesNi != gotVAES {
				t.Fatalf("width %d trial %d: AES-NI %v != VAES %v", w.n, trial, gotAesNi, gotVAES)
			}
		}
	}
}

// TestAreion256ChainAbsorb13x4AesNi_BitSensitivity flips every input bit
// (per lane) and requires that lane's digest to change.
func TestAreion256ChainAbsorb13x4AesNi_BitSensitivity(t *testing.T) {
	if !goaes.CPU.HasAESNI {
		t.Skip("requires AES-NI")
	}
	var fixedKey [32]byte
	if _, err := rand.Read(fixedKey[:]); err != nil {
		t.Fatal(err)
	}
	var seeds [4][4]uint64
	var seedBytes [128]byte
	if _, err := rand.Read(seedBytes[:]); err != nil {
		t.Fatal(err)
	}
	seedsBytes := (*[128]byte)(unsafe.Pointer(&seeds))
	copy(seedsBytes[:], seedBytes[:])
	base := make([][]byte, 4)
	for lane := 0; lane < 4; lane++ {
		base[lane] = make([]byte, 13)
		if _, err := rand.Read(base[lane]); err != nil {
			t.Fatal(err)
		}
	}
	run := func(d [][]byte) [4][4]uint64 {
		var ptrs [4]*byte
		for lane := 0; lane < 4; lane++ {
			ptrs[lane] = &d[lane][0]
		}
		var out [4][4]uint64
		Areion256ChainAbsorb13x4AesNi(&fixedKey, &seeds, &ptrs, &out)
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
