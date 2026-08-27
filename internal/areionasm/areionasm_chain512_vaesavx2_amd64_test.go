//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"crypto/rand"
	"testing"
	"unsafe"

	goaes "github.com/jedisct1/go-aes"
)

// runVaesAvx2_512Parity drives one (YMM VAES kernel, length) pair through
// a random-fixture parity sweep against the portable reference shared
// with the AES-NI parity tests (portableRefSoEM512ChainAbsorb).
func runVaesAvx2_512Parity(
	t *testing.T,
	dataLen, trials int,
	kernel func(*[64]byte, *[4][8]uint64, *[4]*byte, *[4][8]uint64),
) {
	t.Helper()
	if !goaes.CPU.HasVAES || !goaes.CPU.HasAVX2 {
		t.Skip("requires VAES + AVX2")
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

func TestAreion512ChainAbsorb13x4VaesAvx2_Parity(t *testing.T) {
	runVaesAvx2_512Parity(t, 13, 200, Areion512ChainAbsorb13x4VaesAvx2)
}

func TestAreion512ChainAbsorb20x4VaesAvx2_Parity(t *testing.T) {
	runVaesAvx2_512Parity(t, 20, 200, Areion512ChainAbsorb20x4VaesAvx2)
}

func TestAreion512ChainAbsorb36x4VaesAvx2_Parity(t *testing.T) {
	runVaesAvx2_512Parity(t, 36, 200, Areion512ChainAbsorb36x4VaesAvx2)
}

func TestAreion512ChainAbsorb68x4VaesAvx2_Parity(t *testing.T) {
	runVaesAvx2_512Parity(t, 68, 200, Areion512ChainAbsorb68x4VaesAvx2)
}

// TestAreion512ChainAbsorbVaesAvx2_MatchesVAES cross-checks the YMM VAES
// kernels against the ZMM VAES kernels on hosts that carry both.
func TestAreion512ChainAbsorbVaesAvx2_MatchesVAES(t *testing.T) {
	if !goaes.CPU.HasVAES || !goaes.CPU.HasAVX2 || !HasVAESAVX512 {
		t.Skip("requires VAES + AVX2 + AVX-512")
	}
	widths := []struct {
		n   int
		ymm func(*[64]byte, *[4][8]uint64, *[4]*byte, *[4][8]uint64)
		zmm func(*[64]byte, *[4][8]uint64, *[4]*byte, *[4][8]uint64)
	}{
		{13, Areion512ChainAbsorb13x4VaesAvx2, Areion512ChainAbsorb13x4},
		{20, Areion512ChainAbsorb20x4VaesAvx2, Areion512ChainAbsorb20x4},
		{36, Areion512ChainAbsorb36x4VaesAvx2, Areion512ChainAbsorb36x4},
		{68, Areion512ChainAbsorb68x4VaesAvx2, Areion512ChainAbsorb68x4},
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
			var gotYMM, gotZMM [4][8]uint64
			w.ymm(&fixedKey, &seeds, &ptrs, &gotYMM)
			w.zmm(&fixedKey, &seeds, &ptrs, &gotZMM)
			if gotYMM != gotZMM {
				t.Fatalf("width %d trial %d: YMM %v != ZMM %v", w.n, trial, gotYMM, gotZMM)
			}
		}
	}
}

// TestAreion512ChainAbsorb68x4VaesAvx2_BitSensitivity flips every input
// bit (per lane) and requires that lane's digest to change.
func TestAreion512ChainAbsorb68x4VaesAvx2_BitSensitivity(t *testing.T) {
	if !goaes.CPU.HasVAES || !goaes.CPU.HasAVX2 {
		t.Skip("requires VAES + AVX2")
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
		base[lane] = make([]byte, 68)
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
		Areion512ChainAbsorb68x4VaesAvx2(&fixedKey, &seeds, &ptrs, &out)
		return out
	}
	baseOut := run(base)
	for lane := 0; lane < 4; lane++ {
		for bit := 0; bit < 68*8; bit++ {
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
