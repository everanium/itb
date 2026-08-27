//go:build amd64 && !purego && !noitbasm

package areionasm

import (
	"crypto/rand"
	"testing"
	"unsafe"

	goaes "github.com/jedisct1/go-aes"
)

// runVaesAvx2_256Parity drives one (YMM VAES kernel, length) pair through
// a random-fixture parity sweep against the portable reference shared
// with the AES-NI parity tests (portableRefSoEM256ChainAbsorb).
func runVaesAvx2_256Parity(
	t *testing.T,
	dataLen, trials int,
	kernel func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64),
) {
	t.Helper()
	if !goaes.CPU.HasVAES || !goaes.CPU.HasAVX2 {
		t.Skip("requires VAES + AVX2")
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

func TestAreion256ChainAbsorb13x4VaesAvx2_Parity(t *testing.T) {
	runVaesAvx2_256Parity(t, 13, 200, Areion256ChainAbsorb13x4VaesAvx2)
}

func TestAreion256ChainAbsorb20x4VaesAvx2_Parity(t *testing.T) {
	runVaesAvx2_256Parity(t, 20, 200, Areion256ChainAbsorb20x4VaesAvx2)
}

func TestAreion256ChainAbsorb36x4VaesAvx2_Parity(t *testing.T) {
	runVaesAvx2_256Parity(t, 36, 200, Areion256ChainAbsorb36x4VaesAvx2)
}

func TestAreion256ChainAbsorb68x4VaesAvx2_Parity(t *testing.T) {
	runVaesAvx2_256Parity(t, 68, 200, Areion256ChainAbsorb68x4VaesAvx2)
}

// TestAreion256ChainAbsorbVaesAvx2_MatchesVAES cross-checks the YMM VAES
// kernels against the ZMM VAES kernels on hosts that carry both (the
// 11700K / Zen 5), guaranteeing the two arms agree bit-for-bit.
func TestAreion256ChainAbsorbVaesAvx2_MatchesVAES(t *testing.T) {
	if !goaes.CPU.HasVAES || !goaes.CPU.HasAVX2 || !HasVAESAVX512 {
		t.Skip("requires VAES + AVX2 + AVX-512")
	}
	widths := []struct {
		n   int
		ymm func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64)
		zmm func(*[32]byte, *[4][4]uint64, *[4]*byte, *[4][4]uint64)
	}{
		{13, Areion256ChainAbsorb13x4VaesAvx2, Areion256ChainAbsorb13x4},
		{20, Areion256ChainAbsorb20x4VaesAvx2, Areion256ChainAbsorb20x4},
		{36, Areion256ChainAbsorb36x4VaesAvx2, Areion256ChainAbsorb36x4},
		{68, Areion256ChainAbsorb68x4VaesAvx2, Areion256ChainAbsorb68x4},
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
			var gotYMM, gotZMM [4][4]uint64
			w.ymm(&fixedKey, &seeds, &ptrs, &gotYMM)
			w.zmm(&fixedKey, &seeds, &ptrs, &gotZMM)
			if gotYMM != gotZMM {
				t.Fatalf("width %d trial %d: YMM %v != ZMM %v", w.n, trial, gotYMM, gotZMM)
			}
		}
	}
}

// TestAreion256ChainAbsorb68x4VaesAvx2_BitSensitivity flips every input
// bit (per lane) and requires that lane's digest to change.
func TestAreion256ChainAbsorb68x4VaesAvx2_BitSensitivity(t *testing.T) {
	if !goaes.CPU.HasVAES || !goaes.CPU.HasAVX2 {
		t.Skip("requires VAES + AVX2")
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
		base[lane] = make([]byte, 68)
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
		Areion256ChainAbsorb68x4VaesAvx2(&fixedKey, &seeds, &ptrs, &out)
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
