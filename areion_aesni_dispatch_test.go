//go:build amd64 && !purego && !noitbasm

package itb

import (
	"crypto/rand"
	"testing"

	goaes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/areionasm"
)

// TestAreionSoEM256ChainAbsorbHot_AesNiDispatch is the dispatch-wiring
// guard (playbook §10.6) for the amd64 Areion-SoEM-256 hot dispatcher.
// With HasVAESAVX512 forced false and HasAESNIBatched forced true, the
// dispatcher must route to the XMM AES-NI kernels and return results
// bit-identical to the VAES kernels (restored afterwards). Only the
// dispatch flags are toggled; the underlying instructions are legal on
// any AES-NI host.
func TestAreionSoEM256ChainAbsorbHot_AesNiDispatch(t *testing.T) {
	if !goaes.CPU.HasAESNI || !areionasm.HasVAESAVX512 {
		t.Skip("requires AES-NI and VAES + AVX-512 (to compare both arms)")
	}
	savedVAES := areionasm.HasVAESAVX512
	savedAesNi := areionasm.HasAESNIBatched
	t.Cleanup(func() {
		areionasm.HasVAESAVX512 = savedVAES
		areionasm.HasAESNIBatched = savedAesNi
	})

	for _, commonLen := range []int{13, 20, 36, 68} {
		var fixedKey [32]byte
		if _, err := rand.Read(fixedKey[:]); err != nil {
			t.Fatal(err)
		}
		var seeds [4][4]uint64
		var sb [128]byte
		if _, err := rand.Read(sb[:]); err != nil {
			t.Fatal(err)
		}
		for lane := 0; lane < 4; lane++ {
			for i := 0; i < 4; i++ {
				seeds[lane][i] = leU64(sb[lane*32+i*8:])
			}
		}
		var data [4][]byte
		for lane := 0; lane < 4; lane++ {
			data[lane] = make([]byte, commonLen)
			if _, err := rand.Read(data[lane]); err != nil {
				t.Fatal(err)
			}
		}

		areionasm.HasVAESAVX512 = true
		areionasm.HasAESNIBatched = false
		wantVAES, okV := areionSoEM256ChainAbsorbHot(&fixedKey, &seeds, &data, commonLen)
		if !okV {
			t.Fatalf("len=%d: VAES hot dispatch reported ok=false", commonLen)
		}

		areionasm.HasVAESAVX512 = false
		areionasm.HasAESNIBatched = true
		gotAesNi, okA := areionSoEM256ChainAbsorbHot(&fixedKey, &seeds, &data, commonLen)
		if !okA {
			t.Fatalf("len=%d: AES-NI hot dispatch reported ok=false (routing bug)", commonLen)
		}
		if gotAesNi != wantVAES {
			t.Fatalf("len=%d: AES-NI dispatch %v != VAES dispatch %v", commonLen, gotAesNi, wantVAES)
		}
	}
}

// TestAreionSoEM512ChainAbsorbHot_AesNiDispatch — 512-bit counterpart.
func TestAreionSoEM512ChainAbsorbHot_AesNiDispatch(t *testing.T) {
	if !goaes.CPU.HasAESNI || !areionasm.HasVAESAVX512 {
		t.Skip("requires AES-NI and VAES + AVX-512 (to compare both arms)")
	}
	savedVAES := areionasm.HasVAESAVX512
	savedAesNi := areionasm.HasAESNIBatched
	t.Cleanup(func() {
		areionasm.HasVAESAVX512 = savedVAES
		areionasm.HasAESNIBatched = savedAesNi
	})

	for _, commonLen := range []int{13, 20, 36, 68} {
		var fixedKey [64]byte
		if _, err := rand.Read(fixedKey[:]); err != nil {
			t.Fatal(err)
		}
		var seeds [4][8]uint64
		var sb [256]byte
		if _, err := rand.Read(sb[:]); err != nil {
			t.Fatal(err)
		}
		for lane := 0; lane < 4; lane++ {
			for i := 0; i < 8; i++ {
				seeds[lane][i] = leU64(sb[lane*64+i*8:])
			}
		}
		var data [4][]byte
		for lane := 0; lane < 4; lane++ {
			data[lane] = make([]byte, commonLen)
			if _, err := rand.Read(data[lane]); err != nil {
				t.Fatal(err)
			}
		}

		areionasm.HasVAESAVX512 = true
		areionasm.HasAESNIBatched = false
		wantVAES, okV := areionSoEM512ChainAbsorbHot(&fixedKey, &seeds, &data, commonLen)
		if !okV {
			t.Fatalf("len=%d: VAES hot dispatch reported ok=false", commonLen)
		}

		areionasm.HasVAESAVX512 = false
		areionasm.HasAESNIBatched = true
		gotAesNi, okA := areionSoEM512ChainAbsorbHot(&fixedKey, &seeds, &data, commonLen)
		if !okA {
			t.Fatalf("len=%d: AES-NI hot dispatch reported ok=false (routing bug)", commonLen)
		}
		if gotAesNi != wantVAES {
			t.Fatalf("len=%d: AES-NI dispatch %v != VAES dispatch %v", commonLen, gotAesNi, wantVAES)
		}
	}
}

func leU64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
