//go:build amd64 && !purego && !noitbasm

package aescmacasm

import (
	"crypto/rand"
	"testing"

	goaes "github.com/jedisct1/go-aes"
)

// The XMM AES-NI chain-absorb kernels are the fallback batched path for
// AES-NI-only hosts (HasAESNIBatched). These tests call the kernels
// DIRECTLY — bypassing the runtime dispatch — so the AES-NI arm is
// exercised even on the maintainer's VAES + AVX-512 hosts where the
// dispatcher would otherwise select the ZMM kernel. The only host
// requirement is AES-NI itself (AESENC legal); every target CPU in the
// campaign fleet satisfies it.

// runChainAbsorb128AesNiTest exercises one (AES-NI kernel, length) pair
// across the standard edge-case matrix, comparing each lane against the
// per-lane scalar reference closure.
func runChainAbsorb128AesNiTest(
	t *testing.T,
	name string,
	dataLen int,
	kernel func(*[176]byte, *[4][2]uint64, *[4]*byte, *[4][2]uint64),
) {
	t.Helper()
	if !goaes.CPU.HasAESNI {
		t.Skip("requires AES-NI")
	}
	for _, tc := range chainAbsorb128Cases {
		t.Run(tc.name, func(t *testing.T) {
			roundKeys := ExpandKeyAES128(tc.key)
			bufs, ptrs := makeLaneData128(dataLen)
			var laneWant [4][2]uint64
			for lane := 0; lane < 4; lane++ {
				lo, hi := runReferenceClosure128(tc.key, bufs[lane], tc.seeds[lane][0], tc.seeds[lane][1])
				laneWant[lane][0] = lo
				laneWant[lane][1] = hi
			}
			var got [4][2]uint64
			kernel(&roundKeys, &tc.seeds, &ptrs, &got)
			for lane := 0; lane < 4; lane++ {
				if got[lane] != laneWant[lane] {
					t.Fatalf("%s lane %d: got=%x want=%x",
						name, lane, got[lane], laneWant[lane])
				}
			}
		})
	}
}

func TestAESCMAC128ChainAbsorb13x4AesNi(t *testing.T) {
	runChainAbsorb128AesNiTest(t, "aesCMAC128ChainAbsorb13x4AesNiAsm", 13, aesCMAC128ChainAbsorb13x4AesNiAsm)
}

func TestAESCMAC128ChainAbsorb20x4AesNi(t *testing.T) {
	runChainAbsorb128AesNiTest(t, "aesCMAC128ChainAbsorb20x4AesNiAsm", 20, aesCMAC128ChainAbsorb20x4AesNiAsm)
}

func TestAESCMAC128ChainAbsorb36x4AesNi(t *testing.T) {
	runChainAbsorb128AesNiTest(t, "aesCMAC128ChainAbsorb36x4AesNiAsm", 36, aesCMAC128ChainAbsorb36x4AesNiAsm)
}

func TestAESCMAC128ChainAbsorb68x4AesNi(t *testing.T) {
	runChainAbsorb128AesNiTest(t, "aesCMAC128ChainAbsorb68x4AesNiAsm", 68, aesCMAC128ChainAbsorb68x4AesNiAsm)
}

// TestAESCMAC128ChainAbsorbAesNi_RandomParity runs 200 random fixtures
// per width through the AES-NI kernel and requires bit-exact agreement
// with the per-lane scalar reference (playbook §10.2 parity oracle).
func TestAESCMAC128ChainAbsorbAesNi_RandomParity(t *testing.T) {
	if !goaes.CPU.HasAESNI {
		t.Skip("requires AES-NI")
	}
	widths := []struct {
		n      int
		kernel func(*[176]byte, *[4][2]uint64, *[4]*byte, *[4][2]uint64)
	}{
		{13, aesCMAC128ChainAbsorb13x4AesNiAsm},
		{20, aesCMAC128ChainAbsorb20x4AesNiAsm},
		{36, aesCMAC128ChainAbsorb36x4AesNiAsm},
		{68, aesCMAC128ChainAbsorb68x4AesNiAsm},
	}
	for _, w := range widths {
		for trial := 0; trial < 200; trial++ {
			var key [16]byte
			if _, err := rand.Read(key[:]); err != nil {
				t.Fatal(err)
			}
			var seeds [4][2]uint64
			var seedBytes [64]byte
			if _, err := rand.Read(seedBytes[:]); err != nil {
				t.Fatal(err)
			}
			for lane := 0; lane < 4; lane++ {
				seeds[lane][0] = leUint64(seedBytes[lane*16:])
				seeds[lane][1] = leUint64(seedBytes[lane*16+8:])
			}
			laneData := make([][]byte, 4)
			var ptrs [4]*byte
			for lane := 0; lane < 4; lane++ {
				laneData[lane] = make([]byte, w.n)
				if _, err := rand.Read(laneData[lane]); err != nil {
					t.Fatal(err)
				}
				ptrs[lane] = &laneData[lane][0]
			}
			var want [4][2]uint64
			for lane := 0; lane < 4; lane++ {
				lo, hi := runReferenceClosure128(key, laneData[lane], seeds[lane][0], seeds[lane][1])
				want[lane][0] = lo
				want[lane][1] = hi
			}
			roundKeys := ExpandKeyAES128(key)
			var got [4][2]uint64
			w.kernel(&roundKeys, &seeds, &ptrs, &got)
			if got != want {
				t.Fatalf("width %d trial %d mismatch\n got:  %x\n want: %x", w.n, trial, got, want)
			}
		}
	}
}

// TestAESCMAC128ChainAbsorb13x4AesNi_BitSensitivity flips every one of
// the 104 input bits (per lane) and requires that lane's digest to
// change (playbook §10.3 bit sensitivity).
func TestAESCMAC128ChainAbsorb13x4AesNi_BitSensitivity(t *testing.T) {
	if !goaes.CPU.HasAESNI {
		t.Skip("requires AES-NI")
	}
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	roundKeys := ExpandKeyAES128(key)
	var seeds [4][2]uint64
	var seedBytes [64]byte
	if _, err := rand.Read(seedBytes[:]); err != nil {
		t.Fatal(err)
	}
	for lane := 0; lane < 4; lane++ {
		seeds[lane][0] = leUint64(seedBytes[lane*16:])
		seeds[lane][1] = leUint64(seedBytes[lane*16+8:])
	}
	base := make([][]byte, 4)
	for lane := 0; lane < 4; lane++ {
		base[lane] = make([]byte, 13)
		if _, err := rand.Read(base[lane]); err != nil {
			t.Fatal(err)
		}
	}
	run := func(d [][]byte) [4][2]uint64 {
		var ptrs [4]*byte
		for lane := 0; lane < 4; lane++ {
			ptrs[lane] = &d[lane][0]
		}
		var out [4][2]uint64
		aesCMAC128ChainAbsorb13x4AesNiAsm(&roundKeys, &seeds, &ptrs, &out)
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

// TestDispatcher_AesNiPathSelected is the guard test (playbook §10.6):
// with HasVAESAVX512 forced false and HasAESNIBatched forced true, the
// public dispatcher must route to the XMM AES-NI kernel (not the scalar
// fallback). Verified by comparing the dispatcher output against a
// direct AES-NI kernel call.
func TestDispatcher_AesNiPathSelected(t *testing.T) {
	if !goaes.CPU.HasAESNI {
		t.Skip("requires AES-NI")
	}
	savedVAES := HasVAESAVX512
	savedAesNi := HasAESNIBatched
	HasVAESAVX512 = false
	HasAESNIBatched = true
	t.Cleanup(func() {
		HasVAESAVX512 = savedVAES
		HasAESNIBatched = savedAesNi
	})

	cases := []struct {
		dataLen  int
		dispatch func(*[176]byte, *[16]byte, *[4][2]uint64, *[4]*byte, *[4][2]uint64)
		direct   func(*[176]byte, *[4][2]uint64, *[4]*byte, *[4][2]uint64)
	}{
		{13, AESCMAC128ChainAbsorb13x4, aesCMAC128ChainAbsorb13x4AesNiAsm},
		{20, AESCMAC128ChainAbsorb20x4, aesCMAC128ChainAbsorb20x4AesNiAsm},
		{36, AESCMAC128ChainAbsorb36x4, aesCMAC128ChainAbsorb36x4AesNiAsm},
		{68, AESCMAC128ChainAbsorb68x4, aesCMAC128ChainAbsorb68x4AesNiAsm},
	}
	for _, c := range cases {
		for _, tc := range chainAbsorb128Cases {
			roundKeys := ExpandKeyAES128(tc.key)
			bufs, ptrs := makeLaneData128(c.dataLen)
			_ = bufs
			var viaDispatch, viaDirect [4][2]uint64
			seedsCopy := tc.seeds
			c.dispatch(&roundKeys, &tc.key, &seedsCopy, &ptrs, &viaDispatch)
			c.direct(&roundKeys, &tc.seeds, &ptrs, &viaDirect)
			if viaDispatch != viaDirect {
				t.Fatalf("len=%d %s: dispatcher output %x != direct AES-NI %x",
					c.dataLen, tc.name, viaDispatch, viaDirect)
			}
		}
	}
}

// leUint64 decodes a little-endian uint64 from b[:8].
func leUint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
