//go:build arm64 && !purego && !noitbasm

package aesitbasm

import (
	"bytes"
	"testing"

	aes "github.com/jedisct1/go-aes"

	"github.com/everanium/itb/internal/forcetier"
)

// TestNoiseFillNeonParity drives the NEON kernel directly at block
// counts from one group up to several groups, from every start that
// keeps the run clear of the 64-bit wrap, at every dst alignment
// offset 0 .. 15, and pins each output to the pure-Go sponge.
func TestNoiseFillNeonParity(t *testing.T) {
	if !aes.CPU.HasARMCrypto {
		t.Skip("requires the ARM crypto extension")
	}
	for trial := 0; trial < 200; trial++ {
		key, nonce := randomNoiseKeyNonce(t)
		s := NewNoiseSchedule(key, nonce)
		nblk := 8 * (1 + trial%5)
		c := noiseStarts[trial%len(noiseStarts)]
		lo, hi := c[0], c[1]
		if room := ^lo; uint64(nblk-1) > room {
			lo = ^uint64(0) - uint64(nblk)
		}
		want := make([]byte, 16*nblk)
		noiseRefFill(key, nonce, want, lo, hi)
		off := trial % 16
		got := make([]byte, 16*nblk+32)
		noiseFillX8NeonAsm(&s, &got[off], nblk, lo, hi)
		if !bytes.Equal(got[off:off+16*nblk], want) {
			t.Fatalf("trial %d nblk=%d off=%d: kernel differs from sponge", trial, nblk, off)
		}
		for i := 16*nblk + off; i < len(got); i++ {
			if got[i] != 0 {
				t.Fatalf("trial %d: kernel wrote past nblk blocks at %d", trial, i)
			}
		}
	}
}

// TestNoiseFillTierSelectedOnCapableHostARM64 guards against a silent
// fall-through to the Go path on a crypto-extension host.
func TestNoiseFillTierSelectedOnCapableHostARM64(t *testing.T) {
	if forcetier.HashTier() != "" {
		t.Skip("ITB_FORCE_HASH_TIER set")
	}
	if !aes.CPU.HasARMCrypto {
		t.Skip("host has no ARM crypto extension")
	}
	if gran := noiseFillGran(); gran == 0 {
		t.Fatal("crypto-extension host selected no noise-filler kernel")
	}
}

// TestNoiseFillForcedTierParityARM64 runs the full NoiseFill driver
// with the NEON flag armed and disarmed, so the carry split and the
// tail hand-off are covered on the kernel and on the Go path, then
// restores the flag.
func TestNoiseFillForcedTierParityARM64(t *testing.T) {
	saved := FusedHasARMAES
	defer func() { FusedHasARMAES = saved }()
	for _, armed := range []bool{true, false} {
		if armed && !aes.CPU.HasARMCrypto {
			continue
		}
		FusedHasARMAES = armed
		for _, n := range noiseLengths {
			for _, st := range noiseStarts {
				key, nonce := randomNoiseKeyNonce(t)
				s := NewNoiseSchedule(key, nonce)
				want := make([]byte, n)
				noiseRefFill(key, nonce, want, st[0], st[1])
				got := make([]byte, n)
				NoiseFill(&s, got, st[0], st[1])
				if !bytes.Equal(got, want) {
					t.Fatalf("neon=%v n=%d ctr=%v: fill differs from sponge", armed, n, st)
				}
			}
		}
	}
}
