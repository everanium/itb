package itb

import (
	"encoding/binary"
	"testing"

	"github.com/everanium/itb/internal/aesitbasm"
	"github.com/everanium/itb/internal/forcetier"
)

// interlock48_cascade_test.go — the cascade fill of an aesitb128
// lockSeed ([buildLockBatchPRF48_128Cascade]).
//
// Three properties are pinned on fixed keys and components:
//
//  1. Three-arm parity: fill / fillRanks (single-lane cascade),
//     fillRanksX4 (four-lane cascade) and fillRanksSuper (batch-16
//     kernel) agree with the pure-Go cascade
//     aesitbasm.ScalarFusedChain over the prepended lock components on
//     every group, with the fused hooks absent (sequential Hash /
//     BatchHash loops) and armed (FusedChain13x1 / FusedChain13x4 under
//     the hooks, exactly as hashes.AttachFused128 wires them) — the
//     shipped wiring, pinned directly.
//  2. Intentional break: the cascade fill differs from the single
//     derived-pair call the same seed makes without the batch-16 hook,
//     and the hook-absent seed produces that derived-pair fill — the
//     documented Low-Level hazard, and a guard against a silent revert
//     of the cascade selection.
//  3. Nonce binding: two interlock nonces give distinct fills on the
//     same group.

// cascadeLockSeed builds an aesitb128 lockSeed with the batch-16 hook
// and, when armed, the fused ChainHash hooks, dispatching through the
// same aesitbasm entries hashes.AttachFused128 /
// hashes.AttachInterlockBatch16 install.
func cascadeLockSeed(t *testing.T, key [16]byte, comps []uint64, armed bool) *Seed128 {
	t.Helper()
	h, bh, _ := MakeAESITB128Hash(key)
	seed, err := SeedFromComponents128(h, comps...)
	if err != nil {
		t.Fatal(err)
	}
	seed.BatchHash = bh
	if armed {
		seed.FusedChain = func(components []uint64, data []byte) (uint64, uint64, bool) {
			if len(data) != 13 {
				return 0, 0, false
			}
			var out [2]uint64
			aesitbasm.FusedChain13x1(&key, components, &data[0], &out)
			return out[0], out[1], true
		}
		seed.BatchFusedChain = func(components []uint64, data *[4][]byte) ([4][2]uint64, bool) {
			var out [4][2]uint64
			for i := range data {
				if len(data[i]) != 13 {
					return out, false
				}
			}
			ptrs := [4]*byte{&data[0][0], &data[1][0], &data[2][0], &data[3][0]}
			aesitbasm.FusedChain13x4(&key, components, &ptrs, &out)
			return out, true
		}
	}
	seed.SetInterlockBatch16(func(components []uint64, groupIdxBase uint64, out *[16][2]uint64) {
		aesitbasm.FusedChain13x16(&key, components, groupIdxBase, out)
	})
	return seed
}

var cascadeLockSeedKeys = [][16]byte{
	{},
	{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
	{0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98},
}

// cascadeLockSeedComponents covers the 512-, 1024- and 2048-bit key
// sizes (5 / 9 / 17 cascade rounds).
var cascadeLockSeedComponents = [][]uint64{
	{1, 2, 3, 4, 5, 6, 7, 8},
	{0x0102030405060708, 0x090a0b0c0d0e0f00, 0xFFFFFFFFFFFFFFFF, 0, 0x8000000000000000, 0x7FFFFFFFFFFFFFFF, 0xAAAAAAAAAAAAAAAA, 0x5555555555555555,
		0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0, 0x082EFA98EC4E6C89, 0x452821E638D01377, 0xBE5466CF34E90C6C, 0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917},
	func() []uint64 {
		c := make([]uint64, 32)
		for i := range c {
			c[i] = uint64(i+1) * 0x9E3779B97F4A7C15
		}
		return c
	}(),
}

// cascadeFillBlock returns the fill block of group g.
func cascadeFillBlock(g uint64) [13]byte {
	var buf [13]byte
	buf[0] = 0x03
	binary.LittleEndian.PutUint64(buf[1:9], g)
	return buf
}

// TestCascadeFillThreeArmParity pins every fill closure of the cascade
// builder to the pure-Go cascade over the prepended lock components,
// with the fused hooks absent and armed, under every batch-16 dispatch
// tier the host can execute.
func TestCascadeFillThreeArmParity(t *testing.T) {
	saved := readX16TierFlags()
	t.Cleanup(saved.apply)
	nonce := interlock48Nonce()
	for _, tier := range x16HostTiers() {
		tier := tier
		t.Run(tier.name, func(t *testing.T) {
			tier.flags.apply()
			for _, armed := range []bool{false, true} {
				for i, key := range cascadeLockSeedKeys {
					comps := cascadeLockSeedComponents[i]
					seed := cascadeLockSeed(t, key, comps, armed)
					bp := buildLockBatchPRF48_128(seed, nonce)
					if bp.fillRanksX4 == nil {
						t.Fatal("fillRanksX4 not armed")
					}
					if bp.fillRanksSuper == nil && !forcetier.InterlockPRFFillSeq() {
						t.Fatal("fillRanksSuper not armed")
					}
					lockLo, lockHi := seed.deriveInterLockSeed(nonce)
					lockComps := append([]uint64{lockLo, lockHi}, comps...)
					for _, base := range x16FillRanksBases {
						var want [16][2]uint64
						for j := 0; j < 16; j++ {
							buf := cascadeFillBlock(base + uint64(j))
							want[j][0], want[j][1] = aesitbasm.ScalarFusedChain(&key, lockComps, buf[:])
						}

						var buf [13]byte
						var seq [2]uint64
						var masksSeq [lockBatchFactor48Max][3]uint64
						var masksWant [lockBatchFactor48Max][3]uint64
						for j := 0; j < 16; j++ {
							g := base + uint64(j)
							bp.fillRanks(buf[:], g, seq[:])
							if seq != want[j] {
								t.Fatalf("armed=%v key %d base=%#x lane %d: fillRanks %x != cascade %x", armed, i, base, j, seq, want[j])
							}
							bp.fill(buf[:], g, &masksSeq)
							var prf [8]uint64
							prf[0], prf[1] = want[j][0], want[j][1]
							fillLockMasksTriple48(&prf, lockBatchFactor48_128, &masksWant)
							if masksSeq[0] != masksWant[0] {
								t.Fatalf("armed=%v key %d base=%#x lane %d: fill masks diverge from the cascade rank", armed, i, base, j)
							}
						}

						var scratch lockFillScratch48
						var x4 [8 * lockBatchFactor48Max]uint64
						for j := 0; j < 16; j += 4 {
							bp.fillRanksX4(&scratch, base+uint64(j), x4[2*j:])
						}
						for j := 0; j < 16; j++ {
							if x4[2*j] != want[j][0] || x4[2*j+1] != want[j][1] {
								t.Fatalf("armed=%v key %d base=%#x lane %d: fillRanksX4 != cascade", armed, i, base, j)
							}
						}

						if bp.fillRanksSuper != nil {
							var super [8 * lockBatchFactor48Max]uint64
							bp.fillRanksSuper(&scratch, base, super[0:32])
							for j := 0; j < 16; j++ {
								if super[2*j] != want[j][0] || super[2*j+1] != want[j][1] {
									t.Fatalf("armed=%v key %d base=%#x lane %d: fillRanksSuper != cascade", armed, i, base, j)
								}
							}
						}
					}
				}
			}
		})
	}
}

// TestCascadeFillDiffersFromDerivedPair is the intentional-break pin:
// with the batch-16 hook attached the fill is the cascade, not the
// single derived-pair call, and the same seed without the hook fills
// through the derived-pair call — the two wires differ on every group
// checked.
func TestCascadeFillDiffersFromDerivedPair(t *testing.T) {
	nonce := interlock48Nonce()
	for i, key := range cascadeLockSeedKeys {
		comps := cascadeLockSeedComponents[i]
		hooked := cascadeLockSeed(t, key, comps, true)
		plain := cascadeLockSeed(t, key, comps, true)
		plain.SetInterlockBatch16(nil)
		bpHooked := buildLockBatchPRF48_128(hooked, nonce)
		bpPlain := buildLockBatchPRF48_128(plain, nonce)
		if bpPlain.fillRanksSuper != nil {
			t.Fatalf("key %d: hook-absent seed armed fillRanksSuper", i)
		}
		lockLo, lockHi := hooked.deriveInterLockSeed(nonce)
		differ := 0
		for g := uint64(0); g < 64; g++ {
			buf := cascadeFillBlock(g)
			var cascade, derived [2]uint64
			bpHooked.fillRanks(buf[:], g, cascade[:])
			bpPlain.fillRanks(buf[:], g, derived[:])
			wantDerived := [2]uint64{}
			wantDerived[0], wantDerived[1] = hooked.Hash(buf[:], lockLo, lockHi)
			if derived != wantDerived {
				t.Fatalf("key %d group %d: hook-absent fill is not the derived-pair call", i, g)
			}
			if cascade != derived {
				differ++
			}
		}
		if differ != 64 {
			t.Fatalf("key %d: cascade fill equals the derived-pair fill on %d of 64 groups", i, 64-differ)
		}
	}
}

// TestCascadeFillNonceBinding pins the nonce binding of round 1: two
// interlock nonces over the same lockSeed give distinct fills on the
// same group.
func TestCascadeFillNonceBinding(t *testing.T) {
	nonceA := interlock48Nonce()
	nonceB := append([]byte(nil), nonceA...)
	nonceB[0] ^= 0x01
	for i, key := range cascadeLockSeedKeys {
		seed := cascadeLockSeed(t, key, cascadeLockSeedComponents[i], true)
		bpA := buildLockBatchPRF48_128(seed, nonceA)
		bpB := buildLockBatchPRF48_128(seed, nonceB)
		for g := uint64(0); g < 32; g++ {
			buf := cascadeFillBlock(g)
			var a, b [2]uint64
			bpA.fillRanks(buf[:], g, a[:])
			bpB.fillRanks(buf[:], g, b[:])
			if a == b {
				t.Fatalf("key %d group %d: fill identical under two interlock nonces", i, g)
			}
		}
	}
}
