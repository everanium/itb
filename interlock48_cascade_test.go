package itb

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync/atomic"
	"testing"

	"github.com/everanium/itb/internal/aesitbasm"
	"github.com/everanium/itb/internal/forcetier"
)

// The Interlocked Barrier cascade fill,
// one section per subject: the cascade fill of an aesitb128 lockSeed
// ([buildLockBatchPRF48_128]) through the shipped aesitbasm kernels and
// its golden rank pairs; the primitive-agnostic universal cascade fill
// at every hash width; and the batch-32 rung of the fill ladder.
//
// On the aesitb128 lockSeed, three properties are pinned on fixed keys
// and components:
//
//  1. Three-arm parity: fill / fillRanks (single-lane cascade),
//     fillRanksX4 (four-lane cascade) and fillRanksSuper (batch-16
//     kernel) agree with the pure-Go cascade
//     aesitbasm.ScalarFusedChain over the prepended lock components on
//     every group, with the fused hooks absent (sequential Hash /
//     BatchHash loops) and armed (FusedChain13x1 / FusedChain13x4 under
//     the hooks, exactly as the hashes package's constructors wire them) — the
//     shipped wiring, pinned directly.
//  2. Hook independence and the cascade itself: the seed with every
//     kernel hook and the same seed with none produce the same fill,
//     and that fill differs from the single derived-pair call — a guard
//     against a silent revert to a one-round fill.
//  3. Nonce binding: two interlock nonces give distinct fills on the
//     same group.

// cascadeLockSeed builds an aesitb128 lockSeed with the batch-16 hook
// and, when armed, the fused ChainHash hooks, dispatching through the
// same aesitbasm entries the hashes package's constructors install.
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
	seed.SetInterlockBatch16(func(components []uint64, groupIdxBase uint64, v uint32, out *[16][2]uint64) {
		aesitbasm.FusedChain13x16(&key, components, groupIdxBase, v, out)
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

// cascadeFillBlock returns the fill block [0x03 | LE64(g) | LE32(v)] of
// group g under the interlock-nonce fold v.
func cascadeFillBlock(g uint64, v uint32) [13]byte {
	var buf [13]byte
	buf[0] = 0x03
	binary.LittleEndian.PutUint64(buf[1:9], g)
	binary.LittleEndian.PutUint32(buf[9:13], v)
	return buf
}

// testNonceFold is the test-side reference of the interlock-nonce fold,
// written as the XOR of the nonce's little-endian 32-bit words so that
// it is an independent formulation of the production bytewise fold.
func testNonceFold(nonce []byte) uint32 {
	var v uint32
	for i := 0; i+4 <= len(nonce); i += 4 {
		v ^= binary.LittleEndian.Uint32(nonce[i:])
	}
	return v
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
					if bp.fillRanksX4 == nil && !forcetier.InterlockPRFFillSeq() && !forcetier.InterlockPRFFillX1() {
						t.Fatal("fillRanksX4 not armed")
					}
					if bp.fillRanksSuper == nil && !fillBatch16Disarmed() {
						t.Fatal("fillRanksSuper not armed")
					}
					lockLo, lockHi := seed.deriveInterLockSeed(nonce)
					lockComps := append([]uint64{lockLo, lockHi}, comps...)
					for _, base := range x16FillRanksBases {
						var want [16][2]uint64
						for j := 0; j < 16; j++ {
							buf := cascadeFillBlock(base+uint64(j), testNonceFold(nonce))
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
						if bp.fillRanksX4 != nil {
							var x4 [8 * lockBatchFactor48Max]uint64
							for j := 0; j < 16; j += 4 {
								bp.fillRanksX4(&scratch, base+uint64(j), x4[2*j:])
							}
							for j := 0; j < 16; j++ {
								if x4[2*j] != want[j][0] || x4[2*j+1] != want[j][1] {
									t.Fatalf("armed=%v key %d base=%#x lane %d: fillRanksX4 != cascade", armed, i, base, j)
								}
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

// TestCascadeFillHookIndependence pins that the aesitb128 kernel hooks
// never change the wire: the seed carrying the fused and batch-16 hooks
// and the same seed with none of them produce the same fill on every
// group, and that fill is the cascade, not the single derived-pair call
// Hash(block, lockLo, lockHi).
func TestCascadeFillHookIndependence(t *testing.T) {
	nonce := interlock48Nonce()
	for i, key := range cascadeLockSeedKeys {
		comps := cascadeLockSeedComponents[i]
		hooked := cascadeLockSeed(t, key, comps, true)
		plain := cascadeLockSeed(t, key, comps, false)
		plain.SetInterlockBatch16(nil)
		bpHooked := buildLockBatchPRF48_128(hooked, nonce)
		bpPlain := buildLockBatchPRF48_128(plain, nonce)
		if bpPlain.fillRanksSuper != nil {
			t.Fatalf("key %d: hook-free seed armed fillRanksSuper", i)
		}
		lockLo, lockHi := hooked.deriveInterLockSeed(nonce)
		for g := uint64(0); g < 64; g++ {
			buf := cascadeFillBlock(g, testNonceFold(nonce))
			var a, b, derived [2]uint64
			bpHooked.fillRanks(buf[:], g, a[:])
			bpPlain.fillRanks(buf[:], g, b[:])
			if a != b {
				t.Fatalf("key %d group %d: hooked and hook-free fills differ", i, g)
			}
			derived[0], derived[1] = hooked.Hash(buf[:], lockLo, lockHi)
			if a == derived {
				t.Fatalf("key %d group %d: fill equals the single derived-pair call", i, g)
			}
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
			buf := cascadeFillBlock(g, testNonceFold(nonceA)) // scratch: each closure rewrites all 13 bytes
			var a, b [2]uint64
			bpA.fillRanks(buf[:], g, a[:])
			bpB.fillRanks(buf[:], g, b[:])
			if a == b {
				t.Fatalf("key %d group %d: fill identical under two interlock nonces", i, g)
			}
		}
	}
}

// TestCascadeFill128DisarmKnobs pins the fill-ladder knobs at width 128,
// where the batch-16 hook is the widest rung: _X16 leaves it armed, _X4
// leaves the four-lane arm as the top rung, _X1 and _SEQ disarm every
// batched rung, and with no knob set both rungs are armed.
func TestCascadeFill128DisarmKnobs(t *testing.T) {
	knobs := []string{"ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", "ITB_FORCE_INTERLOCK_PRF_FILL_X1", "ITB_FORCE_INTERLOCK_PRF_FILL_X4", "ITB_FORCE_INTERLOCK_PRF_FILL_X16"}
	key, comps := cascadeLockSeedKeys[0], cascadeLockSeedComponents[0]
	nonce := interlock48Nonce()
	check := func(set string, x4, b16 bool) {
		t.Helper()
		for _, k := range knobs {
			if k == set {
				t.Setenv(k, "1")
			} else {
				t.Setenv(k, "")
			}
		}
		seed := cascadeLockSeed(t, key, comps, true)
		seed.SetInterlockBatch16(func(components []uint64, groupIdxBase uint64, v uint32, out *[16][2]uint64) {
			aesitbasm.FusedChain13x16(&key, components, groupIdxBase, v, out)
		})
		bp := buildLockBatchPRF48_128(seed, nonce)
		if (bp.fillRanksX4 != nil) != x4 || (bp.fillRanksSuper != nil) != b16 {
			t.Fatalf("%s: four-lane armed=%v batch-16 armed=%v, want %v/%v", set, bp.fillRanksX4 != nil, bp.fillRanksSuper != nil, x4, b16)
		}
	}
	check("ITB_FORCE_INTERLOCK_PRF_FILL_X16", true, true)
	check("ITB_FORCE_INTERLOCK_PRF_FILL_X4", true, false)
	check("ITB_FORCE_INTERLOCK_PRF_FILL_X1", false, false)
	check("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", false, false)
	check("", true, true)
}

// ============================================================================
// Golden rank pairs of the aesitb128 cascade fill.
// ============================================================================
//
// The values pin the wire itself (prepend order of the
// lock components, the 0x04 setup and 0x03 hot-loop tags, the cascade
// depth) on fixed key, components and interlock nonce at every shipped
// key size, independently of the kernel ≡ reference parity the other
// tests provide: a kernel and its reference drifting together would
// pass parity and fail here. Computed through the pure-Go cascade and
// matched byte for byte by an independent implementation of the
// construction written from its specification.

var cascadeGoldenNonce = func() []byte {
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(0xA5 ^ i*29)
	}
	return nonce
}()

var cascadeGoldenGroups = []uint64{0, 1, 15, 16, 0xFF, 0x0100000000000000, 0xFFFFFFFFFFFFFFFF}

// cascadeGoldenWant[i][j] is the (lo, hi) rank pair of group
// cascadeGoldenGroups[j] under cascadeLockSeedKeys[i] /
// cascadeLockSeedComponents[i] (512 / 1024 / 2048-bit) and
// cascadeGoldenNonce.
var cascadeGoldenWant = [3][7][2]uint64{
	{
		{0xdd1e78ff0ac89daf, 0xc17e89b94dd0429a},
		{0x6cfe4d112053795a, 0x5bae2ba0254fd51e},
		{0xb054a0c7575a8a38, 0x7b372f84b96a4497},
		{0xda02edc4388eb2a8, 0xcbe6864bfaeb3804},
		{0xfc26133385410176, 0xae92567b15ef35d2},
		{0xe4d78413a3a8ee34, 0x396a670dbb7ab1cb},
		{0xd9028d63c216c54b, 0x26635b791d947b78},
	},
	{
		{0xc7c891fc7f11cda1, 0xef57632440eeea26},
		{0xded82370595d5a0d, 0xb51c3cb2aa5b214d},
		{0x3bf5b89a7d2ab7c9, 0xcb461e0892d6f330},
		{0x8ab0b3aa57d2ea62, 0xdd297d627be6db68},
		{0x07856022d62c0646, 0x1e20a468ad58c766},
		{0xce71e98aac36cca3, 0x8e3dce4c4fd6d86b},
		{0xe4f592079c4782d1, 0x1ba4ac1a45e06210},
	},
	{
		{0xb009c0be4b11adf6, 0x5e2d53931c717965},
		{0xc2b9a85a96f010bf, 0x3c227e28e288ba31},
		{0x280c31b27708d55a, 0x36564402ae0e0210},
		{0x06e44540a727085c, 0xf20ff3bf7bc3c8b2},
		{0x1a78f2e65d33fb7c, 0x59570b15bf419f83},
		{0x308426cb5953948d, 0x6a2bd2f26b8cce75},
		{0x9f551c85ac131ebf, 0xf787406c9dcd0b7b},
	},
}

// TestCascadeFillGolden pins the cascade fill of every shipped key size
// to the golden rank pairs through the shipped builder — fillRanks (the
// single-lane cascade) and, when armed, fillRanksSuper (the batch-16
// kernel) on the batch holding each group.
func TestCascadeFillGolden(t *testing.T) {
	for i, key := range cascadeLockSeedKeys {
		seed := cascadeLockSeed(t, key, cascadeLockSeedComponents[i], true)
		bp := buildLockBatchPRF48_128(seed, cascadeGoldenNonce)
		for j, g := range cascadeGoldenGroups {
			buf := cascadeFillBlock(g, testNonceFold(cascadeGoldenNonce))
			var got [2]uint64
			bp.fillRanks(buf[:], g, got[:])
			if got != cascadeGoldenWant[i][j] {
				t.Errorf("key %d group %#x: fillRanks {%#016x, %#016x}, golden {%#016x, %#016x}",
					i, g, got[0], got[1], cascadeGoldenWant[i][j][0], cascadeGoldenWant[i][j][1])
			}
			if bp.fillRanksSuper != nil {
				base := g &^ 0xF
				var scratch lockFillScratch48
				var super [8 * lockBatchFactor48Max]uint64
				bp.fillRanksSuper(&scratch, base, super[0:32])
				lane := int(g - base)
				if super[2*lane] != cascadeGoldenWant[i][j][0] || super[2*lane+1] != cascadeGoldenWant[i][j][1] {
					t.Errorf("key %d group %#x: fillRanksSuper lane %d {%#016x, %#016x}, golden {%#016x, %#016x}",
						i, g, lane, super[2*lane], super[2*lane+1], cascadeGoldenWant[i][j][0], cascadeGoldenWant[i][j][1])
				}
			}
		}
	}
}

// ============================================================================
// The universal Interlocked Barrier cascade fill at every hash width.
// ============================================================================
//
// The builders under test are [buildLockBatchPRF48_128] /
// [buildLockBatchPRF48_256] / [buildLockBatchPRF48_512] on
// primitive-agnostic test hashes (SipHash-2-4 wrapped at 128 / 256 / 512
// bits), table-driven over the three widths.
//
// Properties pinned on fixed components and a fixed interlock nonce:
//
//  1. Reference parity: fill / fillRanks (single-lane cascade),
//     fillRanksX4 (four-lane cascade) and fillRanksSuper (batch-16 hook)
//     agree with an explicit reference cascade written directly over the
//     raw hash function — setup key K = cascade(0x04 ‖ nonce) over the
//     components, hot-loop rank words = cascade(0x03 ‖ LE64(g) ‖ 0⁴) over
//     [K ‖ components] — with the optional hooks absent and present.
//  2. Hook independence: a seed carrying FusedChain / BatchFusedChain /
//     InterlockFillX16 hooks and the same seed without them produce the
//     same rank words on every group (the hooks are consulted, counted,
//     and must not change the wire).
//  3. Not the derived-key call: the cascade differs from the single
//     Hash(block, K) call on every group — a guard against a silent
//     revert to a one-round fill.
//  4. Nonce binding: two interlock nonces give distinct fills on the same
//     group.
//  5. Golden pins: SHA-256 digests of the rank words of fixed groups at
//     every shipped key size, pinning the wire of the universal fill
//     independently of any kernel.
//  6. Wide-factor batch-16 wiring: the worker split with fillRanksSuper
//     armed (16 chunks = 8 groups at factor 2, 4 groups at factor 4)
//     produces lane bytes bit-identical to the same closure with it
//     disarmed, and the armed / disarmed encoders and decoders round-trip
//     each other's lanes at sizes straddling the 16-chunk batch.

// cascadeWideCase adapts one hash width to the table-driven tests.
type cascadeWideCase struct {
	label  string
	factor int
	// words is the rank-word count one group yields (2 * factor).
	words int
	// build returns the fill builder over comps and nonce; hooked
	// attaches synthetic FusedChain / BatchFusedChain / InterlockFillX16
	// hooks that evaluate the reference cascade and count their calls.
	build func(t *testing.T, comps []uint64, nonce []byte, hooked bool, calls *atomic.Int64) lockBatchPRF48
	// ref returns the reference rank words of group g.
	ref func(comps []uint64, nonce []byte, g uint64) []uint64
	// derived returns the single derived-key call Hash(block(g), K).
	derived func(comps []uint64, nonce []byte, g uint64) []uint64
}

// Reference cascades written directly over the raw test hashes.

func refCascade128(comps []uint64, buf []byte) (uint64, uint64) {
	lo, hi := sipHash128(buf, comps[0], comps[1])
	for i := 2; i < len(comps); i += 2 {
		lo, hi = sipHash128(buf, comps[i]^lo, comps[i+1]^hi)
	}
	return lo, hi
}

func refCascade256(comps []uint64, buf []byte) [4]uint64 {
	var seed [4]uint64
	copy(seed[:], comps[:4])
	h := testHash256(buf, seed)
	for i := 4; i < len(comps); i += 4 {
		for j := 0; j < 4; j++ {
			seed[j] = comps[i+j] ^ h[j]
		}
		h = testHash256(buf, seed)
	}
	return h
}

func refCascade512(comps []uint64, buf []byte) [8]uint64 {
	var seed [8]uint64
	copy(seed[:], comps[:8])
	h := testHash512(buf, seed)
	for i := 8; i < len(comps); i += 8 {
		for j := 0; j < 8; j++ {
			seed[j] = comps[i+j] ^ h[j]
		}
		h = testHash512(buf, seed)
	}
	return h
}

func refSetupBlock(nonce []byte) []byte {
	return append([]byte{0x04}, nonce...)
}

func refLockComps128(comps []uint64, nonce []byte) []uint64 {
	lo, hi := refCascade128(comps, refSetupBlock(nonce))
	return append([]uint64{lo, hi}, comps...)
}

func refLockComps256(comps []uint64, nonce []byte) []uint64 {
	k := refCascade256(comps, refSetupBlock(nonce))
	return append(k[:], comps...)
}

func refLockComps512(comps []uint64, nonce []byte) []uint64 {
	k := refCascade512(comps, refSetupBlock(nonce))
	return append(k[:], comps...)
}

func synthBatch256(h HashFunc256) BatchHashFunc256 {
	return func(data *[4][]byte, seeds [4][4]uint64) [4][4]uint64 {
		var out [4][4]uint64
		for lane := 0; lane < 4; lane++ {
			out[lane] = h(data[lane], seeds[lane])
		}
		return out
	}
}

func synthBatch512(h HashFunc512) BatchHashFunc512 {
	return func(data *[4][]byte, seeds [4][8]uint64) [4][8]uint64 {
		var out [4][8]uint64
		for lane := 0; lane < 4; lane++ {
			out[lane] = h(data[lane], seeds[lane])
		}
		return out
	}
}

func cascadeWideCases() []cascadeWideCase {
	return []cascadeWideCase{
		{
			label: "128", factor: 1, words: 2,
			build: func(t *testing.T, comps []uint64, nonce []byte, hooked bool, calls *atomic.Int64) lockBatchPRF48 {
				seed, err := SeedFromComponents128(sipHash128, comps...)
				if err != nil {
					t.Fatal(err)
				}
				seed.BatchHash = synthBatch128(sipHash128)
				if hooked {
					seed.FusedChain = func(c []uint64, data []byte) (uint64, uint64, bool) {
						calls.Add(1)
						lo, hi := refCascade128(c, data)
						return lo, hi, true
					}
					seed.BatchFusedChain = func(c []uint64, data *[4][]byte) ([4][2]uint64, bool) {
						calls.Add(1)
						var out [4][2]uint64
						for l := range data {
							out[l][0], out[l][1] = refCascade128(c, data[l])
						}
						return out, true
					}
					seed.SetInterlockBatch16(func(c []uint64, base uint64, v uint32, out *[16][2]uint64) {
						calls.Add(1)
						for i := range out {
							b := cascadeFillBlock(base+uint64(i), v)
							out[i][0], out[i][1] = refCascade128(c, b[:])
						}
					})
				}
				return buildLockBatchPRF48_128(seed, nonce)
			},
			ref: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g, testNonceFold(nonce))
				lo, hi := refCascade128(refLockComps128(comps, nonce), b[:])
				return []uint64{lo, hi}
			},
			derived: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g, testNonceFold(nonce))
				k := refLockComps128(comps, nonce)
				lo, hi := sipHash128(b[:], k[0], k[1])
				return []uint64{lo, hi}
			},
		},
		{
			label: "256", factor: 2, words: 4,
			build: func(t *testing.T, comps []uint64, nonce []byte, hooked bool, calls *atomic.Int64) lockBatchPRF48 {
				seed, err := SeedFromComponents256(testHash256, comps...)
				if err != nil {
					t.Fatal(err)
				}
				seed.BatchHash = synthBatch256(testHash256)
				if hooked {
					seed.FusedChain = func(c []uint64, data []byte) ([4]uint64, bool) {
						calls.Add(1)
						return refCascade256(c, data), true
					}
					seed.BatchFusedChain = func(c []uint64, data *[4][]byte) ([4][4]uint64, bool) {
						calls.Add(1)
						var out [4][4]uint64
						for l := range data {
							out[l] = refCascade256(c, data[l])
						}
						return out, true
					}
					seed.SetInterlockBatch16(func(c []uint64, base uint64, v uint32, out *[8][4]uint64) {
						calls.Add(1)
						for i := range out {
							b := cascadeFillBlock(base+uint64(i), v)
							out[i] = refCascade256(c, b[:])
						}
					})
				}
				return buildLockBatchPRF48_256(seed, nonce)
			},
			ref: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g, testNonceFold(nonce))
				out := refCascade256(refLockComps256(comps, nonce), b[:])
				return out[:]
			},
			derived: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g, testNonceFold(nonce))
				k := refLockComps256(comps, nonce)
				var seed [4]uint64
				copy(seed[:], k[:4])
				out := testHash256(b[:], seed)
				return out[:]
			},
		},
		{
			label: "512", factor: 4, words: 8,
			build: func(t *testing.T, comps []uint64, nonce []byte, hooked bool, calls *atomic.Int64) lockBatchPRF48 {
				seed, err := SeedFromComponents512(testHash512, comps...)
				if err != nil {
					t.Fatal(err)
				}
				seed.BatchHash = synthBatch512(testHash512)
				if hooked {
					seed.FusedChain = func(c []uint64, data []byte) ([8]uint64, bool) {
						calls.Add(1)
						return refCascade512(c, data), true
					}
					seed.BatchFusedChain = func(c []uint64, data *[4][]byte) ([4][8]uint64, bool) {
						calls.Add(1)
						var out [4][8]uint64
						for l := range data {
							out[l] = refCascade512(c, data[l])
						}
						return out, true
					}
					seed.SetInterlockBatch16(func(c []uint64, base uint64, v uint32, out *[4][8]uint64) {
						calls.Add(1)
						for i := range out {
							b := cascadeFillBlock(base+uint64(i), v)
							out[i] = refCascade512(c, b[:])
						}
					})
				}
				return buildLockBatchPRF48_512(seed, nonce)
			},
			ref: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g, testNonceFold(nonce))
				out := refCascade512(refLockComps512(comps, nonce), b[:])
				return out[:]
			},
			derived: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g, testNonceFold(nonce))
				k := refLockComps512(comps, nonce)
				var seed [8]uint64
				copy(seed[:], k[:8])
				out := testHash512(b[:], seed)
				return out[:]
			},
		},
	}
}

// cascadeWideGroups are the group indices the reference and golden
// layers check: small indices, the batch-16 boundary, byte carries and
// the top of the uint64 range.
var cascadeWideGroups = []uint64{0, 1, 15, 16, 17, 0xFF, 0x100, 0x0100000000000000, 0xFFFFFFFFFFFFFFF0, 0xFFFFFFFFFFFFFFFF}

// wordsEqual compares two rank-word slices.
func wordsEqual(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestCascadeFillWideReferenceParity is the reference layer at every
// width, with the hooks absent and present: every fill closure of the
// builder must reproduce the explicit reference cascade on every group,
// and the hooked build must actually route through the hooks.
func TestCascadeFillWideReferenceParity(t *testing.T) {
	if fillBatch16Disarmed() {
		t.Skip("a fill-ladder knob disarms the batch-16 hooks")
	}
	nonce := interlock48Nonce()
	for _, wc := range cascadeWideCases() {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			for ci, comps := range cascadeLockSeedComponents {
				for _, hooked := range []bool{false, true} {
					var calls atomic.Int64
					bp := wc.build(t, comps, nonce, hooked, &calls)
					if bp.factor != wc.factor {
						t.Fatalf("factor %d, want %d", bp.factor, wc.factor)
					}
					if bp.fillRanksX4 == nil {
						t.Fatal("fillRanksX4 not armed")
					}
					if (bp.fillRanksSuper != nil) != hooked {
						t.Fatalf("hooked=%v: fillRanksSuper armed=%v", hooked, bp.fillRanksSuper != nil)
					}
					superGroups := superGroups48 / wc.factor
					for _, base := range cascadeWideGroups {
						want := make([][]uint64, superGroups)
						for j := range want {
							want[j] = wc.ref(comps, nonce, base+uint64(j))
						}

						var buf [13]byte
						prf := make([]uint64, 8*lockBatchFactor48Max)
						var masks, masksWant [lockBatchFactor48Max][3]uint64
						for j := 0; j < superGroups; j++ {
							g := base + uint64(j)
							bp.fillRanks(buf[:], g, prf)
							if !wordsEqual(prf[:wc.words], want[j]) {
								t.Fatalf("comps %d hooked=%v base=%#x lane %d: fillRanks %x != reference %x", ci, hooked, base, j, prf[:wc.words], want[j])
							}
							bp.fill(buf[:], g, &masks)
							var p8 [8]uint64
							copy(p8[:], want[j])
							fillLockMasksTriple48(&p8, wc.factor, &masksWant)
							for c := 0; c < wc.factor; c++ {
								if masks[c] != masksWant[c] {
									t.Fatalf("comps %d hooked=%v base=%#x lane %d chunk %d: fill masks diverge from the reference rank", ci, hooked, base, j, c)
								}
							}
						}

						var scratch lockFillScratch48
						x4 := make([]uint64, 8*lockBatchFactor48Max)
						for j := 0; j+4 <= superGroups || j == 0; j += 4 {
							bp.fillRanksX4(&scratch, base+uint64(j), x4[j*wc.words:])
							for l := 0; l < 4 && j+l < superGroups; l++ {
								got := x4[(j+l)*wc.words : (j+l+1)*wc.words]
								if !wordsEqual(got, want[j+l]) {
									t.Fatalf("comps %d hooked=%v base=%#x lane %d: fillRanksX4 != reference", ci, hooked, base, j+l)
								}
							}
							if superGroups < 4 {
								break
							}
						}

						if bp.fillRanksSuper != nil {
							super := make([]uint64, 8*lockBatchFactor48Max)
							bp.fillRanksSuper(&scratch, base, super[0:2*superGroups48])
							for j := 0; j < superGroups; j++ {
								got := super[j*wc.words : (j+1)*wc.words]
								if !wordsEqual(got, want[j]) {
									t.Fatalf("comps %d hooked=%v base=%#x lane %d: fillRanksSuper != reference", ci, hooked, base, j)
								}
							}
						}
					}
					if hooked && calls.Load() == 0 {
						t.Fatalf("comps %d: hooked build never consulted a hook", ci)
					}
					if !hooked && calls.Load() != 0 {
						t.Fatalf("comps %d: hook-free build recorded %d hook calls", ci, calls.Load())
					}
				}
			}
		})
	}
}

// TestCascadeFillWideHookIndependence pins that the hooks never change
// the wire: at every width the hooked and the hook-free builders agree
// on every group through every closure the two share.
func TestCascadeFillWideHookIndependence(t *testing.T) {
	nonce := interlock48Nonce()
	for _, wc := range cascadeWideCases() {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			for ci, comps := range cascadeLockSeedComponents {
				// Required by build's hooked path, which increments it from
				// inside the installed hooks; this test does not inspect it.
				var calls atomic.Int64
				hooked := wc.build(t, comps, nonce, true, &calls)
				plain := wc.build(t, comps, nonce, false, &calls)
				var buf [13]byte
				a := make([]uint64, 8*lockBatchFactor48Max)
				b := make([]uint64, 8*lockBatchFactor48Max)
				for g := uint64(0); g < 64; g++ {
					hooked.fillRanks(buf[:], g, a)
					plain.fillRanks(buf[:], g, b)
					if !wordsEqual(a[:wc.words], b[:wc.words]) {
						t.Fatalf("comps %d group %d: hooked and hook-free fills differ", ci, g)
					}
				}
			}
		})
	}
}

// TestCascadeFillWideIsNotDerivedKey pins that the fill is the cascade
// over [K ‖ components] and not the single Hash(block, K) call: the two
// differ on every group checked at every width and key size.
func TestCascadeFillWideIsNotDerivedKey(t *testing.T) {
	nonce := interlock48Nonce()
	for _, wc := range cascadeWideCases() {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			for ci, comps := range cascadeLockSeedComponents {
				// Required by build's hooked path, which increments it from
				// inside the installed hooks; this test does not inspect it.
				var calls atomic.Int64
				bp := wc.build(t, comps, nonce, false, &calls)
				var buf [13]byte
				prf := make([]uint64, 8*lockBatchFactor48Max)
				for g := uint64(0); g < 64; g++ {
					bp.fillRanks(buf[:], g, prf)
					if wordsEqual(prf[:wc.words], wc.derived(comps, nonce, g)) {
						t.Fatalf("comps %d group %d: fill equals the single derived-key call", ci, g)
					}
				}
			}
		})
	}
}

// TestCascadeFillWideNonceBinding pins the nonce binding of round 1 at
// every width: two interlock nonces over the same lockSeed give
// distinct fills on the same group.
func TestCascadeFillWideNonceBinding(t *testing.T) {
	nonceA := interlock48Nonce()
	nonceB := append([]byte(nil), nonceA...)
	nonceB[0] ^= 0x01
	for _, wc := range cascadeWideCases() {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			for ci, comps := range cascadeLockSeedComponents {
				// Required by build's hooked path, which increments it from
				// inside the installed hooks; this test does not inspect it.
				var calls atomic.Int64
				bpA := wc.build(t, comps, nonceA, false, &calls)
				bpB := wc.build(t, comps, nonceB, false, &calls)
				var buf [13]byte
				a := make([]uint64, 8*lockBatchFactor48Max)
				b := make([]uint64, 8*lockBatchFactor48Max)
				for g := uint64(0); g < 32; g++ {
					bpA.fillRanks(buf[:], g, a)
					bpB.fillRanks(buf[:], g, b)
					if wordsEqual(a[:wc.words], b[:wc.words]) {
						t.Fatalf("comps %d group %d: fill identical under two interlock nonces", ci, g)
					}
				}
			}
		})
	}
}

// cascadeWideGolden[width][keySize] is the SHA-256 digest of the
// little-endian rank words of cascadeWideGroups under
// cascadeLockSeedComponents[keySize] (512 / 1024 / 2048-bit) and
// cascadeGoldenNonce, through the shipped builder on the SipHash-2-4
// test hashes. The digests pin the wire of the universal cascade fill
// (prepend order, the 0x04 setup and 0x03 hot-loop tags, the cascade
// depth) at every width, independently of any primitive kernel.
var cascadeWideGolden = map[string][3]string{
	"128": {
		"93b8f1e6be4a2c45ee0345e0241aea3cc5db984479cc8e032d5b7a976a3140e9",
		"83e45ec8f8488c946f92df57327895f28704d7f174b49365f07cfe27540f4326",
		"5bcb87411c3f84edecc1217eef6a839f3ce373e301a69e68dbb4ca26574e8494",
	},
	"256": {
		"82d043b739e5e2de4be52b8909d3cba0ff83ebff5c41f04837277a1c6d912a41",
		"ead63582dcdecae5947cb8b5ac2f82807eed871ded34226191a598a518fdd065",
		"597dfe0a66c762b64d552cd46cf1dbc951bafd47a0247902d5eacd4df157812d",
	},
	"512": {
		"84361b15d781b37db96b668cba443e40456cf926daf74bf2ed41df6b2c9ad7fb",
		"49a75190ed96c2dafd6f73786ffae8f5cac611f03c9dece7b1fc1ac9836066b6",
		"a93c7938027a04a2c19924464c74f71d355718d011ddf03b966f37f2b81cc723",
	},
}

// cascadeWideDigest returns the golden digest of one (width, key size)
// cell through the shipped builder.
func cascadeWideDigest(t *testing.T, wc cascadeWideCase, comps []uint64) string {
	t.Helper()
	var calls atomic.Int64
	bp := wc.build(t, comps, cascadeGoldenNonce, false, &calls)
	h := sha256.New()
	var buf [13]byte
	prf := make([]uint64, 8*lockBatchFactor48Max)
	var w [8]byte
	for _, g := range cascadeWideGroups {
		bp.fillRanks(buf[:], g, prf)
		for _, x := range prf[:wc.words] {
			binary.LittleEndian.PutUint64(w[:], x)
			h.Write(w[:])
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestCascadeFillWideGolden pins the universal cascade fill of every
// width and shipped key size to its golden digest.
func TestCascadeFillWideGolden(t *testing.T) {
	for _, wc := range cascadeWideCases() {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			for i, comps := range cascadeLockSeedComponents {
				got := cascadeWideDigest(t, wc, comps)
				if want := cascadeWideGolden[wc.label][i]; got != want {
					t.Errorf("key %d: digest %s, golden %s", i, got, want)
				}
			}
		})
	}
}

// cascadeWideSplitSizes are framed-input sizes whose chunk counts
// straddle the 16-chunk batch-16 span and the worker split (15 / 16 /
// 17, 31 / 32 / 33, 47 / 48, 63 / 64 / 65, 96 chunks), plus the standard
// residue-class and worker-spawning sizes.
var cascadeWideSplitSizes = func() []int {
	sizes := []int{
		6 * 15, 6*15 + 1, 6 * 16, 6*16 + 1, 6 * 17,
		6 * 31, 6 * 32, 6*32 + 5, 6 * 33,
		6 * 47, 6 * 48, 6 * 63, 6 * 64, 6 * 65, 6 * 96,
		6*100 + 3, 6*1000 + 1, 6*1024 + 2,
	}
	return append(sizes, interlock48Sizes...)
}()

// TestFillRanksSuperWideSplitParity is the wiring layer of the
// batch-16 path at every factor: the worker split with fillRanksSuper
// armed must produce lane bytes bit-identical to the same closure with
// it disarmed, the armed path must actually run, and the armed and
// disarmed encoders and decoders must round-trip each other's lanes.
func TestFillRanksSuperWideSplitParity(t *testing.T) {
	if fillBatch16Disarmed() {
		t.Skip("a fill-ladder knob disarms the batch-16 hooks")
	}
	nonce := interlock48Nonce()
	for _, wc := range cascadeWideCases() {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			var calls atomic.Int64
			armed := wc.build(t, cascadeLockSeedComponents[1], nonce, true, &calls)
			if armed.fillRanksSuper == nil {
				t.Fatal("fillRanksSuper not armed")
			}
			var superCalls atomic.Int64
			origSuper := armed.fillRanksSuper
			armed.fillRanksSuper = func(s *lockFillScratch48, base uint64, prf []uint64) {
				superCalls.Add(1)
				origSuper(s, base, prf)
			}
			seq := armed
			seq.fillRanksSuper = nil
			for _, sz := range cascadeWideSplitSizes {
				framed := interlock48RandomBytes(sz)
				src := framedSrc48{body: framed}
				M := src.chunkCount()
				superCalls.Store(0)
				x0, x1, x2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
				s0, s1, s2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
				splitTriple48LockedBatchInto(src, x0, x1, x2, armed, nil)
				splitTriple48LockedBatchInto(src, s0, s1, s2, seq, nil)
				if !bytes.Equal(x0, s0) || !bytes.Equal(x1, s1) || !bytes.Equal(x2, s2) {
					t.Fatalf("size %d: batch-16 lanes diverge from sequential lanes", sz)
				}
				// A single-worker range of at least 16 chunks must enter the
				// batch-16 path at least once.
				if M >= superGroups48 && configuredWorkerCount(nil) == 1 && superCalls.Load() == 0 {
					t.Fatalf("size %d: split never entered the batch-16 path", sz)
				}
				for _, dir := range []struct {
					label    string
					enc, dec lockBatchPRF48
				}{
					{"armed→disarmed", armed, seq},
					{"disarmed→armed", seq, armed},
					{"armed→armed", armed, armed},
				} {
					p0, p1, p2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
					splitTriple48LockedBatchInto(src, p0, p1, p2, dir.enc, nil)
					got := interleaveTriple48LockedBatch(p0, p1, p2, dir.dec, nil)
					if len(got) < len(framed) || !bytes.Equal(got[:len(framed)], framed) {
						t.Fatalf("size %d %s: round-trip mismatch", sz, dir.label)
					}
					for i := len(framed); i < len(got); i++ {
						if got[i] != 0 {
							t.Fatalf("size %d %s: non-zero padding byte at %d", sz, dir.label, i)
						}
					}
				}
			}
			// The batch-16 path must have run on a large input under a
			// single worker regardless of the host's core count.
			cfg := &Config{MaxWorkers: 1}
			framed := interlock48RandomBytes(6 * 1024)
			src := framedSrc48{body: framed}
			M := src.chunkCount()
			superCalls.Store(0)
			p0, p1, p2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
			splitTriple48LockedBatchInto(src, p0, p1, p2, armed, cfg)
			if superCalls.Load() == 0 {
				t.Fatal("single-worker split never entered the batch-16 path")
			}
			superCalls.Store(0)
			got := interleaveTriple48LockedBatch(p0, p1, p2, armed, cfg)
			if superCalls.Load() == 0 {
				t.Fatal("single-worker interleave never entered the batch-16 path")
			}
			if !bytes.Equal(got[:len(framed)], framed) {
				t.Fatal("single-worker round-trip mismatch")
			}
		})
	}
}

// ============================================================================
// The batch-32 rung of the Interlocked Barrier fill ladder.
// ============================================================================
//
// At width 256 (16 groups per call) and
// width 512 (8 groups per call), under synthetic batch-32 hooks: the
// builder arms fillRanksSuper32 exactly when the lockSeed carries the
// hook and neither disarm knob is set, the armed closure reproduces the
// reference cascade on every group, and the worker split / interleave
// with the rung armed produce lanes bit-identical to the batch-16 rung
// and to the sequential arms, round-tripping each other's wire.

// cascadeWide32Case is one width of the batch-32 surface.
type cascadeWide32Case struct {
	label  string
	factor int
	words  int
	groups int // groups per batch-32 call
	// build returns the builder over a lockSeed carrying the batch-16
	// hook and, when wide is set, the batch-32 hook; calls counts the
	// batch-32 hook's invocations.
	build func(t *testing.T, comps []uint64, nonce []byte, wide bool, calls *atomic.Int64) lockBatchPRF48
	ref   func(comps []uint64, nonce []byte, g uint64) []uint64
}

func cascadeWide32Cases() []cascadeWide32Case {
	return []cascadeWide32Case{
		{
			label: "256", factor: 2, words: 4, groups: 16,
			build: func(t *testing.T, comps []uint64, nonce []byte, wide bool, calls *atomic.Int64) lockBatchPRF48 {
				seed, err := SeedFromComponents256(testHash256, comps...)
				if err != nil {
					t.Fatal(err)
				}
				seed.BatchHash = synthBatch256(testHash256)
				seed.SetInterlockBatch16(func(c []uint64, base uint64, v uint32, out *[8][4]uint64) {
					for i := range out {
						b := cascadeFillBlock(base+uint64(i), v)
						out[i] = refCascade256(c, b[:])
					}
				})
				if wide {
					seed.SetInterlockBatch32(func(c []uint64, base uint64, v uint32, out *[16][4]uint64) {
						calls.Add(1)
						for i := range out {
							b := cascadeFillBlock(base+uint64(i), v)
							out[i] = refCascade256(c, b[:])
						}
					})
				}
				if (seed.InterlockFillX32() != nil) != wide {
					t.Fatalf("InterlockFillX32 attached=%v, want %v", seed.InterlockFillX32() != nil, wide)
				}
				return buildLockBatchPRF48_256(seed, nonce)
			},
			ref: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g, testNonceFold(nonce))
				out := refCascade256(refLockComps256(comps, nonce), b[:])
				return out[:]
			},
		},
		{
			label: "512", factor: 4, words: 8, groups: 8,
			build: func(t *testing.T, comps []uint64, nonce []byte, wide bool, calls *atomic.Int64) lockBatchPRF48 {
				seed, err := SeedFromComponents512(testHash512, comps...)
				if err != nil {
					t.Fatal(err)
				}
				seed.BatchHash = synthBatch512(testHash512)
				seed.SetInterlockBatch16(func(c []uint64, base uint64, v uint32, out *[4][8]uint64) {
					for i := range out {
						b := cascadeFillBlock(base+uint64(i), v)
						out[i] = refCascade512(c, b[:])
					}
				})
				if wide {
					seed.SetInterlockBatch32(func(c []uint64, base uint64, v uint32, out *[8][8]uint64) {
						calls.Add(1)
						for i := range out {
							b := cascadeFillBlock(base+uint64(i), v)
							out[i] = refCascade512(c, b[:])
						}
					})
				}
				if (seed.InterlockFillX32() != nil) != wide {
					t.Fatalf("InterlockFillX32 attached=%v, want %v", seed.InterlockFillX32() != nil, wide)
				}
				return buildLockBatchPRF48_512(seed, nonce)
			},
			ref: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g, testNonceFold(nonce))
				out := refCascade512(refLockComps512(comps, nonce), b[:])
				return out[:]
			},
		},
	}
}

// TestCascadeFillWide32ReferenceParity pins the batch-32 closure of the
// builder: armed exactly when the hook is attached, it reproduces the
// reference cascade on every group of every probe base, and it agrees
// with the batch-16 closure over the same groups.
func TestCascadeFillWide32ReferenceParity(t *testing.T) {
	if fillBatch32Disarmed() {
		t.Skip("a fill-ladder knob disarms the batch-32 hooks")
	}
	nonce := interlock48Nonce()
	for _, wc := range cascadeWide32Cases() {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			for ci, comps := range cascadeLockSeedComponents {
				for _, wide := range []bool{false, true} {
					var calls atomic.Int64
					bp := wc.build(t, comps, nonce, wide, &calls)
					if bp.fillRanksSuper == nil {
						t.Fatal("fillRanksSuper not armed")
					}
					if (bp.fillRanksSuper32 != nil) != wide {
						t.Fatalf("wide=%v: fillRanksSuper32 armed=%v", wide, bp.fillRanksSuper32 != nil)
					}
					if !wide {
						continue
					}
					var scratch lockFillScratch48
					for _, base := range cascadeWideGroups {
						prf := make([]uint64, 2*8*lockBatchFactor48Max)
						bp.fillRanksSuper32(&scratch, base, prf[0:4*superGroups48])
						super := make([]uint64, 8*lockBatchFactor48Max)
						for j := 0; j < wc.groups; j++ {
							got := prf[j*wc.words : (j+1)*wc.words]
							if want := wc.ref(comps, nonce, base+uint64(j)); !wordsEqual(got, want) {
								t.Fatalf("comps %d base=%#x lane %d: fillRanksSuper32 %x != reference %x", ci, base, j, got, want)
							}
						}
						half := wc.groups / 2
						for h := 0; h < 2; h++ {
							bp.fillRanksSuper(&scratch, base+uint64(h*half), super[0:2*superGroups48])
							if !wordsEqual(super[:half*wc.words], prf[h*half*wc.words:(h+1)*half*wc.words]) {
								t.Fatalf("comps %d base=%#x half %d: fillRanksSuper32 and fillRanksSuper disagree", ci, base, h)
							}
						}
					}
					if calls.Load() == 0 {
						t.Fatalf("comps %d: wide build never consulted the batch-32 hook", ci)
					}
				}
			}
		})
	}
}

// TestFillRanksSuper32WideSplitParity is the wiring layer of the
// batch-32 rung: the worker split with fillRanksSuper32 armed must
// produce lane bytes bit-identical to the batch-16 rung and to the
// sequential arms, the armed path must actually run, and every pair of
// encoders and decoders must round-trip each other's lanes.
func TestFillRanksSuper32WideSplitParity(t *testing.T) {
	if fillBatch32Disarmed() {
		t.Skip("a fill-ladder knob disarms the batch-32 hooks")
	}
	nonce := interlock48Nonce()
	for _, wc := range cascadeWide32Cases() {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			var calls atomic.Int64
			wide := wc.build(t, cascadeLockSeedComponents[1], nonce, true, &calls)
			if wide.fillRanksSuper32 == nil {
				t.Fatal("fillRanksSuper32 not armed")
			}
			var wideCalls atomic.Int64
			orig := wide.fillRanksSuper32
			wide.fillRanksSuper32 = func(s *lockFillScratch48, base uint64, prf []uint64) {
				wideCalls.Add(1)
				orig(s, base, prf)
			}
			narrow := wide
			narrow.fillRanksSuper32 = nil
			seq := narrow
			seq.fillRanksSuper = nil
			variants := []struct {
				label string
				bp    lockBatchPRF48
			}{{"batch-32", wide}, {"batch-16", narrow}, {"sequential", seq}}
			for _, sz := range cascadeWideSplitSizes {
				framed := interlock48RandomBytes(sz)
				src := framedSrc48{body: framed}
				M := src.chunkCount()
				wideCalls.Store(0)
				var lanes [3][3][]byte
				for v := range variants {
					for l := range lanes[v] {
						lanes[v][l] = make([]byte, 2*M)
					}
					splitTriple48LockedBatchInto(src, lanes[v][0], lanes[v][1], lanes[v][2], variants[v].bp, nil)
				}
				for v := 1; v < len(variants); v++ {
					for l := 0; l < 3; l++ {
						if !bytes.Equal(lanes[0][l], lanes[v][l]) {
							t.Fatalf("size %d: %s lane %d diverges from %s", sz, variants[0].label, l, variants[v].label)
						}
					}
				}
				// A single-worker range of at least 32 chunks must enter the
				// batch-32 path at least once.
				if M >= 2*superGroups48 && configuredWorkerCount(nil) == 1 && wideCalls.Load() == 0 {
					t.Fatalf("size %d: split never entered the batch-32 path", sz)
				}
				for ei, enc := range variants {
					for _, dec := range variants {
						got := interleaveTriple48LockedBatch(lanes[ei][0], lanes[ei][1], lanes[ei][2], dec.bp, nil)
						if len(got) < len(framed) || !bytes.Equal(got[:len(framed)], framed) {
							t.Fatalf("size %d %s→%s: round-trip mismatch", sz, enc.label, dec.label)
						}
						for i := len(framed); i < len(got); i++ {
							if got[i] != 0 {
								t.Fatalf("size %d %s→%s: non-zero padding byte at %d", sz, enc.label, dec.label, i)
							}
						}
					}
				}
			}
			// The batch-32 path must run on a large input under a single
			// worker regardless of the host's core count, in both directions.
			cfg := &Config{MaxWorkers: 1}
			framed := interlock48RandomBytes(6 * 1024)
			src := framedSrc48{body: framed}
			M := src.chunkCount()
			wideCalls.Store(0)
			p0, p1, p2 := make([]byte, 2*M), make([]byte, 2*M), make([]byte, 2*M)
			splitTriple48LockedBatchInto(src, p0, p1, p2, wide, cfg)
			if wideCalls.Load() == 0 {
				t.Fatal("single-worker split never entered the batch-32 path")
			}
			wideCalls.Store(0)
			got := interleaveTriple48LockedBatch(p0, p1, p2, wide, cfg)
			if wideCalls.Load() == 0 {
				t.Fatal("single-worker interleave never entered the batch-32 path")
			}
			if !bytes.Equal(got[:len(framed)], framed) {
				t.Fatal("single-worker round-trip mismatch")
			}
		})
	}
}

// TestCascadeFillWide32DisarmKnobs pins the fill-ladder knobs on the
// wide widths: ITB_FORCE_INTERLOCK_PRF_FILL_X16 leaves the batch-16 rung
// armed and the batch-32 rung off, _X4 leaves the four-lane arm as the
// top rung, _X1 and _SEQ disarm every batched rung, and with no knob set
// every rung is armed.
func TestCascadeFillWide32DisarmKnobs(t *testing.T) {
	nonce := interlock48Nonce()
	knobs := []string{"ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", "ITB_FORCE_INTERLOCK_PRF_FILL_X1", "ITB_FORCE_INTERLOCK_PRF_FILL_X4", "ITB_FORCE_INTERLOCK_PRF_FILL_X16"}
	for _, wc := range cascadeWide32Cases() {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			var calls atomic.Int64
			check := func(set string, x4, b16, b32 bool) {
				t.Helper()
				for _, k := range knobs {
					if k == set {
						t.Setenv(k, "1")
					} else {
						t.Setenv(k, "")
					}
				}
				bp := wc.build(t, cascadeLockSeedComponents[0], nonce, true, &calls)
				if (bp.fillRanksX4 != nil) != x4 || (bp.fillRanksSuper != nil) != b16 || (bp.fillRanksSuper32 != nil) != b32 {
					t.Fatalf("%s: four-lane armed=%v batch-16 armed=%v batch-32 armed=%v, want %v/%v/%v", set,
						bp.fillRanksX4 != nil, bp.fillRanksSuper != nil, bp.fillRanksSuper32 != nil, x4, b16, b32)
				}
			}
			check("ITB_FORCE_INTERLOCK_PRF_FILL_X16", true, true, false)
			check("ITB_FORCE_INTERLOCK_PRF_FILL_X4", true, false, false)
			check("ITB_FORCE_INTERLOCK_PRF_FILL_X1", false, false, false)
			check("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ", false, false, false)
			check("", true, true, true)
		})
	}
}

// TestInterlockNonceFold pins the interlock-nonce fold carried in bytes
// 9..12 of every Rank Barrier fill block: at every shipped nonce width
// the production fold equals the independent word-XOR formulation
// (testNonceFold), flipping any single nonce byte changes it, the fill
// closures rewrite the fold into the block on every call (a stale
// value in the worker scratch never survives into the next cascade),
// and a nonce differing in one byte yields a different mask triple on
// the same group under the same lockSeed.
func TestInterlockNonceFold(t *testing.T) {
	for _, size := range []int{16, 32, 64} {
		nonce := make([]byte, size)
		for i := range nonce {
			nonce[i] = byte(i*73 + 11)
		}
		fold := interlockNonceFold(nonce)
		if got, want := interlockNonceFoldWord(fold), testNonceFold(nonce); got != want {
			t.Fatalf("nonce %d bytes: fold %#x, word-XOR reference %#x", size, got, want)
		}
		var byHand [4]byte
		for i := 0; i < size; i += 4 {
			for j := 0; j < 4; j++ {
				byHand[j] ^= nonce[i+j]
			}
		}
		if fold != byHand {
			t.Fatalf("nonce %d bytes: fold %x, bytewise slice XOR %x", size, fold, byHand)
		}
		for i := range nonce {
			flipped := append([]byte(nil), nonce...)
			flipped[i] ^= 0x80
			if interlockNonceFold(flipped) == fold {
				t.Fatalf("nonce %d bytes: flipping byte %d leaves the fold unchanged", size, i)
			}
		}
	}

	nonce := interlock48Nonce()
	fold := interlockNonceFold(nonce)
	seed := cascadeLockSeed(t, cascadeLockSeedKeys[1], cascadeLockSeedComponents[1], true)
	bp := buildLockBatchPRF48_128(seed, nonce)
	var buf [13]byte
	var masks [lockBatchFactor48Max][3]uint64
	var prf [2]uint64
	for g := uint64(0); g < 8; g++ {
		for i := range buf {
			buf[i] = 0xFF
		}
		bp.fill(buf[:], g, &masks)
		if [4]byte(buf[9:13]) != fold {
			t.Fatalf("fill group %d left bytes 9..12 at %x, want the fold %x", g, buf[9:13], fold)
		}
		for i := range buf {
			buf[i] = 0xFF
		}
		bp.fillRanks(buf[:], g, prf[:])
		if [4]byte(buf[9:13]) != fold {
			t.Fatalf("fillRanks group %d left bytes 9..12 at %x, want the fold %x", g, buf[9:13], fold)
		}
	}
	if bp.fillRanksX4 != nil {
		var scratch lockFillScratch48
		for i := range scratch.bufs {
			for j := range scratch.bufs[i] {
				scratch.bufs[i][j] = 0xFF
			}
		}
		var x4 [8 * lockBatchFactor48Max]uint64
		bp.fillRanksX4(&scratch, 3, x4[:])
		for i := range scratch.bufs {
			if [4]byte(scratch.bufs[i][9:13]) != fold {
				t.Fatalf("fillRanksX4 lane %d left bytes 9..12 at %x, want the fold %x", i, scratch.bufs[i][9:13], fold)
			}
		}
	}

	// A nonce that differs from the first in exactly one byte changes
	// the fold and, through it and the derived key, the mask triple of
	// every probed group.
	other := append([]byte(nil), nonce...)
	other[len(other)-1] ^= 0x01
	bpOther := buildLockBatchPRF48_128(seed, other)
	for g := uint64(0); g < 8; g++ {
		var a, b [lockBatchFactor48Max][3]uint64
		bp.fill(buf[:], g, &a)
		bpOther.fill(buf[:], g, &b)
		if a[0] == b[0] {
			t.Fatalf("group %d: mask triple identical under two nonces differing in one byte", g)
		}
	}
}
