package itb

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sync/atomic"
	"testing"

	"github.com/everanium/itb/internal/forcetier"
)

// interlock48_cascade_wide_test.go — the universal Interlocked Barrier
// cascade fill at every hash width ([buildLockBatchPRF48_128] /
// [buildLockBatchPRF48_256] / [buildLockBatchPRF48_512]) on
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
					seed.SetInterlockBatch16(func(c []uint64, base uint64, out *[16][2]uint64) {
						calls.Add(1)
						for i := range out {
							b := cascadeFillBlock(base + uint64(i))
							out[i][0], out[i][1] = refCascade128(c, b[:])
						}
					})
				}
				return buildLockBatchPRF48_128(seed, nonce)
			},
			ref: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g)
				lo, hi := refCascade128(refLockComps128(comps, nonce), b[:])
				return []uint64{lo, hi}
			},
			derived: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g)
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
					seed.SetInterlockBatch16(func(c []uint64, base uint64, out *[8][4]uint64) {
						calls.Add(1)
						for i := range out {
							b := cascadeFillBlock(base + uint64(i))
							out[i] = refCascade256(c, b[:])
						}
					})
				}
				return buildLockBatchPRF48_256(seed, nonce)
			},
			ref: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g)
				out := refCascade256(refLockComps256(comps, nonce), b[:])
				return out[:]
			},
			derived: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g)
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
					seed.SetInterlockBatch16(func(c []uint64, base uint64, out *[4][8]uint64) {
						calls.Add(1)
						for i := range out {
							b := cascadeFillBlock(base + uint64(i))
							out[i] = refCascade512(c, b[:])
						}
					})
				}
				return buildLockBatchPRF48_512(seed, nonce)
			},
			ref: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g)
				out := refCascade512(refLockComps512(comps, nonce), b[:])
				return out[:]
			},
			derived: func(comps []uint64, nonce []byte, g uint64) []uint64 {
				b := cascadeFillBlock(g)
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
	if forcetier.InterlockPRFFillSeq() {
		t.Skip("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ set; batch-16 hooks disarmed")
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
		"1400e4eab62502cc568dc80df3389674d31edc982c203d6c4db6a27fb26c4bad",
		"dc4ffde4bef8db7e9f64e55e87edac80869a062e682c7f80a1f32c6287624e0e",
		"ab35392b9e0e53eacf59fe1cb81e10c05f7f03d6567e30b0ee0a287f9cab3576",
	},
	"256": {
		"51a5e39ed38c6e0d067ae3e3a973f39e46a30a08f724d63139466b8da0a4d5b7",
		"4b6a0ff8ce904b233272c5589859cb5c449b02676369efbdb729a1eb81269f53",
		"71a12d11b46cd3dfceb446741a99b17a0bf46876eec77666daf7e1aa8707fa74",
	},
	"512": {
		"b54060e590a75b73ee4798d7dc8efbb60658b026c9254dbd6de51c4fa56a0d36",
		"cdd7293d64265c3e54972b0fa5dab7daf4104cff500db01727f6c2b275f582f3",
		"c2e02767094da0f26ee955d4c1e86fc6b4b8a9a4f4752bff08021127cfa6f294",
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
	if forcetier.InterlockPRFFillSeq() {
		t.Skip("ITB_FORCE_INTERLOCK_PRF_FILL_SEQ set; batch-16 hooks disarmed")
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
