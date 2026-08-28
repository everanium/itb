package itb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// ============================================================================
// Superblock parity + golden lane digests for the batched 48-bit lock path.
// ============================================================================
//
// The production worker loops in splitTriple48LockedBatch /
// interleaveTriple48LockedBatch accumulate the 128-bit rank pairs of up
// to superChunks48 chunks and derive their mask triples in one
// fillLockMasksTriple48Super pass. The mask derivation is a pure
// function of each chunk's rank pair, so the lane bytes must be
// bit-identical to a sequential per-group derivation through bp.fill.
// Two independent anchors enforce that:
//
//  1. refSplitPerGroup48 / refInterleavePerGroup48 — sequential
//     single-threaded references driven by bp.fill (one mask-derivation
//     pass per PRF group), compared byte-for-byte against the parallel
//     superblock production kernels across M values that cross every
//     superblock boundary at every width factor.
//  2. Golden SHA-256 digests of the lane bytes under fixed seed
//     components, fixed nonce, and fixed data — locking the overlay's
//     wire contribution against any derivation-order or kernel change.

// refSplitPerGroup48 is the sequential per-group reference for
// [splitTriple48LockedBatch]: identical padding, group indexing, and
// lane serialisation, with one bp.fill mask-derivation per group and no
// superblock accumulation and no parallelism.
func refSplitPerGroup48(data []byte, bp lockBatchPRF48) (p0, p1, p2 []byte) {
	L := len(data)
	LPad := ((L + 5) / 6) * 6
	padded := make([]byte, LPad)
	copy(padded, data)
	M := LPad / 6

	p0 = make([]byte, 2*M)
	p1 = make([]byte, 2*M)
	p2 = make([]byte, 2*M)

	factor := bp.factor
	numGroups := (M + factor - 1) / factor
	var buf [13]byte
	var masks [lockBatchFactor48Max][3]uint64
	for g := 0; g < numGroups; g++ {
		bp.fill(buf[:], uint64(g), &masks)
		for j := 0; j < factor; j++ {
			k := g*factor + j
			if k >= M {
				break
			}
			m0, m1, m2 := masks[j][0], masks[j][1], masks[j][2]
			x := readChunk48(padded, 6*k)
			l0, l1, l2 := chunk48lock(x, m0, m1, m2)
			p0[2*k] = byte(l0)
			p0[2*k+1] = byte(l0 >> 8)
			p1[2*k] = byte(l1)
			p1[2*k+1] = byte(l1 >> 8)
			p2[2*k] = byte(l2)
			p2[2*k+1] = byte(l2 >> 8)
		}
	}
	return
}

// refInterleavePerGroup48 is the sequential per-group reference for
// [interleaveTriple48LockedBatch].
func refInterleavePerGroup48(p0, p1, p2 []byte, bp lockBatchPRF48) []byte {
	M := len(p0) / 2
	result := make([]byte, M*6)

	factor := bp.factor
	numGroups := (M + factor - 1) / factor
	var buf [13]byte
	var masks [lockBatchFactor48Max][3]uint64
	for g := 0; g < numGroups; g++ {
		bp.fill(buf[:], uint64(g), &masks)
		for j := 0; j < factor; j++ {
			k := g*factor + j
			if k >= M {
				break
			}
			m0, m1, m2 := masks[j][0], masks[j][1], masks[j][2]
			l0 := uint16(p0[2*k]) | uint16(p0[2*k+1])<<8
			l1 := uint16(p1[2*k]) | uint16(p1[2*k+1])<<8
			l2 := uint16(p2[2*k]) | uint16(p2[2*k+1])<<8
			x := unchunk48lock(l0, l1, l2, m0, m1, m2)
			writeChunk48(result, 6*k, x)
		}
	}
	return result
}

// superTestFixedData returns n deterministic bytes for the parity and
// golden fixtures (no RNG — the fixtures must be reproducible across
// runs and trees).
func superTestFixedData(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*131 + 7)
	}
	return b
}

// superTestNonce is the fixed nonce shared by the parity and golden
// fixtures in this file.
var superTestNonce = []byte{
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
}

// superTestComponents is the fixed 8-component seed material shared by
// the parity and golden fixtures in this file.
var superTestComponents = []uint64{
	0xc07724706ed0758b, 0x0489964ee29ad754,
	0x97819a4b77e0fd0a, 0xd9b9322f08f9eb5c,
	0x9d8dc0b866e92b87, 0xaf7f4a99914da68b,
	0x51101868dab807ae, 0xbc6e07a2a5067689,
}

// superTestBuilders returns one deterministic lockBatchPRF48 per hash
// width (factor 1 / 2 / 4), all keyed from the same fixed components
// and fixed nonce.
func superTestBuilders(t *testing.T) []struct {
	label string
	bp    lockBatchPRF48
} {
	t.Helper()
	ls128, err := SeedFromComponents128(sipHash128, superTestComponents...)
	if err != nil {
		t.Fatal(err)
	}
	ls256, err := SeedFromComponents256(testHash256, superTestComponents...)
	if err != nil {
		t.Fatal(err)
	}
	ls512, err := SeedFromComponents512(testHash512, superTestComponents...)
	if err != nil {
		t.Fatal(err)
	}
	return []struct {
		label string
		bp    lockBatchPRF48
	}{
		{"128-factor1", buildLockBatchPRF48_128(ls128, superTestNonce)},
		{"256-factor2", buildLockBatchPRF48_256(ls256, superTestNonce)},
		{"512-factor4", buildLockBatchPRF48_512(ls512, superTestNonce)},
	}
}

// TestSuperblockVsPerGroupParity asserts that the superblock production
// kernels produce lane bytes bit-identical to the sequential per-group
// bp.fill reference at every width factor, across M values that cross
// the superblock boundary (multiples of superChunks48 and their
// neighbours), short tails at every factor residue, and worker-range
// splits from the parallel dispatch.
func TestSuperblockVsPerGroupParity(t *testing.T) {
	// M values crossing every superblock / factor / worker boundary of
	// interest; sizes exercise both 6-aligned and padded framed lengths.
	mValues := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 23, 24, 25, 31, 32, 33, 40, 64, 65, 100, 257}
	for _, wc := range superTestBuilders(t) {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			for _, m := range mValues {
				for _, sz := range []int{6 * m, 6*m - 3} {
					if sz <= 0 {
						continue
					}
					framed := superTestFixedData(sz)

					refP0, refP1, refP2 := refSplitPerGroup48(framed, wc.bp)
					gotP0, gotP1, gotP2 := splitTriple48LockedBatch(framed, wc.bp)
					if !bytes.Equal(refP0, gotP0) || !bytes.Equal(refP1, gotP1) || !bytes.Equal(refP2, gotP2) {
						t.Fatalf("M=%d size=%d: superblock split lane bytes diverge from per-group reference", m, sz)
					}

					refOut := refInterleavePerGroup48(refP0, refP1, refP2, wc.bp)
					gotOut := interleaveTriple48LockedBatch(gotP0, gotP1, gotP2, wc.bp)
					if !bytes.Equal(refOut, gotOut) {
						t.Fatalf("M=%d size=%d: superblock interleave diverges from per-group reference", m, sz)
					}
					if !bytes.Equal(gotOut[:sz], framed) {
						t.Fatalf("M=%d size=%d: round-trip mismatch", m, sz)
					}
				}
			}
		})
	}
}

// TestInterlock48LockedLaneGolden locks the batched lock split's lane
// bytes to fixed SHA-256 digests under fixed seed components, fixed
// nonce, and fixed data. Any change to the mask derivation, PRF group
// indexing, chunk packing, or lane serialisation — including asm-kernel
// and derivation-order changes — breaks these digests. The interleave
// of the same lanes must also round-trip to the input.
func TestInterlock48LockedLaneGolden(t *testing.T) {
	golden := map[string]map[int]string{
		"128-factor1": {
			144:  "ae946fabd42e89159d4f28d390c098d33f0dfef920d78b9a15ce22f681356c50",
			1000: "8bb7458ad7ca9ad4ad7243277cc5366b8f797c7faa6db476793d0b49d1d98198",
		},
		"256-factor2": {
			144:  "2c835b87ec8835716f7578f542c01c7d93ebc437389e21684ac174170c592e15",
			1000: "8bd1a32af335e88e1e1e3800b3f0159c5bc7099369f3c326b5804548d5cdf83f",
		},
		"512-factor4": {
			144:  "70a7463fd8fdf4ea415247e0eb3f3f55b544e2ba659d2c485088e9f93d4bafe1",
			1000: "df6a2f64090e2d5b9e6cf2a8dfee97f9377f04e03ccff584118d6c14c43ed300",
		},
	}
	for _, wc := range superTestBuilders(t) {
		wc := wc
		t.Run(wc.label, func(t *testing.T) {
			for sz, want := range golden[wc.label] {
				framed := superTestFixedData(sz)
				p0, p1, p2 := splitTriple48LockedBatch(framed, wc.bp)
				h := sha256.New()
				h.Write(p0)
				h.Write(p1)
				h.Write(p2)
				got := hex.EncodeToString(h.Sum(nil))
				if got != want {
					t.Fatalf("size=%d: lane digest %s, want %s", sz, got, want)
				}
				out := interleaveTriple48LockedBatch(p0, p1, p2, wc.bp)
				if !bytes.Equal(out[:sz], framed) {
					t.Fatalf("size=%d: golden lanes do not round-trip", sz)
				}
			}
		})
	}
}
