package itb

import (
	"bytes"
	"testing"
)

// interlock48_x4_test.go — parity coverage for the fillRanksX4 batched
// PRF fill path of splitTriple48LockedBatch / interleaveTriple48LockedBatch.
//
// The x4 arm must produce lane bytes bit-identical to the scalar
// fillRanks arm on every input: the tests below run the same split with
// fillRanksX4 armed and disarmed and require byte-equal lane outputs,
// then round-trip the x4-armed encode through the x4-armed decode.
// The 256/512-bit widths use the real Areion-SoEM batched arm; the
// 128-bit width uses a synthetic 4-lane BatchHash wrapper over the
// scalar test hash, which satisfies the BatchHash parity invariant by
// construction and exercises the loop restructure on any host.

// synthBatch128 wraps a HashFunc128 into a 4-lane BatchHashFunc128 that
// trivially satisfies the parity invariant.
func synthBatch128(h HashFunc128) BatchHashFunc128 {
	return func(data *[4][]byte, seeds [4][2]uint64) [4][2]uint64 {
		var out [4][2]uint64
		for lane := 0; lane < 4; lane++ {
			out[lane][0], out[lane][1] = h(data[lane], seeds[lane][0], seeds[lane][1])
		}
		return out
	}
}

func interlock48X4Cases(t *testing.T) []struct {
	label string
	bp    lockBatchPRF48
} {
	t.Helper()
	nonce := interlock48Nonce()

	ns128, err := NewSeed128(512, sipHash128)
	if err != nil {
		t.Fatal(err)
	}
	ns128.BatchHash = synthBatch128(sipHash128)

	h256, b256, _ := MakeAreionSoEM256Hash()
	ns256, err := NewSeed256(512, h256)
	if err != nil {
		t.Fatal(err)
	}
	ns256.BatchHash = b256

	h512, b512 := makeAreionSoEM512Pair()
	ns512, err := NewSeed512(512, h512)
	if err != nil {
		t.Fatal(err)
	}
	ns512.BatchHash = b512

	return []struct {
		label string
		bp    lockBatchPRF48
	}{
		{"128-sip-synthbatch", buildLockBatchPRF48_128(ns128, nonce)},
		{"256-areion", buildLockBatchPRF48_256(ns256, nonce)},
		{"512-areion", buildLockBatchPRF48_512(ns512, nonce)},
	}
}

// TestFillRanksX4VsScalarParity splits identical framed inputs through
// the x4-armed and scalar-only variants of the same lockBatchPRF48 and
// requires bit-identical lane bytes at every size class.
func TestFillRanksX4VsScalarParity(t *testing.T) {
	for _, tc := range interlock48X4Cases(t) {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			if tc.bp.fillRanksX4 == nil {
				t.Skip("BatchHash arm unavailable on this host/build — fillRanksX4 not armed")
			}
			scalar := tc.bp
			scalar.fillRanksX4 = nil
			for _, sz := range interlock48Sizes {
				framed := interlock48RandomBytes(sz)
				x0, x1, x2 := splitTriple48LockedBatch(framed, tc.bp)
				s0, s1, s2 := splitTriple48LockedBatch(framed, scalar)
				if !bytes.Equal(x0, s0) || !bytes.Equal(x1, s1) || !bytes.Equal(x2, s2) {
					t.Fatalf("size %d: x4 lanes diverge from scalar lanes", sz)
				}
			}
		})
	}
}

// TestFillRanksX4RoundTrip encodes with the x4-armed closure and
// decodes with the same closure, requiring exact recovery of the
// framed input (modulo the 6-byte zero padding the encoder added).
func TestFillRanksX4RoundTrip(t *testing.T) {
	for _, tc := range interlock48X4Cases(t) {
		tc := tc
		t.Run(tc.label, func(t *testing.T) {
			if tc.bp.fillRanksX4 == nil {
				t.Skip("BatchHash arm unavailable on this host/build — fillRanksX4 not armed")
			}
			for _, sz := range interlock48Sizes {
				framed := interlock48RandomBytes(sz)
				p0, p1, p2 := splitTriple48LockedBatch(framed, tc.bp)
				got := interleaveTriple48LockedBatch(p0, p1, p2, tc.bp)
				if len(got) < len(framed) {
					t.Fatalf("size %d: recovered %d bytes < input %d", sz, len(got), len(framed))
				}
				if !bytes.Equal(got[:len(framed)], framed) {
					t.Fatalf("size %d: round-trip mismatch", sz)
				}
				for i := len(framed); i < len(got); i++ {
					if got[i] != 0 {
						t.Fatalf("size %d: non-zero padding byte at %d", sz, i)
					}
				}
			}
		})
	}
}
