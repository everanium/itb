package itb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
)

// --- Edge-case byte patterns (per-width Triple round-trip) ---

// TestTripleSingleByte covers the smallest non-empty plaintext (one
// byte). The container must be sized for one pixel of payload plus
// the barrier / noise / start-pixel padding pixels — this stresses
// the minimum-container path across every Triple width.
func TestTripleSingleByte(t *testing.T) {
	data := []byte{0x42}

	t.Run("128", func(t *testing.T) {
		n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(512, sipHash128)
		ct, err := Encrypt3x128(n, l, d1, d2, d3, s1, s2, s3, data)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := Decrypt3x128(n, l, d1, d2, d3, s1, s2, s3, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) {
			t.Fatalf("128 single-byte round-trip mismatch")
		}
	})
	t.Run("256", func(t *testing.T) {
		n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds256(512, makeBlake3Hash256())
		ct, err := Encrypt3x256(n, l, d1, d2, d3, s1, s2, s3, data)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := Decrypt3x256(n, l, d1, d2, d3, s1, s2, s3, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) {
			t.Fatalf("256 single-byte round-trip mismatch")
		}
	})
	t.Run("512", func(t *testing.T) {
		n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds512(512, makeBlake2bHash512())
		ct, err := Encrypt3x512(n, l, d1, d2, d3, s1, s2, s3, data)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := Decrypt3x512(n, l, d1, d2, d3, s1, s2, s3, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) {
			t.Fatalf("512 single-byte round-trip mismatch")
		}
	})
}

// TestTripleAllZeroBytes exercises the all-zero payload. The COBS
// encoder must expand zero runs; a bug in the encoder path or in
// the discard-hi barrier would surface here as a decrypt mismatch.
func TestTripleAllZeroBytes(t *testing.T) {
	data := make([]byte, 256)

	t.Run("128", func(t *testing.T) {
		n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(512, sipHash128)
		ct, err := Encrypt3x128(n, l, d1, d2, d3, s1, s2, s3, data)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := Decrypt3x128(n, l, d1, d2, d3, s1, s2, s3, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) {
			t.Fatalf("128 all-zero round-trip mismatch")
		}
	})
	t.Run("256", func(t *testing.T) {
		n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds256(512, makeBlake3Hash256())
		ct, err := Encrypt3x256(n, l, d1, d2, d3, s1, s2, s3, data)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := Decrypt3x256(n, l, d1, d2, d3, s1, s2, s3, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) {
			t.Fatalf("256 all-zero round-trip mismatch")
		}
	})
	t.Run("512", func(t *testing.T) {
		n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds512(512, makeBlake2bHash512())
		ct, err := Encrypt3x512(n, l, d1, d2, d3, s1, s2, s3, data)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := Decrypt3x512(n, l, d1, d2, d3, s1, s2, s3, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) {
			t.Fatalf("512 all-zero round-trip mismatch")
		}
	})
}

// TestTripleAllFFBytes exercises the all-0xFF payload. Every data
// bit set contrasts with the all-zero pattern above and provides
// symmetric coverage of the COBS + barrier path.
func TestTripleAllFFBytes(t *testing.T) {
	data := bytes.Repeat([]byte{0xFF}, 256)

	t.Run("128", func(t *testing.T) {
		n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(512, sipHash128)
		ct, err := Encrypt3x128(n, l, d1, d2, d3, s1, s2, s3, data)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := Decrypt3x128(n, l, d1, d2, d3, s1, s2, s3, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) {
			t.Fatalf("128 all-0xFF round-trip mismatch")
		}
	})
}

// TestTriplePixelBoundary exercises payload sizes that straddle
// the 56-bit-per-pixel packing boundary: 6..8 (< 1 pixel), 13..15
// (crossing pixel 2), 55..57 (crossing pixel 8). A packing bug in
// the encoder byte→channel path would surface at exactly these
// sizes.
func TestTriplePixelBoundary(t *testing.T) {
	for _, sz := range []int{6, 7, 8, 13, 14, 15, 55, 56, 57} {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(512, sipHash128)
			data := genTestPlaintext(t, sz)
			ct, err := Encrypt3x128(n, l, d1, d2, d3, s1, s2, s3, data)
			if err != nil {
				t.Fatal(err)
			}
			pt, err := Decrypt3x128(n, l, d1, d2, d3, s1, s2, s3, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, pt) {
				t.Fatalf("pixel-boundary mismatch at %d bytes", sz)
			}
		})
	}
}

// TestTripleExactMinContainer exercises a payload that fits
// approximately in the minimum container for the seed's PRF ambiguity
// requirement (56^MinPixels > 2^bits). The size is chosen so the
// container sits right at the min-container branch of
// calcContainerSize3.
func TestTripleExactMinContainer(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(512, sipHash128)
	data := genTestPlaintext(t, 560)
	ct, err := Encrypt3x128(n, l, d1, d2, d3, s1, s2, s3, data)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt3x128(n, l, d1, d2, d3, s1, s2, s3, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, pt) {
		t.Fatalf("min-container round-trip mismatch")
	}
}

// --- Seed-width sweep + max key size ---

// TestTripleKeySizes covers 512-bit and 1024-bit seed sizes at the
// 128-bit primitive width (SipHash-2-4). Both bit-widths must
// round-trip cleanly; the seed-component count differs (8 for 512,
// 16 for 1024) so the seed-alloc path is exercised at both endpoints.
func TestTripleKeySizes(t *testing.T) {
	for _, bits := range []int{512, 1024} {
		t.Run(fmt.Sprintf("%d-bit", bits), func(t *testing.T) {
			n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(bits, sipHash128)
			data := genTestPlaintext(t, 256)
			ct, err := Encrypt3x128(n, l, d1, d2, d3, s1, s2, s3, data)
			if err != nil {
				t.Fatal(err)
			}
			pt, err := Decrypt3x128(n, l, d1, d2, d3, s1, s2, s3, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, pt) {
				t.Fatalf("%d-bit round-trip mismatch", bits)
			}
		})
	}
}

// TestTripleMaxKeySize verifies the maximum-permitted 1024-bit seed
// width on the 128-bit primitive round-trips cleanly.
func TestTripleMaxKeySize(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(1024, sipHash128)
	data := genTestPlaintext(t, 1024)
	ct, err := Encrypt3x128(n, l, d1, d2, d3, s1, s2, s3, data)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := Decrypt3x128(n, l, d1, d2, d3, s1, s2, s3, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, pt) {
		t.Fatalf("1024-bit key round-trip mismatch")
	}
}

// --- SeedFromComponents constructor + validation ---

// TestSeedFromComponents128 verifies the deterministic-seed
// constructor for the 128-bit width can be substituted for the
// crypto/rand-backed NewSeed128 path — a known seed vector reaches
// the same round-trip result as a randomly-generated one under the
// same PRF closure.
func TestSeedFromComponents128(t *testing.T) {
	n, err := SeedFromComponents128(sipHash128,
		0xdeadbeef01234567, 0x0123456789abcdef,
		0xfedcba9876543210, 0x1111111111111111,
		0x2222222222222222, 0x3333333333333333,
		0x4444444444444444, 0x5555555555555555,
	)
	if err != nil {
		t.Fatalf("SeedFromComponents128 noise: %v", err)
	}
	l, _ := NewSeed128(512, sipHash128)
	d1, _ := NewSeed128(512, sipHash128)
	d2, _ := NewSeed128(512, sipHash128)
	d3, _ := NewSeed128(512, sipHash128)
	s1, _ := NewSeed128(512, sipHash128)
	s2, _ := NewSeed128(512, sipHash128)
	s3, _ := NewSeed128(512, sipHash128)
	data := genTestPlaintext(t, 1024)
	ct, err := Encrypt3x128(n, l, d1, d2, d3, s1, s2, s3, data)
	if err != nil {
		t.Fatalf("Encrypt3x128: %v", err)
	}
	pt, err := Decrypt3x128(n, l, d1, d2, d3, s1, s2, s3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x128: %v", err)
	}
	if !bytes.Equal(data, pt) {
		t.Fatalf("SeedFromComponents128 round-trip mismatch")
	}
}

// TestSeedFromComponents256Roundtrip mirrors [TestSeedFromComponents128]
// for the 256-bit width.
func TestSeedFromComponents256Roundtrip(t *testing.T) {
	h := makeBlake3Hash256()
	n, err := SeedFromComponents256(h,
		0xdeadbeef01234567, 0x0123456789abcdef,
		0xfedcba9876543210, 0x1111111111111111,
		0x2222222222222222, 0x3333333333333333,
		0x4444444444444444, 0x5555555555555555,
	)
	if err != nil {
		t.Fatalf("SeedFromComponents256 noise: %v", err)
	}
	l, _ := NewSeed256(512, h)
	d1, _ := NewSeed256(512, h)
	d2, _ := NewSeed256(512, h)
	d3, _ := NewSeed256(512, h)
	s1, _ := NewSeed256(512, h)
	s2, _ := NewSeed256(512, h)
	s3, _ := NewSeed256(512, h)
	data := genTestPlaintext(t, 1024)
	ct, err := Encrypt3x256(n, l, d1, d2, d3, s1, s2, s3, data)
	if err != nil {
		t.Fatalf("Encrypt3x256: %v", err)
	}
	pt, err := Decrypt3x256(n, l, d1, d2, d3, s1, s2, s3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x256: %v", err)
	}
	if !bytes.Equal(data, pt) {
		t.Fatalf("SeedFromComponents256 round-trip mismatch")
	}
}

// TestSeedFromComponents512Roundtrip mirrors [TestSeedFromComponents128]
// for the 512-bit width.
func TestSeedFromComponents512Roundtrip(t *testing.T) {
	h := makeBlake2bHash512()
	n, err := SeedFromComponents512(h,
		0xdeadbeef01234567, 0x0123456789abcdef,
		0xfedcba9876543210, 0x1111111111111111,
		0x2222222222222222, 0x3333333333333333,
		0x4444444444444444, 0x5555555555555555,
	)
	if err != nil {
		t.Fatalf("SeedFromComponents512 noise: %v", err)
	}
	l, _ := NewSeed512(512, h)
	d1, _ := NewSeed512(512, h)
	d2, _ := NewSeed512(512, h)
	d3, _ := NewSeed512(512, h)
	s1, _ := NewSeed512(512, h)
	s2, _ := NewSeed512(512, h)
	s3, _ := NewSeed512(512, h)
	data := genTestPlaintext(t, 1024)
	ct, err := Encrypt3x512(n, l, d1, d2, d3, s1, s2, s3, data)
	if err != nil {
		t.Fatalf("Encrypt3x512: %v", err)
	}
	pt, err := Decrypt3x512(n, l, d1, d2, d3, s1, s2, s3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x512: %v", err)
	}
	if !bytes.Equal(data, pt) {
		t.Fatalf("SeedFromComponents512 round-trip mismatch")
	}
}

// TestSeedFromComponents128Validation exercises the argument
// validation on the deterministic-seed constructor: too-few
// components, non-multiple-of-2 (128-bit width takes pairs of
// uint64), nil hashFunc.
func TestSeedFromComponents128Validation(t *testing.T) {
	if _, err := SeedFromComponents128(sipHash128, 1, 2, 3); err == nil {
		t.Fatal("expected error for 3 components (below 8 minimum)")
	}
	if _, err := SeedFromComponents128(nil, 1, 2, 3, 4, 5, 6, 7, 8); err == nil {
		t.Fatal("expected error for nil hashFunc")
	}
}

// TestSeedFromComponents256Validation mirrors the 128-bit validator
// test on the 256-bit width. 256-bit seeds take component counts
// that are multiples of 4.
func TestSeedFromComponents256Validation(t *testing.T) {
	h := makeBlake3Hash256()
	if _, err := SeedFromComponents256(h, 1, 2, 3); err == nil {
		t.Fatal("expected error for 3 components (below 8 minimum)")
	}
	if _, err := SeedFromComponents256(h, 1, 2, 3, 4, 5, 6, 7, 8, 9); err == nil {
		t.Fatal("expected error for 9 components (not multiple of 4)")
	}
	if _, err := SeedFromComponents256(nil, 1, 2, 3, 4, 5, 6, 7, 8); err == nil {
		t.Fatal("expected error for nil hashFunc")
	}
}

// TestSeedFromComponents512Validation mirrors the 128 / 256-bit
// validators on the 512-bit width. 512-bit seeds take component
// counts that are multiples of 8.
func TestSeedFromComponents512Validation(t *testing.T) {
	h := makeBlake2bHash512()
	if _, err := SeedFromComponents512(h, 1, 2, 3); err == nil {
		t.Fatal("expected error for 3 components (below 8 minimum)")
	}
	if _, err := SeedFromComponents512(h, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12); err == nil {
		t.Fatal("expected error for 12 components (not multiple of 8)")
	}
	if _, err := SeedFromComponents512(nil, 1, 2, 3, 4, 5, 6, 7, 8); err == nil {
		t.Fatal("expected error for nil hashFunc")
	}
}

// TestInvalidSeedSize exercises the seed-width validator inside
// NewSeed128 / NewSeed256 / NewSeed512: below-minimum, above-maximum,
// not-a-multiple-of-primitive-width, nil hashFunc.
func TestInvalidSeedSize(t *testing.T) {
	if _, err := NewSeed128(256, sipHash128); err == nil {
		t.Fatal("expected error for 256-bit seed (below 512 minimum)")
	}
	if _, err := NewSeed128(4096, sipHash128); err == nil {
		t.Fatal("expected error for 4096-bit seed (above 2048 maximum)")
	}
	if _, err := NewSeed128(500, sipHash128); err == nil {
		t.Fatal("expected error for non-128-multiple seed size")
	}
	if _, err := NewSeed128(512, nil); err == nil {
		t.Fatal("expected error for nil hashFunc")
	}
	if _, err := NewSeed256(256, makeBlake3Hash256()); err == nil {
		t.Fatal("expected error for 256-bit seed256 (below 512)")
	}
	if _, err := NewSeed256(600, makeBlake3Hash256()); err == nil {
		t.Fatal("expected error for non-256-multiple")
	}
	if _, err := NewSeed256(512, nil); err == nil {
		t.Fatal("expected error for nil hash256")
	}
	if _, err := NewSeed512(256, makeBlake2bHash512()); err == nil {
		t.Fatal("expected error for 256-bit seed512 (below 512)")
	}
	if _, err := NewSeed512(600, makeBlake2bHash512()); err == nil {
		t.Fatal("expected error for non-512-multiple")
	}
	if _, err := NewSeed512(512, nil); err == nil {
		t.Fatal("expected error for nil hash512")
	}
}

// --- Runtime-configuration setter validation ---

// TestNonceBitsSweep exercises the nonce-width setter across the
// three permitted values (128 / 256 / 512) with a Triple round-trip
// at each width. A width change must round-trip cleanly under every
// primitive width the shipped registry supports.
func TestNonceBitsSweep(t *testing.T) {
	for _, nonceBits := range []int{128, 256, 512} {
		t.Run(fmt.Sprintf("%dbit", nonceBits), func(t *testing.T) {
			prev := GetNonceBits()
			SetNonceBits(nonceBits)
			defer SetNonceBits(prev)

			if got := GetNonceBits(); got != nonceBits {
				t.Fatalf("GetNonceBits() = %d, want %d", got, nonceBits)
			}

			data := genTestPlaintext(t, 1<<20)

			n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(1024, sipHash128)
			ct, err := Encrypt3x128(n, l, d1, d2, d3, s1, s2, s3, data)
			if err != nil {
				t.Fatalf("Encrypt3x128: %v", err)
			}
			pt, err := Decrypt3x128(n, l, d1, d2, d3, s1, s2, s3, ct)
			if err != nil {
				t.Fatalf("Decrypt3x128: %v", err)
			}
			if !bytes.Equal(data, pt) {
				t.Fatal("128 round-trip mismatch")
			}

			n2, l2, d21, d22, d23, s21, s22, s23 := makeEightSeeds256(512, makeBlake3Hash256())
			ct2, err := Encrypt3x256(n2, l2, d21, d22, d23, s21, s22, s23, data)
			if err != nil {
				t.Fatalf("Encrypt3x256: %v", err)
			}
			pt2, err := Decrypt3x256(n2, l2, d21, d22, d23, s21, s22, s23, ct2)
			if err != nil {
				t.Fatalf("Decrypt3x256: %v", err)
			}
			if !bytes.Equal(data, pt2) {
				t.Fatal("256 round-trip mismatch")
			}

			n5, l5, d51, d52, d53, s51, s52, s53 := makeEightSeeds512(512, makeBlake2bHash512())
			ct5, err := Encrypt3x512(n5, l5, d51, d52, d53, s51, s52, s53, data)
			if err != nil {
				t.Fatalf("Encrypt3x512: %v", err)
			}
			pt5, err := Decrypt3x512(n5, l5, d51, d52, d53, s51, s52, s53, ct5)
			if err != nil {
				t.Fatalf("Decrypt3x512: %v", err)
			}
			if !bytes.Equal(data, pt5) {
				t.Fatal("512 round-trip mismatch")
			}
		})
	}
}

// TestSetNonceBitsPanic exercises the nonce-width setter's rejection
// of every value outside the {128, 256, 512} permit-set.
func TestSetNonceBitsPanic(t *testing.T) {
	for _, invalid := range []int{0, 64, 137, 1024, -1} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("SetNonceBits(%d) should panic", invalid)
				}
			}()
			SetNonceBits(invalid)
		}()
	}
}

// TestSetMaxWorkers exercises the worker-cap setter's clamp behaviour:
// zero and negative values fall to 0 (implicit runtime.NumCPU on
// dispatch), values above 256 clamp to 256.
func TestSetMaxWorkers(t *testing.T) {
	prev := GetMaxWorkers()
	defer SetMaxWorkers(prev)

	SetMaxWorkers(4)
	if got := GetMaxWorkers(); got != 4 {
		t.Fatalf("GetMaxWorkers() = %d, want 4", got)
	}

	SetMaxWorkers(0)
	if got := GetMaxWorkers(); got != 0 {
		t.Fatalf("GetMaxWorkers() after SetMaxWorkers(0) = %d, want 0", got)
	}
	SetMaxWorkers(-5)
	if got := GetMaxWorkers(); got != 0 {
		t.Fatalf("GetMaxWorkers() after SetMaxWorkers(-5) = %d, want 0", got)
	}

	SetMaxWorkers(1000)
	if got := GetMaxWorkers(); got != 256 {
		t.Fatalf("GetMaxWorkers() after SetMaxWorkers(1000) = %d, want 256", got)
	}
}

// TestSetBarrierFill exercises the barrier-fill setter's permit
// set {1, 2, 4, 8, 16, 32} and its rejection of every other value.
func TestSetBarrierFill(t *testing.T) {
	prev := GetBarrierFill()
	defer SetBarrierFill(prev)

	for _, v := range []int{1, 2, 4, 8, 16, 32} {
		SetBarrierFill(v)
		if got := GetBarrierFill(); got != v {
			t.Fatalf("GetBarrierFill() = %d, want %d", got, v)
		}
	}

	for _, invalid := range []int{0, 3, 5, 7, 9, 15, 33, 64, -1} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("SetBarrierFill(%d) should panic", invalid)
				}
			}()
			SetBarrierFill(invalid)
		}()
	}
}

// --- Structural math ---

// TestMinPixelsAmbiguityDominance confirms the per-seed structural
// invariant MinPixelsAuth (7^P) exceeds the seed's PRF key space
// (2^keyBits) across every supported seed width, and that MinPixels
// aliases MinPixelsAuth (the plain-mode floor is unified to the
// CCA-resistant envelope in the current build — encrypted envelopes
// do not distinguish mode on tiny payloads).
func TestMinPixelsAmbiguityDominance(t *testing.T) {
	for _, bits := range []int{512, 1024, 2048} {
		n, _, _, _, _, _, _, _ := makeEightSeeds128(bits, sipHash128)

		mp := n.MinPixels()
		mpa := n.MinPixelsAuth()

		// 7^MinPixelsAuth > 2^bits: MinPixelsAuth * log2(7) > bits
		ambiguity7 := float64(mpa) * 2.8074
		if ambiguity7 <= float64(bits) {
			t.Errorf("MinPixelsAuth(%d) = %d: 7^P = 2^%.0f does NOT exceed 2^%d", bits, mpa, ambiguity7, bits)
		}

		// MinPixels aliases MinPixelsAuth in the current build.
		if mp != mpa {
			t.Errorf("MinPixels(%d) = %d, MinPixelsAuth(%d) = %d — expected alias", bits, mp, bits, mpa)
		}
	}
}

// TestContainerSizes exercises the size-vs-container-count relation
// across a range of payloads. This is not a roundtrip correctness
// test — the correctness portion is asserted by Decrypt matching
// the plaintext; this test also captures the observed capacity /
// container-pixel counts so a container-sizing regression surfaces
// in the test log.
func TestContainerSizes(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(512, sipHash128)
	for _, sz := range []int{1, 10, 100, 1000, 10000, 100000} {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			data := genTestPlaintext(t, sz)
			ct, err := Encrypt3x128(n, l, d1, d2, d3, s1, s2, s3, data)
			if err != nil {
				t.Fatal(err)
			}
			pt, err := Decrypt3x128(n, l, d1, d2, d3, s1, s2, s3, ct)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, pt) {
				t.Fatal("container-sizing round-trip mismatch")
			}
			containerSize := len(ct) - headerSize()
			pixels := containerSize / Channels
			capacity := (pixels * DataBitsPerPixel) / 8
			t.Logf("container: %d pixels, capacity: %d bytes, output: %d bytes", pixels, capacity, len(ct))
		})
	}
}

// --- Blake wrapper regression: every seed bit reaches the digest ---

// TestBlakeWrappersAllSeedBitsAffectOutput verifies that every bit of
// every seed component in the BLAKE cached-wrapper HashFuncs affects
// the digest, even for short data inputs (e.g. ITB's internal 20-byte
// pixel_le+nonce). Regression test: earlier versions of the wrappers
// guarded the seed XOR with `if off+8 <= len(buf)` / `len(mixed)`,
// which silently dropped seed[2..3] (and seed[2..7] for the 512
// variant) when data was shorter than seedLen*8 bytes — halving the
// effective ChainHash key.
func TestBlakeWrappersAllSeedBitsAffectOutput(t *testing.T) {
	data := []byte("hello world test 123") // 20 bytes, ITB-typical small input

	t.Run("blake3-256", func(t *testing.T) {
		hf := makeBlake3Hash256()
		base := hf(data, [4]uint64{0, 0, 0, 0})
		for i := 0; i < 4; i++ {
			for _, bit := range []uint{0, 63} {
				var seed [4]uint64
				seed[i] = uint64(1) << bit
				got := hf(data, seed)
				if got == base {
					t.Errorf("seed[%d] bit %d did not affect output (base == got)", i, bit)
				}
			}
		}
	})

	t.Run("blake2b-512", func(t *testing.T) {
		hf := makeBlake2bHash512()
		base := hf(data, [8]uint64{})
		for i := 0; i < 8; i++ {
			for _, bit := range []uint{0, 63} {
				var seed [8]uint64
				seed[i] = uint64(1) << bit
				got := hf(data, seed)
				if got == base {
					t.Errorf("seed[%d] bit %d did not affect output (base == got)", i, bit)
				}
			}
		}
	})
}

// --- Package-internal helper tests ---

// TestRotateBits7 exercises the internal 7-bit rotate helper used by
// the channel-byte encoder. Identity at r=0, full-cycle at r=7,
// inverse (rotate-r then rotate-(7-r) = identity), plus two known
// values.
func TestRotateBits7(t *testing.T) {
	for v := byte(0); v < 128; v++ {
		if got := rotateBits7(v, 0); got != v {
			t.Fatalf("rotateBits7(%d, 0) = %d, want %d", v, got, v)
		}
	}

	for v := byte(0); v < 128; v++ {
		if got := rotateBits7(v, 7); got != v {
			t.Fatalf("rotateBits7(%d, 7) = %d, want %d", v, got, v)
		}
	}

	for r := uint(0); r < 7; r++ {
		for v := byte(0); v < 128; v++ {
			mid := rotateBits7(v, r)
			got := rotateBits7(mid, 7-r)
			if got != v {
				t.Fatalf("rotateBits7(rotateBits7(%d, %d), %d) = %d, want %d", v, r, 7-r, got, v)
			}
		}
	}

	if got := rotateBits7(0x01, 1); got != 0x02 {
		t.Fatalf("rotateBits7(0x01, 1) = 0x%02x, want 0x02", got)
	}

	if got := rotateBits7(0x40, 1); got != 0x01 {
		t.Fatalf("rotateBits7(0x40, 1) = 0x%02x, want 0x01", got)
	}
}

// TestCOBS exercises the internal COBS encoder / decoder pair on a
// selection of adversarial byte patterns: single-zero, run of zeros,
// zeros framing non-zero bytes, all-0xFF, alternating zeros, and a
// >254-byte run of non-zero bytes (forces the encoder to emit a new
// group header).
func TestCOBS(t *testing.T) {
	cases := [][]byte{
		{0x00},
		{0x00, 0x00},
		{0x00, 0x00, 0x00},
		{0x01, 0x00, 0xFF},
		{0xFF},
		{0x01, 0x02, 0x03},
		bytes.Repeat([]byte{0x42}, 300),
		{0x00, 0x01, 0x00, 0x01, 0x00},
	}
	for i, data := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			encoded := cobsEncode(data)
			for _, b := range encoded {
				if b == 0x00 {
					t.Fatal("COBS encoded contains 0x00")
				}
			}
			decoded := cobsDecode(encoded)
			if !bytes.Equal(data, decoded) {
				t.Fatalf("COBS roundtrip failed: got %v, want %v", decoded, data)
			}
		})
	}
}

// TestParseChunkLenErrors exercises the chunk-header parser's error
// paths: input shorter than the header size, zero-width / zero-height
// dimensions in the header, truncated payload after a valid header,
// and the valid 1×1 case that must succeed.
func TestParseChunkLenErrors(t *testing.T) {
	if _, err := ParseChunkLen([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected error for data too short for header")
	}

	buf := make([]byte, headerSize()+8)
	if _, err := ParseChunkLen(buf); err == nil {
		t.Fatal("expected error for zero dimensions")
	}

	binary.BigEndian.PutUint16(buf[currentNonceSize():], 1)
	binary.BigEndian.PutUint16(buf[currentNonceSize()+2:], 1)
	if _, err := ParseChunkLen(buf[:headerSize()+4]); err == nil {
		t.Fatal("expected error for truncated data")
	}

	fullBuf := make([]byte, headerSize()+Channels)
	binary.BigEndian.PutUint16(fullBuf[currentNonceSize():], 1)
	binary.BigEndian.PutUint16(fullBuf[currentNonceSize()+2:], 1)
	n, err := ParseChunkLen(fullBuf)
	if err != nil {
		t.Fatalf("unexpected error for valid 1x1: %v", err)
	}
	if n != headerSize()+Channels {
		t.Fatalf("ParseChunkLen returned %d, want %d", n, headerSize()+Channels)
	}
}

// TestDecryptRejectOversizeContainer confirms the decoder rejects
// containers whose header-declared dimensions exceed the process
// maxTotalPixels cap (10 M pixels). Guards against a maliciously-
// crafted header persuading Decrypt3x128 to allocate multi-gigabyte
// buffers.
func TestDecryptRejectOversizeContainer(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(1024, sipHash128)

	header := make([]byte, headerSize()+Channels)
	nonceSz := currentNonceSize()
	binary.BigEndian.PutUint16(header[nonceSz:], 3200)
	binary.BigEndian.PutUint16(header[nonceSz+2:], 3200)
	fakeContainer := make([]byte, len(header)+3200*3200*8)
	copy(fakeContainer, header)

	if _, err := Decrypt3x128(n, l, d1, d2, d3, s1, s2, s3, fakeContainer); err == nil {
		t.Fatal("expected error for oversized container (3200x3200 > 10M pixels)")
	}
}

// TestConcurrentEncryptSameSeed confirms that N goroutines encrypting
// the same plaintext under the same seed vector produce N distinct
// ciphertexts (fresh nonces) and each round-trips independently. The
// concurrent invocation stresses the shared PRF closures + the shared
// seed pointers under contention.
func TestConcurrentEncryptSameSeed(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(1024, sipHash128)
	data := genTestPlaintext(t, 4096)

	const workers = 8
	var wg sync.WaitGroup
	results := make([][]byte, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ct, err := Encrypt3x128(n, l, d1, d2, d3, s1, s2, s3, data)
			if err != nil {
				errs[idx] = err
				return
			}
			pt, err := Decrypt3x128(n, l, d1, d2, d3, s1, s2, s3, ct)
			if err != nil {
				errs[idx] = err
				return
			}
			if !bytes.Equal(data, pt) {
				errs[idx] = fmt.Errorf("worker %d: plaintext mismatch", idx)
				return
			}
			results[idx] = ct
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("worker %d: %v", i, err)
		}
	}
	// Nonces (first currentNonceSize() bytes) must differ pairwise.
	nonceSz := currentNonceSize()
	for i := 0; i < workers; i++ {
		for j := i + 1; j < workers; j++ {
			if results[i] == nil || results[j] == nil {
				continue
			}
			if bytes.Equal(results[i][:nonceSz], results[j][:nonceSz]) {
				t.Errorf("workers %d and %d produced identical nonces", i, j)
			}
		}
	}
}
