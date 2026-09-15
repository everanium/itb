package itb

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

// nonceWidths enumerates the interlock-nonce widths the split has to
// cover. 128 and 512 bits leave a remainder of 1 byte (the extra byte
// lands on lane 0 alone) and 256 bits leaves 2; between them the three
// rows exercise every remainder case.
var nonceWidths = []int{128, 256, 512}

// TestNonceSplitFormula pins the per-lane fragment lengths and offsets
// for every admissible interlock-nonce width and checks the structural
// invariants the encode and decode sides both rely on: the fragments
// tile the nonce exactly, offsets are the running sum of the lengths,
// and no two lanes differ by more than one byte.
func TestNonceSplitFormula(t *testing.T) {
	cases := []struct {
		nonceLen int
		wantLens [3]int
		wantOffs [3]int
	}{
		{16, [3]int{6, 5, 5}, [3]int{0, 6, 11}},
		{32, [3]int{11, 11, 10}, [3]int{0, 11, 22}},
		{64, [3]int{22, 21, 21}, [3]int{0, 22, 43}},
	}
	for _, c := range cases {
		lens, offs := nonceSplit(c.nonceLen)
		if lens != c.wantLens {
			t.Errorf("nonceSplit(%d) lens = %v, want %v", c.nonceLen, lens, c.wantLens)
		}
		if offs != c.wantOffs {
			t.Errorf("nonceSplit(%d) offs = %v, want %v", c.nonceLen, offs, c.wantOffs)
		}
	}

	// Structural invariants over a wider sweep than the shipped widths,
	// so the formula stays correct if another width is ever admitted.
	for n := 0; n <= 128; n++ {
		lens, offs := nonceSplit(n)
		total := 0
		for i := 0; i < 3; i++ {
			if offs[i] != total {
				t.Fatalf("nonceSplit(%d): offs[%d] = %d, want %d", n, i, offs[i], total)
			}
			total += lens[i]
		}
		if total != n {
			t.Fatalf("nonceSplit(%d): fragments total %d", n, total)
		}
		if lens[0]-lens[2] > 1 || lens[0] < lens[2] {
			t.Fatalf("nonceSplit(%d): unbalanced lens %v", n, lens)
		}
	}
}

// TestRecoverInterlockNonceInvertsPlacement confirms the decode-side
// reassembly is the exact inverse of the encode-side lane placement:
// laying each fragment at the front of its lane and then recovering
// returns the original nonce plus the untouched lane remainders.
func TestRecoverInterlockNonceInvertsPlacement(t *testing.T) {
	for _, bits := range nonceWidths {
		nonceLen := bits / 8
		nonce := make([]byte, nonceLen)
		for i := range nonce {
			nonce[i] = byte(0x40 + i)
		}
		lens, offs := nonceSplit(nonceLen)

		const laneLen = 12
		var parts [3][]byte
		var wantLane [3][]byte
		for i := 0; i < 3; i++ {
			lane := make([]byte, lens[i]+laneLen)
			copy(lane[:lens[i]], nonce[offs[i]:offs[i]+lens[i]])
			for j := 0; j < laneLen; j++ {
				lane[lens[i]+j] = byte(0x80 + 16*i + j)
			}
			parts[i] = lane
			wantLane[i] = lane[lens[i]:]
		}

		gotNonce, gotLanes := recoverInterlockNonce(nonceLen, parts)
		if !bytes.Equal(gotNonce, nonce) {
			t.Errorf("%d-bit: recovered nonce %x, want %x", bits, gotNonce, nonce)
		}
		for i := 0; i < 3; i++ {
			if !bytes.Equal(gotLanes[i], wantLane[i]) {
				t.Errorf("%d-bit: lane %d = %x, want %x", bits, i, gotLanes[i], wantLane[i])
			}
		}
	}
}

// TestRecoverInterlockNonceShortLane exercises the clamp that keeps the
// plausible-decryption invariant intact. A wrong-seed decrypt truncates
// each lane at whatever spurious 0x00 the garbage contained, so a lane
// can be shorter than its own fragment or empty outright. The take is
// clamped to the bytes that exist, the rest of the fragment stays zero,
// and the lane keeps the remainder — no error, no panic, one code path.
func TestRecoverInterlockNonceShortLane(t *testing.T) {
	for _, bits := range nonceWidths {
		nonceLen := bits / 8
		lens, offs := nonceSplit(nonceLen)

		// Every combination of lane shapes worth distinguishing: nil,
		// empty, one byte short of the fragment, exactly the fragment,
		// and the fragment plus a remainder.
		shapes := []int{-1, 0, 1, lens[0] - 1, lens[0], lens[0] + 7}
		for _, s0 := range shapes {
			for _, s1 := range shapes {
				for _, s2 := range shapes {
					var parts [3][]byte
					for i, s := range [3]int{s0, s1, s2} {
						if s < 0 {
							continue // leave parts[i] nil
						}
						p := make([]byte, s)
						for j := range p {
							p[j] = byte(0x11 + i)
						}
						parts[i] = p
					}

					gotNonce, gotLanes := recoverInterlockNonce(nonceLen, parts)
					if len(gotNonce) != nonceLen {
						t.Fatalf("%d-bit %v/%v/%v: nonce length %d", bits, s0, s1, s2, len(gotNonce))
					}
					for i := 0; i < 3; i++ {
						take := lens[i]
						if take > len(parts[i]) {
							take = len(parts[i])
						}
						if want := len(parts[i]) - take; len(gotLanes[i]) != want {
							t.Fatalf("%d-bit %v/%v/%v: lane %d length %d, want %d",
								bits, s0, s1, s2, i, len(gotLanes[i]), want)
						}
						// Bytes of the fragment that the lane could not
						// supply stay at their zero value.
						for j := take; j < lens[i]; j++ {
							if gotNonce[offs[i]+j] != 0 {
								t.Fatalf("%d-bit %v/%v/%v: fragment %d byte %d not zero-filled",
									bits, s0, s1, s2, i, j)
							}
						}
					}
				}
			}
		}
	}
}

// TestInterlockNonceRoundTripMatrix walks the full product of hash
// width, nonce width and wire shape. Hash width and nonce width are
// independent axes and the fragment split differs per nonce width, so
// each pairing has to round-trip on its own.
func TestInterlockNonceRoundTripMatrix(t *testing.T) {
	sizes := []int{1, 6, 777, 4096}
	var streamID [32]byte
	for i := range streamID {
		streamID[i] = byte(i)
	}

	for _, bits := range nonceWidths {
		cfg := &Config{NonceBits: bits}
		for _, size := range sizes {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(i * 7)
			}

			t.Run("128", func(t *testing.T) {
				ns, ls, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(512, sipHash128)
				ct, err := Encrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, data)
				if err != nil {
					t.Fatalf("nonce %d size %d: %v", bits, size, err)
				}
				pt, err := Decrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ct)
				if err != nil || !bytes.Equal(pt, data) {
					t.Fatalf("nonce %d size %d: plain round-trip err=%v match=%v", bits, size, err, bytes.Equal(pt, data))
				}

				ctA, err := EncryptAuthenticated3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, data, simpleMACFunc)
				if err != nil {
					t.Fatalf("nonce %d size %d: %v", bits, size, err)
				}
				ptA, err := DecryptAuthenticated3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ctA, simpleMACFunc)
				if err != nil || !bytes.Equal(ptA, data) {
					t.Fatalf("nonce %d size %d: auth round-trip err=%v match=%v", bits, size, err, bytes.Equal(ptA, data))
				}

				ctS, err := EncryptStreamAuthenticated3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, data, simpleMACFunc, streamID, 0, true)
				if err != nil {
					t.Fatalf("nonce %d size %d: %v", bits, size, err)
				}
				ptS, final, err := DecryptStreamAuthenticated3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ctS, simpleMACFunc, streamID, 0)
				if err != nil || !final || !bytes.Equal(ptS, data) {
					t.Fatalf("nonce %d size %d: stream round-trip err=%v final=%v match=%v", bits, size, err, final, bytes.Equal(ptS, data))
				}
			})

			t.Run("256", func(t *testing.T) {
				ns, ls, d1, d2, d3, s1, s2, s3 := makeEightSeeds256(512, makeBlake3Hash256())
				ct, err := Encrypt3x256Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, data)
				if err != nil {
					t.Fatalf("nonce %d size %d: %v", bits, size, err)
				}
				pt, err := Decrypt3x256Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ct)
				if err != nil || !bytes.Equal(pt, data) {
					t.Fatalf("nonce %d size %d: plain round-trip err=%v match=%v", bits, size, err, bytes.Equal(pt, data))
				}

				ctA, err := EncryptAuthenticated3x256Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, data, simpleMACFunc)
				if err != nil {
					t.Fatalf("nonce %d size %d: %v", bits, size, err)
				}
				ptA, err := DecryptAuthenticated3x256Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ctA, simpleMACFunc)
				if err != nil || !bytes.Equal(ptA, data) {
					t.Fatalf("nonce %d size %d: auth round-trip err=%v match=%v", bits, size, err, bytes.Equal(ptA, data))
				}

				ctS, err := EncryptStreamAuthenticated3x256Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, data, simpleMACFunc, streamID, 0, true)
				if err != nil {
					t.Fatalf("nonce %d size %d: %v", bits, size, err)
				}
				ptS, final, err := DecryptStreamAuthenticated3x256Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ctS, simpleMACFunc, streamID, 0)
				if err != nil || !final || !bytes.Equal(ptS, data) {
					t.Fatalf("nonce %d size %d: stream round-trip err=%v final=%v match=%v", bits, size, err, final, bytes.Equal(ptS, data))
				}
			})

			t.Run("512", func(t *testing.T) {
				ns, ls, d1, d2, d3, s1, s2, s3 := makeEightSeeds512(512, makeBlake2bHash512())
				ct, err := Encrypt3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, data)
				if err != nil {
					t.Fatalf("nonce %d size %d: %v", bits, size, err)
				}
				pt, err := Decrypt3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ct)
				if err != nil || !bytes.Equal(pt, data) {
					t.Fatalf("nonce %d size %d: plain round-trip err=%v match=%v", bits, size, err, bytes.Equal(pt, data))
				}

				ctA, err := EncryptAuthenticated3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, data, simpleMACFunc)
				if err != nil {
					t.Fatalf("nonce %d size %d: %v", bits, size, err)
				}
				ptA, err := DecryptAuthenticated3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ctA, simpleMACFunc)
				if err != nil || !bytes.Equal(ptA, data) {
					t.Fatalf("nonce %d size %d: auth round-trip err=%v match=%v", bits, size, err, bytes.Equal(ptA, data))
				}

				ctS, err := EncryptStreamAuthenticated3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, data, simpleMACFunc, streamID, 0, true)
				if err != nil {
					t.Fatalf("nonce %d size %d: %v", bits, size, err)
				}
				ptS, final, err := DecryptStreamAuthenticated3x512Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ctS, simpleMACFunc, streamID, 0)
				if err != nil || !final || !bytes.Equal(ptS, data) {
					t.Fatalf("nonce %d size %d: stream round-trip err=%v final=%v match=%v", bits, size, err, final, bytes.Equal(ptS, data))
				}
			})
		}
	}
}

// TestInterlockNonceEmptyFinalChunk covers the shortest lane the
// encoder ever produces: the terminating Streaming AEAD chunk carries no
// payload, so each lane is its interlock-nonce fragment followed by the
// two bytes the barrier writes for the framed length prefix alone.
func TestInterlockNonceEmptyFinalChunk(t *testing.T) {
	var streamID [32]byte
	for i := range streamID {
		streamID[i] = byte(0xA0 + i)
	}
	for _, bits := range nonceWidths {
		cfg := &Config{NonceBits: bits}
		ns, ls, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(512, sipHash128)
		ct, err := EncryptStreamAuthenticated3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, nil, simpleMACFunc, streamID, 0, true)
		if err != nil {
			t.Fatalf("nonce %d: %v", bits, err)
		}
		pt, final, err := DecryptStreamAuthenticated3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ct, simpleMACFunc, streamID, 0)
		if err != nil {
			t.Fatalf("nonce %d: %v", bits, err)
		}
		if !final {
			t.Fatalf("nonce %d: terminating chunk did not report finalFlag", bits)
		}
		if len(pt) != 0 {
			t.Fatalf("nonce %d: terminating chunk returned %d payload bytes", bits, len(pt))
		}
	}
}

// TestWrongSeedDecryptNeverPanics drives the plausible-decryption
// invariant against a structurally valid wire decrypted under
// independently drawn seeds. Every attempt must return clamped garbage
// with no error and no panic, at every nonce width: the lane prefix
// strip runs on COBS output that truncated at an arbitrary spurious
// 0x00, so a lane routinely arrives shorter than its own fragment.
func TestWrongSeedDecryptNeverPanics(t *testing.T) {
	const attempts = 120
	data := make([]byte, 777)
	for i := range data {
		data[i] = byte(i * 31)
	}

	for _, bits := range nonceWidths {
		cfg := &Config{NonceBits: bits}
		ns, ls, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(512, sipHash128)
		ct, err := Encrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, data)
		if err != nil {
			t.Fatalf("nonce %d: %v", bits, err)
		}
		for i := 0; i < attempts; i++ {
			wn, wl, wd1, wd2, wd3, ws1, ws2, ws3 := makeEightSeeds128(512, sipHash128)
			out, derr := Decrypt3x128Cfg(cfg, wn, wl, wd1, wd2, wd3, ws1, ws2, ws3, ct)
			if derr != nil {
				t.Fatalf("nonce %d attempt %d: wrong-seed decrypt returned an error oracle: %v", bits, i, derr)
			}
			if bytes.Equal(out, data) {
				t.Fatalf("nonce %d attempt %d: wrong seeds recovered the plaintext", bits, i)
			}
		}
	}
}

// TestWireHeaderFormat confirms the wire header layout: the header is
// exactly N+4 bytes (main nonce, width, height), the payload begins at
// N+4, and the No MAC and MAC single-message wire envelopes remain
// equal in size (the shipped AEAD/No MAC indistinguishability
// invariant, preserved because both carry the same header and the same
// per-lane interlock-nonce fragments).
func TestWireHeaderFormat(t *testing.T) {
	n := currentNonceSizeCfg(nil)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	data := bytes.Repeat([]byte{0x42}, 777)

	ct, err := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(ct) < headerSizeCfg(nil)+Channels {
		t.Fatalf("ciphertext shorter than header: %d", len(ct))
	}
	if headerSizeCfg(nil) != n+4 {
		t.Fatalf("headerSizeCfg = %d, want %d", headerSizeCfg(nil), n+4)
	}
	// Round-trip still succeeds with the single-nonce header.
	pt, err := Decrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, data) {
		t.Fatal("round-trip mismatch under the wire header")
	}

	// AEAD / No MAC single-message envelope sizes must match. Small
	// payload (777 B) — the MinPixels floor pads containers, so this
	// primarily verifies that the floor absorbs the reserved-tail
	// difference between simpleMACFunc's 8-byte tag (tagSize+1 = 9
	// reserved) and the No MAC nomacTagStubSizeCfg default (32 + 1 = 33).
	ctMAC, err := EncryptAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	if len(ctMAC) != len(ct) {
		t.Fatalf("MAC/No-MAC envelope size drift (small, 8-byte tag): MAC=%d No-MAC=%d", len(ctMAC), len(ct))
	}

	// Envelope-parity sanity beyond the MinPixels floor: 100 KiB
	// payload well above the floor's absorption range paired with a
	// 32-byte MAC (matching nomacTagStubSizeCfg's default 32 + 1
	// reservation) —
	// the two envelopes must match by construction (identical
	// reserved-tail size), independent of any floor slack.
	mac32Func := func(_ []byte) []byte { return make([]byte, 32) }
	largeData := bytes.Repeat([]byte{0x5A}, 100*1024)
	ctLarge, err := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, largeData)
	if err != nil {
		t.Fatal(err)
	}
	ctLargeMAC, err := EncryptAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, largeData, mac32Func)
	if err != nil {
		t.Fatal(err)
	}
	if len(ctLargeMAC) != len(ctLarge) {
		t.Fatalf("MAC/No-MAC envelope size drift (large, 32-byte tag): MAC=%d No-MAC=%d", len(ctLargeMAC), len(ctLarge))
	}
	// Round-trip the large 32-byte-MAC path to confirm the pair is
	// wire-compatible end-to-end, not only length-equal.
	ptLarge, err := DecryptAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ctLargeMAC, mac32Func)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ptLarge, largeData) {
		t.Fatal("round-trip mismatch on large 32-byte-MAC path")
	}
}

// TestHeaderByteCorruptionRejected pins the wire header's integrity
// coverage: every single-byte corruption anywhere in the header is
// rejected by the authenticated decrypt path. The main nonce drives
// deriveStartPixel, so corrupting it garbles the Pixel Barrier walk and
// the MAC over the recovered payloads fails; the width and height bytes
// are rejected either structurally (dimension and capacity checks) or,
// where the corrupted geometry still parses, by the same MAC. There is
// no header field whose corruption authenticates.
func TestHeaderByteCorruptionRejected(t *testing.T) {
	for _, bits := range nonceWidths {
		cfg := &Config{NonceBits: bits}
		nonceLen := bits / 8
		hdr := headerSizeCfg(cfg)
		if hdr != nonceLen+4 {
			t.Fatalf("nonce %d: headerSizeCfg = %d, want %d", bits, hdr, nonceLen+4)
		}

		ns, ls, d1, d2, d3, s1, s2, s3 := makeEightSeeds128(512, sipHash128)
		data := bytes.Repeat([]byte{0x5A}, 512)
		ct, err := EncryptAuthenticated3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, data, simpleMACFunc)
		if err != nil {
			t.Fatalf("nonce %d: %v", bits, err)
		}
		if pt, err := DecryptAuthenticated3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ct, simpleMACFunc); err != nil || !bytes.Equal(pt, data) {
			t.Fatalf("nonce %d: baseline round-trip err=%v match=%v", bits, err, bytes.Equal(pt, data))
		}

		for i := 0; i < hdr; i++ {
			tampered := bytes.Clone(ct)
			tampered[i] ^= 0x01
			_, err := DecryptAuthenticated3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, tampered, simpleMACFunc)
			if err == nil {
				t.Fatalf("nonce %d: header byte %d corruption authenticated", bits, i)
			}
			// Main-nonce corruption reaches MAC verification and fails
			// there; it is never absorbed by a structural check.
			if i < nonceLen && !errors.Is(err, ErrMACFailure) {
				t.Fatalf("nonce %d: main-nonce byte %d gave %v, want %v", bits, i, err, ErrMACFailure)
			}
		}
	}
}

// TestGenerateNoncePairContract confirms generateNoncePairCfg draws a
// byte-distinct pair on the CSPRNG path, and respects test overrides
// literally (the distinctness re-draw loop must NOT fire when either
// override is installed, so red-team fixtures can force a both-collide
// scenario).
func TestGenerateNoncePairContract(t *testing.T) {
	// CSPRNG path: distinct by construction.
	m, il, err := generateNoncePairCfg(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(m, il) {
		t.Fatal("CSPRNG pair returned byte-identical nonces")
	}

	// Override path: identical overrides are respected literally
	// (loop bypassed), enabling the both-collide red-team class.
	fixed := bytes.Repeat([]byte{0x11}, currentNonceSizeCfg(nil))
	cp1 := slices.Clone(fixed)
	cp2 := slices.Clone(fixed)
	testNonceOverride.Store(&cp1)
	testInterlockNonceOverride.Store(&cp2)
	defer func() {
		testNonceOverride.Store(nil)
		testInterlockNonceOverride.Store(nil)
	}()
	m2, il2, err := generateNoncePairCfg(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m2, fixed) || !bytes.Equal(il2, fixed) {
		t.Fatal("override path did not return the forced identical pair (loop fired on override path)")
	}
}

// TestInterlockDomainTagDecorrelated confirms the interlock derivation
// (domain tag 0x04) produces output distinct from the startPixel-domain
// ChainHash (tag 0x02) of the SAME seed material and nonce. Using one
// seed for both derivations is the byte-identical worst case: the tag
// separation must keep the two full PRF outputs independent regardless.
func TestInterlockDomainTagDecorrelated(t *testing.T) {
	nonce := bytes.Repeat([]byte{0xA5}, currentNonceSizeCfg(nil))

	t.Run("512", func(t *testing.T) {
		s, _ := NewSeed512(512, makeBlake2bHash512())
		startBuf := append([]byte{0x02}, nonce...)
		startFull := s.ChainHash512(startBuf) // startPixel-domain full output
		lockFull := s.deriveInterLockSeed(nonce)
		if startFull == lockFull {
			t.Fatal("512: interlock (0x04) output equals startPixel-domain (0x02) output")
		}
	})
	t.Run("256", func(t *testing.T) {
		s, _ := NewSeed256(512, makeBlake3Hash256())
		startBuf := append([]byte{0x02}, nonce...)
		startFull := s.ChainHash256(startBuf)
		lockFull := s.deriveInterLockSeed(nonce)
		if startFull == lockFull {
			t.Fatal("256: interlock (0x04) output equals startPixel-domain (0x02) output")
		}
	})
	t.Run("128", func(t *testing.T) {
		s, _ := NewSeed128(512, sipHash128)
		startBuf := append([]byte{0x02}, nonce...)
		startLo, startHi := s.ChainHash128(startBuf)
		lockLo, lockHi := s.deriveInterLockSeed(nonce)
		if startLo == lockLo && startHi == lockHi {
			t.Fatal("128: interlock (0x04) output equals startPixel-domain (0x02) output")
		}
	})
}

// TestValueDistinctSeedsRejected confirms that byte-identical Components
// in two different-pointer seed slots are rejected by checkEightSeeds on
// every width and on both the encrypt and decrypt entry points. This is
// the value-distinct fix: pointer-only comparison would pass such a pair
// (fresh pointers wrap identical material — exactly what blob import and
// the low-level constructors can produce), collapsing the per-slot
// derivations that keep the seed roles independent.
func TestValueDistinctSeedsRejected(t *testing.T) {
	t.Run("128", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
		// lockSeed made byte-identical to startSeed1 via a fresh slice
		// (distinct pointer, identical content) — the collision the
		// pointer-only check missed.
		ls.Components = slices.Clone(ss1.Components)
		if _, err := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, []byte("hello world")); err == nil {
			t.Fatal("Encrypt3x128Cfg accepted byte-identical lock/start seeds")
		}
		if _, err := Decrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, make([]byte, headerSizeCfg(nil)+Channels)); err == nil {
			t.Fatal("Decrypt3x128Cfg accepted byte-identical lock/start seeds")
		}
	})
	t.Run("256", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
		ls.Components = slices.Clone(ss1.Components)
		if _, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, []byte("hello world")); err == nil {
			t.Fatal("Encrypt3x256Cfg accepted byte-identical lock/start seeds")
		}
		if _, err := Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, make([]byte, headerSizeCfg(nil)+Channels)); err == nil {
			t.Fatal("Decrypt3x256Cfg accepted byte-identical lock/start seeds")
		}
	})
	t.Run("512", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
		ls.Components = slices.Clone(ss1.Components)
		if _, err := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, []byte("hello world")); err == nil {
			t.Fatal("Encrypt3x512Cfg accepted byte-identical lock/start seeds")
		}
		if _, err := Decrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, make([]byte, headerSizeCfg(nil)+Channels)); err == nil {
			t.Fatal("Decrypt3x512Cfg accepted byte-identical lock/start seeds")
		}
	})
}
