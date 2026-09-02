package itb

import (
	"bytes"
	"slices"
	"testing"
)

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

// TestDualNonceWireFormat confirms the dual-nonce header layout:
// header is exactly 2N+4 bytes, both nonces sit at their fixed offsets
// and are byte-distinct, the payload begins at 2N+4, and the No MAC and
// MAC single-message wire envelopes remain equal in size (the shipped
// AEAD/No MAC indistinguishability invariant, preserved because both
// grow by the same 2N).
func TestDualNonceWireFormat(t *testing.T) {
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
	if headerSizeCfg(nil) != 2*n+4 {
		t.Fatalf("headerSizeCfg = %d, want %d", headerSizeCfg(nil), 2*n+4)
	}
	mainNonce := ct[:n]
	ilNonce := ct[n : 2*n]
	if bytes.Equal(mainNonce, ilNonce) {
		t.Fatal("main nonce and interlock nonce are byte-identical on the wire")
	}
	// Round-trip still succeeds with the dual-nonce header.
	pt, err := Decrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, data) {
		t.Fatal("round-trip mismatch under dual-nonce header")
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
