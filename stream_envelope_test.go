package itb

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"testing"
)

// installTestNonce forces every generateNonce call within the test's
// scope — the main-nonce and interlock-nonce draws alike — to return
// an identical byte slice, so the encrypt path is deterministic across
// independent invocations. The nonce contents arrive from the caller —
// the test picks a fixed byte pattern per width. Cleanup restores the
// previous overrides on test exit.
func installTestNonce(t *testing.T, nonce []byte) {
	t.Helper()
	old := testNonceOverride.Load()
	oldIl := testInterlockNonceOverride.Load()
	n := append([]byte(nil), nonce...)
	testNonceOverride.Store(&n)
	il := append([]byte(nil), nonce...)
	testInterlockNonceOverride.Store(&il)
	t.Cleanup(func() {
		testNonceOverride.Store(old)
		testInterlockNonceOverride.Store(oldIl)
	})
}

// testStreamNonceCfg carries the test-scoped nonce width the stream
// envelope tests thread through their Cfg-suffixed calls. Populated by
// [installNonceBits] and reset by that fixture's t.Cleanup. Zero
// (nil) means "no override; use the compile-in default".
var testStreamNonceCfg *Config

// installNonceBits switches the test-scoped nonce width for the
// caller's scope, populating [testStreamNonceCfg] so that tests can
// pass it to *Cfg entry points. Cleanup restores the previous value
// on test exit.
func installNonceBits(t *testing.T, bits int) {
	t.Helper()
	old := testStreamNonceCfg
	testStreamNonceCfg = &Config{NonceBits: bits}
	t.Cleanup(func() {
		testStreamNonceCfg = old
	})
}

// dummy32MAC returns a deterministic 32-byte zero tag for any input.
// The envelope-parity tests use this so the on-wire byte counts are
// determined only by the chunk sizing arithmetic, not by any MAC
// primitive's own state. The AEAD path uses tag length to size the
// container's third snake — a 32-byte tag matches nomacTagStubSize's
// canonical assumption and makes AEAD vs No-MAC chunk widths align.
func dummy32MAC(data []byte) []byte { return make([]byte, 32) }

// seedFixtures128 constructs eight fresh 128-bit Triple-Ouroboros
// seeds keyed by SipHash-2-4. Every seed slot uses the same primitive
// but carries its own random Components under NewSeed128, matching
// the fixture shape the rest of itb_test uses.
func seedFixtures128(t *testing.T, bits int) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *Seed128) {
	t.Helper()
	var err error
	build := func() *Seed128 {
		s, e := NewSeed128(bits, sipHash128)
		if e != nil {
			err = e
		}
		return s
	}
	ns = build()
	ls = build()
	ds1 = build()
	ds2 = build()
	ds3 = build()
	ss1 = build()
	ss2 = build()
	ss3 = build()
	if err != nil {
		t.Fatalf("seedFixtures128: %v", err)
	}
	return
}

// seedFixtures256 constructs eight fresh 256-bit Triple-Ouroboros
// seeds keyed by BLAKE3-256.
func seedFixtures256(t *testing.T, bits int) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *Seed256) {
	t.Helper()
	var err error
	h := makeBlake3Hash256()
	build := func() *Seed256 {
		s, e := NewSeed256(bits, h)
		if e != nil {
			err = e
		}
		return s
	}
	ns = build()
	ls = build()
	ds1 = build()
	ds2 = build()
	ds3 = build()
	ss1 = build()
	ss2 = build()
	ss3 = build()
	if err != nil {
		t.Fatalf("seedFixtures256: %v", err)
	}
	return
}

// seedFixtures512 constructs eight fresh 512-bit Triple-Ouroboros
// seeds keyed by Areion-SoEM-512.
func seedFixtures512(t *testing.T, bits int) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *Seed512) {
	t.Helper()
	var err error
	h, _ := makeAreionSoEM512Pair()
	build := func() *Seed512 {
		s, e := NewSeed512(bits, h)
		if e != nil {
			err = e
		}
		return s
	}
	ns = build()
	ls = build()
	ds1 = build()
	ds2 = build()
	ds3 = build()
	ss1 = build()
	ss2 = build()
	ss3 = build()
	if err != nil {
		t.Fatalf("seedFixtures512: %v", err)
	}
	return
}

// nonceFixture returns a distinctive fixed nonce of the given byte
// length so the test's on-wire chunks are deterministic across runs.
func nonceFixture(nBytes int) []byte {
	buf := make([]byte, nBytes)
	for i := range buf {
		buf[i] = byte(0x40 ^ i)
	}
	return buf
}

// randomPlaintext returns a fresh cryptographic-random plaintext.
func randomPlaintext(t *testing.T, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("randomPlaintext: %v", err)
	}
	return buf
}

// TestStreamEnvelopeParityAEADvsNoMAC verifies that the wire byte
// length of a Streaming AEAD stream equals the wire byte length of
// the corresponding No-MAC stream at every plaintext size — the D18
// mode-ambiguity invariant. The dummy32MAC yields 32-byte tags,
// matching the No-MAC nomacTagStubSize convention. A fixed nonce is
// injected via testNonceOverride so the mask-driven byte
// distribution across the three snakes is identical on both paths,
// which in turn makes COBS-encoded lengths and container sizes
// identical.
func TestStreamEnvelopeParityAEADvsNoMAC(t *testing.T) {
	sizes := []int{1, 6, 63, 64, 65, 1024, 8192, 1 << 20}
	widths := []struct {
		name     string
		nonceLen int
		encrypt  func(t *testing.T, src io.Reader, dst io.Writer, chunkSize int, mac MACFunc, doAEAD bool)
	}{
		{
			name:     "128",
			nonceLen: 16,
			encrypt: func(t *testing.T, src io.Reader, dst io.Writer, chunkSize int, mac MACFunc, doAEAD bool) {
				ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures128(t, 512)
				var err error
				if doAEAD {
					err = EncryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, src, dst, mac, chunkSize)
				} else {
					err = EncryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, src, dst, chunkSize)
				}
				if err != nil {
					t.Fatalf("encrypt (aead=%v): %v", doAEAD, err)
				}
			},
		},
		{
			name:     "256",
			nonceLen: 32,
			encrypt: func(t *testing.T, src io.Reader, dst io.Writer, chunkSize int, mac MACFunc, doAEAD bool) {
				ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures256(t, 512)
				var err error
				if doAEAD {
					err = EncryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, src, dst, mac, chunkSize)
				} else {
					err = EncryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, src, dst, chunkSize)
				}
				if err != nil {
					t.Fatalf("encrypt (aead=%v): %v", doAEAD, err)
				}
			},
		},
		{
			name:     "512",
			nonceLen: 64,
			encrypt: func(t *testing.T, src io.Reader, dst io.Writer, chunkSize int, mac MACFunc, doAEAD bool) {
				ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures512(t, 512)
				var err error
				if doAEAD {
					err = EncryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, src, dst, mac, chunkSize)
				} else {
					err = EncryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, src, dst, chunkSize)
				}
				if err != nil {
					t.Fatalf("encrypt (aead=%v): %v", doAEAD, err)
				}
			},
		},
	}

	for _, w := range widths {
		w := w
		t.Run("w"+w.name, func(t *testing.T) {
			installNonceBits(t, w.nonceLen*8)
			installTestNonce(t, nonceFixture(w.nonceLen))

			for _, sz := range sizes {
				sz := sz
				t.Run(fmt.Sprintf("plaintext=%d", sz), func(t *testing.T) {
					plaintext := randomPlaintext(t, sz)
					chunkSize := 4096

					var aeadWire, plainWire bytes.Buffer
					w.encrypt(t, bytes.NewReader(plaintext), &aeadWire, chunkSize, dummy32MAC, true)
					w.encrypt(t, bytes.NewReader(plaintext), &plainWire, chunkSize, dummy32MAC, false)

					if aeadWire.Len() != plainWire.Len() {
						t.Fatalf("envelope byte-length mismatch at plaintext=%d: aead=%d nomac=%d (diff=%d)",
							sz, aeadWire.Len(), plainWire.Len(), aeadWire.Len()-plainWire.Len())
					}
				})
			}
		})
	}
}

// TestStreamEnvelopeRoundTripByteExact verifies both streaming paths
// recover the original plaintext exactly on round-trip across every
// fixture size and width. The fixed-nonce install applies uniformly
// so any subtle streaming boundary bug (short-final-chunk padding,
// COBS terminator placement inside the reserved tag stub, prefix
// off-by-one) surfaces as a decoded-byte mismatch.
func TestStreamEnvelopeRoundTripByteExact(t *testing.T) {
	sizes := []int{1, 6, 63, 64, 65, 1024, 8192, 1 << 20}

	roundTrip := func(t *testing.T, width int, nonceLen int, plaintext []byte, doAEAD bool) {
		var wire, recovered bytes.Buffer
		switch width {
		case 128:
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures128(t, 512)
			if doAEAD {
				if err := EncryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &wire, dummy32MAC, 4096); err != nil {
					t.Fatalf("AEAD encrypt: %v", err)
				}
				if err := DecryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &wire, &recovered, dummy32MAC); err != nil {
					t.Fatalf("AEAD decrypt: %v", err)
				}
			} else {
				if err := EncryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &wire, 4096); err != nil {
					t.Fatalf("No-MAC encrypt: %v", err)
				}
				if err := DecryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &wire, &recovered); err != nil {
					t.Fatalf("No-MAC decrypt: %v", err)
				}
			}
		case 256:
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures256(t, 512)
			if doAEAD {
				if err := EncryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &wire, dummy32MAC, 4096); err != nil {
					t.Fatalf("AEAD encrypt: %v", err)
				}
				if err := DecryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &wire, &recovered, dummy32MAC); err != nil {
					t.Fatalf("AEAD decrypt: %v", err)
				}
			} else {
				if err := EncryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &wire, 4096); err != nil {
					t.Fatalf("No-MAC encrypt: %v", err)
				}
				if err := DecryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &wire, &recovered); err != nil {
					t.Fatalf("No-MAC decrypt: %v", err)
				}
			}
		case 512:
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures512(t, 512)
			if doAEAD {
				if err := EncryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &wire, dummy32MAC, 4096); err != nil {
					t.Fatalf("AEAD encrypt: %v", err)
				}
				if err := DecryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &wire, &recovered, dummy32MAC); err != nil {
					t.Fatalf("AEAD decrypt: %v", err)
				}
			} else {
				if err := EncryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &wire, 4096); err != nil {
					t.Fatalf("No-MAC encrypt: %v", err)
				}
				if err := DecryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &wire, &recovered); err != nil {
					t.Fatalf("No-MAC decrypt: %v", err)
				}
			}
		}

		got := recovered.Bytes()
		if !bytes.Equal(got, plaintext) {
			t.Fatalf("recovered plaintext mismatch: got %d bytes, want %d", len(got), len(plaintext))
		}
	}

	for _, wCfg := range []struct {
		width, nonceLen int
	}{{128, 16}, {256, 32}, {512, 64}} {
		wCfg := wCfg
		t.Run(fmt.Sprintf("w%d", wCfg.width), func(t *testing.T) {
			installNonceBits(t, wCfg.nonceLen*8)
			installTestNonce(t, nonceFixture(wCfg.nonceLen))
			for _, sz := range sizes {
				sz := sz
				for _, doAEAD := range []bool{true, false} {
					name := "nomac"
					if doAEAD {
						name = "aead"
					}
					t.Run(fmt.Sprintf("size=%d/%s", sz, name), func(t *testing.T) {
						plaintext := randomPlaintext(t, sz)
						roundTrip(t, wCfg.width, wCfg.nonceLen, plaintext, doAEAD)
					})
				}
			}
		})
	}
}

// TestStreamEnvelopeEdgeCases exercises the corner-case plaintext
// sizes (1-byte and larger) across all three nonce widths and both
// AEAD / No-MAC modes. Round-trip byte-exact recovery is the success
// criterion.
func TestStreamEnvelopeEdgeCases(t *testing.T) {
	edges := []int{1, 6, 4096}
	for _, wCfg := range []struct {
		width, nonceLen int
	}{{128, 16}, {256, 32}, {512, 64}} {
		wCfg := wCfg
		t.Run(fmt.Sprintf("w%d", wCfg.width), func(t *testing.T) {
			installNonceBits(t, wCfg.nonceLen*8)
			installTestNonce(t, nonceFixture(wCfg.nonceLen))
			for _, sz := range edges {
				sz := sz
				t.Run(fmt.Sprintf("size=%d", sz), func(t *testing.T) {
					plaintext := randomPlaintext(t, sz)

					// No-MAC round-trip (empty input → empty wire, both
					// sides handle it cleanly).
					var nomacWire, nomacBack bytes.Buffer
					switch wCfg.width {
					case 128:
						ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures128(t, 512)
						if err := EncryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &nomacWire, 4096); err != nil {
							t.Fatalf("No-MAC encrypt: %v", err)
						}
						if err := DecryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &nomacWire, &nomacBack); err != nil {
							t.Fatalf("No-MAC decrypt: %v", err)
						}
					case 256:
						ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures256(t, 512)
						if err := EncryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &nomacWire, 4096); err != nil {
							t.Fatalf("No-MAC encrypt: %v", err)
						}
						if err := DecryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &nomacWire, &nomacBack); err != nil {
							t.Fatalf("No-MAC decrypt: %v", err)
						}
					case 512:
						ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures512(t, 512)
						if err := EncryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &nomacWire, 4096); err != nil {
							t.Fatalf("No-MAC encrypt: %v", err)
						}
						if err := DecryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &nomacWire, &nomacBack); err != nil {
							t.Fatalf("No-MAC decrypt: %v", err)
						}
					}
					if !bytes.Equal(nomacBack.Bytes(), plaintext) {
						t.Fatalf("No-MAC edge %d recovery mismatch", sz)
					}

					// AEAD round-trip; the empty case still emits the
					// terminating chunk, so the wire is not zero even for
					// empty input.
					var aeadWire, aeadBack bytes.Buffer
					switch wCfg.width {
					case 128:
						ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures128(t, 512)
						if err := EncryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &aeadWire, dummy32MAC, 4096); err != nil {
							t.Fatalf("AEAD encrypt: %v", err)
						}
						if err := DecryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &aeadWire, &aeadBack, dummy32MAC); err != nil {
							t.Fatalf("AEAD decrypt: %v", err)
						}
					case 256:
						ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures256(t, 512)
						if err := EncryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &aeadWire, dummy32MAC, 4096); err != nil {
							t.Fatalf("AEAD encrypt: %v", err)
						}
						if err := DecryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &aeadWire, &aeadBack, dummy32MAC); err != nil {
							t.Fatalf("AEAD decrypt: %v", err)
						}
					case 512:
						ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures512(t, 512)
						if err := EncryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &aeadWire, dummy32MAC, 4096); err != nil {
							t.Fatalf("AEAD encrypt: %v", err)
						}
						if err := DecryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &aeadWire, &aeadBack, dummy32MAC); err != nil {
							t.Fatalf("AEAD decrypt: %v", err)
						}
					}
					if !bytes.Equal(aeadBack.Bytes(), plaintext) {
						t.Fatalf("AEAD edge %d recovery mismatch", sz)
					}
				})
			}
		})
	}
}

// TestStreamEnvelopeChunkSizes covers a spread of chunk sizes with
// plaintexts that straddle boundaries — single-chunk, exactly one
// chunk boundary, two chunks, and heavy multi-chunk. Round-trip
// byte-exactness is the correctness check on both AEAD and No-MAC
// paths, so a chunk-boundary off-by-one in the prefix or stub logic
// surfaces here.
func TestStreamEnvelopeChunkSizes(t *testing.T) {
	installNonceBits(t, 128)
	installTestNonce(t, nonceFixture(16))
	chunkSizes := []int{1024, 4096, 16 << 10, 64 << 10}
	multipliers := []float64{0.5, 1.0, 1.25, 3.7}
	for _, cs := range chunkSizes {
		cs := cs
		for _, m := range multipliers {
			m := m
			sz := int(float64(cs) * m)
			if sz < 1 {
				sz = 1
			}
			t.Run(fmt.Sprintf("cs=%d/plaintext=%d", cs, sz), func(t *testing.T) {
				plaintext := randomPlaintext(t, sz)
				ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures128(t, 512)

				// No-MAC round-trip
				var wireA, backA bytes.Buffer
				if err := EncryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &wireA, cs); err != nil {
					t.Fatalf("No-MAC encrypt: %v", err)
				}
				if err := DecryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &wireA, &backA); err != nil {
					t.Fatalf("No-MAC decrypt: %v", err)
				}
				if !bytes.Equal(backA.Bytes(), plaintext) {
					t.Fatalf("No-MAC recovery mismatch at cs=%d sz=%d", cs, sz)
				}

				// AEAD round-trip
				var wireB, backB bytes.Buffer
				if err := EncryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &wireB, dummy32MAC, cs); err != nil {
					t.Fatalf("AEAD encrypt: %v", err)
				}
				if err := DecryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &wireB, &backB, dummy32MAC); err != nil {
					t.Fatalf("AEAD decrypt: %v", err)
				}
				if !bytes.Equal(backB.Bytes(), plaintext) {
					t.Fatalf("AEAD recovery mismatch at cs=%d sz=%d", cs, sz)
				}
			})
		}
	}
}

// TestSingleMessageEnvelopeParityAEADvsNoMAC asserts the on-wire byte
// length of a Single Message AEAD ciphertext equals the byte length
// of the corresponding Single Message No-MAC ciphertext for the same
// plaintext, seeds and nonce. Both paths reserve tagSize + 1 bytes in
// the third snake's container capacity (AEAD: real tag + fixed 0x00
// dummy flag; No-MAC: pure CSPRNG stub via nomacTagStubSize), so the
// two containers round to the identical square and the resulting
// wire byte counts are equal.
func TestSingleMessageEnvelopeParityAEADvsNoMAC(t *testing.T) {
	const plaintextSize = 1024
	for _, wCfg := range []struct {
		width, nonceLen int
	}{{128, 16}, {256, 32}, {512, 64}} {
		wCfg := wCfg
		t.Run(fmt.Sprintf("w%d", wCfg.width), func(t *testing.T) {
			installNonceBits(t, wCfg.nonceLen*8)
			installTestNonce(t, nonceFixture(wCfg.nonceLen))
			plaintext := randomPlaintext(t, plaintextSize)

			var aeadWire, plainWire []byte
			var err error
			switch wCfg.width {
			case 128:
				ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures128(t, 512)
				aeadWire, err = EncryptAuthenticated3x128Cfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, dummy32MAC)
				if err != nil {
					t.Fatalf("AEAD SM encrypt: %v", err)
				}
				plainWire, err = Encrypt3x128Cfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
				if err != nil {
					t.Fatalf("No-MAC SM encrypt: %v", err)
				}
			case 256:
				ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures256(t, 512)
				aeadWire, err = EncryptAuthenticated3x256Cfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, dummy32MAC)
				if err != nil {
					t.Fatalf("AEAD SM encrypt: %v", err)
				}
				plainWire, err = Encrypt3x256Cfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
				if err != nil {
					t.Fatalf("No-MAC SM encrypt: %v", err)
				}
			case 512:
				ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures512(t, 512)
				aeadWire, err = EncryptAuthenticated3x512Cfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, dummy32MAC)
				if err != nil {
					t.Fatalf("AEAD SM encrypt: %v", err)
				}
				plainWire, err = Encrypt3x512Cfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext)
				if err != nil {
					t.Fatalf("No-MAC SM encrypt: %v", err)
				}
			}
			if len(aeadWire) != len(plainWire) {
				t.Fatalf("SM envelope byte-length mismatch on w%d: aead=%d nomac=%d (diff=%d)",
					wCfg.width, len(aeadWire), len(plainWire), len(aeadWire)-len(plainWire))
			}
		})
	}
}

// TestSingleMessageAEADRoundTripAfterStubReservation confirms
// Encrypt then Decrypt on the Single Message AEAD path recovers the
// original plaintext byte-exact across all three widths, catching any
// tag-position or dummy-byte off-by-one introduced by the stub
// reservation.
func TestSingleMessageAEADRoundTripAfterStubReservation(t *testing.T) {
	sizes := []int{1, 6, 63, 64, 65, 1024, 8192, 1 << 20}
	for _, wCfg := range []struct {
		width, nonceLen int
	}{{128, 16}, {256, 32}, {512, 64}} {
		wCfg := wCfg
		t.Run(fmt.Sprintf("w%d", wCfg.width), func(t *testing.T) {
			installNonceBits(t, wCfg.nonceLen*8)
			installTestNonce(t, nonceFixture(wCfg.nonceLen))
			for _, sz := range sizes {
				sz := sz
				t.Run(fmt.Sprintf("size=%d", sz), func(t *testing.T) {
					plaintext := randomPlaintext(t, sz)
					switch wCfg.width {
					case 128:
						ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures128(t, 512)
						ct, err := EncryptAuthenticated3x128Cfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, dummy32MAC)
						if err != nil {
							t.Fatalf("encrypt: %v", err)
						}
						pt, err := DecryptAuthenticated3x128Cfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, dummy32MAC)
						if err != nil {
							t.Fatalf("decrypt: %v", err)
						}
						if !bytes.Equal(pt, plaintext) {
							t.Fatalf("recovered plaintext mismatch: got %d bytes, want %d", len(pt), len(plaintext))
						}
					case 256:
						ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures256(t, 512)
						ct, err := EncryptAuthenticated3x256Cfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, dummy32MAC)
						if err != nil {
							t.Fatalf("encrypt: %v", err)
						}
						pt, err := DecryptAuthenticated3x256Cfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, dummy32MAC)
						if err != nil {
							t.Fatalf("decrypt: %v", err)
						}
						if !bytes.Equal(pt, plaintext) {
							t.Fatalf("recovered plaintext mismatch: got %d bytes, want %d", len(pt), len(plaintext))
						}
					case 512:
						ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures512(t, 512)
						ct, err := EncryptAuthenticated3x512Cfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, dummy32MAC)
						if err != nil {
							t.Fatalf("encrypt: %v", err)
						}
						pt, err := DecryptAuthenticated3x512Cfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, dummy32MAC)
						if err != nil {
							t.Fatalf("decrypt: %v", err)
						}
						if !bytes.Equal(pt, plaintext) {
							t.Fatalf("recovered plaintext mismatch: got %d bytes, want %d", len(pt), len(plaintext))
						}
					}
				})
			}
		})
	}
}

// TestStreamCfgEnvelopeParity_NoMACvsAEAD ratifies the D18
// mode-ambiguity envelope invariants (items 1/2/3) via the Cfg
// IO-Driven path. With a fixed plaintext + fixed 8 seeds
// + fixed nonce + fixed chunkSize, encrypt through both
// [EncryptStream3xCfg] (No-MAC) and [EncryptStreamAuth3xCfg] (AEAD)
// using the same *Config and assert:
//
//  1. Per-chunk byte lengths are identical across the two modes.
//  2. Full-stream byte lengths are identical across the two modes.
//
// The dummy32MAC yields 32-byte tags, matching the No-MAC
// nomacTagStubSize convention; a fixed nonce is injected via
// testNonceOverride so the mask-driven byte distribution across the
// three snakes is identical on both paths, which in turn makes
// COBS-encoded lengths and container sizes identical.
func TestStreamCfgEnvelopeParity_NoMACvsAEAD(t *testing.T) {
	sizes := []int{1, 6, 63, 64, 65, 1024, 8192, 1 << 20}
	widths := []struct {
		name     string
		bits     int
		nonceLen int
	}{
		{"128", 128, 16},
		{"256", 256, 32},
		{"512", 512, 64},
	}

	for _, w := range widths {
		w := w
		t.Run("w"+w.name, func(t *testing.T) {
			installTestNonce(t, nonceFixture(w.nonceLen))
			cfg := &Config{NonceBits: w.bits}

			for _, sz := range sizes {
				sz := sz
				t.Run(fmt.Sprintf("plaintext=%d", sz), func(t *testing.T) {
					plaintext := randomPlaintext(t, sz)
					chunkSize := 4096

					var aeadWire, plainWire bytes.Buffer
					switch w.bits {
					case 128:
						ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures128(t, 512)
						if err := EncryptStreamAuth3xCfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &aeadWire, dummy32MAC, chunkSize); err != nil {
							t.Fatalf("AEAD Cfg encrypt: %v", err)
						}
						if err := EncryptStream3xCfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &plainWire, chunkSize); err != nil {
							t.Fatalf("No-MAC Cfg encrypt: %v", err)
						}
					case 256:
						ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures256(t, 512)
						if err := EncryptStreamAuth3xCfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &aeadWire, dummy32MAC, chunkSize); err != nil {
							t.Fatalf("AEAD Cfg encrypt: %v", err)
						}
						if err := EncryptStream3xCfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &plainWire, chunkSize); err != nil {
							t.Fatalf("No-MAC Cfg encrypt: %v", err)
						}
					case 512:
						ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures512(t, 512)
						if err := EncryptStreamAuth3xCfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &aeadWire, dummy32MAC, chunkSize); err != nil {
							t.Fatalf("AEAD Cfg encrypt: %v", err)
						}
						if err := EncryptStream3xCfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &plainWire, chunkSize); err != nil {
							t.Fatalf("No-MAC Cfg encrypt: %v", err)
						}
					}

					// Full-stream length parity.
					if aeadWire.Len() != plainWire.Len() {
						t.Fatalf("Cfg envelope byte-length mismatch at plaintext=%d: aead=%d nomac=%d (diff=%d)",
							sz, aeadWire.Len(), plainWire.Len(), aeadWire.Len()-plainWire.Len())
					}

					// Per-chunk length parity. Both wires carry a
					// streamIDPrefixLen prefix (streamID on AEAD, dummy
					// prefix on No-MAC) then a sequence of chunks whose
					// header layout ParseChunkLenCfg can walk.
					aeadBytes := aeadWire.Bytes()
					plainBytes := plainWire.Bytes()
					if len(aeadBytes) < streamIDPrefixLen || len(plainBytes) < streamIDPrefixLen {
						// Empty-plaintext-with-No-MAC edge is not in the
						// sizes list; nothing to walk.
						return
					}
					aOff := streamIDPrefixLen
					pOff := streamIDPrefixLen
					for aOff < len(aeadBytes) && pOff < len(plainBytes) {
						aLen, err := ParseChunkLenCfg(cfg, aeadBytes[aOff:])
						if err != nil {
							t.Fatalf("ParseChunkLenCfg (aead) at %d: %v", aOff, err)
						}
						pLen, err := ParseChunkLenCfg(cfg, plainBytes[pOff:])
						if err != nil {
							t.Fatalf("ParseChunkLenCfg (nomac) at %d: %v", pOff, err)
						}
						if aLen != pLen {
							t.Fatalf("per-chunk length mismatch at aead=%d nomac=%d: aead=%d nomac=%d",
								aOff, pOff, aLen, pLen)
						}
						aOff += aLen
						pOff += pLen
					}
					if aOff != len(aeadBytes) || pOff != len(plainBytes) {
						t.Fatalf("wire tail mismatch: aead consumed=%d/%d nomac consumed=%d/%d",
							aOff, len(aeadBytes), pOff, len(plainBytes))
					}
				})
			}
		})
	}
}

// TestStreamEnvelopeNonceWidths exercises each supported nonce width
// (128 / 256 / 512) through a small round-trip on both modes so a
// header-width or nonce-offset regression surfaces on every branch of
// currentNonceSize / headerSize.
func TestStreamEnvelopeNonceWidths(t *testing.T) {
	widths := []struct{ bits, bytes int }{{128, 16}, {256, 32}, {512, 64}}
	for _, w := range widths {
		w := w
		t.Run(fmt.Sprintf("nonce=%d", w.bits), func(t *testing.T) {
			installNonceBits(t, w.bits)
			installTestNonce(t, nonceFixture(w.bytes))
			plaintext := randomPlaintext(t, 4096)
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := seedFixtures128(t, 512)

			var wireA, backA bytes.Buffer
			if err := EncryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &wireA, 4096); err != nil {
				t.Fatalf("No-MAC encrypt: %v", err)
			}
			if err := DecryptStream3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &wireA, &backA); err != nil {
				t.Fatalf("No-MAC decrypt: %v", err)
			}
			if !bytes.Equal(backA.Bytes(), plaintext) {
				t.Fatalf("No-MAC recovery mismatch at nonce=%d", w.bits)
			}

			var wireB, backB bytes.Buffer
			if err := EncryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(plaintext), &wireB, dummy32MAC, 4096); err != nil {
				t.Fatalf("AEAD encrypt: %v", err)
			}
			if err := DecryptStreamAuth3xCfg(testStreamNonceCfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, &wireB, &backB, dummy32MAC); err != nil {
				t.Fatalf("AEAD decrypt: %v", err)
			}
			if !bytes.Equal(backB.Bytes(), plaintext) {
				t.Fatalf("AEAD recovery mismatch at nonce=%d", w.bits)
			}
		})
	}
}
