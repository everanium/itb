package itb

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
)

// smFixture bundles one width's Single Message and streaming entry
// points behind width-less closures so the prefix tests below run the
// same assertions at every hash width.
type smFixture struct {
	width       int
	encrypt     func(cfg *Config, data []byte) ([]byte, error)
	decrypt     func(cfg *Config, wire []byte) ([]byte, error)
	encryptAuth func(cfg *Config, data []byte, mac MACFunc) ([]byte, error)
	decryptAuth func(cfg *Config, wire []byte, mac MACFunc) ([]byte, error)
	// encryptChunkAuth is the per-chunk Streaming AEAD entry, used to
	// build a non-terminating chunk by hand.
	encryptChunkAuth  func(cfg *Config, data []byte, mac MACFunc, streamID [streamIDPrefixLen]byte, offset uint64, finalFlag bool) ([]byte, error)
	encryptStream     func(cfg *Config, data []byte, chunkSize int, emit func([]byte) error) error
	encryptStreamAuth func(cfg *Config, data []byte, chunkSize int, mac MACFunc, emit func([]byte) error) error
}

// smFixtures builds the three width fixtures over fresh seed sets.
func smFixtures(t *testing.T) []smFixture {
	t.Helper()
	n1, l1, a1, b1, c1, x1, y1, z1 := seedFixtures128(t, 512)
	n2, l2, a2, b2, c2, x2, y2, z2 := seedFixtures256(t, 512)
	n3, l3, a3, b3, c3, x3, y3, z3 := seedFixtures512(t, 512)
	return []smFixture{
		{
			width: 128,
			encrypt: func(cfg *Config, data []byte) ([]byte, error) {
				return Encrypt3x128Cfg(cfg, n1, l1, a1, b1, c1, x1, y1, z1, data)
			},
			decrypt: func(cfg *Config, wire []byte) ([]byte, error) {
				return Decrypt3x128Cfg(cfg, n1, l1, a1, b1, c1, x1, y1, z1, wire)
			},
			encryptAuth: func(cfg *Config, data []byte, mac MACFunc) ([]byte, error) {
				return EncryptAuthenticated3x128Cfg(cfg, n1, l1, a1, b1, c1, x1, y1, z1, data, mac)
			},
			decryptAuth: func(cfg *Config, wire []byte, mac MACFunc) ([]byte, error) {
				return DecryptAuthenticated3x128Cfg(cfg, n1, l1, a1, b1, c1, x1, y1, z1, wire, mac)
			},
			encryptChunkAuth: func(cfg *Config, data []byte, mac MACFunc, sid [streamIDPrefixLen]byte, off uint64, fin bool) ([]byte, error) {
				return EncryptStreamAuthenticated3x128Cfg(cfg, n1, l1, a1, b1, c1, x1, y1, z1, data, mac, sid, nil, off, fin)
			},
			encryptStream: func(cfg *Config, data []byte, cs int, emit func([]byte) error) error {
				return EncryptStream3x128Cfg(cfg, n1, l1, a1, b1, c1, x1, y1, z1, data, cs, emit)
			},
			encryptStreamAuth: func(cfg *Config, data []byte, cs int, mac MACFunc, emit func([]byte) error) error {
				return EncryptStreamAuth3x128Cfg(cfg, n1, l1, a1, b1, c1, x1, y1, z1, data, cs, mac, emit)
			},
		},
		{
			width: 256,
			encrypt: func(cfg *Config, data []byte) ([]byte, error) {
				return Encrypt3x256Cfg(cfg, n2, l2, a2, b2, c2, x2, y2, z2, data)
			},
			decrypt: func(cfg *Config, wire []byte) ([]byte, error) {
				return Decrypt3x256Cfg(cfg, n2, l2, a2, b2, c2, x2, y2, z2, wire)
			},
			encryptAuth: func(cfg *Config, data []byte, mac MACFunc) ([]byte, error) {
				return EncryptAuthenticated3x256Cfg(cfg, n2, l2, a2, b2, c2, x2, y2, z2, data, mac)
			},
			decryptAuth: func(cfg *Config, wire []byte, mac MACFunc) ([]byte, error) {
				return DecryptAuthenticated3x256Cfg(cfg, n2, l2, a2, b2, c2, x2, y2, z2, wire, mac)
			},
			encryptChunkAuth: func(cfg *Config, data []byte, mac MACFunc, sid [streamIDPrefixLen]byte, off uint64, fin bool) ([]byte, error) {
				return EncryptStreamAuthenticated3x256Cfg(cfg, n2, l2, a2, b2, c2, x2, y2, z2, data, mac, sid, nil, off, fin)
			},
			encryptStream: func(cfg *Config, data []byte, cs int, emit func([]byte) error) error {
				return EncryptStream3x256Cfg(cfg, n2, l2, a2, b2, c2, x2, y2, z2, data, cs, emit)
			},
			encryptStreamAuth: func(cfg *Config, data []byte, cs int, mac MACFunc, emit func([]byte) error) error {
				return EncryptStreamAuth3x256Cfg(cfg, n2, l2, a2, b2, c2, x2, y2, z2, data, cs, mac, emit)
			},
		},
		{
			width: 512,
			encrypt: func(cfg *Config, data []byte) ([]byte, error) {
				return Encrypt3x512Cfg(cfg, n3, l3, a3, b3, c3, x3, y3, z3, data)
			},
			decrypt: func(cfg *Config, wire []byte) ([]byte, error) {
				return Decrypt3x512Cfg(cfg, n3, l3, a3, b3, c3, x3, y3, z3, wire)
			},
			encryptAuth: func(cfg *Config, data []byte, mac MACFunc) ([]byte, error) {
				return EncryptAuthenticated3x512Cfg(cfg, n3, l3, a3, b3, c3, x3, y3, z3, data, mac)
			},
			decryptAuth: func(cfg *Config, wire []byte, mac MACFunc) ([]byte, error) {
				return DecryptAuthenticated3x512Cfg(cfg, n3, l3, a3, b3, c3, x3, y3, z3, wire, mac)
			},
			encryptChunkAuth: func(cfg *Config, data []byte, mac MACFunc, sid [streamIDPrefixLen]byte, off uint64, fin bool) ([]byte, error) {
				return EncryptStreamAuthenticated3x512Cfg(cfg, n3, l3, a3, b3, c3, x3, y3, z3, data, mac, sid, nil, off, fin)
			},
			encryptStream: func(cfg *Config, data []byte, cs int, emit func([]byte) error) error {
				return EncryptStream3x512Cfg(cfg, n3, l3, a3, b3, c3, x3, y3, z3, data, cs, emit)
			},
			encryptStreamAuth: func(cfg *Config, data []byte, cs int, mac MACFunc, emit func([]byte) error) error {
				return EncryptStreamAuth3x512Cfg(cfg, n3, l3, a3, b3, c3, x3, y3, z3, data, cs, mac, emit)
			},
		},
	}
}

// smNonceCfgs enumerates the nonce widths the Single Message prefix
// tests run under; the header size follows the nonce width, the
// prefix does not.
var smNonceCfgs = []*Config{nil, {NonceBits: 128}, {NonceBits: 256}, {NonceBits: 512}}

// TestSingleMessagePrefixLength pins the Single Message wire length on
// both arms at every hash width and nonce width: 32 prefix bytes, then
// the N+4 header, then W·H·8 container bytes, where W and H are the
// dimensions the header behind the prefix announces. The one chunk
// behind the prefix therefore parses as exactly the remainder of the
// wire, and the MAC and No MAC wires are the same length.
func TestSingleMessagePrefixLength(t *testing.T) {
	mac := makeTagMAC(32)
	for _, fx := range smFixtures(t) {
		fx := fx
		for _, cfg := range smNonceCfgs {
			cfg := cfg
			t.Run(fmt.Sprintf("w%d/nonce=%d", fx.width, currentNonceSizeCfg(cfg)*8), func(t *testing.T) {
				for _, sz := range []int{1, 777, 4096, 100 * 1024} {
					data := randomPlaintext(t, sz)
					plain, err := fx.encrypt(cfg, data)
					if err != nil {
						t.Fatalf("No MAC encrypt %d B: %v", sz, err)
					}
					auth, err := fx.encryptAuth(cfg, data, mac)
					if err != nil {
						t.Fatalf("MAC encrypt %d B: %v", sz, err)
					}
					for name, wire := range map[string][]byte{"nomac": plain, "mac": auth} {
						chunkLen, perr := ParseChunkLenCfg(cfg, wire[streamIDPrefixLen:])
						if perr != nil {
							t.Fatalf("%s %d B: header does not parse behind the prefix: %v", name, sz, perr)
						}
						if got, want := len(wire), streamIDPrefixLen+chunkLen; got != want {
							t.Fatalf("%s %d B: wire length %d, want prefix+chunk %d", name, sz, got, want)
						}
						if (chunkLen-headerSizeCfg(cfg))%Channels != 0 {
							t.Fatalf("%s %d B: container length %d is not a whole number of pixels", name, sz, chunkLen-headerSizeCfg(cfg))
						}
					}
					if len(plain) != len(auth) {
						t.Fatalf("%d B: No MAC wire %d B, MAC wire %d B", sz, len(plain), len(auth))
					}
					back, err := fx.decrypt(cfg, plain)
					if err != nil || !bytes.Equal(back, data) {
						t.Fatalf("No MAC round-trip %d B: err=%v match=%v", sz, err, bytes.Equal(back, data))
					}
					back, err = fx.decryptAuth(cfg, auth, mac)
					if err != nil || !bytes.Equal(back, data) {
						t.Fatalf("MAC round-trip %d B: err=%v match=%v", sz, err, bytes.Equal(back, data))
					}
				}
			})
		}
	}
}

// TestSingleMessagePrefixBoundIntoMAC confirms the MAC Authenticated
// prefix is the streamID the MAC covers: flipping any one of its 32
// bytes fails verification with [ErrMACFailure] at every hash width.
// On the No MAC arm the prefix is a dummy the decoder skips, so the
// same flips decrypt cleanly — the two arms differ only in whether the
// prefix is authenticated, never in shape. A keyed MAC is required
// here: a constant-tag stand-in would verify any prefix.
func TestSingleMessagePrefixBoundIntoMAC(t *testing.T) {
	mac := newHMACBlake3Bench(bytes.Repeat([]byte{0x5C}, 32))
	for _, fx := range smFixtures(t) {
		fx := fx
		t.Run(fmt.Sprintf("w%d", fx.width), func(t *testing.T) {
			data := randomPlaintext(t, 2048)
			auth, err := fx.encryptAuth(nil, data, mac)
			if err != nil {
				t.Fatalf("MAC encrypt: %v", err)
			}
			for i := 0; i < streamIDPrefixLen; i++ {
				tampered := bytes.Clone(auth)
				tampered[i] ^= 0x80
				if _, err := fx.decryptAuth(nil, tampered, mac); !errors.Is(err, ErrMACFailure) {
					t.Fatalf("prefix byte %d flipped: got %v, want %v", i, err, ErrMACFailure)
				}
			}
			plain, err := fx.encrypt(nil, data)
			if err != nil {
				t.Fatalf("No MAC encrypt: %v", err)
			}
			for i := 0; i < streamIDPrefixLen; i++ {
				tampered := bytes.Clone(plain)
				tampered[i] ^= 0x80
				back, err := fx.decrypt(nil, tampered)
				if err != nil || !bytes.Equal(back, data) {
					t.Fatalf("No MAC prefix byte %d flipped: err=%v match=%v, want clean decrypt", i, err, bytes.Equal(back, data))
				}
			}
		})
	}
}

// TestSingleMessageAuthRequiresFinalFlag pins the mirror of the
// streaming terminator check on the MAC Authenticated Single Message
// decoder: a chunk whose final flag is not set, placed behind its own
// streamID, is rejected with [ErrStreamTruncated] rather than
// decrypted.
func TestSingleMessageAuthRequiresFinalFlag(t *testing.T) {
	mac := newHMACBlake3Bench(bytes.Repeat([]byte{0x36}, 32))
	for _, fx := range smFixtures(t) {
		fx := fx
		t.Run(fmt.Sprintf("w%d", fx.width), func(t *testing.T) {
			data := randomPlaintext(t, 1024)
			streamID, err := generateStreamID()
			if err != nil {
				t.Fatal(err)
			}
			chunk, err := fx.encryptChunkAuth(nil, data, mac, streamID, 0, false)
			if err != nil {
				t.Fatalf("chunk encrypt: %v", err)
			}
			wire := append(append([]byte(nil), streamID[:]...), chunk...)
			if _, err := fx.decryptAuth(nil, wire, mac); !errors.Is(err, ErrStreamTruncated) {
				t.Fatalf("non-terminating chunk: got %v, want %v", err, ErrStreamTruncated)
			}
			// The same chunk with the flag set decrypts.
			final, err := fx.encryptChunkAuth(nil, data, mac, streamID, 0, true)
			if err != nil {
				t.Fatalf("final chunk encrypt: %v", err)
			}
			wire = append(append([]byte(nil), streamID[:]...), final...)
			back, err := fx.decryptAuth(nil, wire, mac)
			if err != nil || !bytes.Equal(back, data) {
				t.Fatalf("terminating chunk: err=%v match=%v", err, bytes.Equal(back, data))
			}
		})
	}
}

// TestSingleMessageDecryptRejectsShortWire pins the length floor of
// the Single Message decoders: a wire that is shorter than the prefix
// plus the header plus one pixel is rejected before any parse, on both
// arms, and an empty wire is [ErrEmptyInput].
func TestSingleMessageDecryptRejectsShortWire(t *testing.T) {
	mac := makeTagMAC(32)
	for _, fx := range smFixtures(t) {
		fx := fx
		t.Run(fmt.Sprintf("w%d", fx.width), func(t *testing.T) {
			if _, err := fx.decrypt(nil, nil); !errors.Is(err, ErrEmptyInput) {
				t.Fatalf("No MAC empty: got %v, want %v", err, ErrEmptyInput)
			}
			if _, err := fx.decryptAuth(nil, nil, mac); !errors.Is(err, ErrEmptyInput) {
				t.Fatalf("MAC empty: got %v, want %v", err, ErrEmptyInput)
			}
			floor := streamIDPrefixLen + headerSizeCfg(nil) + Channels
			for _, n := range []int{1, streamIDPrefixLen, floor - 1} {
				if _, err := fx.decrypt(nil, make([]byte, n)); err == nil {
					t.Fatalf("No MAC accepted a %d-byte wire below the %d-byte floor", n, floor)
				}
				if _, err := fx.decryptAuth(nil, make([]byte, n), mac); err == nil {
					t.Fatalf("MAC accepted a %d-byte wire below the %d-byte floor", n, floor)
				}
			}
		})
	}
}

// TestStreamingChunkRecordShape pins the streaming wire shape on both
// arms: every emitted piece is one chunk record — a 32-byte prefix
// followed by one chunk whose header sits at offset 32 and whose
// announced length is the rest of the piece — so every record has the
// shape of a Single Message wire. On the MAC arm the prefixes of the
// later records are fresh values, distinct from the streamID ahead of
// record 0 and from each other. A one-chunk stream is byte-shape
// identical to the Single Message wire for the same plaintext: same
// total length, same header offset.
func TestStreamingChunkRecordShape(t *testing.T) {
	mac := makeTagMAC(32)
	for _, fx := range smFixtures(t) {
		fx := fx
		for _, cfg := range smNonceCfgs {
			cfg := cfg
			t.Run(fmt.Sprintf("w%d/nonce=%d", fx.width, currentNonceSizeCfg(cfg)*8), func(t *testing.T) {
				data := randomPlaintext(t, 3*4096+13)
				for _, arm := range []string{"nomac", "mac"} {
					var pieces [][]byte
					collect := func(chunk []byte) error {
						pieces = append(pieces, bytes.Clone(chunk))
						return nil
					}
					var err error
					if arm == "mac" {
						err = fx.encryptStreamAuth(cfg, data, 4096, mac, collect)
					} else {
						err = fx.encryptStream(cfg, data, 4096, collect)
					}
					if err != nil {
						t.Fatalf("%s stream encrypt: %v", arm, err)
					}
					if len(pieces) != 4 {
						t.Fatalf("%s: %d pieces emitted, want 4 chunk records", arm, len(pieces))
					}
					seen := map[string]int{}
					for i, rec := range pieces {
						if len(rec) <= streamIDPrefixLen {
							t.Fatalf("%s record %d: %d B, no room for a chunk behind the prefix", arm, i, len(rec))
						}
						n, perr := ParseChunkLenCfg(cfg, rec[streamIDPrefixLen:])
						if perr != nil {
							t.Fatalf("%s record %d: header does not sit at offset %d: %v", arm, i, streamIDPrefixLen, perr)
						}
						if streamIDPrefixLen+n != len(rec) {
							t.Fatalf("%s record %d: prefix + announced %d B, emitted %d B", arm, i, n, len(rec))
						}
						key := string(rec[:streamIDPrefixLen])
						if j, dup := seen[key]; dup {
							t.Fatalf("%s: records %d and %d travel behind the same prefix", arm, j, i)
						}
						seen[key] = i
					}
				}

				// One-chunk stream versus Single Message: same shape.
				small := randomPlaintext(t, 1500)
				var stream []byte
				if err := fx.encryptStream(cfg, small, 0, func(chunk []byte) error {
					stream = append(stream, chunk...)
					return nil
				}); err != nil {
					t.Fatalf("one-chunk stream encrypt: %v", err)
				}
				single, err := fx.encrypt(cfg, small)
				if err != nil {
					t.Fatalf("Single Message encrypt: %v", err)
				}
				if len(stream) != len(single) {
					t.Fatalf("one-chunk stream %d B, Single Message %d B", len(stream), len(single))
				}
				ns, err1 := ParseChunkLenCfg(cfg, stream[streamIDPrefixLen:])
				nm, err2 := ParseChunkLenCfg(cfg, single[streamIDPrefixLen:])
				if err1 != nil || err2 != nil || ns != nm || ns != len(single)-streamIDPrefixLen {
					t.Fatalf("header offset mismatch: stream (%d, %v) vs Single Message (%d, %v)", ns, err1, nm, err2)
				}
			})
		}
	}
}

// TestSingleMessageRejectsTrailingBytes pins the exact-length contract
// of the Single Message decoders on both arms at every hash width: the
// wire is the prefix plus the one chunk its header announces, and any
// byte past that — a stray tail or the further chunks of a multi-chunk
// stream — is rejected. On the MAC arm the rejection precedes the MAC:
// the MAC closure is never invoked on an over-long wire, which a
// counting wrapper confirms, so the check is key-independent.
func TestSingleMessageRejectsTrailingBytes(t *testing.T) {
	inner := newHMACBlake3Bench(bytes.Repeat([]byte{0x7A}, 32))
	for _, fx := range smFixtures(t) {
		fx := fx
		t.Run(fmt.Sprintf("w%d", fx.width), func(t *testing.T) {
			data := randomPlaintext(t, 3000)
			plain, err := fx.encrypt(nil, data)
			if err != nil {
				t.Fatalf("No MAC encrypt: %v", err)
			}
			auth, err := fx.encryptAuth(nil, data, inner)
			if err != nil {
				t.Fatalf("MAC encrypt: %v", err)
			}
			macCalls := 0
			counting := func(b []byte) []byte {
				macCalls++
				return inner(b)
			}
			for _, tail := range []int{1, 7, Channels, 4096} {
				long := append(bytes.Clone(plain), make([]byte, tail)...)
				if _, err := fx.decrypt(nil, long); err == nil {
					t.Fatalf("No MAC accepted %d trailing bytes", tail)
				}
				long = append(bytes.Clone(auth), make([]byte, tail)...)
				macCalls = 0
				if _, err := fx.decryptAuth(nil, long, counting); err == nil {
					t.Fatalf("MAC accepted %d trailing bytes", tail)
				}
				if macCalls != 0 {
					t.Fatalf("MAC closure ran %d times on a wire with %d trailing bytes; the length check must precede the MAC", macCalls, tail)
				}
			}

			// A multi-chunk stream is several chunk records; the first
			// record parses and the rest is the over-length.
			big := randomPlaintext(t, 3*2048+5)
			for _, arm := range []string{"nomac", "mac"} {
				var stream []byte
				var n int
				collect := func(piece []byte) error {
					n++
					stream = append(stream, piece...)
					return nil
				}
				var err error
				if arm == "mac" {
					err = fx.encryptStreamAuth(nil, big, 2048, inner, collect)
				} else {
					err = fx.encryptStream(nil, big, 2048, collect)
				}
				if err != nil {
					t.Fatalf("%s stream encrypt: %v", arm, err)
				}
				if n < 2 {
					t.Fatalf("%s: %d pieces emitted, want at least two chunk records", arm, n)
				}
				if arm == "mac" {
					macCalls = 0
					if _, err := fx.decryptAuth(nil, stream, counting); err == nil {
						t.Fatal("MAC Single Message decoder accepted a multi-chunk stream")
					}
					if macCalls != 0 {
						t.Fatalf("MAC closure ran %d times on a multi-chunk stream", macCalls)
					}
				} else if _, err := fx.decrypt(nil, stream); err == nil {
					t.Fatal("No MAC Single Message decoder accepted a multi-chunk stream")
				}
			}

			// The exact wire still decrypts on both arms.
			if back, err := fx.decrypt(nil, plain); err != nil || !bytes.Equal(back, data) {
				t.Fatalf("No MAC exact wire: err=%v match=%v", err, bytes.Equal(back, data))
			}
			if back, err := fx.decryptAuth(nil, auth, inner); err != nil || !bytes.Equal(back, data) {
				t.Fatalf("MAC exact wire: err=%v match=%v", err, bytes.Equal(back, data))
			}
		})
	}
}

// TestSingleMessageAuthEmptyTranscript pins the one zero-payload wire
// the MAC Authenticated Single Message decoder accepts: a terminating
// Streaming AEAD chunk encoding no bytes, placed behind its own
// streamID, is a complete and authentic transcript and decrypts to an
// empty plaintext with a nil error at every hash width. Tampering with
// its streamID still fails verification.
func TestSingleMessageAuthEmptyTranscript(t *testing.T) {
	mac := newHMACBlake3Bench(bytes.Repeat([]byte{0x4D}, 32))
	for _, fx := range smFixtures(t) {
		fx := fx
		t.Run(fmt.Sprintf("w%d", fx.width), func(t *testing.T) {
			streamID, err := generateStreamID()
			if err != nil {
				t.Fatal(err)
			}
			chunk, err := fx.encryptChunkAuth(nil, nil, mac, streamID, 0, true)
			if err != nil {
				t.Fatalf("empty terminating chunk: %v", err)
			}
			wire := append(append([]byte(nil), streamID[:]...), chunk...)
			back, err := fx.decryptAuth(nil, wire, mac)
			if err != nil {
				t.Fatalf("empty transcript: %v", err)
			}
			if len(back) != 0 {
				t.Fatalf("empty transcript decrypted to %d bytes", len(back))
			}
			// A flipped streamID byte always reaches the MAC (a container
			// bit may land on a noise bit the decoder ignores).
			tampered := bytes.Clone(wire)
			tampered[0] ^= 0x01
			if _, err := fx.decryptAuth(nil, tampered, mac); !errors.Is(err, ErrMACFailure) {
				t.Fatalf("tampered empty transcript: got %v, want %v", err, ErrMACFailure)
			}
		})
	}
}

// goldenSingleMessagePlain, goldenSingleMessageKey and
// goldenSingleMessageSeeds fix the inputs of the known-answer wires.
var (
	goldenSingleMessagePlain = []byte("Single Message wire known-answer plaintext")
	goldenSingleMessageKey   = []byte("single-message golden HMAC key 0")
)

func goldenSingleMessageSeeds(t *testing.T) [8]*Seed128 {
	t.Helper()
	var out [8]*Seed128
	for i := range out {
		c := make([]uint64, 8)
		for j := range c {
			c[j] = 0x9E3779B97F4A7C15*uint64(i*8+j+1) ^ 0xD1B54A32D192ED03
		}
		s, err := SeedFromComponents128(sipHash128, c...)
		if err != nil {
			t.Fatal(err)
		}
		out[i] = s
	}
	return out
}

// TestSingleMessageWireKnownAnswer pins the Single Message wire on both
// arms against fixed known-answer wires. The MAC arm's wire verifies,
// which holds only while the MAC input of chunk 0 — payloads ‖
// streamID ‖ offset ‖ flag — is unchanged, and both wires decode
// through the Single Message entries and, as one-record streams,
// through the User-Driven Loop and IO-Driven stream decoders. A wire
// whose streamID is altered fails the MAC.
func TestSingleMessageWireKnownAnswer(t *testing.T) {
	s := goldenSingleMessageSeeds(t)
	cfg := &Config{NonceBits: 128}
	mac := func(d []byte) []byte {
		h := hmac.New(sha256.New, goldenSingleMessageKey)
		h.Write(d)
		return h.Sum(nil)
	}
	if os.Getenv("ITB_KAT_PRINT") != "" {
		// Regeneration path: emit fresh known-answer wires for the
		// constants below (the nonces are drawn fresh, so any run yields
		// a valid pair).
		nomac, err := Encrypt3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], goldenSingleMessagePlain)
		if err != nil {
			t.Fatal(err)
		}
		auth, err := EncryptAuthenticated3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], goldenSingleMessagePlain, mac)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("goldenSingleMessageNoMAC = %q", hex.EncodeToString(nomac))
		t.Logf("goldenSingleMessageMAC = %q", hex.EncodeToString(auth))
		return
	}
	nomac, err := hex.DecodeString(goldenSingleMessageNoMAC)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := hex.DecodeString(goldenSingleMessageMAC)
	if err != nil {
		t.Fatal(err)
	}
	want := goldenSingleMessagePlain
	check := func(what string, got []byte, err error) {
		t.Helper()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s: err=%v match=%v", what, err, bytes.Equal(got, want))
		}
	}

	got, err := Decrypt3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], nomac)
	check("No MAC Single Message", got, err)
	got, err = DecryptAuthenticated3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], auth, mac)
	check("MAC Single Message", got, err)

	var loop bytes.Buffer
	collect := func(c []byte) error { _, err := loop.Write(c); return err }
	err = DecryptStream3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], nomac, collect)
	check("No MAC one-record stream, User-Driven Loop", loop.Bytes(), err)
	loop.Reset()
	err = DecryptStreamAuth3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], auth, mac, collect)
	check("MAC one-record stream, User-Driven Loop", loop.Bytes(), err)

	var iod bytes.Buffer
	err = DecryptStream3xCfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], bytes.NewReader(nomac), &iod)
	check("No MAC one-record stream, IO-Driven", iod.Bytes(), err)
	iod.Reset()
	err = DecryptStreamAuth3xCfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], bytes.NewReader(auth), &iod, mac)
	check("MAC one-record stream, IO-Driven", iod.Bytes(), err)

	tampered := bytes.Clone(auth)
	tampered[0] ^= 0x01
	if _, err := DecryptAuthenticated3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], tampered, mac); !errors.Is(err, ErrMACFailure) {
		t.Fatalf("streamID altered: want ErrMACFailure, got %v", err)
	}
}

// Known-answer Single Message wires for [TestSingleMessageWireKnownAnswer],
// produced by the 128-bit Single Message entries at a 128-bit nonce
// under the seeds of [goldenSingleMessageSeeds], the plaintext
// [goldenSingleMessagePlain] and HMAC-SHA-256 keyed with
// [goldenSingleMessageKey]. Every chunk record of a stream has the
// shape of these wires, and a one-record stream is one of them.
const (
	goldenSingleMessageNoMAC = "d936e38b306bd6f0132e499e608ec52e9cb7c50e460871f301c07ba30a817753c232b7a3cfef2add30b0eda242c3de300019001919f6b0214295cb9aa99bd1c6" +
		"7a946f247272efbfbe30760769a0f1abfde67ed34cb012a59647dae441d9a4da6b71eb133090945ff17cc5f0b60a8588bc555a318982a0c22b6f0a0d3c01776b" +
		"86753d43e52c144a775daa2a931907df3a314e4ac51fe3356d35e27118310ca9c6ebe5d413dfc0ddd19008fd0bfb5bd396f21d1f69a044a0d19c167a1c1dba62" +
		"9b8a58c395a9df3cf961a1ed52552593549bf7ff4ef5cea32f9f19deba052fcaf4006bce5dd1ac7613dd8f160fefa0245d4b57d9070ea7f303d3b2a756f46a1f" +
		"16fc8b827c63076e6d3f7b03dc4e89f8d47b69644676349eb9b77e5662106196ae6b58592ddbc2f62f4c6e5e902a4c1dbcf93c1e84bc4ba1c8cbab93418109a7" +
		"5a7dadc1cf3a6aa63bbcae872f03b5e350e195210762c79e3e71f95bd880c74ad283e9e6dd2957022fe6007e3dac77780278ca6bdba18a098dd5a47d64277776" +
		"3e7814b5292785fe225bf2c318f57cdd526ba9de6985fb430580358dee71b9464bab5223385db28de112eea592db33979cb7724cff3344f1c760b5e36d021986" +
		"8ea8fea8f20f0ad8da877edb7e1bbca2447b858f446dd3f969ad43162cf3915cb2a123de2165ef0acea45fdf3c3d824cf290f05c10f2b31c24b5775cbb5d63f6" +
		"2924f9bfaf687ffa150b86c872332cab843219131d805fe5734dacb32ad69397412630c8022f5ccb9a6ca177978e0bfb752b236c7b7eb852ac3c01e757a31823" +
		"acc83d8f79a671c1fd709c344ade1761d3f26a7db166ba98ce4fb559d4912b76653a338b1c5882d78876b426a2f2ad0f678d47060439625dbf84fe3c2c9559c0" +
		"69983809c7f6e47de0e38ee69bff7a051875dcd1313c0676df739ecad051d54574e4505b0ad57e18215df31a7dd713fb1978ab08067193431bcb118d41560dce" +
		"17af6796950f4df53351ee42fa54968e99b4fefed49fc51ce0ee0871ffbf4771c25b526fc0858ced31339d869ecd37dbd977abc0691c79599dad381a6240c647" +
		"8264a540a1dc00bf968b42116a139951245c9ce421a125e7aa1df5a6681b93f5060bd8d87638348fdb5203cab28d55a70e1198d372856a3b8802b7274de857ea" +
		"09834b0dc44a8f83a1ab4a03991dc73671e75d3d56f01052225a1b7d118788d9eeaec9c72f7257f5a7b59a77627fcc5319f19dce66b7320b17af71eef9e91969" +
		"ff60c6f233610ce4a37e0657f78b1a23640ee939c07db80a8270c3e0505db3358fc8a4813d8417774b90f78e52f81300f582b5d867db7cdf4a66d9c0793bf12f" +
		"e05834b827e82a6b2ad4e9eb2f7d8620f3a8f428a495f5b5a9df83bee123d738523cf48d0ee9db1aeec3d9a4958d27ebbb80fc785aaaf9de054c19ebfe739d1e" +
		"bda85bcc9fc5c6d951d0bdb23ba509f4459b5ac73609e47830ce20f81ba7bb841bec689565d19e5d2644699d7b51122078445ce3e6b029d3e2de4b4c4a8e75d6" +
		"e654387ab4ee8212a21991551217c13e99cbb463f31afdfa65d2677ac888c9a0a5bff804483a9fce162ccc826bd7ab961d5c69fdd73dd798c6de17770c306654" +
		"c4c95de86fe86480cb7e873e3397564e06dca9b5ff01506cdf350d714b487b740d2a06f33bbcd6dd1e91e83f826b874e775607f275ccc69367be7966eb650041" +
		"46e061719ed59d03c670815c442cb672eb80024b8bbd08cfbeb87eed2c489f28b219880712fa60d0ea8c1ddd901c31f11d04d275bc0e1ebdd7d71b08a32bc48e" +
		"7f593cff0bd0df96e7bd3bbf055b0ec6f33f6f9ecd6e98b737d810988313df251a1c7f89ad0d8a3e3d0022086deff8d9b87b8c6359936d9555b6333a62c77c43" +
		"026bc3c7e8a9769b6530438e95d12a867e1823359ac6759a7ef53f09f5fc34ece966235d9906c6d9c653a0853c1769da5c003c760638deb648aa506289d6d492" +
		"2ba4d6c2ff729892f5733ea88ef7a050c131a28ec2c6679a6ff42ba67cae8124fa90f1ae7c8cca7c4bcb4b9a7bacce73fa860b38266cf6529f1cc5444fcd1fe8" +
		"7041df130b7c64c5e27ea164b316b9ce9b9f470669ac078f63e89b35e54370233c186c074be4e772baca27b19dc3b6ecf61686ece138bac1e6b5aad91065eb32" +
		"f7c2b10620075909b8b2eca4cae437d672b85170764950407b086682960149e13e9adca4821dc0ce321df96ca9adb74785c65bd93a551e9a2bbf5468de564094" +
		"fdf7446d4fdcb43fec7b8ffa12d124156c9b92c51147373594cbdada1304687c042a0d8400777aefe206fa3ac7c54c5b462084a6cc04d65523158b7f11b275af" +
		"2aa9afc5a89fb5fabf44d412bd499cdee27677a96c507ac39419097162bf8e29cfec0fe6a6c2b88f7024d17e25b6976b6a90321f077a16e434350ad38a1985f6" +
		"2a7718fab4f0e9d0f2dfa6fe1b9cc7756c122587cbb2c2d586b62d88737b6bca84615dc2af7483f05fb32afbfbc55e96e7601f2d95865dc4cc85e21c0cb7a569" +
		"81f76fcfd0051362088afb63d7f01b50d6397e237828d8679448cf2e0b99947e064d5a3ac5e177dc235406b77232e67e2b89a25985f4ff2c4655942acfccc4f6" +
		"fc75496e958be15e4fe57d3bbb89742f73327b57391954656a0dd62edc686aa4516ae1ac619662722a9ad28ab89a93fd45cc6a3831159a943a60fa58ba7841d4" +
		"f5349846709edab88e73342955ec0410ac17b66365a2be709ad84304fbf2e013973f351f1a2131f9fe915c4e5009c168f01be2e2f2b501cf36a9e93f2ba0ebcf" +
		"0965f1a505d9fcc37ed6eda10bf94ae7798143e1cf124e4e58a8995e77fb6c0900986b9cbe15d12fbf708f835e26f3d1f6bfc7d0f2f78b66d64cf1a89d3f5eac" +
		"197c867781844fbcf2fe3a0294c1f4ebe5394b1112920817280a3106cec01a6836ce48c5a23e503e3f930ebe9ef87fb289a473199b3e7294909ddbe40f7e8965" +
		"953eba876c22b58e5b6e8fae208778b59ce3d63a548549734ed7a087a412533f843fd167cff0a46fc1df05714b96921b7745cc771d63d7050bf35eddf7f87bf2" +
		"ccd4c66dc115648edd2996c302f9d00a6c59ac04e3fd8fb4e59b36688d69a6aa68aa0ac56ad7025f18b86b094265e6186f6c94931b0ab48cf387e5707a0af501" +
		"fc0d43cffb6be01d8eba9aeff4f1f40100605c3aa5a84016c39a2706482d4525f228d63aa58fc86fb23a5e5706856fbdd19f2797f91a6a5f1dc16a639a8b30f9" +
		"b4859d1c5d9a1abaa24914b6df40cb3cc3022b8345b1e35e82b675655c0b2ecb503b1dfb825280b4a0984dddd1cde22c9e9b3b06cc81ad4d99cbf9ec07ce0a08" +
		"1af92c91aa90d3600d8f68fc2125f9d13921cd0684ae2e12cf669e8e7d5ef03d40ba5f09901d0c899a448f219994ec7aba16fa8f9e7e62a17794919c19a98fb3" +
		"eb426078deb6a98ec0c50cf5b45b958379082ba57b12afad2dc5a325cc188e7dad2bea3b45f17467b44394ede8379e9a5fc90a99b359365da5030f6e855b660e" +
		"44c5bb3ac2b10de12ec4694005834c977364740345e54f4ec5cf9046e0e72fd1afae8594d5b304f18c2c014223f2e65bfcbc3a331ebd8bd70152403535fdd2cd" +
		"2da13f73ee310246f8fefb91758cca4a87b2b71134cbfac5049c9853225be3c18adcf293de3d52b31f31f4a01c757250d5ffa5d84e8a90e23d8f364da3e31fbc" +
		"763739417979782e0749640320bee0379371a071c5b70a1a723bb2a33e11389f8a561601a1840efdcbe3a6a5e640723f61ee3f82bb65303bcf223b59d92b204d" +
		"c35b444ee763c26b9ae26fc1c4342bb68e72a7618ad13bbbb89f7750191138f42798bb3a735e6d9b24cc68334995ca4c3b21227ba7593f10c13b4fde68d9ae67" +
		"861e5218ee1381006c736ad34d88da20ede8b00ca75296afe9a23218997c2add8941593cc5a424c4a2d30ad0423d0d2566d17cc35c9bdea711b1bcb3a16c8980" +
		"980b7f921f8b0214effda1e13e28661d053a30fd0d32133e042cdfd37d37eff6c81fa4d762e9d45be156f714d33a610371a96f7acc5fed3f739c8eb4868b2bba" +
		"4a1cd4be299f33b13ad5dbff05d4b3a3e8cf1118f63826ba5803c6de4fde17e998ae52977a8bf1ab5944be06e19cfef3fd159beb8722f0e17d9cec069c0c3ac8" +
		"555ce67a9a58094d21f383461c780b61290a38d4ace44f0710627a672602580e1e976c46e0e4f5876589db804dcfbd99d02d0fb942985eafad010f0168805b9b" +
		"51aa1b5e21098cd14f8eaf21ccb64b1b846ac141b1a86771b73c9a2c64736d88a85167140c6c58c0cb58b2b10ed1dee31a1f531d2e643beacb9665810f55b0e6" +
		"6aa26bd1ba2f653f9516d665a569ce2094afa388f0ba1eaffc1ce080246b542b574bd1449ce524bedaa92d11e931300ddf32236399991b53f0ea8c66137587a3" +
		"ec5404b359dd5d48c72528b896e19d9789e4c8947955394f471089004236dbcce7b2215c57184e5259e024d9a83196b066880859e8c4a0df6bd5bd33862ad59e" +
		"27dc059d2831198bae36062cf4ef11a4195369e187651e22c26382b4400841b451cf048da9ed972ab39e1e63965568e06ce4d9723dc0f1b89f67087986e21f80" +
		"d4af2e1527febfc11b162bb22745892a23968d47d0c03e284d74a19d34e9f13a1ec555a63e74afe0b9797fd6d1c964f570a066256e21de168e83a4a7dbae4a4f" +
		"65a62eaffb0e473b435a58e7604118b90d2e14dd6e7793e024a65dec26c67462eb46e53541bcba9dd6e984a4b7f0950e76adb6148a6b71c562a6b28afe6ed1d9" +
		"b6ecaf28ae585d59fb3de7cdf201d4fce3f6f3ca33fa48bc74e151457675188c11f76d85a441a7b047fc7ec1898426c0cd9d89eaa1edb346d7c73de27cb97a54" +
		"4a82e6e06b8198befc40e048fce0d20bdf89acc18d1dc01b8f9bfe5dd270a95e500a1eca37c14b1681f0de325f6b68c84c5e5eff391e5a16f74783631744a1cf" +
		"d1f4b7443779bbdd61059681fc606c0a993dfc371e65ac5fa3013efcf62f99fdc39aea69795b2cf912fab908bd15a6d48efe494a6b5429452f34593807baac03" +
		"c89ffd2579ece79e39663803bc1cf8e28575fb174650246dc4851453924686f8efb71b00677c9e3fdaab6ca5ab98139918859c7057b02783314ccd34cd822c53" +
		"678be46c4db42659a1872ec63b9f964d307270279a9d946405fc58a077cc5fc678e5c09a8cd067054cee0d697b84862eaac676865c3d06aa5733781af9039053" +
		"c915092643f6d869bd236f0674c77ef0ca0c1673fdeba117fcef52da721f4420704737816a33db9395c58d9d85230e5111afa772ad78e00921c01238279a3ee1" +
		"04a40d575b5b8a330fda38511bccf0967f88590f9a9b3197df7d82b952e4978e051c550a7545019dca378b4de4bbd0f91f5f30f8457c328ded1447d100a7cde4" +
		"e10b1dbb87745fc2ecc5247913ed113de8d2f5c901af3b1292a8b0cbfc65ebd24ded992042b6dcbb34b8d79f4e4c991e3a1ca2bff0e7ed5250527521c3368fb5" +
		"1054c1fa43b4612c9ba4f0f3438a0638df452c5eb634bf6009cce19fd8fe00e72a10a7a722fd54aca4259002e2941236bd31376bca8c7fa217c62ddda69368a8" +
		"f06a9cafe588b0e3fd43efc2b9eaa2f7101ab97138e84ba5e66662e5af8df293278ed92d9a864128ea5e3a429e218268cfbfb065528a0df3fce65ed0591b669f" +
		"cca36cd9bed616b41b2cd89a7754684342998aefc2997f7be3fc5d2ed0747260afbb9551f19e4f5101f638509ea698334a0ff2565e4ad9cce166da2dd3ac5904" +
		"5ab8ff06fade72091283a15519a8103fb6532de31355dee5b4912ba04908736a88d7e3badcfa569ecb4e90203abfbd458c5ee4e277543dd394384ff20b1242ca" +
		"82243a30fddb9020b8c0f53188513ba3a042d2fcbfe2f6b488f0f77c4baa4b3d0e92e2812ce26aaf956239e991c46e4184be5ee8603386dc4af22c9d362892b9" +
		"1b7a4b235bf4027a8f1f5a547734dab1fe393c07d852b608910c83e419a2201c238de01722fede1dcea8ab4da03c88f3bee1ee01a242c40f55c30c18c80ce4c8" +
		"dccd816a7bb2fdbfb67e3dd7ab0c0341900e9a203c9b373b00793911717a2ad00ec0e4b19ee7dcb68482d1059e7a1b7127cea01b633b1e843236a871b89231fa" +
		"c6cfda0aaed14220be5e5aff925090a14d2219b82cc9518513006062ec7def6a2b8ceefba828bda8de583155fbfc130d50e5b479882b6e1bda3d0e896d98595c" +
		"7f8da8c36234cdf30d70dc4f525c76e5d2d55296807e128516663e5d521af490ad449e8897cc519e6ed5bdc1cbaeb914ac97885d09554ad130f8f9aec942e083" +
		"356377f171678f9d10aaa122f14031f3e678d488be29e0f46259afd2db2f0bcf33b696991354327f35fc49d7378716a4a89b65d06c694e87c072e8615971e2d4" +
		"ccc971e6c5ecbb7fa157077f3ddfc07c437e6b35c72dc2800f84d0aad0ba14bced8266a50b8356feb1c548f0a4b0219ff8e81b1bcad1c9ec534045c0fc212770" +
		"0f7771d4d4c073f8dadefa8258f7cda19ff8e4ad678b1b8560e8e70e2ff057b02963bc75e0f038a7819ceccfe179d2bfd0961e22d118c4b6a581dc3c1fb5bf5e" +
		"a5c575d25627c9cd3a40b8d4ff0691fcb6b7a08a8a78cfa326b85d11a14c8b80ae7be9d433bb3e5382711c3f237b361803cfacccb0225e4e80cd8987bf82e40a" +
		"137dd6fdfc6a40c2937c5dda6227737c5615db1bd0576ec2cd073269e14e683bf6be3b530e726d2adf336d76faf8889b3c2740879bc817c576c16f0268b1efdc" +
		"60d25bd278d9bf9b0d6ec2652801e593fe43afe2714b2341783f58f2a0e4b72f316804e806848b622d528f9b280d8e97bd824ff6a73b01a920d64af444a839f6" +
		"e60e79ebece6079fd50040735794c3422b614c76c13a627ee01083f4f8e2e3b9dfb5bfc207c3f18453c81a3c6991c95d4a855fb49ae0b4728b270bb772c41133" +
		"b453706199f2120397140ecc4dc3b9cc1096b9800bf9178ba460b698f74f1feef55e7f95059ce12cd95b776fa88062134b40ad0fc3cbf1585c0ed27a07f39c48" +
		"4e31a181e7f3af98e55169abe5615b7b80357adb6393e0bfbf2f6da311907f5751b66fbf3e5d977e9f6f7d809f921e2897082c57d305067dafa7b6f2"
	goldenSingleMessageMAC = "547ba4067a883c80ac8bf2b5925aaed01a0cd185544c391e639cfdbe984d853e56f97d31a06b81a7e9352b9f79db26f8001900190f0ef0379b29f4b1b9d81fa0" +
		"613915e042c94ae408c40be13f8cdaa62600d60d482e5427938840eef2f3e3cd2899ef6685cc7f7d2f93678bb887d805256a8006ce2da1cc6d4982c6dba1873d" +
		"8ec5fc239376b595e51a9100ddeca4addaa33e1df7181702e781f338097a5c9edb55de8c31eff3b8c1c217a0437e24865745a447c2995abc63d469bada0eb7d4" +
		"ae1ee9349090ca14e62fb1b68730e620f414cd80c9eb0ddcabf3682e09c905544ebd8223583f7d5e94c67f7dcabafad56ce0599269520098b5ab576418a39a88" +
		"c3738dc1d28591f13c1552b27f81ec8b0e5c6a8d33f287c0afe71361cc556eacf2c9153133dac9f1d87e289e4ac962121301dc9b3ab349fcad65cbe9ef9fb57d" +
		"ae0fbda271ba870f8404454d142b2f6cb01c62b037506128f6043844f918e43a2e4e8d19836fd62e5d4e35316548c8a35b2aba77c56ed50c3e3978aa551cb940" +
		"b9d866c08b5b85a01dd4cdd0e3db76619c5de2c119b0c70362a4e21bd1fc402685beae6f48f3dec6915097d8ead62c1e09da18b8c57f9566150f4de25e15753a" +
		"111010691a82ea39418ae302a18af2ead3296f52071c24f5eba16c38152d7b8270d04c046e02cd7e3080b04af6c93edfc1c9b2999e48894d6ef70252eb4c9480" +
		"bf07aa9e7d75dc4eb5963b0b0cf986772fbc2e05615124803b753906d92670bebb7efb8d5e23933c346524c8e69d518f3fd31466796f43505697eb8d3b924717" +
		"678a0ca8e8c26c75bfc1ed0cbc2454c56fb7c728ed62e746c15071f09549ff29ef6371b9d6d8ba186b05691ae9b559da086f74ab9eabf373611d9b1b83782f70" +
		"72d1ed24c7cbd1bf16bc6bf9d48e001b817cb09618cfd451aaae202191cf782cb0327512ac2a7dca34081a3450727729f6b5f8240d3d42e9eeecc49659917098" +
		"c408851059ed949b06ffc87a7a2b924d15e619f02f4242487904087117dfdf9220314eb483be53fe109f4f11c717fc302aa9c953a976f72f4ba2aee4854a82d8" +
		"1a73589fc005d5a83d2cf9986157a61e2e2419ca91876fcbfbb8e1a51f95ba3dc85e26114b57597ce27c30ff18b37db31d40e35a8bc37f179414c6349373873d" +
		"1af7f8cee2a2e551f68110c36750ac17367fe2c1461e1695ccbec644ee24d55ac3afd348885776d06c155d9126f36c65e4a3d9cf89c36393ac04861006efa507" +
		"6614fc92549d857b2daf9469b879bb4e267a96b6aa931566744c5a13b16102b27d2606ade25d3dd0b0baeda829af65c8e357b902eb9f6d71ebfbe031caeea344" +
		"dcb86de50e78c4e676aea7adfb3add0755fe7ccfc56e46e79325b16403c1872189c7df88c8b3d75a721c088b3feae2184ff9dac0211e09b05341d7f11ffd6a01" +
		"3c6135d6d0e5bcdbfa3445a8305cb9e0e966746cf98fef155055b8be409bc94add78a2cc674ecf8d1656f7e614164b331c63c0ace74eb77751c6421baf66731d" +
		"3982325dd587516d94e8b18ec498f30d683fc7633eacc3abf84aead879708e0df499a44a1e96e409d8043034b0cd8b1db6e24669544b804751957aad78339932" +
		"f040e093d93ab0e1129ffd38f49b66f77dbb82409bd3899be71e2eba7593e2825aca82acfbda7716cde295977660b02be09cd941080fd28c03f0a145ad3caa42" +
		"ef1d75a2207bb989ffbec2dee635b681f1e26b16fada003688130ce9579fc5794781165d493a1cc50cc69f9033f2a740f7a899bf31543696b066003668e5cfb3" +
		"c6d884386c5acb35bb634f946663c834b7ed8f233cc3c762bd991d60afe07f7417509bb81aa6d38825bf08e19da6437923b4a275707c4eab1fb10e52cdc884e4" +
		"eef646f045153eba89640fbeb95dc4f9a8ee753b6b0ff290d204602443effef059f5e7fc1c2ddce228e133dd6ecac4f607272b03990901fd1541f300005de02a" +
		"d745642e2e308a8d9c26dfc35e8f54e76d2db5279b8fb64620a2760ce4b27b90769455baaffc88d5ae6d96131961517b5650131438c222f3e86b00e2207642a8" +
		"2a51388b0d8df8273b50d9444189dc13b9b24ea0202b64f514bdc1d395e74f30d890f4559b43b5c074f5906ba9b6853efa0a11eb0516b8637ca5539b786b014a" +
		"39b4e21ff33b546d0054db291debed3a6bd3dd59df278b36ea37113737616821c23cf6df22db47a30df745ef0b2917856fc2dd7c5f0ceeda2e636ab24a9f30b9" +
		"8fdfabdedb9ad4e96339050f55ea58537618c38d762fdf59f7063c1e9e822fc2a2eeb8778549c725c11f88f5c11ca2f3f02ea1f2f7d89d5090532873f2ff107c" +
		"7388ba0c829a48d2a95d5f80ce505413bb1df3a298080217be23f019a6fc25c1b2051d8339cf4463a26fc7d3c339d62258196c73d516bd0dc50469e637b11c06" +
		"9e605f223bca36a9a89775cadb0fe0f58312b358ebba71d130e670d3cd84c093593ad476d52abb64709125cb889b2c14e26b0bf381f867d578bc30b255867f9a" +
		"cf77fa36f2e2b8b7ca124ebf373731ed51b128f7e57da7d4e1b395cff8a45992771571768d313355724dfad854d6c45873a9cc1fc615fafebb14e0fe7c0513b3" +
		"d17e647363e2a73b9fe697640516fb13e0dfbfb9e633b05304b7643b107c359f81cdef0fd3d3cff71854cf306ee9dc5599233a7a13f69ff48dbafd3800702091" +
		"1a02006718d388d310965650e0990cd0677dc88496b4dff45fc8136fa839c4d926c3301e3b0282f174774b80039be7b249a0f0a0c883c98c20c4731a3e4b5d75" +
		"a1842445996c01b5bb1cd88cef292e928f5fa57d9ae394bd7b399973dc787c568d02fa522679022c6e3600cd03f3d3cc247b4f6237c7b3689ec1ce1bc6b5799a" +
		"2522c8257072f27cc8adfb25fd4ef62369d92565a1663df5a1d8203fe6aff304cc68282d57b1c058bfcfe496450327685fabab22e0797f863c78acebf2342be5" +
		"33a1d5ee25a65ac9c4d7c54400977c6b2f0af233b39f3ac4be19d546c894ddeeb7c3d9d304c1ab8c27c791785de91614db247c3f61021e7194ef763cbb99ceed" +
		"6ffbf476481d63095f509413177054eed8227867ad03afd2e785c0821268f2b26e30c16dedefd7744c5080b9b68be54bbc24de2cded9b2a53cf54b44cf619e1e" +
		"777d9474b77e342716daef66e49353e9c42cbbe031582e4cca0eaffe764e7d7fd1e3986e606ba4cec7687e573cbf0e390a37476cd6e2ba087c0f6119c53ada38" +
		"a121dfabe0e6c1f4d926fe6e2925c293dc3a8cfc594dcfd5b13644ea52c377d4effd20ad098c06b0e56a358a16bd8eba1dfcc274fc9bd5f223824187193bc737" +
		"57464c3d94f0fe69f4922d77d70a54d1b6ce5f2fbfc709da46ef7738480c01d749acc0baf9370e4ec452a2d2d0ec6819182bd3701f26b1b19df961e0b1f71229" +
		"75cba573f96254ec8deb63cec47f15032c26672ad7c7048b49b78c5091ef967bd19e5c116b9c71172d6ea6648f7a04649837321afdb1960c762ffd87efecf818" +
		"eecf61d47b9557939b9175ec7250b7f73f95ab3251eb4f83f8019b1feefed10fd7ade141bc8fca3502c785a5bba060b246ad3252bf9a19973e26eca5d31a5b0e" +
		"7cdf69e0429376a17c35c9f761c60b74ce0d5560612a87435af20aee2123ad5b142afa521d985a1dda9f882c6418b8f624b60cd6c402268400c6cda91537c570" +
		"3daf7c6622593aae052115d92a7e57181e558db5a223b6f4c5c01b13a5b320125c903cba1154702e10f783e27399ed932cd8ea0febc63e0c1857ca8868270f8a" +
		"1107d80d3a48d333cdeb3f13b36c93ce5357a7b69957d99a780d3e7d37ee0009cf82db285cb25a01b309c725124903b139121b6176dbf8cda61620de2dceca87" +
		"e806eb4eefd1c6fe696e3c6af036b64fc955fff15929c3f197e3d252457f2de6f927a0576a8d1894ceba1fb8b7248efa79c7d132d9ca0edebf5259fa7ef336bc" +
		"5fccff5c05c6d14f562ee6c3df4a2620e3ea18f8a6431339f2980ac8f20428d6ea257c43c8c026608b3f44860d11d01db5ebee3968841f7aa32d90ac2ab6f3dd" +
		"43e2a3e1ddd79972e03d000a7466b297521561b7fa761a6e929ea483f38d7d73f460cb9f985f674486652642dac26f7ea965fb6b684355822d81b1a398c8953d" +
		"e9b8be18637185b16f115930e0031cfdf2c2dc9595b70fafb6fd39b043526a947c60a617bf66eb8f6e735c2476310c7b8ff07728f38e6130f86c41d76d3f73ad" +
		"12b986a96ce18f70937f5444a5da19434ae12e4b8b56bc0f33e588dfe1e7184fe33f16cc53590f56905830be2c07919b9a075ca337d222bc7f7ec078d1d15a58" +
		"33d39c9ee0336f8d210cee695f0847c347fe8f5bf7c87ced7b10340634e822868197b202d3aa50315e2278ca2f88137f6f071d5eb75dd724ac4f28545618a5a4" +
		"1681683f82156b0910b6318ca9776efae2e5cae2327b4b24097a52c4fe7a6252ed0633f4c2bd79af91a706af17bf3fbd44d2d53ed90204e536188403881861d5" +
		"591628e546c04ba37925725bc2fac171a07e852ab704f23ee17ef6e07945cccaa33f0968022635b7027e7fe50f3f9e09d6cd0210aca9f5ee56b3f8c63af102fb" +
		"27b08921881b4ad90d7f724c25a699d7243d6eec098ed115be1de18609d076a25d5cd88b43fb62a39800169a60b0a5c7dc07f31b5f7569d4a830b09539744921" +
		"ad47ba584b139c207cbe1618e41644befc8eb3fde1475169047879a060c62b21a033dd720fd853a265fc9d3d2dd7294e548e8f23beb4977c81f75f2cd96e8dc1" +
		"8abe5d44f63cd6cb32ae56ef8a7986b771c30a12363cc739c6e100e7007be7edfe059ad1c09352fc169bcb4cc11347f5092d96d392c6fe8560d37765b930f257" +
		"d1cb5753d82ea7cf661ad92605b560a8ff5d8b1a8222dfea25dd3735cbd0098de6f85c9c676a9902f28d9b5c7b992feca32de1468455ee61c87d81b61bb7e1ce" +
		"db52cefe161b25b8f89e1901cbf6a83fae128f8ffc2be3c8506e46fdf6575f2e1ab8a650ef74cffef2c3dd3ce08aec5deff0a506b6e502a5ea379d98ed80cf3d" +
		"a3dec0dae5317df7922522b89231dd48861539440d16d30b476872a1cea597d5e67c476a128824719728d5d355a4d63936f6a06a200f538fc99a17c163d62419" +
		"36ab31197d6ef7d6d7f94e3db0f70d0f5e295293b7a3d2e5b6b6e5aa4c82e9902f7b398ae94c2557fbd36993760233a9fb2cdffe9fcb3ee9149da7c47102283e" +
		"8f49e53570f0760c0e8f39bd75948d92f245546e142fc33ba343e738a97bc46a700d2c806835a86da05b150da342ccab21b9f6adb4f92c3b09af9b3a781ee122" +
		"68cac7157d9673a9ac1cd39a4ddf325d74b4b94c3ddc795db320ddcdf9ac613b9b98691053b53d11c2785eefefb1857b3d5e676f20f9b8cd0ec8e91852c655d9" +
		"4c0e3fa8532dfff7c0647b1a6a08486d714ed7d5c9c2553e8c4d4399960f531374c9639fa8871a23256f7d2ed5982af37ddd28ba0aef8172a7789bb0a13edf83" +
		"cba469ab2452ea399cdf335f1657c7ac7051511ef71bed8db9a470dd6dd70d031366392162ade9003d73600c19648182d7504c962b33cd57891f409d2baf8bf5" +
		"8a5d57543891bb72729d4f7dcd8d5114232332c97ba06d533bd42002cda73deb8e3e8179746bcfe662885d881aaff7e1e63f131f97a04482590df5640ac082f0" +
		"b05cceea11f36c75e080029e0095f477f2edb8e0e8ad37090d1df6e0ffc2bc76e47a1ad5db845aa5297abed47b95c83945e971825344384e813a19b96e535d2e" +
		"8d90bdc4fe7f385bb4a990a121411c927dca6673f7251d74511b1337653f35199022f115deb97857dbdf18f9dfc3b89ee914b4ad32311cb89c386ba3f8ca8ebb" +
		"ffbe5ad77e8b5f75c511d03b9b720f31dc466f4b0bf30c96fad9a2ef4a475662a302bc1347336fd51ab561cf3169cc7557071be9e230ab17d0acfbd98a795a38" +
		"1aa7e2456e673d605817e2d10816297eaf30cff59ba0d928d5d9a2d2da08f99febed5d38f9dfca5435d608e2a8e5b92047451264988d7590c56f5232e2d813c8" +
		"32137651e6114c1a92974d2cc9fb3325cbfcc8af39b62471f9ab6181cc2f2579b15810089ae90e31b37b9527d4484d2bf6d61ce1018244ced82f425f6916fbd2" +
		"ca1fac7c733b124e3a58efb7d7461789bd3794f48cd66506d97d8352378b3d5d755d431362f60d91f07a2abb62c3b0e6b715c2dd062b16951123a42cc07abc3b" +
		"25cc702966465622d485e1f42fd85dd99454f85a981a995c961da309b634a3df453399a773941bc815d4b3c2ecb5adabf0838d7c990066999c1374f162f014c9" +
		"d1128a9fd6bd8ee2ab69a6c43f9196ed838f4e519984e8712d4801a3db0bbf19deed1069b2f78a93f9c7060de36e48d159c0dde74e2e48c194a7d596bd320eb0" +
		"8e9550202861c76a27f303856e6987ee9a3b2923a3477a48ae4143603238ee6835fce853ea598aea49341551083d6788f5a2e10987d32746eb8bea75c011313d" +
		"929df93d3738232a52a50100fce446401dab2f44dfc7f815a4dd9a75717b562b595dfbc6fd9949307edbc6229948f128f4a6010166d7e0ab704d52abf084b427" +
		"927119aa7b0ecbd2a82c32fd8b9cb0369ccc88398e8c5f789d1829062f5b70aa94007225f00372e1f3f10ad75fb1d0b72cf36886dd06e27ec8629367afcc4847" +
		"b29a6644ac98317c7094fc0db0dc339bea38d4843be6d38e139cef786b868fc30b8e5666016d9e0aa57af8f0a54f1e85488e18d76fe6354e36a4c269113608ec" +
		"d4d4ecda26a8013886bf120f87bf4573dacf281dd879df38be483977865474e70e3871eb46993892c1af261f77c2ab15b88ccd5fc3dd526756aa1d51aa7c26e7" +
		"68c6ec8bc734709c9e9c0b162acc2d94ee3bd3d8b9b61f45a40e5dac55da56b1d8007819335c9e4553a64b80d1786e16f507e044db1b6185bc8e0555334258ed" +
		"859cb4d23ee17fb3edddaa5da56a2b642b227451acdae34102acb186422881702a0b7c40beb0527bb95ec571b05304bdac0007f9631769c4fbc5584c9dc407a2" +
		"3ec8ba08ada6e296f22af4ac4236ba666707b7b722288270a0ebebd29c1ca7c3463428b818a8a22d4d213b1c82e06a69addf1e969e9fc9208287dfa2"
)
