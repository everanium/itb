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

	t.Run("DesyncOff", func(t *testing.T) {
		t.Setenv("ITB_BARRIERS_DESYNC", "off")
		nomacOff, err := hex.DecodeString(goldenSingleMessageNoMACSyncOff)
		if err != nil {
			t.Fatal(err)
		}
		authOff, err := hex.DecodeString(goldenSingleMessageMACSyncOff)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Decrypt3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], nomacOff)
		check("No MAC Single Message (Desync=off)", got, err)
		got, err = DecryptAuthenticated3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], authOff, mac)
		check("MAC Single Message (Desync=off)", got, err)
	})
}

// Known-answer Single Message wires for [TestSingleMessageWireKnownAnswer],
// produced by the 128-bit Single Message entries at a 128-bit nonce
// under the seeds of [goldenSingleMessageSeeds], the plaintext
// [goldenSingleMessagePlain] and HMAC-SHA-256 keyed with
// [goldenSingleMessageKey]. Every chunk record of a stream has the
// shape of these wires, and a one-record stream is one of them.
const (
	goldenSingleMessageNoMAC = "73f361ccab82107f8a4acf27d688cd8951c01915e23a1ba643b0283a7d090ade6e13985d98261424e8a3ad3326269d9e00190019fbc395966a673376ac1fe364cdbe" +
		"898a25dab556cec440bc6c26978ee4ddc1ec235598d6d0e53378250f34a951070625b147567204a3c7518996776d6f77c666c37a0fe7cd49223c4cc46eb34c7fa8e8" +
		"a07c29ac6386551196888854dd0a663bd14478ed845d1bec5ecc123fa2acaa8b287e63a177b9c1d2ba1aa112d57531436044d81ee5cf263b218e59a13a5e20660e68" +
		"20074826d6a096616ad47df2e1f52ceb875aadc6eba68b314764d14c30c55f89ac8abb19d9ee496ec88b771b070b348c7cb2983a439f5778cc53995ae5cc05dd414c" +
		"abf14aa4bb3602910bf3d98c2689fae263d3a92d950af282e6e06340c9634bcbb92d06cdb17d19baa77f707aa2bb84ddbcd433375c4f7b07560486a65b3d7681ee8b" +
		"7e037993032015a2cc85c4558b76d0a2a7d2ca9e0746d6748d81f8dcdfdcb1f5c9c6b16562889bfb33dc10ceb2e26e216375a80137c2dbe56f0bace5a3c6e8c40bb1" +
		"97f47afcf7d553c7ccd847dc429bd19229adb9c3806896c4c6ba524409bbee61c23b1d6b80b6f314214c75aa3214ccce213f0a3ce50c69f4284061080176e8a766cf" +
		"e173218d7d1570d94d2724fc28b135a94c591339c1d95eadca019eb91ba67502de6fe1add72ec7c6c4552eccc1b5ac9e3126824e9bb41c6d5b3e72c87473d09423cf" +
		"5a401021237417512c1b6b0c588a6910208c98da175d88f2567835874aff6e587aa62e4574636bce9df69e56ad3ff098ab3394c12790cc3998834968ca1fc15d66f6" +
		"f783c4f539d59421c8dfd03089703e5a84d3f16b02888c90f9b3e78b6d584ffafdee01c98c6dafd887ff47377390194d386de46b0cbaf34a1874befb0b8f738c0abb" +
		"805dfd3b8f00de2ae52e8387a8dc8c41d264abfbddfbb50270dd2004c57e96d84687bf03507a9fd53eb21e1326adf8fd06d980424ac5d9c286f5beb085e816822340" +
		"149ce58e6416dda7c302ebf5ee9fc9a9abbe474f781f0d088956a718007f88599f10ed1d7ed631c7fcc406dc4303ffe3d99cec5f4e6a9d14f263e814fc16b92cef16" +
		"20cb750f20c2144beddd3c8f1a6e9bf6bd655b9c63fba3ffb9cad861a03363761e0be80a16fe086d6fa4967894a53a67ee949cb582bf41a8026067ce2e0f06fa8e9f" +
		"6652b308b66ca4e5ee8015a849eb7e2f95ba22d76b5b57b401a585d63972d481a175306c19e27f7c728ea6e16169744509c87d95c623fee847cda52afa51a5529a90" +
		"c947cf4a86e627702e723416b7096bbc04d06e2729b10da0baa81af22153f90a900d122f19004ad61bcf4fcdd515eb1e3cd3ed1c968702a46108e53e7d01769476dd" +
		"692670ee5a8ed6ba5063318f5989d843fd6a262395187695cc2c47b7f34f257d684d5ea2e0f5b51bceed17afebca22303158f01efcda31a8f41dbad159ded9650dc6" +
		"cac06773f525747a5184a8894ec4b1493670b5f1e3cae52a51c5d66000d5c6bef0bbc8ddac06656606a5fe490bd17e9756242c9945ab428b59b47d6040b218354043" +
		"5950edef00a0a2bc1df0576f7025cde516f64ef05b272d38f8f4b9b1c9f73510110ca56416a04bc00b18ec48df066dea54287de5fceefbe53f16c2e76745d977eb83" +
		"e7e0db34e608b31c16fdd02ebaa47119d9726dc120c6c2543344906983da4129b750a6ca73fe4d77247c318ff6c590e7021e693b9c0b730cb3bb9e049b2c064678a5" +
		"dbaa854ad5f5488866fd6afc72c1df7b744ca803f6837a77373a6aac88aa5a54e52ea6855b4224e373a439fc73d9b973f4cc42e9c117f7c05250cf331e6d186d4950" +
		"a741fc986bce0910de874d5fa5f197767a02265b3335388ceff53f1d58b1e8792c3ed2ed1d938c15beffaa0798cf28b071b4058a9ff406f3ce5c4770cdc049aacff3" +
		"e7471cf987a999fe47c49ade58f4bf9d2c1748c0bf067c5e810f16a0da2885090edee513e893b0ccece7e87bdf2c9fd230df512d7d1d32253a8873c8a49447351ff2" +
		"6a2ad1bc6be643d37af61994f2c658325ed139ae78009a1a2605424df677cb8aee79b9db0ce260176791b22bf3acf6a989ca367dbbcd36d0e58f885f787d4191a02c" +
		"d1d82fb9c7d8f252b0f239493cfc307a5df09d57880fa4beafd1612f5b2b1ae25265b7fe817481f4ffdbf39e9017536947804e6d4f34a6b083011bfd4a023711e253" +
		"f0f499d0a9674e5fe4cb46df6ae0c9a2b1941d20df6feb1e6b1f9e5f1aee3c7512b28aca7d1a09850cc781212cadc72b95d9b28f36371ddd5c02940667dcb050ab8f" +
		"3206a59f91ce05dbbcaeffcaab93a5822891cc7c72724297c2ab6fed0e160fee2ee9c7b30e9c76c60b16da3b4ceec1d63aa8dc2aa896d6cb53379e08f4dbda2e3844" +
		"bc8c122c4ca982d36222fa0efa7cd3c92969997344c99a2cb2676dd1e3f80e0c713e3c06c059198f550e975398c9188c981453c5392605cf4150f48eb5e674a95eeb" +
		"254f79865253834ead0607eb7d429aee76c7c9040ea3c00cbf6b2b513d9a8f080438e2801659ad5dcc8b04d3ab0d75c3a3298af9caa4e2aa25d12c68b72a9458431a" +
		"f137e9747175c085b7d04a25a68cdada03cebcf41a93666581435c11180b40dd45da6fb0dfb2fa7c5d9a2a68c603655b042e3bb988c0da2647f61dbd35f663f17d0e" +
		"1d83c814bf66135cd8a8bdcf9fb71ff237298930d5f48ae4d99ebe046c63855efd18e48eae4451c26278aa6a4c8aa53470927b855d0309723aec16b1ff587ce75e3d" +
		"33b240420025efdb926b138af07262901a45b906a64f16066e58ca920b824e220f911f8c2102d1a121738591bedfed301571c5f028001180d105b029b1dcc0608b76" +
		"08075b7f16e14e2800fdaa9f19b08ce780052d44b322df2434b10691928da05e0dfbc38a7692fb5bcfcc50395c94235d236071afb2f9685e7a89352250ac4d7a47a8" +
		"4b9b0e0d55f5761c5886a85885ef4f7f4038fda724ab9f9e62928031550a7e4d7929d592749754a7b08d711a54550ee2ed100485f98f75f093a02c6e719d42e3b1a1" +
		"010f08cc8c41ff444bb9a2f854a77b54323065a512eed95b84a907fa3081534610e6942b14ce18a84b533ff547de13376951faed4d99d29a82f4e9cb1d983c695cee" +
		"3a8c6cc2536bd89c77d907bb8ec5d766fc79a553adcdd22636779d8d685c52c5eb500001996083a2edfa8f5b7d9a0422727e608b6a23d81cd60ee09dd7fce20b0723" +
		"935ca445f24184d1a914f28e6443fb8b927aad369b815b9fcb840ebfe89487abd1220b8d502cac20876195dd888c2cb0c6085b01a2b92f35e2f4f53dde185b7af9ea" +
		"61d0614c92102543efc9aac80532fdc7d2a2a23381cf021d239c01334c14bd340958fb3a37e8806923940b82b58fce1c9e99db27e6e2f14e33b0f7be077d08dd76bb" +
		"d68ec3c623571fb5241290fb8b303c5aed9311a659baa5a029a3e8907016a526a0eb37652994b8978762736e431ae38c92f58497a94d6749fc150ec23a9def917772" +
		"f885f228d9482fdba9fd9398fcbe6e8395dac1d24bc5da1fd2da8f7d0f1d89ab306bc7b291a7b8067d1f0bacc8fabd465166d9744412dc93194fb2af8f61e37db92d" +
		"fbc70575d363f200cb758a2e56a8059e1871bf6bff00ff76f6ab42ca3a3b6897a3f48606aaf547ce72e470bbe43a9e01807cd64fffd62afd01a113ba6a8823361430" +
		"8ecfca134eafd98a6b4fdfeb88eea923c172a5b5e44c2cee13ced7500466526da3a2a2cbe7bef98cd04ee1667566d17e286d94fe8f834ce086ed54a1f1253f874f63" +
		"ed29b456cfaa1ca34f9b2a7ef78c8c706ff14a2bd96d236206ebd233f6a1d8f68ad73f995a2bac7238d0ade86ed4453ab5cd3bacf24c46a165b42977fc8c94856884" +
		"6ee4965f5c911b16e030441982d03d8cfeb92183aa591c675d625155e03f6b336939dcf39fcb5857629e5c642852dfba4e154f1eef67acbd1d2672577ca93de750d4" +
		"bbec55681100365c0a2fe62cfc138ded3749a43a597982396d11cf549b5e23c6875e63cbc45d6d3c883ddb3d002929ba56e9793d8212ebf3c01399d8cf6789808646" +
		"7c2701df649bea08d2f17979ece5d40fd6bdb038ee39ded07283d2284f85c1283c6b1a6ed13661e096e927d09b8ec096cfa76d25897093a45b04f274a92a585fda12" +
		"21e0941a7036570a8a39e468c41613b9140a6b119b5f1d030c7fa5ce763ac2d800d3efd230f53b9e989455b272b12f63a7df13323469019b10a153dfe90305f82d1b" +
		"369adb28619a70e914c1c22a588031693e8e59f42564f1a4edbfd6d9c4daee83f2651b4ccf553056f006236f8547d29e6eca6777d25d65e0c38bad88e15072c9f871" +
		"9a6af9cfc13470bf65877e51fdfdcbbffa4e55c49cb660cc6fe55bdc02cf5a40f1e1d9dcbe07ac19c3652da9d777df8256fcf8adae64d90823cff647fd4dd3ecd6c8" +
		"67b87892473273389684aca0a138257cd9bc63651818aaa3513560df2afb9ecba2c22fa46f8c7af1b586ab4e909c629dc9f8728f89c80f3d88d14e98996c600d5340" +
		"73f8042be4c5c92b2a7182e3345a6d0df4f5e20eed0ab1076e83bdf6899e242a34d56b2eb2932bd82a9ad7718e2d1afbf875add29ec34a4bff8b1956db3486da20af" +
		"d875b77e1db1f72a3f016bc59ca06c08d2db9cafb81252442ca76a5df73a33713ced7d1947fea2fbfa017b6094e2cb9159221d5c7e43b7a75c2bf20d1450a06f4303" +
		"1f86ccb48c45ca8e7fb9a1ce9d6965f45a89be65f6872ca773bd0d8a6e812a3e4f01e442ccf4527d5c2fb556326424b77653a6886e1d1cafe14c38d88d8bfd66a448" +
		"46584f51e33835ea50727e4e74f814b2d5b850123cf6c17c960a9ab9f53d3b16d6697be481bb7a346cfa3e492ee40fb8bf5fe4b1dc17fb2c1931b798406d3e0f0313" +
		"23c46ba5571f0052fd0f6a36490511f6f48e71dbba0dcaea5b20b185a9c4cd7e1776008c13711ce2351e35d5a0b847f2fad41ed95489dfef9dd4e25dde49a70b177d" +
		"5d6876f937cc4353d3511c8a9226ea8cd743409244f118321638aab044abf17c226ffc0fcea5711a288390f6f148477b89fc53f6993a5ccbf7d2629a7e065cda71be" +
		"29f9138e6a788171f114ce39004afb0bfda64fb9fbb94e6370cac8fda28464d20032b8453a47883d50a6c18b9d80190a30568f7d87474bd76aec5215b7398076194e" +
		"766b2badf5b67a89a133af29e79ab4c0db380e5b3e9754aff2862d3fbe03fd54e13c74bc143d722c643802a09434f38b77e38285162a51b9329170904ad7b5bb2d97" +
		"2a934957550a4e1ebe52f9ed2da418964998329235fe86b9d0cad75c3bc346aec8d67fc2ab4a865112fedcf3544572dac01072aa20a416a0f41d4ee3fd557e3d338b" +
		"1775a1d8a42372e60181aa425b72543ed45c450d07310ef8a9965a8f578eafc6420bc8a30f181e6457a7583e9b434dd5ea8449add53d1a982ffb3a5998230d35ec40" +
		"e607fda397ea3fd109c110f891f48027dd6cc0f8fec5aaf0e6a59ad9abc52e492e8a8c3185b3533c65bfd984bebb28a14d083a70a7d67a06acea866b73ca88bc64d7" +
		"c065a191a94aacfad4968cb408020c24aa6ed0b82a2de8a3e4932de3ea34eebb2a63f8ef80b62b2174109478fd45027ed92eede14a2ae1e7923b4f66d01a30fccabb" +
		"73faf07a859f96360e02090f8f2a2b323360bfa1d098d61bf6dfdad775276ac353273c0de398f292a3e87d5456f7e3948b69e6961dc412e3573fe4c69a943ac849f3" +
		"a76e98702b608641142cedea0df242b87e27484b76447965260ffef0504129581035504e7678793939e95163a68295b3a2d0a28ed0cb2e194a6ca452d95f2601b23d" +
		"845bed89ab12282aec6cc433485612f91389d058368b197c6eb5a363a20e88c837bd028029dcd2492658bf80d74348cc51f93d72654b2b217b66cbc4ba55ca3dee6d" +
		"c60a7230163bd26dd9ae00a7cdb8ad4c3fd0cb4e673590600401a9c63949c8433850b3556bbb3f3c02008df46d5c786361f65304dbd4c5bde5e7407112bf0a108795" +
		"c143b43d9eb009be4e982c55a3f4fb717451f3e0813da5f36a38618d1b577bc006e8c95b1d79506a8b8aee5c62a4741952ae9e4799037d35c7ee830a072a30a938be" +
		"c1d53e6ea99d2a21312bf51fde3770ff2cb92bb03de2c54b72816f2607b8daf465c9bfd991e92907c327bb8d1a5bc47213a2f4684bb1b8a0693d8e416a940e8784bc" +
		"b3f908f8676e3f5f9ef39629837d5fef831a0b4ed1f971967a5ef7f528c0dc90c2cbd181f8a16a7a5e8f980954059aa6faebb114d39842c118a680d90ecbb79b12df" +
		"a150ec48515c7e205ff0ef634dc356aad71e84f42086b81d1437b06763505adee0ce3ef1f5beb3692dbc5417c1ab50d0e6daf94a75a995a06517056309388e86ccd2" +
		"d39917e63f8ddb5ad4ff78f263a0c32be9919ff32a5ec9ddebc4f2ced6612fab672c62d1025703da9dffc6bd0edb78ce68ae7c3d721159d4edb23bbc001a37a329d2" +
		"6826b9ba2d10f994c38f7b310577e45c0b47dfc200c0362993c6b1a0164f986444ab6a9203a277185c9e6cdeb8d49a33e56b86f5efb57bc853c0b36a1d389bc53778" +
		"7df7369c451272e48cf3a8b855733dc7cfef6fd899e7f6530c735c0e44f7a90797ebef93ab825c8fb923c2a15120208700e7afbff011f26ec8aa993806df331f456b" +
		"6a63efa47a8d3a37cdc4719ae9fb46edf8d7c3eee419e03e5b68ece88e3a8a546656604f3437b1880d53f4df286c8d66e13146ce37edf886faf06f0c6829c1704751" +
		"23599b3f245ee055b1494ac21ce7769ccebd4bc2d05d7bac21c1a34b55654714beff88e6b7b027f68166d4d9f69e5eb1aec00f2e4fbfb987d0da123cc4f01d396d33" +
		"d2a7d4280bb9f8f079f110a64448eca52d8fe2512925703e3ee0c961ec8d74b77137de56dfd5bd4a2a353cc66d35b7b59d29416cc3e5c4918bbaa032d3f2f252d156" +
		"38bb846482d2d93c65f95ab6136dabe497427c69f6267d7a64418d141b8d3afb9d0d0a4d51044cce7db775e9a4c7f39b3f9ccf34f7da3c7ffece9800790913facedc" +
		"80514833523578f8bf02420328cef997844c9451d11a65578d7f33ec5518c258e638a3b8"
	goldenSingleMessageMAC = "1122e59e471e97065f748d1664b927fede4d5a326d8796636d80d1ec3d463bdd50a0831b476f525ce511b275f0939dc400190019b73745ac7bba32b3295632db8049" +
		"46942295c51906b33d5f86c64ff728f5d914ac7ab25c8d3e969177261b113f146acc14082600570c65a393552951d49ea0ccbf975c3964ff67fb7c9436b33bbcd58c" +
		"0e34a24e649e7cd11cbd8996fd0570cfea3f9a019dfa71c8cff4c93689c1f06ed39821d2aae1d1a7b6f4cfb89047f9083fb888d2a5f40b6898ccb54e34854248cec4" +
		"4b4cf3d6cf7af87b5a43ca49407402c847f4c33ba05523894b231426f7251c2f52384fb2de4239e9b3ebb5b0aaf5ea4af6587fa0bf40a3e1e2a3acf98da8cc026571" +
		"ec0569c8268dad8da5a2751dd42372533615501732c84f2c6d8a6687ae4b471c87b7ab00df707c191886fcfc4211e1a4987d1ed02f36b7b8b283bec3529ac834b107" +
		"8d94f681d36c308a80e0cc5bbd74e11300ee824243a1d0047f6f6d6beb97c78b62afc93bd1b5d0867013848951d7a9c7a7b9be31635e59ad21ef06a3d61ebba1d6d0" +
		"2a5500fb73933ada38dc7e115f401159dbf08d1b1628de1be1cd244ac74cb56a4ae7ace909dd7fddd1af4fd53bb5440417be3e37b82f2dc978d20855e5799535ada8" +
		"097a56488e0ebef5899c33d2f27cc321ed938f6857f5e58f157f2276c8e1706a2f0b42963aa462b5ef8368c85840eef03907f308b02b76a5ef171dcb42cf3112a808" +
		"a777e22f6662e2badb0d121f6ca8b14d4815977f7770199579fafa8e86f63a0394f03a8d819f4156c4bb43c750e317fc9b57733bb458931c67532a9d8efb8c53125f" +
		"2bd088fe4bab76425d8b421d879920c5ef4c9896a7243b2f748dbea1c9113e3efac1119330ed554dca92eccca0b1b02d7d8d11b263990396623f9b40d1bfdfca9490" +
		"9ee2befaad0a7ba4477c48c39a93422371b1091c4e0ef4af08b4ad4d80d4c7acb26c5d34d0233ff552b68544eb33a386a1160e0319cca3fd195e188d6ca9cf5f7250" +
		"487ceb9ba92773ba09382c0e0cea1ed5f918ad8bc751687d3deb6b7a1706ea25fe5587bbb9ccdf10e35d8cf731155e890c73edcaa2ebbd580f333cb6d64c640dd2c5" +
		"0c71a2e2ab0c15874dc1619850fb9b1f0916ca6b71cbfa3f4ac7b4ac9138cd8924a5893e1ba5bc9555b523fd9d15a0e130557be20cb66a262a5fd5889e4823633053" +
		"a56dfbd8a5e44b90c553a2ae143b8239fd61733506ed04aeaf18362468c3c3935b06a0a13fee7cb53cfce65f9048fba458169164eabff1da1f9fd6dd66eb6dfa8a06" +
		"4cb16da4039b96b0f7d8dfec20f73f4ce24fff13aa6e9d60fe7be678e25b822dd55b44493038dd635337ba80ebada5b8a2d9a3aee2f39f026d0842e38dffef5d30e7" +
		"170735e14ff16267ca376e29c363192412348ce2cd2820fb0ac55917f00c3bdae95e8239485940f6b639b3fcba4e1edf0b38ee7712ed1a5e22148b31139c4cded1c1" +
		"ea8e6928ef50149fa590ca068cedada91d6c6e0c8979617c80fae5437a96b56630c17ab980f25a979816321e7ecd9e2d05f93cef323ca89dec9d25e3622f59686edf" +
		"c0f57324ffa434a99f7a991732a00cbaeffd18227a57c42fd3c43463bb799b18053d2b0f600218ea268fa94951380774babe3f4da0b153eb41bbaf0e7a89a1023a74" +
		"04bb47d0b7f4d68298eb41a3a83ada35d0ec927d3245ff5f94c2f3d06bb8f4ea4eb61a9aea5c4ad6bf32f1c4c53c676fceb4bb349246e619d322257949904130fcc1" +
		"844d30056cba0e0cf442d293831e3ae6286ee03be18db6c1d1a75521142912d9a8ef0598cadfbf6c7e49ddc4edef8f3f73cd16154d1bb1431e9b0af7431167a7e4f0" +
		"784d6ffd8accca76026aafb713ef8790117c7a55882e08175f96cf2b4bffba5d54b57410c351f55a667f14138a6377bd89d3c74eb09aaca9b46d605f659180ff2a1f" +
		"c2625caa7c48d6d3a2d3b99b9129eba2f769e70164fa2b2c4e231f632159a457948fda5a723b2db29cf5b8e43a52e268ae16d03757f897c5ed6a139ee5eeb4c4909b" +
		"76e2023350cf93325b7cfc6d66226f0604de59c1fbabb8cea4951d55f36257139aabf9697e4d9f03c5af1fdeac74469736e70d0c9f948cc3fbccea007b15eae54862" +
		"f113630b65ac23822276154055cf8db56f3d98171199c185c7d774ea249c681d9e42226cd6783e98d3dcba2f54b3393f58fef73bf4e1bf4e4fa5dde68a3650aaa440" +
		"f82763b795d40ce121f8b976360fbc24947a05e22686e422443bd548678f526bad40a541b63623b0cd5173631e65f9c353231f3ec137e0cf10eb7215e39c7f2cc801" +
		"51b1855c2bc7a43e7a799b2c9fec4441d744aba238ada3776d5c03d1e284ac5f1d1fc30ecd900c47c219926f49425cb0df9b6dc937079838100c6d63b9a71a1e1be3" +
		"9c4a687c417231c4976dd029cb49342c37354e9a563700e99345a3c008bd75c2cac0d2f42c71ba20c5aac459c08486361ec3948b506e3cc0a8c7ae84256db1650ba9" +
		"2e1ea844c81d41daf3b5e549c05e61dcf71c60e35e1ee34db51247a6c2e869eaaa99fdeaaf78143a4e1cd51dc3fbcbd6fb884441b7eaf95172ad6ce1f7b7d61cf918" +
		"eab382e23fca078c308e1c41809ba9d3e3c5bf4d2e9729539d671394bf3b4e87e44367fb57fafe7f0406dad17c980fe520f06b71ece4b003e222b93fe4ab7dd69648" +
		"3c379c52c92e7e0b810723d3568338ed5857c96cbfcd090c7ea68bd74bc6f73903f97ff3ad26c44e3890ff2132db6a76d23993fe5f2affc6f213ae9413f344cb1680" +
		"7c7f1ce7cf74c19be7a6565226a619bd19e46eeee2e2202f738fcfdab5a36b72c713d798764d3cfd511077e050d1f85616ceebd18123c78d082ec1883ceadf7e15f8" +
		"9f72fe9af43a4c89be135c89eb7d89e6cf05fead7c9882000fc9e6af0bf235a1c969e5ccfbde377df819bd38e69380d1a6a7930c058c688fa4337276728357813bd6" +
		"72bf02a5044db0b4e0bb9a75f3952a28f8e019a75369558deee149bf1efeca993821e3b96f4e2b5c333eeb2e83e890d6281101382898f6913b07ae80df81126a036b" +
		"b483da42570f0b927988a39aaa7b2a3cdcd53e03bda5d89bdf7706ce1049b22fcde719c7f587e96bed4367df1e248e0a2e3709b56bc6eb6eb8bad8e16a703dcbd7eb" +
		"2feebe151b8a987d91d4578946f35b89713351070f93afa9eb7e4942622e614e3a96743400b071d47f8e1cf2ee2b312e4eed7bac5f89f59be7729621c163f50633ca" +
		"8f7b1e34d878608a1b0a52827a2586c2597ff8773f2e5949ffffafdd3b694341cb7befa758029ecaebf3c6b394a03af81d2004001999c2eb4c5e8719f6db2b0cdedc" +
		"bbfd5e5893e867e9a652bfb5c9b79724ffd077ea6bfe92b7134a779b4ab795f2a235b37aa4d9d85e113ecc237107b7a591d60da55b484b40672851114fbe52176b85" +
		"a45a4ccc2da4853233cfcb358079c055108e54e42ad95eb91be2eea86ea3f43409474f6daee0128b6607cc258811518609a27fe34efdeda0d694fa16fa9036020b0f" +
		"3b0f1891d51e7ff5362c54cc7f7e91d62f6f64ff04d8614b2fdb5a81aa52eb7c3755c8d6970ba7731d08afd87d3d45fc5825594e3fa009ee5f0b41ee2c1c4f139928" +
		"1e23aed87445dde53801bfaf09ee2b28ae79da94dd0429f2cf4db5a22255dc6c6e466b7c1455afbf5bcaec36786ca346ee4e1dcabe5e77efb1c3b564880deb29e514" +
		"648ea3b071677d24d1d8ee2aab7527cdbf259dfc702be5ff5c19c96cf95f13c4e76583bd6483a707fbc40028bde88e872d6340b6a041b6269f08fbf8f4bf042c9700" +
		"8b4e38d2e15d743959acb6ea80a19a6cab377dac11be7ffb8441c8f6b133afb98e1b5e968cfe6fc7b883a590b3baf70ea13ba91582f29a0873f6ade04fa1611dfd48" +
		"85ca144cb82f18451c43ab37f527d73a1fbe1885e6168b471a674590c51d5a4d2dbe4b0534441cdf18924bc094e04991c494076ceb4120823fec38bb7f14bc8b8343" +
		"cbf0788a7c3652853d73e21762ab2248480887b4798053688b798a60174cf0942415cbb872a72eb1fbbb27b7c8a5f0cb5d2c81422385cbb1f3223c9e57645473cf1b" +
		"aff5b5bed259b5292b87f5e35267cd7c1c0c9892064dab02e9c0764698d4e66ab18d42e68efe7c20cca7e5e960f2709bcdab8fe1eec40ad2bcfa27222ad11e4dbb76" +
		"6c00a80c3fe817303fc721d63eeb7f8353bde59b53a9a9bbb8ee0b41976325b424176281f913da169a7c0941fa9c3cd10df4c4a23edebf20455f35f912a846e883f4" +
		"9e56fb1f086233914c26090a7445eb6040becb2bcb690e85b453b883f59797dab137f8799d1d5cb82e6099acace26710c319378cee5f8d8cfce369945ee73e156ece" +
		"2f21af4679ec1ce2f40be6ad8a0050329adbd1738dd1cf60a7b31f439ad8713e06d1ad73865468b4d5649d3db98ae3ce161d2338878d62dfdda06d82396bcdd82c49" +
		"b4b4eba274ebd956451d8bcb83a15ad54da66c5628a727d2a0ff6bf5f67ec0a7823a571b021c46539fbe9177bf88a869ebc04fcc1ac77035395cbcad9a7373799808" +
		"f82a5b833bf4113fba62013f2b563a33cfb7092ae833126071eefc39222db2ee0a971cfd44bd43fc9b4c1773882d59c5d6b3fdd0a8599624b08a2f99c3a3df532cd9" +
		"393b4e324340fa2ed82d56383ac6f8cb44e00064bdd3229f7bc7a9a2264fc71759174df96ca725ba94747ab9d7b380a71306c633080a70ef931a52817f63917ee0a8" +
		"fd0912fd6a3ab22613fa31876a777363e974dcf4d1126fb0292addeb743609c7181a408511ef59472436b6a321c7ad3973387f5be9242957af8327ca1c78cc36a745" +
		"64e4f57fb73156e769dd318709b794280fb885c6fa245e615680100a9061ef5ba594892c8a751178d23a2334a7c08d863603298585976aa8f17f17e4e9cee6a53f78" +
		"cdb205ec1b532a4dafebb80c1491af685ccee81b3da6e3a85fc4d54c66c23322c30eaeb877494d15945f2da842c7f279c7c62ad890ebc87b2d6f5c00c83608191a8a" +
		"2f950ab1dab711fff2baa90462d5e9d2d175dc4839f5fac893b0347e2d29a82943efa86df85a0a88da9aced6bf0445135b84b99ac339a48e67c54a71726152bf4209" +
		"d74d4354b754b196165ac39243a0877c0850dba24d1060ce44fb9babbb60e76adc081f02f0c25efc90bec55665665148084fbb477564d12ca6e907884c8459de09e0" +
		"c60867b7e8d666ddb4eed5ec9f9f1859451e397d66a4e62c432be1121ab7a2aa6c87003e39f2ca5c009ffbbeca6c5aa85d34f797c07f9f195fb23eb5920a6d21215a" +
		"770ca5b017acb7a72c09e0f5ea93bb55b36799c2e15d2ad3fceb782fe9e23fbd7a8a409355bdf66daf07e9f53a5f08acf2dd83a8133e3e6371b886c404267429fa08" +
		"7ac0bdbf754828c0371ce8bbae09e7745c813e9afc7a7724cc124e5b9caa4912ed505fbf6148f42dd98952091789b58692483266fdab3c3c870fac320c46747f56c0" +
		"7dee75a80a44a92a8579a3dfc17251da2530e87b5f2765a8c2e56108f1f20224a2b1d3e125c8de24fae32d9292ce0fc0843c802338052f0025f0c5130de200ef8766" +
		"8fd6b41308ed19a899f5962ce79adcfdf285433c56581ec7a4c87bc39bf456d470ae3b9666178286b6e8d7fdb47e0f8d64b79687329a3d0888968dac4fcb22eee395" +
		"1458ce5dbc4076b6115d292aa5bbc58a6869733b8d82919d63442404ebe07db939b81cd4683defcfbf5570537d398f2826633394252bfc60cc5eb5a6234ff7e34888" +
		"cf38d4f97a05f8edd5112ae26083f644f616fc648929bed44afe2151cd9dbb7731161c92a148dead2b5dd13a95c6ba590593e74670452d9071f93513321a6d759a5f" +
		"f6be6411dd273d7f34a58abd2077c5cea992005d5cd5471153ed8fb00692d5ea63872000bb86447580cdfe08894d32c9cb8b9521e3a977fa99e68a58252945211abb" +
		"0afcf54c186ac2bbb4d3b2bbef5ea5d0618f79dd9f6af88606ebd786fb6915758392a21a8aeaddc4248d11affe012a1ee6a8d3a2b20ff9a79b5c0cd799f82c5061d1" +
		"07f50a7fbbce9c2080325930a15b015e0c7d7059d1481dad2c79b9ad1e4090050fd42201b5df8ec927cbbd99ce22af637db45f1228d0ba7e09f43e95e8080154caf7" +
		"ba9b04a9b805859ec012071e09940b6a04c16cc9503b1ff06287f98973416d267ab1f9021d6713a81ac557d341d698671d298da1c082dc484b4a163cbc8d97a46097" +
		"0ed5f36fd88b5117e395b994adcad3cae46a4fe0312f609c9c34d475aa94b36efbd7a26be39001ab189f9402f9f69a30c2d72cda4360e99e092e838f7445e2eb2dd9" +
		"03f79196df28570413fd9faa1c16d9a4b0414503ecf1948cf1ecbe0692785c80bcb8a1269c3422815a39e1f1fd8e38ea955adb039f39061425e9d9afd9ea17a8e79a" +
		"01251db3c172615d95a305c0045f318bdc8190b6a293661f980b457fa6f4a630deabcd2b33152ff4a9a188a5f352c2286d6a563d6dba7ee80e81088f3574bd09a9d9" +
		"cd4d8dd6374e71f90010e9dbe610aa8e581b4965e35cb3310ec16611e79239b66f823fca8a55901ab25b8b378f36a33bfa0266b080e480140fbb963ce44425129ef6" +
		"1195e75a886dbde9cf0a52d107c56d592cad3e4c0e9faba3656312ccff72979c07e8d59e707b6efb473c907fd099e6fefcfd2c6463f095d75597fe7e9dae35d29e3f" +
		"4b0363edf16e6dab53feedb56fa27daae2c16104a0e570d88b33943f3ccbbf5a77116b044e6d34c845aa37d805dec123153ff8e6158e638363141116fa529fe66f82" +
		"1df648e321b82698c06b0210bab5e6a96d548d383c98d70d265dbe4ae707fd19dffce10c036faaf63bb4eea0482ccd2db7d177e321832e8c21c4bef82b004f99b89e" +
		"0b733d39c8aee76301a64a1a0e5291b95ffd33a2ea034b066bcc69e3902240d2aed9b558a166a2fbb117233b310f74329116e6780fd2dfd641eeb46fd1bff8d2569a" +
		"f10c0fa89aa538ea249e09471be0239632ce8d1172acf93280e6baafa7bef44dd61b1145630f2b2bc519ca7f12cf5cf52b29d64e90f7fad5c746f510e920de74195f" +
		"c32cb80375bb6257f09a3732c1f718d8769d65dee1adb791cd0b308c2e50de9025f0c1ec"
	goldenSingleMessageNoMACSyncOff = "d936e38b306bd6f0132e499e608ec52e9cb7c50e460871f301c07ba30a817753c232b7a3cfef2add30b0eda242c3de300019001919f6b0214295cb9aa99bd1c6" +
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
	goldenSingleMessageMACSyncOff = "547ba4067a883c80ac8bf2b5925aaed01a0cd185544c391e639cfdbe984d853e56f97d31a06b81a7e9352b9f79db26f8001900190f0ef0379b29f4b1b9d81fa0" +
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
