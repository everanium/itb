package itb

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	goldenSingleMessageNoMAC = "320838c184f33a519e4ee7cb9b06bcbcbe01a0a35db431cb6dfeb61acba3d8d6c1b18cc268514b0607fd8f31c0d8105c001900194d34c2b763b73887af2227ae" +
		"f6dd98772f53f6a469069c54a791c759c8b26d5869489315522834fe0dae9dc98418a9bf98256b6b416afac5c9d94897175d7699764e6ddc2c52fdd5c8ca3c13" +
		"77292532f549369463bc1b35166ffe6491673224cd43cb0297447161a92ad48d7f91b7ccc72a79c7d06cea50c9f88a813137218b61079cc29d63b8aeeeb69e34" +
		"d1b04652c46d6cfd56f88620548bf4387d81bed2e15828b995cc7cde8cfa75bc18104d401a0e55c306fb78c3745f1d5a1aabd30b499dceab9332b366166ed975" +
		"0c748e8fe9633ae9955c8d98d029f611cb7997b2c4d52a7754a11853260c3f1c1ad82d3bb2e458800520654bd69999e2843e69a915d767544fe043b4cee67c84" +
		"941091d7e02d31525388a6c54ad4ce92e1e049c495c858199fb5c060f71e3b47f0c2519b2e9286b609fa6f77e26448894ab6e1e684fe06671f367d03ecd49f82" +
		"5ba9c8bdc40cf8c40f6045a77a51b2553aed41f5fdf24d2946f5a27b53fe540153d0f7a85a8e4039517c52a3ea22ef4214eab77df9b4687e5fb23ed26205831d" +
		"49d219a69d6559917b7388412246dc370baae58fcd8b45342dea6ed4117e9861fa2320ab938bf0094607cdf88c001f1b172be9b8d65755744e95e6556211726a" +
		"6748bff237886863d414275e38d8cc2fe22112fe43c9acc59409dc30756ed49f307d321a4fc7b847e6a4e9d300bacabc25599f994e1fd0bf73c3747b6ed4d072" +
		"e3c19714b3cc41b33635aa1125388a06283b91674b592db10a70bb3aadda959da27f74d32422d77447d3ed7572e00081c75c5694810b35ed73b41beab08788f8" +
		"a24e0ecd86277635d59ca3dcda366c66eddfaa4d155ab32d17b7770ae6dcdafc0a366fa5f2deae95a60e4771d6559d48f001fd5d5d294c39aa09707e52ee40b8" +
		"31b737c58d35d4718880b5def0eca262f0dca130f27e24e642a582bf3830b61d6a26fa1d89fae5309804a284c17184751a336b43e13ff5fa1e1653fb7d8a0873" +
		"c2861da46212ac3565a498914a37c58c2990324d31629087cefd239963e92f69a73a50d61646009d6f3d514549f5ce484fd49307eeb8e4008d2a2fe1f90b27e2" +
		"dd34855770f2d822037b4ef7791fe2948a8c91cec88c6653aea62f0cde8d55108fca539de1f0092f726191b29f263a2fc2879b1adc13ecfe5795389412a1b896" +
		"f70e7e18de66a542c72c7b6d0aa7af089cfc1ff6bd07b60a558eec085f350a0427d97d708a68c871f5196d595551bbfb9462ecc195bea662debd0700ac688bfb" +
		"833318f77dd568f40de11e3c654fd2cc631dd695cd7ae80d6ee4ff6a24f1e77726dc1a8b6f4bd15cad6a2f8b85e86eb211feb3856994b456d23366d3c661a5b1" +
		"3457b691eda5505176a4a3de5d24807feebfc1330d7d2d9e7db728501b236fba80fcd8d28cd1308b3f5ac833144118bd9a2060ccc5c5cf08d451ab88e7c9922b" +
		"9cdbb5fce9e27c929949d2c1cd0f587686db0083398fb989f550976b07970a8a0723360a69ea96f2f5748144fb12177fed24b97878727d131f86371b0a1d4b3c" +
		"bcec641c0419e713fa52c0ae680175026a01423584b7a3498cdc8744beb9ee3cdb8d2718032833034d09f47bcf296929db990c59a3791d973a8b6144ee339363" +
		"4db8c6bf894482a53c0fe2e6abaa3e269f01a2a23466a76b022c7f1ff759a65ea01a6684bbbb03b3b0414ea2e144f77ed1dc175ad062f5f04701bfbfb99fe666" +
		"1342af0ea9f0916a4b18f9712f9742156c1d56ffb8da0534957ea85158849e2d3877b808ca4ab3be09ec4ac31bc2364916cd27743696936c16f69c2127d796e3" +
		"f773529d016693d3719e3aedd5aa72119341e84b84349ffbd849e500404f80329193c7f574d1ec6479d4309a82c269ca4a5df715fece27359515f84f19365253" +
		"9c91204a7d6a87f064639fda8b03cb1331c406b8ceba86d8f4a2af606f28b9b4b869ac54a3b56d6d9f8e238b4e656be6d72b5b20121175541a400b2878024151" +
		"8bd2e255b8c474e68fedac1fcad1ba5537ac78b5339d660898ec2574e3d1c662c7309ebaec862d519eceac817a58bd5c630d3a12ca7482ccb705295d76360b0b" +
		"71f53a785b4cf6259e32a061f3ff57b81a26cdf703953d6e38470531bd85901ade68c34f64820a1103c0cfff6bc8553feabdd6e18c35a9ee74ea0ceb8f2649c7" +
		"03b6ba21cbe6d5ee88ee8d6b119a25eb206ff451e7ee9da20c984b40a41b16c29e424c28c43ed9e645a78db1f7f075bfac60840f18724d448a867ad391f681e5" +
		"17324e1c8553bb44149587a52d0cee94273aaa8433eaea4fd18768582ceeea1dac10eb3ca8c9219eb83a7e0581d0328d69a5168867462a196cc947760efb6f21" +
		"59d6e1a5b86ec5e37b4c89d9d677799dc40db0131f024981dbcc35a39c03b813f3d6f177804a602806a858791af6500efd96dd8905382766da8b8fcdb6500810" +
		"caf7bb0825ef4ce41b8996036c571c0dbd90e1a0120fbc5580dde0107743e985c018013b452874f997857a496d3d8050ef256ca39d91b8f331b1513be2b65555" +
		"00a1ca33868b82b78ea8446aeb2de9016e35e9681c1321c8c390715d88e17936eb79e82ef84a27021592abbb568062992e41b7b9b90154b840b001f2ef924539" +
		"275dc5509f2dd456ac196a342a7936f050cf24be676777aea99f8229c11b7f35c0cc67d557667835824e104a4ade960a5f9ba7f8a31d70482d73d6e19b8a688c" +
		"69727456dc15095ae647289f1092f0061cee51c21f50cba24bdce4d2d955f4aecf9c5dd21450d42bbb3e457bc174a03367312bfbd739cb9297597273c14f3333" +
		"8702d17c3fe23f38bda158c02b1719b85721207684090944c3bf094e36a7c8a832731896b55d20b929c0bd8ca19e7a6860cc7e8e91b1a6ea97679504747947f0" +
		"79b96a6da6c5811a7702582c07012e357a6bb4b107f99a9a525b8ed880f35ef6b2c6b92856461a517813f5c93ed4b2f86a70f435970dd156c6e508a66ae33c7e" +
		"4a5526e2ba823e1623ea9a0cd5fb1d12a6ddf8c816e374accfae1ecaca5eb5f440fb9816442feeaba16ed125dac31fefaa170b340d88245ac5b3feef63c4d610" +
		"cd71554e5ffbdff1095f4da214ceb4c91bee775680c432c0884c6a6bf6c8b3f2be8a1691088c5e9e6defd75e122db3d9e621e816923b8e6e111d173621b5f056" +
		"fd6e7e58213ffb7998c4c28392b965bbc27a7f57b1215cc1a3de6356135c0b1574c9ef7df8a66cd4e83d46222e5ceaf4c06a23e67197ad5744984cdb8df8334b" +
		"f182cfabb1c6accfd183ebd40552f0c734e58b569ea517f20dbe14b63a57e19b0530b7a49e7713540dd1027745272581c864b3ecdd4c1296f45b53795a6bf7ee" +
		"c6eb3935d133a6db17e786818ec85377ff1c0f9c226a4e9dc6bbe720cadf2d95d9d21a1f30b14184a0549325650e4c014dd4c117c21fcd8c8c84c07992386677" +
		"7578db38de6774a3d21233b5746aa858650b92cbaeac8e9f5217ab8a52d20fa36d0f98f66ac57b19072a9baedcf7331b61d17886f1ae2570dd8f757a94719fbd" +
		"42075fedfb449db8454a516a400572fb75742a473e4e8295232cb73c6893b9f1b6572248398072c059e0550f39ffb0678ea8662d300f586df2515f201ce001a0" +
		"bf9b00897eececa82b969e319872e5be1563720427fb9790a49f19b5f91a869747ef79c27a15d1885d13a9e1dc09b3a2f8469c3f51bc5e63103f28840740b60d" +
		"a859a343573a797eb58e2f25c470772b2ab1e7d2d81cac5fbd57857f6fe6a018292e6c7cdc83d4444731c7e87797e90ae7b61cc64cec3f27afa63bbccd393c5f" +
		"34be0678abba205e314babceb01b937a220fe55cd4c7bd599cbeeb1dc12bf8255200099caf6bbabad5380e99d5581a9826a510b339f7e8cca80624865ec6f05b" +
		"b54a1c92ed8f9d12b9d09c01e22a4c095b878e09a3b2c8228910857c3622ef8cfd86e73466a87db0f7a29f27ba4bbdc073c43cedda5f43ae662b017f6219b93d" +
		"6c774a93364a79f119ba37a466d69bfd273cb815f7ddbbebbaa042f7985d1521add2d4a91b8dd771482b608f3a39827129944369c39b12c26d361eb8f4ea42f6" +
		"93e2edff36eedaa220e85119079af845f2d98f8124f3ddb2e396a13172d3d3e3dccbe9da547da1535afffec3e710eb56d1b91ff8e6d7f6f8461bee76177222f6" +
		"50fdf82eeb594506456051702614d468b6e433f6a14736c1ce57f206aaa55ec552f022c95df2a7ff03f09d4e6ac95170ce321cad430bf2940058daa7835a6a9e" +
		"24cc5b8c6a6aca5ef81b3e6397b4f45cf250395d51a11f9059fee67de1eafaca06381e5e27fbab8c0def6d3b477d9f6f16d98c2987553f9f468c9cb2a66599dc" +
		"f95dd6b1196bdeee221834d1c1452f60298fe4d70e1e50039d08635db48da9f6cc714169fd16f53336b3c24f5fc6320145ccf0af4d79b945fe6ed8cdf3e6472f" +
		"688f9dd0d0c8c5d9ff0842b772e5e9fb89568db72884b78c9131081c48cc7ab93eadf2f0d3333ed2bd43fda7861143d93928df95c7e36f24a1e2453bd2ab3f58" +
		"3abd6d208683e238fce97715ecc1cd79d34015edd2124dc6ded7a35b99e0a433d1a5ac93be21720e7ab7741dd03a8d3764656290ee2a4c78c70a912b2a2c9c5d" +
		"f6ae026e34927278a36e1edc34c6518e0f2f89e5d3e42c958115be28cd58f056856716f63f047d1617d655d2175aaa2ac60ae68a0359acdb24f32f63c4584691" +
		"709d80362d79c729f156bbfcc613c4dcac78d8e34edaef53f5513f8de1cfa8db955167a32dae6bf8476584da449a8d04cf2ccdf4b5234c41be9ddfc1f91ab84c" +
		"a7be7aed8f37bac41bdce37bdffb70af80698b0509d34778383b1f7dbc83dfb0c12791a5afc621a39000d1854c97b0dc2e39c4c8ffa777aedda7b64ad1346b7e" +
		"488c28b6890725e4e3aa7d222bc36a6498298e8f194b0fef6853209662a151f27a9fe23dfea1defa8e5ca71453ad21bd7ce64bf4028d4f278d2cebc7aba21cc7" +
		"5b270eb1eefef5cacdd2c071ac0b8749be81e8c1eef4f6eebab978cf15b4d61553cc020971cc692d4bdef8a90f401687031e6ea57a853e89bf9cb42f4a92158c" +
		"f2f2facdd1731d373aa6537d117aeb048f1c18a5f6f182aabd300c7389b2aaefd9be6808e943db4174f23b8eaed87329ab6953fff30373bf2a249a2ac7404061" +
		"176cb8b4790f9902d47ad4a009c5b5d01dba07f3274527764f6f57bb04320b70be1e8fbdaae06530f5cc476c49e5154ab25feeefa86ed84fbd73e18a522ecf2c" +
		"98dce4736a6c7a7316f242e0761021e28fdb1e4db5937c4d22ecad3afc0dc666c929a6223edc075d31e1ec24bc8f59dafb13e74ca581e985eabb5a056a640035" +
		"82042c49eb88e7547c6770cd1ae57599b3f3dce25acba88a0d58fb04842db38f2a54f123ade458342fcacc87cdb60c96acc653a4f9dabcc461a68bba7fac2656" +
		"31ec9d0886d6fa024d3a3cdb0f797a81e69e88f138d92a200f0cde9603e956b94884534985a694cf9f916100b8fc096bc4051b8cca1d84e4fabe0d651f042a52" +
		"2c256364b22f24c3ee4940a5d8d16688325e645ab675a821fe486158713cb717424e30495db93e939025c858926ef56da1575753ddb2560368d09cf0a24ffded" +
		"ad6584676e85f73a9b3ac49fa66117c6f66432d532624a23f455ea8167e70e52f4524e228c6fc2814795d9ab3e5a7876fc41efa00cb771f269e7599c33cd7e0f" +
		"d3af41716be5fa6321696091801d35086582aac0899bb52c320c347d8b59f2f3096326628269ee49f791ccd35b5fc7e18394cc507759aafeda875bbfbab0dae4" +
		"287070a0be32c7c749a3e4b628f29b5770ede21472b06519975c89925aea193073ebbef186e43fe20607c8c0aadbd3d8f15535a59e7164d1d0624d5e2fd90e13" +
		"d69c96fbdc25204ff186bb5b6552197517cb8f8b434f96ab86a6fea0519d277f5806884d6b0a5c0f84cf659669c93cd8607d60293b511bbb47b68f60db19e623" +
		"1e15733db46e43388c00c74781999bd8a5641b6f366eb8a01fff8b50617dea2302549c1e556f0c2155321b878d9ea31c50deacf99d445f6e681bee28ff4e50b9" +
		"35949938bc835a0bbebe73b3727ae5cda09747be0540c5a1fe024cc3d9efda155a3bdfdd79b60b00fd0b7bd3a850e6154e4d6b660cd75330fea5a4e0a0862285" +
		"71ea3db445f5e77b5ec192f9a7b50749d6c3e6878c2d7ca5da2ac2101c4bc1a5bb02c88e6074d6c8c765e6e71e6b3d5aec9241e66b13b80f88bf53a93cf3e708" +
		"3d45b12094698fe98b9ef610c9a1a849f9df80df2f45fdfdc1880062c3ccaa96cc476f0ecaf790695b4df601d721097964936aa55b8ba5d394c42a7d8dff4bf6" +
		"7ee50043a530d99d3eaf0d7ebe4711dcdc4c0b98715ad999daf262fcacf709b87b2c1ad7d8b539440ee4ce1b5c3fb4776f04e01aca5019baf80dad5ecc9f723f" +
		"31697bb7ffdc87f3d29520028b17b351df995bbd82121d36d9b29196a106e5cd062f93e5a4a7c22b34ef964fffcd48af9d4bc20b912b1b04d741ba93bf894954" +
		"e556dea1b414e48855353ca7ed0667068663f72e8e5a640d175898c1272a838b13d69f5b9a2fe1b8d3444aa37c078932a52fc0a934d108249382a85812f158b7" +
		"67e1f180ac5288e581fdc019a43d7b280acc5c3f191629a5897c51ebe859d99d3d74020c5e48b58623e0f3eeb9a7b7b00704bb089e332881687b98e73b2b45e3" +
		"6b726a56327d5252f8f49f76619849cae2080b8c4035c4e2a184e0c4059954e7570600f0188bfc0a822a881d6cf3e7e0752131f3fa241adf6a1692e790de084a" +
		"a7f15f0b66e881c2a97de2ee6088702caf4e6ecb5bb219d4f9440902e8332e2766ef994679d463d1aa1199c5ba791a95b8ad14925757f0782fcca731fcf91d9d" +
		"b7da6669fab298424647210a4b4e6e4eec311f114e3371cd290c6e6adca3bfba193ef0a602bec28817a054f5455cbe3f80d15b9006c23cd88bba14d2301cb33f" +
		"460a75c4eb42214730ba14838b10aab4ea40aa12d6cd69afa821c5cc92f3e21ff912bae93f5d0427cf88f584717a674436b941a5dfb5bc42cc1b17d6"
	goldenSingleMessageMAC = "78e43e9bcdc41a86a8df08933c3d2cd5682af6eee2d13f652e315b2b8a73b89e4e6407c436e8052ac9afd0ffb7d99874001900192138f53d7cbe1023fecab602" +
		"f8cac9c42a8741d5e3d0a543b3582afb880e8ec7f87285036d8a6701d382a0d56faf6ecd2f024c72aa6b1fcf798a4cc30e68af615be7debc9b0a574dd39d6706" +
		"e1a8ed7c15d1f9c359b4ba09b1b8a787fc350ddde20902c1aae8df08f81c32207fc37b9aaaac36b23a1ad44ca41fef3e3acb0d8bd74817783e29cf6bdc6142ac" +
		"741bd213f015c420d801b5a7ff0e922f23559d1b4b810c9813368397dc722707644847664e62ad8189f9a7b5d71c60a6b6e6e0b8af2eeeef1826ae108e6fd12e" +
		"d0a241b035334818a4f0c87dc0e5a275bbf4c6d7b65941443d54f908132f6f0ae97ade0e54602832d5717d0bd9fa52063b9e7cb221121c05339081268a252d59" +
		"326af2b12d02a11c53ec36ebe8f145e69bec4675b9ec75d84a116aed729ba5a93ee148b49f96338ef01e81064bd39fae046a6644e8a8c964cb5fba709479891e" +
		"33ccde180266b27a5f7ecb1b348b9f30f1a54413743ba72b125947204cc4186bbde019713a503f245271f827f2542d9193663d0d79c17970b8e2cebcc4edd120" +
		"fb0e2fd5859df00856cfa6447c1a8a5a5ebdf4b594004ce46fc92a4be57bda06f85f18fcf17db814ec091d89823f7ffc6075287d6c5d0118fb8ef917761bc0e4" +
		"921022541fe8580cad84ac6f04a977bd1900d8c1c54ed1825be1644c831d875c87767c123a9f2cd758f0763ce70dce36a0d4909c4be70e2e4f001809b9f489b4" +
		"a61f01ca4ac933b53bccbe7a764dd878d5d4aa8cf6f3521e9fb90b8d894bb0bce1e0dec6ca2e49cb24a5fbcc7901291aacc03dc5d12b7bc028df111927c3c5cf" +
		"3687faaa58f9b27aa2bc6fd8c080e43fe75f4e5d2e2cf1d40b43409ddd71b74005f272da673243c4069416d3aa74a3712e7013389d40294f534ff72a17a31438" +
		"91844c23f7242887cc1c1dadb623b186ad5a90e26f293fe84b9b92c51c41b7accc8f0ea1ea43b0c5892e7c258af771e910ca1f8203ec999641b050cdbf0be9f6" +
		"235f8fb40dfa6ce7eb1cb227bc5229a1d4a26cc04f946761a144f66b6eae105fe646f9ea7b7398d2522ab7ac80a865349cea6481362423444e87180fe145b331" +
		"90a65e3b99c70616eac53e21d799cf0227d733ee5b9d226b96713a5236fe1ed9fd209bbe5bd3a4469dcb281cb05411cf1ac833f598f0c681dcad4fcb3c8ebeba" +
		"6e77f94f23b3fe4216c0f8f1988eec10969b75e4052d8d6cee3af0482c77fa24ee363d053314200b4f61da15918444985b28e3cea8334f163dfeb256c10a442d" +
		"cc5d653c1ac398cf14ce00b5c7e2fe4a2485b2616368aa62eb9297c38446f1d92c6cd56b768c5f903b32c368c08e672a4863b946fc3febf72a8be8f8f08ca81c" +
		"e41ad7928e5e234fb997db067d84f1f0a48503c615d0bc671054442d394322bfc513d07ad0d11adbe71d1c971aad72157b495848701cb87e36073dc601071ea4" +
		"c8bbf946a0f75f350d1d170591adb7ff9fdf1173ee40ecf4f5c38be9ed10774b655b43aa12c11a6d9c9b5b8aa839e5741024d5157d2043b58513da621d4d02a4" +
		"1f29efe4327e20d0ede5593d7b4e987f645cb46aa932e8c8542b2bfd1bb2cc061e33bc4f7a15950fb3f3f36b88d2c90969ea9d67841d798af0a3df58f725c428" +
		"03e3231dd4cf6884fdc475afefba67f0ab5b676949852467554a23a38f133c90bd62f6864265ffccf2b2ffc6ac1e7b387dddbaecb181606ee0afd2aa0e414eb1" +
		"be151e9574b04fde9b586b62cb1e149c6c9178b1ba3eb91f78d0a44e0a4db5ae136edde89105995147c4e4ade425a6a71cd209e57861382bfde2fd03ba5e5f77" +
		"57db8ccf59922c5f79a87578c1bcf967f86f5000c1caed3f9c797952848641e6dc449ead4dc183252cfcf97440f6333c344acc2afbc8bbb2335fde73745a044e" +
		"81ebf9bc0f32912d9c6ef89da99403d90f8beb3ec7116ddb66505006d1d9ea9e827c33418d33aab03c939cc308d9f6b911cd92f26e6530727535bf8167061e99" +
		"3c15aa58742a8c0ac8f4f4dab5063868c4dc5215f3e39178cf67989afd8daf6a2b6d805e0503cb05364a4962ce302f703925b24eb8c3e9612c52e02cfe7a88ab" +
		"979fb47c65813657fec8c15006031fd987176ea1a0e2cc592bc426e7879d13833e78f5b8d9b1d7f1a1a0c58bfff11f2f02795ca0be10f939f2e2aa000d912cef" +
		"6a91f5ddb8d9396657737e0f015f5b0bbabaf922a62458080fb682a1ee5f4fb3535650d82e536567f8fdcd5a0cdbb08cb7120fb6438575d8984d799e252b2954" +
		"3d6a3061fe8f52341150ecf15c11ae468ed0a27e6d93a96bc0f4a128e60b009c6f226f1699401947117b1bbf397e0232145ad568af1a2951c572f2792800d92c" +
		"70dd7d328e3a3d1bccfdc6f590d7efb2c4fd55bb7415838c310c7c4dff37d7f40c732b69e9392f5749f3ef4fa6df233a506517cba76f7430f703422b2bd0fe54" +
		"d664666e8188368b66358486d89c66263fb056743010ba57a46aca19e8f984afee59182aa26439712aff2f5b6022f77997f650f08e088c21c09605359e09f665" +
		"d847c96831236ddd144a84f33ef57105a5b10b7b4b67c25b4aeef84b79ca7d662bf40bd6900c2325dfeec0c6e62225ff6a0c7ce02a21cfd9e0e1afa4aee29eac" +
		"9d35b670f8f755e6dc1a86e6576cd161091ce423b6763b53498bc2bf38e52b59b85e77a049f36f64dba914c92bfa10206ce95dfc0974e7a85c31f699ddc7195f" +
		"3f4d7d4dbadba852ff250fc590b610d72acbb7f919f04d0e2d26cb3ee4e80fcc9eb20ad7029a0e6a6c2495089ea70b8a746b4cd261a510294323e1bda2c1f991" +
		"c9631a58e155e090805b77ee93e8473084bdf6547564d0a6626602b1cbcc578e01860e83e4b5f83b1deefc33487919760725a77540cee33bdfff6fdf579189be" +
		"34f027e6c85c0f8028b14f4d25453266679a3167f12a77a90f42e68b1b1ede89ba370f023193f276cb21fa30553d541e53f044e95cf781d4eed51fce5f78b677" +
		"c4741692e1c3f054baa2e5d18851109c830f47af3bcf4f2b21877249edfb8e8873278a2defec8a085727ebe5b2f6cf1f9f0b3321ed8d8b102cb9233bfec4212e" +
		"0f46003200828c655a74f5f3040827f6e8e63687b703598230c2f587d90cad482197adfe7fda59eb39f5950dc81cea4f2b0341a6c8d1acf2d998e680d7471017" +
		"5833610d8febf3e058170f11037cb0d60eb5d2e20ade63973aa335e86f5596b71d0e6188433158dedeaa26488ba5640acb4b474ecde8e316eb92db9ce9f38f20" +
		"8325eb3ede81fdeac30773137f4ecfefe21495cecbad61c70819134d9453047fe455e1c03d34404351741e9763ed045ad4c42fb9c4abd3ede2fa7e93e045bace" +
		"522d8f71a20f40fe601ea4a56744dc438183e9202efa4f8458bd9070e79e56cd696d747cae18ac0448d1a9863c165571b236b8e43327530a9081a8225b61d04f" +
		"d60090af0f8658864f679adedb8da29c93e64757cb512aec9b1ba0c0d72264d3e56b477b4909a812b0494519e3c9e3afaf261ce4d27bcadfbdc210561cf9a7bb" +
		"b2ca30898fb49676c53538a22a812e9b6ea0aca6179833e081ca80864768476dc3fa725496c94ecc620e8767dd8283a766aabca7ae527459700478b27b9decad" +
		"f6a90338ccdc17a4cc5dda9780fbe59da57c0c4d94aa5729041cdf92d769b4ba8bdb69c2c995f1f57b0904d1a2ea554569e40e44b5a893ce814fabb9348832ff" +
		"927c138e72cb34a09f4c8976a376c9eda6df734336588cd5a9a7eeb70a3a596fb0c3ebcff7b1641b0e775438d6197f72ccb00da2e3fb7b528e9c65d4b35aca9a" +
		"a6faa55744716bf28a02540483bf9a72600e3dc341f6e40d5939247e63313a9cecf2d559a3fdcd5f35b9f232f30df685b78ad02d30a841ee80da6c5d9b4aef74" +
		"05706f5d508cc11f2dc5783425b4a2fe34dc9ad66dfb3ca745f1891b57c847257921ad17f05f65324a381f18b07d5e2bdee02f94f43aa5dbba6162680345eff8" +
		"174e5995df92c854299bf4550ca2165cc1b1b7fc5fc95ed65e84b3497fc056b38513d48123af422e5c0f8c3cecaa811414aab4207d9ea6ae47d1ebc9b517855e" +
		"dd7a11a7287bb07c2c270583bed1b39f302d5d04631442e8aeec001af3ccc216371f155e56522c3f79a91aa4b83609d0d98db7df7c4066ec24fab2dce9294a99" +
		"1eafe35a1fe347785a4aada4be5b093d3cf7f157f4fb1b7783171daba171d16f0e9e38add16a175284dc0b9680c0ed479c851036bf0368f24e8895834b466869" +
		"d5c757a41324e8550fe572f40eb6f3de8862ebc5694b919396904844af8197a93882c6328477f1e8a152a39de6be83ae7490acfc8ce39a0b1f79a105da0aec0d" +
		"232afd1c533c792d5bc638bfb4fafc26ddd0fbd1fc07ccc9ce6c362687a1ee0d9e01b04bdc8b41b1afad3641ab0aed275556a2f0ab47ec8503dc561c19a9fc64" +
		"c5e9c95e651828d13451658a5e2fc37cfacbb96d666183d0133f6e0e196a9d27f8aa17f14a4083e7cf267a6d90a24b365d2a2731593b16f26ed97542cf17a18d" +
		"5366d234309934c9b209c152952d1773c561f2f972fcfdd7b6438d2f4c3360378664613f41eaf58dff057cce0a3f457425dff2923a228ab2ac6e7e41192c66c0" +
		"85fb3d7e17c44351e17c95f0b4fd1cd5b519b082d5eb804d564eaa16036a26cc1c753701b2375439c4f3ae076246b10b10001a8e0e9021c2d1443b1ba1c8be96" +
		"21a3b00f66d759001be7bba9cb13d7acda66cc7383d8f8ceceaa822f90706a6824092f8db4abc6e6a22f865d6887cf0b107fe9875307a16e65efb9d41536347f" +
		"d68823e3e6a41f250b3ea1bd9a0237d689402a0472207de32b223480cfbce6c95c01b37149c1d6b36a628976e1f52b7b35007462db3f20a87a8f15f653408a8d" +
		"e233c2d76fbd03e17a7b57c128ce7d678571c93bf9e2711c2f270152a2462a718853359bb4c3ec6ea4c47386d86644d1f867ae88a2cfeffb506fa02e46037960" +
		"e01a6f736d36299e7b72856cef4f45ad212c69f839ce74286802b4d048b1b159e03bd46009517efe2bcd789994d1ab0b37b6ce00ede8c3f6176d64b5948589ab" +
		"7f68b796cd302a016dec056c7e13bf62e94606cffc03ef4f465d38849cdfd30997de8fd9cb8a31181c1bb49931badee5591c69110e121e0c102a719ac7f34650" +
		"6ca4e629f88bd4bce3e0ec1feeee5965d77aea3ec57babca0a023916555ed8730695da70e3428a488f3b2aab98cbc9c91331bc6b47e1a436a9b2c9c7b41a24b0" +
		"bced60bcebdebdf3a6a04fd11020a62cace469d95005a24a1e8664d3dfd765ba8ce7ce532b0e6039a22e6232478cf62139271194b1ca1c81e129af95516bd749" +
		"a60c1fc4f3edaaf267b2572f3133afe5e4076ec8758e996c100bfda78a121a43771d8e5b591b46bb48651248812a309b08d66899d84f131ceeb528879076cc49" +
		"af08c27cbefe9df840a2a2a94434b62f746c8f14e91e3c78a38f8429462f7df3b832074e5438d5a1d9c1e75c083e336bc4eb791f95142306503e2e2caa81faf3" +
		"b3f958ef864c8dfbf13ee28e874cc6cac72f05deb5a47d45f166195c8643af64808909dac4146c1325ca6bf543659ac1bdf679aad3d6275bccf38d0abf10ad6b" +
		"fe4c3bb314840e055ee887daae8d38b711f403a2da8dec1e6a9bebeb0bb694d19a5e56c9182c1d713f0de29786497154a78043be84df37693168c676be96e2e9" +
		"904d99e9d27fcd8556a5d8b75fe4b4c99bbcbb6e8d57c0713e40d5cd4a0c03d168c6fb4d4fbbbb30ede3970b29128120cb8cb21f3c9cf3d92be8435e38adfaf1" +
		"a33aa4e921aa3f67fdd652c435e9571345487fab95b6332bb629d91745e3dc0ef363b8b1ca455c7cece14d0e6f4be64dd71adb5236e0a4494c4189fd7969cab0" +
		"d5c85470a7e1ab7c6cfc49769f2b85a5ef0103b997fff9d69770d5c469a8b48f937d201485410b93ca22ac4a41674ade826f34e231d132735a687fcd8cfb21bf" +
		"f4b77c5a1e87c8eb508f6ffd40a23524c4c5bcd4265c98cbbab2d15905f30d8b340676423ab2b3f975fce803fa980f30c834cba26efcc6f7c5992daf135751fc" +
		"d222ccc9d202b1f60d564cdd6ddd70c434d141eb4ba521b40c6430c398a6ba6b466b6979009a0302179633e896f99347096accfa9414ec52998606d3cf73e5f2" +
		"c4e929d1f109f8eb5c1799377a70a5ed298974021658bee92d8e91d4115781c6a778191588628440699859047cfba8fee96e7c38ce2a1d1b93e266694d5f20a6" +
		"5a2bd55193a888e24dee86eae0d3b8363a57912100e08886cf7de59d6cab465a166796f5111227ea786c9cbc4cafca979c5e7e12e482715557ff7e655fcf2de0" +
		"1cae0d079781adc2ac7e4b6e36b39c0df2b811c2c653c45c6f65d97d62f65eebaa9388bf7ebb23d65a300cfdd79d2248a81332c4ac15a13aaaa2ea52ce4fcf78" +
		"9f0f62e8c10f413397923e69249c54c738b1f2a10ada7faadaf4135d9c0844f0c590c632d304fab66ea3ff3c09c4d5c97056dd9ac2b04cbd5032652f2b473bbf" +
		"92951334858e2c7a76c85e3c9663296be0e164ea3c6c0fb1b64086c6325d1f1a8123046fe8fa9cc81d9592de3cc13c8ef89363ff731e553220fe5a7dcc8c022c" +
		"6d74ee6db4b046fea0079531970089d51b01c4dd73d7f2246d0d92f4d61b915f8e589d5c418938a982fef900500626a07cf536dd2ff5f841dafa8979e016aa99" +
		"7c415841a05f28fa3772f1940cb09b74473aa926ee170e2d08c7bce2ee0ad2364153a57e2d84e8e3082f14b4f9219af7c69bce27ade50dc1d13c3fc86b0deb31" +
		"6e02f6ba5688cbefed340f465f9edd0f4af9222fe457c47e3673e791b70897bbfc28f39054e22ae4e6495461eca3e17a5c23ff881a239bc413dea56779e8863e" +
		"21abcefd27947dddb023853866fa901d08a5d20be7062ae7b25efaf14c18985340a4c0d91e074dce396a112256e1c25b46ba51a7553320168589576fc3c18dc5" +
		"a09949a1155d6549237732bcbc11a3585ea20afb7ecacdc5fcc1f8d9f520697422ec2d1bd6de9352de6b1a36dcf4603258be695019dfc2776b6a294d"
)
