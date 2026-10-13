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
	goldenSingleMessageNoMAC = "d814fe0449474e9a0ce68d28ebf06665198548e4392c304b3e11b05815323b91da08fc4cb7334382c287d4d69fcd7d8b001900195758857206449a61fd479caa" +
		"2da68a641a124ec72b6bdcf6fda2ff2a2416113a460a4c8a0aae613333f2183fe8553a32c3e9705d9ab1fb9821e2bbb34aa0d33b2c564cb615a1f31c31e2960d" +
		"e169a47462b61fa981dfcc0bbf37685fc4d12f6e72fe264ba59396a0a52674b9b768baf1690259aba202c5b7658cb9430b7c0e83e3f7afce7bedd3df71ad7964" +
		"cbd60895cbd944c548dfb11e0dc812b57cd4f4c23d57d1cce4ef68727d85a48c4a2c2ac44e55f7c2587698346bdff20144c48c010f86d29e83adca13b9cd67b6" +
		"b651ebc9c6dfc2fd1b527d12f7b064306e1aef1564368e1faff9d51e9a5b81db209da3315f2f00584bd1430ce60bcb530916b7485ee16b6fb4626428acee7f8d" +
		"aaecb6e351a1e2a641c57ddb12a8090a130fd39806a1eff6b7acab9feb0e72fedfc13d478522f04c6e19f85bc7d70ab76f8a9768619f4a8ae9508e5f85b9ade7" +
		"57bb2c161fe5052c40bf2876de2024789fdd2d06098aa3dba46b1bae80661b5af26f1557ca25b5133275b4b192fa9e4582478c3857a6dde7e8e59c40a4ef6da6" +
		"f715843afda28b78a48d66662205a8af2e1e1ed1a1a1392b1b10bc72808f019ce9dc00aa99974c8d1fb9f7b7ecc62c22ae0f0b2c23daa42b04772cd11a8061a6" +
		"c287382b34a67d056e88b602f32b7466d9b2e45b0261ff16f7b318d40d73d2e0f13170e7f04b66ecba4e2687c057e5fa1ac7ff3ce04e4b3fabea77607352612e" +
		"e55ec108e5c31e3a3054c85be3bc0505a3a43ea93e4117565918c38e2ad796106bf8ee003ed79efba77f5a098adbb7648c0c433d3e7d4c31f340ec7fb7238205" +
		"19560befa2f380959ff4fbc679f31f0ad5d847207481502b6370a879d161a1c9ba044246dfd8399d2b584d50175c81018fb039b45dd9a1cfc2b7cfc301791e43" +
		"d06aca4fbb1c79d344dbf4e719ee335c183924259cfaa0c44088db18d89d0c0166771a1ef93a559c3c62f4b390a4976095085b8dfaae60f3b783cb41428c5b2f" +
		"dc8516bb890947af42403d4b33e72730ae60238893fb6a656427a8118f17e370cb43c583d0f3c94b555872639a684b43159af63545d800f3850b687db9ac6c54" +
		"10e97d46eefa80771740d57373a74c51a8b750a4b0b9cd5d85f601b813c90889fd833362ce8c18da54e9cd538ef829aeed1de8379ebd4d78411946eb22914902" +
		"f5bfa5dc7eff24dc34287b8cb1da503f3e0a6e56ee8e6a148080186c276f575674f9b7fd863f5cd4495d18fc4c4bf98eb279f29cdca6e682b0fb354c8f1523a2" +
		"bc9294bca80768b9b007f124c435b0b15b78496c6a97fba7fe10cf062133b1a036339b1c4a803c6da09c07221fd09826647ad1d5214a04f85c14516775474a49" +
		"5cc1cf2062522ffb26673a5bc386e984135c7590b96f2960d007309deded9009b0aea2fe588e7af50c4466eff32fca94437284b29b9a9f299fc6e99ab3e044fb" +
		"69df003bc7a0d3bec677dd822dd669faa7809ebcec2ce8fb50ebcd4c48802a34bc14da24cdb64d06ac2115f1b2629d8a4f73a79e805c638b4419b3aabbc02fb9" +
		"cf3a163c2a044eaafb7436c7a9d5900eef5d4b0f79ec19eeb9379a02d7a427378b17030a5f12612f844ba59d4b72cf2a6bbe3730f02de3824465a757fee733a2" +
		"e6079651056a3de82f15ae81984025627c875dccd09713082b216fb9116751da0b8c90d3ddf695d620744f74e64a819d9623436eee8226d955085a817999dfc8" +
		"27d24df524bc7881fbe0a9b344bacdec37e1a5f8d9c34c138504251c55aedbeb33093a36136df451c08c3e3a145b8211f67b9e76f3844554129e6d43bbfad256" +
		"e7373321aee42a005118af8a4682b9806e2b5ed08d5eb439d8eab820fdec63ab94e02db41af76388532f152dcc0adfce27c0a5859f8cf67e4ad8ab5b93f1f187" +
		"4cd0c3622c6a502d6436d871ef5f559edb1d44e15db7be1c1642e8cf5a61123edcbc09ab6cad41278d060f131d9160b791482be09fb86dc1e097bae367b5c9bf" +
		"9041061c0c5924d9be4f1eb5909d1c67a1151dbc0a4c8576ce79fc39648b3c5b84eb9a6116e036cdb63f3fef28145e5fba45a078a68ecbab61b4e437c9dc049f" +
		"4e55ad1ca4442a57ebd76fff38a587312967ee944afeca5c7d541989c0a81852e99051e2a9ea08fab3463a98c651e838e5ea1717a061c2fe39d52265e2bd1e2a" +
		"2dddf27f2c590fca14b949c5801e34887cba8e83f31cd4d98d59721a25692bcd0ad4eac5d3a658f401ebfd59d35248d9d29b9747fced9807943357d9303e056b" +
		"311c2eb5874361c9cbbbfec6007f8d7091ba4ec36f798a3cc112d7cd3559d917788532f603744f5da73a03ce0d909daa3c2c512f96db5f91857b68e42544a7e0" +
		"120c9d24fb6ba4dd60e3a35a31663ec0859dbe5c750bee5e8d1acacc805b62bd8bf8352cc488e9712decd2c0f7d0141ff263e1621a566267cbe398a127bd34fb" +
		"50271ffc1252dbf1f7ef32c929efb6f44eb577c65ff72c28d881417d5a2fcb7ad84b1ed4f98598cdd7ae2bd4d1af9dc259adbf368ae94430a0a91d8b7ae4a06d" +
		"8202d087358ef09d1e1a94f18100bfc8c71e068054cbf175e7d2daed6e49810de748a3b6284f4114471b6cd802bf22d97203eb064f0d845b1fb9253e64a03df1" +
		"46c8cd2b6d60d28f6c6043d7f47252b4c77e531e97bf656fd9513eda8402b55c396e418e5f722757009014c4994bbdbcb4ec8a68c48b2dba5e159d59ae0654b6" +
		"a14ec54cde1a48f5085f3f488c7ab838c97ca2436bb68d553c89b1c5e0fa0c4d7ebc3485ee0d4cf2d3bffe517777ab86d3b7d52e64a4f10eb19e2b34d7e0d083" +
		"ae6e78ccc10e6b4ce050dfaa6430fe9d859ac1ad40f99f65b1dac1551e84031268decd934b3b4902e95f866b42876324709e0076925b3e02aacd3e21d158d02b" +
		"a995b99975c0107c2cf1b18d764f231745125083b2c45a4149d3c0d0b593cff8b9e8d855833c132722355f6b7b3771492368b9628beaf9772211561c2291f2dc" +
		"c50f621a3a7ff363c4c81dfef78db9e8f1d43801475d26b36087051babb9dd4347303168f583116d010809417117aeed1bca31aeb82baaf35be5978cc4a27ae4" +
		"46229101e54d775d8af75a9a266b5023ef3335f4841acf0efbac6b2bb893e13d92b3c2d4a1ddb0e162d693884807e3f65268798d0abbd3f00c812154b708cac4" +
		"1bf02f70fd92b1a8b0fd351bf1f8b940d06806a2edd6587e03aa52bc177cae4b81a7136a350b61e28246329a0508b07ae27d667ee99f3b52029c6f49c6b7afd5" +
		"e54cac78326c57bc2244850070b72623d977950e5275c60a6dfcfe87a46900886739c449698c3482073bf0d7fb65d424f4c4eab8f714661d25039345dbfff776" +
		"93ec6ae389ff021071aeb84d2c732efc263480b909190e08a733825eb3ff3aeed62dc873f07dcd31a890c119b5a16ce0684e6dfce49e6a1046f5fcae52a72154" +
		"38ee4f030da3202df2c35be5d39209e80116cffd93d7456f95c8ab4325dbed32f8a0dea30ac5b1607e6bf594198b8a3d1e99efedc0073713746326ae27fa4a5b" +
		"6edbff759c0c8449909a06c6d2933c8987ff5888578ac3574cb686ba127299165066be1aae206f941a372ce3477623bb13d801d9fd2af376ec447920b1bf7f7f" +
		"b3d73f48edad070b4f40ba3871d937a83f191d66e93294a794ee24d8d7e8425ad1947d655d4c6b360cc975557dd28168385a74f46c3404823dd673280f3a1bc1" +
		"58d8f112d6a8b743dd3aa9a0c412d4b24f95b9a3441a643ad02bfc83c1294e4d20edf80b2bb8508dca69023b777595e42efd2bae1ede8df8dc39110731b671d8" +
		"393128bc104004374d1d651a2033e1531c16d9f8a178bdad4167b536ae9c3d657cd51d390067d2aedcd2f9a75857061487727d27d05a9afb750d30263490bd13" +
		"9d076e47c58351addf4074fc0e073f155b932e6a48851febe4f40d24ffce00af0bfa03f0999f1fd6518183880d8989c3a76caf11130d7a9498f19482377c3184" +
		"d6166314615236ffea8cf2f47e542aeaa37dcc26939de24fbf39f17a97fafcbac835829e6b53eeba8a4092f28733155ea3736ccffab262077653aba77d74c66c" +
		"e2658e511c73e03b583aac2a021682516cbe57dfc1b1e31be739c9b082d0513dfbade6465075a4ff02cb5c3825d5f0b028145e1b1885b8328e28f17717116bf2" +
		"2be4f964f14eb18948515b7514021540219b5f2159ec0fb28733e536699d9a00b4dee36a8a76c698f381d2a71132cd2e415ca0f13dd34d992575429ae1cd9847" +
		"4f452a38629a2da3797f0fdf8a03ed7a0cc7cbf2fae529e79b016807a9b1829317efc27287294e5a1662db4ef34c2d82f8c1e5bf68552f9424aca4b5f9904b8b" +
		"5fcd57357ae1f14ba4e17112a8aafeebcaaaad80a4a5ee1d5450b9015865cbe0c144d161ee1b59518ed4a4e8f9f8951fc32e58199b7cad6499b8eea2cfb56fcc" +
		"559dc5f28ae5b88e5031457aec7dcc3525fc2df8d6d82b741133dbdd04bf3a1f5e713daf2d781cc1377c3af893af4c7c7b0b9ce4924217779284f82be8483d82" +
		"33805556798368180b153c579fb6affac0ed6427b33bd8c59ab45cbe9112c0120569fb4b57f4cc016871a8f6ba2afc76fd4def28c1109977490b4ba258a266dd" +
		"e4f8f4062ae3a1dee55b83048caf27df81f50c2d1d86ec27157d6b4b632fff6ed73c19115c6ccc9de399545f08625b1bab191a8da846482d54c53ff026d6efca" +
		"df1b101eb2abc876a70113b7f8d8f34609161916c699c1797023c7c658d525891ef86968d7a3f49d3a6aebdb38ed10b52da616bbdf89fedf41c3347e98b1bf5e" +
		"14eb6807ffd94ee3636bd6edb1ba690c3c974e79e5f2699af1391f604b6d1011e19d9bf47f5ead2612a103d18dfdbab7914d7028c5353113acf7e872bdfa4326" +
		"5e57a38c1a980222245d7ccb854cca734ee679931b6b6e9b35d5877deff0bc05b898fc3f3f9f6b6c2651bcd96adbe38d9d55797d64206d0d54355999cb5e8541" +
		"3308f7bde0e13860537961c87b4ede5028de0a8812c05a26aba6da90e5398b880f322da1a7862d293d6c9b0cb517f83f99d8a2bcdbe597a0566bd5a4fb486390" +
		"c24afec6218451e456261b8cbb79b70c025f00d4fd3743d6ff866cb63f504ae351dda88acc3bffceaefb071f1703d9baa33a649cd135a4c030aa56cce5cf7266" +
		"566617e6c89a1b3e4c8d7f74a732fe10c4a85ae3612465d570ce6a5c329037e5b1fd36c2d503af2294fe09466f7beefc08982d29d7f0b3269387e0f797374795" +
		"552a9fc5316acd456ffe2e2667b74f585519dea9305e3aca1bc499ae800383b54bdaa0346a20b3ba7b35f9793f32af579a743fabe250879f373d3bd167c32bd4" +
		"a0e25ed50c52363ae85a46f889c18087cfc2a1d837a1d0f9d4448fec32ce33e324063259df1b9fc4fd4268958e2d650f4702da798dd2cffd2fd36b693b42eb0c" +
		"dc23baf4ce1ec6ec1437a5d65cf955bfc6407660e1c6635fd60782ecb04944ecc046e7c43222f633d0131e6223509d52a37c080fef8f5233908c42152aac9443" +
		"187522128864a4ce1bdab41042579f64ccb578646e7a6055f27cc1c984c82fe6039de7f90b0d17fad5631c76a73485f028b102548cdd973c25c13c3244af81d9" +
		"9efd35ef3ed5da225573c6a3ec8e64a020c354191e603e9006d6dff6e3c9a0518d75a2527a7c2c6d83c6bfcf8a41124b55a1b6b157573ff7f90bc0f890c6476c" +
		"25a34668216ddc866f22767265c47b7bc880f8827864a74fcfef522ada59b4104dd8d4ca00233674233be08fbaddad536a03d30049c636307e2f9e56ec7b58a7" +
		"adb1daf1323af0bca79a8de385fd492fb94091af872bd867bf8671b2e8f8a6c0f00f8063e1e79e1862ad4cd216be9968090b9b89d7340e6d4c0f6c0c2d014bbc" +
		"b1714a9bacf86a9d0b90c244603a9bf25f86775f2778fe118756bfdb9df0b96cb931132e6719f5b8c146056147d8f50f902acfa0805254066fc3d50244186160" +
		"27b99494c96a523b638e9dc43e492238f8d23bf248837514e4c3d47bebdf0096bfcd993e0317d564d70f543b9d2e86ea10250c051fb5bea2f2b08294e392a28e" +
		"e46a205801bfdf692a35cdc433528aec9346facf676f45e3e34c933c69e3d29ce78b80cf31ce70268bb2568e72515d4bcf79fcd3d19e3f19a6eddcd7a8893576" +
		"b9eec7ec8b225e800b981284e180d160c2746afafc6c907caf105008db98ef45ee7c6e6d8f84218e2a292e3a66bb75c91d717b8ef37196d037e43457af410141" +
		"310c4a8de026b2aa04efa7813aaa61969905d9c79c7667e08011f3dd94a916e23ec5c8d8780f8d9e0439cf55f936c88b148bd127f84a0b1447280e8fe4d1b396" +
		"16698fc1bb22bb487c9cb6df4f50171bc8f2801e2c91dce8cbfa126264ce3f7e61245e4d84a7f3ecaa44cb0d6012c6a4221905ecd6a6bda95d89173584396e91" +
		"343261bcba396637b36f750eee518e41ff765d191793a7ff32c82957956fd52f9cda019a403832273dd30ce7a01088b2b8c72930e353dbf18a07f85a1ffeb158" +
		"d0a965d9cb8279dd9b2ad19746a2ec1fc05069207b4aa4378c0df658c34aaf03910efba34cb0899cc17f32efad61bb64144a0cf10e6bdcae72813d7bfd6dc2b8" +
		"e11dae3ae0fe98d5a63c66490c607af8b61925b3f4a4125cd98fc51f0dd7c262d43a3a1f75d184f379d421ec83f037b2388701745051c5ca3435c2bce0d8bfbf" +
		"02e3dc7dfcd84cfe442fa3ff6a52a822522146ac8cf33958671acfec49ce3f9bcfbcce0083d5fcb3d3c7e7290ef04fd1c070cdf39f8816df7922d0a1a1efad58" +
		"cb9fdda927aba1a4f7a9148bf7cedba154e466924f7a2ce5702e9a36d6a78b0b8c0ef02420eb691ce9662c26839def7fbeee1f36d6fe1f6174d88193c2275af6" +
		"7335d09895f74c83b33f0c3b19a411b38b248a7bbadeef0474716904b7b365f7b2be59ff403d730e847dfc273bea9a4abbaf17acf94393a42e322555440a318e" +
		"8e104406983576227a5f109efc2848ae4b57ed4828e85a12ac0337b7cfe830a22fe9895ab42e9d86b483af9d547e2bef171934f068bc398cab87dcc8"
	goldenSingleMessageMAC = "0357384038e5721cd36a2c0aeac297be5cbad64e532f8974298c6f6634da4d9592631f214c0645c63d2ebe19b8e5d20f00190019560332a94b29e99758023fb8" +
		"ca76f39e12175537506b2c50584872f476df641bda8db05b55a29dbca21311428a8844322b4a19b7ce194083dc70010adc0bda6ffd32f9e0e5d1c004e1546d84" +
		"3560c5e9700c15120db2391040a59fb8d00c94f90d4b3c5acb30b8784092ce4e3ae7bbe2a7250a59197f6b1e820d3c39126dd20e5117ba3f7a3b626e3c9c8e91" +
		"5cd208753d09e969005766c1777146cb8f1e3e2e2beffc0d251221454a7167c23bcb9c7ced35499391962f3eafa60177391413b9b6b61218940e2dd4280ce389" +
		"160f9d2adfb656ee6e995b156b32899d0f88daefbf0dd6fabafe6d5a981351cefd2a2f1a1fabd36d87de2780a3c38d302017ed268102a0a0b8c8f5777d38c42e" +
		"847c4ecfdd560568fad3caeae02393471d884326333f3423cb27cad376e766f619e984179075b18f6a1dfa036e0e68beedf5dc8807037600fa63969f9774eb03" +
		"ab926e9ab8df38e55549ac63d1f153c8d5b73058651f4dfb884549724f77a6ff4eeb3804518c13355085a4decb8e629d9d285480f9f6b088835fb16cb5227a54" +
		"7d27b79050596edc22087a4e793baf80c7e81bfc6c2e29bdbfbec275035ba4b5e7118b04cdf8cabbae0e950d53689e6481cccc8132253588e85151cd4e8e4052" +
		"439cd2f38f3b8dffe0b7dcda21d18c5f8d3e4a6e3fe587dd01c3c486325292689cc89cf11fc04a82c8bd5c759d3e882289dd74acfdcf29d2e95e6b9a023d3400" +
		"67c40542e5069eb060b38ee187e9c2e114dac06df68555d512dff614e1405c05ce5a1da7ad171600f6c8e2769922d2a5bf7b7268dd8417ae7b917c5da4e0738f" +
		"35e7449f9a13344c1be295c1fe15c189c8c31df9a24e15d374059edf8871f8e649c3704c408392a148f44cf93fbef3ba441ff9803c35cdae230bbf82b8f601d1" +
		"f4fe1a322e5091b4fc8a806ef87f7bd478a31b5bde71557ac0afdf89f54e925ca03e77e797fad8d977ac11c7c3533f0c399b8486c70125550d66c094c7bd9740" +
		"bccaa8f7ef9bdc34e4a677512abae466a848573167906b7f1b74d086298864a3fe29ad77033e0e73a41f91d3c7bf24430691e4c6c7bb1c91387606061dae7d67" +
		"897e0e953d79c2a301c151ab7b6e37d0b2d590955e848a81771e6683671151162472abf98ffe558f08a325c1cecde479180199be16a384bf0b8baf8f4f574284" +
		"1ce0e783e4323c7412f4f1fddac50c66b6b972ce999d018366cf9d15d60222cafd5cdb16deb27181aa755c17cabe57c4675899f0f20e3b08835d0a5c394cc0ed" +
		"4c66e1393278b4a402fac054c9e4bc99c0c0014510ef4a70c6777da946aeed52da7cd93c4c30f76275738196d14bcb609ea7bee35ba17ea92250db95a515e1ea" +
		"fc96331c25a057160c36f2ef650cc633fb517672393e214a2247ea94a135e5d5f4e6c8d8164d017a209d12ba5c4b397e20406a1dce44bf4281bad957ca05a606" +
		"4f9dd19658eb6a9829e4103050120ad6985118e52994cce33d8137e49bc065452ef296f84ee4ec6cddcf0ec66afe8b3b9002940e912d4e02155cd714e759972b" +
		"cb0a9f7a6f5c449a3cbd86f0ec28fcb0df7a73b11d22eeaeabad55a2942f7f0772967f5bb969619f6c23cf91d4823778643be82118bff70a73b061c58130816e" +
		"4dd922b137ff9e90884f9466403e0e45cd5f68f3c24203b7955b0bd92668ce9436f79feafd4689a10c62d796396d20e83feef4d05026146d24c9b8e342b83738" +
		"0e4a5398e58afaa96e43d47c3b3b8bd92e1571a0afc1591527f4a2f5f42c3d8d68c014c54a4cc301d9ce915f091ad3c965d12a8f652f269600f8803a5e6b3f46" +
		"b61a302a77eb9f2b4796a772cbe0b192ee238c250fcd710e69d03beae0904ec8fb47ac0dc9cb5533ad2b632b75e2bbc57105b12ac454df0b1041810e2e89b94f" +
		"f6b1ef2fafeb788a465bd9ce7283788a07b3cef4827ca55152d5af6fa05f13ec2a94d295cc16e80142a7fca2fdbfaf93439e3844e3d8ab2a748051091203b025" +
		"93f2effd7dc70cad21c3a0f7564e040b786b51b16698db1a780f11358d80404f7a87d67a586a2e51d2df94b27ff203eef227e181f4ef6215c500a4fd4cdd6c79" +
		"f55221e87e6d7d22cee70a899d29a80b797dd394355a73fe08547267e211ca959a679685eec5ce5a36a7279656ae1db97b4652060409b61ea6a010a593767fbd" +
		"0be509dcc41cc6e75488a76f0f3805d8542ef4259f025d49f3c955fe5e84b8319db1687cafa06c4bb25f1e5a1e0b2b8b2de59a894ad53473413ce66e6f2e8068" +
		"5b5e25ce4b8de2e42c04d17b8904691702d7fae641775b897ee0c931db6e853d8d479ea42dd10407eed333dfde5374b38efe0f1b2f2f89c289295cb6db5f415d" +
		"7d7f6d33896a1927bea43677cf611906d681176bbd50df6246289a0b03102ba712dbb5f29d38a1127dd76bbf2e24aa255a9e6f7b934caf792394eb4b48b63228" +
		"4fe1f23ba28bfe4650ccf0422e0dda9d78c215c7a83e053d8df7077b0b7c7cced7ed2320d3170342e7375f6504dd1cda9ecc74f783885ed28a176f06ec300a84" +
		"43d7f880bdadc84ecf58c7dfca422be7cbc5e4133d5595086c42482b50cdba1bc7657854a79183fcc37225d021d603dc656d979a4ec3dc021483d75000c446d5" +
		"840e6268c216aa15ab770239b26161e33d5f4a3cdbe5dc9d04c76241623c39e5e99cf1aa38b7090ad41f2ba46c759e62e014fcb7ae318c2409798b3ae99203cd" +
		"55cdd368ac59abaff707ea22e45c59fad328f662808979bbf7cecce81a999ba515c91eae18fecc2373d7af27bdcd273b14724e3ff01f589982cda6335a094f4c" +
		"d3cd20d3c5c072be01ddb706b5a8425af1ff04739056e3e7ad9669d54f459f8d3ddb5140c6703702c2d40df1b74cf09d2af42bcecf069c42e26b4844eaeb66f4" +
		"484a0571a12ef3df82700843a156269798fe29a8ca2aa0fbb572c33d0603a4fe81a9c4b2d72bf4b0541633cbe8a375e4ac24a3ed98b8340b129b5bda49cb1241" +
		"7876fab1cd4e4b135d721081553742292e8df2218e9ba45c6fa2b785d5fc5944b368de19b0f96340dd6d3b3c1876368a9268475d38e01bd19c8dd1994ff53c3f" +
		"1830c6ee093267e1e21187f7dac81d6c88d7a84b4f6a4a689c22e696128b2f8485ee3b64984359da0c4888f9f705207dbfa5ae72650f822dc84bb2cf6405e241" +
		"c2ed1be7a1889c4729137a7b0dfa3d87ac5e9f7cbd9f1dbe5e6201ca568d01d1bb8d3f9d286a56a85f93a2060d18e68ddf05f84b6e54526c0cc5e594d26f87e1" +
		"fbdaa970c39085338195ad31c794afac127b977e80194f66e8693dfaeb1496fd5ca149b43f137cd9065dbb0a4ef6ca96acf59087624f9787796a50ee4d761729" +
		"6c2396a059cc93169cc46a1e2daaa791f613eea063df0bdeea96adaa84f535147a0f9e30fac6a4365e3fdf17dc3a3f39d209c9b6d38339cfa67bde17fad68d42" +
		"6c5094381654f4024cc325b8a6c25e241d267823b0038d7eb54593b7b201da684a68270ea6f83436f43858f6b46aa4c9b7b64b5d4ce08296d72a5a27b1ea2d40" +
		"38ea1f16a126dad2fe0d4abac00c77873365ca97e20e5b9afb61e4060b8fb44d0b82d636de8b86196ab940ef691ddeb8592b36ea4be76ad035e90a89a3408ce2" +
		"f535e829d6fa4952c2ca1c0d597c723edd454e758e33e403752eefec1b5d17143e09872b0ceb38055c36fa8c418c831c7dd1598464dfaf2fe5de7d2b44f25cd5" +
		"d95eff0e2c7c80025062fe43e06ae63622b476d6c30a89dc9072b9aa5b4bee8bf26e0429f26862d29ae7c68c2eaf078c7b0c7d23a7021fcfb70b636d6e77a38d" +
		"4ea05a7ef5ed2a6b543c79453a8035afd53a0f9198f3fa7c557ca8e192575b92a390817c622a1654cdf92a3030a71e71b2b787f80efd601040acfb1c7bd1fc8c" +
		"ebad6d22f7323a50d31ff3d822a5099c88d17cc1b4af6a68b213adfb90984230f7d7544b060cf011c6dc78ad71bdeaa686d87a951f85a5c2ad85b970e7e09dbb" +
		"8edcac63105325736857840c017a51044013423a5e2f8f1214353681a95b1157f91555296fa12d0547fce116856d6a491f3871843dfadda19c1a20a0f4a82dd0" +
		"a4370ec2ace5068f610ed3f66905f8386c4a125bfc88e2eb8422de7b351a3c297c45c8c268be01b749484d5c01e319041527db88a06abdb9ae707f36d0292673" +
		"fedbcf002807474a6f58d98e88f6db9198a9416a422ab6228475e28d819fa534d6dc937b34ea91108ef7a2e52673677f6deae9259516de5220a178b5a5dd3c7d" +
		"ee9271483562786654746808e4c44f9e7956d6d82b8a35923471747b905041a07df3daa2244a916edb09c140c5b5d5a843e6f6bc14f51b976439667d8c0768e3" +
		"6ad76bb4a471af0f1350f95d70e46cb29a306e337729e3223268c9edd8286131810d9b2823e5990317a6f3a0c7a1600afde2bb02ce5439ce60225ac7eaf8e742" +
		"40421f448a7c27eaa3316493f02a5bfc351fae433f30a9de3b9fa501c81e21aa164a95d2fb05e58d23e2ac1d8c725d6dfe36a871c1ea89da4e4af4305ca67244" +
		"afb192b3ed5e7a0160ae3b0f0d68bd8aa3747ded7f66ef156ac3b76be49953817a6d40685afc2442f6b9077915ed0263701be6df22caac758db16a932fb542ad" +
		"42612ac87a7100d211fdc4840effee2d2390f46722b17a55b4777ff572162e8e197c4b151817fd1a52e2e0d958447f8a8fa8f77ec887a2eea3a370457fa24292" +
		"54f68f9de2a40bae9228d4e13a09057fa25b16b91493f130e4478c4c31ab5a18a9b50a61b7c3c63bfbbf28cc06cb457239d99eb1e811e3e398b93c926e0144d0" +
		"d40864df1d3ba539658d5d591bb5d91edbe72e9b76749527d6448163570e47f08883bab80d36aff1faed23b5434a43fc546b602d5796102933c775b30a156c32" +
		"ec246c303676b35f57bef19954f511a1ae257a88cb2f9301024a47e9e9cfeada24e2b6c2a164f9f6b1d4890cfdf8d1991e0f506d5ed07f66f8d697831fd8ee17" +
		"8c9292412a746620e369a8c7fa3855255f54edf2a4a7e8022d78dce7caf514c2e16c47ec923ee5aa37e612ac86aae961b81f327c4d1659601770e47d4b1e1110" +
		"0a23bdacb88119333320a844c8f925d6bb5fe5db5c605681000d8913e1332670c9497d4cdf5583c420952f8c23c8b9a106689c76f2c63467617189aa996d4910" +
		"d08c3930df5cb1b339b29d4ae37f1928e2f44adc58498a015b9ec16bdc02b4b2fba5a22a03f8c1b1e3cee5a742b48202ec3e84e98c1788d264cb2a0047d190e9" +
		"3667542fba0acfec11aacb65a091af9eaee7825d38b3ee213103e367ac197779db1a599103d9cf78a472f30ff32761565748a982cc461f482a8d0dddf39376e6" +
		"54cb224633728c22584a94a8a69eed6397fb7a8ef252009f7a8415f958a34874d45e13c9a392f52cf7149b977af27c5518698e2eac47f8668949567d8ad3dcb1" +
		"4634d21c195928260d9c4c880778df9a2b9532a6ab75164669bf440f72eca8b452339b6898ca94e4df1d9b0f1141f1a00ea0c54b8914ab6c2c339c7388bb43f1" +
		"a7169366a99e63adfb3a1e8c3cf150291321b140ff2d8e379fe899ec575a8d57a4cb42fa7a7c5e0a376134733bcb986d1f289569ddce17f45e9ea02d70d47e65" +
		"f5748dbb697dca51871f36a89134c858860b5d329cea60ec9d25cd5c257afa526353f6f29a8a83bd04ca0e7d86c14a49d189fff048b5f6d3c6d2d7c2ae9263ec" +
		"e84e4d997e601aaeaece98aecefd2382048fd22840afc8b7aaac69a621e604e4e3263ef49da2047d0d0390fa2c705160e6d6f82226aa25cb485178069e4b9756" +
		"961c36f8c490524dcad3d17e2bcb5385f0207d560a63d955ba6d5d172ddd788d5f11932b9fdf532b8f1f64be81b69e592421b101e48433e46fba4fa05e6f579e" +
		"79d5f292b8b7a45b32f1d5ec162f4dc28f8c7734f8b574048111474181dfc12ba0fecb3ac67bf0ed414c2d1c0ac6f5dd49b5c165b4534d79d8d955ce454392d8" +
		"f35edec0749ff20b536f1be36f491493dfc9e837e1b5bb0279df4a87c80c43925dd63eb27204439571a4f29478e3d656d9e60984b1f57652e623b77be6252b9f" +
		"65e12f1015883596c4cc737f21f96a2b0da7e06df28f75c13d7d648de2c087e6398427de64b6560e857bafa50c559929ad3c17d6f36a2bb4e04c95fa111bf24e" +
		"6bcf79c36989e84590c418eb2e91988b345a94ae9c6972628dddd11bc418008e2bfc4bb758dc2a2a481bda443bdb9ba837ff1135de3e72c4a403bf05224bc37e" +
		"299de4ede2f513c983d0d1e5f0dd65a8552397acc7b1ca52d330c01eb340e8331706d71effe42e98887f24853bffc4761cc2b9425c9ae02fb06b9d9a838e3434" +
		"6cc85e856425dbc1ac11cb2b5514e6cec43fc06c49283125359be460a7bd597ab223e49e279fd18d6b15f6b5e144c14974401e64cfb1f1732a240a46cafd18df" +
		"4091acd9b07dd9b0fba6a1496546dd560e741b0e6a46f23f0ae13d9184dffecbe81e5251ac43d9ac761197c6b125f798d4d82dae589febb614b63fe9340d561c" +
		"2afddc0b299dbcbb22cc374a217c21583a196d19c51c375e886ef2cc9d9abff58ef59bb96cd69b28578d7c0318b386b7e9b5395070ab78391025f065beb14855" +
		"592415ed3be400b71a877fd057aa21737222a0a03dda47ca99be7ddb1171aa3bff4890ce7cfe59c935c3602a8afbb626116829bedd6d2895de3364b1ad5e4270" +
		"e25f9b191c6a6a6525666642f52322bde725d87562ad55307a884c76be4af80297e9a23b168eca0ff8d44a2fd6d5079728a137e8e4309d69a7bbcd4883a4b2e6" +
		"359f575e0b2015668e0f10ba3c893ac6e9c2b1f9849bea717e15a67d97aa900463640a1ebdb27bca53504d057c869e8c18683613ba704f5e8f037409b11d1432" +
		"38151bca5d42277af81bbb8788cd7d9d3673fe5f9f47db35458cb056007ac8dea01cdb4fdc4e2b063bea4ae929cd39cb12ac1708ad36e1aadb77b170ba88bef3" +
		"16117ba435320e1dd02af5b67e185db2fe64672eaadf177759ef6fd664dfafe60e87f35114c3ef6f5c78ef6f13c6ea8a164c541858dae64a86854b40"
)
