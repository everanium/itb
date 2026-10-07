package itb

import (
	"bytes"
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
				return EncryptStreamAuthenticated3x128Cfg(cfg, n1, l1, a1, b1, c1, x1, y1, z1, data, mac, sid, off, fin)
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
				return EncryptStreamAuthenticated3x256Cfg(cfg, n2, l2, a2, b2, c2, x2, y2, z2, data, mac, sid, off, fin)
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
				return EncryptStreamAuthenticated3x512Cfg(cfg, n3, l3, a3, b3, c3, x3, y3, z3, data, mac, sid, off, fin)
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

// TestStreamingChunksCarryNoPrefix pins the streaming wire shape on
// both arms: the first emitted piece is the 32-byte stream prefix and
// every later piece is one bare chunk whose header sits at offset 0
// and whose announced length is its whole length — no per-chunk
// prefix. A one-chunk stream is therefore byte-shape identical to the
// Single Message wire for the same plaintext: same total length, same
// header offset.
func TestStreamingChunksCarryNoPrefix(t *testing.T) {
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
					if len(pieces) != 1+4 {
						t.Fatalf("%s: %d pieces emitted, want prefix + 4 chunks", arm, len(pieces))
					}
					if len(pieces[0]) != streamIDPrefixLen {
						t.Fatalf("%s: first piece is %d B, want the %d-byte prefix", arm, len(pieces[0]), streamIDPrefixLen)
					}
					for i, chunk := range pieces[1:] {
						n, perr := ParseChunkLenCfg(cfg, chunk)
						if perr != nil {
							t.Fatalf("%s chunk %d: header does not sit at offset 0: %v", arm, i, perr)
						}
						if n != len(chunk) {
							t.Fatalf("%s chunk %d: announced %d B, emitted %d B", arm, i, n, len(chunk))
						}
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

			// A multi-chunk stream is a prefix followed by several chunks;
			// the first chunk parses and the rest is the over-length.
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
				if n < 1+2 {
					t.Fatalf("%s: %d pieces emitted, want a prefix and at least two chunks", arm, n)
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
