package itb

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	mathrand "math/rand/v2"
)

// streamAuthTestData returns a deterministic 4 KiB plaintext fixture
// seeded with a fixed value so the Streaming AEAD round-trip suite is
// reproducible across runs.
func streamAuthTestData(seed uint64) []byte {
	r := mathrand.New(mathrand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = byte(r.Uint32())
	}
	return buf
}

// streamAuthFlagMACFunc returns a deterministic 32-byte MAC closure
// suitable for the Streaming AEAD tests. Uses a Mersenne-style mix so
// every input byte propagates to every output byte; not
// cryptographically secure, but the streaming construction's
// authentication properties under test do not require a strong PRF —
// only that the closure matches between encoder and decoder.
func streamAuthFlagMACFunc(data []byte) []byte {
	tag := make([]byte, 32)
	state := uint64(0xcbf29ce484222325)
	for _, b := range data {
		state ^= uint64(b)
		state *= 0x100000001b3
	}
	for i := 0; i < 4; i++ {
		for j := 0; j < 8; j++ {
			tag[i*8+j] = byte(state >> (j * 8))
		}
		state = state*0x9e3779b97f4a7c15 + uint64(i+1)
	}
	return tag
}

// emitToBuffer returns an emit callback that appends every received
// chunk to the supplied bytes.Buffer. The Streaming AEAD test
// scaffolding uses this both to capture wire transcripts on encode
// and to discard plaintext on decode (replacing buf with a per-call
// buffer when only chunk content matters).
func emitToBuffer(buf *bytes.Buffer) func(chunk []byte) error {
	return func(chunk []byte) error {
		_, err := buf.Write(chunk)
		return err
	}
}

// --- Per-chunk Level 1 Triple round-trip ---

// TestStreamAuth_PerChunkTripleRoundtrip covers the width-per-call
// [EncryptStreamAuthenticated3x{128,256,512}Cfg] /
// [DecryptStreamAuthenticated3x{128,256,512}Cfg] pair on the finalFlag
// = true / false axis across all three widths.
func TestStreamAuth_PerChunkTripleRoundtrip(t *testing.T) {
	data := streamAuthTestData(1)
	var streamID [32]byte
	for i := range streamID {
		streamID[i] = byte(i + 1)
	}
	const cumOffset = uint64(12345)

	t.Run("128-Triple-NonFinal", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
		ct, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, nil, cumOffset, false)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, nil, cumOffset)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) {
			t.Fatalf("plaintext mismatch")
		}
		if finalFlag {
			t.Fatalf("expected finalFlag=false, got true")
		}
	})
	t.Run("128-Triple-Final", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
		ct, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, nil, cumOffset, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, nil, cumOffset)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) {
			t.Fatalf("plaintext mismatch")
		}
		if !finalFlag {
			t.Fatalf("expected finalFlag=true, got false")
		}
	})
	t.Run("256-Triple-Final", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
		ct, err := EncryptStreamAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, nil, cumOffset, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, nil, cumOffset)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) {
			t.Fatalf("plaintext mismatch")
		}
		if !finalFlag {
			t.Fatalf("expected finalFlag=true, got false")
		}
	})
	t.Run("512-Triple-Final", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
		ct, err := EncryptStreamAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, nil, cumOffset, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, nil, cumOffset)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) {
			t.Fatalf("plaintext mismatch")
		}
		if !finalFlag {
			t.Fatalf("expected finalFlag=true, got false")
		}
	})
}

// --- Per-chunk Level 1 Triple Cfg-variant round-trip ---

func TestStreamAuth_PerChunkTripleRoundtripCfg(t *testing.T) {
	data := streamAuthTestData(2)
	var streamID [32]byte
	for i := range streamID {
		streamID[i] = byte(0x80 + i)
	}
	const cumOffset = uint64(98765)
	for _, nb := range []int{128, 256, 512} {
		cfg := &Config{NonceBits: nb}
		t.Run(fmt.Sprintf("nonce%d", nb), func(t *testing.T) {
			t.Run("128-Triple-Cfg", func(t *testing.T) {
				ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
				ct, err := EncryptStreamAuthenticated3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, nil, cumOffset, true)
				if err != nil {
					t.Fatal(err)
				}
				pt, finalFlag, err := DecryptStreamAuthenticated3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, nil, cumOffset)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(data, pt) || !finalFlag {
					t.Fatalf("plaintext mismatch or finalFlag=false")
				}
			})
			t.Run("256-Triple-Cfg", func(t *testing.T) {
				ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
				ct, err := EncryptStreamAuthenticated3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, nil, cumOffset, true)
				if err != nil {
					t.Fatal(err)
				}
				pt, finalFlag, err := DecryptStreamAuthenticated3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, nil, cumOffset)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(data, pt) || !finalFlag {
					t.Fatalf("plaintext mismatch or finalFlag=false")
				}
			})
			t.Run("512-Triple-Cfg", func(t *testing.T) {
				ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
				ct, err := EncryptStreamAuthenticated3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, nil, cumOffset, true)
				if err != nil {
					t.Fatal(err)
				}
				pt, finalFlag, err := DecryptStreamAuthenticated3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, nil, cumOffset)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(data, pt) || !finalFlag {
					t.Fatalf("plaintext mismatch or finalFlag=false")
				}
			})
		})
	}
}

// --- Per-chunk Level 1 tampered detection ---

func TestStreamAuth_PerChunkTripleTampered(t *testing.T) {
	data := streamAuthTestData(3)
	var streamID [32]byte
	for i := range streamID {
		streamID[i] = byte(i + 0x40)
	}
	const cumOffset = uint64(7777)

	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	ct, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, nil, cumOffset, true)
	if err != nil {
		t.Fatal(err)
	}

	// Flip every bit of every container byte (header preserved): noise
	// position is unknown so flipping all 8 bits guarantees data
	// corruption regardless of seed-driven noise placement.
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	for i := headerSizeCfg(nil); i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}

	if _, _, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, tampered, streamAuthFlagMACFunc, streamID, nil, cumOffset); err == nil {
		t.Fatal("expected error on tampered ciphertext, got nil")
	}
}

// --- Per-chunk Level 1 cross-stream replay detection ---

func TestStreamAuth_PerChunkTripleCrossStreamReplay(t *testing.T) {
	data := streamAuthTestData(4)
	var streamA, streamB [32]byte
	for i := range streamA {
		streamA[i] = byte(0xA0 + i)
		streamB[i] = byte(0xB0 + i)
	}
	const cumOffset = uint64(0)

	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	ct, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamA, nil, cumOffset, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamB, nil, cumOffset); !errors.Is(err, ErrMACFailure) {
		t.Fatalf("expected ErrMACFailure on stream-id mismatch, got %v", err)
	}
}

// --- Per-chunk Level 1 cumulative-offset reorder detection ---

func TestStreamAuth_PerChunkTripleOffsetReorder(t *testing.T) {
	data := streamAuthTestData(5)
	var streamID [32]byte
	for i := range streamID {
		streamID[i] = byte(i)
	}

	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	ctA, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, nil, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	ctB, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, nil, 1024, true)
	if err != nil {
		t.Fatal(err)
	}

	// Swap cumulative offsets when verifying — both should fail MAC.
	if _, _, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ctA, streamAuthFlagMACFunc, streamID, nil, 1024); !errors.Is(err, ErrMACFailure) {
		t.Fatalf("expected ErrMACFailure on chunk A with B's offset, got %v", err)
	}
	if _, _, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ctB, streamAuthFlagMACFunc, streamID, nil, 0); !errors.Is(err, ErrMACFailure) {
		t.Fatalf("expected ErrMACFailure on chunk B with A's offset, got %v", err)
	}
}

// --- Per-chunk Level 1 empty plaintext + finalFlag=true ---

func TestStreamAuth_PerChunkTripleEmptyFinal(t *testing.T) {
	var streamID [32]byte
	for i := range streamID {
		streamID[i] = byte(0xC0 + i)
	}

	t.Run("128-Triple", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
		ct, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, nil, streamAuthFlagMACFunc, streamID, nil, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(pt) != 0 {
			t.Fatalf("expected empty plaintext, got %d bytes", len(pt))
		}
		if !finalFlag {
			t.Fatalf("expected finalFlag=true on empty terminator")
		}
	})
	t.Run("256-Triple", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
		ct, err := EncryptStreamAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, nil, streamAuthFlagMACFunc, streamID, nil, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(pt) != 0 {
			t.Fatalf("expected empty plaintext, got %d bytes", len(pt))
		}
		if !finalFlag {
			t.Fatalf("expected finalFlag=true on empty terminator")
		}
	})
	t.Run("512-Triple", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
		ct, err := EncryptStreamAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, nil, streamAuthFlagMACFunc, streamID, nil, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(pt) != 0 {
			t.Fatalf("expected empty plaintext, got %d bytes", len(pt))
		}
		if !finalFlag {
			t.Fatalf("expected finalFlag=true on empty terminator")
		}
	})
}

// --- Per-chunk Level 1 empty plaintext + finalFlag=false (rejected) ---

func TestStreamAuth_PerChunkTripleEmptyNonFinalRejected(t *testing.T) {
	var streamID [32]byte
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	if _, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, nil, streamAuthFlagMACFunc, streamID, nil, 0, false); err == nil {
		t.Fatal("expected error on empty plaintext with finalFlag=false (Triple)")
	}
	if _, err := EncryptStreamAuthenticated3x128Cfg(&Config{}, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, nil, streamAuthFlagMACFunc, streamID, nil, 0, false); err == nil {
		t.Fatal("expected error on empty plaintext with finalFlag=false (Triple Cfg)")
	}
}

// --- Full-stream Level 2 Triple round-trip ---

// TestStreamAuth_FullStreamTripleRoundtrip covers the
// [EncryptStreamAuth3x{128,256,512}] / [DecryptStreamAuth3x{128,256,512}]
// full-stream pair (per-chunk emit callback signature) across every
// Triple width.
func TestStreamAuth_FullStreamTripleRoundtrip(t *testing.T) {
	data := streamAuthTestData(6)
	chunkSize := 1024

	t.Run("128-Triple", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
		var wire bytes.Buffer
		if err := EncryptStreamAuth3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, chunkSize, streamAuthFlagMACFunc, emitToBuffer(&wire)); err != nil {
			t.Fatal(err)
		}
		var recovered bytes.Buffer
		if err := DecryptStreamAuth3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, wire.Bytes(), streamAuthFlagMACFunc, emitToBuffer(&recovered)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, recovered.Bytes()) {
			t.Fatalf("recovered plaintext mismatch")
		}
	})
	t.Run("256-Triple", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
		var wire bytes.Buffer
		if err := EncryptStreamAuth3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, chunkSize, streamAuthFlagMACFunc, emitToBuffer(&wire)); err != nil {
			t.Fatal(err)
		}
		var recovered bytes.Buffer
		if err := DecryptStreamAuth3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, wire.Bytes(), streamAuthFlagMACFunc, emitToBuffer(&recovered)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, recovered.Bytes()) {
			t.Fatalf("recovered plaintext mismatch")
		}
	})
	t.Run("512-Triple", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
		var wire bytes.Buffer
		if err := EncryptStreamAuth3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, chunkSize, streamAuthFlagMACFunc, emitToBuffer(&wire)); err != nil {
			t.Fatal(err)
		}
		var recovered bytes.Buffer
		if err := DecryptStreamAuth3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, wire.Bytes(), streamAuthFlagMACFunc, emitToBuffer(&recovered)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, recovered.Bytes()) {
			t.Fatalf("recovered plaintext mismatch")
		}
	})
}

// --- Full-stream Level 2 Triple Cfg round-trip ---

func TestStreamAuth_FullStreamTripleRoundtripCfg(t *testing.T) {
	data := streamAuthTestData(7)
	chunkSize := 512
	for _, nb := range []int{128, 256, 512} {
		cfg := &Config{NonceBits: nb}
		t.Run(fmt.Sprintf("nonce%d", nb), func(t *testing.T) {
			t.Run("128-Triple-Cfg", func(t *testing.T) {
				ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
				var wire bytes.Buffer
				if err := EncryptStreamAuth3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, chunkSize, streamAuthFlagMACFunc, emitToBuffer(&wire)); err != nil {
					t.Fatal(err)
				}
				var recovered bytes.Buffer
				if err := DecryptStreamAuth3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, wire.Bytes(), streamAuthFlagMACFunc, emitToBuffer(&recovered)); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(data, recovered.Bytes()) {
					t.Fatalf("recovered plaintext mismatch")
				}
			})
		})
	}
}

// --- Full-stream Level 2 Triple truncate-tail detection ---

func TestStreamAuth_FullStreamTripleTruncateTail(t *testing.T) {
	data := streamAuthTestData(8)
	chunkSize := 512

	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	var wire bytes.Buffer
	if err := EncryptStreamAuth3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, chunkSize, streamAuthFlagMACFunc, emitToBuffer(&wire)); err != nil {
		t.Fatal(err)
	}

	full := wire.Bytes()
	off := 0
	var lastStart int
	for off < len(full) {
		clen, err := ParseChunkLenCfg(nil, full[off+streamIDPrefixLen:])
		if err != nil {
			t.Fatalf("parse failure at off %d: %v", off, err)
		}
		lastStart = off
		off += streamIDPrefixLen + clen
	}
	if lastStart == 0 {
		t.Fatal("only one chunk emitted; truncate-tail test needs >=2 chunks")
	}
	truncated := full[:lastStart]

	var sink bytes.Buffer
	err := DecryptStreamAuth3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, truncated, streamAuthFlagMACFunc, emitToBuffer(&sink))
	if !errors.Is(err, ErrStreamTruncated) {
		t.Fatalf("expected ErrStreamTruncated, got %v", err)
	}
}

// --- Full-stream Level 2 Triple stream-prefix tamper detection ---

func TestStreamAuth_FullStreamTriplePrefixTamper(t *testing.T) {
	data := streamAuthTestData(9)
	chunkSize := 512

	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	var wire bytes.Buffer
	if err := EncryptStreamAuth3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, chunkSize, streamAuthFlagMACFunc, emitToBuffer(&wire)); err != nil {
		t.Fatal(err)
	}
	tampered := make([]byte, wire.Len())
	copy(tampered, wire.Bytes())
	tampered[0] ^= 0x01

	var sink bytes.Buffer
	err := DecryptStreamAuth3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, tampered, streamAuthFlagMACFunc, emitToBuffer(&sink))
	if err == nil {
		t.Fatal("expected error on stream-prefix tamper, got nil")
	}
}

// --- Final-flag preservation at chunk_size = 1 plaintext byte ---

// TestStreamAuth_FlagPreservedTripleSingleByte exercises the final
// flag round-trip on Triple Ouroboros at the aggressive chunkSize = 1
// path (one full ITB container per plaintext byte). Under the always-on
// 48-bit Interlocked Barrier the per-chunk PRF is applied uniformly;
// the flag byte's container position must survive the barrier without
// leaking mid-transcript regardless of finalFlag value.
func TestStreamAuth_FlagPreservedTripleSingleByte(t *testing.T) {
	plaintext := []byte{0x42}
	var streamID [32]byte
	for i := range streamID {
		streamID[i] = byte(i + 0x10)
	}

	for _, finalFlag := range []bool{false, true} {
		name := "NonFinal"
		if finalFlag {
			name = "Final"
		}
		t.Run(fmt.Sprintf("Triple128-%s", name), func(t *testing.T) {
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
			ct, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, streamAuthFlagMACFunc, streamID, nil, 0, finalFlag)
			if err != nil {
				t.Fatal(err)
			}
			pt, recoveredFinal, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, pt) {
				t.Fatalf("plaintext mismatch")
			}
			if recoveredFinal != finalFlag {
				t.Fatalf("flag mismatch: encoded %v, recovered %v", finalFlag, recoveredFinal)
			}
		})
		t.Run(fmt.Sprintf("Triple256-%s", name), func(t *testing.T) {
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
			ct, err := EncryptStreamAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, streamAuthFlagMACFunc, streamID, nil, 0, finalFlag)
			if err != nil {
				t.Fatal(err)
			}
			pt, recoveredFinal, err := DecryptStreamAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, pt) {
				t.Fatalf("plaintext mismatch")
			}
			if recoveredFinal != finalFlag {
				t.Fatalf("flag mismatch: encoded %v, recovered %v", finalFlag, recoveredFinal)
			}
		})
		t.Run(fmt.Sprintf("Triple512-%s", name), func(t *testing.T) {
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
			ct, err := EncryptStreamAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, streamAuthFlagMACFunc, streamID, nil, 0, finalFlag)
			if err != nil {
				t.Fatal(err)
			}
			pt, recoveredFinal, err := DecryptStreamAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(plaintext, pt) {
				t.Fatalf("plaintext mismatch")
			}
			if recoveredFinal != finalFlag {
				t.Fatalf("flag mismatch: encoded %v, recovered %v", finalFlag, recoveredFinal)
			}
		})
	}
}

// TestStreamAuth_FullStreamTripleAfterFinal confirms bytes appearing
// after a chunk whose recovered finalFlag = true are rejected with
// [ErrStreamAfterFinal] on the Triple full-stream decoder.
func TestStreamAuth_FullStreamTripleAfterFinal(t *testing.T) {
	data := streamAuthTestData(13)
	chunkSize := 512

	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	var wire bytes.Buffer
	if err := EncryptStreamAuth3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, chunkSize, streamAuthFlagMACFunc, emitToBuffer(&wire)); err != nil {
		t.Fatal(err)
	}

	full := wire.Bytes()
	off := 0
	var lastOff, lastEnd int
	for off < len(full) {
		clen, err := ParseChunkLenCfg(nil, full[off+streamIDPrefixLen:])
		if err != nil {
			t.Fatalf("ParseChunkLen at %d: %v", off, err)
		}
		lastOff = off
		lastEnd = off + streamIDPrefixLen + clen
		off += streamIDPrefixLen + clen
	}
	if lastOff == 0 {
		t.Fatal("only one chunk emitted; after-final test needs >=2 chunks")
	}
	tail := append([]byte(nil), full[lastOff:lastEnd]...)
	transcript := append(append([]byte(nil), full...), tail...)

	var sink bytes.Buffer
	err := DecryptStreamAuth3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, transcript, streamAuthFlagMACFunc, emitToBuffer(&sink))
	if !errors.Is(err, ErrStreamAfterFinal) {
		t.Fatalf("expected ErrStreamAfterFinal, got %v", err)
	}
}

// --- Per-chunk prefix binding of the later chunks ---

// chunkAuthFixture bundles one width's per-chunk Streaming AEAD entries
// behind width-less closures over a fixed seed set.
type chunkAuthFixture struct {
	width int
	enc   func(data []byte, mac MACFunc, streamID [32]byte, chunkPrefix []byte, offset uint64, final bool) ([]byte, error)
	dec   func(chunk []byte, mac MACFunc, streamID [32]byte, chunkPrefix []byte, offset uint64) ([]byte, bool, error)
}

func chunkAuthFixtures() []chunkAuthFixture {
	n1, l1, a1, b1, c1, x1, y1, z1 := makeEightSeeds128(512, sipHash128)
	n2, l2, a2, b2, c2, x2, y2, z2 := makeEightSeeds256(512, makeBlake3Hash256())
	n3, l3, a3, b3, c3, x3, y3, z3 := makeEightSeeds512(512, makeBlake2bHash512())
	return []chunkAuthFixture{
		{128,
			func(d []byte, m MACFunc, sid [32]byte, p []byte, off uint64, fin bool) ([]byte, error) {
				return EncryptStreamAuthenticated3x128Cfg(nil, n1, l1, a1, b1, c1, x1, y1, z1, d, m, sid, p, off, fin)
			},
			func(c []byte, m MACFunc, sid [32]byte, p []byte, off uint64) ([]byte, bool, error) {
				return DecryptStreamAuthenticated3x128Cfg(nil, n1, l1, a1, b1, c1, x1, y1, z1, c, m, sid, p, off)
			}},
		{256,
			func(d []byte, m MACFunc, sid [32]byte, p []byte, off uint64, fin bool) ([]byte, error) {
				return EncryptStreamAuthenticated3x256Cfg(nil, n2, l2, a2, b2, c2, x2, y2, z2, d, m, sid, p, off, fin)
			},
			func(c []byte, m MACFunc, sid [32]byte, p []byte, off uint64) ([]byte, bool, error) {
				return DecryptStreamAuthenticated3x256Cfg(nil, n2, l2, a2, b2, c2, x2, y2, z2, c, m, sid, p, off)
			}},
		{512,
			func(d []byte, m MACFunc, sid [32]byte, p []byte, off uint64, fin bool) ([]byte, error) {
				return EncryptStreamAuthenticated3x512Cfg(nil, n3, l3, a3, b3, c3, x3, y3, z3, d, m, sid, p, off, fin)
			},
			func(c []byte, m MACFunc, sid [32]byte, p []byte, off uint64) ([]byte, bool, error) {
				return DecryptStreamAuthenticated3x512Cfg(nil, n3, l3, a3, b3, c3, x3, y3, z3, c, m, sid, p, off)
			}},
	}
}

// TestStreamAuth_ChunkPrefixBinding pins the MAC input of a later
// chunk — payloads ‖ streamID ‖ chunkPrefix ‖ offset ‖ flag — at every
// hash width under a keyed MAC:
//
//   - flipping any one of the 256 bits of the chunk prefix is a MAC
//     failure, so no prefix bit is malleable in flight;
//   - the same chunk and prefix under another stream's streamID at the
//     same offset is a MAC failure, so a later chunk cannot be spliced
//     across streams that share seeds and MAC key;
//   - a later chunk decrypted as chunk 0 (prefix dropped) and chunk 0
//     decrypted as a later chunk under its streamID as prefix both fail;
//   - a chunkPrefix of any length other than 0 or 32 is rejected on
//     both sides before any wire is produced or any MAC runs.
func TestStreamAuth_ChunkPrefixBinding(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(0x5A ^ i*7)
	}
	mac := macFuncForTest(key)
	data := streamAuthTestData(21)
	var streamA, streamB [32]byte
	for i := range streamA {
		streamA[i] = byte(0x11 + i)
		streamB[i] = byte(0x91 + i)
	}
	prefix := make([]byte, 32)
	for i := range prefix {
		prefix[i] = byte(0xC3 + 5*i)
	}
	const offset = uint64(4096)

	for _, fx := range chunkAuthFixtures() {
		fx := fx
		t.Run(fmt.Sprintf("w%d", fx.width), func(t *testing.T) {
			ct, err := fx.enc(data, mac, streamA, prefix, offset, false)
			if err != nil {
				t.Fatalf("encrypt later chunk: %v", err)
			}
			pt, final, err := fx.dec(ct, mac, streamA, prefix, offset)
			if err != nil || final || !bytes.Equal(pt, data) {
				t.Fatalf("control round-trip: err=%v final=%v match=%v", err, final, bytes.Equal(pt, data))
			}

			for bit := 0; bit < 8*len(prefix); bit++ {
				flipped := bytes.Clone(prefix)
				flipped[bit/8] ^= 1 << (bit % 8)
				if _, _, err := fx.dec(ct, mac, streamA, flipped, offset); !errors.Is(err, ErrMACFailure) {
					t.Fatalf("prefix bit %d flipped: want ErrMACFailure, got %v", bit, err)
				}
			}

			if _, _, err := fx.dec(ct, mac, streamB, prefix, offset); !errors.Is(err, ErrMACFailure) {
				t.Fatalf("spliced into another stream: want ErrMACFailure, got %v", err)
			}

			if _, _, err := fx.dec(ct, mac, streamA, nil, offset); !errors.Is(err, ErrMACFailure) {
				t.Fatalf("later chunk decrypted as chunk 0: want ErrMACFailure, got %v", err)
			}
			ct0, err := fx.enc(data, mac, streamA, nil, 0, false)
			if err != nil {
				t.Fatalf("encrypt chunk 0: %v", err)
			}
			if _, _, err := fx.dec(ct0, mac, streamA, streamA[:], 0); !errors.Is(err, ErrMACFailure) {
				t.Fatalf("chunk 0 decrypted as a later chunk: want ErrMACFailure, got %v", err)
			}

			for _, n := range []int{1, 31, 33, 64} {
				bad := make([]byte, n)
				if _, err := fx.enc(data, mac, streamA, bad, offset, false); err == nil {
					t.Fatalf("encrypt accepted a %d-byte chunkPrefix", n)
				}
				if _, _, err := fx.dec(ct, mac, streamA, bad, offset); err == nil {
					t.Fatalf("decrypt accepted a %d-byte chunkPrefix", n)
				}
			}
			if _, _, err := fx.dec(ct, mac, streamA, []byte{}, offset); !errors.Is(err, ErrMACFailure) {
				t.Fatalf("empty non-nil chunkPrefix must select chunk 0: want ErrMACFailure, got %v", err)
			}
		})
	}
}

// TestStreamAuth_FullStreamTripleChunkPrefixTamper flips one bit in the
// prefix of every later record of a User-Driven Loop transcript in
// turn; the decoder rejects each tampered transcript with a MAC
// failure on that record.
func TestStreamAuth_FullStreamTripleChunkPrefixTamper(t *testing.T) {
	data := bytes.Repeat(streamAuthTestData(22), 3)
	var key [32]byte
	for i := range key {
		key[i] = byte(i * 13)
	}
	mac := macFuncForTest(key)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	var wire bytes.Buffer
	if err := EncryptStreamAuth3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, 4096, mac, emitToBuffer(&wire)); err != nil {
		t.Fatal(err)
	}
	full := wire.Bytes()
	var starts []int
	for off := 0; off < len(full); {
		clen, err := ParseChunkLenCfg(nil, full[off+streamIDPrefixLen:])
		if err != nil {
			t.Fatalf("ParseChunkLen at %d: %v", off, err)
		}
		starts = append(starts, off)
		off += streamIDPrefixLen + clen
	}
	if len(starts) != 3 {
		t.Fatalf("setup: %d records, want 3", len(starts))
	}
	for _, at := range starts[1:] {
		for _, bit := range []int{0, 7, 128, 255} {
			tampered := bytes.Clone(full)
			tampered[at+bit/8] ^= 1 << (bit % 8)
			var sink bytes.Buffer
			err := DecryptStreamAuth3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, tampered, mac, emitToBuffer(&sink))
			if !errors.Is(err, ErrMACFailure) {
				t.Fatalf("record at %d, prefix bit %d flipped: want ErrMACFailure, got %v", at, bit, err)
			}
		}
	}
	var sink bytes.Buffer
	if err := DecryptStreamAuth3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, full, mac, emitToBuffer(&sink)); err != nil || !bytes.Equal(sink.Bytes(), data) {
		t.Fatalf("untampered control: err=%v match=%v", err, bytes.Equal(sink.Bytes(), data))
	}
}
