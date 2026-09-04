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
		ct, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, cumOffset, false)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, cumOffset)
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
		ct, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, cumOffset, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, cumOffset)
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
		ct, err := EncryptStreamAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, cumOffset, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, cumOffset)
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
		ct, err := EncryptStreamAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, cumOffset, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, cumOffset)
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
	cfg := &Config{NonceBits: 256}

	t.Run("128-Triple-Cfg", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
		ct, err := EncryptStreamAuthenticated3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, cumOffset, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, cumOffset)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) || !finalFlag {
			t.Fatalf("plaintext mismatch or finalFlag=false")
		}
	})
	t.Run("256-Triple-Cfg", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
		ct, err := EncryptStreamAuthenticated3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, cumOffset, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, cumOffset)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) || !finalFlag {
			t.Fatalf("plaintext mismatch or finalFlag=false")
		}
	})
	t.Run("512-Triple-Cfg", func(t *testing.T) {
		ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
		ct, err := EncryptStreamAuthenticated3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, cumOffset, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, cumOffset)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, pt) || !finalFlag {
			t.Fatalf("plaintext mismatch or finalFlag=false")
		}
	})
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
	ct, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, cumOffset, true)
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

	if _, _, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, tampered, streamAuthFlagMACFunc, streamID, cumOffset); err == nil {
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
	ct, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamA, cumOffset, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamB, cumOffset); !errors.Is(err, ErrMACFailure) {
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
	ctA, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	ctB, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, streamAuthFlagMACFunc, streamID, 1024, true)
	if err != nil {
		t.Fatal(err)
	}

	// Swap cumulative offsets when verifying — both should fail MAC.
	if _, _, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ctA, streamAuthFlagMACFunc, streamID, 1024); !errors.Is(err, ErrMACFailure) {
		t.Fatalf("expected ErrMACFailure on chunk A with B's offset, got %v", err)
	}
	if _, _, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ctB, streamAuthFlagMACFunc, streamID, 0); !errors.Is(err, ErrMACFailure) {
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
		ct, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, nil, streamAuthFlagMACFunc, streamID, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, 0)
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
		ct, err := EncryptStreamAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, nil, streamAuthFlagMACFunc, streamID, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, 0)
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
		ct, err := EncryptStreamAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, nil, streamAuthFlagMACFunc, streamID, 0, true)
		if err != nil {
			t.Fatal(err)
		}
		pt, finalFlag, err := DecryptStreamAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, 0)
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
	if _, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, nil, streamAuthFlagMACFunc, streamID, 0, false); err == nil {
		t.Fatal("expected error on empty plaintext with finalFlag=false (Triple)")
	}
	if _, err := EncryptStreamAuthenticated3x128Cfg(&Config{}, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, nil, streamAuthFlagMACFunc, streamID, 0, false); err == nil {
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
	cfg := &Config{NonceBits: 256}

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
	off := streamIDPrefixLen
	var lastStart int
	for off < len(full) {
		clen, err := ParseChunkLenCfg(nil, full[off:])
		if err != nil {
			t.Fatalf("parse failure at off %d: %v", off, err)
		}
		lastStart = off
		off += clen
	}
	if lastStart == streamIDPrefixLen {
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
// 48-bit Interlocked barrier the per-chunk PRF is applied uniformly;
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
			ct, err := EncryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, streamAuthFlagMACFunc, streamID, 0, finalFlag)
			if err != nil {
				t.Fatal(err)
			}
			pt, recoveredFinal, err := DecryptStreamAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, 0)
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
			ct, err := EncryptStreamAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, streamAuthFlagMACFunc, streamID, 0, finalFlag)
			if err != nil {
				t.Fatal(err)
			}
			pt, recoveredFinal, err := DecryptStreamAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, 0)
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
			ct, err := EncryptStreamAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, plaintext, streamAuthFlagMACFunc, streamID, 0, finalFlag)
			if err != nil {
				t.Fatal(err)
			}
			pt, recoveredFinal, err := DecryptStreamAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct, streamAuthFlagMACFunc, streamID, 0)
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
	off := streamIDPrefixLen
	var lastOff, lastEnd int
	for off < len(full) {
		clen, err := ParseChunkLenCfg(nil, full[off:])
		if err != nil {
			t.Fatalf("ParseChunkLen at %d: %v", off, err)
		}
		lastOff = off
		lastEnd = off + clen
		off += clen
	}
	if lastOff == streamIDPrefixLen {
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
