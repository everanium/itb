package itb_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
)

// macForStreamTest returns a fresh hmac-blake3 itb.MACFunc bound to a
// 32-byte CSPRNG-derived key. The macs.HMACBLAKE3 factory is the
// canonical authenticated-stream MAC across the binding fleet.
func macForStreamTest(t *testing.T) itb.MACFunc {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	mac, err := macs.HMACBLAKE3(key[:])
	if err != nil {
		t.Fatalf("macs.HMACBLAKE3: %v", err)
	}
	return mac
}

func mkSeeds128Ext(t *testing.T) (n, d, s *itb.Seed128) {
	t.Helper()
	h := hashes.SipHash24()
	var err error
	if n, err = itb.NewSeed128(512, h); err != nil {
		t.Fatalf("NewSeed128: %v", err)
	}
	if d, err = itb.NewSeed128(512, h); err != nil {
		t.Fatalf("NewSeed128: %v", err)
	}
	if s, err = itb.NewSeed128(512, h); err != nil {
		t.Fatalf("NewSeed128: %v", err)
	}
	return
}

func mkSeeds256Ext(t *testing.T) (n, d, s *itb.Seed256) {
	t.Helper()
	h, _ := hashes.BLAKE3()
	var err error
	if n, err = itb.NewSeed256(512, h); err != nil {
		t.Fatalf("NewSeed256: %v", err)
	}
	if d, err = itb.NewSeed256(512, h); err != nil {
		t.Fatalf("NewSeed256: %v", err)
	}
	if s, err = itb.NewSeed256(512, h); err != nil {
		t.Fatalf("NewSeed256: %v", err)
	}
	return
}

func mkSeeds512Ext(t *testing.T) (n, d, s *itb.Seed512) {
	t.Helper()
	h, _ := hashes.BLAKE2b512()
	var err error
	if n, err = itb.NewSeed512(512, h); err != nil {
		t.Fatalf("NewSeed512: %v", err)
	}
	if d, err = itb.NewSeed512(512, h); err != nil {
		t.Fatalf("NewSeed512: %v", err)
	}
	if s, err = itb.NewSeed512(512, h); err != nil {
		t.Fatalf("NewSeed512: %v", err)
	}
	return
}

func mkTriple128Ext(t *testing.T) (n, d1, d2, d3, s1, s2, s3 *itb.Seed128) {
	t.Helper()
	n, d1, _ = mkSeeds128Ext(t)
	d2, d3, s1 = mkSeeds128Ext(t)
	s2, s3, _ = mkSeeds128Ext(t)
	return
}

func mkTriple256Ext(t *testing.T) (n, d1, d2, d3, s1, s2, s3 *itb.Seed256) {
	t.Helper()
	n, d1, _ = mkSeeds256Ext(t)
	d2, d3, s1 = mkSeeds256Ext(t)
	s2, s3, _ = mkSeeds256Ext(t)
	return
}

func mkTriple512Ext(t *testing.T) (n, d1, d2, d3, s1, s2, s3 *itb.Seed512) {
	t.Helper()
	n, d1, _ = mkSeeds512Ext(t)
	d2, d3, s1 = mkSeeds512Ext(t)
	s2, s3, _ = mkSeeds512Ext(t)
	return
}

func genTestPlaintextExt(t *testing.T, sz int) []byte {
	t.Helper()
	buf := make([]byte, sz)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return buf
}

func streamPlaintextSizesExt(chunk int) []int {
	return []int{1, chunk - 1, chunk, chunk + 1, 10 * chunk}
}

// streamIDPrefixLenExt mirrors the package-internal streamIDPrefixLen
// constant for external-test slice arithmetic.
const streamIDPrefixLenExt = 32

// --- Single-Ouroboros Streaming AEAD round-trip ---

func TestEncryptStreamAuthRoundtripExt(t *testing.T) {
	const chunk = 4096

	t.Run("128", func(t *testing.T) {
		for _, sz := range streamPlaintextSizesExt(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				ns, ds, ss := mkSeeds128Ext(t)
				mac := macForStreamTest(t)
				pt := genTestPlaintextExt(t, sz)
				var ctBuf bytes.Buffer
				if err := itb.EncryptStreamAuth(ns, ds, ss, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
					t.Fatalf("EncryptStreamAuth: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
					t.Fatalf("DecryptStreamAuth: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("128-bit auth-stream round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("256", func(t *testing.T) {
		for _, sz := range streamPlaintextSizesExt(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				ns, ds, ss := mkSeeds256Ext(t)
				mac := macForStreamTest(t)
				pt := genTestPlaintextExt(t, sz)
				var ctBuf bytes.Buffer
				if err := itb.EncryptStreamAuth(ns, ds, ss, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
					t.Fatalf("EncryptStreamAuth: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
					t.Fatalf("DecryptStreamAuth: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("256-bit auth-stream round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("512", func(t *testing.T) {
		for _, sz := range streamPlaintextSizesExt(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				ns, ds, ss := mkSeeds512Ext(t)
				mac := macForStreamTest(t)
				pt := genTestPlaintextExt(t, sz)
				var ctBuf bytes.Buffer
				if err := itb.EncryptStreamAuth(ns, ds, ss, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
					t.Fatalf("EncryptStreamAuth: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
					t.Fatalf("DecryptStreamAuth: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("512-bit auth-stream round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})
}

// TestEncryptStreamAuthEmptyInputExt exercises the zero-length-input
// terminator path: the encoder still emits the 32-byte streamID
// prefix followed by a single zero-length terminating chunk; the
// decoder accepts the transcript and emits no plaintext.
func TestEncryptStreamAuthEmptyInputExt(t *testing.T) {
	ns, ds, ss := mkSeeds128Ext(t)
	mac := macForStreamTest(t)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth(ns, ds, ss, bytes.NewReader(nil), &ctBuf, mac, 4096); err != nil {
		t.Fatalf("EncryptStreamAuth(empty): %v", err)
	}
	if ctBuf.Len() <= streamIDPrefixLenExt {
		t.Fatalf("EncryptStreamAuth(empty): want > %d bytes (prefix + terminator), got %d", streamIDPrefixLenExt, ctBuf.Len())
	}
	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
		t.Fatalf("DecryptStreamAuth(empty): %v", err)
	}
	if ptBuf.Len() != 0 {
		t.Fatalf("DecryptStreamAuth(empty): want 0-byte plaintext, got %d bytes", ptBuf.Len())
	}
}

func TestEncryptStreamAuthSingleChunkExt(t *testing.T) {
	ns, ds, ss := mkSeeds128Ext(t)
	mac := macForStreamTest(t)
	pt := genTestPlaintextExt(t, 100)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth(ns, ds, ss, bytes.NewReader(pt), &ctBuf, mac, 4096); err != nil {
		t.Fatalf("EncryptStreamAuth: %v", err)
	}
	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
		t.Fatalf("DecryptStreamAuth: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatalf("single-chunk auth round-trip mismatch")
	}
}

func TestEncryptStreamAuthChunkSize1Ext(t *testing.T) {
	ns, ds, ss := mkSeeds128Ext(t)
	mac := macForStreamTest(t)
	pt := genTestPlaintextExt(t, 16)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth(ns, ds, ss, bytes.NewReader(pt), &ctBuf, mac, 1); err != nil {
		t.Fatalf("EncryptStreamAuth(chunkSize=1): %v", err)
	}
	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
		t.Fatalf("DecryptStreamAuth: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatalf("chunkSize=1 auth round-trip mismatch")
	}
}

// TestEncryptStreamAuthTruncatedTailExt confirms the decoder surfaces
// ErrStreamTruncated when the transcript is cut before the terminator
// chunk.
func TestEncryptStreamAuthTruncatedTailExt(t *testing.T) {
	ns, ds, ss := mkSeeds128Ext(t)
	mac := macForStreamTest(t)
	const chunk = 4096
	pt := genTestPlaintextExt(t, 3*chunk+100)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth(ns, ds, ss, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
		t.Fatalf("EncryptStreamAuth: %v", err)
	}
	full := ctBuf.Bytes()
	off := streamIDPrefixLenExt
	var lastOff int
	for off < len(full) {
		clen, err := itb.ParseChunkLen(full[off:])
		if err != nil {
			t.Fatalf("ParseChunkLen at %d: %v", off, err)
		}
		lastOff = off
		off += clen
	}
	truncated := full[:lastOff]

	var ptBuf bytes.Buffer
	err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(truncated), &ptBuf, mac)
	if !errors.Is(err, itb.ErrStreamTruncated) {
		t.Fatalf("DecryptStreamAuth(truncated): want ErrStreamTruncated, got %v", err)
	}
}

// TestEncryptStreamAuthReorderDetectedExt confirms swapping two
// chunks within the transcript triggers MAC failure on the misplaced
// chunk (the cumulative pixel offset binding rejects the swap).
func TestEncryptStreamAuthReorderDetectedExt(t *testing.T) {
	ns, ds, ss := mkSeeds128Ext(t)
	mac := macForStreamTest(t)
	const chunk = 4096
	pt := genTestPlaintextExt(t, 3*chunk)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth(ns, ds, ss, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
		t.Fatalf("EncryptStreamAuth: %v", err)
	}
	full := ctBuf.Bytes()
	type span struct{ off, end int }
	var spans []span
	off := streamIDPrefixLenExt
	for off < len(full) {
		clen, err := itb.ParseChunkLen(full[off:])
		if err != nil {
			t.Fatalf("ParseChunkLen: %v", err)
		}
		spans = append(spans, span{off, off + clen})
		off += clen
	}
	if len(spans) < 3 {
		t.Fatalf("setup: expected >=3 chunks, got %d", len(spans))
	}
	rearr := append([]byte(nil), full...)
	c0 := append([]byte(nil), full[spans[0].off:spans[0].end]...)
	c1 := append([]byte(nil), full[spans[1].off:spans[1].end]...)
	if len(c0) != len(c1) {
		t.Skip("chunk[0] and chunk[1] differ in byte length; reorder swap not byte-safe")
	}
	copy(rearr[spans[0].off:spans[0].end], c1)
	copy(rearr[spans[1].off:spans[1].end], c0)

	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(rearr), &ptBuf, mac); err == nil {
		t.Fatalf("DecryptStreamAuth(reordered): want error, got nil")
	}
}

// TestEncryptStreamAuthCrossStreamReplayExt confirms a chunk replayed
// from a different stream (different streamID prefix) is rejected.
func TestEncryptStreamAuthCrossStreamReplayExt(t *testing.T) {
	ns, ds, ss := mkSeeds128Ext(t)
	mac := macForStreamTest(t)
	const chunk = 4096
	pt := genTestPlaintextExt(t, 2*chunk)

	var ct1, ct2 bytes.Buffer
	if err := itb.EncryptStreamAuth(ns, ds, ss, bytes.NewReader(pt), &ct1, mac, chunk); err != nil {
		t.Fatalf("EncryptStreamAuth #1: %v", err)
	}
	if err := itb.EncryptStreamAuth(ns, ds, ss, bytes.NewReader(pt), &ct2, mac, chunk); err != nil {
		t.Fatalf("EncryptStreamAuth #2: %v", err)
	}
	c1Bytes := ct1.Bytes()
	c2Bytes := ct2.Bytes()
	off := streamIDPrefixLenExt
	clen0, err := itb.ParseChunkLen(c1Bytes[off:])
	if err != nil {
		t.Fatalf("ParseChunkLen: %v", err)
	}
	off2 := streamIDPrefixLenExt
	clen0b, err := itb.ParseChunkLen(c2Bytes[off2:])
	if err != nil {
		t.Fatalf("ParseChunkLen: %v", err)
	}
	off2 += clen0b
	clen1b, err := itb.ParseChunkLen(c2Bytes[off2:])
	if err != nil {
		t.Fatalf("ParseChunkLen: %v", err)
	}
	splicedTail := c2Bytes[off2 : off2+clen1b]

	var spliced bytes.Buffer
	spliced.Write(c1Bytes[:off+clen0])
	spliced.Write(splicedTail)

	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(spliced.Bytes()), &ptBuf, mac); err == nil {
		t.Fatalf("DecryptStreamAuth(cross-stream replay): want error, got nil")
	}
}

// TestEncryptStreamAuthPrefixTamperExt confirms that flipping a byte
// in the streamID prefix breaks every per-chunk MAC binding.
func TestEncryptStreamAuthPrefixTamperExt(t *testing.T) {
	ns, ds, ss := mkSeeds128Ext(t)
	mac := macForStreamTest(t)
	pt := genTestPlaintextExt(t, 4096)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth(ns, ds, ss, bytes.NewReader(pt), &ctBuf, mac, 4096); err != nil {
		t.Fatalf("EncryptStreamAuth: %v", err)
	}
	tampered := append([]byte(nil), ctBuf.Bytes()...)
	tampered[0] ^= 0xFF

	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(tampered), &ptBuf, mac); err == nil {
		t.Fatalf("DecryptStreamAuth(prefix-tampered): want error, got nil")
	}
}

func TestEncryptStreamAuthWidthMixRejectedExt(t *testing.T) {
	mac := macForStreamTest(t)
	n128, _, _ := mkSeeds128Ext(t)
	_, d256, s256 := mkSeeds256Ext(t)
	pt := genTestPlaintextExt(t, 64)
	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth(n128, d256, s256, bytes.NewReader(pt), &ctBuf, mac, 4096); err == nil {
		t.Fatalf("EncryptStreamAuth(mixed widths): want error, got nil")
	}
}

// --- Triple-Ouroboros Streaming AEAD round-trip ---

func TestEncryptStreamAuth3xRoundtripExt(t *testing.T) {
	const chunk = 4096

	t.Run("128", func(t *testing.T) {
		for _, sz := range streamPlaintextSizesExt(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
				mac := macForStreamTest(t)
				pt := genTestPlaintextExt(t, sz)
				var ctBuf bytes.Buffer
				if err := itb.EncryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
					t.Fatalf("EncryptStreamAuth3x: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := itb.DecryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
					t.Fatalf("DecryptStreamAuth3x: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("128-bit Triple-auth-stream round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("256", func(t *testing.T) {
		for _, sz := range streamPlaintextSizesExt(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, d1, d2, d3, s1, s2, s3 := mkTriple256Ext(t)
				mac := macForStreamTest(t)
				pt := genTestPlaintextExt(t, sz)
				var ctBuf bytes.Buffer
				if err := itb.EncryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
					t.Fatalf("EncryptStreamAuth3x: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := itb.DecryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
					t.Fatalf("DecryptStreamAuth3x: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("256-bit Triple-auth-stream round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("512", func(t *testing.T) {
		for _, sz := range streamPlaintextSizesExt(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, d1, d2, d3, s1, s2, s3 := mkTriple512Ext(t)
				mac := macForStreamTest(t)
				pt := genTestPlaintextExt(t, sz)
				var ctBuf bytes.Buffer
				if err := itb.EncryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
					t.Fatalf("EncryptStreamAuth3x: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := itb.DecryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
					t.Fatalf("DecryptStreamAuth3x: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("512-bit Triple-auth-stream round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})
}

func TestEncryptStreamAuth3xEmptyInputExt(t *testing.T) {
	n, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(nil), &ctBuf, mac, 4096); err != nil {
		t.Fatalf("EncryptStreamAuth3x(empty): %v", err)
	}
	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
		t.Fatalf("DecryptStreamAuth3x(empty): %v", err)
	}
	if ptBuf.Len() != 0 {
		t.Fatalf("DecryptStreamAuth3x(empty): want 0-byte plaintext, got %d bytes", ptBuf.Len())
	}
}

func TestEncryptStreamAuth3xChunkSize1Ext(t *testing.T) {
	n, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)
	pt := genTestPlaintextExt(t, 8)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, 1); err != nil {
		t.Fatalf("EncryptStreamAuth3x(chunkSize=1): %v", err)
	}
	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
		t.Fatalf("DecryptStreamAuth3x: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatalf("Triple chunkSize=1 auth round-trip mismatch")
	}
}

func TestEncryptStreamAuth3xTruncatedTailExt(t *testing.T) {
	n, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)
	const chunk = 4096
	pt := genTestPlaintextExt(t, 3*chunk+50)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
		t.Fatalf("EncryptStreamAuth3x: %v", err)
	}
	full := ctBuf.Bytes()
	off := streamIDPrefixLenExt
	var lastOff int
	for off < len(full) {
		clen, err := itb.ParseChunkLen(full[off:])
		if err != nil {
			t.Fatalf("ParseChunkLen: %v", err)
		}
		lastOff = off
		off += clen
	}
	truncated := full[:lastOff]

	var ptBuf bytes.Buffer
	err := itb.DecryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(truncated), &ptBuf, mac)
	if !errors.Is(err, itb.ErrStreamTruncated) {
		t.Fatalf("DecryptStreamAuth3x(truncated): want ErrStreamTruncated, got %v", err)
	}
}

func TestEncryptStreamAuth3xWidthMixRejectedExt(t *testing.T) {
	mac := macForStreamTest(t)
	n128, d128, s128 := mkSeeds128Ext(t)
	_, d256, _ := mkSeeds256Ext(t)
	pt := genTestPlaintextExt(t, 64)
	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3x(n128, d128, d256, d128, s128, s128, s128, bytes.NewReader(pt), &ctBuf, mac, 4096); err == nil {
		t.Fatalf("EncryptStreamAuth3x(mixed widths): want error, got nil")
	}
}

// TestEncryptStreamAuthMissingMACExt asserts that a nil MACFunc
// surfaces an error rather than panicking.
func TestEncryptStreamAuthMissingMACExt(t *testing.T) {
	ns, ds, ss := mkSeeds128Ext(t)
	pt := genTestPlaintextExt(t, 64)
	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth(ns, ds, ss, bytes.NewReader(pt), &ctBuf, nil, 4096); err == nil {
		t.Fatalf("EncryptStreamAuth(nil mac): want error, got nil")
	}
	if err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(pt), &ctBuf, nil); err == nil {
		t.Fatalf("DecryptStreamAuth(nil mac): want error, got nil")
	}
}

// TestDecryptStreamAuthShortPrefixExt confirms a wire shorter than
// the 32-byte streamID prefix surfaces a structural error.
func TestDecryptStreamAuthShortPrefixExt(t *testing.T) {
	ns, ds, ss := mkSeeds128Ext(t)
	mac := macForStreamTest(t)
	short := []byte{0x01, 0x02, 0x03}
	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(short), &ptBuf, mac); err == nil {
		t.Fatalf("DecryptStreamAuth(short): want error, got nil")
	}
}

// TestDecryptStreamAuthShortPrefixMessageExt asserts the diagnostic
// emitted by the io.Reader / io.Writer single-Ouroboros decrypt path
// when the wire ends mid-prefix (1..31 bytes drawn) is the specific
// "stream too short for stream prefix" message rather than the
// generic mid-chunk EOF wrap. Mirrors the Rust / C / D bindings'
// distinction at the same stage.
func TestDecryptStreamAuthShortPrefixMessageExt(t *testing.T) {
	ns, ds, ss := mkSeeds128Ext(t)
	mac := macForStreamTest(t)
	const wantSubstr = "stream too short for stream prefix"

	for _, sz := range []int{0, 1, 17, 31} {
		t.Run(fmt.Sprintf("%dbytes", sz), func(t *testing.T) {
			short := bytes.Repeat([]byte{0xAB}, sz)
			var ptBuf bytes.Buffer
			err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(short), &ptBuf, mac)
			if err == nil {
				t.Fatalf("DecryptStreamAuth(%d-byte): want error, got nil", sz)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(wantSubstr)) {
				t.Fatalf("DecryptStreamAuth(%d-byte): want error containing %q, got %v", sz, wantSubstr, err)
			}
		})
	}
}

// TestDecryptStreamAuth3xShortPrefixMessageExt mirrors
// [TestDecryptStreamAuthShortPrefixMessageExt] for the Triple-Ouroboros
// io.Reader / io.Writer decrypt path.
func TestDecryptStreamAuth3xShortPrefixMessageExt(t *testing.T) {
	n, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)
	const wantSubstr = "stream too short for stream prefix"

	for _, sz := range []int{0, 1, 17, 31} {
		t.Run(fmt.Sprintf("%dbytes", sz), func(t *testing.T) {
			short := bytes.Repeat([]byte{0xAB}, sz)
			var ptBuf bytes.Buffer
			err := itb.DecryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(short), &ptBuf, mac)
			if err == nil {
				t.Fatalf("DecryptStreamAuth3x(%d-byte): want error, got nil", sz)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(wantSubstr)) {
				t.Fatalf("DecryptStreamAuth3x(%d-byte): want error containing %q, got %v", sz, wantSubstr, err)
			}
		})
	}
}

// TestDecryptStreamAuthAfterFinalExt confirms that bytes appearing
// after a chunk whose recovered finalFlag = true are rejected with
// [itb.ErrStreamAfterFinal] on the io.Reader / io.Writer single-
// Ouroboros decrypt path. The transcript is constructed by encrypting
// a multi-chunk stream and appending the terminating chunk again so
// the decoder observes a chunk after the terminator.
func TestDecryptStreamAuthAfterFinalExt(t *testing.T) {
	ns, ds, ss := mkSeeds128Ext(t)
	mac := macForStreamTest(t)
	const chunk = 4096
	pt := genTestPlaintextExt(t, 2*chunk+50)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth(ns, ds, ss, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
		t.Fatalf("EncryptStreamAuth: %v", err)
	}
	full := ctBuf.Bytes()

	// Walk to find the terminating chunk's byte span and append a
	// duplicate of it after the existing terminator. The duplicate
	// is itself a structurally-valid chunk that authenticates under
	// its own per-chunk MAC binding, but the decoder must reject it
	// because seenFinal is already true at the boundary.
	off := streamIDPrefixLenExt
	var lastOff, lastEnd int
	for off < len(full) {
		clen, err := itb.ParseChunkLen(full[off:])
		if err != nil {
			t.Fatalf("ParseChunkLen at %d: %v", off, err)
		}
		lastOff = off
		lastEnd = off + clen
		off += clen
	}
	tail := append([]byte(nil), full[lastOff:lastEnd]...)
	transcript := append(append([]byte(nil), full...), tail...)

	var ptBuf bytes.Buffer
	err := itb.DecryptStreamAuth(ns, ds, ss, bytes.NewReader(transcript), &ptBuf, mac)
	if !errors.Is(err, itb.ErrStreamAfterFinal) {
		t.Fatalf("DecryptStreamAuth(after-final): want ErrStreamAfterFinal, got %v", err)
	}
}

// TestDecryptStreamAuth3xAfterFinalExt mirrors
// [TestDecryptStreamAuthAfterFinalExt] for the Triple Ouroboros
// io.Reader / io.Writer decrypt path. Same construction: append the
// already-terminating chunk's bytes after the terminator and confirm
// the decoder surfaces [itb.ErrStreamAfterFinal].
func TestDecryptStreamAuth3xAfterFinalExt(t *testing.T) {
	n, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)
	const chunk = 4096
	pt := genTestPlaintextExt(t, 2*chunk+50)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
		t.Fatalf("EncryptStreamAuth3x: %v", err)
	}
	full := ctBuf.Bytes()
	off := streamIDPrefixLenExt
	var lastOff, lastEnd int
	for off < len(full) {
		clen, err := itb.ParseChunkLen(full[off:])
		if err != nil {
			t.Fatalf("ParseChunkLen at %d: %v", off, err)
		}
		lastOff = off
		lastEnd = off + clen
		off += clen
	}
	tail := append([]byte(nil), full[lastOff:lastEnd]...)
	transcript := append(append([]byte(nil), full...), tail...)

	var ptBuf bytes.Buffer
	err := itb.DecryptStreamAuth3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(transcript), &ptBuf, mac)
	if !errors.Is(err, itb.ErrStreamAfterFinal) {
		t.Fatalf("DecryptStreamAuth3x(after-final): want ErrStreamAfterFinal, got %v", err)
	}
}
