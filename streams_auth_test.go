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

func mkTriple128Ext(t *testing.T) (n, l, d1, d2, d3, s1, s2, s3 *itb.Seed128) {
	t.Helper()
	h := hashes.SipHash24()
	mk := func() *itb.Seed128 {
		s, err := itb.NewSeed128(512, h)
		if err != nil {
			t.Fatalf("NewSeed128: %v", err)
		}
		return s
	}
	return mk(), mk(), mk(), mk(), mk(), mk(), mk(), mk()
}

func mkTriple256Ext(t *testing.T) (n, l, d1, d2, d3, s1, s2, s3 *itb.Seed256) {
	t.Helper()
	h, _ := hashes.BLAKE3()
	mk := func() *itb.Seed256 {
		s, err := itb.NewSeed256(512, h)
		if err != nil {
			t.Fatalf("NewSeed256: %v", err)
		}
		return s
	}
	return mk(), mk(), mk(), mk(), mk(), mk(), mk(), mk()
}

func mkTriple512Ext(t *testing.T) (n, l, d1, d2, d3, s1, s2, s3 *itb.Seed512) {
	t.Helper()
	h, _ := hashes.BLAKE2b512()
	mk := func() *itb.Seed512 {
		s, err := itb.NewSeed512(512, h)
		if err != nil {
			t.Fatalf("NewSeed512: %v", err)
		}
		return s
	}
	return mk(), mk(), mk(), mk(), mk(), mk(), mk(), mk()
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

// --- Triple Ouroboros Streaming AEAD (io.Reader / io.Writer) round-trip ---

// TestEncryptStreamAuth3xRoundtripExt exercises the width-less
// [itb.EncryptStreamAuth3x] / [itb.DecryptStreamAuth3x] io.Reader /
// io.Writer pair across chunk-boundary edge cases (1 byte, chunk-1,
// chunk, chunk+1, 10*chunk) on every Triple width.
func TestEncryptStreamAuth3xRoundtripExt(t *testing.T) {
	const chunk = 4096

	t.Run("128", func(t *testing.T) {
		for _, sz := range streamPlaintextSizesExt(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, l, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
				mac := macForStreamTest(t)
				pt := genTestPlaintextExt(t, sz)
				var ctBuf bytes.Buffer
				if err := itb.EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
					t.Fatalf("EncryptStreamAuth3x: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := itb.DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
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
				n, l, d1, d2, d3, s1, s2, s3 := mkTriple256Ext(t)
				mac := macForStreamTest(t)
				pt := genTestPlaintextExt(t, sz)
				var ctBuf bytes.Buffer
				if err := itb.EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
					t.Fatalf("EncryptStreamAuth3x: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := itb.DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
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
				n, l, d1, d2, d3, s1, s2, s3 := mkTriple512Ext(t)
				mac := macForStreamTest(t)
				pt := genTestPlaintextExt(t, sz)
				var ctBuf bytes.Buffer
				if err := itb.EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
					t.Fatalf("EncryptStreamAuth3x: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := itb.DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
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
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(nil), &ctBuf, mac, 4096); err != nil {
		t.Fatalf("EncryptStreamAuth3x(empty): %v", err)
	}
	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
		t.Fatalf("DecryptStreamAuth3x(empty): %v", err)
	}
	if ptBuf.Len() != 0 {
		t.Fatalf("DecryptStreamAuth3x(empty): want 0-byte plaintext, got %d bytes", ptBuf.Len())
	}
}

func TestEncryptStreamAuth3xChunkSize1Ext(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)
	pt := genTestPlaintextExt(t, 8)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, 1); err != nil {
		t.Fatalf("EncryptStreamAuth3x(chunkSize=1): %v", err)
	}
	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
		t.Fatalf("DecryptStreamAuth3x: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatalf("Triple chunkSize=1 auth round-trip mismatch")
	}
}

// TestEncryptStreamAuth3xTruncatedTailExt confirms the Triple decoder
// surfaces ErrStreamTruncated when the transcript is cut before the
// terminator chunk.
func TestEncryptStreamAuth3xTruncatedTailExt(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)
	const chunk = 4096
	pt := genTestPlaintextExt(t, 3*chunk+50)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
		t.Fatalf("EncryptStreamAuth3x: %v", err)
	}
	full := ctBuf.Bytes()
	off := streamIDPrefixLenExt
	var lastOff int
	for off < len(full) {
		clen, err := itb.ParseChunkLenCfg(nil, full[off:])
		if err != nil {
			t.Fatalf("ParseChunkLen: %v", err)
		}
		lastOff = off
		off += clen
	}
	truncated := full[:lastOff]

	var ptBuf bytes.Buffer
	err := itb.DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(truncated), &ptBuf, mac)
	if !errors.Is(err, itb.ErrStreamTruncated) {
		t.Fatalf("DecryptStreamAuth3x(truncated): want ErrStreamTruncated, got %v", err)
	}
}

// TestEncryptStreamAuth3xWidthMixRejectedExt confirms width-mix
// detection on the Triple io.Reader / io.Writer Streaming AEAD path.
func TestEncryptStreamAuth3xWidthMixRejectedExt(t *testing.T) {
	mac := macForStreamTest(t)
	n128, l128, d128, _, _, s128, _, _ := mkTriple128Ext(t)
	_, _, d256, _, _, _, _, _ := mkTriple256Ext(t)
	pt := genTestPlaintextExt(t, 64)
	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3xCfg(nil, n128, l128, d128, d256, d128, s128, s128, s128, bytes.NewReader(pt), &ctBuf, mac, 4096); err == nil {
		t.Fatalf("EncryptStreamAuth3x(mixed widths): want error, got nil")
	}
}

// TestEncryptStreamAuth3xMissingMACExt asserts that a nil MACFunc
// surfaces an error rather than panicking.
func TestEncryptStreamAuth3xMissingMACExt(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	pt := genTestPlaintextExt(t, 64)
	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, nil, 4096); err == nil {
		t.Fatalf("EncryptStreamAuth3x(nil mac): want error, got nil")
	}
	if err := itb.DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, nil); err == nil {
		t.Fatalf("DecryptStreamAuth3x(nil mac): want error, got nil")
	}
}

// TestDecryptStreamAuth3xShortPrefixMessageExt asserts the diagnostic
// emitted by the Triple io.Reader / io.Writer decrypt path when the
// wire ends mid-prefix (1..31 bytes drawn) is the specific
// "stream too short for stream prefix" message rather than the
// generic mid-chunk EOF wrap. Mirrors the C / Rust / D bindings'
// distinction at the same stage.
func TestDecryptStreamAuth3xShortPrefixMessageExt(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)
	const wantSubstr = "stream too short for stream prefix"

	for _, sz := range []int{0, 1, 17, 31} {
		t.Run(fmt.Sprintf("%dbytes", sz), func(t *testing.T) {
			short := bytes.Repeat([]byte{0xAB}, sz)
			var ptBuf bytes.Buffer
			err := itb.DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(short), &ptBuf, mac)
			if err == nil {
				t.Fatalf("DecryptStreamAuth3x(%d-byte): want error, got nil", sz)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(wantSubstr)) {
				t.Fatalf("DecryptStreamAuth3x(%d-byte): want error containing %q, got %v", sz, wantSubstr, err)
			}
		})
	}
}

// TestDecryptStreamAuth3xAfterFinalExt confirms bytes appearing
// after a chunk whose recovered finalFlag = true are rejected with
// [itb.ErrStreamAfterFinal] on the Triple Ouroboros io.Reader /
// io.Writer decrypt path.
func TestDecryptStreamAuth3xAfterFinalExt(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)
	const chunk = 4096
	pt := genTestPlaintextExt(t, 2*chunk+50)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
		t.Fatalf("EncryptStreamAuth3x: %v", err)
	}
	full := ctBuf.Bytes()
	off := streamIDPrefixLenExt
	var lastOff, lastEnd int
	for off < len(full) {
		clen, err := itb.ParseChunkLenCfg(nil, full[off:])
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
	err := itb.DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(transcript), &ptBuf, mac)
	if !errors.Is(err, itb.ErrStreamAfterFinal) {
		t.Fatalf("DecryptStreamAuth3x(after-final): want ErrStreamAfterFinal, got %v", err)
	}
}

// --- Triple Ouroboros authenticated-stream Cfg variants ---
//
// The auth-stream Cfg helpers in stream_auth.go take a (data []byte,
// chunkSize int, macFunc MACFunc, emit func([]byte) error) signature.
// Round-trip the 256 / 512 Triple matrix by collecting emitted chunks
// into a byte slice on the encrypt side, then feeding the concatenated
// transcript into the matching decrypt Cfg helper.

func TestEncryptStreamAuth3x256CfgRoundtripExt(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple256Ext(t)
	mac := macForStreamTest(t)
	var cfg *itb.Config
	pt := genTestPlaintextExt(t, 5000)

	var ct bytes.Buffer
	if err := itb.EncryptStreamAuth3x256Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, pt, 1024, mac, func(chunk []byte) error {
		ct.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("EncryptStreamAuth3x256Cfg: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatalf("EncryptStreamAuth3x256Cfg: emitted no bytes")
	}
	var dec bytes.Buffer
	if err := itb.DecryptStreamAuth3x256Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, ct.Bytes(), mac, func(chunk []byte) error {
		dec.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("DecryptStreamAuth3x256Cfg: %v", err)
	}
	if !bytes.Equal(pt, dec.Bytes()) {
		t.Fatalf("EncryptStreamAuth3x256Cfg round-trip mismatch")
	}
}

func TestEncryptStreamAuth3x512CfgRoundtripExt(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple512Ext(t)
	mac := macForStreamTest(t)
	var cfg *itb.Config
	pt := genTestPlaintextExt(t, 5000)

	var ct bytes.Buffer
	if err := itb.EncryptStreamAuth3x512Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, pt, 1024, mac, func(chunk []byte) error {
		ct.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("EncryptStreamAuth3x512Cfg: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatalf("EncryptStreamAuth3x512Cfg: emitted no bytes")
	}
	var dec bytes.Buffer
	if err := itb.DecryptStreamAuth3x512Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, ct.Bytes(), mac, func(chunk []byte) error {
		dec.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("DecryptStreamAuth3x512Cfg: %v", err)
	}
	if !bytes.Equal(pt, dec.Bytes()) {
		t.Fatalf("EncryptStreamAuth3x512Cfg round-trip mismatch")
	}
}

// TestDecryptStreamAuth3xCfgTamperExt exercises the tamper-rejection
// path of the Triple 256 / 512 auth-stream Cfg decrypt helpers — a
// single byte flip mid-transcript must surface as a MAC failure
// rather than silently succeed.
func TestDecryptStreamAuth3xCfgTamperExt(t *testing.T) {
	t.Run("256_Triple", func(t *testing.T) {
		n, l, d1, d2, d3, s1, s2, s3 := mkTriple256Ext(t)
		mac := macForStreamTest(t)
		var cfg *itb.Config
		pt := genTestPlaintextExt(t, 3000)

		var ct bytes.Buffer
		if err := itb.EncryptStreamAuth3x256Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, pt, 1024, mac, func(chunk []byte) error {
			ct.Write(chunk)
			return nil
		}); err != nil {
			t.Fatalf("EncryptStreamAuth3x256Cfg: %v", err)
		}
		tampered := append([]byte(nil), ct.Bytes()...)
		tampered[len(tampered)/2] ^= 0xFF

		var dec bytes.Buffer
		err := itb.DecryptStreamAuth3x256Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, tampered, mac, func(chunk []byte) error {
			dec.Write(chunk)
			return nil
		})
		if err == nil {
			t.Fatalf("DecryptStreamAuth3x256Cfg(tampered): want error, got nil")
		}
	})

	t.Run("512_Triple", func(t *testing.T) {
		n, l, d1, d2, d3, s1, s2, s3 := mkTriple512Ext(t)
		mac := macForStreamTest(t)
		var cfg *itb.Config
		pt := genTestPlaintextExt(t, 3000)

		var ct bytes.Buffer
		if err := itb.EncryptStreamAuth3x512Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, pt, 1024, mac, func(chunk []byte) error {
			ct.Write(chunk)
			return nil
		}); err != nil {
			t.Fatalf("EncryptStreamAuth3x512Cfg: %v", err)
		}
		tampered := append([]byte(nil), ct.Bytes()...)
		tampered[len(tampered)/2] ^= 0xFF

		var dec bytes.Buffer
		err := itb.DecryptStreamAuth3x512Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, tampered, mac, func(chunk []byte) error {
			dec.Write(chunk)
			return nil
		})
		if err == nil {
			t.Fatalf("DecryptStreamAuth3x512Cfg(tampered): want error, got nil")
		}
	})
}

// TestEncryptStreamAuth3xReorderDetectedExt confirms swapping two
// chunks within the Triple transcript triggers MAC failure on the
// misplaced chunk (the cumulative pixel-offset binding rejects the
// swap).
func TestEncryptStreamAuth3xReorderDetectedExt(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)
	const chunk = 4096
	pt := genTestPlaintextExt(t, 3*chunk)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
		t.Fatalf("EncryptStreamAuth3x: %v", err)
	}
	full := ctBuf.Bytes()
	type span struct{ off, end int }
	var spans []span
	off := streamIDPrefixLenExt
	for off < len(full) {
		clen, err := itb.ParseChunkLenCfg(nil, full[off:])
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
	if err := itb.DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(rearr), &ptBuf, mac); err == nil {
		t.Fatalf("DecryptStreamAuth3x(reordered): want error, got nil")
	}
}

// TestEncryptStreamAuth3xCrossStreamReplayExt confirms a chunk
// replayed from a different Triple stream (different streamID prefix)
// is rejected.
func TestEncryptStreamAuth3xCrossStreamReplayExt(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)
	const chunk = 4096
	pt := genTestPlaintextExt(t, 2*chunk)

	var ct1, ct2 bytes.Buffer
	if err := itb.EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ct1, mac, chunk); err != nil {
		t.Fatalf("EncryptStreamAuth3x #1: %v", err)
	}
	if err := itb.EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ct2, mac, chunk); err != nil {
		t.Fatalf("EncryptStreamAuth3x #2: %v", err)
	}
	c1Bytes := ct1.Bytes()
	c2Bytes := ct2.Bytes()
	off := streamIDPrefixLenExt
	clen0, err := itb.ParseChunkLenCfg(nil, c1Bytes[off:])
	if err != nil {
		t.Fatalf("ParseChunkLen: %v", err)
	}
	off2 := streamIDPrefixLenExt
	clen0b, err := itb.ParseChunkLenCfg(nil, c2Bytes[off2:])
	if err != nil {
		t.Fatalf("ParseChunkLen: %v", err)
	}
	off2 += clen0b
	clen1b, err := itb.ParseChunkLenCfg(nil, c2Bytes[off2:])
	if err != nil {
		t.Fatalf("ParseChunkLen: %v", err)
	}
	splicedTail := c2Bytes[off2 : off2+clen1b]

	var spliced bytes.Buffer
	spliced.Write(c1Bytes[:off+clen0])
	spliced.Write(splicedTail)

	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(spliced.Bytes()), &ptBuf, mac); err == nil {
		t.Fatalf("DecryptStreamAuth3x(cross-stream replay): want error, got nil")
	}
}

// --- Triple Ouroboros IO-Driven AEAD Cfg round-trip sweep ---
//
// The width-less [itb.EncryptStreamAuth3xCfg] /
// [itb.DecryptStreamAuth3xCfg] IO-Driven helpers accept a per-encryptor
// *itb.Config so cfg.MaxWorkers / cfg.NonceBits / cfg.BarrierFill flow
// through the chunked authenticated path without touching the process
// globals. This sweep exercises every Triple width (128 / 256 / 512),
// every MaxWorkers cap {1, 2, 4, 8}, and every chunk-boundary
// plaintext size {0, 1, chunkSize-1, chunkSize, chunkSize+1, 1 MiB}
// at a modest chunkSize=4096 override, flat t.Run per combination.
func TestEncryptStreamAuth3xCfgRoundTripAllWidths(t *testing.T) {
	const chunk = 4096
	widths := []int{128, 256, 512}
	workers := []int{1, 2, 4, 8}
	sizes := []int{0, 1, chunk - 1, chunk, chunk + 1, 1 << 20}

	for _, w := range widths {
		w := w
		for _, mw := range workers {
			mw := mw
			for _, sz := range sizes {
				sz := sz
				name := fmt.Sprintf("w%d/mw%d/sz%d", w, mw, sz)
				t.Run(name, func(t *testing.T) {
					cfg := &itb.Config{MaxWorkers: mw}
					mac := macForStreamTest(t)
					pt := genTestPlaintextExt(t, sz)
					var ctBuf bytes.Buffer
					switch w {
					case 128:
						n, l, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
						if err := itb.EncryptStreamAuth3xCfg(cfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
							t.Fatalf("EncryptStreamAuth3xCfg: %v", err)
						}
						var ptBuf bytes.Buffer
						if err := itb.DecryptStreamAuth3xCfg(cfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
							t.Fatalf("DecryptStreamAuth3xCfg: %v", err)
						}
						if !bytes.Equal(pt, ptBuf.Bytes()) {
							t.Fatalf("128-bit Cfg AEAD round-trip mismatch at %d bytes", sz)
						}
					case 256:
						n, l, d1, d2, d3, s1, s2, s3 := mkTriple256Ext(t)
						if err := itb.EncryptStreamAuth3xCfg(cfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
							t.Fatalf("EncryptStreamAuth3xCfg: %v", err)
						}
						var ptBuf bytes.Buffer
						if err := itb.DecryptStreamAuth3xCfg(cfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
							t.Fatalf("DecryptStreamAuth3xCfg: %v", err)
						}
						if !bytes.Equal(pt, ptBuf.Bytes()) {
							t.Fatalf("256-bit Cfg AEAD round-trip mismatch at %d bytes", sz)
						}
					case 512:
						n, l, d1, d2, d3, s1, s2, s3 := mkTriple512Ext(t)
						if err := itb.EncryptStreamAuth3xCfg(cfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, chunk); err != nil {
							t.Fatalf("EncryptStreamAuth3xCfg: %v", err)
						}
						var ptBuf bytes.Buffer
						if err := itb.DecryptStreamAuth3xCfg(cfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
							t.Fatalf("DecryptStreamAuth3xCfg: %v", err)
						}
						if !bytes.Equal(pt, ptBuf.Bytes()) {
							t.Fatalf("512-bit Cfg AEAD round-trip mismatch at %d bytes", sz)
						}
					}
				})
			}
		}
	}
}

// TestEncryptStreamAuth3xCfgNonceBitsOverride encrypts under
// cfg.NonceBits = 256 and confirms:
//
//  1. A receiver with matching cfg.NonceBits = 256 decrypts the wire
//     successfully.
//  2. A receiver with mismatched cfg (default globals — nonce width
//     differs from the encoder's 256-bit envelope) fails on the first
//     chunk header parse, since the header parser reads the width /
//     height uint16 values at a different offset. Any non-nil error
//     satisfies the invariant; the specific error string is not part
//     of the contract (the header parser surfaces one of "invalid
//     dimensions", "chunk too large", or "short body read" depending
//     on where the misaligned uint16 read lands).
//
// The process-global nonce width is pinned via installNonceBits inside
// the encoder path (indirectly, since installNonceBits lives in the
// package_internal test) — the external test can only assert the
// mismatched-cfg failure, not swap the process global. To keep both
// arms authoritative, the mismatched-cfg arm uses a distinct
// cfg.NonceBits value that differs from the encoder's; both sides
// override the same process global, so the outcome is deterministic.
func TestEncryptStreamAuth3xCfgNonceBitsOverride(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)
	pt := genTestPlaintextExt(t, 4096)

	// Encoder pins nonce width via cfg override.
	sendCfg := &itb.Config{NonceBits: 256}
	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3xCfg(sendCfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, 1024); err != nil {
		t.Fatalf("EncryptStreamAuth3xCfg(NonceBits=256): %v", err)
	}
	wire := ctBuf.Bytes()

	t.Run("matching_cfg_decrypts", func(t *testing.T) {
		recvCfg := &itb.Config{NonceBits: 256}
		var out bytes.Buffer
		if err := itb.DecryptStreamAuth3xCfg(recvCfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(wire), &out, mac); err != nil {
			t.Fatalf("DecryptStreamAuth3xCfg(NonceBits=256): %v", err)
		}
		if !bytes.Equal(pt, out.Bytes()) {
			t.Fatalf("matching cfg: recovered plaintext differs from input")
		}
	})

	t.Run("mismatched_cfg_fails", func(t *testing.T) {
		mismatched := &itb.Config{NonceBits: 128}
		var out bytes.Buffer
		err := itb.DecryptStreamAuth3xCfg(mismatched, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(wire), &out, mac)
		if err == nil {
			t.Fatalf("DecryptStreamAuth3xCfg(mismatched NonceBits): want error, got nil")
		}
	})
}

// TestEncryptStreamAuth3xPrefixTamperExt confirms that flipping a
// byte in the streamID prefix breaks every per-chunk MAC binding on
// the Triple path.
func TestEncryptStreamAuth3xPrefixTamperExt(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)
	pt := genTestPlaintextExt(t, 4096)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, 4096); err != nil {
		t.Fatalf("EncryptStreamAuth3x: %v", err)
	}
	tampered := append([]byte(nil), ctBuf.Bytes()...)
	tampered[0] ^= 0xFF

	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(tampered), &ptBuf, mac); err == nil {
		t.Fatalf("DecryptStreamAuth3x(prefix-tampered): want error, got nil")
	}
}

// TestEncryptStreamAuth3xSingleChunkExt exercises the single-chunk
// path (plaintext smaller than one chunk) — the encoder emits stream
// prefix + terminator chunk, the decoder recovers the plaintext.
func TestEncryptStreamAuth3xSingleChunkExt(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128Ext(t)
	mac := macForStreamTest(t)
	pt := genTestPlaintextExt(t, 100)

	var ctBuf bytes.Buffer
	if err := itb.EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, mac, 4096); err != nil {
		t.Fatalf("EncryptStreamAuth3x: %v", err)
	}
	var ptBuf bytes.Buffer
	if err := itb.DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf, mac); err != nil {
		t.Fatalf("DecryptStreamAuth3x: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatalf("single-chunk Triple auth round-trip mismatch")
	}
}
