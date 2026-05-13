package itb

import (
	"bytes"
	"fmt"
	"testing"
)

// streamPlaintextSizes covers the chunk-boundary edge cases at a
// modest chunk override (chunkSize = 4096) plus the multi-chunk path.
func streamPlaintextSizes(chunk int) []int {
	return []int{1, chunk - 1, chunk, chunk + 1, 10 * chunk}
}

// --- Single-Ouroboros plain stream helpers ---

func TestEncryptStreamRoundtrip(t *testing.T) {
	const chunk = 4096

	t.Run("128", func(t *testing.T) {
		for _, sz := range streamPlaintextSizes(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				ns, ds, ss := mkSeeds128(t)
				pt := genTestPlaintext(t, sz)
				var ctBuf bytes.Buffer
				if err := EncryptStream(ns, ds, ss, bytes.NewReader(pt), &ctBuf, chunk); err != nil {
					t.Fatalf("EncryptStream: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := DecryptStream(ns, ds, ss, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
					t.Fatalf("DecryptStream: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("128-bit plain-stream round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("256", func(t *testing.T) {
		for _, sz := range streamPlaintextSizes(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				ns, ds, ss := mkSeeds256(t)
				pt := genTestPlaintext(t, sz)
				var ctBuf bytes.Buffer
				if err := EncryptStream(ns, ds, ss, bytes.NewReader(pt), &ctBuf, chunk); err != nil {
					t.Fatalf("EncryptStream: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := DecryptStream(ns, ds, ss, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
					t.Fatalf("DecryptStream: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("256-bit plain-stream round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("512", func(t *testing.T) {
		for _, sz := range streamPlaintextSizes(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				ns, ds, ss := mkSeeds512(t)
				pt := genTestPlaintext(t, sz)
				var ctBuf bytes.Buffer
				if err := EncryptStream(ns, ds, ss, bytes.NewReader(pt), &ctBuf, chunk); err != nil {
					t.Fatalf("EncryptStream: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := DecryptStream(ns, ds, ss, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
					t.Fatalf("DecryptStream: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("512-bit plain-stream round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})
}

// TestEncryptStreamChunkSize1 exercises the worst-case chunk-size
// override of 1, which forces one full ITB container per plaintext
// byte. Only run on small payloads — the per-chunk fixed overhead
// dominates and 1 KiB plaintext at chunkSize = 1 already produces a
// noticeable test runtime.
func TestEncryptStreamChunkSize1(t *testing.T) {
	ns, ds, ss := mkSeeds128(t)
	pt := genTestPlaintext(t, 64)
	var ctBuf bytes.Buffer
	if err := EncryptStream(ns, ds, ss, bytes.NewReader(pt), &ctBuf, 1); err != nil {
		t.Fatalf("EncryptStream(chunkSize=1): %v", err)
	}
	var ptBuf bytes.Buffer
	if err := DecryptStream(ns, ds, ss, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatalf("chunkSize=1 round-trip mismatch")
	}
}

// TestEncryptStreamEmptyInput confirms that an empty src emits no
// chunks (the plain-stream helper has no terminator framing, so
// "no input -> no output" is the expected wire shape) and that
// DecryptStream on the empty wire returns cleanly.
func TestEncryptStreamEmptyInput(t *testing.T) {
	ns, ds, ss := mkSeeds128(t)
	var ctBuf bytes.Buffer
	if err := EncryptStream(ns, ds, ss, bytes.NewReader(nil), &ctBuf, 4096); err != nil {
		t.Fatalf("EncryptStream(empty): %v", err)
	}
	if ctBuf.Len() != 0 {
		t.Fatalf("EncryptStream(empty): want 0-byte wire, got %d bytes", ctBuf.Len())
	}
	var ptBuf bytes.Buffer
	if err := DecryptStream(ns, ds, ss, bytes.NewReader(nil), &ptBuf); err != nil {
		t.Fatalf("DecryptStream(empty): %v", err)
	}
	if ptBuf.Len() != 0 {
		t.Fatalf("DecryptStream(empty): want 0-byte plaintext, got %d bytes", ptBuf.Len())
	}
}

func TestEncryptStreamSingleChunk(t *testing.T) {
	ns, ds, ss := mkSeeds128(t)
	pt := genTestPlaintext(t, 100)
	var ctBuf bytes.Buffer
	if err := EncryptStream(ns, ds, ss, bytes.NewReader(pt), &ctBuf, 4096); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	var ptBuf bytes.Buffer
	if err := DecryptStream(ns, ds, ss, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatalf("single-chunk round-trip mismatch")
	}
}

// TestEncryptStreamWidthMixRejected confirms width-mix detection on
// the streaming path.
func TestEncryptStreamWidthMixRejected(t *testing.T) {
	n128, _, _ := mkSeeds128(t)
	_, d256, s256 := mkSeeds256(t)
	pt := genTestPlaintext(t, 64)
	var ctBuf bytes.Buffer
	if err := EncryptStream(n128, d256, s256, bytes.NewReader(pt), &ctBuf, 4096); err == nil {
		t.Fatalf("EncryptStream(mixed widths): want error, got nil")
	}
}

// --- Triple-Ouroboros plain stream helpers ---

func TestEncryptStream3xRoundtrip(t *testing.T) {
	const chunk = 4096

	t.Run("128", func(t *testing.T) {
		for _, sz := range streamPlaintextSizes(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
				pt := genTestPlaintext(t, sz)
				var ctBuf bytes.Buffer
				if err := EncryptStream3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, chunk); err != nil {
					t.Fatalf("EncryptStream3x: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := DecryptStream3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
					t.Fatalf("DecryptStream3x: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("128-bit Triple-stream round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("256", func(t *testing.T) {
		for _, sz := range streamPlaintextSizes(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, d1, d2, d3, s1, s2, s3 := mkTriple256(t)
				pt := genTestPlaintext(t, sz)
				var ctBuf bytes.Buffer
				if err := EncryptStream3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, chunk); err != nil {
					t.Fatalf("EncryptStream3x: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := DecryptStream3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
					t.Fatalf("DecryptStream3x: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("256-bit Triple-stream round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("512", func(t *testing.T) {
		for _, sz := range streamPlaintextSizes(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, d1, d2, d3, s1, s2, s3 := mkTriple512(t)
				pt := genTestPlaintext(t, sz)
				var ctBuf bytes.Buffer
				if err := EncryptStream3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, chunk); err != nil {
					t.Fatalf("EncryptStream3x: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := DecryptStream3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
					t.Fatalf("DecryptStream3x: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("512-bit Triple-stream round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})
}

func TestEncryptStream3xChunkSize1(t *testing.T) {
	n, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
	pt := genTestPlaintext(t, 32)
	var ctBuf bytes.Buffer
	if err := EncryptStream3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, 1); err != nil {
		t.Fatalf("EncryptStream3x(chunkSize=1): %v", err)
	}
	var ptBuf bytes.Buffer
	if err := DecryptStream3x(n, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
		t.Fatalf("DecryptStream3x: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatalf("Triple chunkSize=1 round-trip mismatch")
	}
}

func TestEncryptStream3xWidthMixRejected(t *testing.T) {
	n128, d128, s128 := mkSeeds128(t)
	_, d256, _ := mkSeeds256(t)
	pt := genTestPlaintext(t, 64)
	var ctBuf bytes.Buffer
	if err := EncryptStream3x(n128, d128, d256, d128, s128, s128, s128, bytes.NewReader(pt), &ctBuf, 4096); err == nil {
		t.Fatalf("EncryptStream3x(mixed widths): want error, got nil")
	}
}

// --- Single / Triple plain-stream Cfg variants ---
//
// The *Cfg helpers in stream.go take a (data []byte, chunkSize int,
// emit func([]byte) error) signature instead of the high-level
// io.Reader / io.Writer pair. Round-trip the matrix by collecting
// emitted chunks into a byte slice on the encrypt side and feeding
// the concatenation into the matching decrypt Cfg helper.

func TestEncryptStreamCfgRoundtrip128(t *testing.T) {
	ns, ds, ss := mkSeeds128(t)
	cfg := SnapshotGlobals()
	pt := genTestPlaintext(t, 5000)

	var ct bytes.Buffer
	if err := EncryptStream128Cfg(cfg, ns, ds, ss, pt, 1024, func(chunk []byte) error {
		ct.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("EncryptStream128Cfg: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatalf("EncryptStream128Cfg: emitted no bytes")
	}
	var dec bytes.Buffer
	if err := DecryptStream128Cfg(cfg, ns, ds, ss, ct.Bytes(), func(chunk []byte) error {
		dec.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("DecryptStream128Cfg: %v", err)
	}
	if !bytes.Equal(pt, dec.Bytes()) {
		t.Fatalf("EncryptStream128Cfg round-trip mismatch")
	}
}

func TestEncryptStreamCfgRoundtrip256(t *testing.T) {
	ns, ds, ss := mkSeeds256(t)
	cfg := SnapshotGlobals()
	pt := genTestPlaintext(t, 5000)

	var ct bytes.Buffer
	if err := EncryptStream256Cfg(cfg, ns, ds, ss, pt, 1024, func(chunk []byte) error {
		ct.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("EncryptStream256Cfg: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatalf("EncryptStream256Cfg: emitted no bytes")
	}
	var dec bytes.Buffer
	if err := DecryptStream256Cfg(cfg, ns, ds, ss, ct.Bytes(), func(chunk []byte) error {
		dec.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("DecryptStream256Cfg: %v", err)
	}
	if !bytes.Equal(pt, dec.Bytes()) {
		t.Fatalf("EncryptStream256Cfg round-trip mismatch")
	}
}

func TestEncryptStreamCfgRoundtrip512(t *testing.T) {
	ns, ds, ss := mkSeeds512(t)
	cfg := SnapshotGlobals()
	pt := genTestPlaintext(t, 5000)

	var ct bytes.Buffer
	if err := EncryptStream512Cfg(cfg, ns, ds, ss, pt, 1024, func(chunk []byte) error {
		ct.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("EncryptStream512Cfg: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatalf("EncryptStream512Cfg: emitted no bytes")
	}
	var dec bytes.Buffer
	if err := DecryptStream512Cfg(cfg, ns, ds, ss, ct.Bytes(), func(chunk []byte) error {
		dec.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("DecryptStream512Cfg: %v", err)
	}
	if !bytes.Equal(pt, dec.Bytes()) {
		t.Fatalf("EncryptStream512Cfg round-trip mismatch")
	}
}

func TestEncryptStream3xCfgRoundtrip128(t *testing.T) {
	n, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
	cfg := SnapshotGlobals()
	pt := genTestPlaintext(t, 5000)

	var ct bytes.Buffer
	if err := EncryptStream3x128Cfg(cfg, n, d1, d2, d3, s1, s2, s3, pt, 1024, func(chunk []byte) error {
		ct.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("EncryptStream3x128Cfg: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatalf("EncryptStream3x128Cfg: emitted no bytes")
	}
	var dec bytes.Buffer
	if err := DecryptStream3x128Cfg(cfg, n, d1, d2, d3, s1, s2, s3, ct.Bytes(), func(chunk []byte) error {
		dec.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("DecryptStream3x128Cfg: %v", err)
	}
	if !bytes.Equal(pt, dec.Bytes()) {
		t.Fatalf("EncryptStream3x128Cfg round-trip mismatch")
	}
}

func TestEncryptStream3xCfgRoundtrip256(t *testing.T) {
	n, d1, d2, d3, s1, s2, s3 := mkTriple256(t)
	cfg := SnapshotGlobals()
	pt := genTestPlaintext(t, 5000)

	var ct bytes.Buffer
	if err := EncryptStream3x256Cfg(cfg, n, d1, d2, d3, s1, s2, s3, pt, 1024, func(chunk []byte) error {
		ct.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("EncryptStream3x256Cfg: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatalf("EncryptStream3x256Cfg: emitted no bytes")
	}
	var dec bytes.Buffer
	if err := DecryptStream3x256Cfg(cfg, n, d1, d2, d3, s1, s2, s3, ct.Bytes(), func(chunk []byte) error {
		dec.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("DecryptStream3x256Cfg: %v", err)
	}
	if !bytes.Equal(pt, dec.Bytes()) {
		t.Fatalf("EncryptStream3x256Cfg round-trip mismatch")
	}
}

func TestEncryptStream3xCfgRoundtrip512(t *testing.T) {
	n, d1, d2, d3, s1, s2, s3 := mkTriple512(t)
	cfg := SnapshotGlobals()
	pt := genTestPlaintext(t, 5000)

	var ct bytes.Buffer
	if err := EncryptStream3x512Cfg(cfg, n, d1, d2, d3, s1, s2, s3, pt, 1024, func(chunk []byte) error {
		ct.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("EncryptStream3x512Cfg: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatalf("EncryptStream3x512Cfg: emitted no bytes")
	}
	var dec bytes.Buffer
	if err := DecryptStream3x512Cfg(cfg, n, d1, d2, d3, s1, s2, s3, ct.Bytes(), func(chunk []byte) error {
		dec.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("DecryptStream3x512Cfg: %v", err)
	}
	if !bytes.Equal(pt, dec.Bytes()) {
		t.Fatalf("EncryptStream3x512Cfg round-trip mismatch")
	}
}
