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

// --- Triple Ouroboros plain-stream (io.Reader / io.Writer) round-trip ---

// TestEncryptStream3xRoundtrip exercises the width-less
// [EncryptStream3xCfg] / [DecryptStream3xCfg] io.Reader / io.Writer pair
// across chunk-boundary edge cases (1 byte, chunk-1, chunk, chunk+1,
// 10*chunk) on every Triple width. The Triple round-trip covers all 8
// seeds threaded through the plain-stream path — same 8-seed
// Encrypt3x*Cfg wire format on every chunk.
func TestEncryptStream3xRoundtrip(t *testing.T) {
	const chunk = 4096

	t.Run("128", func(t *testing.T) {
		for _, sz := range streamPlaintextSizes(chunk) {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
				pt := genTestPlaintext(t, sz)
				var ctBuf bytes.Buffer
				if err := EncryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, chunk); err != nil {
					t.Fatalf("EncryptStream3x: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := DecryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
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
				n, l, d1, d2, d3, s1, s2, s3 := mkTriple256(t)
				pt := genTestPlaintext(t, sz)
				var ctBuf bytes.Buffer
				if err := EncryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, chunk); err != nil {
					t.Fatalf("EncryptStream3x: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := DecryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
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
				n, l, d1, d2, d3, s1, s2, s3 := mkTriple512(t)
				pt := genTestPlaintext(t, sz)
				var ctBuf bytes.Buffer
				if err := EncryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, chunk); err != nil {
					t.Fatalf("EncryptStream3x: %v", err)
				}
				var ptBuf bytes.Buffer
				if err := DecryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
					t.Fatalf("DecryptStream3x: %v", err)
				}
				if !bytes.Equal(pt, ptBuf.Bytes()) {
					t.Fatalf("512-bit Triple-stream round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})
}

// TestEncryptStream3xChunkSize1 exercises the worst-case chunk-size
// override of 1, which forces one full ITB container per plaintext
// byte. Only run on small payloads — the per-chunk fixed overhead
// dominates and even 32 bytes at chunkSize = 1 already emits 32
// distinct containers.
func TestEncryptStream3xChunkSize1(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
	pt := genTestPlaintext(t, 32)
	var ctBuf bytes.Buffer
	if err := EncryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, 1); err != nil {
		t.Fatalf("EncryptStream3xCfg(nil, chunkSize=1): %v", err)
	}
	var ptBuf bytes.Buffer
	if err := DecryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
		t.Fatalf("DecryptStream3x: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatalf("Triple chunkSize=1 round-trip mismatch")
	}
}

func TestEncryptStream3xSingleChunk(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
	pt := genTestPlaintext(t, 100)
	var ctBuf bytes.Buffer
	if err := EncryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, 4096); err != nil {
		t.Fatalf("EncryptStream3x: %v", err)
	}
	var ptBuf bytes.Buffer
	if err := DecryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
		t.Fatalf("DecryptStream3x: %v", err)
	}
	if !bytes.Equal(pt, ptBuf.Bytes()) {
		t.Fatalf("single-chunk round-trip mismatch")
	}
}

// TestEncryptStream3xWidthMixRejected confirms width-mix detection on
// the io.Reader / io.Writer Triple stream path. The width-less
// dispatch surfaces an error when the 8 seeds are not all the
// same width.
func TestEncryptStream3xWidthMixRejected(t *testing.T) {
	n128, l128, d128, _, _, s128, _, _ := mkTriple128(t)
	_, _, d256, _, _, _, _, _ := mkTriple256(t)
	pt := genTestPlaintext(t, 64)
	var ctBuf bytes.Buffer
	if err := EncryptStream3xCfg(nil, n128, l128, d128, d256, d128, s128, s128, s128, bytes.NewReader(pt), &ctBuf, 4096); err == nil {
		t.Fatalf("EncryptStream3xCfg(nil, mixed widths): want error, got nil")
	}
}

// --- Triple Ouroboros plain-stream Cfg helpers (per-chunk emit) ---
//
// The *3x{N}Cfg helpers in stream.go take a (data []byte, chunkSize
// int, emit func([]byte) error) signature instead of the high-level
// io.Reader / io.Writer pair. Round-trip the matrix by collecting
// emitted chunks into a byte slice on the encrypt side and feeding
// the concatenation into the matching decrypt Cfg helper.

func TestEncryptStream3xCfgRoundtrip128(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
	var cfg *Config
	pt := genTestPlaintext(t, 5000)

	var ct bytes.Buffer
	if err := EncryptStream3x128Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, pt, 1024, func(chunk []byte) error {
		ct.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("EncryptStream3x128Cfg: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatalf("EncryptStream3x128Cfg: emitted no bytes")
	}
	var dec bytes.Buffer
	if err := DecryptStream3x128Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, ct.Bytes(), func(chunk []byte) error {
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
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple256(t)
	var cfg *Config
	pt := genTestPlaintext(t, 5000)

	var ct bytes.Buffer
	if err := EncryptStream3x256Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, pt, 1024, func(chunk []byte) error {
		ct.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("EncryptStream3x256Cfg: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatalf("EncryptStream3x256Cfg: emitted no bytes")
	}
	var dec bytes.Buffer
	if err := DecryptStream3x256Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, ct.Bytes(), func(chunk []byte) error {
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
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple512(t)
	var cfg *Config
	pt := genTestPlaintext(t, 5000)

	var ct bytes.Buffer
	if err := EncryptStream3x512Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, pt, 1024, func(chunk []byte) error {
		ct.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("EncryptStream3x512Cfg: %v", err)
	}
	if ct.Len() == 0 {
		t.Fatalf("EncryptStream3x512Cfg: emitted no bytes")
	}
	var dec bytes.Buffer
	if err := DecryptStream3x512Cfg(cfg, n, l, d1, d2, d3, s1, s2, s3, ct.Bytes(), func(chunk []byte) error {
		dec.Write(chunk)
		return nil
	}); err != nil {
		t.Fatalf("DecryptStream3x512Cfg: %v", err)
	}
	if !bytes.Equal(pt, dec.Bytes()) {
		t.Fatalf("EncryptStream3x512Cfg round-trip mismatch")
	}
}

// --- Triple Ouroboros IO-Driven Cfg round-trip sweep ---
//
// The width-less [EncryptStream3xCfg] / [DecryptStream3xCfg] IO-Driven
// helpers accept a per-encryptor *Config so cfg.MaxWorkers /
// cfg.NonceBits / cfg.BarrierFill flow through the chunked path
// without touching the process globals. This sweep exercises every
// Triple width (128 / 256 / 512), every MaxWorkers cap {1, 2, 4, 8},
// and every chunk-boundary plaintext size {1, chunkSize-1,
// chunkSize, chunkSize+1, 1 MiB} at a modest chunkSize=4096 override,
// flat t.Run per combination.
func TestEncryptStream3xCfgRoundTripAllWidths(t *testing.T) {
	const chunk = 4096
	widths := []int{128, 256, 512}
	workers := []int{1, 2, 4, 8}
	sizes := []int{1, chunk - 1, chunk, chunk + 1, 1 << 20}

	for _, w := range widths {
		w := w
		for _, mw := range workers {
			mw := mw
			for _, sz := range sizes {
				sz := sz
				name := fmt.Sprintf("w%d/mw%d/sz%d", w, mw, sz)
				t.Run(name, func(t *testing.T) {
					cfg := &Config{MaxWorkers: mw}
					pt := genTestPlaintext(t, sz)
					var ctBuf bytes.Buffer
					switch w {
					case 128:
						n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
						if err := EncryptStream3xCfg(cfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, chunk); err != nil {
							t.Fatalf("EncryptStream3xCfg: %v", err)
						}
						var ptBuf bytes.Buffer
						if err := DecryptStream3xCfg(cfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
							t.Fatalf("DecryptStream3xCfg: %v", err)
						}
						if !bytes.Equal(pt, ptBuf.Bytes()) {
							t.Fatalf("128-bit Cfg round-trip mismatch at %d bytes", sz)
						}
					case 256:
						n, l, d1, d2, d3, s1, s2, s3 := mkTriple256(t)
						if err := EncryptStream3xCfg(cfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, chunk); err != nil {
							t.Fatalf("EncryptStream3xCfg: %v", err)
						}
						var ptBuf bytes.Buffer
						if err := DecryptStream3xCfg(cfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
							t.Fatalf("DecryptStream3xCfg: %v", err)
						}
						if !bytes.Equal(pt, ptBuf.Bytes()) {
							t.Fatalf("256-bit Cfg round-trip mismatch at %d bytes", sz)
						}
					case 512:
						n, l, d1, d2, d3, s1, s2, s3 := mkTriple512(t)
						if err := EncryptStream3xCfg(cfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &ctBuf, chunk); err != nil {
							t.Fatalf("EncryptStream3xCfg: %v", err)
						}
						var ptBuf bytes.Buffer
						if err := DecryptStream3xCfg(cfg, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(ctBuf.Bytes()), &ptBuf); err != nil {
							t.Fatalf("DecryptStream3xCfg: %v", err)
						}
						if !bytes.Equal(pt, ptBuf.Bytes()) {
							t.Fatalf("512-bit Cfg round-trip mismatch at %d bytes", sz)
						}
					}
				})
			}
		}
	}
}

// TestStreamNoMACChunkPrefixIgnored pins that the No MAC decoders read
// the 32-byte prefix ahead of every chunk and discard it: a multi-chunk
// transcript whose prefixes are all overwritten — with zeros, with
// 0xFF, or with each other's bytes — decodes to the same plaintext on
// both the User-Driven Loop and the IO-Driven decoder.
func TestStreamNoMACChunkPrefixIgnored(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
	pt := genTestPlaintext(t, 3*4096+77)
	var wire bytes.Buffer
	if err := EncryptStream3x128Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, pt, 4096, func(rec []byte) error {
		_, err := wire.Write(rec)
		return err
	}); err != nil {
		t.Fatalf("EncryptStream3x128Cfg: %v", err)
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
	if len(starts) != 4 {
		t.Fatalf("setup: %d records, want 4", len(starts))
	}
	for _, fill := range []string{"zero", "ff", "rotated"} {
		mod := bytes.Clone(full)
		for i, at := range starts {
			p := mod[at : at+streamIDPrefixLen]
			switch fill {
			case "zero":
				clear(p)
			case "ff":
				for j := range p {
					p[j] = 0xFF
				}
			case "rotated":
				src := starts[(i+1)%len(starts)]
				copy(p, full[src:src+streamIDPrefixLen])
			}
		}
		var cb bytes.Buffer
		if err := DecryptStream3x128Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, mod, func(c []byte) error {
			_, err := cb.Write(c)
			return err
		}); err != nil || !bytes.Equal(cb.Bytes(), pt) {
			t.Fatalf("%s prefixes, User-Driven Loop decoder: err=%v match=%v", fill, err, bytes.Equal(cb.Bytes(), pt))
		}
		var iob bytes.Buffer
		if err := DecryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(mod), &iob); err != nil || !bytes.Equal(iob.Bytes(), pt) {
			t.Fatalf("%s prefixes, IO-Driven decoder: err=%v match=%v", fill, err, bytes.Equal(iob.Bytes(), pt))
		}
	}
}

// TestStreamDecodeRecordBoundaries pins how the decoders treat the end
// of a transcript relative to the record grid, on both arms and both
// decoder shapes. A transcript that ends exactly on a record boundary
// decodes; one that ends inside a prefix, or right after a prefix with
// no chunk behind it, is rejected.
func TestStreamDecodeRecordBoundaries(t *testing.T) {
	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
	var key [32]byte
	for i := range key {
		key[i] = byte(i ^ 0x3C)
	}
	mac := macFuncForTest(key)
	pt := genTestPlaintext(t, 2*4096+5)

	var nomac, aead bytes.Buffer
	if err := EncryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &nomac, 4096); err != nil {
		t.Fatalf("EncryptStream3xCfg: %v", err)
	}
	if err := EncryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(pt), &aead, mac, 4096); err != nil {
		t.Fatalf("EncryptStreamAuth3xCfg: %v", err)
	}
	decode := map[string]func(wire []byte) error{
		"nomac/io": func(w []byte) error {
			var sink bytes.Buffer
			return DecryptStream3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(w), &sink)
		},
		"nomac/loop": func(w []byte) error {
			return DecryptStream3x128Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, w, func([]byte) error { return nil })
		},
		"aead/io": func(w []byte) error {
			var sink bytes.Buffer
			return DecryptStreamAuth3xCfg(nil, n, l, d1, d2, d3, s1, s2, s3, bytes.NewReader(w), &sink, mac)
		},
		"aead/loop": func(w []byte) error {
			return DecryptStreamAuth3x128Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, w, mac, func([]byte) error { return nil })
		},
	}
	for name, dec := range decode {
		full := nomac.Bytes()
		if name[:4] == "aead" {
			full = aead.Bytes()
		}
		if err := dec(full); err != nil {
			t.Fatalf("%s: exact transcript: %v", name, err)
		}
		dangling := append(bytes.Clone(full), full[:streamIDPrefixLen]...)
		if err := dec(dangling); err == nil {
			t.Fatalf("%s: accepted a prefix with no chunk behind it", name)
		}
		for _, cut := range []int{1, streamIDPrefixLen - 1} {
			partial := append(bytes.Clone(full), full[:cut]...)
			if err := dec(partial); err == nil {
				t.Fatalf("%s: accepted a %d-byte partial prefix at the end", name, cut)
			}
		}
	}
}
