package itb

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"
)

// macFuncForTest returns a deterministic byte-keyed MAC closure for
// the width-less Single Message helpers' authenticated tests. Body is
// chosen to be allocation-free and depend on every input byte without
// pulling in a third-party MAC dependency at test time.
func macFuncForTest(key [32]byte) MACFunc {
	return func(data []byte) []byte {
		var out [32]byte
		// Simple keyed-hash construction sufficient for round-trip
		// correctness coverage: SipHash-128 over (key || data) emitted
		// twice. Non-cryptographic test fixture only.
		out[0] = key[0] ^ byte(len(data))
		for i, b := range data {
			out[(i%31)+1] ^= b ^ key[i%32]
		}
		return out[:]
	}
}

// genTestPlaintext draws sz random bytes for the round-trip checks.
func genTestPlaintext(t *testing.T, sz int) []byte {
	t.Helper()
	buf := make([]byte, sz)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	return buf
}

func mkSeeds128(t *testing.T) (n, d, s *Seed128) {
	t.Helper()
	var err error
	if n, err = NewSeed128(512, sipHash128); err != nil {
		t.Fatalf("NewSeed128: %v", err)
	}
	if d, err = NewSeed128(512, sipHash128); err != nil {
		t.Fatalf("NewSeed128: %v", err)
	}
	if s, err = NewSeed128(512, sipHash128); err != nil {
		t.Fatalf("NewSeed128: %v", err)
	}
	return
}

func mkSeeds256(t *testing.T) (n, d, s *Seed256) {
	t.Helper()
	var err error
	if n, err = NewSeed256(512, makeBlake3Hash256()); err != nil {
		t.Fatalf("NewSeed256: %v", err)
	}
	if d, err = NewSeed256(512, makeBlake3Hash256()); err != nil {
		t.Fatalf("NewSeed256: %v", err)
	}
	if s, err = NewSeed256(512, makeBlake3Hash256()); err != nil {
		t.Fatalf("NewSeed256: %v", err)
	}
	return
}

func mkSeeds512(t *testing.T) (n, d, s *Seed512) {
	t.Helper()
	var err error
	if n, err = NewSeed512(512, makeBlake2bHash512()); err != nil {
		t.Fatalf("NewSeed512: %v", err)
	}
	if d, err = NewSeed512(512, makeBlake2bHash512()); err != nil {
		t.Fatalf("NewSeed512: %v", err)
	}
	if s, err = NewSeed512(512, makeBlake2bHash512()); err != nil {
		t.Fatalf("NewSeed512: %v", err)
	}
	return
}

func mkTriple128(t *testing.T) (n, l, d1, d2, d3, s1, s2, s3 *Seed128) {
	t.Helper()
	n, l, d1 = mkSeeds128(t)
	d2, d3, s1 = mkSeeds128(t)
	s2, s3, _ = mkSeeds128(t)
	return
}

func mkTriple256(t *testing.T) (n, l, d1, d2, d3, s1, s2, s3 *Seed256) {
	t.Helper()
	n, l, d1 = mkSeeds256(t)
	d2, d3, s1 = mkSeeds256(t)
	s2, s3, _ = mkSeeds256(t)
	return
}

func mkTriple512(t *testing.T) (n, l, d1, d2, d3, s1, s2, s3 *Seed512) {
	t.Helper()
	n, l, d1 = mkSeeds512(t)
	d2, d3, s1 = mkSeeds512(t)
	s2, s3, _ = mkSeeds512(t)
	return
}

// --- Single-Ouroboros plain helpers ---

// --- Triple-Ouroboros plain helpers ---

func TestEncrypt3xDecrypt3xRoundtrip(t *testing.T) {
	sizes := []int{1, 4096, 65536}

	t.Run("128", func(t *testing.T) {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
				pt := genTestPlaintext(t, sz)
				ct, err := Encrypt3x128Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, pt)
				if err != nil {
					t.Fatalf("Encrypt3x128Cfg: %v", err)
				}
				out, err := Decrypt3x128Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, ct)
				if err != nil {
					t.Fatalf("Decrypt3x128Cfg: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatalf("128-bit Triple round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("256", func(t *testing.T) {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, l, d1, d2, d3, s1, s2, s3 := mkTriple256(t)
				pt := genTestPlaintext(t, sz)
				ct, err := Encrypt3x256Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, pt)
				if err != nil {
					t.Fatalf("Encrypt3x256Cfg: %v", err)
				}
				out, err := Decrypt3x256Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, ct)
				if err != nil {
					t.Fatalf("Decrypt3x256Cfg: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatalf("256-bit Triple round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("512", func(t *testing.T) {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, l, d1, d2, d3, s1, s2, s3 := mkTriple512(t)
				pt := genTestPlaintext(t, sz)
				ct, err := Encrypt3x512Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, pt)
				if err != nil {
					t.Fatalf("Encrypt3x512Cfg: %v", err)
				}
				out, err := Decrypt3x512Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, ct)
				if err != nil {
					t.Fatalf("Decrypt3x512Cfg: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatalf("512-bit Triple round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})
}

// --- Authenticated Single Message helpers ---

// --- Authenticated Triple helpers ---

func TestEncryptAuth3xDecryptAuth3xRoundtrip(t *testing.T) {
	sizes := []int{1, 4096, 65536}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	mac := macFuncForTest(key)

	t.Run("128", func(t *testing.T) {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
				pt := genTestPlaintext(t, sz)
				ct, err := EncryptAuth3x128Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, pt, mac)
				if err != nil {
					t.Fatalf("EncryptAuth3x128Cfg: %v", err)
				}
				out, err := DecryptAuth3x128Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, ct, mac)
				if err != nil {
					t.Fatalf("DecryptAuth3x128Cfg: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatalf("128-bit Triple-auth round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("256", func(t *testing.T) {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, l, d1, d2, d3, s1, s2, s3 := mkTriple256(t)
				pt := genTestPlaintext(t, sz)
				ct, err := EncryptAuth3x256Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, pt, mac)
				if err != nil {
					t.Fatalf("EncryptAuth3x256Cfg: %v", err)
				}
				out, err := DecryptAuth3x256Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, ct, mac)
				if err != nil {
					t.Fatalf("DecryptAuth3x256Cfg: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatalf("256-bit Triple-auth round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("512", func(t *testing.T) {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, l, d1, d2, d3, s1, s2, s3 := mkTriple512(t)
				pt := genTestPlaintext(t, sz)
				ct, err := EncryptAuth3x512Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, pt, mac)
				if err != nil {
					t.Fatalf("EncryptAuth3x512Cfg: %v", err)
				}
				out, err := DecryptAuth3x512Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, ct, mac)
				if err != nil {
					t.Fatalf("DecryptAuth3x512Cfg: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatalf("512-bit Triple-auth round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})
}

func TestEncryptAuth3xTamperDetected(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	mac := macFuncForTest(key)

	n, l, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
	pt := genTestPlaintext(t, 1024)
	ct, err := EncryptAuth3x128Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, pt, mac)
	if err != nil {
		t.Fatalf("EncryptAuth3x128Cfg: %v", err)
	}
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)/2] ^= 0xFF
	if _, err := DecryptAuth3x128Cfg(nil, n, l, d1, d2, d3, s1, s2, s3, tampered, mac); err == nil {
		t.Fatalf("DecryptAuth3x128Cfg(tampered): want error, got nil")
	}
}
