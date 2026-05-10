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

func mkTriple128(t *testing.T) (n, d1, d2, d3, s1, s2, s3 *Seed128) {
	t.Helper()
	n, d1, _ = mkSeeds128(t)
	d2, d3, s1 = mkSeeds128(t)
	s2, s3, _ = mkSeeds128(t)
	return
}

func mkTriple256(t *testing.T) (n, d1, d2, d3, s1, s2, s3 *Seed256) {
	t.Helper()
	n, d1, _ = mkSeeds256(t)
	d2, d3, s1 = mkSeeds256(t)
	s2, s3, _ = mkSeeds256(t)
	return
}

func mkTriple512(t *testing.T) (n, d1, d2, d3, s1, s2, s3 *Seed512) {
	t.Helper()
	n, d1, _ = mkSeeds512(t)
	d2, d3, s1 = mkSeeds512(t)
	s2, s3, _ = mkSeeds512(t)
	return
}

// --- Single-Ouroboros plain helpers ---

func TestEncryptDecryptRoundtrip(t *testing.T) {
	sizes := []int{1, 4096, 65536}

	t.Run("128", func(t *testing.T) {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				ns, ds, ss := mkSeeds128(t)
				pt := genTestPlaintext(t, sz)
				ct, err := Encrypt(ns, ds, ss, pt)
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				out, err := Decrypt(ns, ds, ss, ct)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatalf("128-bit round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("256", func(t *testing.T) {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				ns, ds, ss := mkSeeds256(t)
				pt := genTestPlaintext(t, sz)
				ct, err := Encrypt(ns, ds, ss, pt)
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				out, err := Decrypt(ns, ds, ss, ct)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatalf("256-bit round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("512", func(t *testing.T) {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				ns, ds, ss := mkSeeds512(t)
				pt := genTestPlaintext(t, sz)
				ct, err := Encrypt(ns, ds, ss, pt)
				if err != nil {
					t.Fatalf("Encrypt: %v", err)
				}
				out, err := Decrypt(ns, ds, ss, ct)
				if err != nil {
					t.Fatalf("Decrypt: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatalf("512-bit round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})
}

// TestEncryptDispatchCrossDecrypt confirms that the width-less
// helpers and the width-suffixed implementations are
// interchangeable: a ciphertext produced by Encrypt decrypts cleanly
// through Decrypt128 / Decrypt256 / Decrypt512 and vice versa. Random
// CSPRNG fill in barrier pixels makes byte-identical ciphertext
// comparison infeasible without a deeper test seam, so cross-decrypt
// is the load-bearing dispatch-correctness check.
func TestEncryptDispatchCrossDecrypt(t *testing.T) {
	t.Run("128", func(t *testing.T) {
		ns, ds, ss := mkSeeds128(t)
		pt := genTestPlaintext(t, 4096)
		ctViaAny, err := Encrypt(ns, ds, ss, pt)
		if err != nil {
			t.Fatalf("Encrypt(any): %v", err)
		}
		out, err := Decrypt128(ns, ds, ss, ctViaAny)
		if err != nil {
			t.Fatalf("Decrypt128: %v", err)
		}
		if !bytes.Equal(pt, out) {
			t.Fatalf("128: any-encrypt -> suffixed-decrypt mismatch")
		}
		ctViaSuffixed, err := Encrypt128(ns, ds, ss, pt)
		if err != nil {
			t.Fatalf("Encrypt128: %v", err)
		}
		out2, err := Decrypt(ns, ds, ss, ctViaSuffixed)
		if err != nil {
			t.Fatalf("Decrypt(any): %v", err)
		}
		if !bytes.Equal(pt, out2) {
			t.Fatalf("128: suffixed-encrypt -> any-decrypt mismatch")
		}
	})

	t.Run("256", func(t *testing.T) {
		ns, ds, ss := mkSeeds256(t)
		pt := genTestPlaintext(t, 4096)
		ctViaAny, err := Encrypt(ns, ds, ss, pt)
		if err != nil {
			t.Fatalf("Encrypt(any): %v", err)
		}
		out, err := Decrypt256(ns, ds, ss, ctViaAny)
		if err != nil {
			t.Fatalf("Decrypt256: %v", err)
		}
		if !bytes.Equal(pt, out) {
			t.Fatalf("256: any-encrypt -> suffixed-decrypt mismatch")
		}
	})

	t.Run("512", func(t *testing.T) {
		ns, ds, ss := mkSeeds512(t)
		pt := genTestPlaintext(t, 4096)
		ctViaAny, err := Encrypt(ns, ds, ss, pt)
		if err != nil {
			t.Fatalf("Encrypt(any): %v", err)
		}
		out, err := Decrypt512(ns, ds, ss, ctViaAny)
		if err != nil {
			t.Fatalf("Decrypt512: %v", err)
		}
		if !bytes.Equal(pt, out) {
			t.Fatalf("512: any-encrypt -> suffixed-decrypt mismatch")
		}
	})
}

// TestEncryptWidthMixRejected asserts that mixing seed widths in a
// single call surfaces the documented seed-width-mix error.
func TestEncryptWidthMixRejected(t *testing.T) {
	n128, _, _ := mkSeeds128(t)
	_, d256, s256 := mkSeeds256(t)

	pt := genTestPlaintext(t, 64)
	if _, err := Encrypt(n128, d256, s256, pt); err == nil {
		t.Fatalf("Encrypt(mixed widths): want error, got nil")
	}
	if _, err := Decrypt(n128, d256, s256, pt); err == nil {
		t.Fatalf("Decrypt(mixed widths): want error, got nil")
	}
}

// TestEncryptEmptyPlaintextRejected confirms that empty plaintext is
// rejected at the underlying width-suffixed entry point and that the
// width-less wrapper surfaces the same error verbatim.
func TestEncryptEmptyPlaintextRejected(t *testing.T) {
	ns, ds, ss := mkSeeds128(t)
	if _, err := Encrypt(ns, ds, ss, nil); err == nil {
		t.Fatalf("Encrypt(empty): want error, got nil")
	}
	if _, err := Encrypt(ns, ds, ss, []byte{}); err == nil {
		t.Fatalf("Encrypt(empty): want error, got nil")
	}
}

// --- Triple-Ouroboros plain helpers ---

func TestEncrypt3xDecrypt3xRoundtrip(t *testing.T) {
	sizes := []int{1, 4096, 65536}

	t.Run("128", func(t *testing.T) {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				n, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
				pt := genTestPlaintext(t, sz)
				ct, err := Encrypt3x(n, d1, d2, d3, s1, s2, s3, pt)
				if err != nil {
					t.Fatalf("Encrypt3x: %v", err)
				}
				out, err := Decrypt3x(n, d1, d2, d3, s1, s2, s3, ct)
				if err != nil {
					t.Fatalf("Decrypt3x: %v", err)
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
				n, d1, d2, d3, s1, s2, s3 := mkTriple256(t)
				pt := genTestPlaintext(t, sz)
				ct, err := Encrypt3x(n, d1, d2, d3, s1, s2, s3, pt)
				if err != nil {
					t.Fatalf("Encrypt3x: %v", err)
				}
				out, err := Decrypt3x(n, d1, d2, d3, s1, s2, s3, ct)
				if err != nil {
					t.Fatalf("Decrypt3x: %v", err)
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
				n, d1, d2, d3, s1, s2, s3 := mkTriple512(t)
				pt := genTestPlaintext(t, sz)
				ct, err := Encrypt3x(n, d1, d2, d3, s1, s2, s3, pt)
				if err != nil {
					t.Fatalf("Encrypt3x: %v", err)
				}
				out, err := Decrypt3x(n, d1, d2, d3, s1, s2, s3, ct)
				if err != nil {
					t.Fatalf("Decrypt3x: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatalf("512-bit Triple round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})
}

func TestEncrypt3xWidthMixRejected(t *testing.T) {
	n128, d128, s128 := mkSeeds128(t)
	_, d256, _ := mkSeeds256(t)
	pt := genTestPlaintext(t, 64)
	// Mix the second data seed only — every other slot is *Seed128.
	if _, err := Encrypt3x(n128, d128, d256, d128, s128, s128, s128, pt); err == nil {
		t.Fatalf("Encrypt3x(mixed widths): want error, got nil")
	}
}

// --- Authenticated Single Message helpers ---

func TestEncryptAuthDecryptAuthRoundtrip(t *testing.T) {
	sizes := []int{1, 4096, 65536}
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	mac := macFuncForTest(key)

	t.Run("128", func(t *testing.T) {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				ns, ds, ss := mkSeeds128(t)
				pt := genTestPlaintext(t, sz)
				ct, err := EncryptAuth(ns, ds, ss, pt, mac)
				if err != nil {
					t.Fatalf("EncryptAuth: %v", err)
				}
				out, err := DecryptAuth(ns, ds, ss, ct, mac)
				if err != nil {
					t.Fatalf("DecryptAuth: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatalf("128-bit auth round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("256", func(t *testing.T) {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				ns, ds, ss := mkSeeds256(t)
				pt := genTestPlaintext(t, sz)
				ct, err := EncryptAuth(ns, ds, ss, pt, mac)
				if err != nil {
					t.Fatalf("EncryptAuth: %v", err)
				}
				out, err := DecryptAuth(ns, ds, ss, ct, mac)
				if err != nil {
					t.Fatalf("DecryptAuth: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatalf("256-bit auth round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})

	t.Run("512", func(t *testing.T) {
		for _, sz := range sizes {
			t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
				ns, ds, ss := mkSeeds512(t)
				pt := genTestPlaintext(t, sz)
				ct, err := EncryptAuth(ns, ds, ss, pt, mac)
				if err != nil {
					t.Fatalf("EncryptAuth: %v", err)
				}
				out, err := DecryptAuth(ns, ds, ss, ct, mac)
				if err != nil {
					t.Fatalf("DecryptAuth: %v", err)
				}
				if !bytes.Equal(pt, out) {
					t.Fatalf("512-bit auth round-trip mismatch at %d bytes", sz)
				}
			})
		}
	})
}

// TestEncryptAuthTamperDetected confirms the MAC verifier rejects a
// flipped ciphertext byte at the decrypt boundary.
func TestEncryptAuthTamperDetected(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("crypto/rand: %v", err)
	}
	mac := macFuncForTest(key)

	ns, ds, ss := mkSeeds128(t)
	pt := genTestPlaintext(t, 1024)
	ct, err := EncryptAuth(ns, ds, ss, pt, mac)
	if err != nil {
		t.Fatalf("EncryptAuth: %v", err)
	}
	// Flip a byte in the body (past the header).
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)/2] ^= 0xFF
	if _, err := DecryptAuth(ns, ds, ss, tampered, mac); err == nil {
		t.Fatalf("DecryptAuth(tampered): want error, got nil")
	}
}

func TestEncryptAuthWidthMixRejected(t *testing.T) {
	var key [32]byte
	mac := macFuncForTest(key)

	n128, _, _ := mkSeeds128(t)
	_, d256, s256 := mkSeeds256(t)
	pt := genTestPlaintext(t, 64)
	if _, err := EncryptAuth(n128, d256, s256, pt, mac); err == nil {
		t.Fatalf("EncryptAuth(mixed widths): want error, got nil")
	}
	if _, err := DecryptAuth(n128, d256, s256, pt, mac); err == nil {
		t.Fatalf("DecryptAuth(mixed widths): want error, got nil")
	}
}

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
				n, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
				pt := genTestPlaintext(t, sz)
				ct, err := EncryptAuth3x(n, d1, d2, d3, s1, s2, s3, pt, mac)
				if err != nil {
					t.Fatalf("EncryptAuth3x: %v", err)
				}
				out, err := DecryptAuth3x(n, d1, d2, d3, s1, s2, s3, ct, mac)
				if err != nil {
					t.Fatalf("DecryptAuth3x: %v", err)
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
				n, d1, d2, d3, s1, s2, s3 := mkTriple256(t)
				pt := genTestPlaintext(t, sz)
				ct, err := EncryptAuth3x(n, d1, d2, d3, s1, s2, s3, pt, mac)
				if err != nil {
					t.Fatalf("EncryptAuth3x: %v", err)
				}
				out, err := DecryptAuth3x(n, d1, d2, d3, s1, s2, s3, ct, mac)
				if err != nil {
					t.Fatalf("DecryptAuth3x: %v", err)
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
				n, d1, d2, d3, s1, s2, s3 := mkTriple512(t)
				pt := genTestPlaintext(t, sz)
				ct, err := EncryptAuth3x(n, d1, d2, d3, s1, s2, s3, pt, mac)
				if err != nil {
					t.Fatalf("EncryptAuth3x: %v", err)
				}
				out, err := DecryptAuth3x(n, d1, d2, d3, s1, s2, s3, ct, mac)
				if err != nil {
					t.Fatalf("DecryptAuth3x: %v", err)
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

	n, d1, d2, d3, s1, s2, s3 := mkTriple128(t)
	pt := genTestPlaintext(t, 1024)
	ct, err := EncryptAuth3x(n, d1, d2, d3, s1, s2, s3, pt, mac)
	if err != nil {
		t.Fatalf("EncryptAuth3x: %v", err)
	}
	tampered := append([]byte(nil), ct...)
	tampered[len(tampered)/2] ^= 0xFF
	if _, err := DecryptAuth3x(n, d1, d2, d3, s1, s2, s3, tampered, mac); err == nil {
		t.Fatalf("DecryptAuth3x(tampered): want error, got nil")
	}
}
