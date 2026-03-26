package itb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"testing"
	"unsafe"

	"github.com/dchest/siphash"
	"github.com/zeebo/blake3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"
)

func TestMain(m *testing.M) {
	SetMaxWorkers(8)
	os.Exit(m.Run())
}

// noescape hides a pointer from escape analysis. The Go runtime uses
// this trick internally. Safe when the callee does not retain the pointer.
//
//go:nosplit
func noescape(p unsafe.Pointer) unsafe.Pointer {
	x := uintptr(p)
	return unsafe.Pointer(x ^ 0)
}

// aesEncryptNoescape calls block.Encrypt without escaping src/dst to heap.
// Safe because cipher.Block.Encrypt is documented to not retain slice references.
func aesEncryptNoescape(block cipher.Block, buf *[16]byte) {
	dst := (*[16]byte)(noescape(unsafe.Pointer(buf)))
	block.Encrypt(dst[:], dst[:])
}

// --- Helpers ---

func makeTripleSeed128(bits int, h HashFunc128) (noise, data, start *Seed128) {
	noise, _ = NewSeed128(bits, h)
	data, _ = NewSeed128(bits, h)
	start, _ = NewSeed128(bits, h)
	return
}

func makeTripleSeed256(bits int, h HashFunc256) (noise, data, start *Seed256) {
	noise, _ = NewSeed256(bits, h)
	data, _ = NewSeed256(bits, h)
	start, _ = NewSeed256(bits, h)
	return
}

func generateData(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// --- Correctness tests ---

func TestRoundtrip(t *testing.T) {
	sizes := []int{1, 10, 64, 256, 1024, 4096, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed128(512, sipHash128)
			data := generateData(sz)
			encrypted, err := Encrypt128(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt128(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("data mismatch: got %d bytes, want %d", len(decrypted), len(data))
			}
		})
	}
}

func TestBinarySafety(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	data := []byte{0x00, 0x01, 0x00, 0x00, 0xFF, 0x00, 0xAB, 0x00, 0x00}
	encrypted, err := Encrypt128(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt128(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatalf("data mismatch")
	}
}

func TestWrongSeed(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	data := []byte("secret message for wrong seed test")
	encrypted, err := Encrypt128(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong seeds — may return error OR garbage data (oracle-free deniability)
	wns, wds, wss := makeTripleSeed128(512, sipHash128)
	decrypted, err := Decrypt128(wns, wds, wss, encrypted)
	if err != nil {
		return // expected
	}
	if bytes.Equal(data, decrypted) {
		t.Fatal("wrong seed produced correct plaintext")
	}
}

func TestNonceUniqueness(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	data := []byte("same data, different nonce")
	enc1, _ := Encrypt128(ns, ds, ss, data)
	enc2, _ := Encrypt128(ns, ds, ss, data)
	if bytes.Equal(enc1[:currentNonceSize()], enc2[:currentNonceSize()]) {
		t.Fatal("two encryptions produced identical nonces")
	}
}

func TestSeedFromComponents(t *testing.T) {
	ns, _ := SeedFromComponents128(sipHash128,
		0xdeadbeef01234567, 0x0123456789abcdef,
		0xfedcba9876543210, 0x1111111111111111,
		0x2222222222222222, 0x3333333333333333,
		0x4444444444444444, 0x5555555555555555,
	)
	ds, _ := NewSeed128(512, sipHash128)
	ss, _ := NewSeed128(512, sipHash128)
	data := generateData(1024)
	encrypted, err := Encrypt128(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt128(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch")
	}
}

func TestContainerSizes(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	sizes := []int{1, 10, 100, 1000, 10000, 100000}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			data := generateData(sz)
			encrypted, err := Encrypt128(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt128(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatal("data mismatch")
			}
			containerSize := len(encrypted) - headerSize()
			pixels := containerSize / Channels
			capacity := (pixels * DataBitsPerPixel) / 8
			t.Logf("container: %d pixels, capacity: %d bytes, output: %d bytes", pixels, capacity, len(encrypted))
		})
	}
}

func TestKeySizes(t *testing.T) {
	keySizes := []int{512, 1024}
	data := generateData(256)
	for _, bits := range keySizes {
		t.Run(fmt.Sprintf("%d-bit", bits), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed128(bits, sipHash128)
			encrypted, err := Encrypt128(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt128(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatal("data mismatch")
			}
		})
	}
}

func TestEmptyData(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	_, err := Encrypt128(ns, ds, ss, []byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestSingleByte(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	data := []byte{0x42}
	encrypted, err := Encrypt128(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt128(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch")
	}
}

// --- Edge case tests ---

func TestSingleZeroByte(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	data := []byte{0x00}
	encrypted, err := Encrypt128(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt128(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch for single 0x00 byte")
	}
}

func TestAllZeroBytes(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	data := make([]byte, 256) // 256 zero bytes
	encrypted, err := Encrypt128(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt128(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch for all-zero data")
	}
}

func TestAllFFBytes(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	data := bytes.Repeat([]byte{0xFF}, 256)
	encrypted, err := Encrypt128(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt128(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch for all-0xFF data")
	}
}

func TestExactMinContainer(t *testing.T) {
	// Data that fits exactly in minimum container (147 pixels for 1024-bit seed)
	// 147 pixels × 56 data bits = 8232 bits = 1029 bytes capacity
	// COBS overhead ~0.4%, so ~1025 bytes of plaintext
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	data := generateData(560)
	encrypted, err := Encrypt128(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt128(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch at min container boundary")
	}
}

func TestPixelBoundary(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	// Test sizes around pixel boundaries (56 bits = 7 bytes per pixel)
	for _, sz := range []int{6, 7, 8, 13, 14, 15, 55, 56, 57} {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			data := generateData(sz)
			encrypted, err := Encrypt128(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt128(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("data mismatch at %d bytes", sz)
			}
		})
	}
}

func TestTripleSeedIndependence(t *testing.T) {
	// Three different seeds must produce valid encrypt/decrypt.
	// Use 16MB data to ensure very large container (~2.4M pixels),
	// minimizing startPixel collision probability to ~1/2400000.
	//
	// Note: startSeed only controls startPixel = ChainHash(...) mod totalPixels.
	// Two different startSeeds can theoretically produce the same startPixel,
	// in which case decryption with the wrong startSeed will succeed.
	// This is expected behavior (oracle-free deniability), not a bug.
	// Larger data = larger container = lower collision probability.
	noiseSeed, _ := NewSeed128(512, sipHash128)
	dataSeed, _ := NewSeed128(512, sipHash128)
	startSeed, _ := NewSeed128(512, sipHash128)
	data := generateData(16 << 20)

	encrypted, err := Encrypt128(noiseSeed, dataSeed, startSeed, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt128(noiseSeed, dataSeed, startSeed, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch with independent triple seeds")
	}

	// Wrong seed: may return error OR garbage data (oracle-free deniability).
	// If decryption "succeeds", the output must NOT match original plaintext.
	wrongSeed, _ := NewSeed128(512, sipHash128)

	if dec, err := Decrypt128(wrongSeed, dataSeed, startSeed, encrypted); err == nil {
		if bytes.Equal(data, dec) {
			t.Fatal("wrong noiseSeed produced correct plaintext")
		}
	}

	if dec, err := Decrypt128(noiseSeed, wrongSeed, startSeed, encrypted); err == nil {
		if bytes.Equal(data, dec) {
			t.Fatal("wrong dataSeed produced correct plaintext")
		}
	}

	if dec, err := Decrypt128(noiseSeed, dataSeed, wrongSeed, encrypted); err == nil {
		if bytes.Equal(data, dec) {
			t.Fatal("wrong startSeed produced correct plaintext")
		}
	}
}

func TestMaxKeySize(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(1024, sipHash128)
	data := generateData(1024)
	encrypted, err := Encrypt128(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt128(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch with 1024-bit key")
	}
}

func TestMaxDataSize64MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 64 MB roundtrip in short mode")
	}
	ns, ds, ss := makeTripleSeed128(1024, sipHash128)
	data := make([]byte, 64<<20) // 64 MB
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	encrypted, err := Encrypt128(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt128(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("64 MB roundtrip data mismatch")
	}
}

func TestNonceBits(t *testing.T) {
	for _, nonceBits := range []int{128, 256, 512} {
		t.Run(fmt.Sprintf("%dbit", nonceBits), func(t *testing.T) {
			SetNonceBits(nonceBits)
			defer SetNonceBits(128)

			if got := GetNonceBits(); got != nonceBits {
				t.Fatalf("GetNonceBits() = %d, want %d", got, nonceBits)
			}

			// SipHash 128-bit roundtrip
			ns, ds, ss := makeTripleSeed128(1024, sipHash128)
			data := generateData(1 << 20) // 1 MB
			encrypted, err := Encrypt128(ns, ds, ss, data)
			if err != nil {
				t.Fatalf("Encrypt128: %v", err)
			}
			decrypted, err := Decrypt128(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatalf("Decrypt128: %v", err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatal("SipHash roundtrip mismatch")
			}

			// BLAKE3 256-bit roundtrip
			ns2, ds2, ss2 := makeTripleSeed256(512, makeBlake3Hash256())
			encrypted2, err := Encrypt256(ns2, ds2, ss2, data)
			if err != nil {
				t.Fatalf("Encrypt256: %v", err)
			}
			decrypted2, err := Decrypt256(ns2, ds2, ss2, encrypted2)
			if err != nil {
				t.Fatalf("Decrypt256: %v", err)
			}
			if !bytes.Equal(data, decrypted2) {
				t.Fatal("BLAKE3 roundtrip mismatch")
			}

			// BLAKE2b-512 roundtrip
			ns5, ds5, ss5 := makeTripleSeed512(512, makeBlake2bHash512())
			encrypted5, err := Encrypt512(ns5, ds5, ss5, data)
			if err != nil {
				t.Fatalf("Encrypt512: %v", err)
			}
			decrypted5, err := Decrypt512(ns5, ds5, ss5, encrypted5)
			if err != nil {
				t.Fatalf("Decrypt512: %v", err)
			}
			if !bytes.Equal(data, decrypted5) {
				t.Fatal("BLAKE2b-512 roundtrip mismatch")
			}

			// AES 128-bit roundtrip
			aesHash := makeAESHash128()
			ns3, ds3, ss3 := makeTripleSeed128(1024, aesHash)
			encrypted3, err := Encrypt128(ns3, ds3, ss3, data)
			if err != nil {
				t.Fatalf("AES Encrypt128: %v", err)
			}
			decrypted3, err := Decrypt128(ns3, ds3, ss3, encrypted3)
			if err != nil {
				t.Fatalf("AES Decrypt128: %v", err)
			}
			if !bytes.Equal(data, decrypted3) {
				t.Fatal("AES roundtrip mismatch")
			}

			t.Logf("nonce=%d bits: SipHash ✓ BLAKE3 ✓ BLAKE2b-512 ✓ AES ✓ (1 MB each)", nonceBits)
		})
	}
}

func TestSetNonceBitsPanic(t *testing.T) {
	for _, invalid := range []int{0, 64, 137, 1024, -1} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("SetNonceBits(%d) should panic", invalid)
				}
			}()
			SetNonceBits(invalid)
		}()
	}
}

func TestMinPixelsAmbiguityDominance(t *testing.T) {
	// Verify MinPixels (56^P) and MinPixelsAuth (7^P) exceed key space
	for _, bits := range []int{512, 1024, 2048} {
		ns, _, _ := makeTripleSeed128(bits, sipHash128)

		mp := ns.MinPixels()
		mpa := ns.MinPixelsAuth()

		// 56^MinPixels > 2^bits: MinPixels * log2(56) > bits
		ambiguity56 := float64(mp) * 5.8074
		if ambiguity56 <= float64(bits) {
			t.Errorf("MinPixels(%d) = %d: 56^P = 2^%.0f does NOT exceed 2^%d", bits, mp, ambiguity56, bits)
		}

		// 7^MinPixelsAuth > 2^bits: MinPixelsAuth * log2(7) > bits
		ambiguity7 := float64(mpa) * 2.8074
		if ambiguity7 <= float64(bits) {
			t.Errorf("MinPixelsAuth(%d) = %d: 7^P = 2^%.0f does NOT exceed 2^%d", bits, mpa, ambiguity7, bits)
		}

		// Auth must be larger than regular
		if mpa <= mp {
			t.Errorf("MinPixelsAuth(%d) = %d should be > MinPixels(%d) = %d", bits, mpa, bits, mp)
		}

		t.Logf("%d-bit: MinPixels=%d (56^P=2^%.0f), MinPixelsAuth=%d (7^P=2^%.0f)", bits, mp, ambiguity56, mpa, ambiguity7)
	}
}

func TestSetMaxWorkers(t *testing.T) {
	SetMaxWorkers(4)
	if got := GetMaxWorkers(); got != 4 {
		t.Fatalf("GetMaxWorkers() = %d, want 4", got)
	}

	// Clamp to 1
	SetMaxWorkers(0)
	if got := GetMaxWorkers(); got != 1 {
		t.Fatalf("GetMaxWorkers() after SetMaxWorkers(0) = %d, want 1", got)
	}
	SetMaxWorkers(-5)
	if got := GetMaxWorkers(); got != 1 {
		t.Fatalf("GetMaxWorkers() after SetMaxWorkers(-5) = %d, want 1", got)
	}

	// Clamp to 256
	SetMaxWorkers(1000)
	if got := GetMaxWorkers(); got != 256 {
		t.Fatalf("GetMaxWorkers() after SetMaxWorkers(1000) = %d, want 256", got)
	}

	// Restore global default for other tests
	SetMaxWorkers(8)
}

func TestSetBarrierFill(t *testing.T) {
	// Valid values
	for _, v := range []int{1, 2, 4, 8, 16, 32} {
		SetBarrierFill(v)
		if got := GetBarrierFill(); got != v {
			t.Fatalf("GetBarrierFill() = %d, want %d", got, v)
		}
	}

	// Invalid values must panic
	for _, invalid := range []int{0, 3, 5, 7, 9, 15, 33, 64, -1} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("SetBarrierFill(%d) should panic", invalid)
				}
			}()
			SetBarrierFill(invalid)
		}()
	}

	// Restore default
	SetBarrierFill(1)
}

func TestBarrierFill32_64MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 64 MB + BarrierFill(32) in short mode")
	}
	SetBarrierFill(32)
	SetMaxWorkers(8)
	defer func() {
		SetBarrierFill(1)
		SetMaxWorkers(8)
	}()

	ns, ds, ss := makeTripleSeed128(1024, sipHash128)
	data := make([]byte, 64<<20) // 64 MB
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	encrypted, err := Encrypt128(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt128(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("64 MB + BarrierFill(32) roundtrip data mismatch")
	}
}

func TestMaxDataSizeExceeded(t *testing.T) {
	t.Run("Encrypt128", func(t *testing.T) {
		ns, ds, ss := makeTripleSeed128(1024, sipHash128)
		if _, err := Encrypt128(ns, ds, ss, make([]byte, 64<<20+1)); err == nil {
			t.Fatal("expected error for 64 MB + 1 byte")
		}
		if _, err := Encrypt128(ns, ds, ss, make([]byte, 80<<20)); err == nil {
			t.Fatal("expected error for 80 MB")
		}
		if _, err := Encrypt128(ns, ds, ss, make([]byte, 16<<20)); err != nil {
			t.Fatalf("16 MB should succeed: %v", err)
		}
	})

	t.Run("Encrypt256", func(t *testing.T) {
		ns, ds, ss := makeTripleSeed256(512, makeBlake2bHash256())
		if _, err := Encrypt256(ns, ds, ss, make([]byte, 64<<20+1)); err == nil {
			t.Fatal("expected error for 64 MB + 1 byte")
		}
		if _, err := Encrypt256(ns, ds, ss, make([]byte, 80<<20)); err == nil {
			t.Fatal("expected error for 80 MB")
		}
		if _, err := Encrypt256(ns, ds, ss, make([]byte, 16<<20)); err != nil {
			t.Fatalf("16 MB should succeed: %v", err)
		}
	})

	t.Run("Encrypt512", func(t *testing.T) {
		ns, ds, ss := makeTripleSeed512(512, makeBlake2bHash512())
		if _, err := Encrypt512(ns, ds, ss, make([]byte, 64<<20+1)); err == nil {
			t.Fatal("expected error for 64 MB + 1 byte")
		}
		if _, err := Encrypt512(ns, ds, ss, make([]byte, 80<<20)); err == nil {
			t.Fatal("expected error for 80 MB")
		}
		if _, err := Encrypt512(ns, ds, ss, make([]byte, 16<<20)); err != nil {
			t.Fatalf("16 MB should succeed: %v", err)
		}
	})

	t.Run("EncryptAuthenticated128", func(t *testing.T) {
		ns, ds, ss := makeTripleSeed128(1024, sipHash128)
		if _, err := EncryptAuthenticated128(ns, ds, ss, make([]byte, 64<<20+1), simpleMACFunc); err == nil {
			t.Fatal("expected error for 64 MB + 1 byte")
		}
		if _, err := EncryptAuthenticated128(ns, ds, ss, make([]byte, 80<<20), simpleMACFunc); err == nil {
			t.Fatal("expected error for 80 MB")
		}
	})

	t.Run("EncryptAuthenticated256", func(t *testing.T) {
		ns, ds, ss := makeTripleSeed256(512, makeBlake2bHash256())
		if _, err := EncryptAuthenticated256(ns, ds, ss, make([]byte, 64<<20+1), simpleMACFunc); err == nil {
			t.Fatal("expected error for 64 MB + 1 byte")
		}
		if _, err := EncryptAuthenticated256(ns, ds, ss, make([]byte, 80<<20), simpleMACFunc); err == nil {
			t.Fatal("expected error for 80 MB")
		}
	})

	t.Run("EncryptAuthenticated512", func(t *testing.T) {
		ns, ds, ss := makeTripleSeed512(512, makeBlake2bHash512())
		if _, err := EncryptAuthenticated512(ns, ds, ss, make([]byte, 64<<20+1), simpleMACFunc); err == nil {
			t.Fatal("expected error for 64 MB + 1 byte")
		}
		if _, err := EncryptAuthenticated512(ns, ds, ss, make([]byte, 80<<20), simpleMACFunc); err == nil {
			t.Fatal("expected error for 80 MB")
		}
	})

	t.Run("EncryptStream128", func(t *testing.T) {
		ns, ds, ss := makeTripleSeed128(1024, sipHash128)
		err := EncryptStream128(ns, ds, ss, make([]byte, 1024), 80<<20, func([]byte) error { return nil })
		if err == nil {
			t.Fatal("expected error for chunk size 80 MB")
		}
	})

	t.Run("EncryptStream256", func(t *testing.T) {
		ns, ds, ss := makeTripleSeed256(512, makeBlake2bHash256())
		err := EncryptStream256(ns, ds, ss, make([]byte, 1024), 80<<20, func([]byte) error { return nil })
		if err == nil {
			t.Fatal("expected error for chunk size 80 MB")
		}
	})

	t.Run("EncryptStream512", func(t *testing.T) {
		ns, ds, ss := makeTripleSeed512(512, makeBlake2bHash512())
		err := EncryptStream512(ns, ds, ss, make([]byte, 1024), 80<<20, func([]byte) error { return nil })
		if err == nil {
			t.Fatal("expected error for chunk size 80 MB")
		}
	})
}

func TestDecryptRejectOversizeContainer(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(1024, sipHash128)

	// Craft a fake container with dimensions that exceed maxTotalPixels (10M).
	// 3200x3200 = 10,240,000 pixels > 10M limit.
	header := make([]byte, headerSize()+Channels) // nonce + dimensions
	nonceSz := currentNonceSize()
	binary.BigEndian.PutUint16(header[nonceSz:], 3200)
	binary.BigEndian.PutUint16(header[nonceSz+2:], 3200)
	fakeContainer := make([]byte, len(header)+3200*3200*8)
	copy(fakeContainer, header)

	_, err := Decrypt128(ns, ds, ss, fakeContainer)
	if err == nil {
		t.Fatal("expected error for oversized container (3200x3200 > 10M pixels)")
	}
}

func TestInvalidSeedSize(t *testing.T) {
	// Below minimum
	_, err := NewSeed128(256, sipHash128)
	if err == nil {
		t.Fatal("expected error for 256-bit seed (below 512 minimum)")
	}

	// Above maximum
	_, err = NewSeed128(4096, sipHash128)
	if err == nil {
		t.Fatal("expected error for 4096-bit seed (above 2048 maximum)")
	}

	// Not multiple of 128
	_, err = NewSeed128(500, sipHash128)
	if err == nil {
		t.Fatal("expected error for non-128-multiple seed")
	}

	// Nil hash
	_, err = NewSeed128(512, nil)
	if err == nil {
		t.Fatal("expected error for nil hashFunc")
	}
}

func TestSeedFromComponentsValidation(t *testing.T) {
	// Too few components
	_, err := SeedFromComponents128(sipHash128, 1, 2, 3)
	if err == nil {
		t.Fatal("expected error for 3 components (below 8 minimum)")
	}

	// Nil hash
	_, err = SeedFromComponents128(nil, 1, 2, 3, 4, 5, 6, 7, 8)
	if err == nil {
		t.Fatal("expected error for nil hashFunc")
	}
}

func TestTripleSeedIsolationValidation(t *testing.T) {
	s1, _ := NewSeed128(512, sipHash128)
	s2, _ := NewSeed128(512, sipHash128)
	data := []byte("test")

	// Same noiseSeed and dataSeed
	if _, err := Encrypt128(s1, s1, s2, data); err == nil {
		t.Fatal("expected error when noiseSeed == dataSeed")
	}
	// Same noiseSeed and startSeed
	if _, err := Encrypt128(s1, s2, s1, data); err == nil {
		t.Fatal("expected error when noiseSeed == startSeed")
	}
	// Same dataSeed and startSeed
	if _, err := Encrypt128(s2, s1, s1, data); err == nil {
		t.Fatal("expected error when dataSeed == startSeed")
	}
	// All three same
	if _, err := Encrypt128(s1, s1, s1, data); err == nil {
		t.Fatal("expected error when all seeds same")
	}
}

func TestCorruptedContainer(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	data := generateData(256)

	encrypted, err := Encrypt128(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}

	// Truncated container
	_, err = Decrypt128(ns, ds, ss, encrypted[:headerSize()+1])
	if err == nil {
		t.Fatal("expected error for truncated container")
	}

	// Too short
	_, err = Decrypt128(ns, ds, ss, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}

	// Zero dimensions
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[currentNonceSize()] = 0
	corrupted[currentNonceSize()+1] = 0
	corrupted[currentNonceSize()+2] = 0
	corrupted[currentNonceSize()+3] = 0
	_, err = Decrypt128(ns, ds, ss, corrupted)
	if err == nil {
		t.Fatal("expected error for zero dimensions")
	}
}

// --- Authenticated encryption tests ---

// simpleMACFunc returns a simple MAC function for testing.
// NOT cryptographically secure — for testing only.
func simpleMACFunc(data []byte) []byte {
	h := uint64(0x736f6d6570736575)
	for _, b := range data {
		h = h*131 + uint64(b)
	}
	tag := make([]byte, 8)
	for i := range tag {
		tag[i] = byte(h >> (i * 8))
	}
	return tag
}

func TestAuthenticatedRoundtrip(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	data := generateData(1024)

	encrypted, err := EncryptAuthenticated128(ns, ds, ss, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptAuthenticated128(ns, ds, ss, encrypted, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch")
	}
}

func TestAuthenticatedTamperDetection(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)

	// Use large data to fill most of the container capacity,
	// minimizing the padding region where undetectable modifications
	// are expected (noise/padding bits don't affect the message).
	data := generateData(4096)

	encrypted, err := EncryptAuthenticated128(ns, ds, ss, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}

	// Flip ALL bits in every container byte. With noise at any position
	// 0-7 (from noiseSeed), no single bit position is guaranteed data.
	// Flipping all 8 bits guarantees data corruption regardless of
	// noise position.
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	for i := headerSize(); i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}

	_, err = DecryptAuthenticated128(ns, ds, ss, tampered, simpleMACFunc)
	if err == nil {
		t.Fatal("expected MAC verification failure on tampered data")
	}
}

func TestAuthenticatedWrongSeed(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	data := []byte("authenticated wrong seed test")

	encrypted, err := EncryptAuthenticated128(ns, ds, ss, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong seeds — must fail MAC verification or produce garbage
	wns, wds, wss := makeTripleSeed128(512, sipHash128)
	_, err = DecryptAuthenticated128(wns, wds, wss, encrypted, simpleMACFunc)
	if err == nil {
		t.Fatal("expected error with wrong seed")
	}
}

// --- 128-bit hash tests ---

// makeAESHash128 creates a HashFunc128 with a pre-cached AES cipher.
// The AES key is fixed per seed (created once), seed components are
// XOR'd into the plaintext. This avoids key schedule on every call.
// Each of the 3 seeds gets its own closure with its own AES key.
// Zero allocations per call — all state on stack.
func makeAESHash128() HashFunc128 {
	var aesKey [16]byte
	if _, err := rand.Read(aesKey[:]); err != nil {
		panic(err)
	}
	block, _ := aes.NewCipher(aesKey[:])

	return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
		// Block 1: XOR seed into first 16 bytes of data, encrypt.
		// Input is always 20 bytes (4-byte counter + 16-byte nonce).
		var b1 [16]byte
		if len(data) >= 16 {
			_ = data[15]
			b1[0] = data[0] ^ byte(seed0)
			b1[1] = data[1] ^ byte(seed0>>8)
			b1[2] = data[2] ^ byte(seed0>>16)
			b1[3] = data[3] ^ byte(seed0>>24)
			b1[4] = data[4] ^ byte(seed0>>32)
			b1[5] = data[5] ^ byte(seed0>>40)
			b1[6] = data[6] ^ byte(seed0>>48)
			b1[7] = data[7] ^ byte(seed0>>56)
			b1[8] = data[8] ^ byte(seed1)
			b1[9] = data[9] ^ byte(seed1>>8)
			b1[10] = data[10] ^ byte(seed1>>16)
			b1[11] = data[11] ^ byte(seed1>>24)
			b1[12] = data[12] ^ byte(seed1>>32)
			b1[13] = data[13] ^ byte(seed1>>40)
			b1[14] = data[14] ^ byte(seed1>>48)
			b1[15] = data[15] ^ byte(seed1>>56)
		}
		aesEncryptNoescape(block, &b1)

		// Remaining blocks: XOR 16-byte chunks into state, encrypt each.
		for off := 16; off < len(data); off += 16 {
			end := off + 16
			if end > len(data) {
				end = len(data)
			}
			for j := off; j < end; j++ {
				b1[j-off] ^= data[j]
			}
			aesEncryptNoescape(block, &b1)
		}

		return binary.LittleEndian.Uint64(b1[:8]), binary.LittleEndian.Uint64(b1[8:])
	}
}

func TestRoundtrip128(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed128(512, sipHash128)
			data := generateData(sz)
			encrypted, err := Encrypt128(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt128(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("128-bit: data mismatch at %d bytes", sz)
			}
		})
	}
}

func TestRoundtrip128_1024bit(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(1024, sipHash128)
	data := generateData(4096)
	encrypted, err := Encrypt128(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt128(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("128-bit 1024-key: data mismatch")
	}
}

func TestAuthenticated128(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	data := generateData(1024)
	encrypted, err := EncryptAuthenticated128(ns, ds, ss, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptAuthenticated128(ns, ds, ss, encrypted, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("128-bit authenticated: data mismatch")
	}
}

// --- 256-bit hash tests ---

// testHash256 wraps SipHash-2-4 into a 256-bit interface for testing.
func testHash256(data []byte, seed [4]uint64) [4]uint64 {
	lo0, hi0 := siphash.Hash128(seed[0], seed[1], data)
	lo1, hi1 := siphash.Hash128(seed[2], seed[3], data)
	return [4]uint64{lo0, hi0, lo1, hi1}
}

func TestRoundtrip256(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed256(512, testHash256)
			data := generateData(sz)
			encrypted, err := Encrypt256(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt256(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("256-bit: data mismatch at %d bytes", sz)
			}
		})
	}
}

func TestRoundtrip256_2048bit(t *testing.T) {
	ns, ds, ss := makeTripleSeed256(2048, testHash256)
	data := generateData(4096)
	encrypted, err := Encrypt256(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt256(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("256-bit 2048-key: data mismatch")
	}
}

func TestAuthenticated256(t *testing.T) {
	ns, ds, ss := makeTripleSeed256(512, testHash256)
	data := generateData(1024)
	encrypted, err := EncryptAuthenticated256(ns, ds, ss, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptAuthenticated256(ns, ds, ss, encrypted, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("256-bit authenticated: data mismatch")
	}
}

func TestSeed128Validation(t *testing.T) {
	_, err := NewSeed128(256, sipHash128)
	if err == nil {
		t.Fatal("expected error for 256-bit seed128")
	}
	_, err = NewSeed128(600, sipHash128)
	if err == nil {
		t.Fatal("expected error for non-128-multiple")
	}
	_, err = NewSeed128(512, nil)
	if err == nil {
		t.Fatal("expected error for nil hash")
	}
}

func TestSeed256Validation(t *testing.T) {
	_, err := NewSeed256(256, testHash256)
	if err == nil {
		t.Fatal("expected error for 256-bit seed256 (below 512)")
	}
	_, err = NewSeed256(600, testHash256)
	if err == nil {
		t.Fatal("expected error for non-256-multiple")
	}
	_, err = NewSeed256(512, nil)
	if err == nil {
		t.Fatal("expected error for nil hash")
	}
}

// --- AES-NI cached roundtrip test ---

func TestRoundtrip128_AES(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed128(512, makeAESHash128())
			ns.Hash = makeAESHash128()
			ds.Hash = makeAESHash128()
			ss.Hash = makeAESHash128()
			data := generateData(sz)
			encrypted, err := Encrypt128(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt128(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("AES-NI cached: data mismatch at %d bytes", sz)
			}
		})
	}
}

// makeBlake3Hash256 creates a HashFunc256 with a fixed BLAKE3 key per seed.
// Seed components are XOR'd into the data before hashing.
// A fresh hasher is created per call via Clone() of a template to avoid
// the data race that Reset() on a shared hasher would cause under
// parallel goroutines in process256.
func makeBlake3Hash256() HashFunc256 {
	var blake3Key [32]byte
	if _, err := rand.Read(blake3Key[:]); err != nil {
		panic(err)
	}
	template, _ := blake3.NewKeyed(blake3Key[:])
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

	return func(data []byte, seed [4]uint64) [4]uint64 {
		h := template.Clone()

		mixedPtr := pool.Get().(*[]byte)
		mixed := *mixedPtr
		if cap(mixed) < len(data) {
			mixed = make([]byte, len(data))
		} else {
			mixed = mixed[:len(data)]
		}
		copy(mixed, data)
		// XOR seed[0..3] into first 32 bytes.
		for i := 0; i < 4; i++ {
			s := seed[i]
			off := i * 8
			if off+8 <= len(mixed) {
				binary.LittleEndian.PutUint64(mixed[off:], binary.LittleEndian.Uint64(mixed[off:])^s)
			}
		}
		h.Write(mixed)
		*mixedPtr = mixed
		pool.Put(mixedPtr)
		var buf [32]byte
		h.Sum(buf[:0])

		return [4]uint64{
			binary.LittleEndian.Uint64(buf[0:]),
			binary.LittleEndian.Uint64(buf[8:]),
			binary.LittleEndian.Uint64(buf[16:]),
			binary.LittleEndian.Uint64(buf[24:]),
		}
	}
}

// makeBlake2bHash256 creates a HashFunc256 using BLAKE2b-256.
// Fixed random key is prepended to data+seed as a 32-byte prefix.
// Uses blake2b.Sum256 (no allocation, no keyed mode) with the key
// mixed into the message: H(key || data ^ seed).
// BLAKE2b hash.Hash lacks Clone(), so keyed mode (New256) would
// allocate per call. This approach avoids that entirely.
func makeBlake2bHash256() HashFunc256 {
	var b2key [32]byte
	if _, err := rand.Read(b2key[:]); err != nil {
		panic(err)
	}
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

	return func(data []byte, seed [4]uint64) [4]uint64 {
		need := 32 + len(data)
		bufPtr := pool.Get().(*[]byte)
		buf := *bufPtr
		if cap(buf) < need {
			buf = make([]byte, need)
		} else {
			buf = buf[:need]
		}
		copy(buf[:32], b2key[:])
		copy(buf[32:], data)
		for i := 0; i < 4; i++ {
			off := 32 + i*8
			if off+8 <= len(buf) {
				binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
			}
		}
		digest := blake2b.Sum256(buf)
		*bufPtr = buf
		pool.Put(bufPtr)
		return [4]uint64{
			binary.LittleEndian.Uint64(digest[0:]),
			binary.LittleEndian.Uint64(digest[8:]),
			binary.LittleEndian.Uint64(digest[16:]),
			binary.LittleEndian.Uint64(digest[24:]),
		}
	}
}

// makeBlake2sHash256 creates a HashFunc256 using BLAKE2s-256.
// Same approach as BLAKE2b: fixed key prepended, seed XOR'd into data.
// Uses blake2s.Sum256 (no allocation).
func makeBlake2sHash256() HashFunc256 {
	var b2key [32]byte
	if _, err := rand.Read(b2key[:]); err != nil {
		panic(err)
	}
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

	return func(data []byte, seed [4]uint64) [4]uint64 {
		need := 32 + len(data)
		bufPtr := pool.Get().(*[]byte)
		buf := *bufPtr
		if cap(buf) < need {
			buf = make([]byte, need)
		} else {
			buf = buf[:need]
		}
		copy(buf[:32], b2key[:])
		copy(buf[32:], data)
		for i := 0; i < 4; i++ {
			off := 32 + i*8
			if off+8 <= len(buf) {
				binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
			}
		}
		digest := blake2s.Sum256(buf)
		*bufPtr = buf
		pool.Put(bufPtr)
		return [4]uint64{
			binary.LittleEndian.Uint64(digest[0:]),
			binary.LittleEndian.Uint64(digest[8:]),
			binary.LittleEndian.Uint64(digest[16:]),
			binary.LittleEndian.Uint64(digest[24:]),
		}
	}
}

// sipHash128 uses SipHash-2-4 as HashFunc128.
// Natively 128-bit: two uint64 key parts -> two uint64 output.
// Zero allocations per call — pure function.
func sipHash128(data []byte, seed0, seed1 uint64) (uint64, uint64) {
	return siphash.Hash128(seed0, seed1, data)
}

// --- BLAKE3 keyed cached roundtrip test ---

func TestRoundtrip256_Blake3(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed256(512, makeBlake3Hash256())
			ns.Hash = makeBlake3Hash256()
			ds.Hash = makeBlake3Hash256()
			ss.Hash = makeBlake3Hash256()
			data := generateData(sz)
			encrypted, err := Encrypt256(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt256(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("BLAKE3 cached: data mismatch at %d bytes", sz)
			}
		})
	}
}

// --- BLAKE2b-256 keyed roundtrip test ---

func TestRoundtrip256_Blake2b(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed256(512, makeBlake2bHash256())
			ns.Hash = makeBlake2bHash256()
			ds.Hash = makeBlake2bHash256()
			ss.Hash = makeBlake2bHash256()
			data := generateData(sz)
			encrypted, err := Encrypt256(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt256(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("BLAKE2b-256: data mismatch at %d bytes", sz)
			}
		})
	}
}

// --- BLAKE2s-256 keyed roundtrip test ---

func TestRoundtrip256_Blake2s(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed256(512, makeBlake2sHash256())
			ns.Hash = makeBlake2sHash256()
			ds.Hash = makeBlake2sHash256()
			ss.Hash = makeBlake2sHash256()
			data := generateData(sz)
			encrypted, err := Encrypt256(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt256(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("BLAKE2s-256: data mismatch at %d bytes", sz)
			}
		})
	}
}

// --- SipHash-2-4 roundtrip test ---

func TestRoundtrip128_SipHash(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed128(512, sipHash128)
			data := generateData(sz)
			encrypted, err := Encrypt128(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt128(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("SipHash-128: data mismatch at %d bytes", sz)
			}
		})
	}
}

// --- Stream tests ---

func TestStreamRoundtrip(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)

	sizes := []struct {
		name      string
		dataSize  int
		chunkSize int
	}{
		{"small-single-chunk", 1024, 0},
		{"multi-chunk-4KB", 16384, 4096},
		{"multi-chunk-1KB", 8192, 1024},
		{"exact-boundary", 4096, 2048},
		{"last-chunk-smaller", 5000, 2048},
		{"1-byte-chunks", 100, 1},
	}

	for _, tc := range sizes {
		t.Run(tc.name, func(t *testing.T) {
			data := generateData(tc.dataSize)

			// Encrypt stream
			var encrypted []byte
			err := EncryptStream128(ns, ds, ss, data, tc.chunkSize, func(chunk []byte) error {
				encrypted = append(encrypted, chunk...)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}

			// Decrypt stream
			var decrypted []byte
			err = DecryptStream128(ns, ds, ss, encrypted, func(chunk []byte) error {
				decrypted = append(decrypted, chunk...)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(data, decrypted) {
				t.Fatalf("stream roundtrip: data mismatch (got %d bytes, want %d)", len(decrypted), len(data))
			}
		})
	}
}

func TestStreamRoundtrip128(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	data := generateData(8192)

	var encrypted []byte
	err := EncryptStream128(ns, ds, ss, data, 2048, func(chunk []byte) error {
		encrypted = append(encrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var decrypted []byte
	err = DecryptStream128(ns, ds, ss, encrypted, func(chunk []byte) error {
		decrypted = append(decrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, decrypted) {
		t.Fatal("stream128 roundtrip: data mismatch")
	}
}

func TestStreamRoundtrip256(t *testing.T) {
	ns, ds, ss := makeTripleSeed256(512, testHash256)
	data := generateData(8192)

	var encrypted []byte
	err := EncryptStream256(ns, ds, ss, data, 2048, func(chunk []byte) error {
		encrypted = append(encrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var decrypted []byte
	err = DecryptStream256(ns, ds, ss, encrypted, func(chunk []byte) error {
		decrypted = append(decrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, decrypted) {
		t.Fatal("stream256 roundtrip: data mismatch")
	}
}

func TestStreamChunkSize(t *testing.T) {
	// Verify auto chunk size selection
	if cs := ChunkSize(1024); cs != 1024 {
		t.Fatalf("ChunkSize(1024) = %d, want 1024", cs)
	}
	if cs := ChunkSize(16 << 20); cs != 16<<20 {
		t.Fatalf("ChunkSize(16MB) = %d, want 16MB", cs)
	}
	if cs := ChunkSize(100 << 20); cs != 16<<20 {
		t.Fatalf("ChunkSize(100MB) = %d, want 16MB", cs)
	}
	if cs := ChunkSize(300 << 20); cs != 64<<20 {
		t.Fatalf("ChunkSize(300MB) = %d, want 64MB", cs)
	}
}

func TestStreamEmptyData(t *testing.T) {
	ns, ds, ss := makeTripleSeed128(512, sipHash128)
	err := EncryptStream128(ns, ds, ss, []byte{}, 0, func(chunk []byte) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestStreamTripleSeedValidation(t *testing.T) {
	s1, _ := NewSeed128(512, sipHash128)
	s2, _ := NewSeed128(512, sipHash128)
	data := []byte("test")

	err := EncryptStream128(s1, s1, s2, data, 0, func(chunk []byte) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error when noiseSeed == dataSeed")
	}
}

// --- 512-bit hash tests ---

// testHash512 wraps SipHash-2-4 into a 512-bit interface for testing.
func testHash512(data []byte, seed [8]uint64) [8]uint64 {
	lo0, hi0 := siphash.Hash128(seed[0], seed[1], data)
	lo1, hi1 := siphash.Hash128(seed[2], seed[3], data)
	lo2, hi2 := siphash.Hash128(seed[4], seed[5], data)
	lo3, hi3 := siphash.Hash128(seed[6], seed[7], data)
	return [8]uint64{lo0, hi0, lo1, hi1, lo2, hi2, lo3, hi3}
}

func makeTripleSeed512(bits int, h HashFunc512) (noise, data, start *Seed512) {
	noise, _ = NewSeed512(bits, h)
	data, _ = NewSeed512(bits, h)
	start, _ = NewSeed512(bits, h)
	return
}

// makeBlake2bHash512 creates a HashFunc512 using BLAKE2b-512.
// BLAKE2b natively supports 512-bit output and up to 64-byte (512-bit) key.
func makeBlake2bHash512() HashFunc512 {
	var b2key [64]byte
	if _, err := rand.Read(b2key[:]); err != nil {
		panic(err)
	}
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}

	return func(data []byte, seed [8]uint64) [8]uint64 {
		need := 64 + len(data)
		bufPtr := pool.Get().(*[]byte)
		buf := *bufPtr
		if cap(buf) < need {
			buf = make([]byte, need)
		} else {
			buf = buf[:need]
		}
		copy(buf[:64], b2key[:])
		copy(buf[64:], data)
		for i := 0; i < 8; i++ {
			off := 64 + i*8
			if off+8 <= len(buf) {
				binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
			}
		}
		digest := blake2b.Sum512(buf)
		*bufPtr = buf
		pool.Put(bufPtr)
		return [8]uint64{
			binary.LittleEndian.Uint64(digest[0:]),
			binary.LittleEndian.Uint64(digest[8:]),
			binary.LittleEndian.Uint64(digest[16:]),
			binary.LittleEndian.Uint64(digest[24:]),
			binary.LittleEndian.Uint64(digest[32:]),
			binary.LittleEndian.Uint64(digest[40:]),
			binary.LittleEndian.Uint64(digest[48:]),
			binary.LittleEndian.Uint64(digest[56:]),
		}
	}
}

func TestRoundtrip512(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed512(512, testHash512)
			data := generateData(sz)
			encrypted, err := Encrypt512(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt512(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("512-bit: data mismatch at %d bytes", sz)
			}
		})
	}
}

func TestRoundtrip512_2048bit(t *testing.T) {
	ns, ds, ss := makeTripleSeed512(2048, testHash512)
	data := generateData(4096)
	encrypted, err := Encrypt512(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt512(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("512-bit 2048-key: data mismatch")
	}
}

func TestAuthenticated512(t *testing.T) {
	ns, ds, ss := makeTripleSeed512(512, testHash512)
	data := generateData(1024)
	encrypted, err := EncryptAuthenticated512(ns, ds, ss, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptAuthenticated512(ns, ds, ss, encrypted, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("512-bit authenticated: data mismatch")
	}
}

func TestRoundtrip512_Blake2b(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed512(512, makeBlake2bHash512())
			ns.Hash = makeBlake2bHash512()
			ds.Hash = makeBlake2bHash512()
			ss.Hash = makeBlake2bHash512()
			data := generateData(sz)
			encrypted, err := Encrypt512(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt512(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("BLAKE2b-512: data mismatch at %d bytes", sz)
			}
		})
	}
}

func TestStreamRoundtrip512(t *testing.T) {
	ns, ds, ss := makeTripleSeed512(512, testHash512)
	data := generateData(8192)

	var encrypted []byte
	err := EncryptStream512(ns, ds, ss, data, 2048, func(chunk []byte) error {
		encrypted = append(encrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var decrypted []byte
	err = DecryptStream512(ns, ds, ss, encrypted, func(chunk []byte) error {
		decrypted = append(decrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, decrypted) {
		t.Fatal("stream512 roundtrip: data mismatch")
	}
}

func TestSeed512Validation(t *testing.T) {
	_, err := NewSeed512(256, testHash512)
	if err == nil {
		t.Fatal("expected error for 256-bit seed512 (below 512)")
	}
	_, err = NewSeed512(600, testHash512)
	if err == nil {
		t.Fatal("expected error for non-512-multiple")
	}
	_, err = NewSeed512(512, nil)
	if err == nil {
		t.Fatal("expected error for nil hash")
	}
}

// --- SeedFromComponents256/512 tests ---

func TestSeedFromComponents256Roundtrip(t *testing.T) {
	ns, _ := SeedFromComponents256(testHash256,
		0xdeadbeef01234567, 0x0123456789abcdef,
		0xfedcba9876543210, 0x1111111111111111,
		0x2222222222222222, 0x3333333333333333,
		0x4444444444444444, 0x5555555555555555,
	)
	ds, _ := NewSeed256(512, testHash256)
	ss, _ := NewSeed256(512, testHash256)
	data := generateData(1024)
	encrypted, err := Encrypt256(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt256(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch")
	}
}

func TestSeedFromComponents256Validation(t *testing.T) {
	// Too few components
	_, err := SeedFromComponents256(testHash256, 1, 2, 3)
	if err == nil {
		t.Fatal("expected error for 3 components (below 8 minimum)")
	}

	// Not multiple of 4
	_, err = SeedFromComponents256(testHash256, 1, 2, 3, 4, 5, 6, 7, 8, 9)
	if err == nil {
		t.Fatal("expected error for 9 components (not multiple of 4)")
	}

	// Nil hash
	_, err = SeedFromComponents256(nil, 1, 2, 3, 4, 5, 6, 7, 8)
	if err == nil {
		t.Fatal("expected error for nil hashFunc")
	}
}

func TestSeedFromComponents512Roundtrip(t *testing.T) {
	ns, _ := SeedFromComponents512(testHash512,
		0xdeadbeef01234567, 0x0123456789abcdef,
		0xfedcba9876543210, 0x1111111111111111,
		0x2222222222222222, 0x3333333333333333,
		0x4444444444444444, 0x5555555555555555,
	)
	ds, _ := NewSeed512(512, testHash512)
	ss, _ := NewSeed512(512, testHash512)
	data := generateData(1024)
	encrypted, err := Encrypt512(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt512(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch")
	}
}

func TestSeedFromComponents512Validation(t *testing.T) {
	// Too few components
	_, err := SeedFromComponents512(testHash512, 1, 2, 3)
	if err == nil {
		t.Fatal("expected error for 3 components (below 8 minimum)")
	}

	// Not multiple of 8
	_, err = SeedFromComponents512(testHash512, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)
	if err == nil {
		t.Fatal("expected error for 12 components (not multiple of 8)")
	}

	// Nil hash
	_, err = SeedFromComponents512(nil, 1, 2, 3, 4, 5, 6, 7, 8)
	if err == nil {
		t.Fatal("expected error for nil hashFunc")
	}
}

// --- MinSide tests for Seed256 and Seed512 ---

func TestMinSide256(t *testing.T) {
	s, _ := NewSeed256(512, testHash256)
	side := s.MinSide()
	if side <= 0 {
		t.Fatalf("MinSide256 returned %d, expected > 0", side)
	}
	// side*side must be >= MinPixels
	if side*side < s.MinPixels() {
		t.Fatalf("MinSide256 %d: side^2=%d < MinPixels=%d", side, side*side, s.MinPixels())
	}
}

func TestMinSide512(t *testing.T) {
	s, _ := NewSeed512(512, testHash512)
	side := s.MinSide()
	if side <= 0 {
		t.Fatalf("MinSide512 returned %d, expected > 0", side)
	}
	if side*side < s.MinPixels() {
		t.Fatalf("MinSide512 %d: side^2=%d < MinPixels=%d", side, side*side, s.MinPixels())
	}
}

// --- Stream 256/512 empty data and triple-seed validation ---

func TestStreamEmptyData256(t *testing.T) {
	ns, ds, ss := makeTripleSeed256(512, testHash256)
	err := EncryptStream256(ns, ds, ss, []byte{}, 0, func(chunk []byte) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestStreamEmptyData512(t *testing.T) {
	ns, ds, ss := makeTripleSeed512(512, testHash512)
	err := EncryptStream512(ns, ds, ss, []byte{}, 0, func(chunk []byte) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestStreamTripleSeedValidation256(t *testing.T) {
	s1, _ := NewSeed256(512, testHash256)
	s2, _ := NewSeed256(512, testHash256)
	data := []byte("test")

	err := EncryptStream256(s1, s1, s2, data, 0, func(chunk []byte) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error when noiseSeed == dataSeed")
	}
}

func TestStreamTripleSeedValidation512(t *testing.T) {
	s1, _ := NewSeed512(512, testHash512)
	s2, _ := NewSeed512(512, testHash512)
	data := []byte("test")

	err := EncryptStream512(s1, s1, s2, data, 0, func(chunk []byte) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error when noiseSeed == dataSeed")
	}
}

// --- rotateBits7 unit test ---

func TestRotateBits7(t *testing.T) {
	// Identity: rotation by 0 is no-op
	for v := byte(0); v < 128; v++ {
		if got := rotateBits7(v, 0); got != v {
			t.Fatalf("rotateBits7(%d, 0) = %d, want %d", v, got, v)
		}
	}

	// Full cycle: rotating by 7 is identity (mod 7 = 0)
	for v := byte(0); v < 128; v++ {
		if got := rotateBits7(v, 7); got != v {
			t.Fatalf("rotateBits7(%d, 7) = %d, want %d", v, got, v)
		}
	}

	// Inverse: rotate left r then left (7-r) = identity
	for r := uint(0); r < 7; r++ {
		for v := byte(0); v < 128; v++ {
			mid := rotateBits7(v, r)
			got := rotateBits7(mid, 7-r)
			if got != v {
				t.Fatalf("rotateBits7(rotateBits7(%d, %d), %d) = %d, want %d", v, r, 7-r, got, v)
			}
		}
	}

	// Known value: 0b0000001 << 1 = 0b0000010
	if got := rotateBits7(0x01, 1); got != 0x02 {
		t.Fatalf("rotateBits7(0x01, 1) = 0x%02x, want 0x02", got)
	}

	// Known value: 0b1000000 << 1 wraps = 0b0000001
	if got := rotateBits7(0x40, 1); got != 0x01 {
		t.Fatalf("rotateBits7(0x40, 1) = 0x%02x, want 0x01", got)
	}
}

// --- Decrypt error paths for 256 and 512 ---

func TestCorruptedContainer256(t *testing.T) {
	ns, ds, ss := makeTripleSeed256(512, testHash256)
	data := generateData(256)

	encrypted, err := Encrypt256(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}

	// Too short
	_, err = Decrypt256(ns, ds, ss, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}

	// Truncated container
	_, err = Decrypt256(ns, ds, ss, encrypted[:headerSize()+1])
	if err == nil {
		t.Fatal("expected error for truncated container")
	}

	// Zero dimensions
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[currentNonceSize()] = 0
	corrupted[currentNonceSize()+1] = 0
	corrupted[currentNonceSize()+2] = 0
	corrupted[currentNonceSize()+3] = 0
	_, err = Decrypt256(ns, ds, ss, corrupted)
	if err == nil {
		t.Fatal("expected error for zero dimensions")
	}
}

func TestCorruptedContainer512(t *testing.T) {
	ns, ds, ss := makeTripleSeed512(512, testHash512)
	data := generateData(256)

	encrypted, err := Encrypt512(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}

	// Too short
	_, err = Decrypt512(ns, ds, ss, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}

	// Truncated container
	_, err = Decrypt512(ns, ds, ss, encrypted[:headerSize()+1])
	if err == nil {
		t.Fatal("expected error for truncated container")
	}

	// Zero dimensions
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[currentNonceSize()] = 0
	corrupted[currentNonceSize()+1] = 0
	corrupted[currentNonceSize()+2] = 0
	corrupted[currentNonceSize()+3] = 0
	_, err = Decrypt512(ns, ds, ss, corrupted)
	if err == nil {
		t.Fatal("expected error for zero dimensions")
	}
}

// --- DecryptAuthenticated error paths for 256 and 512 ---

func TestAuthenticatedTamperDetection256(t *testing.T) {
	ns, ds, ss := makeTripleSeed256(512, testHash256)
	data := generateData(4096)

	encrypted, err := EncryptAuthenticated256(ns, ds, ss, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}

	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	for i := headerSize(); i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}

	_, err = DecryptAuthenticated256(ns, ds, ss, tampered, simpleMACFunc)
	if err == nil {
		t.Fatal("expected MAC verification failure on tampered data")
	}
}

func TestAuthenticatedTamperDetection512(t *testing.T) {
	ns, ds, ss := makeTripleSeed512(512, testHash512)
	data := generateData(4096)

	encrypted, err := EncryptAuthenticated512(ns, ds, ss, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}

	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	for i := headerSize(); i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}

	_, err = DecryptAuthenticated512(ns, ds, ss, tampered, simpleMACFunc)
	if err == nil {
		t.Fatal("expected MAC verification failure on tampered data")
	}
}

func TestAuthenticatedWrongSeed256(t *testing.T) {
	ns, ds, ss := makeTripleSeed256(512, testHash256)
	data := []byte("authenticated wrong seed test 256")

	encrypted, err := EncryptAuthenticated256(ns, ds, ss, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}

	wns, wds, wss := makeTripleSeed256(512, testHash256)
	_, err = DecryptAuthenticated256(wns, wds, wss, encrypted, simpleMACFunc)
	if err == nil {
		t.Fatal("expected error with wrong seed")
	}
}

func TestAuthenticatedWrongSeed512(t *testing.T) {
	ns, ds, ss := makeTripleSeed512(512, testHash512)
	data := []byte("authenticated wrong seed test 512")

	encrypted, err := EncryptAuthenticated512(ns, ds, ss, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}

	wns, wds, wss := makeTripleSeed512(512, testHash512)
	_, err = DecryptAuthenticated512(wns, wds, wss, encrypted, simpleMACFunc)
	if err == nil {
		t.Fatal("expected error with wrong seed")
	}
}

// --- parseChunkLen error paths ---

func TestParseChunkLenErrors(t *testing.T) {
	// Data too short for header
	_, err := parseChunkLen([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for data too short for header")
	}

	// Zero dimensions (width=0, height=0)
	buf := make([]byte, headerSize()+8)
	// nonce: 16 bytes of zeros, then width=0, height=0
	_, err = parseChunkLen(buf)
	if err == nil {
		t.Fatal("expected error for zero dimensions")
	}

	// Valid header but truncated data
	// Set width=1, height=1 => need headerSize() + 1*1*8 = 28 bytes
	binary.BigEndian.PutUint16(buf[currentNonceSize():], 1)
	binary.BigEndian.PutUint16(buf[currentNonceSize()+2:], 1)
	// buf is only headerSize()+8 bytes = 28, which is exactly enough for 1x1
	// Make it shorter to trigger truncation
	_, err = parseChunkLen(buf[:headerSize()+4])
	if err == nil {
		t.Fatal("expected error for truncated data")
	}

	// Valid case: 1x1 should succeed with full data
	fullBuf := make([]byte, headerSize()+Channels)
	binary.BigEndian.PutUint16(fullBuf[currentNonceSize():], 1)
	binary.BigEndian.PutUint16(fullBuf[currentNonceSize()+2:], 1)
	n, err := parseChunkLen(fullBuf)
	if err != nil {
		t.Fatalf("unexpected error for valid 1x1: %v", err)
	}
	if n != headerSize()+Channels {
		t.Fatalf("parseChunkLen returned %d, want %d", n, headerSize()+Channels)
	}
}

// --- COBS unit tests ---

func TestCOBS(t *testing.T) {
	cases := [][]byte{
		{0x00},
		{0x00, 0x00},
		{0x00, 0x00, 0x00},
		{0x01, 0x00, 0xFF},
		{0xFF},
		{0x01, 0x02, 0x03},
		bytes.Repeat([]byte{0x42}, 300), // > 254 bytes non-zero
		{0x00, 0x01, 0x00, 0x01, 0x00},
	}
	for i, data := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			encoded := cobsEncode(data)
			for _, b := range encoded {
				if b == 0x00 {
					t.Fatal("COBS encoded contains 0x00")
				}
			}
			decoded := cobsDecode(encoded)
			if !bytes.Equal(data, decoded) {
				t.Fatalf("COBS roundtrip failed: got %v, want %v", decoded, data)
			}
		})
	}
}

// --- ChaCha20 as HashFunc256 (PRF, ARX-based, zero table lookups) ---

// makeChaCha20Hash256 creates a HashFunc256 using ChaCha20.
// Fixed random key + seed XOR'd into data. ChaCha20 keystream used as hash output.
// ARX-based: no S-box, no table lookups — register-only operations.
func makeChaCha20Hash256() HashFunc256 {
	var fixedKey [32]byte
	if _, err := rand.Read(fixedKey[:]); err != nil {
		panic(err)
	}

	return func(data []byte, seed [4]uint64) [4]uint64 {
		// XOR seed into fixed key to derive per-call key
		var key [32]byte
		copy(key[:], fixedKey[:])
		for i := 0; i < 4; i++ {
			off := i * 8
			v := binary.LittleEndian.Uint64(key[off:])
			binary.LittleEndian.PutUint64(key[off:], v^seed[i])
		}
		// Use first 12 bytes of data as nonce (pad if shorter)
		var nonce [12]byte
		copy(nonce[:], data)
		c, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
		if err != nil {
			panic(err)
		}
		var out [32]byte
		c.XORKeyStream(out[:], out[:])
		return [4]uint64{
			binary.LittleEndian.Uint64(out[0:]),
			binary.LittleEndian.Uint64(out[8:]),
			binary.LittleEndian.Uint64(out[16:]),
			binary.LittleEndian.Uint64(out[24:]),
		}
	}
}

func TestRoundtrip256_ChaCha20(t *testing.T) {
	sizes := []int{1, 10, 64, 256, 1024, 4096}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed256(512, makeChaCha20Hash256())
			data := generateData(sz)
			encrypted, err := Encrypt256(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt256(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("roundtrip failed for %d bytes", sz)
			}
		})
	}
}

// --- Benchmark helpers ---

func benchEncrypt128(b *testing.B, hashFunc HashFunc128, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed128(bits, hashFunc)
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt128(ns, ds, ss, data)
	}
}

func benchDecrypt128(b *testing.B, hashFunc HashFunc128, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed128(bits, hashFunc)
	data := generateData(dataSize)
	encrypted, _ := Encrypt128(ns, ds, ss, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt128(ns, ds, ss, encrypted)
	}
}

func benchEncrypt128Cached(b *testing.B, maker func() HashFunc128, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed128(bits, maker())
	ns.Hash = maker()
	ds.Hash = maker()
	ss.Hash = maker()
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt128(ns, ds, ss, data)
	}
}

func benchDecrypt128Cached(b *testing.B, maker func() HashFunc128, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed128(bits, maker())
	ns.Hash = maker()
	ds.Hash = maker()
	ss.Hash = maker()
	data := generateData(dataSize)
	encrypted, _ := Encrypt128(ns, ds, ss, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt128(ns, ds, ss, encrypted)
	}
}

func benchEncrypt256(b *testing.B, hashFunc HashFunc256, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed256(bits, hashFunc)
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt256(ns, ds, ss, data)
	}
}

func benchDecrypt256(b *testing.B, hashFunc HashFunc256, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed256(bits, hashFunc)
	data := generateData(dataSize)
	encrypted, _ := Encrypt256(ns, ds, ss, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt256(ns, ds, ss, encrypted)
	}
}

func benchEncrypt256Cached(b *testing.B, maker func() HashFunc256, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed256(bits, maker())
	ns.Hash = maker()
	ds.Hash = maker()
	ss.Hash = maker()
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt256(ns, ds, ss, data)
	}
}

func benchDecrypt256Cached(b *testing.B, maker func() HashFunc256, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed256(bits, maker())
	ns.Hash = maker()
	ds.Hash = maker()
	ss.Hash = maker()
	data := generateData(dataSize)
	encrypted, _ := Encrypt256(ns, ds, ss, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt256(ns, ds, ss, encrypted)
	}
}

// --- Benchmarks: AES-NI 128-bit cached (Encrypt128, 512-bit key) ---

func BenchmarkAES_Encrypt_1KB(b *testing.B)  { benchEncrypt128Cached(b, makeAESHash128, 512, 1<<10) }
func BenchmarkAES_Encrypt_64KB(b *testing.B) { benchEncrypt128Cached(b, makeAESHash128, 512, 64<<10) }
func BenchmarkAES_Encrypt_1MB(b *testing.B)  { benchEncrypt128Cached(b, makeAESHash128, 512, 1<<20) }
func BenchmarkAES_Encrypt_4MB(b *testing.B)  { benchEncrypt128Cached(b, makeAESHash128, 512, 4<<20) }
func BenchmarkAES_Encrypt_16MB(b *testing.B) { benchEncrypt128Cached(b, makeAESHash128, 512, 16<<20) }
func BenchmarkAES_Encrypt_64MB(b *testing.B) { benchEncrypt128Cached(b, makeAESHash128, 512, 64<<20) }

func BenchmarkAES_Decrypt_1KB(b *testing.B)  { benchDecrypt128Cached(b, makeAESHash128, 512, 1<<10) }
func BenchmarkAES_Decrypt_64KB(b *testing.B) { benchDecrypt128Cached(b, makeAESHash128, 512, 64<<10) }
func BenchmarkAES_Decrypt_1MB(b *testing.B)  { benchDecrypt128Cached(b, makeAESHash128, 512, 1<<20) }
func BenchmarkAES_Decrypt_4MB(b *testing.B)  { benchDecrypt128Cached(b, makeAESHash128, 512, 4<<20) }
func BenchmarkAES_Decrypt_16MB(b *testing.B) { benchDecrypt128Cached(b, makeAESHash128, 512, 16<<20) }
func BenchmarkAES_Decrypt_64MB(b *testing.B) { benchDecrypt128Cached(b, makeAESHash128, 512, 64<<20) }

func BenchmarkAES_KeySize512(b *testing.B)  { benchEncrypt128Cached(b, makeAESHash128, 512, 64<<10) }
func BenchmarkAES_KeySize1024(b *testing.B) { benchEncrypt128Cached(b, makeAESHash128, 1024, 64<<10) }

// --- Benchmarks: BLAKE3 keyed 256-bit cached (Encrypt256, 512-bit key) ---

func BenchmarkBLAKE3_Encrypt_1KB(b *testing.B)  { benchEncrypt256Cached(b, makeBlake3Hash256, 512, 1<<10) }
func BenchmarkBLAKE3_Encrypt_64KB(b *testing.B) { benchEncrypt256Cached(b, makeBlake3Hash256, 512, 64<<10) }
func BenchmarkBLAKE3_Encrypt_1MB(b *testing.B)  { benchEncrypt256Cached(b, makeBlake3Hash256, 512, 1<<20) }
func BenchmarkBLAKE3_Encrypt_4MB(b *testing.B)  { benchEncrypt256Cached(b, makeBlake3Hash256, 512, 4<<20) }
func BenchmarkBLAKE3_Encrypt_16MB(b *testing.B) { benchEncrypt256Cached(b, makeBlake3Hash256, 512, 16<<20) }
func BenchmarkBLAKE3_Encrypt_64MB(b *testing.B) { benchEncrypt256Cached(b, makeBlake3Hash256, 512, 64<<20) }

func BenchmarkBLAKE3_Decrypt_1KB(b *testing.B)  { benchDecrypt256Cached(b, makeBlake3Hash256, 512, 1<<10) }
func BenchmarkBLAKE3_Decrypt_64KB(b *testing.B) { benchDecrypt256Cached(b, makeBlake3Hash256, 512, 64<<10) }
func BenchmarkBLAKE3_Decrypt_1MB(b *testing.B)  { benchDecrypt256Cached(b, makeBlake3Hash256, 512, 1<<20) }
func BenchmarkBLAKE3_Decrypt_4MB(b *testing.B)  { benchDecrypt256Cached(b, makeBlake3Hash256, 512, 4<<20) }
func BenchmarkBLAKE3_Decrypt_16MB(b *testing.B) { benchDecrypt256Cached(b, makeBlake3Hash256, 512, 16<<20) }
func BenchmarkBLAKE3_Decrypt_64MB(b *testing.B) { benchDecrypt256Cached(b, makeBlake3Hash256, 512, 64<<20) }

func BenchmarkBLAKE3_Encrypt_64MB_1Worker(b *testing.B) {
	SetMaxWorkers(1)
	defer SetMaxWorkers(8)
	benchEncrypt256Cached(b, makeBlake3Hash256, 512, 64<<20)
}
func BenchmarkBLAKE3_Encrypt_64MB_8Workers(b *testing.B) {
	SetMaxWorkers(8)
	defer SetMaxWorkers(8)
	benchEncrypt256Cached(b, makeBlake3Hash256, 512, 64<<20)
}
func BenchmarkBLAKE3_Decrypt_64MB_1Worker(b *testing.B) {
	SetMaxWorkers(1)
	defer SetMaxWorkers(8)
	benchDecrypt256Cached(b, makeBlake3Hash256, 512, 64<<20)
}
func BenchmarkBLAKE3_Decrypt_64MB_8Workers(b *testing.B) {
	SetMaxWorkers(8)
	defer SetMaxWorkers(8)
	benchDecrypt256Cached(b, makeBlake3Hash256, 512, 64<<20)
}

func BenchmarkBLAKE3_KeySize512(b *testing.B)  { benchEncrypt256Cached(b, makeBlake3Hash256, 512, 64<<10) }
func BenchmarkBLAKE3_KeySize2048(b *testing.B) { benchEncrypt256Cached(b, makeBlake3Hash256, 2048, 64<<10) }

// --- Benchmarks: BLAKE2b-256 keyed (Encrypt256, 512-bit key, cached) ---

func BenchmarkBLAKE2b_Encrypt_1KB(b *testing.B)  { benchEncrypt256Cached(b, makeBlake2bHash256, 512, 1<<10) }
func BenchmarkBLAKE2b_Encrypt_64KB(b *testing.B) { benchEncrypt256Cached(b, makeBlake2bHash256, 512, 64<<10) }
func BenchmarkBLAKE2b_Encrypt_1MB(b *testing.B)  { benchEncrypt256Cached(b, makeBlake2bHash256, 512, 1<<20) }
func BenchmarkBLAKE2b_Encrypt_4MB(b *testing.B)  { benchEncrypt256Cached(b, makeBlake2bHash256, 512, 4<<20) }
func BenchmarkBLAKE2b_Encrypt_16MB(b *testing.B) { benchEncrypt256Cached(b, makeBlake2bHash256, 512, 16<<20) }
func BenchmarkBLAKE2b_Encrypt_64MB(b *testing.B) { benchEncrypt256Cached(b, makeBlake2bHash256, 512, 64<<20) }

func BenchmarkBLAKE2b_Decrypt_1KB(b *testing.B)  { benchDecrypt256Cached(b, makeBlake2bHash256, 512, 1<<10) }
func BenchmarkBLAKE2b_Decrypt_64KB(b *testing.B) { benchDecrypt256Cached(b, makeBlake2bHash256, 512, 64<<10) }
func BenchmarkBLAKE2b_Decrypt_1MB(b *testing.B)  { benchDecrypt256Cached(b, makeBlake2bHash256, 512, 1<<20) }
func BenchmarkBLAKE2b_Decrypt_4MB(b *testing.B)  { benchDecrypt256Cached(b, makeBlake2bHash256, 512, 4<<20) }
func BenchmarkBLAKE2b_Decrypt_16MB(b *testing.B) { benchDecrypt256Cached(b, makeBlake2bHash256, 512, 16<<20) }
func BenchmarkBLAKE2b_Decrypt_64MB(b *testing.B) { benchDecrypt256Cached(b, makeBlake2bHash256, 512, 64<<20) }

func BenchmarkBLAKE2b_KeySize512(b *testing.B)  { benchEncrypt256Cached(b, makeBlake2bHash256, 512, 64<<10) }
func BenchmarkBLAKE2b_KeySize2048(b *testing.B) { benchEncrypt256Cached(b, makeBlake2bHash256, 2048, 64<<10) }

// --- Benchmarks: BLAKE2s-256 keyed (Encrypt256, 512-bit key, cached) ---

func BenchmarkBLAKE2s_Encrypt_1KB(b *testing.B)  { benchEncrypt256Cached(b, makeBlake2sHash256, 512, 1<<10) }
func BenchmarkBLAKE2s_Encrypt_64KB(b *testing.B) { benchEncrypt256Cached(b, makeBlake2sHash256, 512, 64<<10) }
func BenchmarkBLAKE2s_Encrypt_1MB(b *testing.B)  { benchEncrypt256Cached(b, makeBlake2sHash256, 512, 1<<20) }
func BenchmarkBLAKE2s_Encrypt_4MB(b *testing.B)  { benchEncrypt256Cached(b, makeBlake2sHash256, 512, 4<<20) }
func BenchmarkBLAKE2s_Encrypt_16MB(b *testing.B) { benchEncrypt256Cached(b, makeBlake2sHash256, 512, 16<<20) }
func BenchmarkBLAKE2s_Encrypt_64MB(b *testing.B) { benchEncrypt256Cached(b, makeBlake2sHash256, 512, 64<<20) }

func BenchmarkBLAKE2s_Decrypt_1KB(b *testing.B)  { benchDecrypt256Cached(b, makeBlake2sHash256, 512, 1<<10) }
func BenchmarkBLAKE2s_Decrypt_64KB(b *testing.B) { benchDecrypt256Cached(b, makeBlake2sHash256, 512, 64<<10) }
func BenchmarkBLAKE2s_Decrypt_1MB(b *testing.B)  { benchDecrypt256Cached(b, makeBlake2sHash256, 512, 1<<20) }
func BenchmarkBLAKE2s_Decrypt_4MB(b *testing.B)  { benchDecrypt256Cached(b, makeBlake2sHash256, 512, 4<<20) }
func BenchmarkBLAKE2s_Decrypt_16MB(b *testing.B) { benchDecrypt256Cached(b, makeBlake2sHash256, 512, 16<<20) }
func BenchmarkBLAKE2s_Decrypt_64MB(b *testing.B) { benchDecrypt256Cached(b, makeBlake2sHash256, 512, 64<<20) }

func BenchmarkBLAKE2s_KeySize512(b *testing.B)  { benchEncrypt256Cached(b, makeBlake2sHash256, 512, 64<<10) }
func BenchmarkBLAKE2s_KeySize2048(b *testing.B) { benchEncrypt256Cached(b, makeBlake2sHash256, 2048, 64<<10) }

// --- Benchmarks: ChaCha20-256 (Encrypt/Decrypt, cached) ---

func BenchmarkChaCha20_Encrypt_1KB(b *testing.B)  { benchEncrypt256Cached(b, makeChaCha20Hash256, 512, 1<<10) }
func BenchmarkChaCha20_Encrypt_64KB(b *testing.B) { benchEncrypt256Cached(b, makeChaCha20Hash256, 512, 64<<10) }
func BenchmarkChaCha20_Encrypt_1MB(b *testing.B)  { benchEncrypt256Cached(b, makeChaCha20Hash256, 512, 1<<20) }
func BenchmarkChaCha20_Encrypt_16MB(b *testing.B) { benchEncrypt256Cached(b, makeChaCha20Hash256, 512, 16<<20) }
func BenchmarkChaCha20_Encrypt_64MB(b *testing.B) { benchEncrypt256Cached(b, makeChaCha20Hash256, 512, 64<<20) }

func BenchmarkChaCha20_Decrypt_1KB(b *testing.B)  { benchDecrypt256Cached(b, makeChaCha20Hash256, 512, 1<<10) }
func BenchmarkChaCha20_Decrypt_64KB(b *testing.B) { benchDecrypt256Cached(b, makeChaCha20Hash256, 512, 64<<10) }
func BenchmarkChaCha20_Decrypt_1MB(b *testing.B)  { benchDecrypt256Cached(b, makeChaCha20Hash256, 512, 1<<20) }
func BenchmarkChaCha20_Decrypt_16MB(b *testing.B) { benchDecrypt256Cached(b, makeChaCha20Hash256, 512, 16<<20) }
func BenchmarkChaCha20_Decrypt_64MB(b *testing.B) { benchDecrypt256Cached(b, makeChaCha20Hash256, 512, 64<<20) }

// --- Benchmarks: SipHash-2-4 128-bit (Encrypt128, 512-bit key) ---

func BenchmarkSipHash_Encrypt_1KB(b *testing.B)  { benchEncrypt128(b, sipHash128, 512, 1<<10) }
func BenchmarkSipHash_Encrypt_64KB(b *testing.B) { benchEncrypt128(b, sipHash128, 512, 64<<10) }
func BenchmarkSipHash_Encrypt_1MB(b *testing.B)  { benchEncrypt128(b, sipHash128, 512, 1<<20) }
func BenchmarkSipHash_Encrypt_4MB(b *testing.B)  { benchEncrypt128(b, sipHash128, 512, 4<<20) }
func BenchmarkSipHash_Encrypt_16MB(b *testing.B) { benchEncrypt128(b, sipHash128, 512, 16<<20) }
func BenchmarkSipHash_Encrypt_64MB(b *testing.B) { benchEncrypt128(b, sipHash128, 512, 64<<20) }

func BenchmarkSipHash_Decrypt_1KB(b *testing.B)  { benchDecrypt128(b, sipHash128, 512, 1<<10) }
func BenchmarkSipHash_Decrypt_64KB(b *testing.B) { benchDecrypt128(b, sipHash128, 512, 64<<10) }
func BenchmarkSipHash_Decrypt_1MB(b *testing.B)  { benchDecrypt128(b, sipHash128, 512, 1<<20) }
func BenchmarkSipHash_Decrypt_4MB(b *testing.B)  { benchDecrypt128(b, sipHash128, 512, 4<<20) }
func BenchmarkSipHash_Decrypt_16MB(b *testing.B) { benchDecrypt128(b, sipHash128, 512, 16<<20) }
func BenchmarkSipHash_Decrypt_64MB(b *testing.B) { benchDecrypt128(b, sipHash128, 512, 64<<20) }

func BenchmarkSipHash_KeySize512(b *testing.B)  { benchEncrypt128(b, sipHash128, 512, 64<<10) }
func BenchmarkSipHash_KeySize1024(b *testing.B) { benchEncrypt128(b, sipHash128, 1024, 64<<10) }

// --- Benchmarks: 512-bit (Encrypt512/Decrypt512) ---

func benchEncrypt512(b *testing.B, hashFunc HashFunc512, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed512(bits, hashFunc)
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt512(ns, ds, ss, data)
	}
}

func benchDecrypt512(b *testing.B, hashFunc HashFunc512, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed512(bits, hashFunc)
	data := generateData(dataSize)
	encrypted, _ := Encrypt512(ns, ds, ss, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt512(ns, ds, ss, encrypted)
	}
}

func benchEncrypt512Cached(b *testing.B, maker func() HashFunc512, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed512(bits, maker())
	ns.Hash = maker()
	ds.Hash = maker()
	ss.Hash = maker()
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt512(ns, ds, ss, data)
	}
}

func benchDecrypt512Cached(b *testing.B, maker func() HashFunc512, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed512(bits, maker())
	ns.Hash = maker()
	ds.Hash = maker()
	ss.Hash = maker()
	data := generateData(dataSize)
	encrypted, _ := Encrypt512(ns, ds, ss, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt512(ns, ds, ss, encrypted)
	}
}

// --- Benchmarks: BLAKE2b-512 keyed (Encrypt512, 512-bit key, cached) ---

func BenchmarkBLAKE2b512_Encrypt_1KB(b *testing.B)  { benchEncrypt512Cached(b, makeBlake2bHash512, 512, 1<<10) }
func BenchmarkBLAKE2b512_Encrypt_64KB(b *testing.B) { benchEncrypt512Cached(b, makeBlake2bHash512, 512, 64<<10) }
func BenchmarkBLAKE2b512_Encrypt_1MB(b *testing.B)  { benchEncrypt512Cached(b, makeBlake2bHash512, 512, 1<<20) }
func BenchmarkBLAKE2b512_Encrypt_4MB(b *testing.B)  { benchEncrypt512Cached(b, makeBlake2bHash512, 512, 4<<20) }
func BenchmarkBLAKE2b512_Encrypt_16MB(b *testing.B) { benchEncrypt512Cached(b, makeBlake2bHash512, 512, 16<<20) }
func BenchmarkBLAKE2b512_Encrypt_64MB(b *testing.B) { benchEncrypt512Cached(b, makeBlake2bHash512, 512, 64<<20) }

func BenchmarkBLAKE2b512_Decrypt_1KB(b *testing.B)  { benchDecrypt512Cached(b, makeBlake2bHash512, 512, 1<<10) }
func BenchmarkBLAKE2b512_Decrypt_64KB(b *testing.B) { benchDecrypt512Cached(b, makeBlake2bHash512, 512, 64<<10) }
func BenchmarkBLAKE2b512_Decrypt_1MB(b *testing.B)  { benchDecrypt512Cached(b, makeBlake2bHash512, 512, 1<<20) }
func BenchmarkBLAKE2b512_Decrypt_4MB(b *testing.B)  { benchDecrypt512Cached(b, makeBlake2bHash512, 512, 4<<20) }
func BenchmarkBLAKE2b512_Decrypt_16MB(b *testing.B) { benchDecrypt512Cached(b, makeBlake2bHash512, 512, 16<<20) }
func BenchmarkBLAKE2b512_Decrypt_64MB(b *testing.B) { benchDecrypt512Cached(b, makeBlake2bHash512, 512, 64<<20) }

func BenchmarkBLAKE2b512_KeySize512(b *testing.B)  { benchEncrypt512Cached(b, makeBlake2bHash512, 512, 64<<10) }
func BenchmarkBLAKE2b512_KeySize2048(b *testing.B) { benchEncrypt512Cached(b, makeBlake2bHash512, 2048, 64<<10) }
