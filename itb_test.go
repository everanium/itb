package itb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"
	"unsafe"

	"github.com/dchest/siphash"
	"github.com/minio/highwayhash"
	"github.com/zeebo/blake3"
	"github.com/zeebo/xxh3"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20"
)

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

// makeTripleSeed creates three independent seeds for triple-seed isolation.
func makeTripleSeed(bits int, h HashFunc) (noise, data, start *Seed) {
	noise, _ = NewSeed(bits, h)
	data, _ = NewSeed(bits, h)
	start, _ = NewSeed(bits, h)
	return
}

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
			ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
			data := generateData(sz)
			encrypted, err := Encrypt(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt(ns, ds, ss, encrypted)
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
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	data := []byte{0x00, 0x01, 0x00, 0x00, 0xFF, 0x00, 0xAB, 0x00, 0x00}
	encrypted, err := Encrypt(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatalf("data mismatch")
	}
}

func TestWrongSeed(t *testing.T) {
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	data := []byte("secret message for wrong seed test")
	encrypted, err := Encrypt(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong seeds — may return error OR garbage data (oracle-free deniability)
	wns, wds, wss := makeTripleSeed(512, xxh3.HashSeed)
	decrypted, err := Decrypt(wns, wds, wss, encrypted)
	if err != nil {
		return // expected
	}
	if bytes.Equal(data, decrypted) {
		t.Fatal("wrong seed produced correct plaintext")
	}
}

func TestNonceUniqueness(t *testing.T) {
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	data := []byte("same data, different nonce")
	enc1, _ := Encrypt(ns, ds, ss, data)
	enc2, _ := Encrypt(ns, ds, ss, data)
	if bytes.Equal(enc1[:NonceSize], enc2[:NonceSize]) {
		t.Fatal("two encryptions produced identical nonces")
	}
}

func TestSeedFromComponents(t *testing.T) {
	ns, _ := SeedFromComponents(xxh3.HashSeed,
		0xdeadbeef01234567, 0x0123456789abcdef,
		0xfedcba9876543210, 0x1111111111111111,
		0x2222222222222222, 0x3333333333333333,
		0x4444444444444444, 0x5555555555555555,
	)
	ds, _ := NewSeed(512, xxh3.HashSeed)
	ss, _ := NewSeed(512, xxh3.HashSeed)
	data := generateData(1024)
	encrypted, err := Encrypt(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch")
	}
}

func TestContainerSizes(t *testing.T) {
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	sizes := []int{1, 10, 100, 1000, 10000, 100000}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			data := generateData(sz)
			encrypted, err := Encrypt(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatal("data mismatch")
			}
			containerSize := len(encrypted) - headerSize
			pixels := containerSize / Channels
			capacity := (pixels * DataBitsPerPixel) / 8
			t.Logf("container: %d pixels, capacity: %d bytes, output: %d bytes", pixels, capacity, len(encrypted))
		})
	}
}

func TestKeySizes(t *testing.T) {
	keySizes := []int{512, 1024, 2048}
	data := generateData(256)
	for _, bits := range keySizes {
		t.Run(fmt.Sprintf("%d-bit", bits), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed(bits, xxh3.HashSeed)
			encrypted, err := Encrypt(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt(ns, ds, ss, encrypted)
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
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	_, err := Encrypt(ns, ds, ss, []byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestSingleByte(t *testing.T) {
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	data := []byte{0x42}
	encrypted, err := Encrypt(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch")
	}
}

// --- Edge case tests ---

func TestSingleZeroByte(t *testing.T) {
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	data := []byte{0x00}
	encrypted, err := Encrypt(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch for single 0x00 byte")
	}
}

func TestAllZeroBytes(t *testing.T) {
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	data := make([]byte, 256) // 256 zero bytes
	encrypted, err := Encrypt(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch for all-zero data")
	}
}

func TestAllFFBytes(t *testing.T) {
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	data := bytes.Repeat([]byte{0xFF}, 256)
	encrypted, err := Encrypt(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch for all-0xFF data")
	}
}

func TestExactMinContainer(t *testing.T) {
	// Data that fits exactly in minimum container (81 pixels for 512-bit seed)
	// 81 pixels × 56 data bits = 4536 bits = 567 bytes capacity
	// COBS overhead ~0.4%, so ~564 bytes of plaintext
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	data := generateData(560)
	encrypted, err := Encrypt(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch at min container boundary")
	}
}

func TestPixelBoundary(t *testing.T) {
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	// Test sizes around pixel boundaries (56 bits = 7 bytes per pixel)
	for _, sz := range []int{6, 7, 8, 13, 14, 15, 55, 56, 57} {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			data := generateData(sz)
			encrypted, err := Encrypt(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt(ns, ds, ss, encrypted)
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
	noiseSeed, _ := NewSeed(512, xxh3.HashSeed)
	dataSeed, _ := NewSeed(512, xxh3.HashSeed)
	startSeed, _ := NewSeed(512, xxh3.HashSeed)
	data := generateData(16 << 20)

	encrypted, err := Encrypt(noiseSeed, dataSeed, startSeed, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(noiseSeed, dataSeed, startSeed, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch with independent triple seeds")
	}

	// Wrong seed: may return error OR garbage data (oracle-free deniability).
	// If decryption "succeeds", the output must NOT match original plaintext.
	wrongSeed, _ := NewSeed(512, xxh3.HashSeed)

	if dec, err := Decrypt(wrongSeed, dataSeed, startSeed, encrypted); err == nil {
		if bytes.Equal(data, dec) {
			t.Fatal("wrong noiseSeed produced correct plaintext")
		}
	}

	if dec, err := Decrypt(noiseSeed, wrongSeed, startSeed, encrypted); err == nil {
		if bytes.Equal(data, dec) {
			t.Fatal("wrong dataSeed produced correct plaintext")
		}
	}

	if dec, err := Decrypt(noiseSeed, dataSeed, wrongSeed, encrypted); err == nil {
		if bytes.Equal(data, dec) {
			t.Fatal("wrong startSeed produced correct plaintext")
		}
	}
}

func TestMaxKeySize(t *testing.T) {
	ns, ds, ss := makeTripleSeed(2048, xxh3.HashSeed)
	data := generateData(1024)
	encrypted, err := Encrypt(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt(ns, ds, ss, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch with 2048-bit key")
	}
}

func TestInvalidSeedSize(t *testing.T) {
	// Below minimum
	_, err := NewSeed(256, xxh3.HashSeed)
	if err == nil {
		t.Fatal("expected error for 256-bit seed (below 512 minimum)")
	}

	// Above maximum
	_, err = NewSeed(4096, xxh3.HashSeed)
	if err == nil {
		t.Fatal("expected error for 4096-bit seed (above 2048 maximum)")
	}

	// Not multiple of 64
	_, err = NewSeed(500, xxh3.HashSeed)
	if err == nil {
		t.Fatal("expected error for non-64-multiple seed")
	}

	// Nil hash
	_, err = NewSeed(512, nil)
	if err == nil {
		t.Fatal("expected error for nil hashFunc")
	}
}

func TestSeedFromComponentsValidation(t *testing.T) {
	// Too few components
	_, err := SeedFromComponents(xxh3.HashSeed, 1, 2, 3)
	if err == nil {
		t.Fatal("expected error for 3 components (below 8 minimum)")
	}

	// Nil hash
	_, err = SeedFromComponents(nil, 1, 2, 3, 4, 5, 6, 7, 8)
	if err == nil {
		t.Fatal("expected error for nil hashFunc")
	}
}

func TestTripleSeedIsolationValidation(t *testing.T) {
	s1, _ := NewSeed(512, xxh3.HashSeed)
	s2, _ := NewSeed(512, xxh3.HashSeed)
	data := []byte("test")

	// Same noiseSeed and dataSeed
	if _, err := Encrypt(s1, s1, s2, data); err == nil {
		t.Fatal("expected error when noiseSeed == dataSeed")
	}
	// Same noiseSeed and startSeed
	if _, err := Encrypt(s1, s2, s1, data); err == nil {
		t.Fatal("expected error when noiseSeed == startSeed")
	}
	// Same dataSeed and startSeed
	if _, err := Encrypt(s2, s1, s1, data); err == nil {
		t.Fatal("expected error when dataSeed == startSeed")
	}
	// All three same
	if _, err := Encrypt(s1, s1, s1, data); err == nil {
		t.Fatal("expected error when all seeds same")
	}
}

func TestCorruptedContainer(t *testing.T) {
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	data := generateData(256)

	encrypted, err := Encrypt(ns, ds, ss, data)
	if err != nil {
		t.Fatal(err)
	}

	// Truncated container
	_, err = Decrypt(ns, ds, ss, encrypted[:headerSize+1])
	if err == nil {
		t.Fatal("expected error for truncated container")
	}

	// Too short
	_, err = Decrypt(ns, ds, ss, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}

	// Zero dimensions
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[NonceSize] = 0
	corrupted[NonceSize+1] = 0
	corrupted[NonceSize+2] = 0
	corrupted[NonceSize+3] = 0
	_, err = Decrypt(ns, ds, ss, corrupted)
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
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	data := generateData(1024)

	encrypted, err := EncryptAuthenticated(ns, ds, ss, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptAuthenticated(ns, ds, ss, encrypted, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch")
	}
}

func TestAuthenticatedTamperDetection(t *testing.T) {
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)

	// Use large data to fill most of the container capacity,
	// minimizing the padding region where undetectable modifications
	// are expected (noise/padding bits don't affect the message).
	data := generateData(4096)

	encrypted, err := EncryptAuthenticated(ns, ds, ss, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}

	// Flip ALL bits in every container byte. With noise at any position
	// 0-7 (from noiseSeed), no single bit position is guaranteed data.
	// Flipping all 8 bits guarantees data corruption regardless of
	// noise position.
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	for i := headerSize; i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}

	_, err = DecryptAuthenticated(ns, ds, ss, tampered, simpleMACFunc)
	if err == nil {
		t.Fatal("expected MAC verification failure on tampered data")
	}
}

func TestAuthenticatedWrongSeed(t *testing.T) {
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	data := []byte("authenticated wrong seed test")

	encrypted, err := EncryptAuthenticated(ns, ds, ss, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong seeds — must fail MAC verification or produce garbage
	wns, wds, wss := makeTripleSeed(512, xxh3.HashSeed)
	_, err = DecryptAuthenticated(wns, wds, wss, encrypted, simpleMACFunc)
	if err == nil {
		t.Fatal("expected error with wrong seed")
	}
}

// --- 128-bit hash tests ---

// testHash128 wraps xxh3.HashSeed into a 128-bit interface for testing.
// Uses seed0 as xxh3 seed, XORs seed1 into hash output for 128-bit state.
func testHash128(data []byte, seed0, seed1 uint64) (uint64, uint64) {
	lo := xxh3.HashSeed(data, seed0)
	hi := xxh3.HashSeed(data, seed1)
	return lo, hi
}

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

		// Block 2: XOR remaining data bytes (16-19) into state.
		if len(data) > 16 {
			for j := 16; j < len(data); j++ {
				b1[j-16] ^= data[j]
			}
		}
		aesEncryptNoescape(block, &b1)

		return binary.LittleEndian.Uint64(b1[:8]), binary.LittleEndian.Uint64(b1[8:])
	}
}

func TestRoundtrip128(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed128(512, testHash128)
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
	ns, ds, ss := makeTripleSeed128(1024, testHash128)
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
	ns, ds, ss := makeTripleSeed128(512, testHash128)
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

// testHash256 wraps xxh3.HashSeed into a 256-bit interface for testing.
func testHash256(data []byte, seed [4]uint64) [4]uint64 {
	return [4]uint64{
		xxh3.HashSeed(data, seed[0]),
		xxh3.HashSeed(data, seed[1]),
		xxh3.HashSeed(data, seed[2]),
		xxh3.HashSeed(data, seed[3]),
	}
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

func TestCrossWidthIsolation(t *testing.T) {
	ns64, ds64, ss64 := makeTripleSeed(512, xxh3.HashSeed)
	ns128, ds128, ss128 := makeTripleSeed128(512, testHash128)

	data := generateData(256)

	// Encrypt with 128-bit, try decrypt with 64-bit — must fail or produce garbage
	encrypted128, _ := Encrypt128(ns128, ds128, ss128, data)
	if dec, err := Decrypt(ns64, ds64, ss64, encrypted128); err == nil {
		if bytes.Equal(data, dec) {
			t.Fatal("cross-width: 128→64 produced correct plaintext")
		}
	}
}

func TestSeed128Validation(t *testing.T) {
	_, err := NewSeed128(256, testHash128)
	if err == nil {
		t.Fatal("expected error for 256-bit seed128")
	}
	_, err = NewSeed128(600, testHash128)
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
	// Template hasher — never written to, only cloned.
	template, _ := blake3.NewKeyed(blake3Key[:])

	return func(data []byte, seed [4]uint64) [4]uint64 {
		h := template.Clone()

		// Mix seed into data via stack buffer, then write.
		var mixed [32]byte
		copy(mixed[:], data)
		// XOR seed[0..3] into first 32 bytes.
		for i := 0; i < 4; i++ {
			s := seed[i]
			off := i * 8
			if off+8 <= len(mixed) {
				binary.LittleEndian.PutUint64(mixed[off:], binary.LittleEndian.Uint64(mixed[off:])^s)
			}
		}
		h.Write(mixed[:len(data)])
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
// mixed into the message: H(key || data ⊕ seed).
// BLAKE2b hash.Hash lacks Clone(), so keyed mode (New256) would
// allocate per call. This approach avoids that entirely.
func makeBlake2bHash256() HashFunc256 {
	var b2key [32]byte
	if _, err := rand.Read(b2key[:]); err != nil {
		panic(err)
	}

	return func(data []byte, seed [4]uint64) [4]uint64 {
		// Build: [32-byte key][data ⊕ seed]
		var buf [64]byte
		copy(buf[:32], b2key[:])
		copy(buf[32:], data)
		for i := 0; i < 4; i++ {
			off := 32 + i*8
			if off+8 <= len(buf) {
				binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
			}
		}
		digest := blake2b.Sum256(buf[:32+len(data)])
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

	return func(data []byte, seed [4]uint64) [4]uint64 {
		var buf [64]byte
		copy(buf[:32], b2key[:])
		copy(buf[32:], data)
		for i := 0; i < 4; i++ {
			off := 32 + i*8
			if off+8 <= len(buf) {
				binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
			}
		}
		digest := blake2s.Sum256(buf[:32+len(data)])
		return [4]uint64{
			binary.LittleEndian.Uint64(digest[0:]),
			binary.LittleEndian.Uint64(digest[8:]),
			binary.LittleEndian.Uint64(digest[16:]),
			binary.LittleEndian.Uint64(digest[24:]),
		}
	}
}

// makeHighwayHash256 creates a HashFunc256 using HighwayHash-256.
// HighwayHash always takes a 256-bit (32-byte) key — this matches
// HashFunc256's [4]uint64 seed perfectly. The seed IS the key.
// Uses Sum256 (single-pass, no streaming overhead).
func makeHighwayHash256() HashFunc256 {
	return func(data []byte, seed [4]uint64) [4]uint64 {
		var key [32]byte
		binary.LittleEndian.PutUint64(key[0:], seed[0])
		binary.LittleEndian.PutUint64(key[8:], seed[1])
		binary.LittleEndian.PutUint64(key[16:], seed[2])
		binary.LittleEndian.PutUint64(key[24:], seed[3])

		digest := highwayhash.Sum(data, key[:])
		return [4]uint64{
			binary.LittleEndian.Uint64(digest[0:]),
			binary.LittleEndian.Uint64(digest[8:]),
			binary.LittleEndian.Uint64(digest[16:]),
			binary.LittleEndian.Uint64(digest[24:]),
		}
	}
}

// makeHighwayHash128 creates a HashFunc128 using HighwayHash-128.
// HighwayHash requires a 256-bit key, but HashFunc128 provides only
// 2×uint64 (128 bits) as seed. Fixed random key + seed XOR'd into data.
func makeHighwayHash128() HashFunc128 {
	var hwKey [32]byte
	if _, err := rand.Read(hwKey[:]); err != nil {
		panic(err)
	}

	return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
		var mixed [32]byte
		copy(mixed[:], data)
		binary.LittleEndian.PutUint64(mixed[0:], binary.LittleEndian.Uint64(mixed[0:])^seed0)
		binary.LittleEndian.PutUint64(mixed[8:], binary.LittleEndian.Uint64(mixed[8:])^seed1)

		digest := highwayhash.Sum128(mixed[:len(data)], hwKey[:])
		return binary.LittleEndian.Uint64(digest[0:]), binary.LittleEndian.Uint64(digest[8:])
	}
}

// makeHighwayHash64 creates a HashFunc using HighwayHash-64.
// HighwayHash requires a 256-bit key, but HashFunc provides only
// uint64 (64 bits) as seed. Fixed random key + seed XOR'd into data.
func makeHighwayHash64() HashFunc {
	var hwKey [32]byte
	if _, err := rand.Read(hwKey[:]); err != nil {
		panic(err)
	}

	return func(data []byte, seed uint64) uint64 {
		var mixed [32]byte
		copy(mixed[:], data)
		binary.LittleEndian.PutUint64(mixed[0:], binary.LittleEndian.Uint64(mixed[0:])^seed)

		return highwayhash.Sum64(mixed[:len(data)], hwKey[:])
	}
}

// sipHash128 uses SipHash-2-4 as HashFunc128.
// Natively 128-bit: two uint64 key parts → two uint64 output.
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

// --- HighwayHash roundtrip tests ---

func TestRoundtrip_HighwayHash64(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed(512, makeHighwayHash64())
			ns.Hash = makeHighwayHash64()
			ds.Hash = makeHighwayHash64()
			ss.Hash = makeHighwayHash64()
			data := generateData(sz)
			encrypted, err := Encrypt(ns, ds, ss, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt(ns, ds, ss, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("HighwayHash-64: data mismatch at %d bytes", sz)
			}
		})
	}
}

func TestRoundtrip128_HighwayHash(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed128(512, makeHighwayHash128())
			ns.Hash = makeHighwayHash128()
			ds.Hash = makeHighwayHash128()
			ss.Hash = makeHighwayHash128()
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
				t.Fatalf("HighwayHash-128: data mismatch at %d bytes", sz)
			}
		})
	}
}

func TestRoundtrip256_HighwayHash(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds, ss := makeTripleSeed256(512, makeHighwayHash256())
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
				t.Fatalf("HighwayHash-256: data mismatch at %d bytes", sz)
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
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)

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
			err := EncryptStream(ns, ds, ss, data, tc.chunkSize, func(chunk []byte) error {
				encrypted = append(encrypted, chunk...)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}

			// Decrypt stream
			var decrypted []byte
			err = DecryptStream(ns, ds, ss, encrypted, func(chunk []byte) error {
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
	ns, ds, ss := makeTripleSeed128(512, testHash128)
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
	ns, ds, ss := makeTripleSeed(512, xxh3.HashSeed)
	err := EncryptStream(ns, ds, ss, []byte{}, 0, func(chunk []byte) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestStreamTripleSeedValidation(t *testing.T) {
	s1, _ := NewSeed(512, xxh3.HashSeed)
	s2, _ := NewSeed(512, xxh3.HashSeed)
	data := []byte("test")

	err := EncryptStream(s1, s1, s2, data, 0, func(chunk []byte) error {
		return nil
	})
	if err == nil {
		t.Fatal("expected error when noiseSeed == dataSeed")
	}
}

// --- 512-bit hash tests ---

// testHash512 wraps xxh3.HashSeed into a 512-bit interface for testing.
func testHash512(data []byte, seed [8]uint64) [8]uint64 {
	return [8]uint64{
		xxh3.HashSeed(data, seed[0]),
		xxh3.HashSeed(data, seed[1]),
		xxh3.HashSeed(data, seed[2]),
		xxh3.HashSeed(data, seed[3]),
		xxh3.HashSeed(data, seed[4]),
		xxh3.HashSeed(data, seed[5]),
		xxh3.HashSeed(data, seed[6]),
		xxh3.HashSeed(data, seed[7]),
	}
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

	return func(data []byte, seed [8]uint64) [8]uint64 {
		var buf [84]byte // 64-byte key + 20-byte max data
		copy(buf[:64], b2key[:])
		copy(buf[64:], data)
		for i := 0; i < 8; i++ {
			off := 64 + i*8
			if off+8 <= len(buf) {
				binary.LittleEndian.PutUint64(buf[off:], binary.LittleEndian.Uint64(buf[off:])^seed[i])
			}
		}
		digest := blake2b.Sum512(buf[:64+len(data)])
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

// --- Benchmark helpers ---

func benchEncrypt(b *testing.B, hashFunc HashFunc, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed(bits, hashFunc)
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt(ns, ds, ss, data)
	}
}

func benchDecrypt(b *testing.B, hashFunc HashFunc, bits, dataSize int) {
	ns, ds, ss := makeTripleSeed(bits, hashFunc)
	data := generateData(dataSize)
	encrypted, _ := Encrypt(ns, ds, ss, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt(ns, ds, ss, encrypted)
	}
}

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

// --- Benchmarks: XXH3 64-bit (Encrypt/Decrypt, 512-bit key) ---

func BenchmarkXXH3_Encrypt_1KB(b *testing.B)  { benchEncrypt(b, xxh3.HashSeed, 512, 1<<10) }
func BenchmarkXXH3_Encrypt_64KB(b *testing.B) { benchEncrypt(b, xxh3.HashSeed, 512, 64<<10) }
func BenchmarkXXH3_Encrypt_1MB(b *testing.B)  { benchEncrypt(b, xxh3.HashSeed, 512, 1<<20) }
func BenchmarkXXH3_Encrypt_4MB(b *testing.B)  { benchEncrypt(b, xxh3.HashSeed, 512, 4<<20) }
func BenchmarkXXH3_Encrypt_16MB(b *testing.B) { benchEncrypt(b, xxh3.HashSeed, 512, 16<<20) }
func BenchmarkXXH3_Encrypt_64MB(b *testing.B) { benchEncrypt(b, xxh3.HashSeed, 512, 64<<20) }

func BenchmarkXXH3_Decrypt_1KB(b *testing.B)  { benchDecrypt(b, xxh3.HashSeed, 512, 1<<10) }
func BenchmarkXXH3_Decrypt_64KB(b *testing.B) { benchDecrypt(b, xxh3.HashSeed, 512, 64<<10) }
func BenchmarkXXH3_Decrypt_1MB(b *testing.B)  { benchDecrypt(b, xxh3.HashSeed, 512, 1<<20) }
func BenchmarkXXH3_Decrypt_4MB(b *testing.B)  { benchDecrypt(b, xxh3.HashSeed, 512, 4<<20) }
func BenchmarkXXH3_Decrypt_16MB(b *testing.B) { benchDecrypt(b, xxh3.HashSeed, 512, 16<<20) }
func BenchmarkXXH3_Decrypt_64MB(b *testing.B) { benchDecrypt(b, xxh3.HashSeed, 512, 64<<20) }

func BenchmarkXXH3_KeySize512(b *testing.B)  { benchEncrypt(b, xxh3.HashSeed, 512, 64<<10) }

// --- Benchmarks: XXH3x2 128-bit (Encrypt128/Decrypt128, 512-bit key) ---

func BenchmarkXXH3x2_Encrypt_1KB(b *testing.B)  { benchEncrypt128(b, testHash128, 512, 1<<10) }
func BenchmarkXXH3x2_Encrypt_64KB(b *testing.B) { benchEncrypt128(b, testHash128, 512, 64<<10) }
func BenchmarkXXH3x2_Encrypt_1MB(b *testing.B)  { benchEncrypt128(b, testHash128, 512, 1<<20) }
func BenchmarkXXH3x2_Encrypt_4MB(b *testing.B)  { benchEncrypt128(b, testHash128, 512, 4<<20) }
func BenchmarkXXH3x2_Encrypt_16MB(b *testing.B) { benchEncrypt128(b, testHash128, 512, 16<<20) }
func BenchmarkXXH3x2_Encrypt_64MB(b *testing.B) { benchEncrypt128(b, testHash128, 512, 64<<20) }

func BenchmarkXXH3x2_Decrypt_1KB(b *testing.B)  { benchDecrypt128(b, testHash128, 512, 1<<10) }
func BenchmarkXXH3x2_Decrypt_64KB(b *testing.B) { benchDecrypt128(b, testHash128, 512, 64<<10) }
func BenchmarkXXH3x2_Decrypt_1MB(b *testing.B)  { benchDecrypt128(b, testHash128, 512, 1<<20) }
func BenchmarkXXH3x2_Decrypt_4MB(b *testing.B)  { benchDecrypt128(b, testHash128, 512, 4<<20) }
func BenchmarkXXH3x2_Decrypt_16MB(b *testing.B) { benchDecrypt128(b, testHash128, 512, 16<<20) }
func BenchmarkXXH3x2_Decrypt_64MB(b *testing.B) { benchDecrypt128(b, testHash128, 512, 64<<20) }

func BenchmarkXXH3_KeySize1024(b *testing.B) { benchEncrypt(b, xxh3.HashSeed, 1024, 64<<10) }

// --- Benchmarks: XXH3x4 256-bit (Encrypt256/Decrypt256, 512-bit key) ---

func BenchmarkXXH3x4_Encrypt_1KB(b *testing.B)  { benchEncrypt256(b, testHash256, 512, 1<<10) }
func BenchmarkXXH3x4_Encrypt_64KB(b *testing.B) { benchEncrypt256(b, testHash256, 512, 64<<10) }
func BenchmarkXXH3x4_Encrypt_1MB(b *testing.B)  { benchEncrypt256(b, testHash256, 512, 1<<20) }
func BenchmarkXXH3x4_Encrypt_4MB(b *testing.B)  { benchEncrypt256(b, testHash256, 512, 4<<20) }
func BenchmarkXXH3x4_Encrypt_16MB(b *testing.B) { benchEncrypt256(b, testHash256, 512, 16<<20) }
func BenchmarkXXH3x4_Encrypt_64MB(b *testing.B) { benchEncrypt256(b, testHash256, 512, 64<<20) }

func BenchmarkXXH3x4_Decrypt_1KB(b *testing.B)  { benchDecrypt256(b, testHash256, 512, 1<<10) }
func BenchmarkXXH3x4_Decrypt_64KB(b *testing.B) { benchDecrypt256(b, testHash256, 512, 64<<10) }
func BenchmarkXXH3x4_Decrypt_1MB(b *testing.B)  { benchDecrypt256(b, testHash256, 512, 1<<20) }
func BenchmarkXXH3x4_Decrypt_4MB(b *testing.B)  { benchDecrypt256(b, testHash256, 512, 4<<20) }
func BenchmarkXXH3x4_Decrypt_16MB(b *testing.B) { benchDecrypt256(b, testHash256, 512, 16<<20) }
func BenchmarkXXH3x4_Decrypt_64MB(b *testing.B) { benchDecrypt256(b, testHash256, 512, 64<<20) }

func BenchmarkXXH3_KeySize2048(b *testing.B) { benchEncrypt(b, xxh3.HashSeed, 2048, 64<<10) }

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

// --- Benchmarks: HighwayHash-64 (Encrypt/Decrypt, 512-bit key, cached) ---

func BenchmarkHW64_Encrypt_1KB(b *testing.B)  { benchEncrypt(b, makeHighwayHash64(), 512, 1<<10) }
func BenchmarkHW64_Encrypt_64KB(b *testing.B) { benchEncrypt(b, makeHighwayHash64(), 512, 64<<10) }
func BenchmarkHW64_Encrypt_1MB(b *testing.B)  { benchEncrypt(b, makeHighwayHash64(), 512, 1<<20) }
func BenchmarkHW64_Encrypt_4MB(b *testing.B)  { benchEncrypt(b, makeHighwayHash64(), 512, 4<<20) }
func BenchmarkHW64_Encrypt_16MB(b *testing.B) { benchEncrypt(b, makeHighwayHash64(), 512, 16<<20) }
func BenchmarkHW64_Encrypt_64MB(b *testing.B) { benchEncrypt(b, makeHighwayHash64(), 512, 64<<20) }

func BenchmarkHW64_Decrypt_1KB(b *testing.B)  { benchDecrypt(b, makeHighwayHash64(), 512, 1<<10) }
func BenchmarkHW64_Decrypt_64KB(b *testing.B) { benchDecrypt(b, makeHighwayHash64(), 512, 64<<10) }
func BenchmarkHW64_Decrypt_1MB(b *testing.B)  { benchDecrypt(b, makeHighwayHash64(), 512, 1<<20) }
func BenchmarkHW64_Decrypt_4MB(b *testing.B)  { benchDecrypt(b, makeHighwayHash64(), 512, 4<<20) }
func BenchmarkHW64_Decrypt_16MB(b *testing.B) { benchDecrypt(b, makeHighwayHash64(), 512, 16<<20) }
func BenchmarkHW64_Decrypt_64MB(b *testing.B) { benchDecrypt(b, makeHighwayHash64(), 512, 64<<20) }

func BenchmarkHW64_KeySize512(b *testing.B)  { benchEncrypt(b, makeHighwayHash64(), 512, 64<<10) }

// --- Benchmarks: HighwayHash-128 (Encrypt128/Decrypt128, 512-bit key, cached) ---

func BenchmarkHW128_Encrypt_1KB(b *testing.B)  { benchEncrypt128Cached(b, makeHighwayHash128, 512, 1<<10) }
func BenchmarkHW128_Encrypt_64KB(b *testing.B) { benchEncrypt128Cached(b, makeHighwayHash128, 512, 64<<10) }
func BenchmarkHW128_Encrypt_1MB(b *testing.B)  { benchEncrypt128Cached(b, makeHighwayHash128, 512, 1<<20) }
func BenchmarkHW128_Encrypt_4MB(b *testing.B)  { benchEncrypt128Cached(b, makeHighwayHash128, 512, 4<<20) }
func BenchmarkHW128_Encrypt_16MB(b *testing.B) { benchEncrypt128Cached(b, makeHighwayHash128, 512, 16<<20) }
func BenchmarkHW128_Encrypt_64MB(b *testing.B) { benchEncrypt128Cached(b, makeHighwayHash128, 512, 64<<20) }

func BenchmarkHW128_Decrypt_1KB(b *testing.B)  { benchDecrypt128Cached(b, makeHighwayHash128, 512, 1<<10) }
func BenchmarkHW128_Decrypt_64KB(b *testing.B) { benchDecrypt128Cached(b, makeHighwayHash128, 512, 64<<10) }
func BenchmarkHW128_Decrypt_1MB(b *testing.B)  { benchDecrypt128Cached(b, makeHighwayHash128, 512, 1<<20) }
func BenchmarkHW128_Decrypt_4MB(b *testing.B)  { benchDecrypt128Cached(b, makeHighwayHash128, 512, 4<<20) }
func BenchmarkHW128_Decrypt_16MB(b *testing.B) { benchDecrypt128Cached(b, makeHighwayHash128, 512, 16<<20) }
func BenchmarkHW128_Decrypt_64MB(b *testing.B) { benchDecrypt128Cached(b, makeHighwayHash128, 512, 64<<20) }

func BenchmarkHW128_KeySize1024(b *testing.B) { benchEncrypt128(b, makeHighwayHash128(), 1024, 64<<10) }

// --- Benchmarks: HighwayHash-256 (Encrypt256/Decrypt256, 512-bit key) ---

func BenchmarkHW256_Encrypt_1KB(b *testing.B)  { benchEncrypt256(b, makeHighwayHash256(), 512, 1<<10) }
func BenchmarkHW256_Encrypt_64KB(b *testing.B) { benchEncrypt256(b, makeHighwayHash256(), 512, 64<<10) }
func BenchmarkHW256_Encrypt_1MB(b *testing.B)  { benchEncrypt256(b, makeHighwayHash256(), 512, 1<<20) }
func BenchmarkHW256_Encrypt_4MB(b *testing.B)  { benchEncrypt256(b, makeHighwayHash256(), 512, 4<<20) }
func BenchmarkHW256_Encrypt_16MB(b *testing.B) { benchEncrypt256(b, makeHighwayHash256(), 512, 16<<20) }
func BenchmarkHW256_Encrypt_64MB(b *testing.B) { benchEncrypt256(b, makeHighwayHash256(), 512, 64<<20) }

func BenchmarkHW256_Decrypt_1KB(b *testing.B)  { benchDecrypt256(b, makeHighwayHash256(), 512, 1<<10) }
func BenchmarkHW256_Decrypt_64KB(b *testing.B) { benchDecrypt256(b, makeHighwayHash256(), 512, 64<<10) }
func BenchmarkHW256_Decrypt_1MB(b *testing.B)  { benchDecrypt256(b, makeHighwayHash256(), 512, 1<<20) }
func BenchmarkHW256_Decrypt_4MB(b *testing.B)  { benchDecrypt256(b, makeHighwayHash256(), 512, 4<<20) }
func BenchmarkHW256_Decrypt_16MB(b *testing.B) { benchDecrypt256(b, makeHighwayHash256(), 512, 16<<20) }
func BenchmarkHW256_Decrypt_64MB(b *testing.B) { benchDecrypt256(b, makeHighwayHash256(), 512, 64<<20) }

func BenchmarkHW256_KeySize2048(b *testing.B) { benchEncrypt256(b, makeHighwayHash256(), 2048, 64<<10) }

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

// --- Benchmarks: XXH3x8 512-bit (Encrypt512/Decrypt512, 512-bit key) ---

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

func BenchmarkXXH3x8_Encrypt_1KB(b *testing.B)  { benchEncrypt512(b, testHash512, 512, 1<<10) }
func BenchmarkXXH3x8_Encrypt_64KB(b *testing.B) { benchEncrypt512(b, testHash512, 512, 64<<10) }
func BenchmarkXXH3x8_Encrypt_1MB(b *testing.B)  { benchEncrypt512(b, testHash512, 512, 1<<20) }
func BenchmarkXXH3x8_Encrypt_4MB(b *testing.B)  { benchEncrypt512(b, testHash512, 512, 4<<20) }
func BenchmarkXXH3x8_Encrypt_16MB(b *testing.B) { benchEncrypt512(b, testHash512, 512, 16<<20) }
func BenchmarkXXH3x8_Encrypt_64MB(b *testing.B) { benchEncrypt512(b, testHash512, 512, 64<<20) }

func BenchmarkXXH3x8_Decrypt_1KB(b *testing.B)  { benchDecrypt512(b, testHash512, 512, 1<<10) }
func BenchmarkXXH3x8_Decrypt_64KB(b *testing.B) { benchDecrypt512(b, testHash512, 512, 64<<10) }
func BenchmarkXXH3x8_Decrypt_1MB(b *testing.B)  { benchDecrypt512(b, testHash512, 512, 1<<20) }
func BenchmarkXXH3x8_Decrypt_4MB(b *testing.B)  { benchDecrypt512(b, testHash512, 512, 4<<20) }
func BenchmarkXXH3x8_Decrypt_16MB(b *testing.B) { benchDecrypt512(b, testHash512, 512, 16<<20) }
func BenchmarkXXH3x8_Decrypt_64MB(b *testing.B) { benchDecrypt512(b, testHash512, 512, 64<<20) }

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
