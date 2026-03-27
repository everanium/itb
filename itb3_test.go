package itb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"testing"
)

// --- Seven-seed helpers ---

func makeSevenSeeds128(bits int, h HashFunc128) (ns, ds1, ds2, ds3, ss1, ss2, ss3 *Seed128) {
	ns, _ = NewSeed128(bits, h)
	ds1, _ = NewSeed128(bits, h)
	ds2, _ = NewSeed128(bits, h)
	ds3, _ = NewSeed128(bits, h)
	ss1, _ = NewSeed128(bits, h)
	ss2, _ = NewSeed128(bits, h)
	ss3, _ = NewSeed128(bits, h)
	return
}

func makeSevenSeeds256(bits int, h HashFunc256) (ns, ds1, ds2, ds3, ss1, ss2, ss3 *Seed256) {
	ns, _ = NewSeed256(bits, h)
	ds1, _ = NewSeed256(bits, h)
	ds2, _ = NewSeed256(bits, h)
	ds3, _ = NewSeed256(bits, h)
	ss1, _ = NewSeed256(bits, h)
	ss2, _ = NewSeed256(bits, h)
	ss3, _ = NewSeed256(bits, h)
	return
}

func makeSevenSeeds512(bits int, h HashFunc512) (ns, ds1, ds2, ds3, ss1, ss2, ss3 *Seed512) {
	ns, _ = NewSeed512(bits, h)
	ds1, _ = NewSeed512(bits, h)
	ds2, _ = NewSeed512(bits, h)
	ds3, _ = NewSeed512(bits, h)
	ss1, _ = NewSeed512(bits, h)
	ss2, _ = NewSeed512(bits, h)
	ss3, _ = NewSeed512(bits, h)
	return
}

// --- Correctness tests ---

func TestTriple_SplitInterleave(t *testing.T) {
	sizes := []int{0, 1, 2, 3, 4, 5, 6, 7, 100, 1000, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			data := make([]byte, sz)
			if sz > 0 {
				if _, err := rand.Read(data); err != nil {
					t.Fatal(err)
				}
			}
			p0, p1, p2 := splitTriple(data)
			result := interleaveTriple(p0, p1, p2)
			if !bytes.Equal(data, result) {
				t.Fatalf("splitTriple/interleaveTriple roundtrip failed for %d bytes", sz)
			}
		})
	}
}

func TestTriple_SplitInterleaveBits(t *testing.T) {
	sizes := []int{0, 1, 2, 3, 4, 5, 6, 7, 100, 1000, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			data := make([]byte, sz)
			if sz > 0 {
				rand.Read(data)
			}
			p0, p1, p2, totalBits := splitTripleBits(data)
			result := interleaveTripleBits(p0, p1, p2, totalBits)
			if !bytes.Equal(data, result) {
				t.Fatalf("splitTripleBits/interleaveTripleBits roundtrip failed for %d bytes", sz)
			}
		})
	}
}

func BenchmarkSplitTripleBytes_64MB(b *testing.B) {
	data := generateData(64 << 20)
	b.SetBytes(64 << 20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p0, p1, p2 := splitTriple(data)
		_ = interleaveTriple(p0, p1, p2)
	}
}

func BenchmarkSplitTripleBits_64MB(b *testing.B) {
	data := generateData(64 << 20)
	b.SetBytes(64 << 20)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p0, p1, p2, totalBits := splitTripleBits(data)
		_ = interleaveTripleBits(p0, p1, p2, totalBits)
	}
}

func TestTriple_Roundtrip(t *testing.T) {
	sizes := []int{1, 10, 64, 255, 256, 1024, 1377, 4096, 65536, 65537}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
			data := generateData(sz)
			encrypted, err := Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("data mismatch: got %d bytes, want %d", len(decrypted), len(data))
			}
		})
	}
}

func TestTriple_BinarySafety(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
	data := []byte{0x00, 0x01, 0x00, 0x00, 0xFF, 0x00, 0xAB, 0x00, 0x00}
	encrypted, err := Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatalf("data mismatch")
	}
}

func TestTriple_WrongSeed(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
	data := []byte("secret message for wrong seed test")
	encrypted, err := Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong seeds — may return error OR garbage data (oracle-free deniability)
	wns, wds1, wds2, wds3, wss1, wss2, wss3 := makeSevenSeeds128(512, sipHash128)
	decrypted, err := Decrypt3x128(wns, wds1, wds2, wds3, wss1, wss2, wss3, encrypted)
	if err != nil {
		return // expected
	}
	if bytes.Equal(data, decrypted) {
		t.Fatal("wrong seed produced correct plaintext")
	}
}

func TestTriple_NonceUniqueness(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
	data := []byte("same data, different nonce")
	enc1, _ := Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	enc2, _ := Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if bytes.Equal(enc1[:currentNonceSize()], enc2[:currentNonceSize()]) {
		t.Fatal("two encryptions produced identical nonces")
	}
}

func TestTriple_TripleSeedIsolationValidation(t *testing.T) {
	s1, _ := NewSeed128(512, sipHash128)
	s2, _ := NewSeed128(512, sipHash128)
	s3, _ := NewSeed128(512, sipHash128)
	s4, _ := NewSeed128(512, sipHash128)
	s5, _ := NewSeed128(512, sipHash128)
	s6, _ := NewSeed128(512, sipHash128)
	data := []byte("test")

	// Any pair of aliased seeds must be rejected.
	// Test all 21 possible pairs among 7 positions (ns, ds1, ds2, ds3, ss1, ss2, ss3).
	// We use s1 as the aliased seed and fill remaining positions with unique seeds.
	unique := []*Seed128{s1, s2, s3, s4, s5, s6}

	// Helper: build 7-element slice with positions i and j pointing to same seed.
	tryAlias := func(i, j int) error {
		seeds := make([]*Seed128, 7)
		u := 0
		for k := 0; k < 7; k++ {
			if k == i || k == j {
				continue
			}
			seeds[k] = unique[u]
			u++
		}
		alias, _ := NewSeed128(512, sipHash128)
		seeds[i] = alias
		seeds[j] = alias
		_, err := Encrypt3x128(seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], data)
		return err
	}

	for i := 0; i < 7; i++ {
		for j := i + 1; j < 7; j++ {
			if err := tryAlias(i, j); err == nil {
				t.Fatalf("expected error when seeds at positions %d and %d are aliased", i, j)
			}
		}
	}

	// All seven same
	if _, err := Encrypt3x128(s1, s1, s1, s1, s1, s1, s1, data); err == nil {
		t.Fatal("expected error when all seeds same")
	}
}

func TestTriple_CorruptedContainer(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
	data := generateData(256)

	encrypted, err := Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}

	// Truncated container
	_, err = Decrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted[:headerSize()+1])
	if err == nil {
		t.Fatal("expected error for truncated container")
	}

	// Too short
	_, err = Decrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, []byte{1, 2, 3})
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
	_, err = Decrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, corrupted)
	if err == nil {
		t.Fatal("expected error for zero dimensions")
	}
}

func TestTriple_AuthRoundtrip(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
	data := generateData(1024)

	encrypted, err := EncryptAuthenticated3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptAuthenticated3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch")
	}
}

func TestTriple_AuthTamperDetection(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
	data := generateData(4096)

	encrypted, err := EncryptAuthenticated3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}

	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	for i := headerSize(); i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}

	_, err = DecryptAuthenticated3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, tampered, simpleMACFunc)
	if err == nil {
		t.Fatal("expected MAC verification failure on tampered data")
	}
}

func TestTriple_AuthWrongSeed(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
	data := []byte("authenticated wrong seed test")

	encrypted, err := EncryptAuthenticated3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong seeds — must fail MAC verification or produce garbage
	wns, wds1, wds2, wds3, wss1, wss2, wss3 := makeSevenSeeds128(512, sipHash128)
	_, err = DecryptAuthenticated3x128(wns, wds1, wds2, wds3, wss1, wss2, wss3, encrypted, simpleMACFunc)
	if err == nil {
		t.Fatal("expected error with wrong seed")
	}
}

func TestTriple_StreamRoundtrip(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
	data := generateData(256 << 10) // 256 KB

	var encrypted []byte
	err := EncryptStream3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data, 64<<10, func(chunk []byte) error {
		encrypted = append(encrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var decrypted []byte
	err = DecryptStream3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted, func(chunk []byte) error {
		decrypted = append(decrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(data, decrypted) {
		t.Fatalf("stream roundtrip: data mismatch (got %d bytes, want %d)", len(decrypted), len(data))
	}
}

func TestTriple_MaxDataSize64MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 64 MB roundtrip in short mode")
	}
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(1024, sipHash128)
	data := make([]byte, 64<<20) // 64 MB
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	encrypted, err := Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("64 MB roundtrip data mismatch")
	}
}

func TestTriple_FormatIdentical(t *testing.T) {
	// Both Single Ouroboros and Triple Ouroboros must produce containers
	// with the same header format: nonce || width || height || pixel data.
	ns1, ds1, ss1 := makeTripleSeed128(512, sipHash128)
	data := generateData(1024)

	single, err := Encrypt128(ns1, ds1, ss1, data)
	if err != nil {
		t.Fatal(err)
	}

	ns7, d1, d2, d3, s1, s2, s3 := makeSevenSeeds128(512, sipHash128)
	triple, err := Encrypt3x128(ns7, d1, d2, d3, s1, s2, s3, data)
	if err != nil {
		t.Fatal(err)
	}

	// Both must have nonce + 4-byte dimensions header.
	nonceSize := currentNonceSize()
	if len(single) < nonceSize+4 || len(triple) < nonceSize+4 {
		t.Fatal("container too short for header")
	}

	// Pixel data must be 8-byte aligned (Channels = 8 bytes per pixel).
	singlePixelData := len(single) - headerSize()
	triplePixelData := len(triple) - headerSize()
	if singlePixelData%Channels != 0 {
		t.Fatalf("single container pixel data not aligned: %d", singlePixelData)
	}
	if triplePixelData%Channels != 0 {
		t.Fatalf("triple container pixel data not aligned: %d", triplePixelData)
	}
}

func TestTriple_SmallData(t *testing.T) {
	for _, sz := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
			data := generateData(sz)
			encrypted, err := Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("data mismatch at %d bytes", sz)
			}
		})
	}
}

func TestTriple_Roundtrip256(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds256(512, makeBlake3Hash256())
			ns.Hash = makeBlake3Hash256()
			ds1.Hash = makeBlake3Hash256()
			ds2.Hash = makeBlake3Hash256()
			ds3.Hash = makeBlake3Hash256()
			ss1.Hash = makeBlake3Hash256()
			ss2.Hash = makeBlake3Hash256()
			ss3.Hash = makeBlake3Hash256()
			data := generateData(sz)
			encrypted, err := Encrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("256-bit: data mismatch at %d bytes", sz)
			}
		})
	}
}

func TestTriple_Roundtrip512(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds512(512, makeBlake2bHash512())
			ns.Hash = makeBlake2bHash512()
			ds1.Hash = makeBlake2bHash512()
			ds2.Hash = makeBlake2bHash512()
			ds3.Hash = makeBlake2bHash512()
			ss1.Hash = makeBlake2bHash512()
			ss2.Hash = makeBlake2bHash512()
			ss3.Hash = makeBlake2bHash512()
			data := generateData(sz)
			encrypted, err := Encrypt3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("512-bit: data mismatch at %d bytes", sz)
			}
		})
	}
}

// --- Additional Triple Ouroboros tests ---

func TestTriple_EmptyData(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
	_, err := Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, []byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestTriple_AuthRoundtrip256(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds256(512, makeBlake3Hash256())
	data := generateData(1024)
	encrypted, err := EncryptAuthenticated3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptAuthenticated3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("auth 256 roundtrip data mismatch")
	}
}

func TestTriple_AuthRoundtrip512(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds512(512, makeBlake2bHash512())
	data := generateData(1024)
	encrypted, err := EncryptAuthenticated3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptAuthenticated3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("auth 512 roundtrip data mismatch")
	}
}

func TestTriple_AuthTamperDetection256(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds256(512, makeBlake3Hash256())
	data := generateData(4096)
	encrypted, err := EncryptAuthenticated3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	for i := headerSize(); i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}
	_, err = DecryptAuthenticated3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, tampered, simpleMACFunc)
	if err == nil {
		t.Fatal("expected MAC verification failure on tampered data")
	}
}

func TestTriple_AuthTamperDetection512(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds512(512, makeBlake2bHash512())
	data := generateData(4096)
	encrypted, err := EncryptAuthenticated3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	for i := headerSize(); i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}
	_, err = DecryptAuthenticated3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, tampered, simpleMACFunc)
	if err == nil {
		t.Fatal("expected MAC verification failure on tampered data")
	}
}

func TestTriple_AuthWrongSeed256(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds256(512, makeBlake3Hash256())
	data := []byte("auth wrong seed 256")
	encrypted, err := EncryptAuthenticated3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	wds1, _ := NewSeed256(512, makeBlake3Hash256())
	_, err = DecryptAuthenticated3x256(ns, wds1, ds2, ds3, ss1, ss2, ss3, encrypted, simpleMACFunc)
	if err == nil {
		t.Fatal("expected error with wrong seed")
	}
}

func TestTriple_AuthWrongSeed512(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds512(512, makeBlake2bHash512())
	data := []byte("auth wrong seed 512")
	encrypted, err := EncryptAuthenticated3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	wds1, _ := NewSeed512(512, makeBlake2bHash512())
	_, err = DecryptAuthenticated3x512(ns, wds1, ds2, ds3, ss1, ss2, ss3, encrypted, simpleMACFunc)
	if err == nil {
		t.Fatal("expected error with wrong seed")
	}
}

func TestTriple_CorruptedContainer256(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds256(512, makeBlake3Hash256())
	// Truncated
	_, err := Decrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, make([]byte, headerSize()+1))
	if err == nil {
		t.Fatal("expected error for truncated container")
	}
	// Too short
	_, err = Decrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

func TestTriple_CorruptedContainer512(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds512(512, makeBlake2bHash512())
	// Truncated
	_, err := Decrypt3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, make([]byte, headerSize()+1))
	if err == nil {
		t.Fatal("expected error for truncated container")
	}
	// Too short
	_, err = Decrypt3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

func TestTriple_StreamRoundtrip256(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds256(512, makeBlake3Hash256())
	data := generateData(1 << 18)
	var encrypted []byte
	err := EncryptStream3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, data, 64<<10, func(chunk []byte) error {
		encrypted = append(encrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var decrypted []byte
	err = DecryptStream3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted, func(chunk []byte) error {
		decrypted = append(decrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("stream 256 roundtrip data mismatch")
	}
}

func TestTriple_StreamRoundtrip512(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds512(512, makeBlake2bHash512())
	data := generateData(1 << 18)
	var encrypted []byte
	err := EncryptStream3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, data, 64<<10, func(chunk []byte) error {
		encrypted = append(encrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var decrypted []byte
	err = DecryptStream3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted, func(chunk []byte) error {
		decrypted = append(decrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("stream 512 roundtrip data mismatch")
	}
}

func TestTriple_MaxDataSizeExceeded(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
	if _, err := Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, make([]byte, 64<<20+1)); err == nil {
		t.Fatal("expected error for 64 MB + 1 byte")
	}
}

func TestTriple_DecryptRejectOversizeContainer(t *testing.T) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
	header := make([]byte, headerSize()+Channels)
	nonceSz := currentNonceSize()
	binary.BigEndian.PutUint16(header[nonceSz:], 3200)
	binary.BigEndian.PutUint16(header[nonceSz+2:], 3200)
	fakeContainer := make([]byte, len(header)+3200*3200*8)
	copy(fakeContainer, header)
	_, err := Decrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, fakeContainer)
	if err == nil {
		t.Fatal("expected error for oversized container (3200x3200 > 10M pixels)")
	}
}

func TestTriple_BarrierFill32_64MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 64 MB + BarrierFill(32) Triple in short mode")
	}
	SetBarrierFill(32)
	defer SetBarrierFill(1)
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(512, sipHash128)
	data := make([]byte, 64<<20)
	rand.Read(data)
	encrypted, err := Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("64 MB + BarrierFill(32) Triple roundtrip data mismatch")
	}
}

// --- Triple Ouroboros benchmark helpers ---

func benchTripleEncrypt128(b *testing.B, hashFunc HashFunc128, bits, dataSize int) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(bits, hashFunc)
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchTripleDecrypt128(b *testing.B, hashFunc HashFunc128, bits, dataSize int) {
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(bits, hashFunc)
	data := generateData(dataSize)
	encrypted, _ := Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

func benchTripleEncrypt128Cached(b *testing.B, maker func() HashFunc128, bits, dataSize int) {
	h := maker
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(bits, h())
	ns.Hash = h(); ds1.Hash = h(); ds2.Hash = h(); ds3.Hash = h()
	ss1.Hash = h(); ss2.Hash = h(); ss3.Hash = h()
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchTripleDecrypt128Cached(b *testing.B, maker func() HashFunc128, bits, dataSize int) {
	h := maker
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds128(bits, h())
	ns.Hash = h(); ds1.Hash = h(); ds2.Hash = h(); ds3.Hash = h()
	ss1.Hash = h(); ss2.Hash = h(); ss3.Hash = h()
	data := generateData(dataSize)
	encrypted, _ := Encrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt3x128(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

func benchTripleEncrypt256Cached(b *testing.B, maker func() HashFunc256, bits, dataSize int) {
	h := maker
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds256(bits, h())
	ns.Hash = h(); ds1.Hash = h(); ds2.Hash = h(); ds3.Hash = h()
	ss1.Hash = h(); ss2.Hash = h(); ss3.Hash = h()
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchTripleDecrypt256Cached(b *testing.B, maker func() HashFunc256, bits, dataSize int) {
	h := maker
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds256(bits, h())
	ns.Hash = h(); ds1.Hash = h(); ds2.Hash = h(); ds3.Hash = h()
	ss1.Hash = h(); ss2.Hash = h(); ss3.Hash = h()
	data := generateData(dataSize)
	encrypted, _ := Encrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt3x256(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

func benchTripleEncrypt512Cached(b *testing.B, maker func() HashFunc512, bits, dataSize int) {
	h := maker
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds512(bits, h())
	ns.Hash = h(); ds1.Hash = h(); ds2.Hash = h(); ds3.Hash = h()
	ss1.Hash = h(); ss2.Hash = h(); ss3.Hash = h()
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchTripleDecrypt512Cached(b *testing.B, maker func() HashFunc512, bits, dataSize int) {
	h := maker
	ns, ds1, ds2, ds3, ss1, ss2, ss3 := makeSevenSeeds512(bits, h())
	ns.Hash = h(); ds1.Hash = h(); ds2.Hash = h(); ds3.Hash = h()
	ss1.Hash = h(); ss2.Hash = h(); ss3.Hash = h()
	data := generateData(dataSize)
	encrypted, _ := Encrypt3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt3x512(ns, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

// --- Benchmarks: ITB Triple Ouroboros Width 512-bit (all hash functions at 512-bit key) ---

func BenchmarkTripleAES_512bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt128Cached(b, makeAESHash128, 512, 1<<20) }
func BenchmarkTripleAES_512bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt128Cached(b, makeAESHash128, 512, 16<<20) }
func BenchmarkTripleAES_512bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt128Cached(b, makeAESHash128, 512, 64<<20) }
func BenchmarkTripleAES_512bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt128Cached(b, makeAESHash128, 512, 1<<20) }
func BenchmarkTripleAES_512bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt128Cached(b, makeAESHash128, 512, 16<<20) }
func BenchmarkTripleAES_512bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt128Cached(b, makeAESHash128, 512, 64<<20) }

func BenchmarkTripleChaCha20_512bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt256Cached(b, makeChaCha20Hash256, 512, 1<<20) }
func BenchmarkTripleChaCha20_512bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeChaCha20Hash256, 512, 16<<20) }
func BenchmarkTripleChaCha20_512bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeChaCha20Hash256, 512, 64<<20) }
func BenchmarkTripleChaCha20_512bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt256Cached(b, makeChaCha20Hash256, 512, 1<<20) }
func BenchmarkTripleChaCha20_512bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeChaCha20Hash256, 512, 16<<20) }
func BenchmarkTripleChaCha20_512bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeChaCha20Hash256, 512, 64<<20) }

func BenchmarkTripleSipHash_512bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt128(b, sipHash128, 512, 1<<20) }
func BenchmarkTripleSipHash_512bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt128(b, sipHash128, 512, 16<<20) }
func BenchmarkTripleSipHash_512bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt128(b, sipHash128, 512, 64<<20) }
func BenchmarkTripleSipHash_512bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt128(b, sipHash128, 512, 1<<20) }
func BenchmarkTripleSipHash_512bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt128(b, sipHash128, 512, 16<<20) }
func BenchmarkTripleSipHash_512bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt128(b, sipHash128, 512, 64<<20) }

func BenchmarkTripleBLAKE3_512bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt256Cached(b, makeBlake3Hash256, 512, 1<<20) }
func BenchmarkTripleBLAKE3_512bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeBlake3Hash256, 512, 16<<20) }
func BenchmarkTripleBLAKE3_512bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeBlake3Hash256, 512, 64<<20) }
func BenchmarkTripleBLAKE3_512bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt256Cached(b, makeBlake3Hash256, 512, 1<<20) }
func BenchmarkTripleBLAKE3_512bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeBlake3Hash256, 512, 16<<20) }
func BenchmarkTripleBLAKE3_512bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeBlake3Hash256, 512, 64<<20) }

func BenchmarkTripleBLAKE2s_512bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt256Cached(b, makeBlake2sHash256, 512, 1<<20) }
func BenchmarkTripleBLAKE2s_512bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeBlake2sHash256, 512, 16<<20) }
func BenchmarkTripleBLAKE2s_512bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeBlake2sHash256, 512, 64<<20) }
func BenchmarkTripleBLAKE2s_512bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt256Cached(b, makeBlake2sHash256, 512, 1<<20) }
func BenchmarkTripleBLAKE2s_512bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeBlake2sHash256, 512, 16<<20) }
func BenchmarkTripleBLAKE2s_512bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeBlake2sHash256, 512, 64<<20) }

func BenchmarkTripleBLAKE2b512_512bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt512Cached(b, makeBlake2bHash512, 512, 1<<20) }
func BenchmarkTripleBLAKE2b512_512bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt512Cached(b, makeBlake2bHash512, 512, 16<<20) }
func BenchmarkTripleBLAKE2b512_512bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt512Cached(b, makeBlake2bHash512, 512, 64<<20) }
func BenchmarkTripleBLAKE2b512_512bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt512Cached(b, makeBlake2bHash512, 512, 1<<20) }
func BenchmarkTripleBLAKE2b512_512bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt512Cached(b, makeBlake2bHash512, 512, 16<<20) }
func BenchmarkTripleBLAKE2b512_512bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt512Cached(b, makeBlake2bHash512, 512, 64<<20) }

// --- Benchmarks: ITB Triple Ouroboros Width 1024-bit (all hash functions at 1024-bit key) ---

func BenchmarkTripleAES_1024bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt128Cached(b, makeAESHash128, 1024, 1<<20) }
func BenchmarkTripleAES_1024bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt128Cached(b, makeAESHash128, 1024, 16<<20) }
func BenchmarkTripleAES_1024bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt128Cached(b, makeAESHash128, 1024, 64<<20) }
func BenchmarkTripleAES_1024bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt128Cached(b, makeAESHash128, 1024, 1<<20) }
func BenchmarkTripleAES_1024bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt128Cached(b, makeAESHash128, 1024, 16<<20) }
func BenchmarkTripleAES_1024bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt128Cached(b, makeAESHash128, 1024, 64<<20) }

func BenchmarkTripleChaCha20_1024bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt256Cached(b, makeChaCha20Hash256, 1024, 1<<20) }
func BenchmarkTripleChaCha20_1024bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeChaCha20Hash256, 1024, 16<<20) }
func BenchmarkTripleChaCha20_1024bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeChaCha20Hash256, 1024, 64<<20) }
func BenchmarkTripleChaCha20_1024bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt256Cached(b, makeChaCha20Hash256, 1024, 1<<20) }
func BenchmarkTripleChaCha20_1024bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeChaCha20Hash256, 1024, 16<<20) }
func BenchmarkTripleChaCha20_1024bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeChaCha20Hash256, 1024, 64<<20) }

func BenchmarkTripleSipHash_1024bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt128(b, sipHash128, 1024, 1<<20) }
func BenchmarkTripleSipHash_1024bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt128(b, sipHash128, 1024, 16<<20) }
func BenchmarkTripleSipHash_1024bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt128(b, sipHash128, 1024, 64<<20) }
func BenchmarkTripleSipHash_1024bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt128(b, sipHash128, 1024, 1<<20) }
func BenchmarkTripleSipHash_1024bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt128(b, sipHash128, 1024, 16<<20) }
func BenchmarkTripleSipHash_1024bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt128(b, sipHash128, 1024, 64<<20) }

func BenchmarkTripleBLAKE3_1024bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt256Cached(b, makeBlake3Hash256, 1024, 1<<20) }
func BenchmarkTripleBLAKE3_1024bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeBlake3Hash256, 1024, 16<<20) }
func BenchmarkTripleBLAKE3_1024bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeBlake3Hash256, 1024, 64<<20) }
func BenchmarkTripleBLAKE3_1024bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt256Cached(b, makeBlake3Hash256, 1024, 1<<20) }
func BenchmarkTripleBLAKE3_1024bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeBlake3Hash256, 1024, 16<<20) }
func BenchmarkTripleBLAKE3_1024bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeBlake3Hash256, 1024, 64<<20) }

func BenchmarkTripleBLAKE2s_1024bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt256Cached(b, makeBlake2sHash256, 1024, 1<<20) }
func BenchmarkTripleBLAKE2s_1024bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeBlake2sHash256, 1024, 16<<20) }
func BenchmarkTripleBLAKE2s_1024bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeBlake2sHash256, 1024, 64<<20) }
func BenchmarkTripleBLAKE2s_1024bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt256Cached(b, makeBlake2sHash256, 1024, 1<<20) }
func BenchmarkTripleBLAKE2s_1024bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeBlake2sHash256, 1024, 16<<20) }
func BenchmarkTripleBLAKE2s_1024bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeBlake2sHash256, 1024, 64<<20) }

func BenchmarkTripleBLAKE2b512_1024bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt512Cached(b, makeBlake2bHash512, 1024, 1<<20) }
func BenchmarkTripleBLAKE2b512_1024bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt512Cached(b, makeBlake2bHash512, 1024, 16<<20) }
func BenchmarkTripleBLAKE2b512_1024bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt512Cached(b, makeBlake2bHash512, 1024, 64<<20) }
func BenchmarkTripleBLAKE2b512_1024bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt512Cached(b, makeBlake2bHash512, 1024, 1<<20) }
func BenchmarkTripleBLAKE2b512_1024bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt512Cached(b, makeBlake2bHash512, 1024, 16<<20) }
func BenchmarkTripleBLAKE2b512_1024bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt512Cached(b, makeBlake2bHash512, 1024, 64<<20) }

// --- Benchmarks: ITB Triple Ouroboros Width 2048-bit (all hash functions at 2048-bit key) ---

func BenchmarkTripleAES_2048bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt128Cached(b, makeAESHash128, 2048, 1<<20) }
func BenchmarkTripleAES_2048bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt128Cached(b, makeAESHash128, 2048, 16<<20) }
func BenchmarkTripleAES_2048bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt128Cached(b, makeAESHash128, 2048, 64<<20) }
func BenchmarkTripleAES_2048bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt128Cached(b, makeAESHash128, 2048, 1<<20) }
func BenchmarkTripleAES_2048bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt128Cached(b, makeAESHash128, 2048, 16<<20) }
func BenchmarkTripleAES_2048bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt128Cached(b, makeAESHash128, 2048, 64<<20) }

func BenchmarkTripleChaCha20_2048bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt256Cached(b, makeChaCha20Hash256, 2048, 1<<20) }
func BenchmarkTripleChaCha20_2048bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeChaCha20Hash256, 2048, 16<<20) }
func BenchmarkTripleChaCha20_2048bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeChaCha20Hash256, 2048, 64<<20) }
func BenchmarkTripleChaCha20_2048bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt256Cached(b, makeChaCha20Hash256, 2048, 1<<20) }
func BenchmarkTripleChaCha20_2048bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeChaCha20Hash256, 2048, 16<<20) }
func BenchmarkTripleChaCha20_2048bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeChaCha20Hash256, 2048, 64<<20) }

func BenchmarkTripleSipHash_2048bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt128(b, sipHash128, 2048, 1<<20) }
func BenchmarkTripleSipHash_2048bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt128(b, sipHash128, 2048, 16<<20) }
func BenchmarkTripleSipHash_2048bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt128(b, sipHash128, 2048, 64<<20) }
func BenchmarkTripleSipHash_2048bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt128(b, sipHash128, 2048, 1<<20) }
func BenchmarkTripleSipHash_2048bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt128(b, sipHash128, 2048, 16<<20) }
func BenchmarkTripleSipHash_2048bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt128(b, sipHash128, 2048, 64<<20) }

func BenchmarkTripleBLAKE3_2048bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt256Cached(b, makeBlake3Hash256, 2048, 1<<20) }
func BenchmarkTripleBLAKE3_2048bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeBlake3Hash256, 2048, 16<<20) }
func BenchmarkTripleBLAKE3_2048bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeBlake3Hash256, 2048, 64<<20) }
func BenchmarkTripleBLAKE3_2048bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt256Cached(b, makeBlake3Hash256, 2048, 1<<20) }
func BenchmarkTripleBLAKE3_2048bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeBlake3Hash256, 2048, 16<<20) }
func BenchmarkTripleBLAKE3_2048bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeBlake3Hash256, 2048, 64<<20) }

func BenchmarkTripleBLAKE2s_2048bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt256Cached(b, makeBlake2sHash256, 2048, 1<<20) }
func BenchmarkTripleBLAKE2s_2048bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeBlake2sHash256, 2048, 16<<20) }
func BenchmarkTripleBLAKE2s_2048bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt256Cached(b, makeBlake2sHash256, 2048, 64<<20) }
func BenchmarkTripleBLAKE2s_2048bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt256Cached(b, makeBlake2sHash256, 2048, 1<<20) }
func BenchmarkTripleBLAKE2s_2048bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeBlake2sHash256, 2048, 16<<20) }
func BenchmarkTripleBLAKE2s_2048bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt256Cached(b, makeBlake2sHash256, 2048, 64<<20) }

func BenchmarkTripleBLAKE2b512_2048bit_Encrypt_1MB(b *testing.B)  { benchTripleEncrypt512Cached(b, makeBlake2bHash512, 2048, 1<<20) }
func BenchmarkTripleBLAKE2b512_2048bit_Encrypt_16MB(b *testing.B) { benchTripleEncrypt512Cached(b, makeBlake2bHash512, 2048, 16<<20) }
func BenchmarkTripleBLAKE2b512_2048bit_Encrypt_64MB(b *testing.B) { benchTripleEncrypt512Cached(b, makeBlake2bHash512, 2048, 64<<20) }
func BenchmarkTripleBLAKE2b512_2048bit_Decrypt_1MB(b *testing.B)  { benchTripleDecrypt512Cached(b, makeBlake2bHash512, 2048, 1<<20) }
func BenchmarkTripleBLAKE2b512_2048bit_Decrypt_16MB(b *testing.B) { benchTripleDecrypt512Cached(b, makeBlake2bHash512, 2048, 16<<20) }
func BenchmarkTripleBLAKE2b512_2048bit_Decrypt_64MB(b *testing.B) { benchTripleDecrypt512Cached(b, makeBlake2bHash512, 2048, 64<<20) }
