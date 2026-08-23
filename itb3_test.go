package itb

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"testing"
)

// --- Seven-seed helpers ---

func makeEightSeeds128(bits int, h HashFunc128) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *Seed128) {
	ns, _ = NewSeed128(bits, h)
	ls, _ = NewSeed128(bits, h)
	ds1, _ = NewSeed128(bits, h)
	ds2, _ = NewSeed128(bits, h)
	ds3, _ = NewSeed128(bits, h)
	ss1, _ = NewSeed128(bits, h)
	ss2, _ = NewSeed128(bits, h)
	ss3, _ = NewSeed128(bits, h)
	return
}

func makeEightSeeds256(bits int, h HashFunc256) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *Seed256) {
	ns, _ = NewSeed256(bits, h)
	ls, _ = NewSeed256(bits, h)
	ds1, _ = NewSeed256(bits, h)
	ds2, _ = NewSeed256(bits, h)
	ds3, _ = NewSeed256(bits, h)
	ss1, _ = NewSeed256(bits, h)
	ss2, _ = NewSeed256(bits, h)
	ss3, _ = NewSeed256(bits, h)
	return
}

func makeEightSeeds512(bits int, h HashFunc512) (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 *Seed512) {
	ns, _ = NewSeed512(bits, h)
	ls, _ = NewSeed512(bits, h)
	ds1, _ = NewSeed512(bits, h)
	ds2, _ = NewSeed512(bits, h)
	ds3, _ = NewSeed512(bits, h)
	ss1, _ = NewSeed512(bits, h)
	ss2, _ = NewSeed512(bits, h)
	ss3, _ = NewSeed512(bits, h)
	return
}

// --- Correctness tests ---


func TestTriple_Roundtrip(t *testing.T) {
	sizes := []int{1, 10, 64, 255, 256, 1024, 1377, 4096, 65536, 65537}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
			data := generateData(sz)
			encrypted, err := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
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
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	data := []byte{0x00, 0x01, 0x00, 0x00, 0xFF, 0x00, 0xAB, 0x00, 0x00}
	encrypted, err := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatalf("data mismatch")
	}
}

func TestTriple_BinarySafety256(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	h := makeBlake3Hash256()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	data := []byte{0x00, 0x01, 0x00, 0x00, 0xFF, 0x00, 0xAB, 0x00, 0x00}
	encrypted, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatalf("data mismatch")
	}
}

func TestTriple_BinarySafety512(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	h := makeBlake2bHash512()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	data := []byte{0x00, 0x01, 0x00, 0x00, 0xFF, 0x00, 0xAB, 0x00, 0x00}
	encrypted, err := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatalf("data mismatch")
	}
}

func TestTriple_WrongSeed(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	data := []byte("secret message for wrong seed test")
	encrypted, err := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong seeds — may return error OR garbage data (oracle-free deniability)
	wns, wls, wds1, wds2, wds3, wss1, wss2, wss3 := makeEightSeeds128(512, sipHash128)
	decrypted, err := Decrypt3x128Cfg(nil, wns, wls, wds1, wds2, wds3, wss1, wss2, wss3, encrypted)
	if err != nil {
		return // expected
	}
	if bytes.Equal(data, decrypted) {
		t.Fatal("wrong seed produced correct plaintext")
	}
}

func TestTriple_WrongSeed256(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	h := makeBlake3Hash256()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	data := []byte("secret message for wrong seed test")
	encrypted, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong seeds — may return error OR garbage data (oracle-free deniability)
	wns, wls, wds1, wds2, wds3, wss1, wss2, wss3 := makeEightSeeds256(512, makeBlake3Hash256())
	wh := makeBlake3Hash256()
	wns.Hash, wls.Hash, wds1.Hash, wds2.Hash, wds3.Hash, wss1.Hash, wss2.Hash, wss3.Hash = wh, wh, wh, wh, wh, wh, wh, wh
	decrypted, err := Decrypt3x256Cfg(nil, wns, wls, wds1, wds2, wds3, wss1, wss2, wss3, encrypted)
	if err != nil {
		return // expected
	}
	if bytes.Equal(data, decrypted) {
		t.Fatal("wrong seed produced correct plaintext")
	}
}

func TestTriple_WrongSeed512(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	h := makeBlake2bHash512()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	data := []byte("secret message for wrong seed test")
	encrypted, err := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong seeds — may return error OR garbage data (oracle-free deniability)
	wns, wls, wds1, wds2, wds3, wss1, wss2, wss3 := makeEightSeeds512(512, makeBlake2bHash512())
	wh := makeBlake2bHash512()
	wns.Hash, wls.Hash, wds1.Hash, wds2.Hash, wds3.Hash, wss1.Hash, wss2.Hash, wss3.Hash = wh, wh, wh, wh, wh, wh, wh, wh
	decrypted, err := Decrypt3x512Cfg(nil, wns, wls, wds1, wds2, wds3, wss1, wss2, wss3, encrypted)
	if err != nil {
		return // expected
	}
	if bytes.Equal(data, decrypted) {
		t.Fatal("wrong seed produced correct plaintext")
	}
}

func TestTriple_NonceUniqueness(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	data := []byte("same data, different nonce")
	enc1, _ := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	enc2, _ := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if bytes.Equal(enc1[:currentNonceSizeCfg(nil)], enc2[:currentNonceSizeCfg(nil)]) {
		t.Fatal("two encryptions produced identical nonces")
	}
}

func TestTriple_NonceUniqueness256(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	h := makeBlake3Hash256()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	data := []byte("same data, different nonce")
	enc1, _ := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	enc2, _ := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if bytes.Equal(enc1[:currentNonceSizeCfg(nil)], enc2[:currentNonceSizeCfg(nil)]) {
		t.Fatal("two encryptions produced identical nonces")
	}
}

func TestTriple_NonceUniqueness512(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	h := makeBlake2bHash512()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	data := []byte("same data, different nonce")
	enc1, _ := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	enc2, _ := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if bytes.Equal(enc1[:currentNonceSizeCfg(nil)], enc2[:currentNonceSizeCfg(nil)]) {
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
	s7, _ := NewSeed128(512, sipHash128)
	data := []byte("test")

	// Any pair of aliased seeds must be rejected.
	// Test all 28 possible pairs among 8 positions (ns, ls, ds1, ds2, ds3, ss1, ss2, ss3).
	unique := []*Seed128{s1, s2, s3, s4, s5, s6, s7}

	tryAlias := func(i, j int) error {
		seeds := make([]*Seed128, 8)
		u := 0
		for k := 0; k < 8; k++ {
			if k == i || k == j {
				continue
			}
			seeds[k] = unique[u]
			u++
		}
		alias, _ := NewSeed128(512, sipHash128)
		seeds[i] = alias
		seeds[j] = alias
		_, err := Encrypt3x128Cfg(nil, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], data)
		return err
	}

	for i := 0; i < 8; i++ {
		for j := i + 1; j < 8; j++ {
			if err := tryAlias(i, j); err == nil {
				t.Fatalf("expected error when seeds at positions %d and %d are aliased", i, j)
			}
		}
	}

	// All eight same
	if _, err := Encrypt3x128Cfg(nil, s1, s1, s1, s1, s1, s1, s1, s1, data); err == nil {
		t.Fatal("expected error when all seeds same")
	}
}

func TestTriple_TripleSeedIsolationValidation256(t *testing.T) {
	s1, _ := NewSeed256(512, makeBlake3Hash256())
	s2, _ := NewSeed256(512, makeBlake3Hash256())
	s3, _ := NewSeed256(512, makeBlake3Hash256())
	s4, _ := NewSeed256(512, makeBlake3Hash256())
	s5, _ := NewSeed256(512, makeBlake3Hash256())
	s6, _ := NewSeed256(512, makeBlake3Hash256())
	s7, _ := NewSeed256(512, makeBlake3Hash256())
	data := []byte("test")

	unique := []*Seed256{s1, s2, s3, s4, s5, s6, s7}

	tryAlias := func(i, j int) error {
		seeds := make([]*Seed256, 8)
		u := 0
		for k := 0; k < 8; k++ {
			if k == i || k == j {
				continue
			}
			seeds[k] = unique[u]
			u++
		}
		alias, _ := NewSeed256(512, makeBlake3Hash256())
		seeds[i] = alias
		seeds[j] = alias
		_, err := Encrypt3x256Cfg(nil, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], data)
		return err
	}

	for i := 0; i < 8; i++ {
		for j := i + 1; j < 8; j++ {
			if err := tryAlias(i, j); err == nil {
				t.Fatalf("expected error when seeds at positions %d and %d are aliased", i, j)
			}
		}
	}

	if _, err := Encrypt3x256Cfg(nil, s1, s1, s1, s1, s1, s1, s1, s1, data); err == nil {
		t.Fatal("expected error when all seeds same")
	}
}

func TestTriple_TripleSeedIsolationValidation512(t *testing.T) {
	s1, _ := NewSeed512(512, makeBlake2bHash512())
	s2, _ := NewSeed512(512, makeBlake2bHash512())
	s3, _ := NewSeed512(512, makeBlake2bHash512())
	s4, _ := NewSeed512(512, makeBlake2bHash512())
	s5, _ := NewSeed512(512, makeBlake2bHash512())
	s6, _ := NewSeed512(512, makeBlake2bHash512())
	s7, _ := NewSeed512(512, makeBlake2bHash512())
	data := []byte("test")

	unique := []*Seed512{s1, s2, s3, s4, s5, s6, s7}

	tryAlias := func(i, j int) error {
		seeds := make([]*Seed512, 8)
		u := 0
		for k := 0; k < 8; k++ {
			if k == i || k == j {
				continue
			}
			seeds[k] = unique[u]
			u++
		}
		alias, _ := NewSeed512(512, makeBlake2bHash512())
		seeds[i] = alias
		seeds[j] = alias
		_, err := Encrypt3x512Cfg(nil, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], data)
		return err
	}

	for i := 0; i < 8; i++ {
		for j := i + 1; j < 8; j++ {
			if err := tryAlias(i, j); err == nil {
				t.Fatalf("expected error when seeds at positions %d and %d are aliased", i, j)
			}
		}
	}

	if _, err := Encrypt3x512Cfg(nil, s1, s1, s1, s1, s1, s1, s1, s1, data); err == nil {
		t.Fatal("expected error when all seeds same")
	}
}

func TestTriple_CorruptedContainer(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	data := generateData(256)

	encrypted, err := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}

	// Truncated container
	_, err = Decrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted[:headerSizeCfg(nil)+1])
	if err == nil {
		t.Fatal("expected error for truncated container")
	}

	// Too short
	_, err = Decrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}

	// Zero dimensions
	corrupted := make([]byte, len(encrypted))
	copy(corrupted, encrypted)
	corrupted[currentNonceSizeCfg(nil)] = 0
	corrupted[currentNonceSizeCfg(nil)+1] = 0
	corrupted[currentNonceSizeCfg(nil)+2] = 0
	corrupted[currentNonceSizeCfg(nil)+3] = 0
	_, err = Decrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, corrupted)
	if err == nil {
		t.Fatal("expected error for zero dimensions")
	}
}

func TestTriple_AuthRoundtrip(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	data := generateData(1024)

	encrypted, err := EncryptAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("data mismatch")
	}
}

func TestTriple_AuthTamperDetection(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	data := generateData(4096)

	encrypted, err := EncryptAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}

	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	for i := headerSizeCfg(nil); i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}

	_, err = DecryptAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, tampered, simpleMACFunc)
	if err == nil {
		t.Fatal("expected MAC verification failure on tampered data")
	}
}

func TestTriple_AuthWrongSeed(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	data := []byte("authenticated wrong seed test")

	encrypted, err := EncryptAuthenticated3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}

	// Wrong seeds — must fail MAC verification or produce garbage
	wns, wls, wds1, wds2, wds3, wss1, wss2, wss3 := makeEightSeeds128(512, sipHash128)
	_, err = DecryptAuthenticated3x128Cfg(nil, wns, wls, wds1, wds2, wds3, wss1, wss2, wss3, encrypted, simpleMACFunc)
	if err == nil {
		t.Fatal("expected error with wrong seed")
	}
}

func TestTriple_StreamRoundtrip(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	data := generateData(256 << 10) // 256 KB

	var encrypted []byte
	err := EncryptStream3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, 64<<10, func(chunk []byte) error {
		encrypted = append(encrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var decrypted []byte
	err = DecryptStream3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted, func(chunk []byte) error {
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
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(1024, sipHash128)
	data := make([]byte, 64<<20) // 64 MB
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	encrypted, err := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("64 MB roundtrip data mismatch")
	}
}

func TestTriple_MaxDataSize64MB256(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 64 MB test in short mode")
	}
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(1024, makeBlake3Hash256())
	h := makeBlake3Hash256()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	data := make([]byte, 64<<20) // 64 MB
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	encrypted, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("256-bit: 64 MB roundtrip data mismatch")
	}
}

func TestTriple_MaxDataSize64MB512(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 64 MB test in short mode")
	}
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(1024, makeBlake2bHash512())
	h := makeBlake2bHash512()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	data := make([]byte, 64<<20) // 64 MB
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	encrypted, err := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("512-bit: 64 MB roundtrip data mismatch")
	}
}


func TestTriple_SmallData(t *testing.T) {
	for _, sz := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
			data := generateData(sz)
			encrypted, err := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("data mismatch at %d bytes", sz)
			}
		})
	}
}

func TestTriple_SmallData256(t *testing.T) {
	for _, sz := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
			h := makeBlake3Hash256()
			ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
			data := generateData(sz)
			encrypted, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("256-bit: data mismatch at %d bytes", sz)
			}
		})
	}
}

func TestTriple_SmallData512(t *testing.T) {
	for _, sz := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
			h := makeBlake2bHash512()
			ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
			data := generateData(sz)
			encrypted, err := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, decrypted) {
				t.Fatalf("512-bit: data mismatch at %d bytes", sz)
			}
		})
	}
}

func TestTriple_Roundtrip256(t *testing.T) {
	sizes := []int{1, 64, 1024, 65536}
	for _, sz := range sizes {
		t.Run(fmt.Sprintf("%d-bytes", sz), func(t *testing.T) {
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
			ns.Hash = makeBlake3Hash256()
			ls.Hash = makeBlake3Hash256()
			ds1.Hash = makeBlake3Hash256()
			ds2.Hash = makeBlake3Hash256()
			ds3.Hash = makeBlake3Hash256()
			ss1.Hash = makeBlake3Hash256()
			ss2.Hash = makeBlake3Hash256()
			ss3.Hash = makeBlake3Hash256()
			data := generateData(sz)
			encrypted, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
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
			ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
			ns.Hash = makeBlake2bHash512()
			ls.Hash = makeBlake2bHash512()
			ds1.Hash = makeBlake2bHash512()
			ds2.Hash = makeBlake2bHash512()
			ds3.Hash = makeBlake2bHash512()
			ss1.Hash = makeBlake2bHash512()
			ss2.Hash = makeBlake2bHash512()
			ss3.Hash = makeBlake2bHash512()
			data := generateData(sz)
			encrypted, err := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
			if err != nil {
				t.Fatal(err)
			}
			decrypted, err := Decrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
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
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	_, err := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, []byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestTriple_EmptyData256(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	h := makeBlake3Hash256()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	_, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, []byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestTriple_EmptyData512(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	h := makeBlake2bHash512()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	_, err := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, []byte{})
	if err == nil {
		t.Fatal("expected error for empty data")
	}
}

func TestTriple_AuthRoundtrip256(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	data := generateData(1024)
	encrypted, err := EncryptAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("auth 256 roundtrip data mismatch")
	}
}

func TestTriple_AuthRoundtrip512(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	data := generateData(1024)
	encrypted, err := EncryptAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := DecryptAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("auth 512 roundtrip data mismatch")
	}
}

func TestTriple_AuthTamperDetection256(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	data := generateData(4096)
	encrypted, err := EncryptAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	for i := headerSizeCfg(nil); i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}
	_, err = DecryptAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, tampered, simpleMACFunc)
	if err == nil {
		t.Fatal("expected MAC verification failure on tampered data")
	}
}

func TestTriple_AuthTamperDetection512(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	data := generateData(4096)
	encrypted, err := EncryptAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	for i := headerSizeCfg(nil); i < len(tampered); i++ {
		tampered[i] ^= 0xFF
	}
	_, err = DecryptAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, tampered, simpleMACFunc)
	if err == nil {
		t.Fatal("expected MAC verification failure on tampered data")
	}
}

func TestTriple_AuthWrongSeed256(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	data := []byte("auth wrong seed 256")
	encrypted, err := EncryptAuthenticated3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	wds1, _ := NewSeed256(512, makeBlake3Hash256())
	_, err = DecryptAuthenticated3x256Cfg(nil, ns, ls, wds1, ds2, ds3, ss1, ss2, ss3, encrypted, simpleMACFunc)
	if err == nil {
		t.Fatal("expected error with wrong seed")
	}
}

func TestTriple_AuthWrongSeed512(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	data := []byte("auth wrong seed 512")
	encrypted, err := EncryptAuthenticated3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, simpleMACFunc)
	if err != nil {
		t.Fatal(err)
	}
	wds1, _ := NewSeed512(512, makeBlake2bHash512())
	_, err = DecryptAuthenticated3x512Cfg(nil, ns, ls, wds1, ds2, ds3, ss1, ss2, ss3, encrypted, simpleMACFunc)
	if err == nil {
		t.Fatal("expected error with wrong seed")
	}
}

func TestTriple_CorruptedContainer256(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	// Truncated
	_, err := Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, make([]byte, headerSizeCfg(nil)+1))
	if err == nil {
		t.Fatal("expected error for truncated container")
	}
	// Too short
	_, err = Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

func TestTriple_CorruptedContainer512(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	// Truncated
	_, err := Decrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, make([]byte, headerSizeCfg(nil)+1))
	if err == nil {
		t.Fatal("expected error for truncated container")
	}
	// Too short
	_, err = Decrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, []byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for too-short data")
	}
}

func TestTriple_StreamRoundtrip256(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	data := generateData(1 << 18)
	var encrypted []byte
	err := EncryptStream3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, 64<<10, func(chunk []byte) error {
		encrypted = append(encrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var decrypted []byte
	err = DecryptStream3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted, func(chunk []byte) error {
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
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	data := generateData(1 << 18)
	var encrypted []byte
	err := EncryptStream3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data, 64<<10, func(chunk []byte) error {
		encrypted = append(encrypted, chunk...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var decrypted []byte
	err = DecryptStream3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted, func(chunk []byte) error {
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
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	if _, err := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, make([]byte, 64<<20+1)); err == nil {
		t.Fatal("expected error for 64 MB + 1 byte")
	}
}

func TestTriple_MaxDataSizeExceeded256(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	h := makeBlake3Hash256()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	if _, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, make([]byte, 64<<20+1)); err == nil {
		t.Fatal("expected error for 64 MB + 1 byte")
	}
}

func TestTriple_MaxDataSizeExceeded512(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	h := makeBlake2bHash512()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	if _, err := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, make([]byte, 64<<20+1)); err == nil {
		t.Fatal("expected error for 64 MB + 1 byte")
	}
}

func TestTriple_DecryptRejectOversizeContainer(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	header := make([]byte, headerSizeCfg(nil)+Channels)
	nonceSz := currentNonceSizeCfg(nil)
	binary.BigEndian.PutUint16(header[nonceSz:], 3200)
	binary.BigEndian.PutUint16(header[nonceSz+2:], 3200)
	fakeContainer := make([]byte, len(header)+3200*3200*8)
	copy(fakeContainer, header)
	_, err := Decrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, fakeContainer)
	if err == nil {
		t.Fatal("expected error for oversized container (3200x3200 > 10M pixels)")
	}
}

func TestTriple_DecryptRejectOversizeContainer256(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	h := makeBlake3Hash256()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	header := make([]byte, headerSizeCfg(nil)+Channels)
	nonceSz := currentNonceSizeCfg(nil)
	binary.BigEndian.PutUint16(header[nonceSz:], 3200)
	binary.BigEndian.PutUint16(header[nonceSz+2:], 3200)
	fakeContainer := make([]byte, len(header)+3200*3200*8)
	copy(fakeContainer, header)
	_, err := Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, fakeContainer)
	if err == nil {
		t.Fatal("expected error for oversized container (3200x3200 > 10M pixels)")
	}
}

func TestTriple_DecryptRejectOversizeContainer512(t *testing.T) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	h := makeBlake2bHash512()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	header := make([]byte, headerSizeCfg(nil)+Channels)
	nonceSz := currentNonceSizeCfg(nil)
	binary.BigEndian.PutUint16(header[nonceSz:], 3200)
	binary.BigEndian.PutUint16(header[nonceSz+2:], 3200)
	fakeContainer := make([]byte, len(header)+3200*3200*8)
	copy(fakeContainer, header)
	_, err := Decrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, fakeContainer)
	if err == nil {
		t.Fatal("expected error for oversized container (3200x3200 > 10M pixels)")
	}
}

func TestTriple_BarrierFill32_64MB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 64 MB + BarrierFill(32) Triple in short mode")
	}
	cfg := &Config{BarrierFill: 32}
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(512, sipHash128)
	data := make([]byte, 64<<20)
	rand.Read(data)
	encrypted, err := Encrypt3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt3x128Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("64 MB + BarrierFill(32) Triple roundtrip data mismatch")
	}
}

func TestTriple_BarrierFill32_64MB256(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 64 MB test in short mode")
	}
	cfg := &Config{BarrierFill: 32}
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(512, makeBlake3Hash256())
	h := makeBlake3Hash256()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	data := make([]byte, 64<<20)
	rand.Read(data)
	encrypted, err := Encrypt3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt3x256Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("256-bit: 64 MB + BarrierFill(32) Triple roundtrip data mismatch")
	}
}

func TestTriple_BarrierFill32_64MB512(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 64 MB test in short mode")
	}
	cfg := &Config{BarrierFill: 32}
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(512, makeBlake2bHash512())
	h := makeBlake2bHash512()
	ns.Hash, ls.Hash, ds1.Hash, ds2.Hash, ds3.Hash, ss1.Hash, ss2.Hash, ss3.Hash = h, h, h, h, h, h, h, h
	data := make([]byte, 64<<20)
	rand.Read(data)
	encrypted, err := Encrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := Decrypt3x512Cfg(cfg, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, decrypted) {
		t.Fatal("512-bit: 64 MB + BarrierFill(32) Triple roundtrip data mismatch")
	}
}

// --- Triple Ouroboros benchmark helpers ---

func benchTripleEncrypt128(b *testing.B, hashFunc HashFunc128, bits, dataSize int) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(bits, hashFunc)
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchTripleDecrypt128(b *testing.B, hashFunc HashFunc128, bits, dataSize int) {
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(bits, hashFunc)
	data := generateData(dataSize)
	encrypted, _ := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

func benchTripleEncrypt128Cached(b *testing.B, maker func() HashFunc128, bits, dataSize int) {
	h := maker
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(bits, h())
	ns.Hash = h()
	ds1.Hash = h()
	ds2.Hash = h()
	ds3.Hash = h()
	ss1.Hash = h()
	ss2.Hash = h()
	ss3.Hash = h()
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchTripleDecrypt128Cached(b *testing.B, maker func() HashFunc128, bits, dataSize int) {
	h := maker
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds128(bits, h())
	ns.Hash = h()
	ds1.Hash = h()
	ds2.Hash = h()
	ds3.Hash = h()
	ss1.Hash = h()
	ss2.Hash = h()
	ss3.Hash = h()
	data := generateData(dataSize)
	encrypted, _ := Encrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt3x128Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

func benchTripleEncrypt256Cached(b *testing.B, maker func() HashFunc256, bits, dataSize int) {
	h := maker
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(bits, h())
	ns.Hash = h()
	ds1.Hash = h()
	ds2.Hash = h()
	ds3.Hash = h()
	ss1.Hash = h()
	ss2.Hash = h()
	ss3.Hash = h()
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchTripleDecrypt256Cached(b *testing.B, maker func() HashFunc256, bits, dataSize int) {
	h := maker
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(bits, h())
	ns.Hash = h()
	ds1.Hash = h()
	ds2.Hash = h()
	ds3.Hash = h()
	ss1.Hash = h()
	ss2.Hash = h()
	ss3.Hash = h()
	data := generateData(dataSize)
	encrypted, _ := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

func benchTripleEncrypt512Cached(b *testing.B, maker func() HashFunc512, bits, dataSize int) {
	h := maker
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(bits, h())
	ns.Hash = h()
	ds1.Hash = h()
	ds2.Hash = h()
	ds3.Hash = h()
	ss1.Hash = h()
	ss2.Hash = h()
	ss3.Hash = h()
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchTripleDecrypt512Cached(b *testing.B, maker func() HashFunc512, bits, dataSize int) {
	h := maker
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(bits, h())
	ns.Hash = h()
	ds1.Hash = h()
	ds2.Hash = h()
	ds3.Hash = h()
	ss1.Hash = h()
	ss2.Hash = h()
	ss3.Hash = h()
	data := generateData(dataSize)
	encrypted, _ := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

// benchTripleEncrypt256CachedBatched is the paired-maker variant of
// benchTripleEncrypt256Cached. Each of the seven Triple Ouroboros
// seeds (1 noise + 3 data + 3 start) receives an independent random
// key plus its matching BatchHash, so processChunk256 dispatches every
// per-pixel hash through the batched VAES path.
func benchTripleEncrypt256CachedBatched(b *testing.B, maker func() (HashFunc256, BatchHashFunc256), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(bits, nsH)
	ns.BatchHash = nsB
	dsH1, dsB1 := maker()
	ds1.Hash = dsH1
	ds1.BatchHash = dsB1
	dsH2, dsB2 := maker()
	ds2.Hash = dsH2
	ds2.BatchHash = dsB2
	dsH3, dsB3 := maker()
	ds3.Hash = dsH3
	ds3.BatchHash = dsB3
	ssH1, ssB1 := maker()
	ss1.Hash = ssH1
	ss1.BatchHash = ssB1
	ssH2, ssB2 := maker()
	ss2.Hash = ssH2
	ss2.BatchHash = ssB2
	ssH3, ssB3 := maker()
	ss3.Hash = ssH3
	ss3.BatchHash = ssB3
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchTripleDecrypt256CachedBatched(b *testing.B, maker func() (HashFunc256, BatchHashFunc256), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(bits, nsH)
	ns.BatchHash = nsB
	dsH1, dsB1 := maker()
	ds1.Hash = dsH1
	ds1.BatchHash = dsB1
	dsH2, dsB2 := maker()
	ds2.Hash = dsH2
	ds2.BatchHash = dsB2
	dsH3, dsB3 := maker()
	ds3.Hash = dsH3
	ds3.BatchHash = dsB3
	ssH1, ssB1 := maker()
	ss1.Hash = ssH1
	ss1.BatchHash = ssB1
	ssH2, ssB2 := maker()
	ss2.Hash = ssH2
	ss2.BatchHash = ssB2
	ssH3, ssB3 := maker()
	ss3.Hash = ssH3
	ss3.BatchHash = ssB3
	data := generateData(dataSize)
	encrypted, _ := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}

func benchTripleEncrypt512CachedBatched(b *testing.B, maker func() (HashFunc512, BatchHashFunc512), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(bits, nsH)
	ns.BatchHash = nsB
	dsH1, dsB1 := maker()
	ds1.Hash = dsH1
	ds1.BatchHash = dsB1
	dsH2, dsB2 := maker()
	ds2.Hash = dsH2
	ds2.BatchHash = dsB2
	dsH3, dsB3 := maker()
	ds3.Hash = dsH3
	ds3.BatchHash = dsB3
	ssH1, ssB1 := maker()
	ss1.Hash = ssH1
	ss1.BatchHash = ssB1
	ssH2, ssB2 := maker()
	ss2.Hash = ssH2
	ss2.BatchHash = ssB2
	ssH3, ssB3 := maker()
	ss3.Hash = ssH3
	ss3.BatchHash = ssB3
	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	}
}

func benchTripleDecrypt512CachedBatched(b *testing.B, maker func() (HashFunc512, BatchHashFunc512), bits, dataSize int) {
	nsH, nsB := maker()
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(bits, nsH)
	ns.BatchHash = nsB
	dsH1, dsB1 := maker()
	ds1.Hash = dsH1
	ds1.BatchHash = dsB1
	dsH2, dsB2 := maker()
	ds2.Hash = dsH2
	ds2.BatchHash = dsB2
	dsH3, dsB3 := maker()
	ds3.Hash = dsH3
	ds3.BatchHash = dsB3
	ssH1, ssB1 := maker()
	ss1.Hash = ssH1
	ss1.BatchHash = ssB1
	ssH2, ssB2 := maker()
	ss2.Hash = ssH2
	ss2.BatchHash = ssB2
	ssH3, ssB3 := maker()
	ss3.Hash = ssH3
	ss3.BatchHash = ssB3
	data := generateData(dataSize)
	encrypted, _ := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted)
	}
}


// BenchmarkTripleBLAKE3RoundTripLockSeed measures the itb root
// Encrypt3x + Decrypt3x round-trip throughput and per-iteration
// allocation footprint under the 8-seed API. The 48-bit interlock
// overlay is always engaged, so the lockSeed slot is consumed on
// every encrypt call.
//
// The configuration mirrors the realistic shape:
//
//   - 1024-bit ITB key width (canonical mid-range).
//   - 64 MiB plaintext (large enough that the per-pixel hash
//     pipeline dominates and bench noise from the round-trip-
//     framing overhead is negligible).
//   - BLAKE3 keyed-hash primitive via the makeBlake3Hash256 native
//     test helper (no hashes/ import — itb root tests run
//     in-package and would hit the import cycle).
//   - Triple Ouroboros (1 noise + 1 lock + 3 data + 3 start = 8 seeds).
//
// Run as:
//
//	go test -bench=BenchmarkTripleBLAKE3RoundTripLockSeed \
//	    -benchmem -run=^$ -count=3 -benchtime=3x
//
// to dump per-iteration ns/op + B/op + allocs/op for inspection.
func BenchmarkTripleBLAKE3RoundTripLockSeed(b *testing.B) {
	const (
		bits     = 1024
		dataSize = 64 << 20
	)

	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds256(bits, makeBlake3Hash256())

	data := generateData(dataSize)
	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := Encrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, data)
		if err != nil {
			b.Fatalf("Encrypt3x256: %v", err)
		}
		if _, err := Decrypt3x256Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, encrypted); err != nil {
			b.Fatalf("Decrypt3x256: %v", err)
		}
	}
}

// --- Streaming benchmarks (Low-Level Triple Ouroboros, areion512, 1024-bit) ---

// makeStreamTripleSeeds builds a 7-seed Triple Ouroboros constellation
// (1 noise + 3 data + 3 start) under the supplied 512-bit hash pair,
// with the batched arm wired on every seed so per-pixel hashing routes
// through the ZMM-batched chain-absorb dispatch when AVX-512 is
// available. Counterpart of makeStreamSingleSeeds in itb_test.go.
func makeStreamTripleSeeds(b *testing.B, bits int, maker func() (HashFunc512, BatchHashFunc512)) (*Seed512, *Seed512, *Seed512, *Seed512, *Seed512, *Seed512, *Seed512, *Seed512) {
	nsH, nsB := maker()
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeEightSeeds512(bits, nsH)
	ns.BatchHash = nsB
	h, bf := maker()
	ls.Hash, ls.BatchHash = h, bf
	h, bf = maker()
	ds1.Hash, ds1.BatchHash = h, bf
	h, bf = maker()
	ds2.Hash, ds2.BatchHash = h, bf
	h, bf = maker()
	ds3.Hash, ds3.BatchHash = h, bf
	h, bf = maker()
	ss1.Hash, ss1.BatchHash = h, bf
	h, bf = maker()
	ss2.Hash, ss2.BatchHash = h, bf
	h, bf = maker()
	ss3.Hash, ss3.BatchHash = h, bf
	if ns == nil || ls == nil || ds1 == nil || ds2 == nil || ds3 == nil || ss1 == nil || ss2 == nil || ss3 == nil {
		b.Fatalf("makeStreamTripleSeeds: nil seed")
	}
	return ns, ls, ds1, ds2, ds3, ss1, ss2, ss3
}

// streamTripleMACKey draws a 32-byte CSPRNG MAC key for the Triple
// AEAD streaming benches. Matches streamBenchMACKey shape; duplicated
// to keep the Triple bench helpers self-contained.
func streamTripleMACKey(b *testing.B) []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		b.Fatalf("rand.Read mac key: %v", err)
	}
	return k
}

// streamTriplePlaintext draws an n-byte CSPRNG plaintext for the
// Triple bench cohort.
func streamTriplePlaintext(b *testing.B, n int) []byte {
	src := make([]byte, n)
	if _, err := rand.Read(src); err != nil {
		b.Fatalf("rand.Read plaintext: %v", err)
	}
	return src
}

// BenchmarkTripleEncryptStreamAuthIO_Areion512_1024_64MB_C16MB measures
// the throughput of [EncryptStreamAuth3xCfg] (Triple Ouroboros, areion512
// PRF, 1024-bit ITB key width, hmac-blake3 MAC) on a 64 MiB plaintext
// streamed in 16 MiB chunks. The 8-seed constellation and the MAC
// closure are constructed once outside the timer.
func BenchmarkTripleEncryptStreamAuthIO_Areion512_1024_64MB_C16MB(b *testing.B) {
	const (
		bits      = 1024
		dataSize  = 64 << 20
		chunkSize = 16 << 20
	)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeStreamTripleSeeds(b, bits, makeAreionSoEM512Pair)
	mac := newHMACBlake3Bench(streamTripleMACKey(b))
	src := streamTriplePlaintext(b, dataSize)

	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(src)
		buf := bytes.NewBuffer(make([]byte, 0, 80<<20))
		if err := EncryptStreamAuth3xCfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, r, buf, mac, chunkSize); err != nil {
			b.Fatalf("EncryptStreamAuth3x: %v", err)
		}
	}
}

// BenchmarkTripleDecryptStreamAuthIO_Areion512_1024_64MB_C16MB measures
// the throughput of [DecryptStreamAuth3xCfg] on a transcript pre-built
// once outside the timer.
func BenchmarkTripleDecryptStreamAuthIO_Areion512_1024_64MB_C16MB(b *testing.B) {
	const (
		bits      = 1024
		dataSize  = 64 << 20
		chunkSize = 16 << 20
	)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeStreamTripleSeeds(b, bits, makeAreionSoEM512Pair)
	mac := newHMACBlake3Bench(streamTripleMACKey(b))
	src := streamTriplePlaintext(b, dataSize)

	encBuf := bytes.NewBuffer(make([]byte, 0, 80<<20))
	if err := EncryptStreamAuth3xCfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(src), encBuf, mac, chunkSize); err != nil {
		b.Fatalf("setup EncryptStreamAuth3x: %v", err)
	}
	ciphertext := encBuf.Bytes()

	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(ciphertext)
		buf := bytes.NewBuffer(make([]byte, 0, dataSize))
		if err := DecryptStreamAuth3xCfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, r, buf, mac); err != nil {
			b.Fatalf("DecryptStreamAuth3x: %v", err)
		}
	}
}

// BenchmarkTripleEncryptStreamIO_Areion512_1024_64MB_C16MB measures
// the throughput of [EncryptStream3xCfg] (no MAC) under the same Triple
// Ouroboros / areion512 / 1024-bit configuration.
func BenchmarkTripleEncryptStreamIO_Areion512_1024_64MB_C16MB(b *testing.B) {
	const (
		bits      = 1024
		dataSize  = 64 << 20
		chunkSize = 16 << 20
	)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeStreamTripleSeeds(b, bits, makeAreionSoEM512Pair)
	src := streamTriplePlaintext(b, dataSize)

	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(src)
		buf := bytes.NewBuffer(make([]byte, 0, 80<<20))
		if err := EncryptStream3xCfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, r, buf, chunkSize); err != nil {
			b.Fatalf("EncryptStream3x: %v", err)
		}
	}
}

// BenchmarkTripleDecryptStreamIO_Areion512_1024_64MB_C16MB measures
// the throughput of [DecryptStream3xCfg] on a transcript pre-built once.
func BenchmarkTripleDecryptStreamIO_Areion512_1024_64MB_C16MB(b *testing.B) {
	const (
		bits      = 1024
		dataSize  = 64 << 20
		chunkSize = 16 << 20
	)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeStreamTripleSeeds(b, bits, makeAreionSoEM512Pair)
	src := streamTriplePlaintext(b, dataSize)

	encBuf := bytes.NewBuffer(make([]byte, 0, 80<<20))
	if err := EncryptStream3xCfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, bytes.NewReader(src), encBuf, chunkSize); err != nil {
		b.Fatalf("setup EncryptStream3x: %v", err)
	}
	ciphertext := encBuf.Bytes()

	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(ciphertext)
		buf := bytes.NewBuffer(make([]byte, 0, dataSize))
		if err := DecryptStream3xCfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, r, buf); err != nil {
			b.Fatalf("DecryptStream3x: %v", err)
		}
	}
}

// BenchmarkTripleEncryptStreamUserLoop_Areion512_1024_64MB_C16MB
// measures the User-Driven Encrypt loop: caller reads
// chunkSize-byte windows out of src, calls [Encrypt3x] per chunk, and
// frames each ciphertext on the wire with a 4-byte big-endian length
// prefix. Mirrors the exampleLowLevelModePlainUserLoop walker shape
// from tmp/itb_examples/go/main.go scaled to the Triple 7-seed path.
func BenchmarkTripleEncryptStreamUserLoop_Areion512_1024_64MB_C16MB(b *testing.B) {
	const (
		bits      = 1024
		dataSize  = 64 << 20
		chunkSize = 16 << 20
	)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeStreamTripleSeeds(b, bits, makeAreionSoEM512Pair)
	src := streamTriplePlaintext(b, dataSize)

	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(src)
		buf := bytes.NewBuffer(make([]byte, 0, 80<<20))
		stage := make([]byte, chunkSize)
		var lenBuf [4]byte
		for {
			n, rerr := io.ReadFull(r, stage)
			if rerr == io.EOF {
				break
			}
			if rerr != nil && rerr != io.ErrUnexpectedEOF {
				b.Fatalf("ReadFull: %v", rerr)
			}
			ct, encErr := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, stage[:n])
			if encErr != nil {
				b.Fatalf("Encrypt3x: %v", encErr)
			}
			lenBuf[0] = byte(len(ct) >> 24)
			lenBuf[1] = byte(len(ct) >> 16)
			lenBuf[2] = byte(len(ct) >> 8)
			lenBuf[3] = byte(len(ct))
			if _, werr := buf.Write(lenBuf[:]); werr != nil {
				b.Fatalf("Write length prefix: %v", werr)
			}
			if _, werr := buf.Write(ct); werr != nil {
				b.Fatalf("Write ciphertext: %v", werr)
			}
			if rerr == io.ErrUnexpectedEOF {
				break
			}
		}
	}
}

// BenchmarkTripleDecryptStreamUserLoop_Areion512_1024_64MB_C16MB
// measures the User-Driven Decrypt loop: the framed
// transcript is built once, and each iteration walks it via the
// 4-byte BE length-prefix frame, calling [Decrypt3x] per chunk.
func BenchmarkTripleDecryptStreamUserLoop_Areion512_1024_64MB_C16MB(b *testing.B) {
	const (
		bits      = 1024
		dataSize  = 64 << 20
		chunkSize = 16 << 20
	)
	ns, ls, ds1, ds2, ds3, ss1, ss2, ss3 := makeStreamTripleSeeds(b, bits, makeAreionSoEM512Pair)
	src := streamTriplePlaintext(b, dataSize)

	encBuf := bytes.NewBuffer(make([]byte, 0, 80<<20))
	{
		r := bytes.NewReader(src)
		stage := make([]byte, chunkSize)
		var lenBuf [4]byte
		for {
			n, rerr := io.ReadFull(r, stage)
			if rerr == io.EOF {
				break
			}
			if rerr != nil && rerr != io.ErrUnexpectedEOF {
				b.Fatalf("setup ReadFull: %v", rerr)
			}
			ct, encErr := Encrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, stage[:n])
			if encErr != nil {
				b.Fatalf("setup Encrypt3x: %v", encErr)
			}
			lenBuf[0] = byte(len(ct) >> 24)
			lenBuf[1] = byte(len(ct) >> 16)
			lenBuf[2] = byte(len(ct) >> 8)
			lenBuf[3] = byte(len(ct))
			encBuf.Write(lenBuf[:])
			encBuf.Write(ct)
			if rerr == io.ErrUnexpectedEOF {
				break
			}
		}
	}
	transcript := encBuf.Bytes()

	b.SetBytes(int64(dataSize))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := bytes.NewReader(transcript)
		buf := bytes.NewBuffer(make([]byte, 0, dataSize))
		var lenBuf [4]byte
		for {
			_, rerr := io.ReadFull(r, lenBuf[:])
			if rerr == io.EOF {
				break
			}
			if rerr != nil {
				b.Fatalf("ReadFull length: %v", rerr)
			}
			ctLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
			ct := make([]byte, ctLen)
			if _, rerr2 := io.ReadFull(r, ct); rerr2 != nil {
				b.Fatalf("ReadFull body: %v", rerr2)
			}
			pt, decErr := Decrypt3x512Cfg(nil, ns, ls, ds1, ds2, ds3, ss1, ss2, ss3, ct)
			if decErr != nil {
				b.Fatalf("Decrypt3x: %v", decErr)
			}
			buf.Write(pt)
		}
	}
}
