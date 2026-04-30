package macs

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// ─── KAT vectors ───────────────────────────────────────────────────

// TestKMAC256KAT bit-exactly cross-checks the shipped KMAC256(L=256)
// factory against vectors generated from pycryptodome 3.23.0
// (Crypto.Hash.KMAC256, NIST SP 800-185 reference implementation
// widely deployed in production cryptographic stacks). Every vector
// below uses the SP 800-185 Annex A canonical test key
// (K = bytes 0x40..0x5F, 32 bytes); messages and customizations
// follow Annex A samples 4, 5, 6 plus a degenerate empty-message
// case. The shipped factory uses L = 256 bits (32-byte output);
// NIST's published Annex A KAT samples are for L = 512 bits and
// KMAC's right_encode(L) absorption makes the two outputs
// deliberately unrelated, so we cross-check at the production L.
//
// Reproduce these vectors:
//
//	python3 -c "
//	from Crypto.Hash import KMAC256
//	key = bytes.fromhex('404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F')
//	mac = KMAC256.new(key=key, mac_len=32, custom=b'')
//	mac.update(bytes.fromhex('00010203'))
//	print(mac.hexdigest())
//	"
func TestKMAC256KAT(t *testing.T) {
	key := mustHex("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")

	type vec struct {
		name   string
		data   []byte
		custom string
		expect string
	}

	// Sample 6 message: 200 bytes 0x00..0xC7.
	sample6 := make([]byte, 0xC8)
	for i := range sample6 {
		sample6[i] = byte(i)
	}

	cases := []vec{
		{
			name:   "annex-A.4-sample4-no-custom-L256",
			data:   mustHex("00010203"),
			custom: "",
			expect: "b423798ac38d465560a058b982f56f7ff5d62a5cfa813ab8522998ed32e00a38",
		},
		{
			name:   "annex-A.4-sample5-tagged-L256",
			data:   mustHex("00010203"),
			custom: "My Tagged Application",
			expect: "f2d95c33c9a201eb10c524b9084b4bacae0092f869122df7d7870b92c842e05b",
		},
		{
			name:   "annex-A.4-sample6-long-tagged-L256",
			data:   sample6,
			custom: "My Tagged Application",
			expect: "6a188d60bb5f29cb5a8d132fb8ca2f710b74d8505cf6960f32ce88839ac69d4a",
		},
		{
			name:   "empty-message-no-custom-L256",
			data:   nil,
			custom: "",
			expect: "b0bd4891139d7a354fe4d068bf4b95ee0893f91f5788fc04df8e846446fa1de8",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mac, err := KMAC256WithCustomization(key, []byte(tc.custom))
			if err != nil {
				t.Fatalf("KMAC256WithCustomization: %v", err)
			}
			got := mac(tc.data)
			if hex.EncodeToString(got) != tc.expect {
				t.Fatalf("KMAC256(%s) mismatch:\n  got  %s\n  want %s",
					tc.name, hex.EncodeToString(got), tc.expect)
			}
		})
	}
}

// TestKMAC256Properties checks structural keyed-PRF invariants on
// top of the bit-exact KAT: same input ⇒ same output, customization
// changes output, key change changes output.
func TestKMAC256Properties(t *testing.T) {
	key := mustHex("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F")
	data := mustHex("00010203")

	mac, err := KMAC256(key)
	if err != nil {
		t.Fatal(err)
	}
	t1 := mac(data)
	t2 := mac(data)
	if !bytes.Equal(t1, t2) {
		t.Errorf("KMAC256 not deterministic: %x vs %x", t1, t2)
	}

	macCustom, err := KMAC256WithCustomization(key, []byte("My Tagged Application"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(t1, macCustom(data)) {
		t.Errorf("customization had no effect: tag identical with and without S")
	}

	keyAlt := append([]byte(nil), key...)
	keyAlt[0] ^= 0x01
	macAlt, _ := KMAC256(keyAlt)
	if bytes.Equal(t1, macAlt(data)) {
		t.Errorf("flipping key bit had no effect: tag identical")
	}
}

// TestHMACSHA256Vectors checks against RFC 4231 test cases.
func TestHMACSHA256Vectors(t *testing.T) {
	cases := []struct {
		name   string
		key    string // hex
		data   string // hex
		expect string // hex (32 bytes)
	}{
		{
			// RFC 4231 Test Case 1.
			name:   "rfc4231-tc1",
			key:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			data:   "4869205468657265", // "Hi There"
			expect: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
		},
		{
			// RFC 4231 Test Case 2 (key shorter than block — but stretched internally).
			name:   "rfc4231-tc2",
			key:    "4a656665", // "Jefe"
			data:   "7768617420646f2079612077616e7420666f72206e6f7468696e673f", // "what do ya want for nothing?"
			expect: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := mustHex(tc.key)
			data := mustHex(tc.data)
			// RFC 4231 vectors use deliberately short keys (4 bytes
			// in TC2) to exercise HMAC's internal zero-padding path.
			// HMACSHA256 itself accepts any non-empty key; the
			// 16-byte minimum lives only in the Make dispatcher.
			mac, err := HMACSHA256(key)
			if err != nil {
				t.Fatalf("HMACSHA256: %v", err)
			}
			got := mac(data)
			if hex.EncodeToString(got) != tc.expect {
				t.Fatalf("HMAC-SHA256(%s) mismatch:\n  got  %s\n  want %s",
					tc.name, hex.EncodeToString(got), tc.expect)
			}
		})
	}
}

// TestHMACBLAKE3KeyEnforcement verifies the 32-byte key requirement
// (an HMAC-BLAKE3 KAT against an external reference value would be
// nice but BLAKE3-keyed test vectors live in the upstream
// blake3.test_vectors.json which we do not vendor; the keyed-mode
// correctness is already covered by the upstream zeebo/blake3 tests).
func TestHMACBLAKE3KeyEnforcement(t *testing.T) {
	if _, err := HMACBLAKE3(make([]byte, 16)); err == nil {
		t.Fatal("HMACBLAKE3 with 16-byte key must error")
	}
	if _, err := HMACBLAKE3(make([]byte, 64)); err == nil {
		t.Fatal("HMACBLAKE3 with 64-byte key must error")
	}
	mac, err := HMACBLAKE3(make([]byte, 32))
	if err != nil {
		t.Fatalf("HMACBLAKE3 with 32-byte key: %v", err)
	}
	tag := mac([]byte("hello"))
	if len(tag) != 32 {
		t.Fatalf("HMACBLAKE3 tag size = %d, want 32", len(tag))
	}
}

// TestRegistryStable freezes the FFI ABI ordering: name, key size,
// tag size, minimum key bytes per slot.
func TestRegistryStable(t *testing.T) {
	want := []Spec{
		{Name: "kmac256", KeySize: 32, TagSize: 32, MinKeyBytes: 16},
		{Name: "hmac-sha256", KeySize: 32, TagSize: 32, MinKeyBytes: 16},
		{Name: "hmac-blake3", KeySize: 32, TagSize: 32, MinKeyBytes: 32},
	}
	if len(Registry) != len(want) {
		t.Fatalf("Registry len=%d, want %d", len(Registry), len(want))
	}
	for i := range want {
		if Registry[i] != want[i] {
			t.Errorf("Registry[%d] = %+v, want %+v", i, Registry[i], want[i])
		}
	}
}

// TestRegistryDispatcher exercises Make for each shipped name with a
// 32-byte key, plus a few error cases (unknown name, short key).
func TestRegistryDispatcher(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	for _, spec := range Registry {
		t.Run(spec.Name, func(t *testing.T) {
			mac, err := Make(spec.Name, key)
			if err != nil {
				t.Fatalf("Make(%s, 32b key): %v", spec.Name, err)
			}
			tag := mac([]byte("data"))
			if len(tag) != spec.TagSize {
				t.Errorf("tag len = %d, want %d", len(tag), spec.TagSize)
			}
		})
	}
	if _, err := Make("nonsense", key); err == nil {
		t.Error("Make(nonsense): expected error")
	}
	if _, err := Make("kmac256", key[:8]); err == nil {
		t.Error("Make(kmac256, 8-byte key): expected error")
	}
}

// TestStability verifies that repeated calls with the same key on
// the same data yield the same tag (the cached factory must be
// internally stateless across calls — apart from sync.Pool reuse).
func TestStability(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	for _, spec := range Registry {
		t.Run(spec.Name, func(t *testing.T) {
			mac, err := Make(spec.Name, key)
			if err != nil {
				t.Fatal(err)
			}
			data := []byte("repeat me")
			a := mac(data)
			b := mac(data)
			if !bytes.Equal(a, b) {
				t.Errorf("%s: repeated MAC differs", spec.Name)
			}
		})
	}
}

// ─── ITB Auth integration ──────────────────────────────────────────

// TestITBAuthIntegration round-trips EncryptAuthenticated{128,256,512}
// with each shipped MAC, then flips one bit in the ciphertext to
// confirm DecryptAuthenticated returns a MAC-failure error. This is
// the central regression test: the MAC closure must compose with the
// ITB Auth layer end to end across all three Seed widths.
//
// Note: hash factories in the hashes/ package carry per-instance
// random fixed keys, so the same Seed object must be reused for both
// encrypt and decrypt sides of the round trip. The width-specific
// helpers below build the seeds once and pass them through.
func TestITBAuthIntegration(t *testing.T) {
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	macKey := bytes.Repeat([]byte{0x77}, 32)

	hashByWidth := map[hashes.Width]string{
		hashes.W128: "siphash24",
		hashes.W256: "blake3",
		hashes.W512: "blake2b512",
	}

	for _, macSpec := range Registry {
		for _, w := range []hashes.Width{hashes.W128, hashes.W256, hashes.W512} {
			hashName := hashByWidth[w]
			t.Run(fmt.Sprintf("%s/%s", macSpec.Name, hashName), func(t *testing.T) {
				mac, err := Make(macSpec.Name, macKey)
				if err != nil {
					t.Fatalf("Make(%s): %v", macSpec.Name, err)
				}
				if err := authRoundTrip(w, hashName, mac, plaintext); err != nil {
					t.Fatalf("%s/%s: %v", macSpec.Name, hashName, err)
				}
			})
		}
	}
}

// authRoundTrip builds three seeds of the requested width, runs
// Encrypt → Decrypt with the supplied MAC, asserts the plaintext
// recovers, then flips one bit and asserts the decrypt rejects.
func authRoundTrip(w hashes.Width, hashName string, mac itb.MACFunc, plaintext []byte) error {
	switch w {
	case hashes.W128:
		ns, ds, ss, err := triple128(hashName, 1024)
		if err != nil {
			return err
		}
		ct, err := itb.EncryptAuthenticated128(ns, ds, ss, plaintext, mac)
		if err != nil {
			return fmt.Errorf("Encrypt: %w", err)
		}
		got, err := itb.DecryptAuthenticated128(ns, ds, ss, ct, mac)
		if err != nil {
			return fmt.Errorf("Decrypt: %w", err)
		}
		if !bytes.Equal(plaintext, got) {
			return fmt.Errorf("plaintext mismatch")
		}
		tampered := append([]byte(nil), ct...)
		// ITB scatters payload pixels around a startPixel offset
		// derived from startSeed + nonce; a single bit-flip at a
		// fixed container offset is therefore not guaranteed to
		// land in a payload pixel (random barrier-fill regions
		// surround the data region). To make the tamper test
		// deterministic, flip a contiguous span of bytes wide
		// enough to cover at least one full pixel (8 channels)
		// regardless of startPixel — flipping 256 bytes after the
		// header makes the false-negative probability negligible.
		// Default-config header layout: nonce(16) + width(2) + height(2).
		// These tests run under the default SetNonceBits(128); any
		// override would shift this offset (use itb.GetNonceBits()/8 + 4
		// when extending the test to non-default configurations).
		const tamperStart = 16 + 4
		tamperEnd := tamperStart + 256
		if tamperEnd > len(tampered) {
			tamperEnd = len(tampered)
		}
		for i := tamperStart; i < tamperEnd; i++ {
			tampered[i] ^= 0x01
		}
		if _, err := itb.DecryptAuthenticated128(ns, ds, ss, tampered, mac); err == nil {
			return fmt.Errorf("tampered ct was accepted")
		}
	case hashes.W256:
		ns, ds, ss, err := triple256(hashName, 1024)
		if err != nil {
			return err
		}
		ct, err := itb.EncryptAuthenticated256(ns, ds, ss, plaintext, mac)
		if err != nil {
			return fmt.Errorf("Encrypt: %w", err)
		}
		got, err := itb.DecryptAuthenticated256(ns, ds, ss, ct, mac)
		if err != nil {
			return fmt.Errorf("Decrypt: %w", err)
		}
		if !bytes.Equal(plaintext, got) {
			return fmt.Errorf("plaintext mismatch")
		}
		tampered := append([]byte(nil), ct...)
		// ITB scatters payload pixels around a startPixel offset
		// derived from startSeed + nonce; a single bit-flip at a
		// fixed container offset is therefore not guaranteed to
		// land in a payload pixel (random barrier-fill regions
		// surround the data region). To make the tamper test
		// deterministic, flip a contiguous span of bytes wide
		// enough to cover at least one full pixel (8 channels)
		// regardless of startPixel — flipping 256 bytes after the
		// header makes the false-negative probability negligible.
		// Default-config header layout: nonce(16) + width(2) + height(2).
		// These tests run under the default SetNonceBits(128); any
		// override would shift this offset (use itb.GetNonceBits()/8 + 4
		// when extending the test to non-default configurations).
		const tamperStart = 16 + 4
		tamperEnd := tamperStart + 256
		if tamperEnd > len(tampered) {
			tamperEnd = len(tampered)
		}
		for i := tamperStart; i < tamperEnd; i++ {
			tampered[i] ^= 0x01
		}
		if _, err := itb.DecryptAuthenticated256(ns, ds, ss, tampered, mac); err == nil {
			return fmt.Errorf("tampered ct was accepted")
		}
	case hashes.W512:
		ns, ds, ss, err := triple512(hashName, 1024)
		if err != nil {
			return err
		}
		ct, err := itb.EncryptAuthenticated512(ns, ds, ss, plaintext, mac)
		if err != nil {
			return fmt.Errorf("Encrypt: %w", err)
		}
		got, err := itb.DecryptAuthenticated512(ns, ds, ss, ct, mac)
		if err != nil {
			return fmt.Errorf("Decrypt: %w", err)
		}
		if !bytes.Equal(plaintext, got) {
			return fmt.Errorf("plaintext mismatch")
		}
		tampered := append([]byte(nil), ct...)
		// ITB scatters payload pixels around a startPixel offset
		// derived from startSeed + nonce; a single bit-flip at a
		// fixed container offset is therefore not guaranteed to
		// land in a payload pixel (random barrier-fill regions
		// surround the data region). To make the tamper test
		// deterministic, flip a contiguous span of bytes wide
		// enough to cover at least one full pixel (8 channels)
		// regardless of startPixel — flipping 256 bytes after the
		// header makes the false-negative probability negligible.
		// Default-config header layout: nonce(16) + width(2) + height(2).
		// These tests run under the default SetNonceBits(128); any
		// override would shift this offset (use itb.GetNonceBits()/8 + 4
		// when extending the test to non-default configurations).
		const tamperStart = 16 + 4
		tamperEnd := tamperStart + 256
		if tamperEnd > len(tampered) {
			tamperEnd = len(tampered)
		}
		for i := tamperStart; i < tamperEnd; i++ {
			tampered[i] ^= 0x01
		}
		if _, err := itb.DecryptAuthenticated512(ns, ds, ss, tampered, mac); err == nil {
			return fmt.Errorf("tampered ct was accepted")
		}
	default:
		return fmt.Errorf("unknown width %d", w)
	}
	return nil
}

func triple128(hashName string, keyBits int) (*itb.Seed128, *itb.Seed128, *itb.Seed128, error) {
	mk := func() (*itb.Seed128, error) {
		h, _, err := hashes.Make128(hashName)
		if err != nil {
			return nil, err
		}
		return itb.NewSeed128(keyBits, h)
	}
	a, err := mk()
	if err != nil {
		return nil, nil, nil, err
	}
	b, err := mk()
	if err != nil {
		return nil, nil, nil, err
	}
	c, err := mk()
	if err != nil {
		return nil, nil, nil, err
	}
	return a, b, c, nil
}

func triple256(hashName string, keyBits int) (*itb.Seed256, *itb.Seed256, *itb.Seed256, error) {
	mk := func() (*itb.Seed256, error) {
		h, b, _, err := hashes.Make256Pair(hashName)
		if err != nil {
			return nil, err
		}
		s, err := itb.NewSeed256(keyBits, h)
		if err != nil {
			return nil, err
		}
		if b != nil {
			s.BatchHash = b
		}
		return s, nil
	}
	a, err := mk()
	if err != nil {
		return nil, nil, nil, err
	}
	b, err := mk()
	if err != nil {
		return nil, nil, nil, err
	}
	c, err := mk()
	if err != nil {
		return nil, nil, nil, err
	}
	return a, b, c, nil
}

func triple512(hashName string, keyBits int) (*itb.Seed512, *itb.Seed512, *itb.Seed512, error) {
	mk := func() (*itb.Seed512, error) {
		h, b, _, err := hashes.Make512Pair(hashName)
		if err != nil {
			return nil, err
		}
		s, err := itb.NewSeed512(keyBits, h)
		if err != nil {
			return nil, err
		}
		if b != nil {
			s.BatchHash = b
		}
		return s, nil
	}
	a, err := mk()
	if err != nil {
		return nil, nil, nil, err
	}
	b, err := mk()
	if err != nil {
		return nil, nil, nil, err
	}
	c, err := mk()
	if err != nil {
		return nil, nil, nil, err
	}
	return a, b, c, nil
}

// mustHex decodes a hex string, panicking on error. Test-only helper.
func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
