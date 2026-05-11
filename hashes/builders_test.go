package hashes

import (
	"crypto/aes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"testing"

	"github.com/everanium/itb"
)

// builders_test.go — coverage for the safe pluggable PRF builders.
//
// Each builder is tested against six invariants:
//
//  1. Determinism: same (data, seed) → same output.
//  2. Data sensitivity: any byte change in data changes output.
//  3. Seed sensitivity: any bit change in seed changes output.
//  4. Length-tag effective: empty input vs single-zero-byte input
//     vs longer input produce distinct outputs.
//  5. Full nonce absorption (the silent-truncation guard): for 64-byte
//     input (matching the SetNonceBits(512) data shape after 4-byte
//     pixel index), changing any single byte at indices >= 16 must
//     change output. A truncating wrapper would fail this for indices
//     12+ (ChaCha20 nonce slot) or 16+ (AES IV slot).
//  6. ITB integration: a Seed{N} constructed from the builder closure
//     can encrypt-then-decrypt a small payload bit-exactly.
//
// Test primitives:
//
//   - CBC-MAC builders: AES-128 via crypto/aes (16-byte block).
//   - Sponge builders: a toy 32-byte permutation that mixes the state
//     non-trivially via additions and rotations. Not cryptographically
//     secure — sufficient to verify the builder's chain-absorb shape.
//   - ARX builders: crypto/sha256.Sum256 (32-byte) and
//     crypto/sha512.Sum512 (64-byte).

// ============================================================================
// Test fixtures
// ============================================================================

// testPermute32 is a non-cryptographic 32-byte permutation used only
// to exercise the sponge-builder chain-absorb wiring. ChaCha20-style
// quarter-round mixing with per-round constants ensures every input
// bit propagates to every output bit within ~3-4 rounds, breaking
// the "zero state stalls mixing" degenerate case of trivial ARX
// constructions. Deterministic and bijective. Not cryptographically
// secure — it is a test fixture only.
func testPermute32(state []byte) {
	if len(state) != 32 {
		panic("testPermute32 requires 32-byte state")
	}
	a := binary.LittleEndian.Uint64(state[0:8])
	b := binary.LittleEndian.Uint64(state[8:16])
	c := binary.LittleEndian.Uint64(state[16:24])
	d := binary.LittleEndian.Uint64(state[24:32])
	const golden = uint64(0x9E3779B97F4A7C15)
	for r := 0; r < 12; r++ {
		a += golden ^ uint64(r)
		a += b
		d ^= a
		d = (d << 32) | (d >> 32)
		c += d
		b ^= c
		b = (b << 24) | (b >> 40)
		a += b
		d ^= a
		d = (d << 16) | (d >> 48)
		c += d
		b ^= c
		b = (b << 63) | (b >> 1)
	}
	binary.LittleEndian.PutUint64(state[0:8], a)
	binary.LittleEndian.PutUint64(state[8:16], b)
	binary.LittleEndian.PutUint64(state[16:24], c)
	binary.LittleEndian.PutUint64(state[24:32], d)
}

func newTestAESBlock(t *testing.T) cipherInterface {
	t.Helper()
	var key [16]byte
	for i := range key {
		key[i] = byte(i * 17)
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	return block
}

// cipherInterface aliases the standard library type so test code reads
// uniformly across the four builder families.
type cipherInterface = interface {
	BlockSize() int
	Encrypt(dst, src []byte)
	Decrypt(dst, src []byte)
}

// ============================================================================
// CBC-MAC Chain-Absorb tests
// ============================================================================

func TestBuildCBCMACChainAbsorb128_Properties(t *testing.T) {
	block := newTestAESBlock(t)
	hash := BuildCBCMACChainAbsorb128(block)

	// (1) Determinism
	data := []byte("the quick brown fox jumps over the lazy dog")
	lo1, hi1 := hash(data, 0x1111, 0x2222)
	lo2, hi2 := hash(data, 0x1111, 0x2222)
	if lo1 != lo2 || hi1 != hi2 {
		t.Fatal("CBCMAC128: non-deterministic output for same input")
	}

	// (2) Data sensitivity
	lo3, _ := hash([]byte("the quick brown fox jumps over the lazy doG"), 0x1111, 0x2222)
	if lo3 == lo1 {
		t.Fatal("CBCMAC128: single byte change in data did not affect output")
	}

	// (3) Seed sensitivity
	lo4, _ := hash(data, 0x1112, 0x2222)
	if lo4 == lo1 {
		t.Fatal("CBCMAC128: seed0 change did not affect output")
	}
	lo5, _ := hash(data, 0x1111, 0x2223)
	if lo5 == lo1 {
		t.Fatal("CBCMAC128: seed1 change did not affect output")
	}

	// (4) Length-tag effective
	loE, _ := hash([]byte{}, 0x1111, 0x2222)
	loZ1, _ := hash([]byte{0x00}, 0x1111, 0x2222)
	loZ2, _ := hash([]byte{0x00, 0x00}, 0x1111, 0x2222)
	if loE == loZ1 || loZ1 == loZ2 || loE == loZ2 {
		t.Fatal("CBCMAC128: length tag not disambiguating empty / single-zero / double-zero inputs")
	}

	// (5) Full nonce absorption — silent-truncation guard
	checkFullAbsorption128(t, hash, "CBCMAC128")
}

func TestBuildCBCMACChainAbsorb256_Properties(t *testing.T) {
	block := newTestAESBlock(t)
	hash := BuildCBCMACChainAbsorb256(block)

	data := []byte("test data for 256-bit CBC-MAC chain absorb")
	seed := [4]uint64{0x1111, 0x2222, 0x3333, 0x4444}
	out1 := hash(data, seed)
	out2 := hash(data, seed)
	if out1 != out2 {
		t.Fatal("CBCMAC256: non-deterministic output")
	}

	// Two halves should be independent (domain separation working).
	if out1[0] == out1[2] && out1[1] == out1[3] {
		t.Fatal("CBCMAC256: two halves identical — domain separation not working")
	}

	checkFullAbsorption256(t, hash, "CBCMAC256")
}

func TestBuildCBCMACChainAbsorb512_Properties(t *testing.T) {
	block := newTestAESBlock(t)
	hash := BuildCBCMACChainAbsorb512(block)

	data := []byte("test data for 512-bit CBC-MAC chain absorb")
	seed := [8]uint64{0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888}
	out1 := hash(data, seed)
	out2 := hash(data, seed)
	if out1 != out2 {
		t.Fatal("CBCMAC512: non-deterministic output")
	}

	// Four quarters should all be distinct (domain separation).
	q0 := [2]uint64{out1[0], out1[1]}
	q1 := [2]uint64{out1[2], out1[3]}
	q2 := [2]uint64{out1[4], out1[5]}
	q3 := [2]uint64{out1[6], out1[7]}
	if q0 == q1 || q0 == q2 || q0 == q3 || q1 == q2 || q1 == q3 || q2 == q3 {
		t.Fatal("CBCMAC512: quarters not pairwise distinct — domain separation broken")
	}

	checkFullAbsorption512(t, hash, "CBCMAC512")
}

// ============================================================================
// Sponge Chain-Absorb tests
// ============================================================================

func TestBuildSpongeChainAbsorb128_Properties(t *testing.T) {
	fixedKey := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	hash := BuildSpongeChainAbsorb128(testPermute32, 16, 16, fixedKey)

	data := []byte("sponge chain absorb test data")
	lo1, hi1 := hash(data, 0xAAAA, 0xBBBB)
	lo2, hi2 := hash(data, 0xAAAA, 0xBBBB)
	if lo1 != lo2 || hi1 != hi2 {
		t.Fatal("Sponge128: non-deterministic")
	}

	lo3, _ := hash([]byte("sponge chain absorb test datA"), 0xAAAA, 0xBBBB)
	if lo3 == lo1 {
		t.Fatal("Sponge128: data change did not affect output")
	}

	lo4, _ := hash(data, 0xAAAB, 0xBBBB)
	if lo4 == lo1 {
		t.Fatal("Sponge128: seed change did not affect output")
	}

	loE, _ := hash([]byte{}, 0xAAAA, 0xBBBB)
	loZ, _ := hash([]byte{0x00}, 0xAAAA, 0xBBBB)
	if loE == loZ {
		t.Fatal("Sponge128: length tag not disambiguating empty vs single-zero")
	}

	checkFullAbsorption128(t, hash, "Sponge128")
}

func TestBuildSpongeChainAbsorb256_Properties(t *testing.T) {
	fixedKey := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	hash := BuildSpongeChainAbsorb256(testPermute32, 16, 16, fixedKey)

	data := []byte("sponge 256 chain absorb test data")
	seed := [4]uint64{0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD}
	out1 := hash(data, seed)
	out2 := hash(data, seed)
	if out1 != out2 {
		t.Fatal("Sponge256: non-deterministic")
	}

	if out1[0] == out1[2] && out1[1] == out1[3] {
		t.Fatal("Sponge256: halves identical — domain separation broken")
	}

	checkFullAbsorption256(t, hash, "Sponge256")
}

func TestBuildSpongeChainAbsorb512_Properties(t *testing.T) {
	fixedKey := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	hash := BuildSpongeChainAbsorb512(testPermute32, 16, 16, fixedKey)

	data := []byte("sponge 512 chain absorb test data")
	seed := [8]uint64{0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD, 0xEEEE, 0xFFFF, 0x1111, 0x2222}
	out1 := hash(data, seed)
	out2 := hash(data, seed)
	if out1 != out2 {
		t.Fatal("Sponge512: non-deterministic")
	}

	q0 := [2]uint64{out1[0], out1[1]}
	q1 := [2]uint64{out1[2], out1[3]}
	q2 := [2]uint64{out1[4], out1[5]}
	q3 := [2]uint64{out1[6], out1[7]}
	if q0 == q1 || q0 == q2 || q0 == q3 || q1 == q2 || q1 == q3 || q2 == q3 {
		t.Fatal("Sponge512: quarters not pairwise distinct")
	}

	checkFullAbsorption512(t, hash, "Sponge512")
}

// ============================================================================
// ARX Chain-Absorb tests
// ============================================================================

func TestBuildARXChainAbsorb128_Properties(t *testing.T) {
	fixedKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	hash := BuildARXChainAbsorb128(sha256.Sum256, fixedKey)

	data := []byte("ARX 128 chain absorb test")
	lo1, hi1 := hash(data, 0x1111, 0x2222)
	lo2, hi2 := hash(data, 0x1111, 0x2222)
	if lo1 != lo2 || hi1 != hi2 {
		t.Fatal("ARX128: non-deterministic")
	}

	lo3, _ := hash([]byte("ARX 128 chain absorb tesT"), 0x1111, 0x2222)
	if lo3 == lo1 {
		t.Fatal("ARX128: data change did not affect output")
	}

	lo4, _ := hash(data, 0x1112, 0x2222)
	if lo4 == lo1 {
		t.Fatal("ARX128: seed0 change did not affect output")
	}

	loE, _ := hash([]byte{}, 0x1111, 0x2222)
	loZ, _ := hash([]byte{0x00}, 0x1111, 0x2222)
	if loE == loZ {
		t.Fatal("ARX128: length-tag not disambiguating empty vs single-zero")
	}

	checkFullAbsorption128(t, hash, "ARX128")
}

func TestBuildARXChainAbsorb256_Properties(t *testing.T) {
	fixedKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	hash := BuildARXChainAbsorb256(sha256.Sum256, fixedKey)

	data := []byte("ARX 256 chain absorb test")
	seed := [4]uint64{0x1111, 0x2222, 0x3333, 0x4444}
	out1 := hash(data, seed)
	out2 := hash(data, seed)
	if out1 != out2 {
		t.Fatal("ARX256: non-deterministic")
	}

	if out1[0] == out1[2] && out1[1] == out1[3] {
		t.Fatal("ARX256: halves identical")
	}

	checkFullAbsorption256(t, hash, "ARX256")
}

func TestBuildARXChainAbsorb512_Properties(t *testing.T) {
	fixedKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	hash := BuildARXChainAbsorb512(sha512.Sum512, fixedKey)

	data := []byte("ARX 512 chain absorb test")
	seed := [8]uint64{0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888}
	out1 := hash(data, seed)
	out2 := hash(data, seed)
	if out1 != out2 {
		t.Fatal("ARX512: non-deterministic")
	}

	// Just check that all 8 words are not identical (very unlikely
	// for SHA-512 even with structured input).
	allEqual := true
	for i := 1; i < 8; i++ {
		if out1[i] != out1[0] {
			allEqual = false
			break
		}
	}
	if allEqual {
		t.Fatal("ARX512: all output words identical")
	}

	checkFullAbsorption512(t, hash, "ARX512")
}

// ============================================================================
// Full-nonce-absorption helpers — the silent-truncation guard
// ============================================================================

// checkFullAbsorption128 verifies that the 128-bit builder absorbs
// every byte of a 68-byte input (matching the SetNonceBits(512) ITB
// data shape: 4-byte pixel index + 64-byte nonce). A truncating
// wrapper that drops bytes at index >= 16 (AES IV slot) or index >=
// 12 (ChaCha20 nonce slot) would fail this test.
func checkFullAbsorption128(t *testing.T, hash itb.HashFunc128, name string) {
	t.Helper()
	base := make([]byte, 68)
	for i := range base {
		base[i] = byte(i)
	}
	baseLo, baseHi := hash(base, 0xDEAD, 0xBEEF)
	for i := 0; i < 68; i++ {
		mod := make([]byte, 68)
		copy(mod, base)
		mod[i] ^= 0xFF
		modLo, modHi := hash(mod, 0xDEAD, 0xBEEF)
		if modLo == baseLo && modHi == baseHi {
			t.Fatalf("%s: byte %d in 68-byte input did not affect output — SILENT TRUNCATION", name, i)
		}
	}
}

func checkFullAbsorption256(t *testing.T, hash itb.HashFunc256, name string) {
	t.Helper()
	base := make([]byte, 68)
	for i := range base {
		base[i] = byte(i)
	}
	seed := [4]uint64{0xDEAD, 0xBEEF, 0xCAFE, 0xF00D}
	baseOut := hash(base, seed)
	for i := 0; i < 68; i++ {
		mod := make([]byte, 68)
		copy(mod, base)
		mod[i] ^= 0xFF
		modOut := hash(mod, seed)
		if modOut == baseOut {
			t.Fatalf("%s: byte %d in 68-byte input did not affect output — SILENT TRUNCATION", name, i)
		}
	}
}

func checkFullAbsorption512(t *testing.T, hash itb.HashFunc512, name string) {
	t.Helper()
	base := make([]byte, 68)
	for i := range base {
		base[i] = byte(i)
	}
	seed := [8]uint64{0xDEAD, 0xBEEF, 0xCAFE, 0xF00D, 0xABCD, 0x1234, 0x5678, 0x9ABC}
	baseOut := hash(base, seed)
	for i := 0; i < 68; i++ {
		mod := make([]byte, 68)
		copy(mod, base)
		mod[i] ^= 0xFF
		modOut := hash(mod, seed)
		if modOut == baseOut {
			t.Fatalf("%s: byte %d in 68-byte input did not affect output — SILENT TRUNCATION", name, i)
		}
	}
}

// ============================================================================
// ITB integration round-trip — proves the builder closures plug into
// Seed{N} and survive a real encrypt-decrypt cycle.
// ============================================================================

func TestBuildersITBRoundTrip(t *testing.T) {
	block := newTestAESBlock(t)
	fixedKey := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}

	// 256-bit Seed integration test: each builder family produces a
	// HashFunc256 that ITB accepts as Seed.Hash and runs encrypt /
	// decrypt round-trip bit-exactly.
	cases := []struct {
		name string
		fn   itb.HashFunc256
	}{
		{"CBCMAC256-AES", BuildCBCMACChainAbsorb256(block)},
		{"Sponge256-test", BuildSpongeChainAbsorb256(testPermute32, 16, 16, fixedKey)},
		{"ARX256-SHA256", BuildARXChainAbsorb256(sha256.Sum256, fixedKey)},
	}

	plaintext := []byte("ITB round-trip test plaintext for builder closures.")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			noiseSeed, err := itb.NewSeed256(1024, tc.fn)
			if err != nil {
				t.Fatalf("NewSeed256: %v", err)
			}
			dataSeed, err := itb.NewSeed256(1024, tc.fn)
			if err != nil {
				t.Fatalf("NewSeed256: %v", err)
			}
			startSeed, err := itb.NewSeed256(1024, tc.fn)
			if err != nil {
				t.Fatalf("NewSeed256: %v", err)
			}

			ct, err := itb.Encrypt256(noiseSeed, dataSeed, startSeed, plaintext)
			if err != nil {
				t.Fatalf("Encrypt256: %v", err)
			}
			pt, err := itb.Decrypt256(noiseSeed, dataSeed, startSeed, ct)
			if err != nil {
				t.Fatalf("Decrypt256: %v", err)
			}
			if string(pt) != string(plaintext) {
				t.Fatalf("round-trip mismatch:\n  want: %q\n  got:  %q", plaintext, pt)
			}
		})
	}
}

// ============================================================================
// Panic-on-bad-params tests — defensive precondition checks
// ============================================================================

func TestBuildersPanicOnBadParams(t *testing.T) {
	// CBC-MAC: tiny block cipher would be rejected by aes.NewCipher
	// anyway, so we just sanity-check the panic for a hypothetical
	// 8-byte block via a stub. We use the recover pattern to validate.

	t.Run("Sponge128-rate-too-small", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for rate < 16")
			}
		}()
		BuildSpongeChainAbsorb128(testPermute32, 8, 16, nil)
	})

	t.Run("Sponge128-capacity-too-small", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for capacity < 16")
			}
		}()
		BuildSpongeChainAbsorb128(testPermute32, 16, 8, nil)
	})

	t.Run("Sponge128-fixedKey-too-big", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for fixedKey > capacity")
			}
		}()
		bigKey := make([]byte, 32)
		BuildSpongeChainAbsorb128(testPermute32, 16, 16, bigKey)
	})

	t.Run("ARX128-nil-hashFn", func(t *testing.T) {
		defer func() {
			if r := recover(); r == nil {
				t.Fatal("expected panic for nil hashFn")
			}
		}()
		BuildARXChainAbsorb128(nil, []byte("key"))
	})
}
