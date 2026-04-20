// _parity_dump — emit (primitive, data_hex, seed_components, expected_lo_hex)
// triples that the Python chainhashes/ mirrors must reproduce bit-for-bit.
//
// Usage:
//   go run scripts/redteam/phase2_theory/chainhashes/_parity_dump/main.go
//
// Output: JSON array on stdout. One entry per (primitive, test_vector) pair.
// The Python side loads this via chainhashes/_parity_test.py and verifies
// `chainhash_lo(data, seed) == expected_lo` for every entry.
//
// Test vectors are deterministic (data + seed drawn from a fixed-seed PRNG)
// so the JSON dump is stable across runs — any non-match indicates a
// mirror divergence, not a randomness artefact.
package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
)

type entry struct {
	Primitive       string   `json:"primitive"`
	DataHex         string   `json:"data_hex"`
	SeedComponents []uint64 `json:"seed_components"`
	ExpectedLoHex   string   `json:"expected_lo_hex"`
	ExpectedHiHex   string   `json:"expected_hi_hex"`
}

// md5Hash128 duplicates redteam_test.go:md5Hash128 bit-for-bit. Kept
// in-file so this helper can be built as a standalone main without
// pulling the whole test package.
func md5Hash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	h := md5.New()
	var keyBuf [16]byte
	binary.LittleEndian.PutUint64(keyBuf[:8], seed0)
	binary.LittleEndian.PutUint64(keyBuf[8:], seed1)
	h.Write(keyBuf[:])
	h.Write(data)
	sum := h.Sum(nil)
	lo = binary.LittleEndian.Uint64(sum[:8])
	hi = binary.LittleEndian.Uint64(sum[8:])
	return
}

// chainHash128MD5 reproduces seed128.go:Seed128.ChainHash128 with MD5 as
// the inner primitive, for a fixed 16-component (1024-bit) seed.
func chainHash128MD5(data []byte, seed []uint64) (lo, hi uint64) {
	lo, hi = md5Hash128(data, seed[0], seed[1])
	for i := 2; i < len(seed); i += 2 {
		lo, hi = md5Hash128(data, seed[i]^lo, seed[i+1]^hi)
	}
	return
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return b
}

func randSeed16(rng *rand.Rand) []uint64 {
	s := make([]uint64, 16)
	for i := range s {
		s[i] = rng.Uint64()
	}
	return s
}

func main() {
	rng := rand.New(rand.NewSource(1))
	entries := []entry{}

	sizes := []int{0, 1, 16, 55, 64, 100, 1000}
	for _, sz := range sizes {
		data := randBytes(rng, sz)
		seed := randSeed16(rng)
		lo, hi := chainHash128MD5(data, seed)
		entries = append(entries, entry{
			Primitive:       "md5",
			DataHex:         hex.EncodeToString(data),
			SeedComponents:  seed,
			ExpectedLoHex:   fmt.Sprintf("%016x", lo),
			ExpectedHiHex:   fmt.Sprintf("%016x", hi),
		})
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entries); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		os.Exit(1)
	}
}
