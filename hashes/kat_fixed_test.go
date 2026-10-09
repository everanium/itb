// Construction-regression KAT vectors for PRF-grade
// primitives in the registry. Each primitive has one frozen
// (key, data, seed) triple and one frozen hex digest; the test
// verifies the production single-arm closure reproduces the digest
// bit-exact.
//
// Scope. These vectors detect drift in the construction itself —
// chunk size, lenTag positioning, key-prepend vs key-XOR order,
// seed-mix arithmetic, length-pad bytes, output byte order. Any
// production change that yields a different digest for the same
// input fails the test even when the underlying primitive
// remains intact.
//
// Out of scope. These vectors do NOT certify conformance with RFC /
// NIST canonical primitives. The constructions wrapped here are
// described in hashes/CONSTRUCTIONS.md. For primitive math conformance
// against the canonical RFCs / NIST specs, refer to the upstream
// library tests:
//
//   - third/goaes (vendored go-aes subset, SoEM22) — Areion paper vectors
//   - golang.org/x/crypto/blake2b — RFC 7693 vectors
//   - golang.org/x/crypto/blake2s — RFC 7693 vectors
//   - github.com/zeebo/blake3 — official BLAKE3 reference vectors
//   - crypto/aes — NIST FIPS-197 vectors
//   - github.com/dchest/siphash — official SipHash test vectors
//   - golang.org/x/crypto/chacha20 — RFC 8439 vectors
//
// The primitive-math layer is the upstream libraries' responsibility
// (and they carry RFC-vector KAT for that purpose); this file pins
// the ITB-construction wrapping around those primitives.
//
// Regeneration. After a deliberate construction change, the frozen
// digests must be re-baked. Set ITB_KAT_GENERATE=1 and run:
//
//	ITB_KAT_GENERATE=1 go test -v -run TestFixedKATGenerate ./hashes/
//
// Copy each printed line into fixedKATVectors below. Do NOT rebake
// without first reasoning about which construction component changed
// — silent rebaking destroys the regression-detection value.
package hashes

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
)

// fixedKATVector is one frozen construction-regression KAT.
type fixedKATVector struct {
	name       string // registry key
	dataLen    int    // canonical data length
	seedFlavor int    // canonicalSeed* selector
	expected   string // hex of the production single arm output
}

// Vectors in canonical primitive order (the order from REDTEAM.md's
// hash matrix; CRC128 / FNV-1a are below-spec lab helpers, not
// PRF-grade — they live in the test stress harness, not the registry).
//
// dataLen=36 is chosen because:
//
//   - it is one of the three batched fast-path lengths (20 / 36 / 68);
//   - 36 > chunkSize=24 forces the multi-round CBC-MAC chain in
//     Areion-SoEM-256 and AES-CMAC, and three slot blocks in ChaCha20
//     (key-chaining path exercised);
//   - 36 < chunkSize=56 keeps Areion-SoEM-512 in the single-round
//     fast path;
//   - 36 < 64 keeps BLAKE2b-512 inside the seed-injection zero-pad
//     branch, exercising the pad logic.
//
// seedFlavor=3 (high-entropy pseudo-random) stresses every state slot
// of every width.
var fixedKATVectors = []fixedKATVector{
	{"areion256", 36, 3, "1298daeac5af3c3dbe8dd5f0f8cc4db9bda6eb4d89470cb8fa0bc8931cb7ec07"},
	{"areion512", 36, 3, "9d67f7066c4611f7563ad5f4fb740e8c7c7febb4356eee7984a646b4d2adcde60c9487948f74e245d00541ca71a97e811fb7ff2f4f265a0489f407d6369ad225"},
	{"blake2b256", 36, 3, "fa255838d97272b1303d7dcff33268499ea0adf108f9b421891bef38b8b38211"},
	{"blake2b512", 36, 3, "aff41328166cef8f4b1ef8f246cf9fd00c3094ffa0bfb2b78a7d8055fad14cbb53935f074e7f57f03c45660cc64ca4c37903f5c20085b3768738a25821a3164a"},
	{"blake2s", 36, 3, "2086005154f33d8292797b7951fea69b2805d7de82a534e3f09ec7ad04a88e88"},
	{"blake3", 36, 3, "83b2dd6bfa674378681acec053aa4da70b1a830f4d09a6fb767bc76f90d407bc"},
	{"aescmac", 36, 3, "78c789d0614ce11c4af42e3cf358ab03"},
	{"siphash24", 36, 3, "9b6300d1be6dad7001187452459eb8b6"},
	{"chacha20", 36, 3, "cffa99b9d6d06cea14a3e2fab23f19506b3d6daa85835eeec49ff4fb84cb600b"},
}

// TestFixedKAT runs each frozen vector through the production single
// arm and verifies bit-exact output against the expected hex digest.
// Failure means either the production construction has changed (rebake
// vectors after auditing the change) or the primitive is broken.
func TestFixedKAT(t *testing.T) {
	for _, v := range fixedKATVectors {
		v := v
		t.Run(v.name, func(t *testing.T) {
			data := canonicalData(v.dataLen)
			got := computeFixedKATSingle(v.name, data, v.seedFlavor)
			gotHex := hex.EncodeToString(got)
			if gotHex != v.expected {
				t.Errorf("\n  primitive: %s\n  data_len:  %d\n  seed_flav: %d\n  expected:  %s\n  got:       %s",
					v.name, v.dataLen, v.seedFlavor, v.expected, gotHex)
			}
		})
	}
}

// TestFixedKATGenerate prints the current production single-arm
// output for each vector. Gated behind ITB_KAT_GENERATE=1 so it does
// not fire during normal `go test ./...` runs.
//
// Run as:
//
//	ITB_KAT_GENERATE=1 go test -v -run TestFixedKATGenerate ./hashes/
//
// The printed lines are drop-in replacements for the entries in
// fixedKATVectors above.
func TestFixedKATGenerate(t *testing.T) {
	if os.Getenv("ITB_KAT_GENERATE") != "1" {
		t.Skip("set ITB_KAT_GENERATE=1 to print regenerated vectors")
	}
	t.Log("// re-baked vectors — copy into fixedKATVectors:")
	for _, v := range fixedKATVectors {
		data := canonicalData(v.dataLen)
		got := computeFixedKATSingle(v.name, data, v.seedFlavor)
		t.Logf(`{%q, %d, %d, %q},`, v.name, v.dataLen, v.seedFlavor, hex.EncodeToString(got))
	}
}

// computeFixedKATSingle dispatches to the correct production factory
// for the named primitive, builds a canonical fixed key from
// canonicalKey32 / canonicalKey64, and returns the digest bytes in
// little-endian order matching the natural state-marshal layout of
// each primitive.
func computeFixedKATSingle(name string, data []byte, seedFlavor int) []byte {
	switch name {
	case "areion256":
		k := canonicalKey32()
		single, _ := Areion256PairWithKey(k)
		s := canonicalSeed4(seedFlavor)
		return fixedKATMarshal4(single(data, s))
	case "areion512":
		k := canonicalKey64()
		single, _ := Areion512PairWithKey(k)
		s := canonicalSeed8(seedFlavor)
		return fixedKATMarshal8(single(data, s))
	case "blake2b256":
		k := canonicalKey32()
		single := BLAKE2b256WithKey(k)
		s := canonicalSeed4(seedFlavor)
		return fixedKATMarshal4(single(data, s))
	case "blake2b512":
		k := canonicalKey64()
		single := BLAKE2b512WithKey(k)
		s := canonicalSeed8(seedFlavor)
		return fixedKATMarshal8(single(data, s))
	case "blake2s":
		k := canonicalKey32()
		single := BLAKE2sWithKey(k)
		s := canonicalSeed4(seedFlavor)
		return fixedKATMarshal4(single(data, s))
	case "blake3":
		k := canonicalKey32()
		single := BLAKE3WithKey(k)
		s := canonicalSeed4(seedFlavor)
		return fixedKATMarshal4(single(data, s))
	case "aescmac":
		full := canonicalKey32()
		var k [16]byte
		copy(k[:], full[:16])
		single := AESCMACWithKey(k)
		s := canonicalSeed2(seedFlavor)
		lo, hi := single(data, s[0], s[1])
		var out [16]byte
		binary.LittleEndian.PutUint64(out[0:], lo)
		binary.LittleEndian.PutUint64(out[8:], hi)
		return out[:]
	case "siphash24":
		single := SipHash24()
		s := canonicalSeed2(seedFlavor)
		lo, hi := single(data, s[0], s[1])
		var out [16]byte
		binary.LittleEndian.PutUint64(out[0:], lo)
		binary.LittleEndian.PutUint64(out[8:], hi)
		return out[:]
	case "chacha20":
		k := canonicalKey32()
		single := ChaCha20WithKey(k)
		s := canonicalSeed4(seedFlavor)
		return fixedKATMarshal4(single(data, s))
	}
	panic("unknown primitive: " + name)
}

func fixedKATMarshal4(s [4]uint64) []byte {
	var out [32]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], s[i])
	}
	return out[:]
}

func fixedKATMarshal8(s [8]uint64) []byte {
	var out [64]byte
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], s[i])
	}
	return out[:]
}
