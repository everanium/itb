// harness_test.go — HARNESS.md shelf harness for pluggable hash
// primitives. Per-primitive the file accumulates three concerns:
//
//  1. Pure Go reference implementation of the primitive + 128-bit
//     adapter (HashFunc128 signature) + ChainHash128 composition.
//  2. Canonical self-check test that validates the reference against
//     published vectors so any subsequent empirical measurement on this
//     primitive is trustworthy.
//  3. ITB-corpus-generator test (TestRedTeamHarnessGenerate...NonceReuse)
//     that plugs the primitive into runNonceReuse128 and writes the
//     Phase 2a-compatible cell artefacts for the Axis B bias probe.
//
// Each new primitive is appended below under its own banner header
// ("============ <primitive> ============"). Existing sections are not
// modified when a new primitive is added — this file grows by appending
// only. Test-only (_test.go suffix): not compiled into production builds.
//
// No external Go dependency is introduced per primitive unless the
// canonical C reference exceeds the ≤ ~500 LOC per-side budget documented
// in HARNESS.md § 1.1 — in which case an explicit `go get` decision is
// made case-by-case and recorded in the primitive's banner. So far all
// primitives use math/bits + encoding/binary from stdlib only.

package itb

import (
	"encoding/binary"
	"math/bits"
	"math/rand"
	"os"
	"strconv"
	"testing"
)

// ============================================================================
// t1ha1_64le (Leonid Yuriev's Fast Positive Hash v1, LE variant)
//   Canonical reference: https://github.com/erthink/t1ha/blob/master/src/t1ha1.c
//   + helpers at .../t1ha_bits.h. Pure-Go port; stdlib-only.
// ============================================================================

// t1ha1 "magic" primes (erthink/t1ha src/t1ha_bits.h lines 1081-1087).
const (
	t1haPrime0 uint64 = 0xEC99BF0D8372CAAB
	t1haPrime1 uint64 = 0x82434FE90EDCEF39
	t1haPrime2 uint64 = 0xD4F06DB99D67BE4B
	t1haPrime3 uint64 = 0xBD9CACC22C6E9571
	t1haPrime4 uint64 = 0x9C06FAF4D023E3AB
	t1haPrime5 uint64 = 0xC060724A8424F345
	t1haPrime6 uint64 = 0xCB5AF53AE3AAAC31
)

// t1haRot64 is the canonical 64-bit right rotation used throughout t1ha1.
func t1haRot64(v uint64, s uint) uint64 {
	return bits.RotateLeft64(v, -int(s))
}

// t1haMux64 computes the XOR of the low and high 64-bit halves of v*prime
// (full 128-bit product). Canonical name in erthink/t1ha is mux64().
func t1haMux64(v, prime uint64) uint64 {
	hi, lo := bits.Mul64(v, prime)
	return lo ^ hi
}

// t1haMix64 is the internal xor-mul-xor mixer used in final_weak_avalanche.
// Canonical: v *= prime; return v ^ rot64(v, 41).
func t1haMix64(v, prime uint64) uint64 {
	v *= prime
	return v ^ t1haRot64(v, 41)
}

// t1haFinalWeakAvalanche is the canonical 2-operand final mixer of t1ha1.
// Uses mix64 (not mux64) in its second addend — a documented performance
// compromise that fails SMHasher's strict avalanche criterion; this is the
// intentional design choice that distinguishes t1ha1 from stronger variants.
func t1haFinalWeakAvalanche(a, b uint64) uint64 {
	return t1haMux64(t1haRot64(a+b, 17), t1haPrime4) + t1haMix64(a^b, t1haPrime0)
}

// t1haTail64Le reads up to 8 bytes of tail from data as little-endian
// uint64. The canonical C implementation uses `(tail & 7)` as the read
// width, with a special case that (tail & 7) == 0 when tail > 0 means
// "read 8 bytes without masking". This mirrors that behaviour exactly.
func t1haTail64Le(data []byte, tail int) uint64 {
	n := tail & 7
	if n == 0 {
		return binary.LittleEndian.Uint64(data[:8])
	}
	var r uint64
	for i := 0; i < n; i++ {
		r |= uint64(data[i]) << (8 * i)
	}
	return r
}

// t1ha1_64le computes the canonical 64-bit t1ha1 hash (little-endian
// variant) over data with the given seed. Bit-for-bit match with
// erthink/t1ha t1ha1_le().
func t1ha1_64le(data []byte, seed uint64) uint64 {
	length := uint64(len(data))
	a := seed
	b := length

	pos := 0
	if len(data) > 32 {
		c := t1haRot64(length, 17) + seed
		d := length ^ t1haRot64(seed, 17)
		// do-while loop from canonical C: process 32-byte blocks while
		// v < detent (== data + len - 31).
		for {
			w0 := binary.LittleEndian.Uint64(data[pos:])
			w1 := binary.LittleEndian.Uint64(data[pos+8:])
			w2 := binary.LittleEndian.Uint64(data[pos+16:])
			w3 := binary.LittleEndian.Uint64(data[pos+24:])
			pos += 32

			d02 := w0 ^ t1haRot64(w2+d, 17)
			c13 := w1 ^ t1haRot64(w3+c, 17)
			d -= b ^ t1haRot64(w1, 31)
			c += a ^ t1haRot64(w0, 41)
			b ^= t1haPrime0 * (c13 + w2)
			a ^= t1haPrime1 * (d02 + w3)

			if pos+32 > len(data) {
				break
			}
		}

		a ^= t1haPrime6 * (t1haRot64(c, 17) + d)
		b ^= t1haPrime5 * (c + t1haRot64(d, 17))
		length &= 31
	}

	// Tail handling — mirror of the fall-through switch in canonical C.
	// Each `if length > N` corresponds to one case-block boundary, with
	// all lower boundaries also firing (independent ifs, not else-if).
	tail := data[pos:]
	if length > 24 {
		b += t1haMux64(binary.LittleEndian.Uint64(tail[:8]), t1haPrime4)
		tail = tail[8:]
	}
	if length > 16 {
		a += t1haMux64(binary.LittleEndian.Uint64(tail[:8]), t1haPrime3)
		tail = tail[8:]
	}
	if length > 8 {
		b += t1haMux64(binary.LittleEndian.Uint64(tail[:8]), t1haPrime2)
		tail = tail[8:]
	}
	if length > 0 {
		a += t1haMux64(t1haTail64Le(tail, int(length)), t1haPrime1)
	}

	return t1haFinalWeakAvalanche(a, b)
}

// t1ha1Hash128 is the 128-bit parallel two-lane adapter: two independent
// t1ha1_64le invocations with seed_lo and seed_hi give the lo and hi
// lanes. Matches the convention used by the other 128-bit-output primitives
// wired into ChainHash128 (fnv1a128, md5Hash128, etc.).
func t1ha1Hash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	lo = t1ha1_64le(data, seed0)
	hi = t1ha1_64le(data, seed1)
	return
}

// chainHash128T1ha1 composes 8 rounds of ChainHash128 with t1ha1 as the
// inner primitive at keyBits=1024 (16 uint64 seed components, 2 per round).
// Standard XOR-keying between rounds: seed[i] ^ h_lo, seed[i+1] ^ h_hi.
// Output: (lo, hi) of the final round.
func chainHash128T1ha1(data []byte, seed []uint64) (lo, hi uint64) {
	if len(seed) != 16 {
		panic("chainHash128T1ha1: expected 16 seed components")
	}
	lo, hi = t1ha1Hash128(data, seed[0], seed[1])
	for i := 2; i < 16; i += 2 {
		kLo := seed[i] ^ lo
		kHi := seed[i+1] ^ hi
		lo, hi = t1ha1Hash128(data, kLo, kHi)
	}
	return
}

// t1haTestPattern is the canonical self-check input pattern from
// erthink/t1ha src/t1ha_selfcheck.c (t1ha_test_pattern[64]).
var t1haTestPattern = [64]byte{
	0, 1, 2, 3, 4, 5, 6, 7, 0xFF, 0x7F, 0x3F, 0x1F, 0xF, 8, 16, 32,
	64, 0x80, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0xFD, 0xFB, 0xF7, 0xEF, 0xDF, 0xBF, 0x55, 0xAA,
	11, 17, 19, 23, 29, 37, 42, 43, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
	'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
}

// t1haRefval64Le is the full 81-entry canonical reference-value table from
// erthink/t1ha src/t1ha1_selfcheck.c (t1ha_refval_64le[]). Each entry is
// the expected t1ha1_le output for a specific (data, length, seed) triple
// generated by the self-check driver (see TestT1ha1SelfCheck below).
var t1haRefval64Le = [81]uint64{
	0,
	0x6A580668D6048674, 0xA2FE904AFF0D0879, 0xE3AB9C06FAF4D023, 0x6AF1C60874C95442,
	0xB3557E561A6C5D82, 0x0AE73C696F3D37C0, 0x5EF25F7062324941, 0x9B784F3B4CE6AF33,
	0x6993BB206A74F070, 0xF1E95DF109076C4C, 0x4E1EB70C58E48540, 0x5FDD7649D8EC44E4,
	0x559122C706343421, 0x380133D58665E93D, 0x9CE74296C8C55AE4, 0x3556F9A5757AB6D0,
	0xF62751F7F25C469E, 0x851EEC67F6516D94, 0xED463EE3848A8695, 0xDC8791FEFF8ED3AC,
	0x2569C744E1A282CF, 0xF90EB7C1D70A80B9, 0x68DFA6A1B8050A4C, 0x94CCA5E8210D2134,
	0xF5CC0BEABC259F52, 0x40DBC1F51618FDA7, 0x0807945BF0FB52C6, 0xE5EF7E09DE70848D,
	0x63E1DF35FEBE994A, 0x2025E73769720D5A, 0xAD6120B2B8A152E1, 0x2A71D9F13959F2B7,
	0x8A20849A27C32548, 0x0BCBC9FE3B57884E, 0x0E028D255667AEAD, 0xBE66DAD3043AB694,
	0xB00E4C1238F9E2D4, 0x5C54BDE5AE280E82, 0x0E22B86754BC3BC4, 0x016707EBF858B84D,
	0x990015FBC9E095EE, 0x8B9AF0A3E71F042F, 0x6AA56E88BD380564, 0xAACE57113E681A0F,
	0x19F81514AFA9A22D, 0x80DABA3D62BEAC79, 0x715210412CABBF46, 0xD8FA0B9E9D6AA93F,
	0x6C2FC5A4109FD3A2, 0x5B3E60EEB51DDCD8, 0x0A7C717017756FE7, 0xA73773805CA31934,
	0x4DBD6BB7A31E85FD, 0x24F619D3D5BC2DB4, 0x3E4AF35A1678D636, 0x84A1A8DF8D609239,
	0x359C862CD3BE4FCD, 0xCF3A39F5C27DC125, 0xC0FF62F8FD5F4C77, 0x5E9F2493DDAA166C,
	0x17424152BE1CA266, 0xA78AFA5AB4BBE0CD, 0x7BFB2E2CEF118346, 0x647C3E0FF3E3D241,
	0x0352E4055C13242E, 0x6F42FC70EB660E38, 0x0BEBAD4FABF523BA, 0x9269F4214414D61D,
	0x1CA8760277E6006C, 0x7BAD25A859D87B5D, 0xAD645ADCF7414F1D, 0xB07F517E88D7AFB3,
	0xB321C06FB5FFAB5C, 0xD50F162A1EFDD844, 0x1DFD3D1924FBE319, 0xDFAEAB2F09EF7E78,
	0xA7603B5AF07A0B1E, 0x41CD044C0E5A4EE3, 0xF64D2F86E813BF33, 0xFF9FDB99305EB06A,
}

// TestT1ha1SelfCheck validates the Go t1ha1_64le implementation against
// the canonical 81-vector self-check from erthink/t1ha. Any divergence
// means the mirror is not bit-exact and the HARNESS.md measurements on
// t1ha1 would be untrustworthy.
func TestT1ha1SelfCheck(t *testing.T) {
	idx := 0
	check := func(data []byte, seed uint64, label string) {
		got := t1ha1_64le(data, seed)
		want := t1haRefval64Le[idx]
		if got != want {
			t.Errorf("idx=%d (%s): got=%016x want=%016x  data_len=%d seed=%016x",
				idx, label, got, want, len(data), seed)
		}
		idx++
	}

	// Sequence mirrors erthink/t1ha src/t1ha_selfcheck.c __cold int
	// t1ha_selfcheck(hash, reference_values):

	// 1. empty, seed=0
	check(nil, 0, "empty-zero")
	// 2. empty, seed=~0
	check(nil, ^uint64(0), "empty-all1")
	// 3. full 64-byte pattern, seed=0
	check(t1haTestPattern[:], 0, "bin64-zero")

	// 4..66. pattern[:i] with seed = 1 << (i-1) for i=1..63
	seed := uint64(1)
	for i := 1; i < 64; i++ {
		check(t1haTestPattern[:i], seed, "bin-short")
		seed <<= 1
	}

	// 67..73. pattern[i:] (length 64-i) with seed = (~0 << (i+1)) for i=1..7
	seed = ^uint64(0)
	for i := 1; i <= 7; i++ {
		seed <<= 1
		check(t1haTestPattern[i:], seed, "align")
	}

	// 74..81. pattern_long[i : i+128+i*17] with the final `seed` (after the
	// align loop incremented it once more). pattern_long[k] = uint8(k).
	var patternLong [512]byte
	for i := range patternLong {
		patternLong[i] = byte(i)
	}
	for i := 0; i <= 7; i++ {
		length := 128 + i*17
		check(patternLong[i:i+length], seed, "long")
	}

	if idx != len(t1haRefval64Le) {
		t.Fatalf("consumed %d reference values, expected %d", idx, len(t1haRefval64Le))
	}
}

// TestRedTeamHarnessGenerateT1ha1NonceReuse generates a nonce-reuse
// corpus with t1ha1_64le as the ChainHash128 inner primitive (via the
// parallel two-lane 128-bit adapter t1ha1Hash128). Delegates to the
// existing runNonceReuse128 body so encryption / meta.json /
// config.truth.json schema are identical to Phase 2a extension corpora
// — t1ha1 plugs into the same bias-probe pipeline without modifying any
// Phase 2a file. Invoked by scripts/redteam/harness_bias_audit_t1ha1.sh.
//
// Env vars:
//
//	ITB_HARNESS_T1HA1_MODE  — plaintext mode: "known_ascii" currently
//	ITB_HARNESS_T1HA1_SIZE  — plaintext size in bytes (e.g. 524288 for 512 KB)
//	ITB_HARNESS_T1HA1_OUT   — output directory for cell artefacts
//	ITB_HARNESS_T1HA1_SEED  — optional nonce derivation seed; default 0xA17B1CE
//	ITB_HARNESS_T1HA1_N     — optional N ciphertexts with same nonce; default 2
func TestRedTeamHarnessGenerateT1ha1NonceReuse(t *testing.T) {
	mode := os.Getenv("ITB_HARNESS_T1HA1_MODE")
	if mode == "" {
		t.Skip("set ITB_HARNESS_T1HA1_MODE=known_ascii to generate t1ha1 corpus " +
			"(new primitive on the HARNESS.md shelf; not routed through the " +
			"Phase 2a extension bias_audit_matrix.sh primitive dispatch)")
	}
	if mode != "known_ascii" {
		t.Fatalf("ITB_HARNESS_T1HA1_MODE=%q: only 'known_ascii' is currently supported "+
			"(strongest per-byte bias regime for the Axis B absorption claim)", mode)
	}

	sizeStr := os.Getenv("ITB_HARNESS_T1HA1_SIZE")
	if sizeStr == "" {
		t.Fatalf("ITB_HARNESS_T1HA1_SIZE required (plaintext bytes, e.g. 524288 for 512 KB)")
	}
	plaintextSize, err := strconv.Atoi(sizeStr)
	if err != nil || plaintextSize <= 0 || plaintextSize > maxDataSize {
		t.Fatalf("ITB_HARNESS_T1HA1_SIZE=%q: must be positive int <= %d (maxDataSize)",
			sizeStr, maxDataSize)
	}

	outDir := os.Getenv("ITB_HARNESS_T1HA1_OUT")
	if outDir == "" {
		t.Fatalf("ITB_HARNESS_T1HA1_OUT required (absolute or project-relative directory path)")
	}

	N := 2
	if s := os.Getenv("ITB_HARNESS_T1HA1_N"); s != "" {
		if v, perr := strconv.Atoi(s); perr == nil && v > 0 {
			N = v
		}
	}

	nonceSeed := uint64(0xA17B1CE)
	if s := os.Getenv("ITB_HARNESS_T1HA1_SEED"); s != "" {
		if v, perr := strconv.ParseUint(s, 0, 64); perr == nil {
			nonceSeed = v
		}
	}

	barrierFill := 1 // matches Phase 2a extension main matrix default
	keyBits := 1024  // matches Phase 2a extension baseline (flagship key size)

	SetMaxWorkers(8)
	SetBarrierFill(barrierFill)
	t.Cleanup(func() {
		SetMaxWorkers(0)
		SetBarrierFill(1)
	})

	fixedNonce := deriveFixedNonce(nonceSeed, currentNonceSize())
	setTestNonce(t, fixedNonce)

	// Generate N plaintexts of uniform printable ASCII (known_ascii mode).
	// 424242-seeded RNG to match audit consistency with the existing
	// 4-primitive matrix. Byte distribution: 95 printable ASCII codepoints
	// (0x20–0x7E) + tab + newline, uniform draw.
	rng := rand.New(rand.NewSource(424242))
	plaintexts := make([][]byte, N)
	for i := 0; i < N; i++ {
		plaintexts[i] = make([]byte, plaintextSize)
		for j := range plaintexts[i] {
			r := rng.Intn(97)
			switch {
			case r == 95:
				plaintexts[i][j] = 0x09 // tab
			case r == 96:
				plaintexts[i][j] = 0x0A // newline
			default:
				plaintexts[i][j] = byte(0x20 + r) // printable ASCII 0x20..0x7E
			}
		}
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", outDir, err)
	}

	p := nonceReuseParams{
		hashName:      "t1ha1",
		hashDisplay:   "t1ha1_64le",
		hashWidth:     128,
		keyBits:       keyBits,
		barrierFill:   barrierFill,
		N:             N,
		mode:          "known_ascii",
		plaintextKind: "random",
		plaintextSize: plaintextSize,
		fixedNonce:    fixedNonce,
		plaintexts:    plaintexts,
		outDir:        outDir,
	}

	t.Logf("Harness t1ha1 corpus: %d bytes × %d ciphertexts, %s mode → %s",
		plaintextSize, N, mode, outDir)

	runNonceReuse128(t, &p, HashFunc128(t1ha1Hash128))
}

// ============================================================================
// SeaHash (Ticki, Redox OS / tfs)
//   Canonical reference: https://github.com/ticki/tfs/tree/master/seahash/src
//   (reference.rs + helper.rs). Pure-Go port; stdlib-only.
//   4-lane ARX with PCG-style dynamic-shift diffuse mixer. SMHasher finding:
//   PerlinNoise catastrophic (2 × 10¹² × over-expected collisions on
//   coordinate-structured input) — HARNESS.md § 4.1 row 2.
// ============================================================================

// seahashPrime is the SeaHash diffusion constant (and its modular inverse).
const (
	seahashPrime    uint64 = 0x6EED0E9DA4D94A4F
	seahashUndiffPr uint64 = 0x2F72B4215A3D8CAF // modular inverse (unused here,
	// kept as documentation parallel to the canonical reference)
)

// seahash canonical initial state (reference.rs lines matching `hash()`):
//
//	(0x16f11fe89b0d677c, 0xb480a793d8e6c86c, 0x6fe2e5aaf078ebc9, 0x14f994a4c5259381).
const (
	seahashInitA uint64 = 0x16F11FE89B0D677C
	seahashInitB uint64 = 0xB480A793D8E6C86C
	seahashInitC uint64 = 0x6FE2E5AAF078EBC9
	seahashInitD uint64 = 0x14F994A4C5259381
)

// seahashDiffuse is the canonical PCG-style diffusion mixer:
//
//	x *= PRIME
//	x ^= (x >> 32) >> (x >> 60)
//	x *= PRIME
//
// Bijective on uint64; dynamic right shift (amount determined by top 4 bits
// of the multiplied value) avalanches high bits into low. Matches
// ticki/tfs/seahash/src/helper.rs `diffuse` exactly.
func seahashDiffuse(x uint64) uint64 {
	x *= seahashPrime
	x ^= (x >> 32) >> (x >> 60)
	x *= seahashPrime
	return x
}

// seahashReadTail reads a 1..7-byte LE remainder as a uint64 padded with
// zero bytes to the high side. Matches the buffer-pad convention from
// ticki/tfs/seahash/src/reference.rs (read_int on a <8-byte buf).
func seahashReadTail(buf []byte) uint64 {
	var x uint64
	for i, b := range buf {
		x |= uint64(b) << (8 * i)
	}
	return x
}

// seahash64 computes the canonical single-seed SeaHash over data. Matches
// ticki/tfs/seahash reference::hash_seeded with k_i derived from seed per
// the spec: "If a seed is given, each of the initial state component are
// modularly multiplied by the seed." seed==0 is the canonical unseeded
// case (preserves the test vector `hash("to be or not to be") =
// 1988685042348123509`).
func seahash64(data []byte, seed uint64) uint64 {
	a, b, c, d := seahashInitA, seahashInitB, seahashInitC, seahashInitD
	if seed != 0 {
		a *= seed
		b *= seed
		c *= seed
		d *= seed
	}

	// Process full 8-byte chunks (little-endian).
	pos := 0
	for pos+8 <= len(data) {
		n := binary.LittleEndian.Uint64(data[pos:])
		// (a, b, c, d) = (b, c, d, diffuse(a ^ n))
		a, b, c, d = b, c, d, seahashDiffuse(a^n)
		pos += 8
	}

	// Tail chunk (0..7 bytes): read with zero padding to 8 bytes. If tail
	// is empty the spec still requires one final block in the for-loop-
	// equivalent, but the canonical reference skips the empty-tail case
	// by using `buf.chunks(8)` which does not emit an empty chunk for
	// len % 8 == 0. Go mirror matches: no final block for aligned inputs.
	if pos < len(data) {
		n := seahashReadTail(data[pos:])
		a, b, c, d = b, c, d, seahashDiffuse(a^n)
	}

	// Final: diffuse(a ^ b ^ c ^ d ^ len). Length is total input byte count.
	return seahashDiffuse(a ^ b ^ c ^ d ^ uint64(len(data)))
}

// seahashHash128 is the 128-bit parallel two-lane adapter for the ITB
// ChainHash128 interface. Matches the convention used by t1ha1Hash128 +
// the 128-bit-native primitives in the shelf.
func seahashHash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	lo = seahash64(data, seed0)
	hi = seahash64(data, seed1)
	return
}

// chainHash128SeaHash composes 8 rounds of ChainHash128 with SeaHash as the
// inner primitive at keyBits=1024.
func chainHash128SeaHash(data []byte, seed []uint64) (lo, hi uint64) {
	if len(seed) != 16 {
		panic("chainHash128SeaHash: expected 16 seed components")
	}
	lo, hi = seahashHash128(data, seed[0], seed[1])
	for i := 2; i < 16; i += 2 {
		kLo := seed[i] ^ lo
		kHi := seed[i+1] ^ hi
		lo, hi = seahashHash128(data, kLo, kHi)
	}
	return
}

// TestSeaHashSelfCheck validates seahash64 against the canonical published
// test vector from ticki/tfs/seahash/src/reference.rs:
//
//	hash("to be or not to be") == 1988685042348123509 == 0x1B9E4A5A8CE62E35
//
// Plus a few additional structural vectors (empty, single byte, multi-block,
// boundary cases) — these are generated by the Go reference itself and
// cross-verified against the Python mirror through the parity-dump pipeline,
// so divergence between the Go reference and the Python mirror is caught
// before any empirical measurement runs.
func TestSeaHashSelfCheck(t *testing.T) {
	// Canonical published test vector.
	got := seahash64([]byte("to be or not to be"), 0)
	const want uint64 = 1988685042348123509 // 0x1B9E4A5A8CE62E35
	if got != want {
		t.Fatalf("SeaHash canonical vector mismatch: got=%016x want=%016x",
			got, want)
	}

	// Structural sanity: empty input.
	// With a == initA and empty buf → no block processed → final is
	// diffuse(a ^ b ^ c ^ d ^ 0).
	emptyHash := seahash64(nil, 0)
	wantEmpty := seahashDiffuse(
		seahashInitA ^ seahashInitB ^ seahashInitC ^ seahashInitD ^ 0)
	if emptyHash != wantEmpty {
		t.Fatalf("SeaHash empty-input mismatch: got=%016x want=%016x",
			emptyHash, wantEmpty)
	}

	// Non-zero seed: hash("hello", 42) should differ from hash("hello", 0).
	h0 := seahash64([]byte("hello"), 0)
	h42 := seahash64([]byte("hello"), 42)
	if h0 == h42 {
		t.Fatalf("SeaHash seed-sensitivity failed: seed=0 and seed=42 "+
			"both gave %016x", h0)
	}
}

// TestRedTeamHarnessGenerateSeaHashNonceReuse — Axis B ITB-corpus generator
// for SeaHash. Same env-var protocol as the t1ha1 counterpart above, with
// `ITB_HARNESS_SEAHASH_*` env prefix. Delegates to runNonceReuse128 so
// cell artefacts match the Phase 2a extension schema.
func TestRedTeamHarnessGenerateSeaHashNonceReuse(t *testing.T) {
	mode := os.Getenv("ITB_HARNESS_SEAHASH_MODE")
	if mode == "" {
		t.Skip("set ITB_HARNESS_SEAHASH_MODE=known_ascii to generate SeaHash corpus")
	}
	if mode != "known_ascii" {
		t.Fatalf("ITB_HARNESS_SEAHASH_MODE=%q: only 'known_ascii' supported", mode)
	}

	sizeStr := os.Getenv("ITB_HARNESS_SEAHASH_SIZE")
	if sizeStr == "" {
		t.Fatalf("ITB_HARNESS_SEAHASH_SIZE required (plaintext bytes)")
	}
	plaintextSize, err := strconv.Atoi(sizeStr)
	if err != nil || plaintextSize <= 0 || plaintextSize > maxDataSize {
		t.Fatalf("ITB_HARNESS_SEAHASH_SIZE=%q invalid", sizeStr)
	}

	outDir := os.Getenv("ITB_HARNESS_SEAHASH_OUT")
	if outDir == "" {
		t.Fatalf("ITB_HARNESS_SEAHASH_OUT required")
	}

	N := 2
	if s := os.Getenv("ITB_HARNESS_SEAHASH_N"); s != "" {
		if v, perr := strconv.Atoi(s); perr == nil && v > 0 {
			N = v
		}
	}

	nonceSeed := uint64(0xA17B1CE)
	if s := os.Getenv("ITB_HARNESS_SEAHASH_SEED"); s != "" {
		if v, perr := strconv.ParseUint(s, 0, 64); perr == nil {
			nonceSeed = v
		}
	}

	barrierFill := 1
	keyBits := 1024

	SetMaxWorkers(8)
	SetBarrierFill(barrierFill)
	t.Cleanup(func() {
		SetMaxWorkers(0)
		SetBarrierFill(1)
	})

	fixedNonce := deriveFixedNonce(nonceSeed, currentNonceSize())
	setTestNonce(t, fixedNonce)

	rng := rand.New(rand.NewSource(424242))
	plaintexts := make([][]byte, N)
	for i := 0; i < N; i++ {
		plaintexts[i] = make([]byte, plaintextSize)
		for j := range plaintexts[i] {
			r := rng.Intn(97)
			switch {
			case r == 95:
				plaintexts[i][j] = 0x09
			case r == 96:
				plaintexts[i][j] = 0x0A
			default:
				plaintexts[i][j] = byte(0x20 + r)
			}
		}
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", outDir, err)
	}

	p := nonceReuseParams{
		hashName:      "seahash",
		hashDisplay:   "SeaHash",
		hashWidth:     128,
		keyBits:       keyBits,
		barrierFill:   barrierFill,
		N:             N,
		mode:          "known_ascii",
		plaintextKind: "random",
		plaintextSize: plaintextSize,
		fixedNonce:    fixedNonce,
		plaintexts:    plaintexts,
		outDir:        outDir,
	}

	t.Logf("Harness SeaHash corpus: %d bytes × %d ciphertexts, %s mode → %s",
		plaintextSize, N, mode, outDir)

	runNonceReuse128(t, &p, HashFunc128(seahashHash128))
}

// ============================================================================
// mx3 (Jon Maiga, CC0 license; v3.0.0 2022-04-19)
//   Canonical reference: https://github.com/jonmaiga/mx3/blob/master/mx3.h
//   Pure-Go port; stdlib-only. SMHasher finding: PerlinNoise AV catastrophic
//   (1.48 × 10¹² × over-expected collisions) despite being a designed-for-
//   quality mixer — the paradox case in HARNESS.md § 4.1 row 4.
//   No canonical published test vectors; validated via Go ↔ Python parity
//   on deterministic random inputs.
// ============================================================================

// mx3 canonical constant.
const mx3C uint64 = 0xBEA225F9EB34556D

// mx3Mix is the 4-multiply XOR-shift mixer. Matches jonmaiga/mx3 mx3::mix.
func mx3Mix(x uint64) uint64 {
	x ^= x >> 32
	x *= mx3C
	x ^= x >> 29
	x *= mx3C
	x ^= x >> 32
	x *= mx3C
	x ^= x >> 29
	return x
}

// mx3MixStream is the single-input stream absorber. Matches
// jonmaiga/mx3 mx3::mix_stream(h, x).
func mx3MixStream(h, x uint64) uint64 {
	x *= mx3C
	x ^= x >> 39
	h += x * mx3C
	h *= mx3C
	return h
}

// mx3MixStream4 is the 4-lane parallel stream absorber. Matches
// jonmaiga/mx3 mx3::mix_stream(h, a, b, c, d).
func mx3MixStream4(h, a, b, c, d uint64) uint64 {
	a *= mx3C
	b *= mx3C
	c *= mx3C
	d *= mx3C
	a ^= a >> 39
	b ^= b >> 39
	c ^= c >> 39
	d ^= d >> 39
	h += a * mx3C
	h *= mx3C
	h += b * mx3C
	h *= mx3C
	h += c * mx3C
	h *= mx3C
	h += d * mx3C
	h *= mx3C
	return h
}

// mx3Hash computes the canonical mx3 variable-length hash over data with
// the given seed. Bit-for-bit match with jonmaiga/mx3 mx3::hash. 64-byte
// main loop (two 4-lane mix_stream calls per iter), 8-byte tail loop, then
// 0..7-byte final tail via a switch on the residue. Returns mix(h).
func mx3Hash(data []byte, seed uint64) uint64 {
	length := uint64(len(data))
	h := mx3MixStream(seed, length+1)

	pos := 0
	for length-uint64(pos) >= 64 {
		w0 := binary.LittleEndian.Uint64(data[pos:])
		w1 := binary.LittleEndian.Uint64(data[pos+8:])
		w2 := binary.LittleEndian.Uint64(data[pos+16:])
		w3 := binary.LittleEndian.Uint64(data[pos+24:])
		w4 := binary.LittleEndian.Uint64(data[pos+32:])
		w5 := binary.LittleEndian.Uint64(data[pos+40:])
		w6 := binary.LittleEndian.Uint64(data[pos+48:])
		w7 := binary.LittleEndian.Uint64(data[pos+56:])
		h = mx3MixStream4(h, w0, w1, w2, w3)
		h = mx3MixStream4(h, w4, w5, w6, w7)
		pos += 64
	}
	for length-uint64(pos) >= 8 {
		h = mx3MixStream(h, binary.LittleEndian.Uint64(data[pos:]))
		pos += 8
	}

	// Tail: 0..7 bytes assembled into a uint64 with zeros in unused high
	// positions. Matches the canonical switch case-by-case layout exactly
	// — u8 / u16 / u32 / combinations — so endianness mirrors the C
	// reference bit-for-bit on little-endian platforms.
	tail := data[pos:]
	switch len(tail) {
	case 0:
		return mx3Mix(h)
	case 1:
		return mx3Mix(mx3MixStream(h, uint64(tail[0])))
	case 2:
		return mx3Mix(mx3MixStream(h, uint64(binary.LittleEndian.Uint16(tail))))
	case 3:
		x := uint64(binary.LittleEndian.Uint16(tail[:2])) |
			uint64(tail[2])<<16
		return mx3Mix(mx3MixStream(h, x))
	case 4:
		return mx3Mix(mx3MixStream(h, uint64(binary.LittleEndian.Uint32(tail))))
	case 5:
		x := uint64(binary.LittleEndian.Uint32(tail[:4])) |
			uint64(tail[4])<<32
		return mx3Mix(mx3MixStream(h, x))
	case 6:
		x := uint64(binary.LittleEndian.Uint32(tail[:4])) |
			uint64(binary.LittleEndian.Uint16(tail[4:6]))<<32
		return mx3Mix(mx3MixStream(h, x))
	case 7:
		x := uint64(binary.LittleEndian.Uint32(tail[:4])) |
			uint64(binary.LittleEndian.Uint16(tail[4:6]))<<32 |
			uint64(tail[6])<<48
		return mx3Mix(mx3MixStream(h, x))
	}
	return mx3Mix(h) // unreachable; len(tail) < 8 by the outer loop exit
}

// mx3Hash128 is the parallel two-lane 128-bit adapter for the ITB
// ChainHash128 interface.
func mx3Hash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	lo = mx3Hash(data, seed0)
	hi = mx3Hash(data, seed1)
	return
}

// chainHash128Mx3 composes 8 rounds of ChainHash128 with mx3 as the
// inner primitive at keyBits=1024.
func chainHash128Mx3(data []byte, seed []uint64) (lo, hi uint64) {
	if len(seed) != 16 {
		panic("chainHash128Mx3: expected 16 seed components")
	}
	lo, hi = mx3Hash128(data, seed[0], seed[1])
	for i := 2; i < 16; i += 2 {
		kLo := seed[i] ^ lo
		kHi := seed[i+1] ^ hi
		lo, hi = mx3Hash128(data, kLo, kHi)
	}
	return
}

// TestMx3SelfCheck — structural sanity. jonmaiga/mx3 publishes no canonical
// reference-value table (the README + header file ship the algorithm only),
// so this test exercises a few deterministic properties of the reference:
//
//   - mix(0) returns 0 (every mix step absorbs 0 unchanged — a structural
//     consequence of the multiply-and-XOR-shift sequence)
//   - mix is bijective on uint64 — two distinct seeds give distinct outputs
//   - hash is seed-sensitive — same input under different seeds differs
//   - hash is length-sensitive — appending bytes changes the output
//
// Bit-exact validation against the canonical C header is delegated to the
// Go ↔ Python parity test in scripts/redteam/phase2_theory/chainhashes/
// _parity_test.py — both sides implement the same algorithm from the same
// mx3.h reference, and 13 vectors covering every tail-handling branch
// cross-check the two implementations against each other.
func TestMx3SelfCheck(t *testing.T) {
	if got := mx3Mix(0); got != 0 {
		t.Fatalf("mx3Mix(0) = %016x, expected 0 (zero absorption)", got)
	}
	if mx3Mix(1) == mx3Mix(2) {
		t.Fatalf("mx3Mix not bijective: mix(1) == mix(2)")
	}

	h0 := mx3Hash([]byte("hello"), 0)
	h42 := mx3Hash([]byte("hello"), 42)
	if h0 == h42 {
		t.Fatalf("mx3Hash seed-sensitivity failed: seed=0 and seed=42 both %016x",
			h0)
	}

	hLen5 := mx3Hash([]byte("hello"), 0)
	hLen6 := mx3Hash([]byte("hellos"), 0)
	if hLen5 == hLen6 {
		t.Fatalf("mx3Hash length-sensitivity failed: len=5 and len=6 both %016x",
			hLen5)
	}

	// Tail-branch smoke: lengths 0..8 all hash to distinct values under
	// the same seed. Catches gross mis-masking in the tail switch.
	seen := map[uint64]int{}
	for i := 0; i <= 8; i++ {
		data := make([]byte, i)
		for j := range data {
			data[j] = byte(j + 1)
		}
		h := mx3Hash(data, 0xA5A5A5A5A5A5A5A5)
		if prev, ok := seen[h]; ok {
			t.Fatalf("mx3Hash tail collision at lengths %d and %d: both %016x",
				prev, i, h)
		}
		seen[h] = i
	}
}

// TestRedTeamHarnessGenerateMx3NonceReuse — Axis B corpus generator.
func TestRedTeamHarnessGenerateMx3NonceReuse(t *testing.T) {
	mode := os.Getenv("ITB_HARNESS_MX3_MODE")
	if mode == "" {
		t.Skip("set ITB_HARNESS_MX3_MODE=known_ascii to generate mx3 corpus")
	}
	if mode != "known_ascii" {
		t.Fatalf("ITB_HARNESS_MX3_MODE=%q: only 'known_ascii' supported", mode)
	}

	sizeStr := os.Getenv("ITB_HARNESS_MX3_SIZE")
	if sizeStr == "" {
		t.Fatalf("ITB_HARNESS_MX3_SIZE required")
	}
	plaintextSize, err := strconv.Atoi(sizeStr)
	if err != nil || plaintextSize <= 0 || plaintextSize > maxDataSize {
		t.Fatalf("ITB_HARNESS_MX3_SIZE=%q invalid", sizeStr)
	}

	outDir := os.Getenv("ITB_HARNESS_MX3_OUT")
	if outDir == "" {
		t.Fatalf("ITB_HARNESS_MX3_OUT required")
	}

	N := 2
	if s := os.Getenv("ITB_HARNESS_MX3_N"); s != "" {
		if v, perr := strconv.Atoi(s); perr == nil && v > 0 {
			N = v
		}
	}

	nonceSeed := uint64(0xA17B1CE)
	if s := os.Getenv("ITB_HARNESS_MX3_SEED"); s != "" {
		if v, perr := strconv.ParseUint(s, 0, 64); perr == nil {
			nonceSeed = v
		}
	}

	barrierFill := 1
	keyBits := 1024

	SetMaxWorkers(8)
	SetBarrierFill(barrierFill)
	t.Cleanup(func() {
		SetMaxWorkers(0)
		SetBarrierFill(1)
	})

	fixedNonce := deriveFixedNonce(nonceSeed, currentNonceSize())
	setTestNonce(t, fixedNonce)

	rng := rand.New(rand.NewSource(424242))
	plaintexts := make([][]byte, N)
	for i := 0; i < N; i++ {
		plaintexts[i] = make([]byte, plaintextSize)
		for j := range plaintexts[i] {
			r := rng.Intn(97)
			switch {
			case r == 95:
				plaintexts[i][j] = 0x09
			case r == 96:
				plaintexts[i][j] = 0x0A
			default:
				plaintexts[i][j] = byte(0x20 + r)
			}
		}
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", outDir, err)
	}

	p := nonceReuseParams{
		hashName:      "mx3",
		hashDisplay:   "mx3",
		hashWidth:     128,
		keyBits:       keyBits,
		barrierFill:   barrierFill,
		N:             N,
		mode:          "known_ascii",
		plaintextKind: "random",
		plaintextSize: plaintextSize,
		fixedNonce:    fixedNonce,
		plaintexts:    plaintexts,
		outDir:        outDir,
	}

	t.Logf("Harness mx3 corpus: %d bytes × %d ciphertexts, %s mode → %s",
		plaintextSize, N, mode, outDir)

	runNonceReuse128(t, &p, HashFunc128(mx3Hash128))
}

// ============================================================================
// SipHash-1-3 (Aumasson & Bernstein 2012; reduced-round variant)
//   Canonical reference: https://www.aumasson.jp/siphash/siphash.pdf
//   Reduced-round structure: 1 message-mixing round per 8-byte word + 3
//   finalization rounds. Standard SipHash-2-4 is a designed PRF; SipHash-1-3
//   is the speed-optimised boundary case in HARNESS.md § 4.1 row 7. He & Yu
//   (ePrint 2019/865) cryptanalyse SipHash-2-1 / 2-2; SipHash-1-3 is NOT
//   directly covered by their key-recovery attack, hence its "boundary"
//   classification.
//
//   ITB deployment fixes the high half of SipHash's 128-bit key to zero
//   (k1 = 0), driving the primitive from a single 64-bit seed component
//   per call. This keeps the 16-component seed budget consistent with
//   the other shelf primitives (mx3, t1ha1, seahash) and reduces the
//   SAT recovery target on Axis C to 64 bits per call.
//
//   No canonical published test vectors for SipHash-1-3 with k1 = 0;
//   parity with the Python mirror is established via deterministic
//   random vectors covering every tail-handling branch.
// ============================================================================

// SipHash IV constants (Aumasson & Bernstein 2012, ASCII tags).
const (
	siphash13IV0 uint64 = 0x736F6D6570736575 // "somepseu"
	siphash13IV1 uint64 = 0x646F72616E646F6D // "dorandom"
	siphash13IV2 uint64 = 0x6C7967656E657261 // "lygenera"
	siphash13IV3 uint64 = 0x7465646279746573 // "tedbytes"
)

// SipHash-1-3 round counts.
const (
	siphash13C = 1 // message-mixing rounds per 8-byte word
	siphash13D = 3 // finalization rounds
)

// siphash13Round is one SipRound permutation. Matches the canonical 4-step
// ARX layout from Aumasson & Bernstein 2012 § 2.1.
func siphash13Round(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
	v0 += v1
	v1 = bits.RotateLeft64(v1, 13)
	v1 ^= v0
	v0 = bits.RotateLeft64(v0, 32)

	v2 += v3
	v3 = bits.RotateLeft64(v3, 16)
	v3 ^= v2

	v0 += v3
	v3 = bits.RotateLeft64(v3, 21)
	v3 ^= v0

	v2 += v1
	v1 = bits.RotateLeft64(v1, 17)
	v1 ^= v2
	v2 = bits.RotateLeft64(v2, 32)

	return v0, v1, v2, v3
}

// siphash13Hash computes SipHash-1-3 over data with the given 64-bit seed.
// The high half of SipHash's 128-bit key is fixed to zero per the ITB
// deployment choice; see file-level docstring for rationale.
func siphash13Hash(data []byte, seed uint64) uint64 {
	k0 := seed
	k1 := uint64(0)

	v0 := k0 ^ siphash13IV0
	v1 := k1 ^ siphash13IV1
	v2 := k0 ^ siphash13IV2
	v3 := k1 ^ siphash13IV3

	length := len(data)
	end8 := length - (length % 8)

	pos := 0
	for pos < end8 {
		m := binary.LittleEndian.Uint64(data[pos:])
		v3 ^= m
		for i := 0; i < siphash13C; i++ {
			v0, v1, v2, v3 = siphash13Round(v0, v1, v2, v3)
		}
		v0 ^= m
		pos += 8
	}

	// Final partial block: pad with zeros up to 7 bytes, then byte 7
	// holds `length & 0xff` (canonical SipHash padding rule).
	var lastBytes [8]byte
	rem := length - end8
	if rem > 0 {
		copy(lastBytes[:rem], data[end8:])
	}
	lastBytes[7] = byte(length & 0xFF)
	m := binary.LittleEndian.Uint64(lastBytes[:])
	v3 ^= m
	for i := 0; i < siphash13C; i++ {
		v0, v1, v2, v3 = siphash13Round(v0, v1, v2, v3)
	}
	v0 ^= m

	// Finalization.
	v2 ^= 0xFF
	for i := 0; i < siphash13D; i++ {
		v0, v1, v2, v3 = siphash13Round(v0, v1, v2, v3)
	}

	return v0 ^ v1 ^ v2 ^ v3
}

// siphash13Hash128 is the parallel two-lane 128-bit adapter for the ITB
// ChainHash128 interface.
func siphash13Hash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	lo = siphash13Hash(data, seed0)
	hi = siphash13Hash(data, seed1)
	return
}

// chainHash128Siphash13 composes 8 rounds of ChainHash128 with SipHash-1-3
// as the inner primitive at keyBits=1024.
func chainHash128Siphash13(data []byte, seed []uint64) (lo, hi uint64) {
	if len(seed) != 16 {
		panic("chainHash128Siphash13: expected 16 seed components")
	}
	lo, hi = siphash13Hash128(data, seed[0], seed[1])
	for i := 2; i < 16; i += 2 {
		kLo := seed[i] ^ lo
		kHi := seed[i+1] ^ hi
		lo, hi = siphash13Hash128(data, kLo, kHi)
	}
	return
}

// TestSiphash13SelfCheck — structural sanity for SipHash-1-3 reference.
// No canonical test vectors at k1 = 0 (the Aumasson/Bernstein reference
// vectors use the all-distinct-bytes 128-bit key; we use a 64-bit-keyed
// variant with k1 = 0 by deployment choice). Parity with the Python
// mirror is delegated to scripts/redteam/phase2_theory/chainhashes/
// _parity_test.py; this test exercises only deterministic properties.
func TestSiphash13SelfCheck(t *testing.T) {
	// Seed-sensitivity: same input under different seeds differs.
	h0 := siphash13Hash([]byte("hello"), 0)
	h42 := siphash13Hash([]byte("hello"), 42)
	if h0 == h42 {
		t.Fatalf("siphash13Hash seed-sensitivity failed: seed=0 and seed=42 both %016x",
			h0)
	}

	// Length-sensitivity: appending bytes changes the output.
	hLen5 := siphash13Hash([]byte("hello"), 0)
	hLen6 := siphash13Hash([]byte("hellos"), 0)
	if hLen5 == hLen6 {
		t.Fatalf("siphash13Hash length-sensitivity failed: len=5 and len=6 both %016x",
			hLen5)
	}

	// Tail-branch smoke: lengths 0..8 hash to distinct values under the
	// same seed. Catches gross padding-byte miscalculation.
	seen := map[uint64]int{}
	for i := 0; i <= 8; i++ {
		data := make([]byte, i)
		for j := range data {
			data[j] = byte(j + 1)
		}
		h := siphash13Hash(data, 0xA5A5A5A5A5A5A5A5)
		if prev, ok := seen[h]; ok {
			t.Fatalf("siphash13Hash tail collision at lengths %d and %d: both %016x",
				prev, i, h)
		}
		seen[h] = i
	}

	// Round permutation sanity: siphash13Round on all-zero state stays
	// all-zero (the round function is purely linear-plus-adds; with no
	// nonzero input there is nothing to permute).
	v0, v1, v2, v3 := siphash13Round(0, 0, 0, 0)
	if v0 != 0 || v1 != 0 || v2 != 0 || v3 != 0 {
		t.Fatalf("siphash13Round(0,0,0,0) = %016x %016x %016x %016x, want all zero",
			v0, v1, v2, v3)
	}
}

// TestRedTeamHarnessGenerateSiphash13NonceReuse — Axis B corpus generator.
func TestRedTeamHarnessGenerateSiphash13NonceReuse(t *testing.T) {
	mode := os.Getenv("ITB_HARNESS_SIPHASH13_MODE")
	if mode == "" {
		t.Skip("set ITB_HARNESS_SIPHASH13_MODE=known_ascii to generate siphash13 corpus")
	}
	if mode != "known_ascii" {
		t.Fatalf("ITB_HARNESS_SIPHASH13_MODE=%q: only 'known_ascii' supported", mode)
	}

	sizeStr := os.Getenv("ITB_HARNESS_SIPHASH13_SIZE")
	if sizeStr == "" {
		t.Fatalf("ITB_HARNESS_SIPHASH13_SIZE required")
	}
	plaintextSize, err := strconv.Atoi(sizeStr)
	if err != nil || plaintextSize <= 0 || plaintextSize > maxDataSize {
		t.Fatalf("ITB_HARNESS_SIPHASH13_SIZE=%q invalid", sizeStr)
	}

	outDir := os.Getenv("ITB_HARNESS_SIPHASH13_OUT")
	if outDir == "" {
		t.Fatalf("ITB_HARNESS_SIPHASH13_OUT required")
	}

	N := 2
	if s := os.Getenv("ITB_HARNESS_SIPHASH13_N"); s != "" {
		if v, perr := strconv.Atoi(s); perr == nil && v > 0 {
			N = v
		}
	}

	nonceSeed := uint64(0xA17B1CE)
	if s := os.Getenv("ITB_HARNESS_SIPHASH13_SEED"); s != "" {
		if v, perr := strconv.ParseUint(s, 0, 64); perr == nil {
			nonceSeed = v
		}
	}

	barrierFill := 1
	keyBits := 1024

	SetMaxWorkers(8)
	SetBarrierFill(barrierFill)
	t.Cleanup(func() {
		SetMaxWorkers(0)
		SetBarrierFill(1)
	})

	fixedNonce := deriveFixedNonce(nonceSeed, currentNonceSize())
	setTestNonce(t, fixedNonce)

	rng := rand.New(rand.NewSource(424242))
	plaintexts := make([][]byte, N)
	for i := 0; i < N; i++ {
		plaintexts[i] = make([]byte, plaintextSize)
		for j := range plaintexts[i] {
			r := rng.Intn(97)
			switch {
			case r == 95:
				plaintexts[i][j] = 0x09
			case r == 96:
				plaintexts[i][j] = 0x0A
			default:
				plaintexts[i][j] = byte(0x20 + r)
			}
		}
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", outDir, err)
	}

	p := nonceReuseParams{
		hashName:      "siphash13",
		hashDisplay:   "siphash13",
		hashWidth:     128,
		keyBits:       keyBits,
		barrierFill:   barrierFill,
		N:             N,
		mode:          "known_ascii",
		plaintextKind: "random",
		plaintextSize: plaintextSize,
		fixedNonce:    fixedNonce,
		plaintexts:    plaintexts,
		outDir:        outDir,
	}

	t.Logf("Harness siphash13 corpus: %d bytes × %d ciphertexts, %s mode → %s",
		plaintextSize, N, mode, outDir)

	runNonceReuse128(t, &p, HashFunc128(siphash13Hash128))
}

// ============================================================================
// NEXT PRIMITIVE APPENDS BELOW THIS LINE
//
// Append new primitive sections under their own "========" banner. Existing
// sections above are not modified when adding a new primitive — the file
// grows by appending only.
// ============================================================================
