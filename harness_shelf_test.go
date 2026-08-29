//go:build redteam

package itb

// harness_shelf_test.go — HARNESS.md § 3.3 Axis B corpus generators for the
// four non-cryptographic hash primitives on the shelf (t1ha1_64le, SeaHash,
// mx3, SipHash-1-3), driving the v0.3.0 Triple + always-on 48-bit Interlocked
// Barrier construction. One env-gated `TestRedTeamHarnessGenerate*NonceReuse`
// test per primitive, invoked by the four
// `scripts/redteam/itb/theory/<primitive>/harness_bias_audit.sh` drivers, which then
// feed the emitted `cell.meta.json` + `ct_0000.bin` through
// `scripts/redteam/itb/theory/_common/raw_mode_bias_probe.py` for the |Δ50|
// reading.
//
// Attacker-realism (CLAUDE.md discipline):
//
//   - Fixed nonce (Nonce-Reuse lab assumption) via `setBrokenTestNonce` —
//     forces main + interlock nonce collision on every Encrypt* call. A real
//     caller cannot reach either override; both draw fresh crypto/rand per
//     call. This is a corpus-generation assumption on the ciphertexts, not
//     an oracle the downstream probe consumes.
//   - `cell.meta.json` carries `main_nonce_hex` and `interlock_nonce_hex`
//     (the current dual-nonce header schema) plus attacker-visible container
//     dimensions. `start_pixel` is the first-snake `deriveStartPixel`
//     result, kept as a lab-visible convenience so the probe's terminal
//     rank-of-true-shift printout has a target to compare against; the
//     |Δ50| metric never consumes it.
//   - No ground-truth peek into any decision path — this is a pure
//     ciphertext-producing test, not an attack.
//
// The four primitive adapters (`t1ha1Hash128`, `seahashHash128`, `mx3Hash128`,
// `siphash13Hash128`) are copied verbatim from
// `scripts/redteam/itb/theory/_common/chainhashes/_parity_dump/main.go` — the
// standalone Go dumper used to seed the Python ChainHash mirrors. Keeping
// the copies local to this test file matches the same pattern the
// `_parity_dump` uses ("duplicated so this standalone main can be built
// without pulling the itb test package") — the tests here need the exact
// same primitive implementations that key the Python mirrors, and only in
// a redteam-tagged test file.
//
// Env vars (per primitive, common shape):
//
//   ITB_HARNESS_<PRIM>_MODE  — plaintext mode: "known_ascii" (only value
//                              currently supported; strongest per-byte bit-7=0
//                              bias regime for the Axis B absorption claim)
//   ITB_HARNESS_<PRIM>_SIZE  — plaintext bytes (e.g. 524288 = 512 KB,
//                              1048576 = 1 MB — HARNESS.md § 3.3 baselines)
//   ITB_HARNESS_<PRIM>_OUT   — output directory for cell artefacts
//   ITB_HARNESS_<PRIM>_SEED  — optional nonce derivation seed (default
//                              0xA17B1CE)
//   ITB_HARNESS_<PRIM>_N     — optional N ciphertexts under same nonce (default 1;
//                              the probe consumes only ct_0000.bin, but
//                              downstream aggregators can iterate ct_NNNN.bin)

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/bits"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// ---------------------------------------------------------------------------
// Primitive adapters — verbatim from
// scripts/redteam/itb/theory/_common/chainhashes/_parity_dump/main.go.
// Kept in-file so the corpus generator can key seeds with the exact same
// bytes the downstream Python bias probe's ChainHash mirror expects.
// ---------------------------------------------------------------------------

// --- t1ha1_64le (erthink/t1ha, LE variant) ---------------------------------

const (
	shelfT1haPrime0 uint64 = 0xEC99BF0D8372CAAB
	shelfT1haPrime1 uint64 = 0x82434FE90EDCEF39
	shelfT1haPrime2 uint64 = 0xD4F06DB99D67BE4B
	shelfT1haPrime3 uint64 = 0xBD9CACC22C6E9571
	shelfT1haPrime4 uint64 = 0x9C06FAF4D023E3AB
	shelfT1haPrime5 uint64 = 0xC060724A8424F345
	shelfT1haPrime6 uint64 = 0xCB5AF53AE3AAAC31
)

func shelfT1haRot64(v uint64, s uint) uint64 { return bits.RotateLeft64(v, -int(s)) }

func shelfT1haMux64(v, prime uint64) uint64 {
	hi, lo := bits.Mul64(v, prime)
	return lo ^ hi
}

func shelfT1haMix64(v, prime uint64) uint64 {
	v *= prime
	return v ^ shelfT1haRot64(v, 41)
}

func shelfT1haFinalWeakAvalanche(a, b uint64) uint64 {
	return shelfT1haMux64(shelfT1haRot64(a+b, 17), shelfT1haPrime4) + shelfT1haMix64(a^b, shelfT1haPrime0)
}

func shelfT1haTail64Le(data []byte, tail int) uint64 {
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

func shelfT1ha1_64le(data []byte, seed uint64) uint64 {
	length := uint64(len(data))
	a := seed
	b := length
	pos := 0
	if len(data) > 32 {
		c := shelfT1haRot64(length, 17) + seed
		d := length ^ shelfT1haRot64(seed, 17)
		for {
			w0 := binary.LittleEndian.Uint64(data[pos:])
			w1 := binary.LittleEndian.Uint64(data[pos+8:])
			w2 := binary.LittleEndian.Uint64(data[pos+16:])
			w3 := binary.LittleEndian.Uint64(data[pos+24:])
			pos += 32
			d02 := w0 ^ shelfT1haRot64(w2+d, 17)
			c13 := w1 ^ shelfT1haRot64(w3+c, 17)
			d -= b ^ shelfT1haRot64(w1, 31)
			c += a ^ shelfT1haRot64(w0, 41)
			b ^= shelfT1haPrime0 * (c13 + w2)
			a ^= shelfT1haPrime1 * (d02 + w3)
			if pos+32 > len(data) {
				break
			}
		}
		a ^= shelfT1haPrime6 * (shelfT1haRot64(c, 17) + d)
		b ^= shelfT1haPrime5 * (c + shelfT1haRot64(d, 17))
		length &= 31
	}
	tail := data[pos:]
	if length > 24 {
		b += shelfT1haMux64(binary.LittleEndian.Uint64(tail[:8]), shelfT1haPrime4)
		tail = tail[8:]
	}
	if length > 16 {
		a += shelfT1haMux64(binary.LittleEndian.Uint64(tail[:8]), shelfT1haPrime3)
		tail = tail[8:]
	}
	if length > 8 {
		b += shelfT1haMux64(binary.LittleEndian.Uint64(tail[:8]), shelfT1haPrime2)
		tail = tail[8:]
	}
	if length > 0 {
		a += shelfT1haMux64(shelfT1haTail64Le(tail, int(length)), shelfT1haPrime1)
	}
	return shelfT1haFinalWeakAvalanche(a, b)
}

func shelfT1ha1Hash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	return shelfT1ha1_64le(data, seed0), shelfT1ha1_64le(data, seed1)
}

// --- SeaHash (ticki/tfs) ---------------------------------------------------

const (
	shelfSeahashPrime uint64 = 0x6EED0E9DA4D94A4F
	shelfSeahashInitA uint64 = 0x16F11FE89B0D677C
	shelfSeahashInitB uint64 = 0xB480A793D8E6C86C
	shelfSeahashInitC uint64 = 0x6FE2E5AAF078EBC9
	shelfSeahashInitD uint64 = 0x14F994A4C5259381
)

func shelfSeahashDiffuse(x uint64) uint64 {
	x *= shelfSeahashPrime
	x ^= (x >> 32) >> (x >> 60)
	x *= shelfSeahashPrime
	return x
}

func shelfSeahashReadTail(buf []byte) uint64 {
	var x uint64
	for i, b := range buf {
		x |= uint64(b) << (8 * i)
	}
	return x
}

func shelfSeahash64(data []byte, seed uint64) uint64 {
	a, b, c, d := shelfSeahashInitA, shelfSeahashInitB, shelfSeahashInitC, shelfSeahashInitD
	if seed != 0 {
		a *= seed
		b *= seed
		c *= seed
		d *= seed
	}
	pos := 0
	for pos+8 <= len(data) {
		n := binary.LittleEndian.Uint64(data[pos:])
		a, b, c, d = b, c, d, shelfSeahashDiffuse(a^n)
		pos += 8
	}
	if pos < len(data) {
		n := shelfSeahashReadTail(data[pos:])
		a, b, c, d = b, c, d, shelfSeahashDiffuse(a^n)
	}
	return shelfSeahashDiffuse(a ^ b ^ c ^ d ^ uint64(len(data)))
}

func shelfSeahashHash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	return shelfSeahash64(data, seed0), shelfSeahash64(data, seed1)
}

// --- mx3 (jonmaiga/mx3, v3.0.0) --------------------------------------------

const shelfMx3C uint64 = 0xBEA225F9EB34556D

func shelfMx3Mix(x uint64) uint64 {
	x ^= x >> 32
	x *= shelfMx3C
	x ^= x >> 29
	x *= shelfMx3C
	x ^= x >> 32
	x *= shelfMx3C
	x ^= x >> 29
	return x
}

func shelfMx3MixStream(h, x uint64) uint64 {
	x *= shelfMx3C
	x ^= x >> 39
	h += x * shelfMx3C
	h *= shelfMx3C
	return h
}

func shelfMx3MixStream4(h, a, b, c, d uint64) uint64 {
	a *= shelfMx3C
	b *= shelfMx3C
	c *= shelfMx3C
	d *= shelfMx3C
	a ^= a >> 39
	b ^= b >> 39
	c ^= c >> 39
	d ^= d >> 39
	h += a * shelfMx3C
	h *= shelfMx3C
	h += b * shelfMx3C
	h *= shelfMx3C
	h += c * shelfMx3C
	h *= shelfMx3C
	h += d * shelfMx3C
	h *= shelfMx3C
	return h
}

func shelfMx3Hash(data []byte, seed uint64) uint64 {
	length := uint64(len(data))
	h := shelfMx3MixStream(seed, length+1)
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
		h = shelfMx3MixStream4(h, w0, w1, w2, w3)
		h = shelfMx3MixStream4(h, w4, w5, w6, w7)
		pos += 64
	}
	for length-uint64(pos) >= 8 {
		h = shelfMx3MixStream(h, binary.LittleEndian.Uint64(data[pos:]))
		pos += 8
	}
	tail := data[pos:]
	switch len(tail) {
	case 0:
		return shelfMx3Mix(h)
	case 1:
		return shelfMx3Mix(shelfMx3MixStream(h, uint64(tail[0])))
	case 2:
		return shelfMx3Mix(shelfMx3MixStream(h, uint64(binary.LittleEndian.Uint16(tail))))
	case 3:
		x := uint64(binary.LittleEndian.Uint16(tail[:2])) | uint64(tail[2])<<16
		return shelfMx3Mix(shelfMx3MixStream(h, x))
	case 4:
		return shelfMx3Mix(shelfMx3MixStream(h, uint64(binary.LittleEndian.Uint32(tail))))
	case 5:
		x := uint64(binary.LittleEndian.Uint32(tail[:4])) | uint64(tail[4])<<32
		return shelfMx3Mix(shelfMx3MixStream(h, x))
	case 6:
		x := uint64(binary.LittleEndian.Uint32(tail[:4])) | uint64(binary.LittleEndian.Uint16(tail[4:6]))<<32
		return shelfMx3Mix(shelfMx3MixStream(h, x))
	case 7:
		x := uint64(binary.LittleEndian.Uint32(tail[:4])) |
			uint64(binary.LittleEndian.Uint16(tail[4:6]))<<32 |
			uint64(tail[6])<<48
		return shelfMx3Mix(shelfMx3MixStream(h, x))
	}
	return shelfMx3Mix(h)
}

func shelfMx3Hash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	return shelfMx3Hash(data, seed0), shelfMx3Hash(data, seed1)
}

// --- SipHash-1-3 -----------------------------------------------------------

const (
	shelfSiphash13IV0 uint64 = 0x736F6D6570736575
	shelfSiphash13IV1 uint64 = 0x646F72616E646F6D
	shelfSiphash13IV2 uint64 = 0x6C7967656E657261
	shelfSiphash13IV3 uint64 = 0x7465646279746573

	shelfSiphash13C = 1
	shelfSiphash13D = 3
)

func shelfSiphash13Round(v0, v1, v2, v3 uint64) (uint64, uint64, uint64, uint64) {
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

func shelfSiphash13Hash(data []byte, seed uint64) uint64 {
	k0 := seed
	k1 := uint64(0)
	v0 := k0 ^ shelfSiphash13IV0
	v1 := k1 ^ shelfSiphash13IV1
	v2 := k0 ^ shelfSiphash13IV2
	v3 := k1 ^ shelfSiphash13IV3
	length := len(data)
	end8 := length - (length % 8)
	pos := 0
	for pos < end8 {
		m := binary.LittleEndian.Uint64(data[pos:])
		v3 ^= m
		for i := 0; i < shelfSiphash13C; i++ {
			v0, v1, v2, v3 = shelfSiphash13Round(v0, v1, v2, v3)
		}
		v0 ^= m
		pos += 8
	}
	var lastBytes [8]byte
	rem := length - end8
	if rem > 0 {
		copy(lastBytes[:rem], data[end8:])
	}
	lastBytes[7] = byte(length & 0xFF)
	m := binary.LittleEndian.Uint64(lastBytes[:])
	v3 ^= m
	for i := 0; i < shelfSiphash13C; i++ {
		v0, v1, v2, v3 = shelfSiphash13Round(v0, v1, v2, v3)
	}
	v0 ^= m
	v2 ^= 0xFF
	for i := 0; i < shelfSiphash13D; i++ {
		v0, v1, v2, v3 = shelfSiphash13Round(v0, v1, v2, v3)
	}
	return v0 ^ v1 ^ v2 ^ v3
}

func shelfSiphash13Hash128(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	return shelfSiphash13Hash(data, seed0), shelfSiphash13Hash(data, seed1)
}

// ---------------------------------------------------------------------------
// Shared corpus generator
// ---------------------------------------------------------------------------

// shelfParams captures the env-parsed inputs for one primitive's Axis B
// corpus cell.
type shelfParams struct {
	envPrefix   string      // e.g. "ITB_HARNESS_T1HA1"
	hashName    string      // e.g. "t1ha1"
	hashDisplay string      // e.g. "t1ha1_64le"
	hashFunc    HashFunc128 // primitive adapter
}

// runShelfCorpus generates a single Axis B corpus cell for `p.hashName` and
// writes `cell.meta.json` + `ct_NNNN.bin` (+ `ct_NNNN.plain`) under the
// caller-supplied output directory. Env-gated: the test skips unless
// `<envPrefix>_MODE=known_ascii` is set (see per-primitive docstrings).
func runShelfCorpus(t *testing.T, p shelfParams) {
	t.Helper()

	mode := os.Getenv(p.envPrefix + "_MODE")
	if mode == "" {
		t.Skipf("set %s_MODE=known_ascii to generate %s corpus "+
			"(HARNESS.md § 3.3 Axis B; not part of the default `go test` run)",
			p.envPrefix, p.hashName)
	}
	if mode != "known_ascii" {
		t.Fatalf("%s_MODE=%q: only 'known_ascii' is currently supported "+
			"(strongest per-byte bias regime for the Axis B absorption claim)",
			p.envPrefix, mode)
	}

	sizeStr := os.Getenv(p.envPrefix + "_SIZE")
	if sizeStr == "" {
		t.Fatalf("%s_SIZE required (plaintext bytes, e.g. 524288 for 512 KB)",
			p.envPrefix)
	}
	plaintextSize, err := strconv.Atoi(sizeStr)
	if err != nil || plaintextSize <= 0 || plaintextSize > maxDataSize {
		t.Fatalf("%s_SIZE=%q: must be positive int <= %d (maxDataSize)",
			p.envPrefix, sizeStr, maxDataSize)
	}

	outDir := os.Getenv(p.envPrefix + "_OUT")
	if outDir == "" {
		t.Fatalf("%s_OUT required (absolute or project-relative directory path)",
			p.envPrefix)
	}

	N := 1
	if s := os.Getenv(p.envPrefix + "_N"); s != "" {
		if v, perr := strconv.Atoi(s); perr == nil && v > 0 {
			N = v
		}
	}

	nonceSeed := uint64(0xA17B1CE)
	if s := os.Getenv(p.envPrefix + "_SEED"); s != "" {
		if v, perr := strconv.ParseUint(s, 0, 64); perr == nil {
			nonceSeed = v
		}
	}

	const keyBits = 1024 // HARNESS.md § 3.3 baseline: ChainHash-8 at keyBits=1024

	// Fixed nonce (Nonce-Reuse lab assumption). setBrokenTestNonce forces
	// BOTH the main nonce and the interlock nonce to the same fixed value,
	// realising the dual-nonce collision the reuse threat model targets.
	fixedNonce := make([]byte, NonceSize)
	rng := rand.New(rand.NewSource(int64(nonceSeed)))
	for i := range fixedNonce {
		fixedNonce[i] = byte(rng.Intn(256))
	}
	setBrokenTestNonce(t, fixedNonce)

	// Eight seeds keyed by the shelf primitive. Deterministic RNG (fixed
	// seed) so the corpus is reproducible; independent draws per seed role.
	seedRng := rand.New(rand.NewSource(int64(nonceSeed) ^ 0xFEEDFACE))
	mk := func(role string) *Seed128 {
		// Draw keyBits/64 uint64 components deterministically, then build a
		// Seed128 from them. Uses the exported SeedFromComponents128 factory
		// so the primitive is bound end-to-end.
		nComp := keyBits / 64
		comps := make([]uint64, nComp)
		for i := range comps {
			comps[i] = seedRng.Uint64()
		}
		s, ferr := SeedFromComponents128(p.hashFunc, comps...)
		if ferr != nil {
			t.Fatalf("SeedFromComponents128(%s): %v", role, ferr)
		}
		return s
	}
	ns := mk("noise")
	ls := mk("lock")
	d1 := mk("d1")
	d2 := mk("d2")
	d3 := mk("d3")
	s1 := mk("s1")
	s2 := mk("s2")
	s3 := mk("s3")

	// Deterministic printable-ASCII plaintext(s).
	plainRng := rand.New(rand.NewSource(424242))
	plaintexts := make([][]byte, N)
	for i := 0; i < N; i++ {
		plaintexts[i] = make([]byte, plaintextSize)
		for j := range plaintexts[i] {
			r := plainRng.Intn(97)
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

	t.Logf("Shelf %s corpus: %d bytes × %d ciphertexts, %s mode → %s",
		p.hashName, plaintextSize, N, mode, outDir)

	var firstCt []byte
	for i := 0; i < N; i++ {
		ct, err := Encrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, plaintexts[i])
		if err != nil {
			t.Fatalf("Encrypt3x128Cfg sample %d: %v", i, err)
		}
		back, err := Decrypt3x128Cfg(nil, ns, ls, d1, d2, d3, s1, s2, s3, ct)
		if err != nil {
			t.Fatalf("Decrypt3x128Cfg sample %d: %v", i, err)
		}
		if string(back) != string(plaintexts[i]) {
			t.Fatalf("round-trip mismatch at sample %d", i)
		}
		if i == 0 {
			firstCt = ct
		}
		binPath := filepath.Join(outDir, "ct_"+padIdx4(i)+".bin")
		plainPath := filepath.Join(outDir, "ct_"+padIdx4(i)+".plain")
		if err := os.WriteFile(binPath, ct, 0o644); err != nil {
			t.Fatalf("write %s: %v", binPath, err)
		}
		if err := os.WriteFile(plainPath, plaintexts[i], 0o644); err != nil {
			t.Fatalf("write %s: %v", plainPath, err)
		}
	}

	// Parse the v0.3.0 dual-nonce header off the first ciphertext.
	nonceLen := NonceSize
	mainNonce := firstCt[:nonceLen]
	interlockNonce := firstCt[nonceLen : 2*nonceLen]
	width := int(binary.BigEndian.Uint16(firstCt[2*nonceLen:]))
	height := int(binary.BigEndian.Uint16(firstCt[2*nonceLen+2:]))
	totalPixels := width * height
	headerSize := 2*nonceLen + 4

	// Representative per-snake startPixel. Uses the same
	// `deriveStartPixel(nonce, totalPixels)` call the encrypt path used,
	// but on the first snake only — the probe consumes this exclusively
	// for the terminal "true shift rank" printout and never in the |Δ50|
	// metric, so the coarse single-snake stand-in is sufficient.
	startPixel := s1.deriveStartPixel(mainNonce, totalPixels)

	meta := map[string]any{
		"hash":                p.hashName,
		"hash_display":        p.hashDisplay,
		"hash_width":          128,
		"key_bits":            keyBits,
		"barrier_fill":        DefaultBarrierFill,
		"n":                   N,
		"mode":                "known_ascii",
		"plaintext_size":      plaintextSize,
		"main_nonce_hex":      hex.EncodeToString(mainNonce),
		"interlock_nonce_hex": hex.EncodeToString(interlockNonce),
		"width":               width,
		"height":              height,
		"total_pixels":        totalPixels,
		"header_size":         headerSize,
		"start_pixel":         startPixel,
		// Retained for compatibility with any pre-v0.3.0 consumer that
		// still reads `nonce_hex` — mirrors `main_nonce_hex`.
		"nonce_hex": hex.EncodeToString(mainNonce),
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshal cell.meta: %v", err)
	}
	metaPath := filepath.Join(outDir, "cell.meta.json")
	if err := os.WriteFile(metaPath, metaJSON, 0o644); err != nil {
		t.Fatalf("write %s: %v", metaPath, err)
	}
	t.Logf("Wrote %d ciphertexts + cell.meta.json under %s "+
		"(width=%d height=%d totalPixels=%d headerSize=%d)",
		N, outDir, width, height, totalPixels, headerSize)
}

// padIdx4 formats i as a 4-digit zero-padded decimal (e.g. 0 -> "0000").
func padIdx4(i int) string {
	s := strconv.Itoa(i)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

// ---------------------------------------------------------------------------
// Per-primitive test entry points
// ---------------------------------------------------------------------------

// TestRedTeamHarnessGenerateT1ha1NonceReuse — HARNESS.md § 3.3 Axis B
// corpus generator with t1ha1_64le keyed into ChainHash128 (parallel
// two-lane 128-bit adapter). Invoked by
// `scripts/redteam/itb/theory/t1ha1/harness_bias_audit.sh`.
func TestRedTeamHarnessGenerateT1ha1NonceReuse(t *testing.T) {
	runShelfCorpus(t, shelfParams{
		envPrefix:   "ITB_HARNESS_T1HA1",
		hashName:    "t1ha1",
		hashDisplay: "t1ha1_64le",
		hashFunc:    HashFunc128(shelfT1ha1Hash128),
	})
}

// TestRedTeamHarnessGenerateSeaHashNonceReuse — HARNESS.md § 3.3 Axis B
// corpus generator with SeaHash keyed into ChainHash128 (parallel two-lane
// adapter). Invoked by `scripts/redteam/itb/theory/seahash/harness_bias_audit.sh`.
func TestRedTeamHarnessGenerateSeaHashNonceReuse(t *testing.T) {
	runShelfCorpus(t, shelfParams{
		envPrefix:   "ITB_HARNESS_SEAHASH",
		hashName:    "seahash",
		hashDisplay: "SeaHash",
		hashFunc:    HashFunc128(shelfSeahashHash128),
	})
}

// TestRedTeamHarnessGenerateMx3NonceReuse — HARNESS.md § 3.3 Axis B
// corpus generator with mx3 keyed into ChainHash128 (parallel two-lane
// adapter). Invoked by `scripts/redteam/itb/theory/mx3/harness_bias_audit.sh`.
func TestRedTeamHarnessGenerateMx3NonceReuse(t *testing.T) {
	runShelfCorpus(t, shelfParams{
		envPrefix:   "ITB_HARNESS_MX3",
		hashName:    "mx3",
		hashDisplay: "mx3",
		hashFunc:    HashFunc128(shelfMx3Hash128),
	})
}

// TestRedTeamHarnessGenerateSiphash13NonceReuse — HARNESS.md § 3.3 Axis B
// corpus generator with SipHash-1-3 keyed into ChainHash128 (parallel
// two-lane adapter; k1 = 0). Invoked by
// `scripts/redteam/itb/theory/siphash13/harness_bias_audit.sh`.
func TestRedTeamHarnessGenerateSiphash13NonceReuse(t *testing.T) {
	runShelfCorpus(t, shelfParams{
		envPrefix:   "ITB_HARNESS_SIPHASH13",
		hashName:    "siphash13",
		hashDisplay: "SipHash-1-3",
		hashFunc:    HashFunc128(shelfSiphash13Hash128),
	})
}
