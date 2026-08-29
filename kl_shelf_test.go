//go:build redteam

package itb

// kl_shelf_test.go — Phase 2b Mode B corpus generator for the KL floor probe
// driven by `scripts/redteam/itb/theory/_common/kl/kl_matrix.py`. Emits one massive
// ITB ciphertext per invocation on the v0.3.0 Triple + always-on 48-bit
// Interlocked Barrier wire, together with a `.pixel` KEY=VALUE sidecar
// carrying container dimensions and the dual-nonce header layout the two
// Python sub-scripts (`kl_massive_full.py`, `kl_urandom.py`) consume
// through `kl_matrix.py`.
//
// Attacker-realism (CLAUDE.md discipline):
//
//   - Fresh crypto/rand nonce per invocation (Mode B is a raw ciphertext
//     bias probe, not a nonce-reuse attack — each of `n_samples` driver
//     invocations produces an independent ciphertext). No `setBrokenTestNonce`.
//   - `<hash>.pixel` sidecar carries `main_nonce_hex`, `interlock_nonce_hex`,
//     `total_pixels`, `width`, `height`, `barrier_fill`, `header_size`,
//     `start_pixel` (first-snake `deriveStartPixel`, lab-only decorative
//     value never consumed by the |Δ50| / χ² metric). Matches the field
//     schema `raw_mode_bias_probe.py` consumes.
//   - No ground-truth peek into any Mode B decision path — this is a pure
//     ciphertext-producing test, not an attack.
//
// The BLAKE3 → HashFunc128 adapter (`klBlake3Hash128`) is a local copy of
// the `makeBlake3Hash128CPA` pattern in `redteam_cpa_broken_test.go`
// (keyed BLAKE3 with seed0/seed1 XORed into the first 16 bytes of the
// message, extracts the low 16 bytes of the digest as (lo, hi)). The
// primitive choice is fixed by `kl_matrix.py`'s docstring (BLAKE3 is one
// PRF-grade registry entry; all PRF-grade entries produce statistically
// identical Mode B outputs at matched N).
//
// Env vars (driver: `scripts/redteam/itb/theory/_common/kl/kl_matrix.py`):
//
//   ITB_REDTEAM_MASSIVE          — must equal "blake3" to enable
//                                  (name kept for driver compatibility;
//                                  driver dispatches by hash name)
//   ITB_REDTEAM_MASSIVE_SIZE     — plaintext bytes (e.g. 1024, 65536, ...)
//   ITB_REDTEAM_MASSIVE_OUTDIR   — output directory for `<hash>.bin` +
//                                  `<hash>.pixel` (+ `<hash>.plain`)
//   ITB_BARRIER_FILL             — Config.BarrierFill override (1/2/4/8/16/32)
//   ITB_REDTEAM_MASSIVE_SEED     — optional deterministic BLAKE3 key derivation
//                                  seed (default 0xA17B1CE); nonce always drawn
//                                  from crypto/rand
//
// The output filenames follow the pre-existing driver convention
// (`<hash>.bin` + `<hash>.pixel`) so the two Python sub-scripts consume it
// without further path changes.

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/zeebo/blake3"
)

// ---------------------------------------------------------------------------
// BLAKE3 → HashFunc128 adapter — local copy of `makeBlake3Hash128CPA`'s
// keyed-BLAKE3 recipe (redteam_cpa_broken_test.go). Kept local so this
// generator does not depend on the CPA-attack test file.
// ---------------------------------------------------------------------------

// klBlake3Hash128 wraps a keyed BLAKE3-256 hasher into the HashFunc128
// signature (returns the low 16 bytes of the 32-byte digest as (lo, hi)).
// `key` fixes the BLAKE3 keying material; seed0/seed1 are XORed into the
// first 16 bytes of the message so the primitive's PRF property covers
// both the message and the seed axes.
func klBlake3Hash128(key [32]byte) HashFunc128 {
	template, err := blake3.NewKeyed(key[:])
	if err != nil {
		panic(fmt.Errorf("kl_shelf: BLAKE3 keyed template: %w", err))
	}
	pool := &sync.Pool{New: func() any { b := make([]byte, 0, 128); return &b }}
	return func(data []byte, seed0, seed1 uint64) (uint64, uint64) {
		h := template.Clone()
		const seedInjectBytes = 16
		payloadLen := len(data)
		if payloadLen < seedInjectBytes {
			payloadLen = seedInjectBytes
		}
		mixedPtr := pool.Get().(*[]byte)
		mixed := *mixedPtr
		if cap(mixed) < payloadLen {
			mixed = make([]byte, payloadLen)
		} else {
			mixed = mixed[:payloadLen]
		}
		for i := len(data); i < payloadLen; i++ {
			mixed[i] = 0
		}
		copy(mixed[:len(data)], data)
		binary.LittleEndian.PutUint64(mixed[0:], binary.LittleEndian.Uint64(mixed[0:])^seed0)
		binary.LittleEndian.PutUint64(mixed[8:], binary.LittleEndian.Uint64(mixed[8:])^seed1)
		h.Write(mixed)
		*mixedPtr = mixed
		pool.Put(mixedPtr)
		var buf [32]byte
		h.Sum(buf[:0])
		lo := binary.LittleEndian.Uint64(buf[0:])
		hi := binary.LittleEndian.Uint64(buf[8:])
		return lo, hi
	}
}

// ---------------------------------------------------------------------------
// Corpus generator entry point
// ---------------------------------------------------------------------------

// TestRedTeamGenerateTripleMassive — v0.3.0 corpus-cell generator for the
// Phase 2b Mode B KL floor probe. Drives one BLAKE3-keyed
// `Encrypt3x128Cfg` call on a random plaintext of `ITB_REDTEAM_MASSIVE_SIZE`
// bytes at `Config.BarrierFill = ITB_BARRIER_FILL`, writes the raw
// ciphertext to `<outdir>/blake3.bin` and a KEY=VALUE `<outdir>/blake3.pixel`
// sidecar consumed by `scripts/redteam/itb/theory/_common/kl/kl_massive_full.py`.
//
// Driver: `scripts/redteam/itb/theory/_common/kl/kl_matrix.py` invokes this per
// cell in the size × BarrierFill Cartesian sweep; the test is inert unless
// `ITB_REDTEAM_MASSIVE=blake3` is set. Only the "blake3" hash-name value is
// currently supported (kl_matrix.py fixes the primitive at BLAKE3).
func TestRedTeamGenerateTripleMassive(t *testing.T) {
	hashName := os.Getenv("ITB_REDTEAM_MASSIVE")
	if hashName == "" {
		t.Skip("set ITB_REDTEAM_MASSIVE=blake3 to generate a Phase 2b Mode B " +
			"KL corpus cell (not part of the default `go test` run)")
	}
	if hashName != "blake3" {
		t.Fatalf("ITB_REDTEAM_MASSIVE=%q: only 'blake3' is currently supported "+
			"(kl_matrix.py fixes the Mode B primitive at BLAKE3)", hashName)
	}

	sizeStr := os.Getenv("ITB_REDTEAM_MASSIVE_SIZE")
	if sizeStr == "" {
		t.Fatal("ITB_REDTEAM_MASSIVE_SIZE required (plaintext bytes, e.g. 65536)")
	}
	plaintextSize, err := strconv.Atoi(sizeStr)
	if err != nil || plaintextSize <= 0 || plaintextSize > maxDataSize {
		t.Fatalf("ITB_REDTEAM_MASSIVE_SIZE=%q: must be positive int <= %d",
			sizeStr, maxDataSize)
	}

	outDir := os.Getenv("ITB_REDTEAM_MASSIVE_OUTDIR")
	if outDir == "" {
		t.Fatal("ITB_REDTEAM_MASSIVE_OUTDIR required (absolute or " +
			"project-relative directory path)")
	}

	bf := DefaultBarrierFill
	if s := os.Getenv("ITB_BARRIER_FILL"); s != "" {
		v, perr := strconv.Atoi(s)
		if perr != nil {
			t.Fatalf("ITB_BARRIER_FILL=%q: not an integer", s)
		}
		switch v {
		case 1, 2, 4, 8, 16, 32:
			bf = v
		default:
			t.Fatalf("ITB_BARRIER_FILL=%d: must be one of {1,2,4,8,16,32}", v)
		}
	}

	keySeed := uint64(0xA17B1CE)
	if s := os.Getenv("ITB_REDTEAM_MASSIVE_SEED"); s != "" {
		if v, perr := strconv.ParseUint(s, 0, 64); perr == nil {
			keySeed = v
		}
	}

	// BLAKE3 keying material — deterministic per keySeed so the primitive
	// stays reproducible across runs; the nonce (below) is still drawn
	// fresh, so ciphertexts across runs remain independent even at
	// matched keySeed.
	var key [32]byte
	binary.LittleEndian.PutUint64(key[0:8], keySeed^0x9E3779B97F4A7C15)
	binary.LittleEndian.PutUint64(key[8:16], keySeed^0xBF58476D1CE4E5B9)
	binary.LittleEndian.PutUint64(key[16:24], keySeed^0x94D049BB133111EB)
	binary.LittleEndian.PutUint64(key[24:32], keySeed^0xDA942042E4DD58B5)
	hashFn := klBlake3Hash128(key)

	const keyBits = 1024
	// Eight seeds keyed by BLAKE3. Deterministic RNG seeded by keySeed
	// so seeds are reproducible per keySeed; nonce is still fresh so
	// ciphertexts across invocations differ.
	seedRng := rand.New(rand.NewSource(int64(keySeed) ^ 0xFEEDFACE))
	mk := func(role string) *Seed128 {
		nComp := keyBits / 64
		comps := make([]uint64, nComp)
		for i := range comps {
			comps[i] = seedRng.Uint64()
		}
		s, ferr := SeedFromComponents128(hashFn, comps...)
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

	// Deterministic printable-ASCII plaintext keyed by a fresh RNG per
	// invocation (Go's default global rand.Read reseeds per go test binary
	// launch; per-invocation freshness is what matters for the Mode B
	// KL accumulation across the driver's n_samples iterations).
	plainRng := rand.New(rand.NewSource(rand.Int63()))
	plaintext := make([]byte, plaintextSize)
	for j := range plaintext {
		r := plainRng.Intn(97)
		switch {
		case r == 95:
			plaintext[j] = 0x09 // tab
		case r == 96:
			plaintext[j] = 0x0A // newline
		default:
			plaintext[j] = byte(0x20 + r) // printable ASCII 0x20..0x7E
		}
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", outDir, err)
	}

	cfg := &Config{BarrierFill: bf}
	ct, err := Encrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3x128Cfg: %v", err)
	}
	back, err := Decrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x128Cfg: %v", err)
	}
	if string(back) != string(plaintext) {
		t.Fatal("round-trip mismatch")
	}

	// Parse v0.3.0 dual-nonce header off the ciphertext.
	nonceLen := currentNonceSizeCfg(cfg)
	mainNonce := ct[:nonceLen]
	interlockNonce := ct[nonceLen : 2*nonceLen]
	width := int(binary.BigEndian.Uint16(ct[2*nonceLen:]))
	height := int(binary.BigEndian.Uint16(ct[2*nonceLen+2:]))
	totalPixels := width * height
	headerSize := 2*nonceLen + 4

	// Representative per-snake startPixel — first-snake `deriveStartPixel`
	// value on the main nonce. Written to the sidecar as a lab-only
	// decorative value; the Mode B distinguisher never consumes it.
	startPixel := s1.deriveStartPixel(mainNonce, totalPixels)

	// Write ciphertext and plaintext blobs under the driver's expected
	// path convention (`<hash>.bin`, `<hash>.plain`).
	binPath := filepath.Join(outDir, hashName+".bin")
	plainPath := filepath.Join(outDir, hashName+".plain")
	if err := os.WriteFile(binPath, ct, 0o644); err != nil {
		t.Fatalf("write %s: %v", binPath, err)
	}
	if err := os.WriteFile(plainPath, plaintext, 0o644); err != nil {
		t.Fatalf("write %s: %v", plainPath, err)
	}

	// KEY=VALUE sidecar for the Python sub-scripts. Preserves the pre-v0.3.0
	// field shape (`total_pixels=N`, `barrier_fill=N`) and adds the v0.3.0
	// dual-nonce fields (`main_nonce_hex`, `interlock_nonce_hex`, `header_size`).
	pixLines := []string{
		"hash=" + hashName,
		"hash_display=BLAKE3",
		"hash_width=128",
		"key_bits=" + strconv.Itoa(keyBits),
		"plaintext_size=" + strconv.Itoa(plaintextSize),
		"width=" + strconv.Itoa(width),
		"height=" + strconv.Itoa(height),
		"total_pixels=" + strconv.Itoa(totalPixels),
		"header_size=" + strconv.Itoa(headerSize),
		"barrier_fill=" + strconv.Itoa(bf),
		"start_pixel=" + strconv.Itoa(startPixel),
		"main_nonce_hex=" + hex.EncodeToString(mainNonce),
		"interlock_nonce_hex=" + hex.EncodeToString(interlockNonce),
		// Retained for compatibility with any pre-v0.3.0 consumer that
		// still reads `nonce_hex` — mirrors `main_nonce_hex`.
		"nonce_hex=" + hex.EncodeToString(mainNonce),
	}
	pixText := ""
	for _, line := range pixLines {
		pixText += line + "\n"
	}
	pixPath := filepath.Join(outDir, hashName+".pixel")
	if err := os.WriteFile(pixPath, []byte(pixText), 0o644); err != nil {
		t.Fatalf("write %s: %v", pixPath, err)
	}

	t.Logf("Mode B cell: %s size=%d BarrierFill=%d totalPixels=%d "+
		"headerSize=%d ct=%d B → %s",
		hashName, plaintextSize, bf, totalPixels, headerSize, len(ct), outDir)
}
