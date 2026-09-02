//go:build redteam

package itb

// Below-floor nullHash adversarial re-verification: the primitive
// reads only the first byte of `data` and the low byte of each seed
// word, discarding everything else. Under [Seed128.ChainHash128]'s
// four-round cascade at 512-bit key (or eight-round at 1024-bit),
// the data byte cancels on every even-numbered round because the
// XOR-carry between prev-state (low byte only) and next-round data
// (low byte only) collapses to a pure per-seed 16-bit constant:
//
//   hLo_final = XOR of C[0], C[2], C[4], C[6] (low bytes)
//   hHi_final = XOR of C[1], C[3], C[5], C[7] (low bytes)
//
// Every pixel and every message produces the SAME (hLo, hHi) per
// seed role, independent of pixel_index and nonce content — a much
// stronger collapse than jokeHash's multiply-add fold, which retains
// 64-bit accumulated per-invocation state.
//
// This primitive violates the barrier's reduction-target lower bound
// (uniform Ω_chunk coverage requires ≥128-bit non-collapsing PRF
// output; nullHash gives 16 bits of static constant per seed role).
// Exists strictly to empirically demonstrate the entropy-floor break
// point of the tandem Part 1 + Part 2 barrier — under Full KPA + given
// startPixels the joint enumeration reduces to five 16-bit unknowns
// (K_noiseSeed, K_lockSeed, K_dataSeed_1/2/3), each brute-forceable
// in seconds.
//
// NEVER plug nullHash into the shipped registry. Test-only baseline
// for the entropy-floor documentation walkthrough.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// nullHash reads only the first byte of `data` and the low byte of each
// seed word. Everything else — subsequent data bytes, higher bytes of
// the seed words — is discarded. Trivially invertible per invocation
// (`data[0] = hLo XOR (seed0 & 0xFF)`).
func nullHash(data []byte, seed0, seed1 uint64) (lo, hi uint64) {
	var d byte
	if len(data) > 0 {
		d = data[0]
	}
	lo = uint64(d) ^ (seed0 & 0xFF)
	hi = uint64(d) ^ (seed1 & 0xFF)
	return
}

// nullHashConstant reproduces the collapsed 16-bit per-seed hash output
// (hLo || hHi as one uint16) that ChainHash128 produces under nullHash
// for a Seed128's Components, independent of the buf argument. Used by
// the expose test to record the ground-truth constants attackers are
// solving for, and by the brute-force validator to verify a recovered
// solution against truth.
func nullHashConstant(components []uint64) uint16 {
	var lo, hi uint64
	for i := 0; i < len(components); i += 2 {
		lo ^= components[i] & 0xFF
		hi ^= components[i+1] & 0xFF
	}
	return uint16(lo)<<8 | uint16(hi)
}

// makeNullHashSeeds constructs the eight seeds required by
// Encrypt3x128Cfg, each keyed by fresh CSPRNG components and each
// running the nullHash primitive.
func makeNullHashSeeds(t *testing.T, keyBits int) (ns, ls, d1, d2, d3, s1, s2, s3 *Seed128) {
	t.Helper()
	mk := func(role string) *Seed128 {
		s, err := NewSeed128(keyBits, nullHash)
		if err != nil {
			t.Fatalf("NewSeed128(%s): %v", role, err)
		}
		return s
	}
	return mk("noiseSeed"), mk("lockSeed"),
		mk("dataSeed1"), mk("dataSeed2"), mk("dataSeed3"),
		mk("startSeed1"), mk("startSeed2"), mk("startSeed3")
}

// generateNullHashPlaintext returns an n-byte JSON body deterministically
// derived from a fixed marker string. Format is a flat {"k":"v"} object
// with padding value string extended to reach exactly n bytes. Every
// byte is a printable ASCII character so the plaintext resembles a
// realistic API response body rather than random bytes.
func generateNullHashPlaintext(n int) []byte {
	prefix := `{"kind":"api-response","payload":"`
	suffix := `"}`
	if len(prefix)+len(suffix) >= n {
		buf := make([]byte, n)
		copy(buf, prefix)
		return buf
	}
	padLen := n - len(prefix) - len(suffix)
	buf := make([]byte, 0, n)
	buf = append(buf, prefix...)
	// Deterministic printable-ASCII pad: cycle 'a'..'z' for reproducibility.
	for i := 0; i < padLen; i++ {
		buf = append(buf, byte('a'+(i%26)))
	}
	buf = append(buf, suffix...)
	return buf
}

// TestRedTeamNullHashRoundtrip is a sanity gate: nullHash must at least
// permit successful roundtrip under Encrypt3x128Cfg / Decrypt3x128Cfg,
// otherwise the expose test below has nothing to attack. If this fails,
// the primitive or its cascade shape has drifted (e.g. changed key-size
// convention).
func TestRedTeamNullHashRoundtrip(t *testing.T) {
	ns, ls, d1, d2, d3, s1, s2, s3 := makeNullHashSeeds(t, 512)
	plaintext := generateNullHashPlaintext(512)
	cfg := &Config{NonceBits: 128, BarrierFill: 1}

	ct, err := Encrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3x128Cfg: %v", err)
	}
	back, err := Decrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x128Cfg: %v", err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Fatalf("roundtrip mismatch (len=%d vs %d)", len(back), len(plaintext))
	}
	t.Logf("nullHash roundtrip ok: plaintext=%d, ciphertext=%d", len(plaintext), len(ct))
}

// TestRedTeamNullHashExpose generates one victim ciphertext under
// nullHash on all eight seed roles with fresh crypto/rand nonces and
// dumps attacker-visible inputs to the output directory:
//
//	ct.bin           — the wire ciphertext (attacker input)
//	kpa.bin          — the Full KPA plaintext (attacker input)
//	cell.meta.json   — nonce, container dims, three snake startPixels,
//	                   plus a `truth:` block with the ground-truth
//	                   16-bit seed constants for post-attack validation
//
// The `truth:` block is lab-only debug — the attack script under
// scripts/redteam/itb/theory/nullhash/ must NEVER consume it in its
// decision path. It exists so a recovered result can be verified
// against ground truth without running Decrypt (which would need
// reconstructed seeds and add another moving part to the verification).
//
// Env vars:
//
//	REDTEAM_NULLHASH_OUTPUT_DIR — output directory (default
//	                              $HOME/scratch/redteam/nullhash/, matches
//	                              every other red-team probe layout)
//	ITB_NULLHASH_KEYBITS        — Seed128 key width in bits (default 512)
//	ITB_NULLHASH_PTSIZE         — plaintext size in bytes (default 512)
//
// Invocation:
//
//	go test -count=1 -tags redteam -run TestRedTeamNullHashExpose \
//	    ./... -v
//
// writeSingleNullHashExpose regenerates the single-message expose files
// (ct.bin, kpa.bin, cell.meta.json) under outDir. Extracted from the
// TestRedTeamNullHashExpose body so attack tests can call it directly at
// start-up and be order-independent: each attack test regenerates a fresh
// victim before it reads. Returns nothing (side-effect on disk).
func writeSingleNullHashExpose(t *testing.T, outDir string, keyBits, ptSize, barrierFill int) {
	t.Helper()
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("MkdirAll %s: %v", outDir, err)
	}

	cfg := &Config{NonceBits: 128, BarrierFill: barrierFill}
	plaintext := generateNullHashPlaintext(ptSize)

	ns, ls, d1, d2, d3, s1, s2, s3 := makeNullHashSeeds(t, keyBits)

	ct, err := Encrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, plaintext)
	if err != nil {
		t.Fatalf("Encrypt3x128Cfg: %v", err)
	}
	back, err := Decrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ct)
	if err != nil {
		t.Fatalf("Decrypt3x128Cfg: %v", err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Fatalf("roundtrip mismatch")
	}

	nonceLen := currentNonceSizeCfg(cfg)
	if len(ct) < 2*nonceLen+4 {
		t.Fatalf("ciphertext too short for dual-nonce header: %d", len(ct))
	}
	mainNonce := ct[:nonceLen]
	interlockNonce := ct[nonceLen : 2*nonceLen]
	width := int(binary.BigEndian.Uint16(ct[2*nonceLen:]))
	height := int(binary.BigEndian.Uint16(ct[2*nonceLen+2:]))
	totalPixels := width * height
	headerSize := 2*nonceLen + 4

	// Per-snake startPixels — lab concession granted to the attacker.
	// deriveStartPixel(mainNonce, totalPixels) reproduces the encoder's
	// own call site (Encrypt3x128Cfg uses total container pixels, not
	// per-snake subdivisions, for each start).
	sp1 := s1.deriveStartPixel(mainNonce, totalPixels)
	sp2 := s2.deriveStartPixel(mainNonce, totalPixels)
	sp3 := s3.deriveStartPixel(mainNonce, totalPixels)

	// Truth block: post-attack validation data. NOT for decision-path
	// consumption in the attacker script.
	truth := map[string]any{
		"K_noiseSeed":   fmt.Sprintf("0x%04x", nullHashConstant(ns.Components)),
		"K_lockSeed":    fmt.Sprintf("0x%04x", ls.Components),
		"K_dataSeed_1":  fmt.Sprintf("0x%04x", nullHashConstant(d1.Components)),
		"K_dataSeed_2":  fmt.Sprintf("0x%04x", nullHashConstant(d2.Components)),
		"K_dataSeed_3":  fmt.Sprintf("0x%04x", nullHashConstant(d3.Components)),
		"K_startSeed_1": fmt.Sprintf("0x%04x", nullHashConstant(s1.Components)),
		"K_startSeed_2": fmt.Sprintf("0x%04x", nullHashConstant(s2.Components)),
		"K_startSeed_3": fmt.Sprintf("0x%04x", nullHashConstant(s3.Components)),
	}

	// Correct the K_lockSeed truth (fix formatting bug above).
	truth["K_lockSeed"] = fmt.Sprintf("0x%04x", nullHashConstant(ls.Components))

	meta := map[string]any{
		"hash":                "nullHash",
		"hash_description":    "8-bit data[0] XOR low(seed) — collapses to per-seed 16-bit constant under 4-round ChainHash128 cascade",
		"key_bits":            keyBits,
		"barrier_fill":        barrierFill,
		"plaintext_size":      ptSize,
		"main_nonce_hex":      hex.EncodeToString(mainNonce),
		"interlock_nonce_hex": hex.EncodeToString(interlockNonce),
		"nonce_len_bytes":     nonceLen,
		"width":               width,
		"height":              height,
		"total_pixels":        totalPixels,
		"header_size":         headerSize,
		"start_pixels": map[string]int{
			"snake_1": sp1,
			"snake_2": sp2,
			"snake_3": sp3,
		},
		"truth_labonly": truth,
	}

	ctPath := filepath.Join(outDir, "ct.bin")
	kpaPath := filepath.Join(outDir, "kpa.bin")
	metaPath := filepath.Join(outDir, "cell.meta.json")

	if err := os.WriteFile(ctPath, ct, 0o644); err != nil {
		t.Fatalf("write %s: %v", ctPath, err)
	}
	if err := os.WriteFile(kpaPath, plaintext, 0o644); err != nil {
		t.Fatalf("write %s: %v", kpaPath, err)
	}
	metaJSON, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshal cell.meta: %v", err)
	}
	if err := os.WriteFile(metaPath, metaJSON, 0o644); err != nil {
		t.Fatalf("write %s: %v", metaPath, err)
	}

	// Fresh random seeds to test that the truth constants are reproducible.
	// (Sanity: nullHashConstant applied to raw Components matches what
	// ChainHash128 actually produces on any buf. Verified by asserting
	// the constant equals the observed hash output.)
	buf := make([]byte, nonceLen+8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read buf: %v", err)
	}
	obsLo, obsHi := ns.ChainHash128(buf)
	got := uint16(obsLo&0xFF)<<8 | uint16(obsHi&0xFF)
	want := nullHashConstant(ns.Components)
	if got != want {
		t.Fatalf("nullHashConstant sanity mismatch: predicted 0x%04x, ChainHash128 produced (lo=0x%016x, hi=0x%016x) = 0x%04x",
			want, obsLo, obsHi, got)
	}

	t.Logf("Wrote ct.bin (%d bytes), kpa.bin (%d bytes), cell.meta.json under %s",
		len(ct), len(plaintext), outDir)
	t.Logf("  width=%d height=%d totalPixels=%d headerSize=%d", width, height, totalPixels, headerSize)
	t.Logf("  startPixels: snake1=%d snake2=%d snake3=%d", sp1, sp2, sp3)
	t.Logf("  truth constants: noiseSeed=%s lockSeed=%s d1=%s d2=%s d3=%s",
		truth["K_noiseSeed"], truth["K_lockSeed"], truth["K_dataSeed_1"], truth["K_dataSeed_2"], truth["K_dataSeed_3"])
}

// TestRedTeamNullHashExpose is the standalone expose test entry point.
// It simply calls writeSingleNullHashExpose with env-var overrides. The
// attack tests each call writeSingleNullHashExpose directly at start-up,
// so ordering with respect to this test is irrelevant.
func TestRedTeamNullHashExpose(t *testing.T) {
	outDir := redteamOutputDir("nullhash")
	keyBits := 512
	if v := os.Getenv("ITB_NULLHASH_KEYBITS"); v != "" {
		fmt.Sscanf(v, "%d", &keyBits)
	}
	ptSize := 512
	if v := os.Getenv("ITB_NULLHASH_PTSIZE"); v != "" {
		fmt.Sscanf(v, "%d", &ptSize)
	}
	writeSingleNullHashExpose(t, outDir, keyBits, ptSize, 1)
}
