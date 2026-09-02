//go:build redteam

package itb

// TestRedTeamNullHashExposeMulti is the multi-message companion to
// TestRedTeamNullHashExpose. It encrypts N messages under ONE shared
// 8-seed nullHash constellation, each with its own fresh crypto/rand
// nonce pair and a distinct plaintext, and dumps the wire ciphertexts
// plus a single shared cell.meta.json. It exists for the Stage 3
// ciphertext-only attack, where a second ciphertext is needed to
// disambiguate false-positive candidates that a single ciphertext cannot
// separate.
//
// Under nullHash every derivation (constants, startPixels, lock mask
// triple) is nonce-independent, so the same recovered candidate applies
// identically to every message — the classic "several messages from one
// sender" threat model. The dumped start_pixels and truth_labonly blocks
// are lab-only; the Stage 3 attacker never reads them.
//
// Env vars:
//
//   REDTEAM_NULLHASH_OUTPUT_DIR — output directory (default
//                                 $HOME/scratch/redteam/nullhash/)
//   ITB_NULLHASH_N_MESSAGES     — message count (default 2)
//   ITB_NULLHASH_KEYBITS        — Seed128 key width (default 512)
//   ITB_NULLHASH_PTSIZE         — plaintext size (default 512)
//
// Output layout:
//
//   ct_0.bin, ct_1.bin, ...   — wire ciphertexts
//   kpa_0.bin, kpa_1.bin, ... — the plaintexts (lab-only; not attacker input)
//   cell.multi.meta.json      — per-message nonces + shared truth block

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// writeMultiNullHashExpose regenerates the multi-message expose files
// (ct_0.bin, ct_1.bin, ..., kpa_0.bin, kpa_1.bin, ..., cell.multi.meta.json)
// under outDir. Extracted so the Stage 3 attack test can call it directly
// at start-up and be order-independent.
func writeMultiNullHashExpose(t *testing.T, outDir string, nMsg, keyBits, ptSize, barrierFill int) {
	t.Helper()
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatalf("MkdirAll %s: %v", outDir, err)
	}

	cfg := &Config{NonceBits: 128, BarrierFill: barrierFill}
	// One shared 8-seed constellation for every message.
	ns, ls, d1, d2, d3, s1, s2, s3 := makeNullHashSeeds(t, keyBits)

	type msgMeta struct {
		MainNonceHex      string `json:"main_nonce_hex"`
		InterlockNonceHex string `json:"interlock_nonce_hex"`
		CtFile            string `json:"ct_file"`
	}
	var msgs []msgMeta
	var width, height, totalPixels, headerSize, nonceLen int

	for m := 0; m < nMsg; m++ {
		// Distinct plaintext per message: vary a byte marker so contents
		// differ while length stays fixed. Content itself is irrelevant to
		// the attacker (content-agnostic threat model).
		pt := generateNullHashPlaintext(ptSize)
		for k := 0; k < len(pt) && k < 8; k++ {
			pt[k] ^= byte(m * 37) // small per-message perturbation
		}
		ct, err := Encrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, pt)
		if err != nil {
			t.Fatalf("Encrypt msg %d: %v", m, err)
		}
		back, err := Decrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ct)
		if err != nil || !bytes.Equal(back, pt) {
			t.Fatalf("roundtrip msg %d failed", m)
		}
		nonceLen = currentNonceSizeCfg(cfg)
		mainNonce := ct[:nonceLen]
		ilNonce := ct[nonceLen : 2*nonceLen]
		width = int(binary.BigEndian.Uint16(ct[2*nonceLen:]))
		height = int(binary.BigEndian.Uint16(ct[2*nonceLen+2:]))
		totalPixels = width * height
		headerSize = 2*nonceLen + 4

		ctFile := fmt.Sprintf("ct_%d.bin", m)
		if err := os.WriteFile(filepath.Join(outDir, ctFile), ct, 0o644); err != nil {
			t.Fatalf("write %s: %v", ctFile, err)
		}
		if err := os.WriteFile(filepath.Join(outDir, fmt.Sprintf("kpa_%d.bin", m)), pt, 0o644); err != nil {
			t.Fatalf("write kpa %d: %v", m, err)
		}
		msgs = append(msgs, msgMeta{
			MainNonceHex:      hex.EncodeToString(mainNonce),
			InterlockNonceHex: hex.EncodeToString(ilNonce),
			CtFile:            ctFile,
		})
	}

	// Shared startPixels (nonce-independent under nullHash) and truth.
	sp1 := s1.deriveStartPixel(nil, totalPixels)
	// deriveStartPixel needs a nonce buffer; under nullHash content is
	// ignored, but pass a zero nonce of the right length for the call.
	zeroNonce := make([]byte, nonceLen)
	sp1 = s1.deriveStartPixel(zeroNonce, totalPixels)
	sp2 := s2.deriveStartPixel(zeroNonce, totalPixels)
	sp3 := s3.deriveStartPixel(zeroNonce, totalPixels)

	truth := map[string]string{
		"K_noiseSeed":   fmt.Sprintf("0x%04x", nullHashConstant(ns.Components)),
		"K_lockSeed":    fmt.Sprintf("0x%04x", nullHashConstant(ls.Components)),
		"K_dataSeed_1":  fmt.Sprintf("0x%04x", nullHashConstant(d1.Components)),
		"K_dataSeed_2":  fmt.Sprintf("0x%04x", nullHashConstant(d2.Components)),
		"K_dataSeed_3":  fmt.Sprintf("0x%04x", nullHashConstant(d3.Components)),
		"K_startSeed_1": fmt.Sprintf("0x%04x", nullHashConstant(s1.Components)),
		"K_startSeed_2": fmt.Sprintf("0x%04x", nullHashConstant(s2.Components)),
		"K_startSeed_3": fmt.Sprintf("0x%04x", nullHashConstant(s3.Components)),
	}

	meta := map[string]any{
		"hash":            "nullHash",
		"key_bits":        keyBits,
		"barrier_fill":    barrierFill,
		"plaintext_size":  ptSize,
		"n_messages":      nMsg,
		"nonce_len_bytes": nonceLen,
		"width":           width,
		"height":          height,
		"total_pixels":    totalPixels,
		"header_size":     headerSize,
		"messages":        msgs,
		"start_pixels": map[string]int{
			"snake_1": sp1, "snake_2": sp2, "snake_3": sp3,
		},
		"truth_labonly": truth,
	}
	metaJSON, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "cell.multi.meta.json"), metaJSON, 0o644); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	t.Logf("wrote %d messages, container %dx%d totalPixels=%d headerSize=%d", nMsg, width, height, totalPixels, headerSize)
	t.Logf("startPixels (lab): %d %d %d", sp1, sp2, sp3)
	t.Logf("truth: noise=%s lock=%s d=%s,%s,%s", truth["K_noiseSeed"], truth["K_lockSeed"], truth["K_dataSeed_1"], truth["K_dataSeed_2"], truth["K_dataSeed_3"])
}

// TestRedTeamNullHashExposeMulti is the standalone multi-message expose
// test entry point. Simply calls writeMultiNullHashExpose with env-var
// overrides. The Stage 3 attack calls writeMultiNullHashExpose directly
// at start-up, so ordering with respect to this test is irrelevant.
func TestRedTeamNullHashExposeMulti(t *testing.T) {
	outDir := redteamOutputDir("nullhash")
	nMsg := 2
	if v := os.Getenv("ITB_NULLHASH_N_MESSAGES"); v != "" {
		fmt.Sscanf(v, "%d", &nMsg)
	}
	keyBits := 512
	if v := os.Getenv("ITB_NULLHASH_KEYBITS"); v != "" {
		fmt.Sscanf(v, "%d", &keyBits)
	}
	ptSize := 512
	if v := os.Getenv("ITB_NULLHASH_PTSIZE"); v != "" {
		fmt.Sscanf(v, "%d", &ptSize)
	}
	writeMultiNullHashExpose(t, outDir, nMsg, keyBits, ptSize, 1)
}
