//go:build redteam

package itb

// Full-KPA brute-force recovery against the below-floor nullHash
// primitive. This is the attacker-realistic companion to
// TestRedTeamNullHashExpose: it consumes ONLY attacker-visible inputs
// (the Full-KPA plaintext, the wire ciphertext, the two public nonces
// read from the dual-nonce header, the three per-snake startPixels
// granted as a lab concession, and the container geometry) and recovers
// the observable seed-role constants, then measures wall-clock.
//
// The truth_labonly block in cell.meta.json is read ONLY at the very end
// for a validation printout. It never feeds a branch in the decision
// path. Removing that final block leaves the recovery byte-identical.
//
// Why this links the shipped internals directly. A real attacker holding
// the public ITB source reimplements the decode and the Part-1 lock from
// that source. Reimplementing them in Python would re-derive the COBS
// terminator handling, the 7/8 noise-bit insertion, the 7-bit rotation
// reversal, and the combinadic unrank — every one a known correctness
// hazard. Linking the shipped process128Cfg (decode), the shipped
// splitForTriple48LockedCfg (Part-1 lock), and cobsEncode is the same
// computation with zero reimplementation risk, so the measured number
// reflects the search cost, not a reimplementation bug. Candidate seeds
// are constructed with attacker-chosen constants; no lab-only seed
// material is ever read.
//
// Attack decomposition (see the report for the full write-up):
//
//   Under nullHash every ChainHash128 collapses to an 8-bit lo constant
//   and an 8-bit hi constant, data- and nonce-independent. The wire then
//   exposes only:
//     - noiseSeed  -> noisePos = lo & 7            (3 bits)
//     - dataSeed_i -> (lo % 7, lo >> 3)            (the full 8-bit lo)
//     - lockSeed   -> deriveInterLockSeed = (lo,hi) (16 bits)
//   The three snakes occupy disjoint container thirds and are decoded
//   independently. Part 1 (the lock) is the only shared coupling and is
//   a pure function of (lockSeed, interlock_nonce, plaintext).
//
//   Phase A: for every 16-bit lockSeed constant, compute the three
//   expected COBS-framed lane payloads via the shipped split, and index
//   lockSeed by each lane's COBS bytes. 2^16 splits — the dominant cost.
//
//   Phase B: for every noisePos (8) and every snake (3) and every 8-bit
//   dataSeed lo constant (256), run the shipped decode over that snake's
//   container third and look the produced COBS prefix up in Phase A's
//   index. A lockSeed that appears for all three snakes under one
//   noisePos is the joint solution. 8*3*256 = 6144 decodes.
//
// Effective explored keyspace: 2^16 + 6144 ~= 2^16, versus the 5*2^16 =
// 2^80 naive joint enumeration of five 16-bit constants.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

// nullHashAttackDir is the attacker's input directory. Uses the shared
// [redteamOutputDir] helper so the layout matches every other red-team
// probe: default `$HOME/scratch/redteam/nullhash/`, override via
// `REDTEAM_NULLHASH_OUTPUT_DIR`. The expose tests write to this same
// directory; each attack test regenerates its own expose files at
// start so ordering under `go test -tags redteam ./` is irrelevant.
func nullHashAttackDir() string {
	return redteamOutputDir("nullhash")
}

// seedConst builds a Seed128 whose nullHash ChainHash128 collapses to the
// requested (lo, hi) 8-bit constant. Under nullHash the collapsed lo is
// XOR of even-index component low bytes and hi is XOR of odd-index low
// bytes; Components = [lo, hi, 0, 0, 0, 0, 0, 0] yields exactly (lo, hi).
// This is attacker code: it constructs a candidate key, it never reads
// victim seed material.
func seedConst(lo, hi byte) *Seed128 {
	s, err := NewSeed128(512, nullHash)
	if err != nil {
		panic(err)
	}
	for i := range s.Components {
		s.Components[i] = 0
	}
	s.Components[0] = uint64(lo)
	s.Components[1] = uint64(hi)
	return s
}

// firstNull returns the index of the first 0x00 byte, or len(b).
func firstNull(b []byte) int {
	for i, x := range b {
		if x == 0 {
			return i
		}
	}
	return len(b)
}

// nullHashCandidateSeeds reconstructs the full 8-seed Triple Ouroboros
// constellation from the observable constants recovered by the search:
// noisePos (3 bits of noiseSeed), the 16-bit lock constant, the three
// dataSeed lo bytes, and the three given startPixels. Distinct hi bytes
// are stamped per slot so the shipped 8-seed-distinctness guard in
// Decrypt3x128Cfg accepts the set; under nullHash the hi byte is unused
// by every observable derivation, so it does not affect the decode.
// Reused verbatim by any later KPA stage that recovers the same
// constants through a different search.
func nullHashCandidateSeeds(noisePos byte, lockConst uint16, dataLo [3]byte, startPixel [3]byte) [8]*Seed128 {
	return [8]*Seed128{
		seedConst(noisePos, 1),
		seedConst(byte(lockConst>>8), byte(lockConst&0xFF)),
		seedConst(dataLo[0], 2),
		seedConst(dataLo[1], 3),
		seedConst(dataLo[2], 4),
		seedConst(startPixel[0], 5),
		seedConst(startPixel[1], 6),
		seedConst(startPixel[2], 7),
	}
}

// verifyRecovered is the attacker-realistic verification seam. It runs
// the shipped Decrypt3x128Cfg with a candidate seed set against the
// observed wire and checks the recovered plaintext:
//
//   - the first cribLen bytes must equal known[:cribLen] (Full KPA passes
//     cribLen == len(known) for a whole-plaintext byte-for-byte match);
//   - if structuralOK is non-nil, the remainder recovered[cribLen:] must
//     also satisfy it (the hook a Crib KPA stage uses to demand the
//     non-crib tail pass public COBS structural checks, so a short crib
//     cannot accidentally certify a colliding wrong key).
//
// Returns whether the candidate verified plus the fully recovered
// plaintext. Uses only attacker-held inputs (wire + known-plaintext
// prefix + recovered constants); never the truth block.
func verifyRecovered(cfg *Config, seeds [8]*Seed128, wire, known []byte, cribLen int, structuralOK func(rest []byte) bool) (bool, []byte) {
	recovered, err := Decrypt3x128Cfg(cfg, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], wire)
	if err != nil {
		return false, nil
	}
	if cribLen > len(recovered) || cribLen > len(known) {
		return false, recovered
	}
	if string(recovered[:cribLen]) != string(known[:cribLen]) {
		return false, recovered
	}
	if structuralOK != nil && !structuralOK(recovered[cribLen:]) {
		return false, recovered
	}
	return true, recovered
}

func TestRedTeamNullHashAttack(t *testing.T) {
	dir := nullHashAttackDir()
	// Regenerate a fresh single-expose victim so this test is
	// order-independent: `go test -tags redteam ./` may run this before
	// TestRedTeamNullHashExpose alphabetically, and TestRedTeamNullHashExposeMulti
	// writes a different meta.json schema. Regenerating here guarantees the
	// files are present in the format this attack reads.
	writeSingleNullHashExpose(t, dir, 512, 512, 1)

	ctPath := filepath.Join(dir, "ct.bin")
	kpaPath := filepath.Join(dir, "kpa.bin")
	metaPath := filepath.Join(dir, "cell.meta.json")

	ct, err := os.ReadFile(ctPath)
	if err != nil {
		t.Fatalf("read ct.bin (run TestRedTeamNullHashExpose first): %v", err)
	}
	kpa, err := os.ReadFile(kpaPath)
	if err != nil {
		t.Fatalf("read kpa.bin: %v", err)
	}
	metaRaw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read cell.meta.json: %v", err)
	}
	var meta struct {
		MainNonceHex   string `json:"main_nonce_hex"`
		InterlockNonce string `json:"interlock_nonce_hex"`
		NonceLen       int    `json:"nonce_len_bytes"`
		Width          int    `json:"width"`
		Height         int    `json:"height"`
		TotalPixels    int    `json:"total_pixels"`
		HeaderSize     int    `json:"header_size"`
		StartPixels    struct {
			S1 int `json:"snake_1"`
			S2 int `json:"snake_2"`
			S3 int `json:"snake_3"`
		} `json:"start_pixels"`
		Truth map[string]string `json:"truth_labonly"`
	}
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatalf("parse meta: %v", err)
	}

	// ---- Attacker inputs only from here on ----
	cfg := &Config{NonceBits: 128, BarrierFill: 1}
	mainNonce, _ := hex.DecodeString(meta.MainNonceHex)
	ilNonce, _ := hex.DecodeString(meta.InterlockNonce)

	container := ct[meta.HeaderSize:]
	totalPixels := meta.TotalPixels
	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third
	off1 := third * Channels
	off2 := 2 * third * Channels
	regions := [3][]byte{
		container[0:off1],
		container[off1:off2],
		container[off2 : totalPixels*Channels],
	}
	widths := [3]int{third, third, thirdPixels2}
	caps := [3]int{
		(third * DataBitsPerPixel) / 8,
		(third * DataBitsPerPixel) / 8,
		(thirdPixels2 * DataBitsPerPixel) / 8,
	}
	startPixelConst := [3]byte{
		byte(meta.StartPixels.S1),
		byte(meta.StartPixels.S2),
		byte(meta.StartPixels.S3),
	}

	start := time.Now()

	// ---------- Phase A: index lockSeed by its lane COBS bytes ----------
	// For every 16-bit lock constant, compute the three expected COBS-
	// framed lane payloads and index the lock constant by each lane's COBS
	// bytes. A single lane does NOT determine the whole 16-bit lock
	// constant — different lanes constrain different bits, and one lane's
	// bytes can be shared by many lock constants — so the index maps each
	// lane key to the SET of lock constants that produce it. The join in
	// Phase B intersects those sets across the three snakes.
	type laneKey struct {
		s   string
		val uint16
	}
	numCPU := runtime.NumCPU()
	if numCPU > 12 {
		numCPU = 12
	}
	shardResults := make([][3][]laneKey, numCPU)
	var wgA sync.WaitGroup
	perW := (65536 + numCPU - 1) / numCPU
	for w := 0; w < numCPU; w++ {
		lo0 := w * perW
		hi0 := lo0 + perW
		if hi0 > 65536 {
			hi0 = 65536
		}
		if lo0 >= hi0 {
			continue
		}
		wgA.Add(1)
		go func(w, lo0, hi0 int) {
			defer wgA.Done()
			var local [3][]laneKey
			for c := lo0; c < hi0; c++ {
				lo := byte(c >> 8)
				hi := byte(c & 0xFF)
				ls := seedConst(lo, hi)
				bp := buildLockBatchPRF48_128Cfg(cfg, ls, ilNonce)
				p0, p1, p2 := splitForTriple48LockedCfg(cfg, kpa, bp)
				ps := [3][]byte{p0, p1, p2}
				for i := 0; i < 3; i++ {
					enc := cobsEncode(ps[i])
					local[i] = append(local[i], laneKey{string(enc), uint16(c)})
				}
			}
			shardResults[w] = local
		}(w, lo0, hi0)
	}
	wgA.Wait()

	lockIdx := [3]map[string][]uint16{{}, {}, {}}
	for _, sh := range shardResults {
		for i := 0; i < 3; i++ {
			for _, lk := range sh[i] {
				lockIdx[i][lk.s] = append(lockIdx[i][lk.s], lk.val)
			}
		}
	}
	phaseA := time.Now()

	// ---------- Phase B: decode each snake third, join on lockSeed ----------
	// For each noisePos and each snake, decode the region under every
	// 8-bit dataSeed lo constant and look the COBS prefix up in Phase A's
	// index. Collect, per noisePos, the set of lock constants each snake
	// can satisfy (with the dataSeed lo that satisfied it). A lock
	// constant present for all three snakes under one noisePos is the
	// solution.
	var (
		foundNoisePos = -1
		foundLock     = uint16(0)
		foundData     [3]byte
		decodeCount   int
	)
	for noisePos := 0; noisePos < 8 && foundNoisePos < 0; noisePos++ {
		// A noiseSeed lo constant with (lo & 7) == noisePos: lo = noisePos.
		noiseSeed := seedConst(byte(noisePos), 0)
		// Per-snake: admissible lockConst -> a witness dataLo. A snake
		// admits a whole SET of lock constants (its lane cannot pin all
		// 16 bits); the witness records which dataSeed lo produced the
		// matching lane so the solution's dataSeeds can be read off.
		snakeHits := [3]map[uint16]byte{{}, {}, {}}
		for i := 0; i < 3; i++ {
			startSeed := seedConst(startPixelConst[i], 0)
			decoded := make([]byte, caps[i])
			for d := 0; d < 256; d++ {
				dataSeed := seedConst(byte(d), 0)
				for k := range decoded {
					decoded[k] = 0
				}
				// Shipped decode over this snake's container third.
				process128Cfg(cfg, noiseSeed, dataSeed, startSeed, mainNonce,
					regions[i], widths[i], 1, decoded, false, 1)
				decodeCount++
				key := decoded[:firstNull(decoded)]
				if lcs, ok := lockIdx[i][string(key)]; ok {
					for _, lc := range lcs {
						if _, dup := snakeHits[i][lc]; !dup {
							snakeHits[i][lc] = byte(d)
						}
					}
				}
			}
		}
		// Intersect the three snakes' admissible lock-constant sets.
		for lc, d0 := range snakeHits[0] {
			d1, ok1 := snakeHits[1][lc]
			d2, ok2 := snakeHits[2][lc]
			if ok1 && ok2 {
				foundNoisePos = noisePos
				foundLock = lc
				foundData = [3]byte{d0, d1, d2}
				break
			}
		}
	}
	elapsed := time.Since(start)

	if foundNoisePos < 0 {
		t.Fatalf("attack failed: no consistent (noisePos, lockSeed, dataSeeds) recovered")
	}

	// ---------- Attacker-realistic confirmation: replay decrypt ----------
	// Reconstruct the full 8-seed candidate and run the shipped Decrypt
	// against the observed wire, then verify the recovered plaintext.
	// This uses only attacker-held data (wire + known plaintext +
	// recovered constants). The truth block is NOT consulted here.
	//
	// verifyRecovered is the reusable verification seam. Stage 1 (Full
	// KPA) passes cribLen == len(kpa) so the whole recovered plaintext is
	// compared byte-for-byte. A later Crib KPA stage would pass a short
	// cribLen (e.g. 48) and a non-nil structuralOK to additionally require
	// the non-crib remainder to pass public COBS structural checks — the
	// search (Phase A/B) is Full-KPA-specific, but this decode-and-verify
	// primitive and nullHashCandidateSeeds carry over unchanged.
	cand := nullHashCandidateSeeds(byte(foundNoisePos), foundLock, foundData, startPixelConst)
	kpaMatch, recovered := verifyRecovered(cfg, cand, ct, kpa, len(kpa), nil)
	_ = recovered

	t.Logf("=== nullHash Full-KPA brute-force recovery ===")
	t.Logf("wall-clock total:        %v", elapsed)
	t.Logf("  Phase A (2^16 splits):  %v", phaseA.Sub(start))
	t.Logf("  Phase B (%d decodes):  %v", decodeCount, elapsed-phaseA.Sub(start))
	t.Logf("candidates enumerated:   lockSeed=65536, decodes=%d", decodeCount)
	t.Logf("recovered noisePos:      %d (noiseSeed lo &7)", foundNoisePos)
	t.Logf("recovered lockSeed:      0x%04x", foundLock)
	t.Logf("recovered dataSeed lo:   d1=0x%02x d2=0x%02x d3=0x%02x", foundData[0], foundData[1], foundData[2])
	t.Logf("attacker KPA-replay decrypt matches wire plaintext: %v", kpaMatch)

	// ---------- Lab-only validation (post-hoc, decorative) ----------
	// Parse the truth block and compare. Nothing above branched on it.
	tv := func(k string) uint16 {
		var v uint64
		s := meta.Truth[k]
		// strings like "0x3e0b"
		for i := 2; i < len(s); i++ {
			c := s[i]
			var n byte
			switch {
			case c >= '0' && c <= '9':
				n = c - '0'
			case c >= 'a' && c <= 'f':
				n = c - 'a' + 10
			}
			v = v<<4 | uint64(n)
		}
		return uint16(v)
	}
	truthNoise := tv("K_noiseSeed")
	truthLock := tv("K_lockSeed")
	truthD1 := tv("K_dataSeed_1")
	truthD2 := tv("K_dataSeed_2")
	truthD3 := tv("K_dataSeed_3")

	truthNoisePos := int((truthNoise >> 8) & 7)
	t.Logf("--- labonly validation ---")
	t.Logf("truth noisePos=%d  lock=0x%04x  d1lo=0x%02x d2lo=0x%02x d3lo=0x%02x",
		truthNoisePos, truthLock, byte(truthD1>>8), byte(truthD2>>8), byte(truthD3>>8))
	okNoise := foundNoisePos == truthNoisePos
	okLock := foundLock == truthLock
	// dataSeed lo constant is the HIGH byte of the packed truth uint16.
	okD1 := foundData[0] == byte(truthD1>>8)
	okD2 := foundData[1] == byte(truthD2>>8)
	okD3 := foundData[2] == byte(truthD3>>8)
	t.Logf("match: noisePos=%v lock=%v d1=%v d2=%v d3=%v",
		okNoise, okLock, okD1, okD2, okD3)

	if !kpaMatch {
		t.Errorf("attacker-realistic KPA replay did NOT reproduce the plaintext")
	}
	if !(okNoise && okLock && okD1 && okD2 && okD3) {
		t.Logf("NOTE: an observable constant differs from truth; see report on unobservable-bit ambiguity")
	}
}

// ============================================================================
// Stage 2 — Crib KPA (first 48 plaintext bytes known, remaining 464 unknown)
// ============================================================================

// cobsStructurallyValid reports whether stream is a canonical COBS block
// sequence (the bytes that precede a 0x00 terminator). It re-encodes the
// decoded content and requires bit-identity with the input — a public
// structural invariant an attacker can check without any plaintext
// knowledge. Correct-candidate decodes yield exactly cobsEncode(p_i),
// which round-trips; garbage decodes generally do not.
func cobsStructurallyValid(stream []byte) bool {
	if len(stream) == 0 {
		return false
	}
	for _, b := range stream {
		if b == 0x00 {
			return false // no interior null before the terminator
		}
	}
	return string(cobsEncode(cobsDecode(stream))) == string(stream)
}

// printableASCII reports whether every byte is in the printable ASCII
// range [0x20, 0x7e]. Secondary structural filter: the crib prefix
// (`{"kind":"api-response",...`) publicly identifies the plaintext as a
// JSON API-response body, so a correct recovery's non-crib remainder must
// also be printable. Applied only AFTER the COBS lane gate and the crib
// match, never as a primary discriminator.
func printableASCII(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}

// TestRedTeamNullHashAttackCrib is the Crib KPA companion to
// TestRedTeamNullHashAttack. The attacker knows ONLY the first
// nullHashCribLen plaintext bytes; the remaining bytes are never read in
// the decision path (only kpa[:cribLen] is consulted before the final
// labonly validation block).
//
// The search reuses the Stage 1 decomposition with one honest weakening:
// the join no longer matches whole recovered lanes against a fully-known
// plaintext. Instead, the known first 48 plaintext bytes plus the 4-byte
// length prefix fill exactly the first eight 6-byte Part-1 chunks, whose
// masked output is the first 16 bytes of each lane. Phase A' indexes each
// 16-bit lock constant by those crib-derived lane prefixes; Phase B
// decodes each container third, gates the decode through the public COBS
// structural invariant, and looks the wire-recovered lane prefix up in
// that index. Candidates surviving the join are confirmed by a full
// shipped decrypt with a crib-prefix match plus a printable-ASCII check
// on the non-crib remainder. No plaintext byte past the crib and no
// truth_labonly field ever steers a branch.
const nullHashCribLen = 48

func TestRedTeamNullHashAttackCrib(t *testing.T) {
	dir := nullHashAttackDir()
	// Regenerate a fresh single-expose victim so this test is
	// order-independent; see the note on TestRedTeamNullHashAttack above.
	writeSingleNullHashExpose(t, dir, 512, 512, 1)
	ct, err := os.ReadFile(filepath.Join(dir, "ct.bin"))
	if err != nil {
		t.Fatalf("read ct.bin (run TestRedTeamNullHashExpose first): %v", err)
	}
	kpaFull, err := os.ReadFile(filepath.Join(dir, "kpa.bin"))
	if err != nil {
		t.Fatalf("read kpa.bin: %v", err)
	}
	metaRaw, err := os.ReadFile(filepath.Join(dir, "cell.meta.json"))
	if err != nil {
		t.Fatalf("read cell.meta.json: %v", err)
	}
	var meta struct {
		MainNonceHex   string `json:"main_nonce_hex"`
		InterlockNonce string `json:"interlock_nonce_hex"`
		Width          int    `json:"width"`
		Height         int    `json:"height"`
		TotalPixels    int    `json:"total_pixels"`
		HeaderSize     int    `json:"header_size"`
		StartPixels    struct {
			S1 int `json:"snake_1"`
			S2 int `json:"snake_2"`
			S3 int `json:"snake_3"`
		} `json:"start_pixels"`
		Truth map[string]string `json:"truth_labonly"`
	}
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatalf("parse meta: %v", err)
	}

	// ---- Attacker inputs: crib is the ONLY plaintext knowledge ----
	if len(kpaFull) < nullHashCribLen {
		t.Fatalf("plaintext shorter than crib")
	}
	crib := kpaFull[:nullHashCribLen]
	ptLen := len(kpaFull) // the plaintext length is public (container geometry)

	cfg := &Config{NonceBits: 128, BarrierFill: 1}
	mainNonce, _ := hex.DecodeString(meta.MainNonceHex)
	ilNonce, _ := hex.DecodeString(meta.InterlockNonce)

	container := ct[meta.HeaderSize:]
	totalPixels := meta.TotalPixels
	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third
	off1 := third * Channels
	off2 := 2 * third * Channels
	regions := [3][]byte{
		container[0:off1],
		container[off1:off2],
		container[off2 : totalPixels*Channels],
	}
	widths := [3]int{third, third, thirdPixels2}
	caps := [3]int{
		(third * DataBitsPerPixel) / 8,
		(third * DataBitsPerPixel) / 8,
		(thirdPixels2 * DataBitsPerPixel) / 8,
	}
	startPixelConst := [3]byte{
		byte(meta.StartPixels.S1),
		byte(meta.StartPixels.S2),
		byte(meta.StartPixels.S3),
	}

	// The crib plus the 4-byte length prefix occupy framed bytes [0,52),
	// so the first floor((4+48)/6) = 8 six-byte chunks are fully known.
	// Each chunk contributes 2 bytes per lane -> lanePrefixLen known
	// bytes per lane, derivable from the crib alone under any lock
	// candidate. A probe plaintext of (crib || zero fill) of the true
	// length reproduces those chunks exactly; higher chunks (which the
	// zero fill corrupts) are never consulted.
	const lanePrefixLen = 16
	probe := make([]byte, ptLen)
	copy(probe, crib) // remainder stays zero; only chunks 0..7 are used

	start := time.Now()

	// ---------- Phase A': index lock constants by crib-derived prefixes ----
	type laneKey struct {
		s   string
		val uint16
	}
	numCPU := runtime.NumCPU()
	if numCPU > 12 {
		numCPU = 12
	}
	shardResults := make([][3][]laneKey, numCPU)
	var wgA sync.WaitGroup
	perW := (65536 + numCPU - 1) / numCPU
	for w := 0; w < numCPU; w++ {
		lo0 := w * perW
		hi0 := lo0 + perW
		if hi0 > 65536 {
			hi0 = 65536
		}
		if lo0 >= hi0 {
			continue
		}
		wgA.Add(1)
		go func(w, lo0, hi0 int) {
			defer wgA.Done()
			var local [3][]laneKey
			for c := lo0; c < hi0; c++ {
				ls := seedConst(byte(c>>8), byte(c&0xFF))
				bp := buildLockBatchPRF48_128Cfg(cfg, ls, ilNonce)
				p0, p1, p2 := splitForTriple48LockedCfg(cfg, probe, bp)
				ps := [3][]byte{p0, p1, p2}
				for i := 0; i < 3; i++ {
					if len(ps[i]) < lanePrefixLen {
						continue
					}
					local[i] = append(local[i], laneKey{string(ps[i][:lanePrefixLen]), uint16(c)})
				}
			}
			shardResults[w] = local
		}(w, lo0, hi0)
	}
	wgA.Wait()

	lockIdx := [3]map[string][]uint16{{}, {}, {}}
	for _, sh := range shardResults {
		for i := 0; i < 3; i++ {
			for _, lk := range sh[i] {
				lockIdx[i][lk.s] = append(lockIdx[i][lk.s], lk.val)
			}
		}
	}
	phaseA := time.Now()

	// ---------- Phase B: decode + COBS gate + prefix join ----------
	type tuple struct {
		noisePos byte
		lock     uint16
		d        [3]byte
	}
	var (
		preJoin     []tuple
		decodeCount int
		cobsPass    int
	)
	for noisePos := 0; noisePos < 8; noisePos++ {
		noiseSeed := seedConst(byte(noisePos), 0)
		// Per snake: lockConst -> witness dataSeed lo values.
		snakeHits := [3]map[uint16][]byte{{}, {}, {}}
		for i := 0; i < 3; i++ {
			startSeed := seedConst(startPixelConst[i], 0)
			decoded := make([]byte, caps[i])
			for d := 0; d < 256; d++ {
				dataSeed := seedConst(byte(d), 0)
				for k := range decoded {
					decoded[k] = 0
				}
				process128Cfg(cfg, noiseSeed, dataSeed, startSeed, mainNonce,
					regions[i], widths[i], 1, decoded, false, 1)
				decodeCount++
				fn := firstNull(decoded)
				if fn == len(decoded) {
					continue // no COBS terminator -> not a framed lane
				}
				stream := decoded[:fn]
				if !cobsStructurallyValid(stream) {
					continue // fails the public COBS structural invariant
				}
				cobsPass++
				p := cobsDecode(stream)
				if len(p) < lanePrefixLen {
					continue
				}
				if lcs, ok := lockIdx[i][string(p[:lanePrefixLen])]; ok {
					for _, lc := range lcs {
						snakeHits[i][lc] = append(snakeHits[i][lc], byte(d))
					}
				}
			}
		}
		// Intersect and enumerate candidate tuples (cartesian over the
		// benign dataSeed low-bit ambiguity witnesses).
		for lc, d0s := range snakeHits[0] {
			d1s, ok1 := snakeHits[1][lc]
			d2s, ok2 := snakeHits[2][lc]
			if !ok1 || !ok2 {
				continue
			}
			for _, d0 := range d0s {
				for _, d1 := range d1s {
					for _, d2 := range d2s {
						preJoin = append(preJoin, tuple{byte(noisePos), lc, [3]byte{d0, d1, d2}})
					}
				}
			}
		}
	}

	// ---------- Final structural verification per candidate ----------
	// Full shipped decrypt, then crib-prefix match plus printable-ASCII on
	// the non-crib remainder. Uses only attacker-held data.
	type survivor struct {
		t         tuple
		recovered []byte
	}
	var survivors []survivor
	restOK := func(rest []byte) bool { return printableASCII(rest) }
	for _, c := range preJoin {
		seeds := nullHashCandidateSeeds(c.noisePos, c.lock, c.d, startPixelConst)
		ok, rec := verifyRecovered(cfg, seeds, ct, crib, nullHashCribLen, restOK)
		if ok {
			survivors = append(survivors, survivor{c, rec})
		}
	}
	elapsed := time.Since(start)

	// Functional dedup: collapse the wire-invisible dataSeed low-bit pairs
	// (lo and lo^0x07 sharing lo%7 and lo>>3) so functionally-identical
	// tuples count once.
	funcKey := func(c tuple) string {
		norm := func(x byte) byte { return byte((int(x)%7)<<5) | (x >> 3) }
		return string([]byte{c.noisePos, byte(c.lock >> 8), byte(c.lock & 0xFF),
			norm(c.d[0]), norm(c.d[1]), norm(c.d[2])})
	}
	funcSet := map[string]bool{}
	for _, s := range survivors {
		funcSet[funcKey(s.t)] = true
	}

	t.Logf("=== nullHash Crib-KPA brute-force recovery (crib=%d bytes) ===", nullHashCribLen)
	t.Logf("wall-clock total:        %v", elapsed)
	t.Logf("  Phase A' (2^16 splits): %v", phaseA.Sub(start))
	t.Logf("  Phase B + verify:       %v", elapsed-phaseA.Sub(start))
	t.Logf("decodes=%d  COBS-gate-pass=%d  pre-join candidates=%d", decodeCount, cobsPass, len(preJoin))
	t.Logf("survivors after full structural verification: %d raw, %d functionally distinct",
		len(survivors), len(funcSet))

	if len(survivors) == 0 {
		t.Fatalf("Crib-KPA attack failed: no survivor passed structural verification")
	}
	for i, s := range survivors {
		t.Logf("  survivor[%d]: noisePos=%d lock=0x%04x dLo=%02x %02x %02x",
			i, s.t.noisePos, s.t.lock, s.t.d[0], s.t.d[1], s.t.d[2])
	}

	// ---------- Lab-only validation (post-hoc, decorative) ----------
	tv := func(k string) uint16 {
		var v uint64
		s := meta.Truth[k]
		for i := 2; i < len(s); i++ {
			c := s[i]
			var n byte
			switch {
			case c >= '0' && c <= '9':
				n = c - '0'
			case c >= 'a' && c <= 'f':
				n = c - 'a' + 10
			}
			v = v<<4 | uint64(n)
		}
		return uint16(v)
	}
	truthNoisePos := int((tv("K_noiseSeed") >> 8) & 7)
	truthLock := tv("K_lockSeed")
	truthDLo := [3]byte{byte(tv("K_dataSeed_1") >> 8), byte(tv("K_dataSeed_2") >> 8), byte(tv("K_dataSeed_3") >> 8)}
	t.Logf("--- labonly validation ---")
	t.Logf("truth noisePos=%d lock=0x%04x dLo=%02x %02x %02x",
		truthNoisePos, truthLock, truthDLo[0], truthDLo[1], truthDLo[2])
	// Confirm one survivor reproduces the full original plaintext beyond
	// the crib (post-hoc only; the recovery above never read it).
	beyondCribMatch := false
	for _, s := range survivors {
		if string(s.recovered) == string(kpaFull) {
			beyondCribMatch = true
			break
		}
	}
	t.Logf("a survivor reproduces the FULL original plaintext beyond crib: %v", beyondCribMatch)
	if !beyondCribMatch {
		t.Errorf("no survivor reproduced the original plaintext beyond the crib")
	}
}

// ============================================================================
// Stage 3 — Ciphertext-only attack (no KPA, unknown startPixels)
// ============================================================================

// TestRedTeamNullHashAttackNoKPA is the strictest attacker-realism
// scenario: a direct ciphertext-only attack (COA). The attacker holds
// only the wire ciphertexts and their parsed public dual-nonce headers
// (main + interlock nonce, container dimensions). There is NO plaintext,
// NO crib, and NO startPixel concession — the three per-snake startPixels
// are brute-forced. The only structural knowledge used is the public COBS
// framing convention; no content-type assumption (printable-ASCII, JSON,
// etc.) is made — the plaintext may be arbitrary binary.
//
// The attack is content-agnostic and multi-ciphertext. Under nullHash
// every derivation (the observable constants, the per-snake startPixel
// walk offset, and the whole-message 48-bit lock mask triple) is
// nonce-independent, so one recovered candidate applies identically to
// every message from the same 8-seed sender. A single ciphertext leaves
// many COBS-plausible false positives; additional ciphertexts from the
// same sender collapse them, because a random COBS coincidence in one
// wire does not repeat at the same (noisePos, dataSeed lo, startPixel) in
// an independent second wire.
//
// Decomposition:
//
//   Phase 1 (per-snake cross-ciphertext COBS gate): each snake occupies a
//   disjoint container third and is decoded independently. For every
//   (noisePos, dataSeed lo, startPixel in [0,third)) every wire's third is
//   decoded and gated through the public COBS structural invariant; a
//   survivor must validate ALL wires and produce equal lane lengths on
//   each. This collapses ~2900 single-wire COBS coincidences per snake to
//   a few dozen.
//
//   Phase 2 (mask table + length-prefix join): under nullHash the lock
//   PRF ignores the chunk index (nullHash reads only the domain tag byte),
//   so every 6-byte chunk is masked by ONE triple fixed by the 16-bit lock
//   constant. The mask triple table is precomputed once for all 2^16 lock
//   constants. Chunk 0 of a lane triple reassembles (via the shipped
//   unchunk48lock) to framed[0:6], whose big-endian first four bytes are
//   the plaintext length. Only a lock constant that lands that length in
//   the window consistent with the observed lane length passes — applied
//   to every wire.
//
//   Phase 3 (full-decrypt confirmation): the shipped Decrypt3x128Cfg is
//   run on every wire with each surviving candidate; all recovered
//   plaintexts must carry a self-consistent length prefix. Survivors are
//   reported and de-duplicated over the wire-invisible dataSeed low-bit
//   equivalence.
//
// No plaintext byte, no start_pixels field, and no truth_labonly field is
// ever read in the decision path. The truth block and the original
// plaintexts are consulted only in the final decorative validation print.

func nullHashBE32(x uint64) uint32 {
	// framed[0:4] is big-endian; readChunk48 packs bytes little-endian into
	// x, so byte b_k = (x >> 8k) & 0xFF and the BE length is b0<<24|...|b3.
	return uint32(x&0xFF)<<24 | uint32((x>>8)&0xFF)<<16 |
		uint32((x>>16)&0xFF)<<8 | uint32((x>>24)&0xFF)
}

func TestRedTeamNullHashAttackNoKPA(t *testing.T) {
	dir := nullHashAttackDir()
	// Regenerate a fresh multi-message expose so this test is
	// order-independent; see the note on TestRedTeamNullHashAttack above.
	// Multi-expose writes cell.multi.meta.json (distinct from the single-
	// expose cell.meta.json), so both expose formats can coexist under the
	// same outDir without stomping on each other.
	writeMultiNullHashExpose(t, dir, 2, 512, 512, 1)
	metaRaw, err := os.ReadFile(filepath.Join(dir, "cell.multi.meta.json"))
	if err != nil {
		t.Fatalf("read cell.multi.meta.json (run TestRedTeamNullHashExposeMulti first): %v", err)
	}
	var meta struct {
		HeaderSize  int `json:"header_size"`
		TotalPixels int `json:"total_pixels"`
		Messages    []struct {
			MainNonceHex      string `json:"main_nonce_hex"`
			InterlockNonceHex string `json:"interlock_nonce_hex"`
			CtFile            string `json:"ct_file"`
		} `json:"messages"`
		StartPixels struct {
			S1 int `json:"snake_1"`
			S2 int `json:"snake_2"`
			S3 int `json:"snake_3"`
		} `json:"start_pixels"`
		Truth map[string]string `json:"truth_labonly"`
	}
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatalf("parse meta: %v", err)
	}
	if len(meta.Messages) < 2 {
		t.Fatalf("Stage 3 needs >=2 messages; run TestRedTeamNullHashExposeMulti with ITB_NULLHASH_N_MESSAGES>=2")
	}
	W := len(meta.Messages)

	cfg := &Config{NonceBits: 128, BarrierFill: 1}
	cts := make([][]byte, W)
	mainNonce := make([][]byte, W)
	for w := 0; w < W; w++ {
		cts[w], err = os.ReadFile(filepath.Join(dir, meta.Messages[w].CtFile))
		if err != nil {
			t.Fatalf("read %s: %v", meta.Messages[w].CtFile, err)
		}
		mainNonce[w], _ = hex.DecodeString(meta.Messages[w].MainNonceHex)
	}

	totalPixels := meta.TotalPixels
	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third
	off1 := third * Channels
	off2 := 2 * third * Channels
	widths := [3]int{third, third, thirdPixels2}
	caps := [3]int{
		(third * DataBitsPerPixel) / 8,
		(third * DataBitsPerPixel) / 8,
		(thirdPixels2 * DataBitsPerPixel) / 8,
	}
	regionsOf := func(ct []byte) [3][]byte {
		c := ct[meta.HeaderSize:]
		return [3][]byte{c[0:off1], c[off1:off2], c[off2 : totalPixels*Channels]}
	}
	regions := make([][3][]byte, W)
	for w := 0; w < W; w++ {
		regions[w] = regionsOf(cts[w])
	}

	start := time.Now()

	// ---------- Phase 1: per-snake cross-ciphertext COBS gate ----------
	type surv struct {
		noisePos byte
		d        byte
		sp       int
		laneLen  int
		chunk0   []uint16 // this snake's chunk-0 lane value per wire
		lane0    []byte   // this snake's full wire-0 lane (for padding gate)
	}
	var snakeSurv [3][8][]surv
	var mu sync.Mutex

	numCPU := runtime.NumCPU()
	if numCPU > 12 {
		numCPU = 12
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		for np := 0; np < 8; np++ {
			wg.Add(1)
			go func(i, np int) {
				defer wg.Done()
				w := widths[i]
				noiseSeed := seedConst(byte(np), 0)
				bufs := make([][]byte, W)
				for k := 0; k < W; k++ {
					bufs[k] = make([]byte, caps[i])
				}
				var local []surv
				startSeed := seedConst(0, 0)
				for d := 0; d < 256; d++ {
					dataSeed := seedConst(byte(d), 0)
					for spv := 0; spv < w; spv++ {
						startSeed.Components[0] = uint64(spv)
						ok := true
						laneLen := 0
						chunk0 := make([]uint16, W)
						var lane0 []byte
						for k := 0; k < W; k++ {
							b := bufs[k]
							for x := range b {
								b[x] = 0
							}
							process128Cfg(cfg, noiseSeed, dataSeed, startSeed, mainNonce[k],
								regions[k][i], w, 1, b, false, 1)
							fn := firstNull(b)
							if fn == len(b) || !cobsStructurallyValid(b[:fn]) {
								ok = false
								break
							}
							p := cobsDecode(b[:fn])
							if len(p) < 2 || len(p)%2 != 0 {
								ok = false
								break
							}
							if k == 0 {
								laneLen = len(p)
								lane0 = append([]byte(nil), p...)
							} else if len(p) != laneLen {
								ok = false
								break
							}
							chunk0[k] = uint16(p[0]) | uint16(p[1])<<8
						}
						if ok {
							local = append(local, surv{byte(np), byte(d), spv, laneLen, chunk0, lane0})
						}
					}
				}
				if len(local) > 0 {
					mu.Lock()
					snakeSurv[i][np] = append(snakeSurv[i][np], local...)
					mu.Unlock()
				}
			}(i, np)
		}
	}
	wg.Wait()
	phase1 := time.Now()

	total1 := 0
	for i := 0; i < 3; i++ {
		for np := 0; np < 8; np++ {
			total1 += len(snakeSurv[i][np])
		}
	}

	// ---------- Phase 2: mask table + length-prefix join ----------
	type mtriple struct{ m0, m1, m2 uint64 }
	maskTab := make([]mtriple, 65536)
	{
		var wgM sync.WaitGroup
		chunk := (65536 + numCPU - 1) / numCPU
		for w := 0; w < numCPU; w++ {
			lo0 := w * chunk
			hi0 := lo0 + chunk
			if hi0 > 65536 {
				hi0 = 65536
			}
			if lo0 >= hi0 {
				continue
			}
			wgM.Add(1)
			go func(lo0, hi0 int) {
				defer wgM.Done()
				for c := lo0; c < hi0; c++ {
					lo := byte(c >> 8)
					hi := byte(c & 0xFF)
					m0, m1, m2 := rankToMaskTriple48(uint64(0x03^lo), uint64(0x03^hi))
					maskTab[c] = mtriple{m0, m1, m2}
				}
			}(lo0, hi0)
		}
		wgM.Wait()
	}

	type cand struct {
		noisePos byte
		lock     uint16
		d        [3]byte
		sp       [3]int
	}
	var candidates []cand
	for np := 0; np < 8; np++ {
		var byLen [3]map[int][]surv
		for i := 0; i < 3; i++ {
			byLen[i] = map[int][]surv{}
			for _, s := range snakeSurv[i][np] {
				byLen[i][s.laneLen] = append(byLen[i][s.laneLen], s)
			}
		}
		for laneLen, l0 := range byLen[0] {
			l1, ok1 := byLen[1][laneLen]
			l2, ok2 := byLen[2][laneLen]
			if !ok1 || !ok2 {
				continue
			}
			M := laneLen / 2
			winLo := uint32(6*M - 9)
			winHi := uint32(6*M - 4)
			for _, s0 := range l0 {
				for _, s1 := range l1 {
					for _, s2 := range l2 {
						for c := 0; c < 65536; c++ {
							mt := maskTab[c]
							good := true
							for w := 0; w < W; w++ {
								x := unchunk48lock(s0.chunk0[w], s1.chunk0[w], s2.chunk0[w], mt.m0, mt.m1, mt.m2)
								L := nullHashBE32(x)
								if L < winLo || L > winHi {
									good = false
									break
								}
							}
							if !good {
								continue
							}
							// Padding-zero structural gate (public framing invariant):
							// the split zero-pads framed to a multiple of 6, so
							// framed[4+L : 6M] must be all zero. Reconstruct wire-0
							// framed from the three lanes under this lock mask via the
							// shipped unchunk48lock. When L+4 == 6M there is no pad and
							// this gate is vacuous (the residual lock low-byte ambiguity
							// documented in the report).
							framed := make([]byte, 6*M)
							for j := 0; j < M; j++ {
								l0v := uint16(s0.lane0[2*j]) | uint16(s0.lane0[2*j+1])<<8
								l1v := uint16(s1.lane0[2*j]) | uint16(s1.lane0[2*j+1])<<8
								l2v := uint16(s2.lane0[2*j]) | uint16(s2.lane0[2*j+1])<<8
								writeChunk48(framed, 6*j, unchunk48lock(l0v, l1v, l2v, mt.m0, mt.m1, mt.m2))
							}
							L0 := int(nullHashBE32(readChunk48(framed, 0)))
							if 4+L0 > len(framed) {
								continue
							}
							padOK := true
							for _, pb := range framed[4+L0:] {
								if pb != 0 {
									padOK = false
									break
								}
							}
							if padOK {
								candidates = append(candidates, cand{
									byte(np), uint16(c),
									[3]byte{s0.d, s1.d, s2.d},
									[3]int{s0.sp, s1.sp, s2.sp},
								})
							}
						}
					}
				}
			}
		}
	}
	phase2 := time.Now()

	// ---------- Phase 3: full-decrypt confirmation on every wire ----------
	buildSeeds := func(c cand) [8]*Seed128 {
		seeds := nullHashCandidateSeeds(c.noisePos, c.lock, [3]byte{}, [3]byte{})
		seeds[2] = seedConst(c.d[0], 2)
		seeds[3] = seedConst(c.d[1], 3)
		seeds[4] = seedConst(c.d[2], 4)
		for j := 0; j < 3; j++ {
			s := seedConst(0, byte(5+j))
			s.Components[0] = uint64(c.sp[j])
			seeds[5+j] = s
		}
		return seeds
	}
	var confirmed []cand
	for _, c := range candidates {
		seeds := buildSeeds(c)
		okBoth := true
		recLen := -1
		for w := 0; w < W; w++ {
			rec, derr := Decrypt3x128Cfg(cfg, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], cts[w])
			if derr != nil || len(rec) == 0 {
				okBoth = false
				break
			}
			if recLen == -1 {
				recLen = len(rec)
			} else if len(rec) != recLen {
				okBoth = false
				break
			}
		}
		if okBoth {
			confirmed = append(confirmed, c)
		}
	}
	elapsed := time.Since(start)

	// Functional dedup over the wire-invisible dataSeed low-bit pairs.
	norm := func(x byte) byte { return byte((int(x)%7)<<5) | (x >> 3) }
	funcKey := func(c cand) string {
		return string([]byte{c.noisePos, byte(c.lock >> 8), byte(c.lock & 0xFF),
			norm(c.d[0]), norm(c.d[1]), norm(c.d[2]),
			byte(c.sp[0]), byte(c.sp[1]), byte(c.sp[2])})
	}
	funcSet := map[string]cand{}
	for _, c := range confirmed {
		funcSet[funcKey(c)] = c
	}
	// Distinct lock constants among functional survivors (all other fields
	// equal at the true solution) — the residual lock ambiguity.
	lockSet := map[uint16]bool{}
	for _, c := range funcSet {
		lockSet[c.lock] = true
	}

	t.Logf("=== nullHash ciphertext-only attack (COA, %d wires, no KPA, unknown startPixels) ===", W)
	t.Logf("wall-clock total:       %v", elapsed)
	t.Logf("  Phase 1 (COBS gate):  %v", phase1.Sub(start))
	t.Logf("  Phase 2 (join):       %v", phase2.Sub(phase1))
	t.Logf("  Phase 3 (verify):     %v", elapsed-phase2.Sub(start))
	t.Logf("per-snake decodes enumerated: %d (%d wires x 8 noisePos x 256 dataSeed x [0,third) startPixel)",
		W*(8*256*(third+third+thirdPixels2)), W)
	t.Logf("Phase 1 cross-ct COBS survivors (all snakes/noisePos): %d", total1)
	t.Logf("Phase 2 length-join candidates: %d", len(candidates))
	t.Logf("survivors after full verification: %d raw, %d functionally distinct, %d distinct lock constants",
		len(confirmed), len(funcSet), len(lockSet))
	shown := 0
	for _, c := range funcSet {
		t.Logf("  survivor: noisePos=%d lock=0x%04x dLo=%02x %02x %02x sp=%d,%d,%d",
			c.noisePos, c.lock, c.d[0], c.d[1], c.d[2], c.sp[0], c.sp[1], c.sp[2])
		if shown++; shown >= 40 {
			t.Logf("  ... (%d more)", len(funcSet)-shown)
			break
		}
	}
	if len(funcSet) == 0 {
		t.Fatalf("Stage 3 attack failed: no survivor")
	}

	// ---------- Lab-only validation (post-hoc, decorative) ----------
	tv := func(k string) uint16 {
		var v uint64
		b, _ := hex.DecodeString(meta.Truth[k][2:])
		for _, x := range b {
			v = v<<8 | uint64(x)
		}
		return uint16(v)
	}
	truthNoisePos := int((tv("K_noiseSeed") >> 8) & 7)
	truthLock := tv("K_lockSeed")
	truthDLo := [3]byte{byte(tv("K_dataSeed_1") >> 8), byte(tv("K_dataSeed_2") >> 8), byte(tv("K_dataSeed_3") >> 8)}
	truthSP := [3]int{meta.StartPixels.S1 % third, meta.StartPixels.S2 % third, meta.StartPixels.S3 % thirdPixels2}
	t.Logf("--- labonly validation ---")
	t.Logf("truth: noisePos=%d lock=0x%04x dLo=%02x %02x %02x spMod=%d,%d,%d",
		truthNoisePos, truthLock, truthDLo[0], truthDLo[1], truthDLo[2], truthSP[0], truthSP[1], truthSP[2])
	matchTruth := false
	for _, c := range funcSet {
		if c.noisePos == byte(truthNoisePos) && c.lock == truthLock &&
			c.sp[0] == truthSP[0] && c.sp[1] == truthSP[1] && c.sp[2] == truthSP[2] &&
			norm(c.d[0]) == norm(truthDLo[0]) && norm(c.d[1]) == norm(truthDLo[1]) && norm(c.d[2]) == norm(truthDLo[2]) {
			matchTruth = true
		}
	}
	t.Logf("the truth constants+startPixels are among the survivors: %v", matchTruth)

	kpa0, _ := os.ReadFile(filepath.Join(dir, "kpa_0.bin"))
	fullMatch := false
	for _, c := range funcSet {
		seeds := buildSeeds(c)
		rec, derr := Decrypt3x128Cfg(cfg, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], cts[0])
		if derr == nil && len(kpa0) > 0 && string(rec) == string(kpa0) {
			fullMatch = true
			break
		}
	}
	t.Logf("a survivor reproduces the FULL original plaintext of wire 0: %v", fullMatch)

	// Diagnostic (post-hoc, labonly): how many DISTINCT wire-0 plaintexts
	// do the survivors decrypt to, and how many equal the true plaintext?
	// This separates "the lock low byte is a functional don't-care (all
	// survivors -> one plaintext)" from "genuine residual ambiguity (many
	// distinct candidate plaintexts)".
	distinctPT := map[string]int{}
	trueMatchCount := 0
	for _, c := range funcSet {
		seeds := buildSeeds(c)
		rec, derr := Decrypt3x128Cfg(cfg, seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], cts[0])
		if derr != nil {
			continue
		}
		distinctPT[string(rec)]++
		if len(kpa0) > 0 && string(rec) == string(kpa0) {
			trueMatchCount++
		}
	}
	t.Logf("survivors decrypt wire 0 to %d DISTINCT plaintexts; %d survivor(s) equal the true plaintext", len(distinctPT), trueMatchCount)
	if len(lockSet) > 1 {
		t.Logf("NOTE: %d lock constants survive; %d distinct plaintexts. See report on the structural COA limit.", len(lockSet), len(distinctPT))
	}
}

// ============================================================================
// Stage 2.5 — Crib KPA (48 bytes) with UNKNOWN startPixels
// ============================================================================

// TestRedTeamNullHashAttackCribNoStartPixels closes the gap between Stage 2
// (crib + startPixels granted) and Stage 3 (no crib + startPixels brute).
// Threat model: a 48-byte crib (first 48 plaintext bytes), one wire, fresh
// nonce, and — unlike Stage 2 — NO startPixel concession. The three
// per-snake startPixels are brute-forced over [0,third) alongside the
// per-snake dataSeed lo, joined by the crib-derived 16-byte lane-prefix
// anchor (Phase A', identical to Stage 2). The hypothesis under test: a
// 48-byte crib is a strong enough anchor to resolve the lock low-byte
// ambiguity that a content-agnostic Stage 3 attack could not, yielding
// unique recovery even without the startPixel concession.
//
// Attacker inputs in the decision path: crib = kpaFull[:48], the wire, and
// the parsed public header. start_pixels, truth_labonly and the non-crib
// plaintext are read only in the post-hoc decorative validation.
func TestRedTeamNullHashAttackCribNoStartPixels(t *testing.T) {
	dir := nullHashAttackDir()
	// Regenerate a fresh single-expose victim so this test is
	// order-independent; see the note on TestRedTeamNullHashAttack above.
	writeSingleNullHashExpose(t, dir, 512, 512, 1)
	ct, err := os.ReadFile(filepath.Join(dir, "ct.bin"))
	if err != nil {
		t.Fatalf("read ct.bin (run TestRedTeamNullHashExpose first): %v", err)
	}
	kpaFull, err := os.ReadFile(filepath.Join(dir, "kpa.bin"))
	if err != nil {
		t.Fatalf("read kpa.bin: %v", err)
	}
	metaRaw, err := os.ReadFile(filepath.Join(dir, "cell.meta.json"))
	if err != nil {
		t.Fatalf("read cell.meta.json: %v", err)
	}
	var meta struct {
		MainNonceHex   string `json:"main_nonce_hex"`
		InterlockNonce string `json:"interlock_nonce_hex"`
		Width          int    `json:"width"`
		Height         int    `json:"height"`
		TotalPixels    int    `json:"total_pixels"`
		HeaderSize     int    `json:"header_size"`
		StartPixels    struct {
			S1 int `json:"snake_1"`
			S2 int `json:"snake_2"`
			S3 int `json:"snake_3"`
		} `json:"start_pixels"`
		Truth map[string]string `json:"truth_labonly"`
	}
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatalf("parse meta: %v", err)
	}
	if len(kpaFull) < nullHashCribLen {
		t.Fatalf("plaintext shorter than crib")
	}
	crib := kpaFull[:nullHashCribLen]
	ptLen := len(kpaFull) // public geometry

	cfg := &Config{NonceBits: 128, BarrierFill: 1}
	mainNonce, _ := hex.DecodeString(meta.MainNonceHex)
	ilNonce, _ := hex.DecodeString(meta.InterlockNonce)

	container := ct[meta.HeaderSize:]
	totalPixels := meta.TotalPixels
	third := totalPixels / 3
	thirdPixels2 := totalPixels - 2*third
	off1 := third * Channels
	off2 := 2 * third * Channels
	regions := [3][]byte{
		container[0:off1],
		container[off1:off2],
		container[off2 : totalPixels*Channels],
	}
	widths := [3]int{third, third, thirdPixels2}
	caps := [3]int{
		(third * DataBitsPerPixel) / 8,
		(third * DataBitsPerPixel) / 8,
		(thirdPixels2 * DataBitsPerPixel) / 8,
	}

	const lanePrefixLen = 16 // 8 crib+len chunks x 2 bytes/lane
	probe := make([]byte, ptLen)
	copy(probe, crib)

	numCPU := runtime.NumCPU()
	if numCPU > 12 {
		numCPU = 12
	}

	start := time.Now()

	// ---------- Phase A': index lock constants by crib lane prefixes ----------
	type laneKey struct {
		s   string
		val uint16
	}
	shardResults := make([][3][]laneKey, numCPU)
	var wgA sync.WaitGroup
	perW := (65536 + numCPU - 1) / numCPU
	for w := 0; w < numCPU; w++ {
		lo0 := w * perW
		hi0 := lo0 + perW
		if hi0 > 65536 {
			hi0 = 65536
		}
		if lo0 >= hi0 {
			continue
		}
		wgA.Add(1)
		go func(w, lo0, hi0 int) {
			defer wgA.Done()
			var local [3][]laneKey
			for c := lo0; c < hi0; c++ {
				ls := seedConst(byte(c>>8), byte(c&0xFF))
				bp := buildLockBatchPRF48_128Cfg(cfg, ls, ilNonce)
				p0, p1, p2 := splitForTriple48LockedCfg(cfg, probe, bp)
				ps := [3][]byte{p0, p1, p2}
				for i := 0; i < 3; i++ {
					if len(ps[i]) < lanePrefixLen {
						continue
					}
					local[i] = append(local[i], laneKey{string(ps[i][:lanePrefixLen]), uint16(c)})
				}
			}
			shardResults[w] = local
		}(w, lo0, hi0)
	}
	wgA.Wait()
	lockIdx := [3]map[string][]uint16{{}, {}, {}}
	for _, sh := range shardResults {
		for i := 0; i < 3; i++ {
			for _, lk := range sh[i] {
				lockIdx[i][lk.s] = append(lockIdx[i][lk.s], lk.val)
			}
		}
	}
	phaseA := time.Now()

	// ---------- Phase B: brute (noisePos, dataSeed lo, startPixel) ----------
	// Per (noisePos, snake): lockConst -> witnesses (dataLo, startPixel).
	type witness struct {
		dLo byte
		sp  int
	}
	var snakeHits [8][3]map[uint16][]witness
	for np := 0; np < 8; np++ {
		for i := 0; i < 3; i++ {
			snakeHits[np][i] = map[uint16][]witness{}
		}
	}
	var mu sync.Mutex
	var decodeCount int64
	var wgB sync.WaitGroup
	for np := 0; np < 8; np++ {
		for i := 0; i < 3; i++ {
			wgB.Add(1)
			go func(np, i int) {
				defer wgB.Done()
				w := widths[i]
				noiseSeed := seedConst(byte(np), 0)
				startSeed := seedConst(0, 0)
				decoded := make([]byte, caps[i])
				local := map[uint16][]witness{}
				var dc int64
				for d := 0; d < 256; d++ {
					dataSeed := seedConst(byte(d), 0)
					for sp := 0; sp < w; sp++ {
						startSeed.Components[0] = uint64(sp)
						for k := range decoded {
							decoded[k] = 0
						}
						process128Cfg(cfg, noiseSeed, dataSeed, startSeed, mainNonce,
							regions[i], w, 1, decoded, false, 1)
						dc++
						fn := firstNull(decoded)
						if fn == len(decoded) || !cobsStructurallyValid(decoded[:fn]) {
							continue
						}
						p := cobsDecode(decoded[:fn])
						if len(p) < lanePrefixLen {
							continue
						}
						if lcs, ok := lockIdx[i][string(p[:lanePrefixLen])]; ok {
							for _, lc := range lcs {
								local[lc] = append(local[lc], witness{byte(d), sp})
							}
						}
					}
				}
				mu.Lock()
				for lc, ws := range local {
					snakeHits[np][i][lc] = append(snakeHits[np][i][lc], ws...)
				}
				decodeCount += dc
				mu.Unlock()
			}(np, i)
		}
	}
	wgB.Wait()

	// ---------- Join across snakes on consistent (noisePos, lockConst) ----------
	type cand struct {
		noisePos byte
		lock     uint16
		d        [3]byte
		sp       [3]byte
	}
	var preJoin []cand
	for np := 0; np < 8; np++ {
		for lc, w0 := range snakeHits[np][0] {
			w1, ok1 := snakeHits[np][1][lc]
			w2, ok2 := snakeHits[np][2][lc]
			if !ok1 || !ok2 {
				continue
			}
			for _, a := range w0 {
				for _, b := range w1 {
					for _, cc := range w2 {
						preJoin = append(preJoin, cand{
							byte(np), lc,
							[3]byte{a.dLo, b.dLo, cc.dLo},
							[3]byte{byte(a.sp), byte(b.sp), byte(cc.sp)},
						})
					}
				}
			}
		}
	}

	// ---------- Full structural verification ----------
	type survivor struct {
		c   cand
		rec []byte
	}
	var survivors []survivor
	restOK := func(rest []byte) bool { return printableASCII(rest) }
	for _, c := range preJoin {
		seeds := nullHashCandidateSeeds(c.noisePos, c.lock, c.d, c.sp)
		ok, rec := verifyRecovered(cfg, seeds, ct, crib, nullHashCribLen, restOK)
		if ok {
			survivors = append(survivors, survivor{c, rec})
		}
	}
	elapsed := time.Since(start)

	// Functional dedup over the wire-invisible dataSeed low-bit pairs; the
	// startPixels are fully observable so they enter the key verbatim.
	norm := func(x byte) byte { return byte((int(x)%7)<<5) | (x >> 3) }
	funcKey := func(c cand) string {
		return string([]byte{c.noisePos, byte(c.lock >> 8), byte(c.lock & 0xFF),
			norm(c.d[0]), norm(c.d[1]), norm(c.d[2]), c.sp[0], c.sp[1], c.sp[2]})
	}
	funcSet := map[string]cand{}
	for _, s := range survivors {
		funcSet[funcKey(s.c)] = s.c
	}

	t.Logf("=== nullHash Crib-KPA, UNKNOWN startPixels (crib=%d bytes, 1 wire) ===", nullHashCribLen)
	t.Logf("wall-clock total:       %v", elapsed)
	t.Logf("  Phase A' (2^16 splits): %v", phaseA.Sub(start))
	t.Logf("  Phase B + verify:       %v", elapsed-phaseA.Sub(start))
	t.Logf("per-snake decodes: %d (8 noisePos x 256 dataSeed x [0,third) startPixel x 3 snakes)", decodeCount)
	t.Logf("pre-join candidates: %d", len(preJoin))
	t.Logf("survivors after full verification: %d raw, %d functionally distinct", len(survivors), len(funcSet))
	if len(funcSet) == 0 {
		t.Fatalf("Stage 2.5 attack failed: no survivor")
	}
	for _, c := range funcSet {
		t.Logf("  survivor: noisePos=%d lock=0x%04x dLo=%02x %02x %02x sp=%d,%d,%d",
			c.noisePos, c.lock, c.d[0], c.d[1], c.d[2], int(c.sp[0]), int(c.sp[1]), int(c.sp[2]))
	}

	// ---------- Lab-only validation (post-hoc, decorative) ----------
	tv := func(k string) uint16 {
		var v uint64
		b, _ := hex.DecodeString(meta.Truth[k][2:])
		for _, x := range b {
			v = v<<8 | uint64(x)
		}
		return uint16(v)
	}
	truthNoisePos := int((tv("K_noiseSeed") >> 8) & 7)
	truthLock := tv("K_lockSeed")
	truthDLo := [3]byte{byte(tv("K_dataSeed_1") >> 8), byte(tv("K_dataSeed_2") >> 8), byte(tv("K_dataSeed_3") >> 8)}
	truthSP := [3]int{meta.StartPixels.S1 % third, meta.StartPixels.S2 % third, meta.StartPixels.S3 % thirdPixels2}
	t.Logf("--- labonly validation ---")
	t.Logf("truth: noisePos=%d lock=0x%04x dLo=%02x %02x %02x spMod=%d,%d,%d",
		truthNoisePos, truthLock, truthDLo[0], truthDLo[1], truthDLo[2], truthSP[0], truthSP[1], truthSP[2])
	matchTruth := false
	for _, c := range funcSet {
		if c.noisePos == byte(truthNoisePos) && c.lock == truthLock &&
			int(c.sp[0]) == truthSP[0] && int(c.sp[1]) == truthSP[1] && int(c.sp[2]) == truthSP[2] &&
			norm(c.d[0]) == norm(truthDLo[0]) && norm(c.d[1]) == norm(truthDLo[1]) && norm(c.d[2]) == norm(truthDLo[2]) {
			matchTruth = true
		}
	}
	t.Logf("the truth constants+startPixels are among the survivors: %v", matchTruth)
	fullMatch := false
	for _, s := range survivors {
		if string(s.rec) == string(kpaFull) {
			fullMatch = true
			break
		}
	}
	t.Logf("a survivor reproduces the FULL original plaintext beyond crib: %v", fullMatch)
	if !fullMatch {
		t.Errorf("no survivor reproduced the original plaintext beyond the crib")
	}
}
