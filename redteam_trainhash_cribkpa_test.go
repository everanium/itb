//go:build redteam

package itb

// Crib KPA against trainHash: how far does a 48-byte plaintext prefix
// carry an attacker who holds one ciphertext and nothing else?
//
// Threat model. The attacker holds the wire bytes of ONE message, the
// first 48 bytes of its plaintext, the public configuration (nonce width
// and the geometry off the header), and the knowledge that the primitive
// is trainHash. Not held: the rest of the plaintext, any of the eight
// seeds, lockSeed.Components, the interlock nonce, the per-region start
// pixels. Every value the decision path consumes below is derived from
// those three inputs; the fixture's recorded seeds and nonce are read
// only in the terminal validation block, after the answer is fixed.
//
// Structure this exploits, all of it public.
//
//  1. trainHash(buf, s0, s1) = (3^n·(s0&0xFF) + C(buf), 5^n·(s1&0xFF) +
//     D(buf)) mod 256, where n = len(buf) and C, D depend on buf alone.
//     Both lanes are affine bijections of the low seed byte under a
//     buf-determined constant the attacker computes for himself.
//
//  2. ChainHash128 re-feeds the same buf every round
//     (seed128.go:186-190), and (comps[i]^hLo)&0xFF == (comps[i]&0xFF)^hLo
//     once hLo < 256. The lo and hi lanes therefore evolve independently
//     and only the low byte of each component enters. The effective key
//     is 5 bytes per lane for the Interlocked Barrier cascade
//     (lockComps = [keyLo, keyHi, Components[0..7]], so lo consumes
//     indices 0,2,4,6,8) and 4 bytes per lane for a per-pixel seed.
//
//  3. Every chunk's rank is the 128-bit pair that cascade returns, so
//     under an 8-bit-per-lane primitive the rank carries 16 bits and the
//     reachable mask-triple space is at most 2^16 — not the C(48,16) ·
//     C(32,16) ≈ 2^70.2 of the construction.
//
//  4. COBS places a nonzero buf byte at index i at output index i+1
//     regardless of how many zeros precede it: each consumed zero is
//     replaced by a code byte at the same net cost. The interlock-nonce
//     fragment therefore shifts the barrier lane by exactly lens[i]+1
//     output bytes and nothing else.
//
// The attack runs in three stages. Stage 1 pins the per-chunk ranks over
// the crib by joining the three regions against one shared rank
// hypothesis. Stage 2 recovers the cascade's effective key by
// meet-in-the-middle over those pinned ranks and forward-computes every
// remaining rank. Stage 3 walks the container pixel by pixel under a
// printable-ASCII plaintext model and reads the message out.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------
// Public algebra of the primitive. Nothing here touches victim material:
// every routine is a restatement of code the attacker reads in the
// shipped source, evaluated on inputs he chooses.
// ---------------------------------------------------------------------

// tcLaneConsts returns the affine constants of trainHash over a given
// buf: the lo lane maps s0 to aLo·(s0&0xFF) + cLo and the hi lane maps
// s1 to aHi·(s1&0xFF) + cHi, both mod 256. Obtained by evaluating the
// public hash at two points rather than by re-deriving 3^n / 5^n.
func tcLaneConsts(buf []byte) (aLo, cLo, aHi, cHi byte) {
	l0, h0 := thLeak_trainHash(buf, 0, 0)
	l1, h1 := thLeak_trainHash(buf, 1, 1)
	cLo, cHi = byte(l0), byte(h0)
	aLo, aHi = byte(l1)-cLo, byte(h1)-cHi
	return
}

// tcInv256 returns the multiplicative inverse of an odd byte mod 256.
func tcInv256(a byte) byte {
	var inv byte
	for x := 0; x < 256; x++ {
		if a*byte(x) == 1 {
			inv = byte(x)
			break
		}
	}
	return inv
}

// tcLockBuf rebuilds the 13-byte Interlocked Barrier fill block for a
// group index: [0x03 ‖ LE64(groupIdx) ‖ 4×0x00] (interlock48.go:334-338).
func tcLockBuf(groupIdx uint64) []byte {
	buf := make([]byte, 13)
	buf[0] = 0x03
	binary.LittleEndian.PutUint64(buf[1:9], groupIdx)
	return buf
}

// tcPixelBuf rebuilds the per-pixel hash block a region's noise and data
// seeds consume at walk index p: [LE32(p) ‖ mainNonce]
// (seed128.go:194-197 over the lane scratch of process_generic.go:22).
func tcPixelBuf(p int, mainNonce []byte) []byte {
	buf := make([]byte, 4+len(mainNonce))
	binary.LittleEndian.PutUint32(buf, uint32(p))
	copy(buf[4:], mainNonce)
	return buf
}

// tcCascade evaluates one lane of the ChainHash cascade on the low key
// bytes: s = f(k[0]); s = f(k[j]^s) for each further byte, where
// f(x) = a·x + c.
func tcCascade(k []byte, a, c byte) byte {
	s := a*k[0] + c
	for j := 1; j < len(k); j++ {
		s = a*(k[j]^s) + c
	}
	return s
}

// ---------------------------------------------------------------------
// Probes — attacker-side measurements on attacker-chosen material.
// ---------------------------------------------------------------------

// TestRedTeamTrainHashCribProbes measures the three structural facts the
// crib attack rests on, all on seeds the probe draws itself. An attacker
// holding the ITB source and knowing the target runs trainHash
// reproduces every number here without observing a victim byte.
func TestRedTeamTrainHashCribProbes(t *testing.T) {
	cfg := &Config{NonceBits: 128, BarrierFill: 1}

	// P1 — the factor-1 mask fill is rankToMaskTriple48 and nothing else.
	{
		var prf [8]uint64
		var masks [lockBatchFactor48Max][3]uint64
		mismatch := 0
		for i := 0; i < 4096; i++ {
			var b [16]byte
			if _, err := rand.Read(b[:]); err != nil {
				t.Fatal(err)
			}
			lo := binary.LittleEndian.Uint64(b[0:8])
			hi := binary.LittleEndian.Uint64(b[8:16])
			prf[0], prf[1] = lo, hi
			fillLockMasksTriple48(&prf, 1, &masks)
			m0, m1, m2 := rankToMaskTriple48(lo, hi)
			if masks[0][0] != m0 || masks[0][1] != m1 || masks[0][2] != m2 {
				mismatch++
			}
		}
		t.Logf("P1 factor-1 mask fill == rankToMaskTriple48 on 4096 random ranks: mismatches=%d", mismatch)
		if mismatch != 0 {
			t.Fatalf("P1 broken: %d mismatches — the per-chunk enumeration premise fails", mismatch)
		}
	}

	// P2 — the reachable mask-triple space under an 8-bit-per-lane
	// primitive. The construction's space is C(48,16)·C(32,16) ≈ 2^70.2;
	// a rank whose two lanes are each one byte wide cannot reach more
	// than 2^16 of it.
	{
		type triple struct{ a, b, c uint64 }
		seen := map[triple]struct{}{}
		for lo := 0; lo < 256; lo++ {
			for hi := 0; hi < 256; hi++ {
				m0, m1, m2 := rankToMaskTriple48(uint64(lo), uint64(hi))
				seen[triple{m0, m1, m2}] = struct{}{}
			}
		}
		t.Logf("P2 reachable mask triples over the whole 8-bit-per-lane rank space: %d distinct of 65536 ranks "+
			"(construction space C(48,16)·C(32,16) = %d · %d ≈ 2^70.20)", len(seen), interlockA48, interlockB48)
	}

	// P3 — the effective key width of the cascade. Mutating the high 56
	// bits of any component, or any odd-index component of a per-pixel
	// seed, must leave the output untouched; mutating a low byte of an
	// even-index component must move it.
	{
		s, err := NewSeed128(512, thLeak_trainHash)
		if err != nil {
			t.Fatal(err)
		}
		buf := tcPixelBuf(7, make([]byte, currentNonceSizeCfg(cfg)))
		base, _ := s.ChainHash128(buf)

		highOnly, _ := SeedFromComponents128(thLeak_trainHash, append([]uint64(nil), s.Components...)...)
		for i := range highOnly.Components {
			highOnly.Components[i] ^= 0xDEADBEEFCAFEBA00
		}
		hLo, _ := highOnly.ChainHash128(buf)

		oddOnly, _ := SeedFromComponents128(thLeak_trainHash, append([]uint64(nil), s.Components...)...)
		for i := 1; i < len(oddOnly.Components); i += 2 {
			oddOnly.Components[i] ^= 0xFF
		}
		oLo, _ := oddOnly.ChainHash128(buf)

		evenOne, _ := SeedFromComponents128(thLeak_trainHash, append([]uint64(nil), s.Components...)...)
		evenOne.Components[4] ^= 1
		eLo, _ := evenOne.ChainHash128(buf)

		// The closed form: lo output == tcCascade over the low bytes of
		// the even-index components under the buf-derived constants.
		aLo, cLo, _, _ := tcLaneConsts(buf)
		k := []byte{}
		for i := 0; i < len(s.Components); i += 2 {
			k = append(k, byte(s.Components[i]))
		}
		closed := tcCascade(k, aLo, cLo)

		t.Logf("P3 effective key: high-56-bit mutation keeps lo output:%v  odd-index mutation keeps lo output:%v  "+
			"even-index low-byte flip moves it:%v  closed form reproduces lo output:%v (%d key bytes per lane)",
			hLo == base, oLo == base, eLo != base, uint64(closed) == base, len(k))
		if hLo != base || oLo != base || eLo == base || uint64(closed) != base {
			t.Fatalf("P3 structural assumption violated")
		}
	}

	// P4 — COBS puts a nonzero buf byte at index i at output index i+1
	// whatever precedes it, so the fragment shift is exactly lens[i]+1.
	{
		bad := 0
		for trial := 0; trial < 512; trial++ {
			src := make([]byte, 200)
			if _, err := rand.Read(src); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 12; i++ {
				src[int(src[i])%len(src)] = 0x00
			}
			enc := cobsEncode(src)
			for i, b := range src {
				if b != 0x00 && enc[i+1] != b {
					bad++
					break
				}
			}
		}
		t.Logf("P4 COBS offset identity (nonzero src[i] lands at enc[i+1]) over 512 zero-seeded buffers: violations=%d", bad)
		if bad != 0 {
			t.Fatalf("P4 broken: the fragment shift is not a constant")
		}
	}
}

// ---------------------------------------------------------------------
// Attacker-side wire handling.
// ---------------------------------------------------------------------

// tcAllMasks precomputes the mask triple of every rank an 8-bit-per-lane
// primitive can produce. Index is lo | hi<<8. This table IS the whole
// per-chunk mask space under trainHash — see probe P2.
func tcAllMasks() *[65536][3]uint64 {
	m := new([65536][3]uint64)
	for lo := 0; lo < 256; lo++ {
		for hi := 0; hi < 256; hi++ {
			a, b, c := rankToMaskTriple48(uint64(lo), uint64(hi))
			m[lo|hi<<8] = [3]uint64{a, b, c}
		}
	}
	return m
}

// tcReadPixel unmasks one pixel's 56-bit window under a candidate
// (noisePos, rotation), returning the seven stream bytes it carries.
// The per-channel XOR is left unapplied: under an 8-bit-output primitive
// dataHash >> DataRotationBits is five bits wide, so only channel 0
// carries a mask and it reaches only bits 0..4 of out[0]. Every other
// bit of the window is exact.
func tcReadPixel(region []byte, linearIdx int, np, rot, xor uint) [7]byte {
	var packed uint64
	noiseMask := byte(1) << np
	for ch := 0; ch < Channels; ch++ {
		b := region[linearIdx*Channels+ch]
		low := b & (noiseMask - 1)
		high := b >> (np + 1)
		d := low | (high << np)
		d = rotateBits7(d, 7-rot)
		if ch == 0 {
			d ^= byte(xor)
		}
		packed |= uint64(d) << uint(ch*DataBitsPerChannel)
	}
	var out [7]byte
	for j := 0; j < 7; j++ {
		out[j] = byte(packed >> uint(8*j))
	}
	return out
}

// tcRegionGeom describes one interlocked region as the attacker sees it
// off the wire: its pixel window, its walk width, and the byte offset at
// which the Rank Barrier lane begins inside its COBS stream.
type tcRegionGeom struct {
	pix     []byte // container slice for this region
	width   int    // pixels in the region's walk
	fragLen int    // interlock-nonce fragment length (public: nonceSplit)
	base    int    // stream offset of barrier[0] == fragLen + 1 (probe P4)
}

// streamPos returns the stream byte offset of barrier lane byte j.
func (g tcRegionGeom) streamPos(j int) int { return g.base + j }

// pixelOf returns the walk index of the pixel carrying stream byte s,
// and the byte's position inside that pixel's seven-byte window.
func (g tcRegionGeom) pixelOf(s int) (w, off int) { return s / 7, s % 7 }

// tcWriteVictim encodes one victim message under trainHash and records
// the lab reference beside it. corpus selects the plaintext
// distribution: "ascii" draws printable characters from a fixed
// alphabet, "binary" draws uniform bytes. The distinction is load
// bearing — Stage 3's disambiguator is a plaintext model, so a recovery
// figure is conditional on the distribution it was measured against.
func tcWriteVictim(t *testing.T, outDir, corpus string, keyBits, ptSize int) {
	t.Helper()
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := &Config{NonceBits: 128, BarrierFill: 1}
	plaintext := make([]byte, ptSize)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatal(err)
	}
	switch corpus {
	case "ascii":
		// Uniform printable ASCII over a 69-character alphabet: every
		// byte independent, ~6.1 bits each, no words and no syntax. A
		// plaintext model has nothing to discriminate on here beyond
		// alphabet membership.
		const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ,.:;-!?"
		for i := range plaintext {
			plaintext[i] = alphabet[int(plaintext[i])%len(alphabet)]
		}
	case "json":
		// Structured text: a JSON array of records over a fixed key set,
		// so keys, punctuation and field shapes repeat the way a real
		// document's do. The byte stream is cut to the requested length,
		// which truncates the final record — the tail is still structured
		// text, it is simply not a parseable document.
		names := []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace", "heidi"}
		roles := []string{"admin", "editor", "viewer", "owner"}
		var b []byte
		b = append(b, '{', '"', 'r', 'e', 'c', 'o', 'r', 'd', 's', '"', ':', '[')
		for i := 0; len(b) < ptSize; i++ {
			if i > 0 {
				b = append(b, ',')
			}
			rec := fmt.Sprintf(`{"user_id":%d,"user_name":"%s","role":"%s","active":%v,"score":%d.%02d}`,
				1000+i, names[i%len(names)], roles[i%len(roles)], i%2 == 0, 10+i%90, i%100)
			b = append(b, rec...)
		}
		copy(plaintext, b[:ptSize])
	}
	mk := func() *Seed128 {
		s, err := NewSeed128(keyBits, thLeak_trainHash)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	ns, ls := mk(), mk()
	d1, d2, d3 := mk(), mk(), mk()
	s1, s2, s3 := mk(), mk(), mk()
	ilNonce := make([]byte, currentNonceSizeCfg(cfg))
	if _, err := rand.Read(ilNonce); err != nil {
		t.Fatal(err)
	}
	setBrokenTestInterlockNonceOnly(t, ilNonce)
	ct, err := Encrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	back, err := Decrypt3x128Cfg(cfg, ns, ls, d1, d2, d3, s1, s2, s3, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, plaintext) {
		t.Fatal("roundtrip mismatch")
	}
	nonceLen := currentNonceSizeCfg(cfg)
	mainNonce := ct[:nonceLen]
	totalPixels := int(binary.BigEndian.Uint16(ct[nonceLen:])) * int(binary.BigEndian.Uint16(ct[nonceLen+2:]))
	third, thirdPixels2, _ := tripleThirdCaps(totalPixels)
	dump := func(s *Seed128) []uint64 { return append([]uint64(nil), s.Components...) }
	meta := map[string]any{
		"corpus":              corpus,
		"main_nonce_hex":      hex.EncodeToString(mainNonce),
		"interlock_nonce_hex": hex.EncodeToString(ilNonce),
		"start_pixels": map[string]int{
			"s1": s1.deriveStartPixel(mainNonce, third),
			"s2": s2.deriveStartPixel(mainNonce, third),
			"s3": s3.deriveStartPixel(mainNonce, thirdPixels2),
		},
		"debug_seeds": map[string][]uint64{
			"noise": dump(ns), "lock": dump(ls),
			"data1": dump(d1), "data2": dump(d2), "data3": dump(d3),
			"start1": dump(s1), "start2": dump(s2), "start3": dump(s3),
		},
	}
	if err := os.WriteFile(filepath.Join(outDir, "ct.bin"), ct, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "kpa.bin"), plaintext, 0o644); err != nil {
		t.Fatal(err)
	}
	mj, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "cell.meta.json"), mj, 0o644); err != nil {
		t.Fatal(err)
	}
}

// tcSolveLane recovers the five effective key bytes of one cascade lane
// from per-chunk candidate output SETS rather than exact outputs.
//
// The chain is s1 = f_i(k0); s_{j+1} = f_i(k_j ^ s_j) over five rounds,
// with f_i(x) = a_i·x + c_i the affine map trainHash induces on the lane
// for sample i's fill block. Meet in the middle at s3: the forward half
// enumerates (k0,k1,k2) into a signature table over three pinning
// samples, the backward half enumerates (k3,k4) and, for each
// combination of candidate outputs those three samples admit, inverts
// two rounds to the same signature. Survivors are verified by forward
// evaluation against every sample's set.
//
// The candidate sets are what makes this a set-valued problem: a chunk's
// observation pins a preimage class of ranks, not one rank, and the
// cascade is the only thing that separates the class members.
func tcSolveLane(a, c []byte, sets [][]byte) [][5]byte {
	n := len(sets)
	if n < 3 {
		return nil
	}
	ainv := make([]byte, n)
	for i := range a {
		ainv[i] = tcInv256(a[i])
	}
	ord := make([]int, n)
	for i := range ord {
		ord[i] = i
	}
	sort.SliceStable(ord, func(x, y int) bool { return len(sets[ord[x]]) < len(sets[ord[y]]) })
	p := [3]int{ord[0], ord[1], ord[2]}

	const span = 1 << 24
	head := make([]int32, span)
	for i := range head {
		head[i] = -1
	}
	next := make([]int32, span)
	for k0 := 0; k0 < 256; k0++ {
		var s1 [3]byte
		for j := 0; j < 3; j++ {
			s1[j] = a[p[j]]*byte(k0) + c[p[j]]
		}
		for k1 := 0; k1 < 256; k1++ {
			var s2 [3]byte
			for j := 0; j < 3; j++ {
				s2[j] = a[p[j]]*(byte(k1)^s1[j]) + c[p[j]]
			}
			for k2 := 0; k2 < 256; k2++ {
				sig := int32(a[p[0]]*(byte(k2)^s2[0]) + c[p[0]])
				sig |= int32(a[p[1]]*(byte(k2)^s2[1])+c[p[1]]) << 8
				sig |= int32(a[p[2]]*(byte(k2)^s2[2])+c[p[2]]) << 16
				idx := int32(k0 | k1<<8 | k2<<16)
				next[idx] = head[sig]
				head[sig] = idx
			}
		}
	}

	seen := map[[5]byte]struct{}{}
	var found [][5]byte
	for k3 := 0; k3 < 256; k3++ {
		for k4 := 0; k4 < 256; k4++ {
			for _, v0 := range sets[p[0]] {
				s4 := ainv[p[0]]*(v0-c[p[0]]) ^ byte(k4)
				g0 := ainv[p[0]]*(s4-c[p[0]]) ^ byte(k3)
				for _, v1 := range sets[p[1]] {
					s4 := ainv[p[1]]*(v1-c[p[1]]) ^ byte(k4)
					g1 := ainv[p[1]]*(s4-c[p[1]]) ^ byte(k3)
					for _, v2 := range sets[p[2]] {
						s4 := ainv[p[2]]*(v2-c[p[2]]) ^ byte(k4)
						g2 := ainv[p[2]]*(s4-c[p[2]]) ^ byte(k3)
						sig := int32(g0) | int32(g1)<<8 | int32(g2)<<16
						for e := head[sig]; e >= 0; e = next[e] {
							key := [5]byte{byte(e), byte(e >> 8), byte(e >> 16), byte(k3), byte(k4)}
							ok := true
							for i := 0; i < n && ok; i++ {
								out := tcCascade(key[:], a[i], c[i])
								hit := false
								for _, v := range sets[i] {
									if v == out {
										hit = true
										break
									}
								}
								ok = hit
							}
							if ok {
								if _, dup := seen[key]; !dup {
									seen[key] = struct{}{}
									found = append(found, key)
								}
							}
						}
					}
				}
			}
		}
	}
	return found
}

// tcPixCfg is a resolved per-pixel configuration.
type tcPixCfg struct {
	np, rot, xor uint
	ok           bool // (noisePos, rotation) resolved
	xorOK        bool // channel-0 XOR resolved too
}

// tcAttack carries the attacker's whole state: what came off the wire,
// what the crib pins, and what has been resolved so far.
type tcAttack struct {
	cfg        *Config
	regions    [3][]byte
	widths     [3]int
	base       [3]int // stream offset of barrier[0] per region
	startPixel [3]int // recovered, not granted
	pix        [3][]tcPixCfg
	crib       []byte
	masks      *[65536][3]uint64
}

// chunkX returns the 48-bit framed word of chunk k, which the crib pins
// for every k whose six bytes lie inside the crib. Chunk 0 straddles the
// 4-byte length header and is excluded.
func (a *tcAttack) chunkX(k int) (uint64, bool) {
	if k < 1 || 6*k+6-4 > len(a.crib) {
		return 0, false
	}
	var x uint64
	for i := 0; i < 6; i++ {
		x |= uint64(a.crib[6*k+i-4]) << uint(8*i)
	}
	return x, true
}

// chunkXPartial returns chunk k's framed word together with the bit mask
// over which the crib determines it. The chunk that straddles the end of
// the crib is partly known — four of its six bytes here — and those bits
// still constrain the lane output, because a Rank Barrier lane bit is a
// copy of one chunk bit selected by the mask.
func (a *tcAttack) chunkXPartial(k int) (x, known uint64) {
	for i := 0; i < 6; i++ {
		fi := 6*k + i
		if fi < 4 {
			continue // the length prefix is not part of the crib
		}
		if fi-4 >= len(a.crib) {
			continue
		}
		x |= uint64(a.crib[fi-4]) << uint(8*i)
		known |= uint64(0xFF) << uint(8*i)
	}
	return x, known
}

// laneBytes returns the lane values (l0,l1,l2) chunk k takes under a
// candidate rank, given the crib-known chunk word.
func (a *tcAttack) laneBytes(k int, rank int) (l0, l1, l2 uint16, ok bool) {
	x, ok := a.chunkX(k)
	if !ok {
		return
	}
	m := a.masks[rank]
	l0, l1, l2 = chunk48lock(x, m[0], m[1], m[2])
	return l0, l1, l2, true
}

// readLaneByte returns barrier byte j of region r as the resolved pixel
// configuration reads it, together with the bit mask over which the
// reading is exact. A byte at a pixel's byte-0 slot is exact only in its
// top three bits: channel 0 occupies bits 0..6 of that byte and carries
// the five-bit channel-0 XOR mask in bits 0..4, while bit 7 already
// belongs to channel 1, which an 8-bit-output primitive leaves unmasked.
// Every other byte of the window is exact throughout.
func (a *tcAttack) readLaneByte(r, j int) (val, bits byte, ok bool) {
	s := a.base[r] + j
	w, off := s/7, s%7
	if w >= a.widths[r] || w >= len(a.pix[r]) || !a.pix[r][w].ok {
		return 0, 0, false
	}
	c := a.pix[r][w]
	lin := (a.startPixel[r] + w) % a.widths[r]
	win := tcReadPixel(a.regions[r], lin, c.np, c.rot, c.xor)
	if off == 0 && !c.xorOK {
		return win[off], 0xE0, true
	}
	return win[off], 0xFF, true
}

// pinRank filters the rank space of chunk k against every lane bit the
// resolved pixels expose. Returns the surviving ranks — the per-chunk
// preimage class of the observation, which is what the Rank Barrier's
// ambiguity amounts to once the primitive has narrowed the reachable
// rank space to 2^16.
func (a *tcAttack) pinRank(k int) []int {
	type obs struct {
		r, j    int
		v, bits byte
	}
	var o []obs
	for r := 0; r < 3; r++ {
		for _, j := range [2]int{2 * k, 2*k + 1} {
			if v, bits, ok := a.readLaneByte(r, j); ok {
				o = append(o, obs{r, j, v, bits})
			}
		}
	}
	if len(o) == 0 {
		return nil
	}
	var out []int
	for rank := 0; rank < 65536; rank++ {
		l0, l1, l2, ok := a.laneBytes(k, rank)
		if !ok {
			return nil
		}
		lv := [3]uint16{l0, l1, l2}
		good := true
		for _, c := range o {
			var want byte
			if c.j == 2*k {
				want = byte(lv[c.r])
			} else {
				want = byte(lv[c.r] >> 8)
			}
			if (want^c.v)&c.bits != 0 {
				good = false
				break
			}
		}
		if good {
			out = append(out, rank)
		}
	}
	return out
}

// tcBandSolution is one joint hypothesis over the three regions at a
// single walk index: a start pixel and a pixel configuration per region.
type tcBandSolution struct {
	sp  [3]int
	np  [3]uint
	rot [3]uint
}

// tcJoinBand resolves walk index w across all three regions at once by
// requiring that a single shared rank explain the lane values every
// region shows for the anchor chunks. Each anchor is 48 bits of check on
// a 16-bit hypothesis, so the join is self-validating: no ground truth
// enters, and a wrong start pixel or a wrong (noisePos, rotation) has no
// rank that fits.
//
// spKnown selects between the bootstrap (start pixels unknown, the full
// walk enumerated) and the continuation (start pixels already recovered).
func (a *tcAttack) tcJoinBand(w int, anchors [2]int, spKnown bool) []tcBandSolution {
	type rankInfo struct{ l [3]uint16 }
	var tab [2][]rankInfo
	var byL0 [2]map[uint16][]int
	for i, k := range anchors {
		tab[i] = make([]rankInfo, 65536)
		byL0[i] = make(map[uint16][]int, 65536)
		for rank := 0; rank < 65536; rank++ {
			l0, l1, l2, ok := a.laneBytes(k, rank)
			if !ok {
				return nil
			}
			tab[i][rank] = rankInfo{[3]uint16{l0, l1, l2}}
			byL0[i][l0] = append(byL0[i][l0], rank)
		}
	}

	// Lane byte positions of the two anchors inside each region's stream.
	type slot struct{ off [4]int } // lo/hi byte offsets of anchor A then B
	var slots [3]slot
	for r := 0; r < 3; r++ {
		for i, k := range anchors {
			slots[r].off[2*i] = a.base[r] + 2*k - 7*w
			slots[r].off[2*i+1] = a.base[r] + 2*k + 1 - 7*w
		}
		for _, o := range slots[r].off {
			if o < 1 || o > 6 {
				return nil // anchor not clean inside this band
			}
		}
	}

	// Enumerate per-region hypotheses.
	type cand struct {
		sp      int
		np, rot uint
		lA, lB  uint16
	}
	var cands [3][]cand
	for r := 0; r < 3; r++ {
		spLo, spHi := 0, a.widths[r]
		if spKnown {
			spLo, spHi = a.startPixel[r], a.startPixel[r]+1
		}
		for sp := spLo; sp < spHi; sp++ {
			lin := (sp + w) % a.widths[r]
			for np := uint(0); np < 8; np++ {
				for rot := uint(0); rot < 7; rot++ {
					win := tcReadPixel(a.regions[r], lin, np, rot, 0)
					lA := uint16(win[slots[r].off[0]]) | uint16(win[slots[r].off[1]])<<8
					lB := uint16(win[slots[r].off[2]]) | uint16(win[slots[r].off[3]])<<8
					cands[r] = append(cands[r], cand{sp, np, rot, lA, lB})
				}
			}
		}
	}

	idx := [2]map[[2]uint16][]int{}
	for r := 1; r < 3; r++ {
		m := make(map[[2]uint16][]int, len(cands[r]))
		for i, c := range cands[r] {
			m[[2]uint16{c.lA, c.lB}] = append(m[[2]uint16{c.lA, c.lB}], i)
		}
		idx[r-1] = m
	}

	seen := map[tcBandSolution]struct{}{}
	var out []tcBandSolution
	for _, c0 := range cands[0] {
		for _, rA := range byL0[0][c0.lA] {
			for _, rB := range byL0[1][c0.lB] {
				k1 := [2]uint16{tab[0][rA].l[1], tab[1][rB].l[1]}
				k2 := [2]uint16{tab[0][rA].l[2], tab[1][rB].l[2]}
				for _, i1 := range idx[0][k1] {
					for _, i2 := range idx[1][k2] {
						// The noiseSeed is one seed shared by all three
						// regions and its per-pixel block is [LE32(p) ‖
						// nonce] with no region tag, so the noise position
						// at a given walk index is the same in all three.
						if c0.np != cands[1][i1].np || c0.np != cands[2][i2].np {
							continue
						}
						s := tcBandSolution{
							sp:  [3]int{c0.sp, cands[1][i1].sp, cands[2][i2].sp},
							np:  [3]uint{c0.np, cands[1][i1].np, cands[2][i2].np},
							rot: [3]uint{c0.rot, cands[1][i1].rot, cands[2][i2].rot},
						}
						if _, dup := seen[s]; !dup {
							seen[s] = struct{}{}
							out = append(out, s)
						}
					}
				}
			}
		}
	}
	return out
}

// tcRunCribKPA executes the whole Crib KPA against one victim message.
// tcRunCribKPA executes the whole Crib KPA against one victim message.
// tcRunCribKPA executes the Crib KPA against one victim message.
// corpus names the plaintext distribution; modelName names the plaintext
// model the attacker brings, which is deliberately separable from the
// corpus so that corpus structure and model discriminating power can be
// varied one at a time.
func tcRunCribKPA(t *testing.T, corpus string, ptSize int, modelName string) {
	const cribLen = 48
	dir := redteamOutputDir(fmt.Sprintf("trainhash_cribkpa_%s_%d_%s", corpus, ptSize, modelName))
	tcWriteVictim(t, dir, corpus, 512, ptSize)

	ct, err := os.ReadFile(filepath.Join(dir, "ct.bin"))
	if err != nil {
		t.Fatal(err)
	}
	fullPlain, err := os.ReadFile(filepath.Join(dir, "kpa.bin"))
	if err != nil {
		t.Fatal(err)
	}
	// The ONLY plaintext the attacker holds.
	crib := append([]byte(nil), fullPlain[:cribLen]...)

	cfg := &Config{NonceBits: 128, BarrierFill: 1}
	nonceLen := currentNonceSizeCfg(cfg)
	mainNonce := append([]byte(nil), ct[:nonceLen]...)
	W := int(binary.BigEndian.Uint16(ct[nonceLen:]))
	H := int(binary.BigEndian.Uint16(ct[nonceLen+2:]))
	totalPixels := W * H
	container := ct[nonceLen+4:]
	third, thirdPixels2, _ := tripleThirdCaps(totalPixels)
	lens, _ := nonceSplit(nonceLen)

	a := &tcAttack{
		cfg:    cfg,
		crib:   crib,
		masks:  tcAllMasks(),
		widths: [3]int{third, third, thirdPixels2},
		regions: [3][]byte{
			container[0 : third*Channels],
			container[third*Channels : 2*third*Channels],
			container[2*third*Channels : totalPixels*Channels],
		},
		base: [3]int{lens[0] + 1, lens[1] + 1, lens[2] + 1},
	}
	for r := 0; r < 3; r++ {
		a.pix[r] = make([]tcPixCfg, a.widths[r])
	}
	maxChunks := (a.widths[0]*7 - a.base[0]) / 2
	t.Logf("wire: %dx%d = %d pixels, thirds = [%d %d %d], fragment lens = %v, barrier lane starts at stream offset %v",
		W, H, totalPixels, third, third, thirdPixels2, lens, a.base)
	t.Logf("crib: %d plaintext bytes; framed chunks 1..7 fully pinned, chunk 8 four bytes of six, "+
		"chunk 0 straddles the length header and is not pinned", cribLen)

	// =================================================================
	// Stage 1 — pin the per-chunk ranks over the crib.
	//
	// The crib does not reach the lane front: the interlock-nonce
	// fragment occupies stream bytes [1, lens[r]+1) and the barrier lane
	// begins at lens[r]+1, so walk pixel 0 carries the COBS code byte and
	// the fragment and nothing the crib predicts. Resolution therefore
	// begins at walk pixel 1 in every region.
	// =================================================================
	t.Logf("=== Stage 1 — cross-region rank pinning from the crib ===")
	s1start := time.Now()
	sols := a.tcJoinBand(1, [2]int{1, 2}, false)
	t.Logf("Stage 1a: walk pixel 1, anchors = chunks {1,2}, start pixels NOT granted — "+
		"search space %d start-pixel offsets x 56 (noisePos,rotation) per region; joint solutions = %d, %v",
		a.widths[0], len(sols), time.Since(s1start))
	if len(sols) == 0 {
		// A clean stop, and deliberately not a failure: a 0x00 inside
		// the crib-anchored barrier prefix puts a COBS code byte where
		// a lane byte is expected and the cross-region join then finds
		// no common rank. Roughly a third of runs end here.
		//
		// Known limitation. A drift in the pixel reader produces the
		// same observable — no joint solution — so this path cannot
		// distinguish the two, and the gates at the end of the run are
		// never reached to catch it. Those gates therefore cover only
		// the case where the stages complete on a wrong geometry. A
		// check that would separate drift from the legitimate stop has
		// to compare the reader against the shipped encoder directly,
		// independently of any stage outcome; one is not in place.
		t.Logf("Stage 1a found no joint solution — attack stops here")
		return
	}

	// Stage 1b disambiguates whatever Stage 1a left standing: a wrong
	// start pixel moves walk index 2 onto a different container pixel,
	// and no shared rank then explains chunks {5,6} across the three
	// regions. Chunks that straddle the two walk pixels link the bands,
	// and every crib chunk is required to retain at least one rank.
	type geom struct{ s1, s2 tcBandSolution }
	var geoms []geom
	for _, s := range sols {
		for r := 0; r < 3; r++ {
			a.startPixel[r] = s.sp[r]
			a.pix[r][1] = tcPixCfg{np: s.np[r], rot: s.rot[r], ok: true}
		}
		for _, s2 := range a.tcJoinBand(2, [2]int{5, 6}, true) {
			for r := 0; r < 3; r++ {
				a.pix[r][2] = tcPixCfg{np: s2.np[r], rot: s2.rot[r], ok: true}
			}
			ok := true
			for k := 1; k <= 7 && ok; k++ {
				ok = len(a.pinRank(k)) > 0
			}
			if ok {
				geoms = append(geoms, geom{s, s2})
			}
		}
	}
	t.Logf("Stage 1b: walk pixel 2, anchors = chunks {5,6}; geometry hypotheses surviving both joins "+
		"and the cross-band link on every crib chunk = %d", len(geoms))
	if len(geoms) == 0 {
		t.Logf("Stage 1b left no geometry — attack stops here")
		return
	}

	// =================================================================
	// Stage 2 — recover the cascade's effective key and forward-compute
	// the rank of every chunk. This is the step the threat model says
	// needs lockSeed.Components; it is reached instead by
	// meet-in-the-middle over the five bytes per lane that actually
	// enter the cascade under an 8-bit-per-lane primitive.
	// =================================================================
	t.Logf("=== Stage 2 — cascade key recovery by meet-in-the-middle ===")
	s2start := time.Now()
	type laneConst struct{ aL, cL, aH, cH byte }
	lc := make([]laneConst, maxChunks)
	for k := 0; k < maxChunks; k++ {
		al, cl, ah, ch := tcLaneConsts(tcLockBuf(uint64(k)))
		lc[k] = laneConst{al, cl, ah, ch}
	}
	type branch struct {
		g     geom
		ranks []int
		fits  [3][]int // walk pixel 3 configurations the crib admits
	}
	var branches []branch
	totalKeyPairs, totalSurviving := 0, 0
	for gi, g := range geoms {
		for r := 0; r < 3; r++ {
			a.startPixel[r] = g.s1.sp[r]
			a.pix[r][1] = tcPixCfg{np: g.s1.np[r], rot: g.s1.rot[r], ok: true}
			a.pix[r][2] = tcPixCfg{np: g.s2.np[r], rot: g.s2.rot[r], ok: true}
			for w := 3; w < len(a.pix[r]); w++ {
				a.pix[r][w] = tcPixCfg{}
			}
		}
		// Per-chunk preimage classes. A chunk's observation does not pin
		// one rank: several ranks compress the same crib word to the same
		// lane bytes, and that residue is the Rank Barrier's per-chunk
		// ambiguity measured under this observation.
		var aL, cL, aH, cH []byte
		var loSets, hiSets [][]byte
		var cribChunks []int
		for k := 1; k <= 7; k++ {
			c := a.pinRank(k)
			if len(c) == 0 {
				continue
			}
			ls, hs := map[byte]bool{}, map[byte]bool{}
			for _, rk := range c {
				ls[byte(rk&0xFF)] = true
				hs[byte(rk>>8)] = true
			}
			var lv, hv []byte
			for v := range ls {
				lv = append(lv, v)
			}
			for v := range hs {
				hv = append(hv, v)
			}
			sort.Slice(lv, func(i, j int) bool { return lv[i] < lv[j] })
			sort.Slice(hv, func(i, j int) bool { return hv[i] < hv[j] })
			aL, cL, aH, cH = append(aL, lc[k].aL), append(cL, lc[k].cL), append(aH, lc[k].aH), append(cH, lc[k].cH)
			loSets, hiSets = append(loSets, lv), append(hiSets, hv)
			cribChunks = append(cribChunks, k)
			if gi == 0 {
				t.Logf("Stage 1c: chunk %d — ranks surviving the observation %d of the 2^16 the primitive can reach "+
					"(lo-lane values %d, hi-lane values %d)", k, len(c), len(lv), len(hv))
			}
		}
		if len(cribChunks) < 5 {
			continue
		}
		keysLo := tcSolveLane(aL, cL, loSets)
		keysHi := tcSolveLane(aH, cH, hiSets)
		if gi == 0 {
			t.Logf("Stage 2: effective lock-cascade keys consistent with the crib — lo lane %d of the 2^40 space, "+
				"hi lane %d of the 2^40 space", len(keysLo), len(keysHi))
		}
		if len(keysLo) == 0 || len(keysHi) == 0 {
			continue
		}

		// Stage 2b — collapse on the last crib chunks. Chunk 7's six lane
		// bytes straddle walk pixels 2 and 3 and chunk 8 carries four
		// crib bytes of six, so both filter a candidate key pair and
		// resolve walk pixel 3. Neither uses a plaintext model.
		var wins3 [3][][7]byte
		for r := 0; r < 3; r++ {
			wins3[r] = a.tcWindows(r, 3)
		}
		inter := func(x, y []int) []int {
			if x == nil {
				return y
			}
			if y == nil {
				return x
			}
			m := map[int]bool{}
			for _, v := range x {
				m[v] = true
			}
			var out []int
			for _, v := range y {
				if m[v] {
					out = append(out, v)
				}
			}
			return out
		}
		seqs := map[string][3][]int{}
		totalKeyPairs += len(keysLo) * len(keysHi)
		for _, kl := range keysLo {
			lo7 := tcCascade(kl[:], lc[7].aL, lc[7].cL)
			lo8 := tcCascade(kl[:], lc[8].aL, lc[8].cL)
			for _, kh := range keysHi {
				hi7 := tcCascade(kh[:], lc[7].aH, lc[7].cH)
				hi8 := tcCascade(kh[:], lc[8].aH, lc[8].cH)
				ok7, f7 := a.tcChunkBandFit(7, 3, int(lo7)|int(hi7)<<8, &wins3)
				if !ok7 {
					continue
				}
				ok8, f8 := a.tcChunkBandFit(8, 3, int(lo8)|int(hi8)<<8, &wins3)
				if !ok8 {
					continue
				}
				var fits [3][]int
				bad := false
				for r := 0; r < 3; r++ {
					if fits[r] = inter(f7[r], f8[r]); len(fits[r]) == 0 {
						bad = true
						break
					}
				}
				if bad {
					continue
				}
				totalSurviving++
				b := make([]byte, 2*maxChunks)
				for k := 0; k < maxChunks; k++ {
					b[2*k] = tcCascade(kl[:], lc[k].aL, lc[k].cL)
					b[2*k+1] = tcCascade(kh[:], lc[k].aH, lc[k].cH)
				}
				if prev, ok := seqs[string(b)]; ok {
					for r := 0; r < 3; r++ {
						fits[r] = inter(prev[r], fits[r])
					}
				}
				seqs[string(b)] = fits
			}
		}
		for seq, fits := range seqs {
			rk := make([]int, maxChunks)
			for k := 0; k < maxChunks; k++ {
				rk[k] = int(seq[2*k]) | int(seq[2*k+1])<<8
			}
			branches = append(branches, branch{g, rk, fits})
		}
	}
	t.Logf("Stage 2b: key pairs surviving the chunk-7 / chunk-8 walk-pixel-3 check: %d of %d",
		totalSurviving, totalKeyPairs)
	t.Logf("Stage 2: the rank schedule over all %d chunks the container can hold is determined up to %d branches "+
		"from a %d-byte crib — no seed, no lockSeed.Components, no interlock nonce, no start pixel entered "+
		"the derivation; %v", maxChunks, len(branches), cribLen, time.Since(s2start))
	if len(branches) == 0 {
		t.Logf("Stage 2 left no branch — attack stops here")
		return
	}

	// =================================================================
	// Stage 3 — read the container out.
	//
	// With the rank schedule known the per-chunk mask triple is known, so
	// the map from the three regions' lane bytes to the plaintext chunk
	// is a bijection. What remains unknown past the crib is the per-pixel
	// configuration, 8 x 7 x 32 possibilities per region per walk index.
	// The walk resolves one band across all three regions at once and
	// scores a candidate by whether the chunks it completes decode to
	// plaintext the attacker's model admits.
	//
	// The model is the only disambiguator here, so everything in this
	// stage is conditional on the plaintext distribution. Stages 1 and 2
	// are not — they run on the crib alone.
	// =================================================================
	t.Logf("=== Stage 3 — pixel walk under a plaintext model (corpus: %s) ===", corpus)
	s3all := time.Now()
	// The attacker's plaintext model, and the chunk-bit positions it
	// forces to zero — the latter is what the per-region prefilter
	// consumes. Every printable model clears bit 7 of each byte; a
	// narrower character class adds no further uniformly-forced bit, so
	// its extra power lands in the full per-chunk test instead.
	var model func(byte) bool
	zeroBits := uint64(0x8080_8080_8080)
	switch modelName {
	case "printable":
		// What a 48-byte crib of printable characters licenses: nothing
		// beyond the printable range.
		model = func(b byte) bool { return b >= 0x20 && b <= 0x7E }
	case "jsonclass":
		// What a crib recognisable as JSON licenses: the character
		// classes a JSON document is built from. Public knowledge of the
		// format, not knowledge of this document.
		var ok [256]bool
		for _, c := range []byte("0123456789abcdefghijklmnopqrstuvwxyz" +
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ{}[]\":,.-_+/ \t\n") {
			ok[c] = true
		}
		model = func(b byte) bool { return ok[b] }
	default: // "none"
		model = func(byte) bool { return true }
		zeroBits = 0
	}
	bandChunks := map[int][]int{}
	for k := 0; k < maxChunks; k++ {
		m := -1
		for r := 0; r < 3; r++ {
			for _, j := range [2]int{2 * k, 2*k + 1} {
				if bw := (a.base[r] + j) / 7; bw > m {
					m = bw
				}
			}
		}
		bandChunks[m] = append(bandChunks[m], k)
	}
	lastBand := (a.widths[0]*7 - 1) / 7
	commit := func(w int, cs [3]tcBandCfg) {
		for r := 0; r < 3; r++ {
			a.pix[r][w] = tcPixCfg{np: cs[r].np, rot: cs[r].rot, xor: cs[r].xor, ok: true, xorOK: true}
		}
	}

	recovered := make([]byte, ptSize)
	known := make([]bool, ptSize)
	bestResolved := -1
	dsReport := ""
	laneEndBand := 0
	for bi, br := range branches {
		for r := 0; r < 3; r++ {
			a.startPixel[r] = br.g.s1.sp[r]
			a.pix[r][1] = tcPixCfg{np: br.g.s1.np[r], rot: br.g.s1.rot[r], ok: true}
			a.pix[r][2] = tcPixCfg{np: br.g.s2.np[r], rot: br.g.s2.rot[r], ok: true}
			for w := 3; w < len(a.pix[r]); w++ {
				a.pix[r][w] = tcPixCfg{}
			}
		}
		// -------------------------------------------------------------
		// Walk band 3 first: it is the last band the crib reaches, and
		// it is where the channel-0 XOR masks become readable. With
		// bands 2 and 3 carrying a full (rotation, XOR) pair the region's
		// dataSeed is over-determined — four effective key bytes against
		// two eight-bit samples plus the high-bit constraints of the
		// following bands — so the walk past the crib needs to enumerate
		// only the three-bit noise position, not the whole per-pixel
		// configuration.
		// -------------------------------------------------------------
		resolved, stoppedAt, stopCount := 0, 0, 0
		brLaneEnd := 0
		pixBuf := func(w int) []byte { return tcPixelBuf(w, mainNonce) }
		bestInner := -1
		var bestPix [3][]tcPixCfg
		for _, c3 := range a.tcResolveBand(3, bandChunks[3], br.ranks, model, zeroBits, 16) {
			for r := 0; r < 3; r++ {
				for w := 3; w < len(a.pix[r]); w++ {
					a.pix[r][w] = tcPixCfg{}
				}
			}
			commit(3, c3)
			// Band 2's XOR comes straight off a crib chunk.
			cribAt2 := [3]int{3, 4, 4}
			okAll := true
			for r := 0; r < 3 && okAll; r++ {
				x2, ok2 := a.tcXorFromCribChunk(r, 2, cribAt2[r], br.ranks[cribAt2[r]])
				if !ok2 {
					okAll = false
					if dsReport == "" {
						dsReport = fmt.Sprintf("band-2 channel-0 XOR not readable in region %d", r)
					}
					break
				}
				a.pix[r][2].xor, a.pix[r][2].xorOK = x2, true
			}
			if !okAll {
				continue
			}
			// dataSeed recovery, region by region.
			var keys [3][][4]byte
			for r := 0; r < 3 && okAll; r++ {
				var aa, cc []byte
				var sets [][]byte
				for _, w := range [2]int{2, 3} {
					al, cl, _, _ := tcLaneConsts(pixBuf(w))
					cand := tcDataHashCandidates(a.pix[r][w].rot, a.pix[r][w].xor)
					if len(cand) == 0 {
						okAll = false
						break
					}
					aa, cc, sets = append(aa, al), append(cc, cl), append(sets, cand)
				}
				if !okAll {
					break
				}
				cands := tcSolveLane4(aa, cc, sets)
				raw := len(cands)
				if zeroBits == 0 {
					// Without a plaintext model there is nothing to narrow
					// the per-pixel seed with; record the residual and stop
					// rather than grinding a search that cannot converge.
					keys[r] = cands
					if dsReport == "" || strings.HasPrefix(dsReport, "region") {
						dsReport = fmt.Sprintf("region %d: %d keys from the two crib-readable pixels, "+
							"no model to narrow them", r, raw)
					}
					continue
				}
				// Narrow on the following bands: for a candidate key the
				// rotation and XOR of every later pixel are fixed, so only
				// the noise position is free, and the high-bit constraints
				// of the chunks that band completes must admit one.
				misses := 0
				for w := 4; w <= lastBand && len(cands) > 1 && w < 60; w++ {
					reqs := a.tcTopBitReqs(r, w, bandChunks[w], br.ranks, zeroBits)
					if len(reqs) == 0 {
						continue
					}
					al, cl, _, _ := tcLaneConsts(pixBuf(w))
					lin := (a.startPixel[r] + w) % a.widths[r]
					var keep [][4]byte
					for _, kk := range cands {
						dh := uint(tcCascade(kk[:], al, cl))
						any := false
						for np := uint(0); np < 8 && !any; np++ {
							win := tcReadPixel(a.regions[r], lin, np, dh%7, dh>>DataRotationBits)
							good := true
							for _, rq := range reqs {
								if win[rq[0]]&(1<<uint(rq[1])) != 0 {
									good = false
									break
								}
							}
							any = good
						}
						if any {
							keep = append(keep, kk)
						}
					}
					if len(keep) == 0 {
						// Every candidate fails here. Either the band has
						// walked past the COBS terminator into the
						// payload's DRBG tail, where the plaintext model
						// does not apply, or this branch's rank schedule is
						// wrong at this chunk. Two such bands in a row are
						// taken as the lane boundary; one is skipped.
						if misses++; misses >= 2 {
							if w > brLaneEnd {
								brLaneEnd = w
							}
							break
						}
						continue
					}
					misses = 0
					cands = keep
				}
				// Distinct keys that predict the same per-pixel schedule are
				// the same hypothesis for this attack; collapse them.
				uniq := map[string][4]byte{}
				for _, kk := range cands {
					sig := make([]byte, 0, 64)
					for w := 2; w < 66 && w <= lastBand; w++ {
						al, cl, _, _ := tcLaneConsts(pixBuf(w))
						sig = append(sig, tcCascade(kk[:], al, cl))
					}
					uniq[string(sig)] = kk
				}
				cands = cands[:0]
				for _, kk := range uniq {
					cands = append(cands, kk)
				}
				keys[r] = cands
				if dsReport == "" || strings.HasPrefix(dsReport, "region") {
					dsReport = fmt.Sprintf("region %d: %d keys from the two crib-readable pixels, "+
						"%d schedule classes after the model filter over bands 4..59", r, raw, len(cands))
				}
				if len(cands) == 0 {
					okAll = false
				}
			}
			if !okAll {
				continue
			}
			prod := len(keys[0]) * len(keys[1]) * len(keys[2])
			if dsReport == "" || strings.HasPrefix(dsReport, "region") {
				dsReport = fmt.Sprintf("%d / %d / %d", len(keys[0]), len(keys[1]), len(keys[2]))
			}
			_ = prod

			// Walk the rest of the container band by band. With the noise
			// position shared across the three regions the per-band space
			// is 8 x 7^3 x 32^3, and the chunks each band completes supply
			// more constraint than that when the model holds.
			if prod == 0 || prod > 4096 {
				continue
			}
			for ki := 0; ki < prod; ki++ {
				sel := [3][4]byte{
					keys[0][ki%len(keys[0])],
					keys[1][(ki/len(keys[0]))%len(keys[1])],
					keys[2][ki/(len(keys[0])*len(keys[1]))],
				}
				for r := 0; r < 3; r++ {
					for w := 4; w < len(a.pix[r]); w++ {
						a.pix[r][w] = tcPixCfg{}
					}
				}
				inner := 0
				for w := 4; w <= lastBand; w++ {
					ks := bandChunks[w]
					if len(ks) == 0 {
						continue
					}
					var rot, xor [3]uint
					for r := 0; r < 3; r++ {
						al, cl, _, _ := tcLaneConsts(pixBuf(w))
						dh := uint(tcCascade(sel[r][:], al, cl))
						rot[r], xor[r] = dh%7, dh>>DataRotationBits
					}
					hit := 0
					var got [3]tcBandCfg
					for np := uint(0); np < 8; np++ {
						try := [3]tcBandCfg{
							{np, rot[0], xor[0]},
							{np, rot[1], xor[1]},
							{np, rot[2], xor[2]},
						}
						commit(w, try)
						if a.tcBandDecodes(w, ks, br.ranks, model) {
							hit++
							got = try
						}
					}
					if hit != 1 {
						if stoppedAt == 0 || w > stoppedAt {
							stoppedAt, stopCount = w, hit
						}
						break
					}
					commit(w, got)
					inner++
				}
				if inner > bestInner {
					bestInner = inner
					laneEndBand = brLaneEnd
					for r := 0; r < 3; r++ {
						bestPix[r] = append([]tcPixCfg(nil), a.pix[r]...)
					}
				}
			}
		}
		if bestInner >= 0 {
			resolved = bestInner + 1
			for r := 0; r < 3; r++ {
				copy(a.pix[r], bestPix[r])
			}
		}
		if stoppedAt == 0 {
			stoppedAt = lastBand + 1
		}
		converged := bestInner >= 0
		rec := make([]byte, ptSize)
		kn := make([]bool, ptSize)
		for k := 0; k < maxChunks; k++ {
			x, ok := a.readChunk(k, br.ranks)
			if !ok {
				continue
			}
			for i := 0; i < 6; i++ {
				if pos := 6*k + i - 4; pos >= 0 && pos < ptSize {
					rec[pos] = byte(x >> uint(8*i))
					kn[pos] = true
				}
			}
		}
		nk := 0
		for _, v := range kn {
			if v {
				nk++
			}
		}
		if bi < 6 {
			t.Logf("Stage 3 branch %d/%d: bands walked %d of %d (dataSeed recovered: %v); halted at band %d "+
				"with %d admissible configurations; plaintext positions produced %d",
				bi+1, len(branches), resolved, lastBand-2, converged, stoppedAt, stopCount, nk)
		}
		if resolved > bestResolved {
			bestResolved = resolved
			recovered, known = rec, kn
		}
	}
	if laneEndBand > 0 {
		t.Logf("Stage 3: on the branch that walked furthest the plaintext model stops holding at walk band %d, "+
			"which is where the COBS terminator puts the end of the Rank Barrier lane; the lane length is "+
			"readable off that boundary", laneEndBand)
	} else {
		t.Logf("Stage 3: no branch walked far enough to place the end of the Rank Barrier lane")
	}
	t.Logf("Stage 3: dataSeed schedule classes surviving the crib plus the model over the bands inside the lane, "+
		"per region: %s", dsReport)
	t.Logf("Stage 3: %d branches tried; the best walked %d of %d bands past the crib; %v",
		len(branches), bestResolved, lastBand-2, time.Since(s3all))

	// ---------- Lab-only validation (post-hoc, decorative) ----------
	// Everything above produced its answer from the wire, the 48-byte
	// crib and the public configuration. These lines say whether it
	// landed; nothing they read fed a decision.
	match, kn := 0, 0
	for i := 0; i < ptSize; i++ {
		if known[i] {
			kn++
			if recovered[i] == fullPlain[i] {
				match++
			}
		}
	}
	beyond, beyondMatch := 0, 0
	for i := cribLen; i < ptSize; i++ {
		if known[i] {
			beyond++
			if recovered[i] == fullPlain[i] {
				beyondMatch++
			}
		}
	}
	t.Logf("--- labonly validation ---")
	t.Logf("corpus=%s model=%s plaintext=%d bytes; positions the attack produced a value for: %d; byte-exact: %d "+
		"(%.2f%% of the message, crib included — the line below is the recovery figure)",
		corpus, modelName, ptSize, kn, match, 100*float64(match)/float64(ptSize))
	t.Logf("RECOVERY beyond the %d-byte crib: produced %d, byte-exact %d (%.2f%% of the %d bytes the attacker did not hold)",
		cribLen, beyond, beyondMatch, 100*float64(beyondMatch)/float64(ptSize-cribLen), ptSize-cribLen)
	var meta struct {
		StartPixels struct{ S1, S2, S3 int } `json:"start_pixels"`
		Debug       struct{ Lock []uint64 }  `json:"debug_seeds"`
		Interlock   string                   `json:"interlock_nonce_hex"`
	}
	mraw, _ := os.ReadFile(filepath.Join(dir, "cell.meta.json"))
	_ = json.Unmarshal(mraw, &meta)
	spMatch := a.startPixel[0] == meta.StartPixels.S1 &&
		a.startPixel[1] == meta.StartPixels.S2 &&
		a.startPixel[2] == meta.StartPixels.S3
	t.Logf("start pixels: recovered=%v truth=[%d %d %d] match=%v",
		a.startPixel, meta.StartPixels.S1, meta.StartPixels.S2, meta.StartPixels.S3, spMatch)
	// Terminal-stage gate on the harness, not on the attack. Stages 1
	// and 2 are corpus- and model-independent: where they run to
	// completion at all they pin the start pixels exactly. How far the
	// Stage 3 walk then gets is a measurement and is never asserted,
	// and the Stage 1 / Stage 2 give-up paths return before reaching
	// here, so a run that legitimately stops early does not trip this.
	// A wrong start-pixel triple past those gates means the recovery
	// machinery drifted from the decoder rather than that the attack
	// narrowed differently.
	if !spMatch {
		t.Errorf("start pixels recovered=%v but truth=[%d %d %d] — Stage 1 completed on a wrong geometry, "+
			"which is harness drift rather than an attack outcome",
			a.startPixel, meta.StartPixels.S1, meta.StartPixels.S2, meta.StartPixels.S3)
	}
	if len(meta.Debug.Lock) >= 8 {
		ilTruth, _ := hex.DecodeString(meta.Interlock)
		lockSeed, _ := SeedFromComponents128(thLeak_trainHash, meta.Debug.Lock...)
		lo, hi := lockSeed.deriveInterLockSeed(ilTruth)
		trueRank := func(k int) int {
			bp := buildLockBatchPRF48_128Cfg(cfg, lockSeed, ilTruth)
			prf := make([]uint64, 2)
			bp.fillRanks(make([]byte, 13), uint64(k), prf)
			return int(prf[0]) | int(prf[1])<<8
		}
		M := tripleLaneLen(ptSize) / 2
		full, prefix := 0, 0
		for _, br := range branches {
			okFull, okPre := true, true
			for k := 0; k < M; k++ {
				if br.ranks[k] != trueRank(k) {
					okFull = false
					if k <= 12 {
						okPre = false
					}
				}
			}
			if okFull {
				full++
			}
			if okPre {
				prefix++
			}
		}
		t.Logf("derived interlock key (labonly): lo=0x%02x hi=0x%02x; branches matching the encoder's rank schedule "+
			"over all %d chunks of the message: %d of %d (over the first 13 chunks: %d)",
			lo&0xFF, hi&0xFF, M, full, len(branches), prefix)
		// Same gate, on the other corpus-independent invariant. The
		// branch count varies widely run to run and is never asserted;
		// what must hold is that the encoder's real schedule is among
		// the branches at all. Its absence means the mirror of the
		// cascade drifted, not that the crib constrained less.
		if full == 0 {
			t.Errorf("the encoder's rank schedule is absent from all %d surviving branches — "+
				"the cascade mirror has drifted from the shipped builder", len(branches))
		}
	}
}

// tcWindows returns the 56 candidate seven-byte readings of one
// region's pixel at walk index w, indexed by np*7+rot.
func (a *tcAttack) tcWindows(r, w int) [][7]byte {
	out := make([][7]byte, 56)
	lin := (a.startPixel[r] + w) % a.widths[r]
	for np := uint(0); np < 8; np++ {
		for rot := uint(0); rot < 7; rot++ {
			out[np*7+rot] = tcReadPixel(a.regions[r], lin, np, rot, 0)
		}
	}
	return out
}

// tcChunkBandFit tests a candidate rank for a crib-known chunk against
// the container, splitting the chunk's six lane bytes into those the
// already-resolved pixels fix and those that fall in band w.
//
// The crib word is known, so the expected lane triple follows from the
// rank by a forward chunk48lock — there is nothing to search on the rank
// side. What the routine returns is the set of band-w pixel
// configurations per region that reproduce the expected bytes. A wrong
// rank leaves some region with no configuration at all, which is what
// makes this a filter on the cascade key as well as a resolver for the
// band.
func (a *tcAttack) tcChunkBandFit(k, w, rank int, wins *[3][][7]byte) (ok bool, fits [3][]int) {
	x, known := a.chunkXPartial(k)
	if known == 0 {
		return false, fits
	}
	m := a.masks[rank]
	v0, v1, v2 := chunk48lock(x, m[0], m[1], m[2])
	k0, k1, k2 := chunk48lock(known, m[0], m[1], m[2])
	want := [3]uint16{v0, v1, v2}
	valid := [3]uint16{k0, k1, k2}
	for r := 0; r < 3; r++ {
		type req struct {
			off     int
			v, bits byte
		}
		var band []req
		for bi, j := range [2]int{2 * k, 2*k + 1} {
			s := a.base[r] + j
			bw, off := s/7, s%7
			ev := byte(want[r] >> uint(8*bi))
			bits := byte(valid[r] >> uint(8*bi))
			if off == 0 {
				bits &= 0xE0
			}
			if bits == 0 {
				continue
			}
			switch {
			case bw < w:
				got, gb, gok := a.readLaneByte(r, j)
				if !gok || (got^ev)&gb&bits != 0 {
					return false, fits
				}
			case bw == w:
				band = append(band, req{off, ev, bits})
			default:
				return false, fits // chunk reaches past the band
			}
		}
		if len(band) == 0 {
			fits[r] = nil
			continue
		}
		for c := 0; c < 56; c++ {
			good := true
			for _, rq := range band {
				if (wins[r][c][rq.off]^rq.v)&rq.bits != 0 {
					good = false
					break
				}
			}
			if good {
				fits[r] = append(fits[r], c)
			}
		}
		if len(fits[r]) == 0 {
			return false, fits
		}
	}
	return true, fits
}

// tcSolveLane4 is the four-round counterpart of [tcSolveLane], for the
// per-pixel seeds: a Seed128 built on eight components runs four cascade
// rounds, so its effective key under an 8-bit-per-lane primitive is four
// bytes. Meet in the middle at s2 — forward (k0,k1), backward (k2,k3),
// both 2^16. Sample outputs are sets because a rotation plus a
// channel-0 XOR mask can leave two dataHash values open.
func tcSolveLane4(a, c []byte, sets [][]byte) [][4]byte {
	n := len(sets)
	if n < 2 {
		return nil
	}
	ainv := make([]byte, n)
	for i := range a {
		ainv[i] = tcInv256(a[i])
	}
	type sig [4]byte
	fwd := make(map[sig][][2]byte, 1<<16)
	for k0 := 0; k0 < 256; k0++ {
		for k1 := 0; k1 < 256; k1++ {
			var g sig
			for i := 0; i < n; i++ {
				s1 := a[i]*byte(k0) + c[i]
				g[i] = a[i]*(byte(k1)^s1) + c[i]
			}
			fwd[g] = append(fwd[g], [2]byte{byte(k0), byte(k1)})
		}
	}
	seen := map[[4]byte]struct{}{}
	var out [][4]byte
	idx := make([]int, n)
	for k2 := 0; k2 < 256; k2++ {
		for k3 := 0; k3 < 256; k3++ {
			for i := range idx {
				idx[i] = 0
			}
			for {
				var g sig
				for i := 0; i < n; i++ {
					s3 := ainv[i]*(sets[i][idx[i]]-c[i]) ^ byte(k3)
					g[i] = ainv[i]*(s3-c[i]) ^ byte(k2)
				}
				for _, fk := range fwd[g] {
					key := [4]byte{fk[0], fk[1], byte(k2), byte(k3)}
					if _, dup := seen[key]; !dup {
						seen[key] = struct{}{}
						out = append(out, key)
					}
				}
				i := 0
				for ; i < n; i++ {
					if idx[i]++; idx[i] < len(sets[i]) {
						break
					}
					idx[i] = 0
				}
				if i == n {
					break
				}
			}
		}
	}
	return out
}

// tcDataHashCandidates returns the dataHash values consistent with an
// observed (rotation, channel-0 XOR) pair. The pipeline derives both
// from one value — rotation is dataHash % 7 and the mask is
// dataHash >> DataRotationBits — so an observed pair usually pins it.
func tcDataHashCandidates(rot, xor uint) []byte {
	var out []byte
	for t := uint(0); t < 8; t++ {
		v := 8*xor + t
		if v < 256 && v%7 == rot {
			out = append(out, byte(v))
		}
	}
	return out
}

// tcXorFromCribChunk recovers the channel-0 XOR mask of a region's pixel
// at walk band w from a crib-known chunk whose lane byte occupies that
// pixel's byte-0 slot. The rank is known, so the expected byte follows
// from a forward chunk48lock on the crib word; the observed byte differs
// from it in exactly the five bits the mask covers.
func (a *tcAttack) tcXorFromCribChunk(r, w, k, rank int) (uint, bool) {
	x, known := a.chunkXPartial(k)
	if known == 0 {
		return 0, false
	}
	m := a.masks[rank]
	v0, v1, v2 := chunk48lock(x, m[0], m[1], m[2])
	kb0, kb1, kb2 := chunk48lock(known, m[0], m[1], m[2])
	want := [3]uint16{v0, v1, v2}[r]
	valid := [3]uint16{kb0, kb1, kb2}[r]
	for bi, j := range [2]int{2 * k, 2*k + 1} {
		st := a.base[r] + j
		if st/7 != w || st%7 != 0 {
			continue
		}
		if byte(valid>>uint(8*bi)) != 0xFF {
			return 0, false
		}
		c := a.pix[r][w]
		lin := (a.startPixel[r] + w) % a.widths[r]
		got := tcReadPixel(a.regions[r], lin, c.np, c.rot, 0)[0]
		ev := byte(want >> uint(8*bi))
		if (got^ev)&0xE0 != 0 {
			return 0, false // the exact bits already disagree
		}
		return uint((got ^ ev) & 0x1F), true
	}
	return 0, false
}

// tcTopBitReqs lists, for one region and one walk band, the positions
// inside that band's seven-byte window whose bit must be zero for the
// chunk it feeds to decode to a printable character. A lane bit is a
// copy of one chunk bit, so the region owns whichever high bits its mask
// selected, and the constraint is testable without the other regions.
func (a *tcAttack) tcTopBitReqs(r, w int, ks []int, ranks []int, zeroBits uint64) [][2]int {
	var out [][2]int
	for _, k := range ks {
		m := a.masks[ranks[k]]
		var pos [16]int
		t := 0
		for b := 0; b < 48 && t < 16; b++ {
			if m[r]&(uint64(1)<<uint(b)) != 0 {
				pos[t] = b
				t++
			}
		}
		for bi, j := range [2]int{2 * k, 2*k + 1} {
			st := a.base[r] + j
			if st/7 != w {
				continue
			}
			off := st % 7
			for bit := 0; bit < 8; bit++ {
				lb := 8*bi + bit
				if zeroBits&(uint64(1)<<uint(pos[lb])) != 0 {
					out = append(out, [2]int{off, bit})
				}
			}
		}
	}
	return out
}

// tcBandCfg is one region's resolved pixel configuration at a band.
type tcBandCfg struct{ np, rot, xor uint }

// tcResolveBand enumerates the pixel configurations of walk band w over
// all three regions at once and keeps those under which every chunk
// completing at that band decodes consistently.
//
// The search runs in two passes because the per-pixel configuration
// splits that way: (noisePos, rotation) fixes six of a pixel's seven
// stream bytes, and the channel-0 XOR fixes the low five bits of the
// seventh. Pass one enumerates 8 x 7 per region against the chunks whose
// lane bytes avoid every byte-0 slot; pass two enumerates the three
// five-bit XOR masks against the rest. A chunk the crib pins is tested
// by exact equality on the bytes the crib determines; a chunk past the
// crib is tested against the plaintext model.
//
// Pass one is cut down by a per-region prefilter before the joint loop.
// A Rank Barrier lane bit is a copy of one chunk bit selected by that
// region's mask, so every constraint on a chunk bit the region owns —
// a crib byte, or the high bit each printable character must clear — is
// testable against that region's 56 configurations alone. Intersecting
// the three surviving lists first turns a 56^3 sweep into a handful.
func (a *tcAttack) tcResolveBand(w int, ks []int, ranks []int, model func(byte) bool, zeroBits uint64, limit int) [][3]tcBandCfg {
	var wins [3][][7]byte
	for r := 0; r < 3; r++ {
		wins[r] = a.tcWindows(r, w)
	}
	type src struct {
		band bool
		off  int
		v    byte
	}
	type plan struct {
		k       int
		s       [3][2]src
		m       [3]uint64
		pos     [3][16]int // lane bit -> chunk bit position
		x, know uint64
		dirty   bool
	}
	var clean, dirty []plan
	for _, k := range ks {
		var p plan
		p.k = k
		mm := a.masks[ranks[k]]
		p.m = [3]uint64{mm[0], mm[1], mm[2]}
		p.x, p.know = a.chunkXPartial(k)
		for r := 0; r < 3; r++ {
			t := 0
			for b := 0; b < 48; b++ {
				if p.m[r]&(uint64(1)<<uint(b)) != 0 {
					p.pos[r][t] = b
					t++
				}
			}
		}
		ok := true
		for r := 0; r < 3 && ok; r++ {
			for bi, j := range [2]int{2 * k, 2*k + 1} {
				st := a.base[r] + j
				bw, off := st/7, st%7
				if bw == w {
					p.s[r][bi] = src{band: true, off: off}
					if off == 0 {
						p.dirty = true
					}
					continue
				}
				if bw > w {
					ok = false
					break
				}
				v, bits, okb := a.readLaneByte(r, j)
				if !okb || bits != 0xFF {
					ok = false
					break
				}
				p.s[r][bi] = src{v: v}
			}
		}
		if !ok {
			continue
		}
		if p.dirty {
			dirty = append(dirty, p)
		} else {
			clean = append(clean, p)
		}
	}
	if len(clean)+len(dirty) == 0 {
		return nil
	}

	// Per-region prefilter over the clean chunks.
	laneOf := func(p *plan, r, c int, xr uint, useXor bool) (uint16, bool) {
		var lv uint16
		for bi := 0; bi < 2; bi++ {
			sc := p.s[r][bi]
			v := sc.v
			if sc.band {
				v = wins[r][c][sc.off]
				if sc.off == 0 {
					if !useXor {
						return 0, false
					}
					v ^= byte(xr)
				}
			}
			lv |= uint16(v) << uint(8*bi)
		}
		return lv, true
	}
	var allow [3][]int
	constrains := false
	for r := 0; r < 3; r++ {
		for c := 0; c < 56; c++ {
			good := true
			for i := range clean {
				p := &clean[i]
				lv, okl := laneOf(p, r, c, 0, false)
				if !okl {
					continue
				}
				for t := 0; t < 16 && good; t++ {
					bit := uint64((lv >> uint(t)) & 1)
					pos := uint(p.pos[r][t])
					if p.know&(uint64(1)<<pos) != 0 {
						constrains = true
						if (p.x>>pos)&1 != bit {
							good = false
						}
					} else if zeroBits&(uint64(1)<<pos) != 0 {
						constrains = true
						if bit != 0 {
							good = false
						}
					}
				}
				if !good {
					break
				}
			}
			if good {
				allow[r] = append(allow[r], c)
			}
		}
		if len(allow[r]) == 0 {
			return nil
		}
	}
	if !constrains {
		// Nothing in this band discriminates: the plaintext model admits
		// every byte and no crib bit reaches it. Report saturation rather
		// than a false resolution.
		out := make([][3]tcBandCfg, limit)
		return out
	}

	test := func(p *plan, cs [3]int, xr [3]uint, useXor bool) bool {
		var lv [3]uint16
		for r := 0; r < 3; r++ {
			v, okl := laneOf(p, r, cs[r], xr[r], useXor)
			if !okl {
				return true // undecidable without the XOR
			}
			lv[r] = v
		}
		x := unchunk48lock(lv[0], lv[1], lv[2], p.m[0], p.m[1], p.m[2])
		if (x^p.x)&p.know != 0 {
			return false
		}
		for i := 0; i < 6; i++ {
			if p.know&(uint64(0xFF)<<uint(8*i)) != 0 {
				continue
			}
			if !model(byte(x >> uint(8*i))) {
				return false
			}
		}
		return true
	}

	var out [][3]tcBandCfg
	var zero [3]uint
	for _, c0 := range allow[0] {
		for _, c1 := range allow[1] {
			if c1/7 != c0/7 {
				continue // shared noise position across regions
			}
			for _, c2 := range allow[2] {
				if c2/7 != c0/7 {
					continue
				}
				cs := [3]int{c0, c1, c2}
				okA := true
				for i := range clean {
					if !test(&clean[i], cs, zero, false) {
						okA = false
						break
					}
				}
				if !okA {
					continue
				}
				emit := func(xr [3]uint) bool {
					out = append(out, [3]tcBandCfg{
						{uint(c0 / 7), uint(c0 % 7), xr[0]},
						{uint(c1 / 7), uint(c1 % 7), xr[1]},
						{uint(c2 / 7), uint(c2 % 7), xr[2]},
					})
					return len(out) >= limit
				}
				if len(dirty) == 0 {
					if emit(zero) {
						return out
					}
					continue
				}
				for x0 := uint(0); x0 < 32; x0++ {
					for x1 := uint(0); x1 < 32; x1++ {
						for x2 := uint(0); x2 < 32; x2++ {
							xr := [3]uint{x0, x1, x2}
							okB := true
							for i := range dirty {
								if !test(&dirty[i], cs, xr, true) {
									okB = false
									break
								}
							}
							if okB && emit(xr) {
								return out
							}
						}
					}
				}
			}
		}
	}
	return out
}

// readChunk returns the plaintext word of chunk k when every lane byte
// it needs is exactly readable under the resolved pixels.
func (a *tcAttack) readChunk(k int, ranks []int) (uint64, bool) {
	var lv [3]uint16
	for r := 0; r < 3; r++ {
		for bi, j := range [2]int{2 * k, 2*k + 1} {
			v, bits, ok := a.readLaneByte(r, j)
			if !ok || bits != 0xFF {
				return 0, false
			}
			lv[r] |= uint16(v) << uint(8*bi)
		}
	}
	m := a.masks[ranks[k]]
	return unchunk48lock(lv[0], lv[1], lv[2], m[0], m[1], m[2]), true
}

// TestRedTeamTrainHashCribKPAAscii runs the Crib KPA against uniform
// printable ASCII over a 69-character alphabet.
func TestRedTeamTrainHashCribKPAAscii(t *testing.T) { tcRunCribKPA(t, "ascii", 512, "printable") }

// tcBandDecodes reports whether every chunk completing at walk band w
// decodes, under the current pixel resolution, to a plaintext word the
// crib and the model both admit.
func (a *tcAttack) tcBandDecodes(w int, ks []int, ranks []int, model func(byte) bool) bool {
	for _, k := range ks {
		var lv [3]uint16
		ok := true
		for r := 0; r < 3 && ok; r++ {
			for bi, j := range [2]int{2 * k, 2*k + 1} {
				v, bits, okb := a.readLaneByte(r, j)
				if !okb || bits != 0xFF {
					ok = false
					break
				}
				lv[r] |= uint16(v) << uint(8*bi)
			}
		}
		if !ok {
			continue
		}
		m := a.masks[ranks[k]]
		x := unchunk48lock(lv[0], lv[1], lv[2], m[0], m[1], m[2])
		cx, know := a.chunkXPartial(k)
		if (x^cx)&know != 0 {
			return false
		}
		for i := 0; i < 6; i++ {
			if know&(uint64(0xFF)<<uint(8*i)) != 0 {
				continue
			}
			if !model(byte(x >> uint(8*i))) {
				return false
			}
		}
	}
	return true
}

// TestRedTeamTrainHashCribKPABinary runs the same Crib KPA against a
// uniform-random plaintext. Stages 1 and 2 are identical — they consume
// the crib and the wire only — so the difference isolates exactly how
// much of the result rests on the plaintext distribution rather than on
// the construction.
func TestRedTeamTrainHashCribKPABinary(t *testing.T) { tcRunCribKPA(t, "binary", 512, "none") }

// The structured-text corpus, at two sizes and under two models. Holding
// the model at "printable" isolates what corpus structure alone buys,
// since that is the model the printable-ASCII run used; "jsonclass"
// then varies the model's discriminating power with the corpus fixed.
func TestRedTeamTrainHashCribKPAJson512Plain(t *testing.T) { tcRunCribKPA(t, "json", 512, "printable") }
func TestRedTeamTrainHashCribKPAJson512Class(t *testing.T) { tcRunCribKPA(t, "json", 512, "jsonclass") }
func TestRedTeamTrainHashCribKPAJson4kPlain(t *testing.T)  { tcRunCribKPA(t, "json", 4096, "printable") }
func TestRedTeamTrainHashCribKPAJson4kClass(t *testing.T)  { tcRunCribKPA(t, "json", 4096, "jsonclass") }
