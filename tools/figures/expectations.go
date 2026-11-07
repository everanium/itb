package main

import (
	"fmt"
	"math"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// Pattern fragments shared across locators. Captures are generic: a
// stale figure still locates and reports as STALE.
const (
	num   = `([\d,]+)`      // integer, with or without thousands separators
	dec   = `([\d.]+)`      // decimal
	p2    = `(2\^[\d,]+)`   // 2^<integer exponent>
	p2d   = `(2\^\d+\.\d+)` // 2^<decimal exponent>
	x     = ` × `
	dimsP = num + x + num + ` \(P = ` + num + `\)` // "21 × 21 (P = 441)"
)

// Registry builds every expectation from the computed figures.
// Each entry names the file, a locator anchored on the surrounding
// text, and the spelling the site uses for each captured figure.
func Registry(f *Figures) []Expectation {
	m1 := map[int]FloorFigures{}
	m2 := map[int]FloorFigures{}
	m3 := map[int]FloorFigures{}
	for _, k := range keySizes {
		m1[k] = f.Floor[k][1]
		m2[k] = f.Floor[k][2]
		m3[k] = f.Floor[k][3]
	}
	// The 1024-bit key is the documentation's worked example.
	a, b, c, t := m1[1024], m2[1024], m3[1024], f.Theoretical[1024]
	m1Wire128 := f.Prefix + f.HeaderSizes[128] + a.P*itb.Channels
	m3Wire128 := f.Prefix + f.HeaderSizes[128] + c.P*itb.Channels
	m3SaveBytes := a.Wire - c.Wire
	m3SavePct128 := fixed(100*float64(m1Wire128-m3Wire128)/float64(m1Wire128), 1)
	mp := f.MinPixels[1024]
	size := map[string]SizeRow{}
	for _, r := range f.Sizes {
		size[r.Label] = r
	}
	s64k, s1m, s16k, s64m, s4m, s16m := size["64 KiB"], size["1 MiB"], size["16 KiB"], size["64 MiB"], size["4 MiB"], size["16 MiB"]

	// Exponents the docs tabulate for the three 1024-bit floors.
	cca := func(P int) int { return log2Pow(7, P) }
	nocca := func(P int) int { return log2Pow(56, P) }
	landauer := func(exp int) string { return ratioBare(float64(exp) / float64(landauerExp)) }
	bf := func(P, m int) (string, string) {
		c, g := bruteForce(P, 1024, m)
		return "2^" + fixed(math.Round(c), 0), "2^" + fixed(math.Round(g), 0)
	}
	aC1, aG1 := bf(a.P, 2)
	bC1, bG1 := bf(b.P, 2)
	aC2, aG2 := bf(a.P, 1)
	bC2, bG2 := bf(b.P, 1)
	_, tG1 := bf(t.P, 2)
	_, tG2 := bf(t.P, 1)
	if tG1 != bG1 || tG2 != bG2 {
		// SCIENCE.md § 3.3 states one Grover figure for the Mode 2 and the
		// theoretical floor together; a divergence surfaces as STALE.
		tG1, tG2 = "divergent", "divergent"
	}

	log2AB := fixed(f.Log2AB, 2)
	log2Pre := fixed(f.Log2Preimage, 2)
	bias := fixed(-f.Log2Preimage, 1)
	accum := fixed(f.AccumBias, 1)
	budget := fixed(f.SampleBudget, 1)
	chunks := fixed(f.Log2Chunks, 2)
	gcd := int(f.GCD.Int64())
	invGCD := 1 / float64(gcd)
	log2A168 := fixed(f.Log2A168, 2)
	log2B168 := fixed(f.Log2B168, 2)
	log2AB168 := fixed(f.Log2AB168, 2)
	log2Pre168 := fixed(f.Log2Preimage168, 2)
	bias168 := fixed(-f.Log2Preimage168, 1)
	accum168 := fixed(f.AccumBias168, 1)
	budget168 := fixed(f.SampleBudget168, 1)
	chunks168 := fixed(f.Log2Chunks168, 2)
	msgs168 := "2^" + fixed(math.Round(f.Log2Messages168), 0)
	crib48 := "2^" + fixed(f.Log2AB-48, 1)
	crib48Floor := "2^" + fixed(math.Floor(f.Log2AB-48), 0)
	crib168 := "2^" + fixed(f.Log2AB168-168, 1)
	crib168Floor := "2^" + fixed(math.Floor(f.Log2AB168-168), 0)
	gcd168Comma := commaBig(f.GCD168)
	gcd168Plain := f.GCD168.String()
	log2GCD168 := fixed(f.Log2GCD168, 2)
	invGCD168 := 1 / float64(f.GCD168.Uint64())
	chainRounds := func(k int) int { return k / narrowestWidth }

	residueLine := func() string {
		return "\\(`s = " + num + "`, container `" + num + x + num + " = " + num + "`\\): `gap ≥ \\(2" + x + num + " \\+ 1\\)" + x + "7 = " + num + " bytes`"
	}

	theoPayloadKB := kb(b.MaxPayload)
	if b.RawSquare*b.RawSquare != t.P {
		theoPayloadKB = "divergent"
	}
	// The README storage-overhead row reads the 0.5-2.5 KB expansion off
	// the floor wire, valid while 2.5 KB fits both 1024-bit floors.
	floorFits2500 := a.MaxPayload >= 2500 && b.MaxPayload >= 2500
	expansionMin := fixed(f.ExpansionMin, 2)
	if expansionMin != fixed(f.ExpansionMinEnd, 2) {
		// The interval minimum lies between the two; they no longer
		// agree to the published precision.
		expansionMin = "divergent"
	}
	tenExp := int(math.Floor(math.Log10(landauerOps)))

	var exps []Expectation
	add := func(e ...Expectation) { exps = append(exps, e...) }

	// ----- SCIENCE.md -------------------------------------------------
	add(
		expect("SCIENCE.md", `At 64 KB plaintext, ambiguity reaches `+p2+`; its exponent is `+dec+`× the 1024-bit key-space exponent`,
			w("cca_64KiB", pow2(cca(s64k.P))), w("cca_64KiB_vs_key", fixed(float64(cca(s64k.P))/1024, 1))),
		expect("SCIENCE.md", `^\|Ω_chunk\| = A · B = `+num+`\s+≈\s+`+p2d+`$`,
			w("AB", commaBig(f.AB)), w("log2_AB", "2^"+log2AB)),
		expect("SCIENCE.md", `where .A = C\(48, 16\) = `+num+`. \(.log₂ ≈ `+dec+`., choices for .m_0.\) and .B = C\(32, 16\) = `+num+`. \(.log₂ ≈ `+dec+`., choices for .m_1.`,
			w("A", commaBig(f.A)), w("log2_A", fixed(f.Log2A, 2)), w("B", commaBig(f.B)), w("log2_B", fixed(f.Log2B, 2))),
		expect("SCIENCE.md", `^A₁₆₈ = C\(168, 56\) = `+num+`\s+\(log₂ ≈ `+dec+`\)$`,
			w("A168", commaBig(f.A168)), w("log2_A168", log2A168)),
		expect("SCIENCE.md", `^B₁₆₈ = C\(112, 56\) = `+num+`\s+\(log₂ ≈ `+dec+`\)$`,
			w("B168", commaBig(f.B168)), w("log2_B168", log2B168)),
		expect("SCIENCE.md", `^\|Ω_chunk,168\| = A₁₆₈ · B₁₆₈ = `+num+`\s+≈\s+`+p2d+`$`,
			w("AB168", commaBig(f.AB168)), w("log2_AB168", "2^"+log2AB168)),
		expect("SCIENCE.md", `defeats the .gcd\(A, B\) = `+num+`. collapse trap that would reduce the reachable space to .1 / `+num+` ≈ ([\d.]+ × 10⁻.).`,
			w("gcd", comma(gcd)), w("gcd", comma(gcd)), w("inv_gcd", sci(invGCD, 1))),
		expect("SCIENCE.md", `defeats the .gcd\(A₁₆₈, B₁₆₈\) = `+num+`. \(.log₂ ≈ `+dec+`.\) collapse trap that would otherwise restrict reachable pairs to .1 / `+num+` ≈ ([\d.]+ × 10⁻..). of the .A₁₆₈ × B₁₆₈. space`,
			w("gcd168", gcd168Comma), w("log2_gcd168", log2GCD168), w("gcd168", gcd168Comma), w("inv_gcd168", sci(invGCD168, 1))),
		expect("SCIENCE.md", `cyclic rotation by a per-pixel amount in .\[0, 6\]. derived from .dataSeed_i. \(.rotation_i = dataHash_i mod 7., providing log₂\(7\) ≈ `+dec+` bits of entropy\)`,
			w("log2_7", fixed(math.Log2(7), 3))),
	)
	add(wireOffsets("SCIENCE.md", f, `Prefix`)...)
	add(
		expect("SCIENCE.md", "For `P = "+num+"` \\(\\*\\*Mode 2\\*\\* per-container floor at a 1024-bit key — joint floor `MinPixels = "+num+"`, square-rounded to `"+num+x+num+" = "+num+"` with `DefaultBarrierFill = "+num+"`\\): `7\\^"+num+" ≈ "+p2+"`. For `P = "+num+"` \\(\\*\\*Mode 1\\*\\* per-region floor — `3"+x+num+" = "+num+"` total pixels, square-rounded to `"+num+x+num+" = "+num+"`\\): `7\\^"+num+" ≈ "+p2+"` observation-consistent candidate configurations \\(with `7\\^"+num+" ≈ "+p2+"`",
			w("m2_P", plain(b.P)), w("minpixels_1024", plain(mp)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)), w("barrier_fill", plain(f.BarrierFill)),
			w("m2_P", plain(b.P)), w("cca_m2", pow2(cca(b.P))),
			w("m1_P", plain(a.P)), w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)),
			w("m1_P", plain(a.P)), w("cca_m1", pow2(cca(a.P))),
			w("theo_P", plain(t.P)), w("cca_theo", pow2(cca(t.P)))),
		expect("SCIENCE.md", "≈ 2\\^\\((\\d+\\.\\d+) × C\\)` observation-consistent mask configurations",
			w("log2_AB", log2AB)),
		expect("SCIENCE.md", "For `keyBits = 1024`: joint floor `MinPixels = "+num+"`. In \\*\\*Mode 2\\*\\* \\(per-container\\), the joint floor produces a `"+num+x+num+"` container \\(`P = "+num+"`\\), where the noise barrier is `"+p2+" ≫ "+p2+"` \\(a margin of `"+p2+"`\\). In \\*\\*Mode 1\\*\\* \\(per-region\\), each region independently enforces `MinPixels = "+num+"`, requiring at least `3"+x+num+" = "+num+"` data pixels; square container rounding \\(`⌈√"+num+"⌉ = "+num+"`\\) plus `DefaultBarrierFill = "+num+"` yields `"+num+x+num+" = "+num+"` pixels, expanding the noise barrier to `"+p2+"` \\(a margin of `"+p2+"` over the key space\\)",
			w("minpixels_1024", plain(mp)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)),
			w("noise_m2", pow2(noiseBarrier(b.P))), w("key_space", pow2(1024)), w("noise_margin_m2", pow2(noiseBarrier(b.P)-1024)),
			w("minpixels_1024", plain(mp)), w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_raw_square", plain(a.RawSquare)), w("barrier_fill", plain(f.BarrierFill)),
			w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)),
			w("noise_m1", pow2(noiseBarrier(a.P))), w("noise_margin_m1", pow2(noiseBarrier(a.P)-1024))),
		expect("SCIENCE.md", `^CCA leak = (\d+) / (\d+) ≈ `+dec+` % of per-pixel configuration`,
			w("noise_config_bits", plain(itb.NoiseConfigBits)), w("config_bits", plain(itb.NoiseConfigBits+itb.DataConfigBits)),
			w("cca_leak_pct", fixed(100*float64(itb.NoiseConfigBits)/float64(itb.NoiseConfigBits+itb.DataConfigBits), 1))),
		expect("SCIENCE.md", `^- \*\*Mode 1\*\* per-region container `+residueLine()+" \\(`\\("+num+" − "+num+"\\)"+x+"7 = "+num+" bytes` at the exact floor\\)",
			w("m1_s", plain(a.Side-1)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)), w("m1_s", plain(a.Side-1)), w("m1_residue", plain(a.Residue)),
			w("m1_P", plain(a.P)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_residue_floor", plain(a.ResidueAtFloor))),
		expect("SCIENCE.md", `^- \*\*Mode 2\*\* per-container container `+residueLine()+" \\(`\\("+num+" − "+num+"\\)"+x+"7 = "+num+" bytes` at the exact floor\\)",
			w("m2_s", plain(b.Side-1)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)), w("m2_s", plain(b.Side-1)), w("m2_residue", plain(b.Residue)),
			w("m2_P", plain(b.P)), w("minpixels_1024", plain(mp)), w("m2_residue_floor", plain(b.ResidueAtFloor))),
		expect("SCIENCE.md", `^- Theoretical single-region floor `+residueLine()+" for payloads `≤ "+num+"² = "+num+"` pixels, and `\\("+num+" − "+num+"\\)"+x+"7 = "+num+" bytes` at the exact "+num+"-pixel floor",
			w("theo_s", plain(t.Side-1)), w("theo_side", plain(t.Side)), w("theo_side", plain(t.Side)), w("theo_P", plain(t.P)), w("theo_s", plain(t.Side-1)), w("theo_residue", plain(t.Residue)),
			w("theo_s", plain(t.Side-1)), w("theo_s_sq", plain((t.Side-1)*(t.Side-1))),
			w("theo_P", plain(t.P)), w("minpixels_1024", plain(mp)), w("theo_residue_floor", plain(t.ResidueAtFloor)), w("minpixels_1024", plain(mp))),
		expect("SCIENCE.md", `^gcd\(A, B\) = gcd\(C\(48, 16\), C\(32, 16\)\) = `+num+` = (.+)$`,
			w("gcd", comma(gcd)), w("gcd_factors", f.GCDFactors)),
		expect("SCIENCE.md", `^gcd\(A₁₆₈, B₁₆₈\) = gcd\(C\(168, 56\), C\(112, 56\)\) = `+num+` = (.+)$`,
			w("gcd168", gcd168Comma), w("gcd168_factors", f.GCD168Factors)),
		expect("SCIENCE.md", `Its image in .\[0, A\) × \[0, B\). has cardinality .A · B / `+num+`.\..*the remaining .≈ `+dec+` %. of the mask space is structurally excluded.*would face a .`+num+`×.-restricted mask space — an erosion of .log₂ `+num+` ≈ `+dec+`. bits`,
			w("gcd", comma(gcd)), w("excluded_pct", trunc(100*(1-invGCD), 3)), w("gcd", comma(gcd)), w("gcd", comma(gcd)), w("log2_gcd", fixed(f.Log2GCD, 2))),
		expect("SCIENCE.md", `In 168-bit mode, the collapse is dramatically steeper: .gcd\(A₁₆₈, B₁₆₈\) = `+num+`. \(.log₂ ≈ `+dec+`.\), so naive same-rank reduction .\(R_512 mod A₁₆₈, R_512 mod B₁₆₈\). reaches only .1 / `+num+` ≈ ([\d.]+ × 10⁻..). of the .A₁₆₈ × B₁₆₈. mask space, eroding .`+dec+`. bits of per-chunk entropy \(collapsing .`+p2d+`. down to .≈ `+p2d+`.\)`,
			w("gcd168", gcd168Comma), w("log2_gcd168", log2GCD168), w("gcd168", gcd168Comma), w("inv_gcd168", sci(invGCD168, 1)), w("log2_gcd168", log2GCD168), w("log2_AB168", "2^"+log2AB168), w("collapsed_AB168", "2^"+fixed(f.Log2AB168-f.Log2GCD168, 2))),
		// Barrier strength table (1024-bit key): Mode 2 | Mode 1 | theoretical.
		expect("SCIENCE.md", `^\| Container dimensions \| `+dimsP+` \| `+dimsP+` \| `+dimsP+` \|$`,
			w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)),
			w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)),
			w("theo_side", plain(t.Side)), w("theo_side", plain(t.Side)), w("theo_P", plain(t.P))),
		expect("SCIENCE.md", `^\| MinPixels enforcement \| `+num+` joint → `+num+` \| 3`+x+num+` = `+num+` → `+num+` \| `+num+` → `+num+` \|$`,
			w("minpixels_1024", plain(mp)), w("m2_P", plain(b.P)), w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_P", plain(a.P)), w("minpixels_1024", plain(mp)), w("theo_P", plain(t.P))),
		expect("SCIENCE.md", `^\| Noise barrier \(2\^\(8P\)\) \| `+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("noise_m2", pow2(noiseBarrier(b.P))), w("noise_m1", pow2(noiseBarrier(a.P))), w("noise_theo", pow2(noiseBarrier(t.P)))),
		expect("SCIENCE.md", `^\| Encoding ambiguity 56\^P \(No CCA\) \| `+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("nocca_m2", pow2(nocca(b.P))), w("nocca_m1", pow2(nocca(a.P))), w("nocca_theo", pow2(nocca(t.P)))),
		expect("SCIENCE.md", `^\| Encoding ambiguity 7\^P \(Under CCA\) \| `+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("cca_m2", pow2(cca(b.P))), w("cca_m1", pow2(cca(a.P))), w("cca_theo", pow2(cca(t.P)))),
		expect("SCIENCE.md", `^\| DRBG residue \(Theorem 10\) \| ≥ `+num+` bytes \(s = `+num+`; `+num+` B at floor\) \| ≥ `+num+` bytes \(s = `+num+`; `+num+` B at floor\) \| ≥ `+num+` bytes \(s = `+num+`; `+num+` B at floor\) \|$`,
			w("m2_residue", plain(b.Residue)), w("m2_s", plain(b.Side-1)), w("m2_residue_floor", plain(b.ResidueAtFloor)),
			w("m1_residue", plain(a.Residue)), w("m1_s", plain(a.Side-1)), w("m1_residue_floor", plain(a.ResidueAtFloor)),
			w("theo_residue", plain(t.Residue)), w("theo_s", plain(t.Side-1)), w("theo_residue_floor", plain(t.ResidueAtFloor))),
		expect("SCIENCE.md", `^\| Config map space \(2\^\(62P\)\) \| `+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("config_m2", pow2(configMap(b.P))), w("config_m1", pow2(configMap(a.P))), w("config_theo", pow2(configMap(t.P)))),
		expect("SCIENCE.md", `^\| Mask-space cardinality \(A₁₆₈ · B₁₆₈, 168-bit\) \| ≈ `+p2d+` \| ≈ `+p2d+` \| ≈ `+p2d+` \|$`,
			w("log2_AB168", "2^"+log2AB168), w("log2_AB168", "2^"+log2AB168), w("log2_AB168", "2^"+log2AB168)),
		expect("SCIENCE.md", `^\| PRF-preimages per mask triple \(168-bit, 2\^512\) \| ≈ `+p2d+` \| ≈ `+p2d+` \| ≈ `+p2d+` \|$`,
			w("log2_preimages168", "2^"+log2Pre168), w("log2_preimages168", "2^"+log2Pre168), w("log2_preimages168", "2^"+log2Pre168)),
		expect("SCIENCE.md", `^\| Distinguisher sample budget \(168-bit\) \| ≈ `+p2d+` chunks \(~`+p2+` msgs\) \| ≈ `+p2d+` chunks \(~`+p2+` msgs\) \| ≈ `+p2d+` chunks \(~`+p2+` msgs\) \|$`,
			w("sample_budget168", "2^"+budget168), w("log2_messages168", msgs168),
			w("sample_budget168", "2^"+budget168), w("log2_messages168", msgs168),
			w("sample_budget168", "2^"+budget168), w("log2_messages168", msgs168)),
		expect("SCIENCE.md", `^\| Key space \| `+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("key_space", pow2(1024)), w("key_space", pow2(1024)), w("key_space", pow2(1024))),
	)
	// Container floor scaling table (Mode 2 vs Mode 1 per key size).
	for _, k := range keySizes {
		mtu := ""
		mtuW := []Want{}
		mtuTail := ""
		if k == 512 {
			mtu = ` \[` + num + x + num + ` at 1460 B payload\]`
			mtuW = []Want{w("mtu512_side", plain(f.MTU512.Side)), w("mtu512_side", plain(f.MTU512.Side))}
			mtuTail = `; ` + num + ` B at 1460 B payload`
		}
		wants := []Want{w(fmt.Sprintf("minpixels_%d", k), plain(f.MinPixels[k])),
			w(fmt.Sprintf("m2_side_%d", k), plain(m2[k].Side)), w(fmt.Sprintf("m2_side_%d", k), plain(m2[k].Side)), w(fmt.Sprintf("m2_P_%d", k), plain(m2[k].P))}
		wants = append(wants, mtuW...)
		wants = append(wants,
			w(fmt.Sprintf("m1_side_%d", k), plain(m1[k].Side)), w(fmt.Sprintf("m1_side_%d", k), plain(m1[k].Side)), w(fmt.Sprintf("m1_P_%d", k), plain(m1[k].P)),
			w(fmt.Sprintf("m2_wire_%d", k), comma(m2[k].Wire)), w(fmt.Sprintf("m1_wire_%d", k), comma(m1[k].Wire)),
			w(fmt.Sprintf("m2_vs_m1_%d", k), pct(m1[k].Wire, m2[k].Wire)+"%"))
		if k == 512 {
			wants = append(wants, w("mtu512_wire", comma(f.MTU512.Wire)))
		}
		add(expect("SCIENCE.md", fmt.Sprintf(`^\| %d-bit \| `, k)+num+` px \| `+dimsP+mtu+` \| `+dimsP+` \| `+num+` B vs `+num+` B \((−[\d.]+%)`+mtuTail+`\) \|$`, wants...))
	}
	add(
		expect("SCIENCE.md", `Wire sizes measured with DefaultNonceBits = `+num+` \(`+num+`-byte stream prefix \+ `+num+`-byte header\), DefaultBarrierFill = `+num+`,`,
			w("nonce_bits", plain(f.NonceBits)), w("prefix", plain(f.Prefix)), w("header", plain(f.HeaderSize)), w("barrier_fill", plain(f.BarrierFill))),
		expect("SCIENCE.md", `Core ITB: .√P × 2\^keyBits. \(~`+p2+` at 1024-bit for \*\*Mode 2\*\* P = `+num+` and theoretical floor P = `+num+`; ~`+p2+` at \*\*Mode 1\*\* P = `+num+`\)\. MAC \+ Reveal: .√P × 2\^\(keyBits/2\). \(~`+p2+` at 1024-bit for P = `+num+` and P = `+num+`; ~`+p2+` at \*\*Mode 1\*\* P = `+num+`\)`,
			w("grover2_m2", bG1), w("m2_P", plain(b.P)), w("theo_P", plain(t.P)), w("grover2_m1", aG1), w("m1_P", plain(a.P)),
			w("grover1_m2", bG2), w("m2_P", plain(b.P)), w("theo_P", plain(t.P)), w("grover1_m1", aG2), w("m1_P", plain(a.P))),
		expect("SCIENCE.md", `the `+p2+` noise-barrier at 1024-bit keys \(P = `+num+`\) is .`+p2+`×. the ~`+p2+` Landauer bound`,
			w("noise_m1", pow2(noiseBarrier(a.P))), w("m1_P", plain(a.P)), w("noise_m1_vs_landauer", pow2(noiseBarrier(a.P)-landauerExp)), w("landauer", pow2(landauerExp))),
		expect("SCIENCE.md", `Under CCA \(MAC \+ Reveal\): .P_threshold = ⌈k / log₂ 7⌉ ≈ ⌈k / `+dec+`⌉`,
			w("log2_7", fixed(math.Log2(7), 3))),
	)
	// Ambiguity-dominance thresholds per region: `P_region ≥ ⌈k / log₂ C⌉`
	// with the raw per-region capacity `P × 7` bytes in decimal KB
	// (SCIENCE.md § 3.4).
	for _, k := range keySizes {
		add(expect("SCIENCE.md", fmt.Sprintf(`^\| %d-bit \| P_region ≥ `, k)+num+` \(~`+dec+` KB\) \| P_region ≥ `+num+` \(~`+dec+` KB\) \|$`,
			w(fmt.Sprintf("threshold_nocca_%d", k), plain(f.ThresholdNoCCA[k])), w(fmt.Sprintf("threshold_nocca_kb_%d", k), kb(f.ThresholdNoCCA[k]*itb.DataBitsPerChannel)),
			w(fmt.Sprintf("minpixels_%d", k), plain(f.MinPixels[k])), w(fmt.Sprintf("minpixels_kb_%d", k), kb(f.MinPixels[k]*itb.DataBitsPerChannel))))
	}
	ambRow := func(label string, P int, pf func(int) string) Expectation {
		return expect("SCIENCE.md", `^\| `+label+` \| `+num+" \\| "+p2+" \\| "+dec+"× \\| "+p2+" \\| "+dec+`× \|$`,
			w("P", pf(P)), w("cca", pow2(cca(P))), w("cca_vs_key", ratioBare(float64(cca(P))/1024)),
			w("nocca", pow2(nocca(P))), w("nocca_vs_key", ratioBare(float64(nocca(P))/1024)))
	}
	add(
		expect("SCIENCE.md", `^\| \*\*Mode 2\*\* container floor \(payload ≤ ~`+dec+` KB\) \|`, w("m2_max_payload_kb", kb(b.MaxPayload))),
		expect("SCIENCE.md", `^\| \*\*Mode 1\*\* container floor \(payload ≤ ~`+dec+` KB\) \|`, w("m1_max_payload_kb", kb(a.MaxPayload))),
		// The theoretical floor is not a shipped shape. Its container is
		// the Mode 2 raw square before the barrier margin, so the payloads
		// it holds are exactly those that fit the Mode 2 floor; the label
		// takes the Mode 2 measured fit while the two containers coincide.
		expect("SCIENCE.md", `^\| Theoretical single-region floor \(~`+dec+` KB\) \|`, w("theo_max_payload_kb", theoPayloadKB)),
		ambRow(`\*\*Mode 2\*\* container floor \(payload ≤ ~[\d.]+ KB\)`, b.P, plain),
		ambRow(`\*\*Mode 1\*\* container floor \(payload ≤ ~[\d.]+ KB\)`, a.P, plain),
		ambRow(`Theoretical single-region floor \(~[\d.]+ KB\)`, t.P, plain),
		ambRow(`64 KB`, s64k.P, plain),
		ambRow(`1 MB`, s1m.P, comma),
		expect("SCIENCE.md", "At 64 KB, encoding ambiguity alone is `"+p2+"`, whose exponent is "+dec+`× the 1024-bit key-space exponent. No computational model can perform \*\*blind enumeration\*\* of `+"`"+p2+"`",
			w("cca_64KiB", pow2(cca(s64k.P))), w("cca_64KiB_vs_key", fixed(float64(cca(s64k.P))/1024, 1)), w("cca_64KiB", pow2(cca(s64k.P)))),
		expect("SCIENCE.md", "At 64 MB \\(`P ≈ "+dec+" × 10⁶`\\), each candidate costs ~"+num+" million pixel-level hash calls",
			w("P_64MiB_sci", fixed(float64(s64m.P)/1e6, 1)), w("hash_calls_64MiB_millions", plain(int(math.Round(float64(s64m.P*2*chainRounds(1024))/1e6))))),
		expect("SCIENCE.md", "Wire format: `prefix \\("+num+" bytes\\) ‖ main_nonce \\(N bytes\\) ‖ W \\(2 bytes\\) ‖ H \\(2 bytes\\) ‖ W × H × 8 raw RGBWYOPA` for a Single Message, with one chunk header of `N \\+ 4` bytes \\(`N` = the configured nonce width in bytes; default `DefaultNonceBits = "+num+"` bits, `N = "+num+"`\\)",
			w("prefix", plain(f.Prefix)), w("nonce_bits", plain(f.NonceBits)), w("nonce_bytes", plain(f.NonceBytes))),
		expect("SCIENCE.md", "\\*\\*Mode 1\\*\\* enforces the per-region floor `MinPixels = "+num+"` across all three regions \\(`3"+x+num+" = "+num+"` square-rounded to `"+num+x+num+" = "+num+"` with `DefaultBarrierFill = "+num+"`\\), yielding barrier `"+p2+"`; \\*\\*Mode 2\\*\\* enforces `MinPixels = "+num+"` jointly across the container \\(`"+num+x+num+" = "+num+"` with `DefaultBarrierFill = "+num+"`\\), yielding barrier `"+p2+"`.*\\(`≥ "+p2+"` at 1024-bit\\).*settles at `8/56 ≈ "+num+"%`",
			w("minpixels_1024", plain(mp)), w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)), w("barrier_fill", plain(f.BarrierFill)),
			w("noise_m1", pow2(noiseBarrier(a.P))), w("minpixels_1024", plain(mp)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)), w("barrier_fill", plain(f.BarrierFill)),
			w("noise_m2", pow2(noiseBarrier(b.P))), w("noise_margin_m1", pow2(noiseBarrier(a.P)-1024)),
			w("noise_overhead_pct", fixed(math.Round(100*float64(itb.Channels)/float64(itb.DataBitsPerPixel)), 0))),
		expect("SCIENCE.md", `relative deviation of ≈ (2\^-\d+\.\d).*maximum-size message of (2\^\d+\.\d+) chunks, the per-message deviation is bounded by ≈ (2\^-\d+\.\d)\..*1/ε² ≈ (2\^\d+\.\d). chunk samples`,
			w("bias", "2^"+bias), w("max_chunks", "2^"+chunks), w("accum_bias", "2^"+accum), w("sample_budget", "2^"+budget)),
		expect("SCIENCE.md", `stacks .\(A₁₆₈ · B₁₆₈\)\^C ≈ 2\^\((\d+\.\d+) × C\). mask configurations.*leaves .≈ (2\^\d+\.\d). \(for a 48-bit / 6-byte crib\) or .≈ (2\^\d+\.\d). \(.≈ `+p2+`., for a 168-bit / 21-byte crib\) compatible mask triples`,
			w("log2_AB168", log2AB168), w("masks_per_crib", crib48), w("masks_per_crib168", crib168), w("masks_per_crib168_floor", crib168Floor)),
		expect("SCIENCE.md", `spans at most .`+num+` ≈ `+p2d+`. chunks of 21 bytes drawn from .\|Ω_chunk,168\| ≈ `+p2d+`.`,
			w("max_chunks168", comma(f.MaxChunks168)), w("log2_chunks168", "2^"+chunks168), w("log2_AB168", "2^"+log2AB168)),
		expect("SCIENCE.md", `each 168-bit \(.21.-byte\) chunk is partitioned into three 56-bit \(.7.-byte\) lanes with .A₁₆₈ = C\(168, 56\) = `+num+`. \(.log₂ ≈ `+dec+`.\), .B₁₆₈ = C\(112, 56\) = `+num+`. \(.log₂ ≈ `+dec+`.\), and .\|Ω_chunk,168\| = A₁₆₈ · B₁₆₈ = `+num+` ≈ `+p2d+`.`,
			w("A168", commaBig(f.A168)), w("log2_A168", log2A168), w("B168", commaBig(f.B168)), w("log2_B168", log2B168), w("AB168", commaBig(f.AB168)), w("log2_AB168", "2^"+log2AB168)),
		expect("SCIENCE.md", `every 168-bit mask triple has .⌊2\^512 / \(A₁₆₈ · B₁₆₈\)⌋ = `+num+` ≈ `+p2d+`. 512-bit PRF-output preimages, and a single 168-bit \(.21.-byte\) known-plaintext crib remains consistent with .≈ `+p2d+`. \(.≈ `+p2+`.\) mask triples per chunk`,
			w("preimages168", commaBig(f.Preimages168)), w("log2_preimages168", "2^"+log2Pre168), w("masks_per_crib168", crib168), w("masks_per_crib168_floor", crib168Floor)),
		expect("SCIENCE.md", `yields a per-chunk relative deviation \(bias\) of .≈ (2\^-\d+\.\d).\..*containing at most .`+num+`. \(.≈ `+p2d+`.\) chunks of 21 bytes, the accumulated per-message bias is bounded by .≈ (2\^-\d+\.\d)., requiring a statistical distinguisher sample budget of .1 / ε² ≈ `+p2d+`. chunks \(.~`+p2+`. maximum-size messages\)`,
			w("bias168", "2^"+bias168), w("max_chunks168", comma(f.MaxChunks168)), w("log2_chunks168", "2^"+chunks168), w("accum_bias168", "2^"+accum168), w("sample_budget168", "2^"+budget168), w("log2_messages168", msgs168)),
		expect("SCIENCE.md", `per-chunk bias ≈ (2\^-\d+\.\d)., accumulated 64 MiB bias .≈ (2\^-\d+\.\d)., distinguisher budget .≈ `+p2d+`. chunks`,
			w("bias168", "2^"+bias168), w("accum_bias168", "2^"+accum168), w("sample_budget168", "2^"+budget168)),
	)

	// ----- PROOFS.md --------------------------------------------------
	add(
		expect("PROOFS.md", "^- Under \\*\\*Mode 1\\*\\* \\(per-region floor `MinPixels = "+num+"` applied to each of three regions, `3"+x+num+" = "+num+"`, square-rounded to `"+num+x+num+" = "+num+"` with `DefaultBarrierFill = "+num+"`\\): `7\\^"+num+" ≈ "+p2+"`",
			w("minpixels_1024", plain(mp)), w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)), w("barrier_fill", plain(f.BarrierFill)), w("m1_P", plain(a.P)), w("cca_m1", pow2(cca(a.P)))),
		expect("PROOFS.md", "^- Under \\*\\*Mode 2\\*\\* \\(per-container floor `MinPixels = "+num+"` evaluated across the container, square-rounded to `"+num+x+num+" = "+num+"` with `DefaultBarrierFill = "+num+"`\\): `7\\^"+num+" ≈ "+p2+"`",
			w("minpixels_1024", plain(mp)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)), w("barrier_fill", plain(f.BarrierFill)), w("m2_P", plain(b.P)), w("cca_m2", pow2(cca(b.P)))),
		expect("PROOFS.md", `The noise barrier \(`+p2+` for \*\*Mode 1\*\*, `+p2+` for \*\*Mode 2\*\*,`,
			w("noise_m1", pow2(noiseBarrier(a.P))), w("noise_m2", pow2(noiseBarrier(b.P)))),
		expect("PROOFS.md", `^MinPixels = MinPixelsAuth = ⌈1024 / log₂\(7\)⌉ = ⌈1024 / `+dec+`⌉ = `+num+` per region$`,
			w("log2_7", fixed(math.Log2(7), 3)), w("minpixels_1024", plain(mp))),
		expect("PROOFS.md", `^Total pixels = 3 × per-region floor = `+num+`; square container side = ⌈√`+num+`⌉ = `+num+`; with default barrier margin \(.DefaultBarrierFill = `+num+`.\) side = `+num+`; P = `+num+x+num+` = `+num+`\.$`,
			w("m1_floor_px", plain(a.FloorPixels)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_raw_square", plain(a.RawSquare)), w("barrier_fill", plain(f.BarrierFill)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P))),
		expect("PROOFS.md", `^2\^\(8`+x+num+`\) = `+p2+`$`, w("m1_P", plain(a.P)), w("noise_m1", pow2(noiseBarrier(a.P)))),
		expect("PROOFS.md", `^`+num+` > 1024  ⟹  `+p2+` > `+p2+`  ✓$`, w("noise_m1_exp", plain(noiseBarrier(a.P))), w("noise_m1", pow2(noiseBarrier(a.P))), w("key_space", pow2(1024))),
		expect("PROOFS.md", `^The barrier strictly exceeds the key space by a factor of `+p2+`\.$`, w("noise_margin_m1", pow2(noiseBarrier(a.P)-1024))),
		expect("PROOFS.md", "^- \\*\\*Mode 1\\*\\* \\(per-region floor\\): `P ≥ 3 × ⌈keyBits / log₂\\(7\\)⌉`. For a 1024-bit key, `P = "+num+"`, yielding noise barrier `2\\^\\(8"+x+num+"\\) = "+p2+" > "+p2+"` \\(margin `"+p2+"`\\)",
			w("m1_P", plain(a.P)), w("m1_P", plain(a.P)), w("noise_m1", pow2(noiseBarrier(a.P))), w("key_space", pow2(1024)), w("noise_margin_m1", pow2(noiseBarrier(a.P)-1024))),
		expect("PROOFS.md", "^- \\*\\*Mode 2\\*\\* \\(per-container floor\\): `P ≥ ⌈keyBits / log₂\\(7\\)⌉`. For a 1024-bit key, `P = "+num+"`, yielding noise barrier `2\\^\\(8"+x+num+"\\) = "+p2+" > "+p2+"` \\(margin `"+p2+"`\\)",
			w("m2_P", plain(b.P)), w("m2_P", plain(b.P)), w("noise_m2", pow2(noiseBarrier(b.P))), w("key_space", pow2(1024)), w("noise_margin_m2", pow2(noiseBarrier(b.P)-1024))),
		expect("PROOFS.md", "Because `Channels = (\\d+)` and `8 / log₂\\(7\\) ≈ "+dec+" > 1`",
			w("channels", plain(itb.Channels)), w("8_over_log2_7", fixed(8/math.Log2(7), 3))),
		expect("PROOFS.md", "^- Under CCA \\(MAC \\+ Reveal\\): `P_threshold = ⌈k / log₂\\(7\\)⌉ ≈ ⌈k / "+dec+"⌉`", w("log2_7", fixed(math.Log2(7), 3))),
		// The leading digit separates the CCA (log₂ 7) and No CCA (log₂ 56)
		// lines of the same derivation.
		expect("PROOFS.md", `^P_region > k / (2\.\d+)$`, w("log2_7", fixed(math.Log2(7), 3))),
		expect("PROOFS.md", `^P_region > k / (5\.\d+)$`, w("log2_56", fixed(math.Log2(56), 3))),
		expect("PROOFS.md", "^- Without CCA \\(Core ITB / MAC \\+ Silent Drop\\): `P_threshold = ⌈k / log₂\\(56\\)⌉ ≈ ⌈k / "+dec+"⌉`", w("log2_56", fixed(math.Log2(56), 3))),
		expect("PROOFS.md", `^\*\*Total CCA leak: (\d+) bits per pixel \(noisePos\) / (\d+) total config bits = `+dec+`%\.\*\*`,
			w("noise_config_bits", plain(itb.NoiseConfigBits)), w("config_bits", plain(itb.NoiseConfigBits+itb.DataConfigBits)),
			w("cca_leak_pct", fixed(100*float64(itb.NoiseConfigBits)/float64(itb.NoiseConfigBits+itb.DataConfigBits), 1))),
	)
	for _, k := range []int{1024, 2048} {
		add(expect("PROOFS.md", fmt.Sprintf(`^\| %d-bit \| P_region ≥ `, k)+num+` pixels \| P_region ≥ `+num+` pixels \|$`,
			w(fmt.Sprintf("minpixels_%d", k), plain(f.MinPixels[k])), w(fmt.Sprintf("threshold_nocca_%d", k), plain(f.ThresholdNoCCA[k]))))
	}
	add(
		expect("PROOFS.md", "^- \\*\\*Mode 1\\*\\* composite container \\(per-region floor `MinPixels = "+num+"` × 3 regions = "+num+" total pixels, `s = ⌈√"+num+"⌉ = "+num+"`, container `"+num+x+num+" = "+num+"`\\): `gap ≥ \\(2"+x+num+" \\+ 1\\)"+x+"7 = "+num+" bytes`, and `\\("+num+" - "+num+"\\)"+x+"7 = "+num+" bytes` at the exact "+num+"-pixel floor",
			w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_s", plain(a.Side-1)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)),
			w("m1_s", plain(a.Side-1)), w("m1_residue", plain(a.Residue)), w("m1_P", plain(a.P)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_residue_floor", plain(a.ResidueAtFloor)), w("m1_floor_px", plain(a.FloorPixels))),
		expect("PROOFS.md", "^- \\*\\*Mode 2\\*\\* compact container \\(per-container floor `MinPixels = "+num+"`, `s = ⌈√"+num+"⌉ = "+num+"`, container `"+num+x+num+" = "+num+"`\\): `gap ≥ \\(2"+x+num+" \\+ 1\\)"+x+"7 = "+num+" bytes` for payloads ≤ "+num+"² = "+num+" pixels \\(payload ≤ ~"+dec+" KB\\), and `\\("+num+" - "+num+"\\)"+x+"7 = "+num+" bytes` at the exact "+num+"-pixel floor",
			w("minpixels_1024", plain(mp)), w("minpixels_1024", plain(mp)), w("m2_s", plain(b.Side-1)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)),
			w("m2_s", plain(b.Side-1)), w("m2_residue", plain(b.Residue)), w("m2_s", plain(b.Side-1)), w("m2_s_sq", plain((b.Side-1)*(b.Side-1))), w("m2_max_payload_kb", kb(b.MaxPayload)),
			w("m2_P", plain(b.P)), w("minpixels_1024", plain(mp)), w("m2_residue_floor", plain(b.ResidueAtFloor)), w("minpixels_1024", plain(mp))),
		expect("PROOFS.md", `^\| \*\*Mode 2\*\* per-container floor \(1024-bit key, P = `+num+`\) \| `+num+` \| `+num+` bytes \(`+num+` bytes at `+num+`-pixel floor\) \|$`,
			w("m2_P", plain(b.P)), w("m2_s", plain(b.Side-1)), w("m2_residue", plain(b.Residue)), w("m2_residue_floor", plain(b.ResidueAtFloor)), w("minpixels_1024", plain(mp))),
		expect("PROOFS.md", `^\| \*\*Mode 1\*\* per-region floor \(1024-bit key, P = `+num+`\) \| `+num+` \| `+num+` bytes \(`+num+` bytes at `+num+`-pixel floor\) \|$`,
			w("m1_P", plain(a.P)), w("m1_s", plain(a.Side-1)), w("m1_residue", plain(a.Residue)), w("m1_residue_floor", plain(a.ResidueAtFloor)), w("m1_floor_px", plain(a.FloorPixels))),
		expect("PROOFS.md", `^\| 16 KB \| `+num+` \| `+num+` bytes \|$`, w("s_16KiB", plain(s16k.Side-1)), w("residue_16KiB", plain(s16k.Residue))),
		expect("PROOFS.md", `^\| 1 MB \| `+num+` \| `+num+` bytes \|$`, w("s_1MiB", plain(s1m.Side-1)), w("residue_1MiB", comma(s1m.Residue))),
		expect("PROOFS.md", `^\| 64 MB \| `+num+` \| `+num+` bytes \|$`, w("s_64MiB", comma(s64m.Side-1)), w("residue_64MiB", comma(s64m.Residue))),
		expect("PROOFS.md", `^- A = C\(48, 16\) = \*\*`+num+`\*\* \(log₂ ≈ `+dec+`\)`, w("A", commaBig(f.A)), w("log2_A", fixed(f.Log2A, 2))),
		expect("PROOFS.md", `^- B = C\(32, 16\) = \*\*`+num+`\*\* \(log₂ ≈ `+dec+`\)`, w("B", commaBig(f.B)), w("log2_B", fixed(f.Log2B, 2))),
		expect("PROOFS.md", `^\|Ω_chunk\| = A · B = `+num+`\s+≈\s+`+p2d+` \.$`, w("AB", commaBig(f.AB)), w("log2_AB", "2^"+log2AB)),
		expect("PROOFS.md", `^gcd\(A, B\) = gcd\(C\(48, 16\), C\(32, 16\)\) = `+num+` = (.+) \.$`, w("gcd", plain(gcd)), w("gcd_factors", f.GCDFactors)),
		expect("PROOFS.md", `cardinality .A · B / d = A · B / `+num+`.\..*\(1 − 1/`+num+`\)`, w("gcd", plain(gcd)), w("gcd", plain(gcd))),
		expect("PROOFS.md", `^1 / `+num+`  ≈  ([\d.]+ × 10⁻.) ,$`, w("gcd", plain(gcd)), w("inv_gcd", sci(invGCD, 1))),
		expect("PROOFS.md", `so ≈ `+dec+` % of the .A × B. mask space would be structurally excluded.*would face a `+num+`×-restricted mask space.*log₂ `+num+` ≈ `+dec+`.-bit erosion`,
			w("excluded_pct", trunc(100*(1-invGCD), 3)), w("gcd", plain(gcd)), w("gcd", plain(gcd)), w("log2_gcd", fixed(f.Log2GCD, 2))),
		expect("PROOFS.md", `relative deviation of \*\*≈ (2\^-\d+\.\d)\*\*.*maximum-size message of .(2\^\d+\.\d+). chunks, the per-message deviation is bounded by \*\*≈ (2\^-\d+\.\d)\*\*.*1 / ε² ≈ (2\^\d+\.\d). chunk samples`,
			w("bias", "2^"+bias), w("max_chunks", "2^"+chunks), w("accum_bias", "2^"+accum), w("sample_budget", "2^"+budget)),
		expect("PROOFS.md", `^- .A₁₆₈ = C\(168, 56\) = `+num+`. \(.log₂ ≈ `+dec+`.\) — choices for .m0.,$`,
			w("A168", commaBig(f.A168)), w("log2_A168", log2A168)),
		expect("PROOFS.md", `^- .B₁₆₈ = C\(112, 56\) = `+num+`. \(.log₂ ≈ `+dec+`.\) — choices for .m1. from the remaining 112 bits`,
			w("B168", commaBig(f.B168)), w("log2_B168", log2B168)),
		expect("PROOFS.md", `^- .\|Ω_chunk,168\| = A₁₆₈ · B₁₆₈ = `+num+` ≈ `+p2d+`.\.$`,
			w("AB168", commaBig(f.AB168)), w("log2_AB168", "2^"+log2AB168)),
		expect("PROOFS.md", `^Each mask triple receives .⌊2\^512 / \(A₁₆₈ · B₁₆₈\)⌋ = `+num+` ≈ `+p2d+`. preimages in .\[0, 2\^512\).*leaves .≈ `+p2d+`. compatible mask triples, and .\(A₁₆₈ · B₁₆₈\)\^C ≈ 2\^\((\d+\.\d+) × C\).*per-chunk relative deviation is .≈ (2\^-\d+\.\d).; across a maximum 64 MiB message of .`+num+`. \(.≈ `+p2d+`.\) chunks, the accumulated deviation is bounded by .≈ (2\^-\d+\.\d)., requiring .1 / ε² ≈ `+p2d+`. chunk samples \(.~`+p2+`. maximum-size messages\)`,
			w("preimages168", commaBig(f.Preimages168)), w("log2_preimages168", "2^"+log2Pre168), w("masks_per_crib168", crib168), w("log2_AB168", log2AB168), w("bias168", "2^"+bias168), w("max_chunks168", comma(f.MaxChunks168)), w("log2_chunks168", "2^"+chunks168), w("accum_bias168", "2^"+accum168), w("sample_budget168", "2^"+budget168), w("log2_messages168", msgs168)),
		expect("PROOFS.md", `^gcd\(A₁₆₈, B₁₆₈\) = gcd\(C\(168, 56\), C\(112, 56\)\) = `+num+` = (.+)$`,
			w("gcd168", gcd168Plain), w("gcd168_factors", f.GCD168Factors)),
		expect("PROOFS.md", `^\(.log₂ ≈ `+dec+`., .1 / `+num+` ≈ ([\d.]+ × 10⁻..).\), structurally excluding all but a .([\d.]+ × 10⁻..). fraction of .A₁₆₈ × B₁₆₈. \(a .`+dec+`.-bit erosion\).*with .⌊2\^512 / \(A₁₆₈ · B₁₆₈\)⌋ ≈ `+p2d+`. preimages per pair`,
			w("log2_gcd168", log2GCD168), w("gcd168", gcd168Plain), w("inv_gcd168", sci(invGCD168, 1)), w("inv_gcd168", sci(invGCD168, 1)), w("log2_gcd168", log2GCD168), w("log2_preimages168", "2^"+log2Pre168)),
		expect("PROOFS.md", `^\| A \(m0 choices\) \| C\(48, 16\) = `+num+` \(log₂ ≈ `+dec+`\) \| C\(168, 56\) = `+num+` \(log₂ ≈ `+dec+`\) \|$`,
			w("A", commaBig(f.A)), w("log2_A", fixed(f.Log2A, 2)), w("A168", commaBig(f.A168)), w("log2_A168", log2A168)),
		expect("PROOFS.md", `^\| B \(m1 choices\) \| C\(32, 16\) = `+num+` \(log₂ ≈ `+dec+`\) \| C\(112, 56\) = `+num+` \(log₂ ≈ `+dec+`\) \|$`,
			w("B", commaBig(f.B)), w("log2_B", fixed(f.Log2B, 2)), w("B168", commaBig(f.B168)), w("log2_B168", log2B168)),
		expect("PROOFS.md", `^\| Mask space \\\|Ω_chunk\\\| = A · B \| ≈ `+p2d+` \| ≈ `+p2d+` \|$`,
			w("log2_AB", "2^"+log2AB), w("log2_AB168", "2^"+log2AB168)),
		expect("PROOFS.md", `^\| Anti-collapse gcd\(A, B\) \| `+num+` = (.+?) \(log₂ ≈ `+dec+`, 1/gcd ≈ ([\d.]+ × 10⁻.)\) \| `+num+` = (.+?) \(log₂ ≈ `+dec+`, 1/gcd ≈ ([\d.]+ × 10⁻..)\) \|$`,
			w("gcd", plain(gcd)), w("gcd_factors", f.GCDFactors), w("log2_gcd", fixed(f.Log2GCD, 2)), w("inv_gcd", sci(invGCD, 1)),
			w("gcd168", gcd168Plain), w("gcd168_factors", f.GCD168Factors), w("log2_gcd168", log2GCD168), w("inv_gcd168", sci(invGCD168, 1))),
		expect("PROOFS.md", `^\| Unrank input width / preimages \| 128-bit \(⌊2\^128 / \(A · B\)⌋ ≈ `+p2d+`\) \| 512-bit \(⌊2\^512 / \(A₁₆₈ · B₁₆₈\)⌋ ≈ `+p2d+`\) \|$`,
			w("log2_preimages", "2^"+log2Pre), w("log2_preimages168", "2^"+log2Pre168)),
		expect("PROOFS.md", `^\| Compatible masks per 1-chunk crib \| ≈ `+p2d+` \(48-bit / 6 B crib\) \| ≈ `+p2d+` \(168-bit / 21 B crib\) \|$`,
			w("masks_per_crib", crib48), w("masks_per_crib168", crib168)),
		expect("PROOFS.md", `^\| Per-chunk bias \| ≈ (2\^-\d+\.\d) \| ≈ (2\^-\d+\.\d) \|$`,
			w("bias", "2^"+bias), w("bias168", "2^"+bias168)),
		expect("PROOFS.md", `^\| Max chunks in 64 MiB / accumulated bias \| `+num+` \(≈ `+p2d+`\) / ≈ (2\^-\d+\.\d) \| `+num+` \(≈ `+p2d+`\) / ≈ (2\^-\d+\.\d) \|$`,
			w("max_chunks", comma(f.MaxChunks)), w("log2_chunks", "2^"+chunks), w("accum_bias", "2^"+accum),
			w("max_chunks168", comma(f.MaxChunks168)), w("log2_chunks168", "2^"+chunks168), w("accum_bias168", "2^"+accum168)),
		expect("PROOFS.md", `^\| Distinguisher sample budget \(1 / ε²\) \| ≈ `+p2d+` chunks \(~`+p2+` max messages\) \| ≈ `+p2d+` chunks \(~`+p2+` max messages\) \|$`,
			w("sample_budget", "2^"+budget), w("log2_messages", "2^"+fixed(math.Round(f.Log2Messages), 0)),
			w("sample_budget168", "2^"+budget168), w("log2_messages168", msgs168)),
		expect("PROOFS.md", `removes noise bits \(`+dec+`% of container\)\. The remaining `+dec+`% contains data bits`,
			w("noise_bits_pct", fixed(100.0/itb.Channels, 1)), w("data_bits_pct", fixed(100-100.0/itb.Channels, 1))),
		expect("PROOFS.md", `uniform across all pixels: `+dec+`% reject, `+dec+`% accept\.`,
			w("data_bits_pct", fixed(100-100.0/itb.Channels, 1)), w("noise_bits_pct", fixed(100.0/itb.Channels, 1))),
	)

	// ----- SECURITY.md ------------------------------------------------
	add(
		sweep("SECURITY.md", `CCA (?:eliminates|reveals) noise bits \(`+dec+` %`, w("noise_bits_pct", fixed(100.0/itb.Channels, 1))),
		expect("SECURITY.md", `^\| Total container bits \| `+num+` \| `+dec+` % \|$`, w("container_bits", plain(itb.Channels*8)), w("pct_100", "100")),
		expect("SECURITY.md", `^\| Data bits \| `+num+` \| `+dec+` % \|$`, w("data_bits", plain(itb.DataBitsPerPixel)), w("data_bits_pct", fixed(100-100.0/itb.Channels, 1))),
		expect("SECURITY.md", `^\| Noise bits \| `+num+` \| `+dec+` % \|$`, w("noise_bits", plain(itb.Channels)), w("noise_bits_pct", fixed(100.0/itb.Channels, 1))),
		expect("SECURITY.md", `^\| noiseSeed \(noise position\) \| `+num+` \| `+num+` \(100 % of noiseSeed\)`, w("noise_config_bits", plain(itb.NoiseConfigBits)), w("noise_config_bits", plain(itb.NoiseConfigBits))),
		expect("SECURITY.md", `^\| dataSeed \(rotation \+ XOR\) \| `+num+` \| \*\*0\*\* \(independent seed\) \| \*\*`+num+` \(100 %\)\*\* \|$`, w("data_config_bits", plain(itb.DataConfigBits)), w("data_config_bits", plain(itb.DataConfigBits))),
		expect("SECURITY.md", `^\| \*\*Total\*\* \| \*\*`+num+`\*\* \| \*\*`+num+` \(`+dec+` %\)\*\* \| \*\*`+num+` \(`+dec+` %\)\*\* \|$`,
			w("config_bits", plain(itb.NoiseConfigBits+itb.DataConfigBits)), w("noise_config_bits", plain(itb.NoiseConfigBits)),
			w("cca_leak_pct", fixed(100*float64(itb.NoiseConfigBits)/float64(itb.NoiseConfigBits+itb.DataConfigBits), 1)),
			w("data_config_bits", plain(itb.DataConfigBits)), w("protected_pct", fixed(100*float64(itb.DataConfigBits)/float64(itb.NoiseConfigBits+itb.DataConfigBits), 1))),
		expect("SECURITY.md", `\(\*\*Mode 1\*\*, P = `+num+`\): classical ~`+p2+`, Grover ~`+p2+` \(under per-container \*\*Mode 2\*\*, P = `+num+`: classical ~`+p2+`, Grover ~`+p2+`\)`,
			w("m1_P", plain(a.P)), w("classical2_m1", aC1), w("grover2_m1", aG1), w("m2_P", plain(b.P)), w("classical2_m2", bC1), w("grover2_m2", bG1)),
		expect("SECURITY.md", `\(\*\*Mode 1\*\*, P = `+num+` = 3 × per-region floor `+num+`, square-rounded to `+num+x+num+` with DefaultBarrierFill = `+num+`\): classical ~`+p2+`, Grover ~`+p2+` \(under per-container \*\*Mode 2\*\*, P = `+num+`: classical ~`+p2+`, Grover ~`+p2+`\)`,
			w("m1_P", plain(a.P)), w("minpixels_1024", plain(mp)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("barrier_fill", plain(f.BarrierFill)),
			w("classical1_m1", aC2), w("grover1_m1", aG2), w("m2_P", plain(b.P)), w("classical1_m2", bC2), w("grover1_m2", bG2)),
		expect("SECURITY.md", `reaches ~50 % after 2\^\(N/2\) messages \(~`+p2+` for default `+num+`-bit, ~`+p2+` for 128-bit\); simultaneous dual-slot collision requires the product probability ~2\^N messages \(~`+p2+` for default `+num+`-bit\)`,
			w("birthday_default", pow2(f.NonceBits/2)), w("nonce_bits", plain(f.NonceBits)), w("birthday_128", pow2(128/2)), w("dual_birthday_default", pow2(f.NonceBits)), w("nonce_bits", plain(f.NonceBits))),
		expect("SECURITY.md", `^\| Container dimensions \| `+dimsP+` \| `+dimsP+` \| `+dimsP+` \|$`,
			w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)),
			w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)),
			w("theo_side", plain(t.Side)), w("theo_side", plain(t.Side)), w("theo_P", plain(t.P))),
		expect("SECURITY.md", `^\| MinPixels enforcement \| `+num+` joint → `+num+` \(DefaultBarrierFill = `+num+`\) \| 3`+x+num+` = `+num+` → `+num+` \(DefaultBarrierFill = `+num+`\) \| `+num+` → `+num+` \|$`,
			w("minpixels_1024", plain(mp)), w("m2_P", plain(b.P)), w("barrier_fill", plain(f.BarrierFill)), w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_P", plain(a.P)), w("barrier_fill", plain(f.BarrierFill)), w("minpixels_1024", plain(mp)), w("theo_P", plain(t.P))),
		expect("SECURITY.md", `^\| Noise barrier \(2\^\(8P\)\) \| `+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("noise_m2", pow2(noiseBarrier(b.P))), w("noise_m1", pow2(noiseBarrier(a.P))), w("noise_theo", pow2(noiseBarrier(t.P)))),
		expect("SECURITY.md", `^\| Encoding ambiguity 56\^P \(No CCA, Theorem 9\) \| `+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("nocca_m2", pow2(nocca(b.P))), w("nocca_m1", pow2(nocca(a.P))), w("nocca_theo", pow2(nocca(t.P)))),
		expect("SECURITY.md", `^\| Encoding ambiguity 7\^P \(Under CCA, Theorem 9\) \| `+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("cca_m2", pow2(cca(b.P))), w("cca_m1", pow2(cca(a.P))), w("cca_theo", pow2(cca(t.P)))),
		expect("SECURITY.md", `^\| Guaranteed DRBG residue \(Theorem 10\) \| ≥ `+num+` bytes \(s = `+num+`\) / `+num+` bytes \| ≥ `+num+` bytes \(s = `+num+`\) / `+num+` bytes \| ≥ `+num+` bytes \(s = `+num+`\) / `+num+` bytes \|$`,
			w("m2_residue", plain(b.Residue)), w("m2_s", plain(b.Side-1)), w("m2_residue_floor", plain(b.ResidueAtFloor)),
			w("m1_residue", plain(a.Residue)), w("m1_s", plain(a.Side-1)), w("m1_residue_floor", plain(a.ResidueAtFloor)),
			w("theo_residue", plain(t.Residue)), w("theo_s", plain(t.Side-1)), w("theo_residue_floor", plain(t.ResidueAtFloor))),
		expect("SECURITY.md", `^\| Blind-enumeration exponent vs Landauer \| `+dec+`× \(`+num+` / `+num+`\) \| `+dec+`× \(`+num+` / `+num+`\) \| `+dec+`× \(`+num+` / `+num+`\) \|$`,
			w("noise_m2_vs_landauer", landauer(noiseBarrier(b.P))), w("noise_m2_exp", plain(noiseBarrier(b.P))), w("landauer_exp", plain(landauerExp)),
			w("noise_m1_vs_landauer", landauer(noiseBarrier(a.P))), w("noise_m1_exp", plain(noiseBarrier(a.P))), w("landauer_exp", plain(landauerExp)),
			w("noise_theo_vs_landauer", landauer(noiseBarrier(t.P))), w("noise_theo_exp", plain(noiseBarrier(t.P))), w("landauer_exp", plain(landauerExp))),
		expect("SECURITY.md", `^\| Config map space \(2\^\(62P\)\) \| `+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("config_m2", pow2(configMap(b.P))), w("config_m1", pow2(configMap(a.P))), w("config_theo", pow2(configMap(t.P)))),
		expect("SECURITY.md", `^\| Key space \| `+p2+` \| `+p2+` \| `+p2+` \|$`, w("key_space", pow2(1024)), w("key_space", pow2(1024)), w("key_space", pow2(1024))),
		expect("SECURITY.md", `^\| gcd\(A, B\) anti-collapse factor \(Theorem 12\) \| `+num+` \(full Cartesian reached\) \| `+num+` \(full Cartesian reached\) \| `+num+` \(full Cartesian reached\) \|$`,
			w("gcd", comma(gcd)), w("gcd", comma(gcd)), w("gcd", comma(gcd))),
		expect("SECURITY.md", `^\| Mask-space cardinality per chunk, 168-bit \(Theorem 11\) \| ≈ `+p2d+` \| ≈ `+p2d+` \| ≈ `+p2d+` \|$`,
			w("log2_AB168", "2^"+log2AB168), w("log2_AB168", "2^"+log2AB168), w("log2_AB168", "2^"+log2AB168)),
		expect("SECURITY.md", `^\| PRF-preimage count per mask triple, 168-bit \(512-bit PRF\) \| ≈ `+p2d+` \| ≈ `+p2d+` \| ≈ `+p2d+` \|$`,
			w("log2_preimages168", "2^"+log2Pre168), w("log2_preimages168", "2^"+log2Pre168), w("log2_preimages168", "2^"+log2Pre168)),
		expect("SECURITY.md", `^\| gcd\(A₁₆₈, B₁₆₈\) anti-collapse factor, 168-bit \(Theorem 12\) \| `+num+` \(full Cartesian reached\) \| `+num+` \(full Cartesian reached\) \| `+num+` \(full Cartesian reached\) \|$`,
			w("gcd168", gcd168Comma), w("gcd168", gcd168Comma), w("gcd168", gcd168Comma)),
		expect("SECURITY.md", `about (2\^\d+\.\d+) chunks of 168 bits`,
			w("log2_chunks168", "2^"+chunks168)),
		expect("SECURITY.md", `^\| 8/1 \(ITB\) \| `+num+` \| `+num+` \| `+dec+`× \| `+dec+` % \| `+p2+` \|$`,
			w("data_bits", plain(itb.DataBitsPerPixel)), w("noise_bits", plain(itb.Channels)), w("noise_overhead", fixed(float64(itb.Channels)/float64(itb.DataBitsPerChannel), 2)),
			w("cca_leak_pct", fixed(100*float64(itb.NoiseConfigBits)/float64(itb.NoiseConfigBits+itb.DataConfigBits), 1)), w("noise_theo", pow2(noiseBarrier(t.P)))),
		expect("SECURITY.md", "giving `P = "+num+"` for 1024-bit keys with barrier `"+p2+"`", w("m1_P", plain(a.P)), w("noise_m1", pow2(noiseBarrier(a.P)))),
	)

	// ----- ITB.md -----------------------------------------------------
	add(
		expect("ITB.md", `\(`+num+` / `+num+` / `+num+` pixels for 512 / 1024 / 2048-bit keys\)`,
			w("minpixels_512", plain(f.MinPixels[512])), w("minpixels_1024", plain(mp)), w("minpixels_2048", plain(f.MinPixels[2048]))),
		expect("ITB.md", `Small messages clamp to .3 × MinPixels. data pixels, yielding a `+num+x+num+` container \(`+num+` pixels\) at 1024-bit keys`,
			w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P))),
		expect("ITB.md", `Small messages clamp to .MinPixels. total pixels, yielding a `+num+x+num+` container \(`+num+` pixels\) at 1024-bit keys`,
			w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P))),
		expect("ITB.md", "At 1024-bit keys \\(`MinPixels = "+num+"`\\), \\*\\*Mode 1\\*\\* \\(per-region, `3"+x+num+" = "+num+"` pixels, `s = "+num+"`, container `"+num+x+num+" = "+num+"` pixels\\) yields `gap ≥ "+num+" bytes`; \\*\\*Mode 2\\*\\* \\(per-container, `totalPixels = "+num+"`, `s = "+num+"`, container `"+num+x+num+" = "+num+"` pixels\\) yields `gap ≥ "+num+" bytes`",
			w("minpixels_1024", plain(mp)), w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_s", plain(a.Side-1)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)), w("m1_residue", plain(a.Residue)),
			w("minpixels_1024", plain(mp)), w("m2_s", plain(b.Side-1)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)), w("m2_residue", plain(b.Residue))),
		expect("ITB.md", "^- `A · B = "+num+"` \\(log₂ ≈ "+dec+"\\)\\.$", w("AB", commaBig(f.AB)), w("log2_AB", log2AB)),
		expect("ITB.md", `the number of preimages per mask triple is .⌊2\^128 / \(A · B\)⌋ ≈ `+p2d+`.`, w("log2_preimages", "2^"+log2Pre)),
		expect("ITB.md", `because .gcd\(A, B\) = gcd\(C\(48, 16\), C\(32, 16\)\) = `+num+` = (.+?)., which would restrict reachable pairs to .1 / `+num+` ≈ ([\d.]+ × 10⁻.). of the space \(eroding .log₂ `+num+` ≈ `+dec+`. bits of entropy\)`,
			w("gcd", comma(gcd)), w("gcd_factors", f.GCDFactors), w("gcd", comma(gcd)), w("inv_gcd", sci(invGCD, 1)), w("gcd", comma(gcd)), w("log2_gcd", fixed(f.Log2GCD, 2))),
		expect("ITB.md", `relative deviation of ≈ (2\^-\d+\.\d) per chunk.*maximum message of (2\^\d+\.\d+) chunks, deviation is bounded by ≈ (2\^-\d+\.\d)\. Detecting this would require ~(2\^\d+\.\d) chunk samples \(~(2\^\d+) maximum-size messages\)`,
			w("bias", "2^"+bias), w("max_chunks", "2^"+chunks), w("accum_bias", "2^"+accum), w("sample_budget", "2^"+budget), w("log2_messages", "2^"+fixed(math.Round(f.Log2Messages), 0))),
		expect("ITB.md", `at most `+num+` ≈ `+p2d+` chunks of 168 bits across a ≈ `+p2d+` mask space`,
			w("max_chunks168", comma(f.MaxChunks168)), w("log2_chunks168", "2^"+chunks168), w("log2_AB168", "2^"+log2AB168)),
		expect("ITB.md", `^- .A₁₆₈ = C\(168, 56\) = `+num+`. \(.log₂ ≈ `+dec+`.\) — choices for the 56 bit positions routed to lane 0`,
			w("A168", commaBig(f.A168)), w("log2_A168", log2A168)),
		expect("ITB.md", `^- .B₁₆₈ = C\(112, 56\) = `+num+`. \(.log₂ ≈ `+dec+`.\) — choices for the 56 bit positions routed to lane 1`,
			w("B168", commaBig(f.B168)), w("log2_B168", log2B168)),
		expect("ITB.md", `^- .\|Ω_chunk,168\| = A₁₆₈ · B₁₆₈ = `+num+`. \(.log₂ ≈ `+dec+`., .≈ `+p2d+`.\)\.$`,
			w("AB168", commaBig(f.AB168)), w("log2_AB168_bare", log2AB168), w("log2_AB168", "2^"+log2AB168)),
		expect("ITB.md", `^- \*\*Preimages per mask triple:\*\* .⌊2\^512 / \(A₁₆₈ · B₁₆₈\)⌋ = `+num+` ≈ `+p2d+`.\.$`,
			w("preimages168", commaBig(f.Preimages168)), w("log2_preimages168", "2^"+log2Pre168)),
		expect("ITB.md", `For a typical balanced 168-bit crib, .≈ `+p2d+`. \(.≈ `+p2+`.\) distinct mask triples out of .≈ `+p2d+`. remain algebraically compatible`,
			w("masks_per_crib168", crib168), w("masks_per_crib168_floor", crib168Floor), w("log2_AB168", "2^"+log2AB168)),
		expect("ITB.md", `^- .gcd\(A₁₆₈, B₁₆₈\) = gcd\(C\(168, 56\), C\(112, 56\)\) = `+num+` = (.+?). \(.log₂ ≈ `+dec+`., .1 / gcd ≈ ([\d.]+ × 10⁻..).\)\.$`,
			w("gcd168", gcd168Comma), w("gcd168_factors", f.GCD168Factors), w("log2_gcd168", log2GCD168), w("inv_gcd168", sci(invGCD168, 1))),
		expect("ITB.md", `restricting reachable masks to .1 / `+num+` ≈ ([\d.]+ × 10⁻..). of the space and destroying .log₂ gcd ≈ `+dec+`. bits of entropy.*Cartesian space \(.≈ `+p2d+`.\)\.$`,
			w("gcd168", gcd168Comma), w("inv_gcd168", sci(invGCD168, 1)), w("log2_gcd168", log2GCD168), w("log2_AB168", "2^"+log2AB168)),
		expect("ITB.md", `^- \*\*Per-chunk bias:\*\* .≈ (2\^-\d+\.\d).\.$`,
			w("bias168", "2^"+bias168)),
		expect("ITB.md", `^- \*\*Maximum chunks in a 64 MiB message:\*\* .`+num+`. \(.≈ `+p2d+`.\)\.$`,
			w("max_chunks168", comma(f.MaxChunks168)), w("log2_chunks168", "2^"+chunks168)),
		expect("ITB.md", `^- \*\*Accumulated bias across a maximum 64 MiB message:\*\* .≈ (2\^-\d+\.\d).\.$`,
			w("accum_bias168", "2^"+accum168)),
		expect("ITB.md", `^- \*\*Statistical distinguisher sample budget \(.1 / ε².\):\*\* .≈ `+p2d+`. chunk samples \(.~`+p2+`. maximum-size 64 MiB messages\)\.$`,
			w("sample_budget168", "2^"+budget168), w("log2_messages168", msgs168)),
		expect("ITB.md", `^\| \*\*Choice count A \(m0\)\*\* \| C\(48, 16\) = `+num+` \(log₂ ≈ `+dec+`\) \| C\(168, 56\) ≈ ([\d.]+ × 10..) \(log₂ ≈ `+dec+`\) \|$`,
			w("A", commaBig(f.A)), w("log2_A", fixed(f.Log2A, 2)), w("A168_sci", sci(math.Exp2(f.Log2A168), 2)), w("log2_A168", log2A168)),
		expect("ITB.md", `^\| \*\*Choice count B \(m1\)\*\* \| C\(32, 16\) = `+num+` \(log₂ ≈ `+dec+`\) \| C\(112, 56\) ≈ ([\d.]+ × 10..) \(log₂ ≈ `+dec+`\) \|$`,
			w("B", commaBig(f.B)), w("log2_B", fixed(f.Log2B, 2)), w("B168_sci", sci(math.Exp2(f.Log2B168), 2)), w("log2_B168", log2B168)),
		expect("ITB.md", `^\| \*\*Mask space \\\|Ω_chunk\\\| = A · B\*\* \| ≈ `+p2d+` \| ≈ `+p2d,
			w("log2_AB", "2^"+log2AB), w("log2_AB168", "2^"+log2AB168)),
		expect("ITB.md", `^\| \*\*Anti-collapse gcd\(A, B\)\*\* \| `+num+` \(log₂ ≈ `+dec+`, 1/gcd ≈ ([\d.]+ × 10⁻.)\) \| `+num+` \(log₂ ≈ `+dec+`, 1/gcd ≈ ([\d.]+ × 10⁻..)\) \|$`,
			w("gcd", comma(gcd)), w("log2_gcd", fixed(f.Log2GCD, 2)), w("inv_gcd", sci(invGCD, 1)),
			w("gcd168", gcd168Comma), w("log2_gcd168", log2GCD168), w("inv_gcd168", sci(invGCD168, 1))),
		expect("ITB.md", `^\| \*\*Preimages per mask triple\*\* \| ⌊2\^128 / \(A · B\)⌋ ≈ `+p2d+` \| ⌊2\^512 / \(A₁₆₈ · B₁₆₈\)⌋ ≈ `+p2d+` \|$`,
			w("log2_preimages", "2^"+log2Pre), w("log2_preimages168", "2^"+log2Pre168)),
		expect("ITB.md", `^\| \*\*Compatible masks per crib chunk\*\* \| ≈ `+p2d+` \(≈ `+p2+`\) \| ≈ `+p2d+` \(≈ `+p2+`\) \|$`,
			w("masks_per_crib", crib48), w("masks_per_crib_floor", crib48Floor), w("masks_per_crib168", crib168), w("masks_per_crib168_floor", crib168Floor)),
		expect("ITB.md", `^\| \*\*Per-chunk bias\*\* \| ≈ (2\^-\d+\.\d) \| ≈ (2\^-\d+\.\d) \|$`,
			w("bias", "2^"+bias), w("bias168", "2^"+bias168)),
		expect("ITB.md", `^\| \*\*Max chunks in 64 MiB message\*\* \| `+num+` \(≈ `+p2d+`\) \| `+num+` \(≈ `+p2d+`\) \|$`,
			w("max_chunks", comma(f.MaxChunks)), w("log2_chunks", "2^"+chunks), w("max_chunks168", comma(f.MaxChunks168)), w("log2_chunks168", "2^"+chunks168)),
		expect("ITB.md", `^\| \*\*Accumulated bias \(64 MiB\)\*\* \| ≈ (2\^-\d+\.\d) \| ≈ (2\^-\d+\.\d) \|$`,
			w("accum_bias", "2^"+accum), w("accum_bias168", "2^"+accum168)),
		expect("ITB.md", `^\| \*\*Distinguisher sample budget \(1/ε²\)\*\* \| ~`+p2d+` chunks \(~`+p2+` max messages\) \| ≈ `+p2d+` chunks \(~`+p2+` max messages;`,
			w("sample_budget", "2^"+budget), w("log2_messages", "2^"+fixed(math.Round(f.Log2Messages), 0)),
			w("sample_budget168", "2^"+budget168), w("log2_messages168", msgs168)),
		expect("ITB.md", "requires `2\\^\\(62·P\\)` attempts \\(≈ "+p2+" for 1024-bit keys\\)", w("config_m1", pow2(configMap(a.P)))),
		expect("ITB.md", `^\| Min container \(\*\*Mode 1\*\*, payload ≤ ~`+dec+` KB, 1024-bit key\) \| `+num+` \|`, w("m1_max_payload_kb", kb(a.MaxPayload)), w("m1_P", plain(a.P))),
		expect("ITB.md", `^\| Min container \(\*\*Mode 2\*\*, payload ≤ ~`+dec+` KB, 1024-bit key\) \| `+num+` \|`, w("m2_max_payload_kb", kb(b.MaxPayload)), w("m2_P", plain(b.P))),
		expect("ITB.md", `^\| 4 MB \| `+num+` \|`, w("P_4MiB", comma(s4m.P))),
		expect("ITB.md", `^\| 16 MB \| `+num+` \|`, w("P_16MiB", comma(s16m.P))),
		expect("ITB.md", `^\| 64 MB \| `+num+` \|`, w("P_64MiB", comma(s64m.P))),
		expect("ITB.md", `Estimates assume a 1024-bit key \(.*, `+num+` sequential ChainHash rounds per pixel\)`, w("chain_rounds_1024_w128", plain(chainRounds(1024)))),
	)

	// ----- README.md --------------------------------------------------
	add(wireOffsets("README.md", f, `Prefix`)...)
	add(
		expect("README.md", `^Default nonce size is `+num+` bits \(`+num+` bytes\)`, w("nonce_bits", plain(f.NonceBits)), w("nonce_bytes", plain(f.NonceBytes))),
		expect("README.md", `^- \*\*Mode 1: Per-Region \(default\)\.\*\* Each of the three regions independently reaches the ambiguity floor \(`+num+` pixels for 1024-bit keys\)\. Total container pixels equal .3 × per-region floor. \(`+num+` pixels for 1024-bit keys\), rounded up to the smallest square by side length plus the DRBG barrier margin \(.DefaultBarrierFill = `+num+`.\): .⌈√`+num+`⌉ = `+num+` → \(`+num+` \+ 1\)² = `+num+` × `+num+` = `+num+`. pixels \(~`+dec+` KB ciphertext\)\.$`,
			w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("barrier_fill", plain(f.BarrierFill)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_raw_square", plain(a.RawSquare)), w("m1_raw_square", plain(a.RawSquare)),
			w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)), w("m1_wire_kb", kb(a.Wire))),
		expect("README.md", `^- \*\*Mode 2: Per-Container \(compact VPN tunnel mode\)\.\*\* The ambiguity floor is evaluated jointly across the whole container \(`+num+` pixels for 1024-bit keys\)\. Container dimensions round up to the smallest square plus the barrier margin: .⌈√`+num+`⌉ = `+num+` → `+num+` × `+num+` = `+num+`. raw square floor \(`+num+` → `+num+`\), which with barrier fill becomes .\(`+num+` \+ 1\)² = `+num+` × `+num+` = `+num+`. pixels \(~`+dec+` KB ciphertext\)\.`,
			w("minpixels_1024", plain(mp)), w("minpixels_1024", plain(mp)), w("m2_raw_square", plain(b.RawSquare)), w("m2_raw_square", plain(b.RawSquare)), w("m2_raw_square", plain(b.RawSquare)), w("m2_raw_square_P", plain(b.RawSquare*b.RawSquare)),
			w("minpixels_1024", plain(mp)), w("m2_raw_square_P", plain(b.RawSquare*b.RawSquare)), w("m2_raw_square", plain(b.RawSquare)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)), w("m2_wire_kb", kb(b.Wire))),
	)
	for _, k := range keySizes {
		add(expect("README.md", fmt.Sprintf(`^\| %d bits\s+\| `, k)+num+` px \| `+num+x+num+` = `+num+` px\s+\| ~`+dec+` KB \| `+num+x+num+` = `+num+` px \| ~`+dec+` KB \|$`,
			w(fmt.Sprintf("minpixels_%d", k), plain(f.MinPixels[k])),
			w(fmt.Sprintf("m1_side_%d", k), plain(m1[k].Side)), w(fmt.Sprintf("m1_side_%d", k), plain(m1[k].Side)), w(fmt.Sprintf("m1_P_%d", k), plain(m1[k].P)), w(fmt.Sprintf("m1_wire_kb_%d", k), kb(m1[k].Wire)),
			w(fmt.Sprintf("m2_side_%d", k), plain(m2[k].Side)), w(fmt.Sprintf("m2_side_%d", k), plain(m2[k].Side)), w(fmt.Sprintf("m2_P_%d", k), plain(m2[k].P)), w(fmt.Sprintf("m2_wire_kb_%d", k), kb(m2[k].Wire))))
	}
	ex := func(wire, n int, d int) string {
		if !floorFits2500 {
			return "divergent"
		}
		v := float64(wire) / float64(n)
		if d == 0 {
			v = math.Round(v)
		}
		return fixed(v, d)
	}
	add(
		expect("README.md", "The on-wire header `\\[main_nonce\\]\\[W\\]\\[H\\]` following the "+num+"-byte prefix", w("prefix", plain(f.Prefix))),
		expect("README.md", `^\| Storage overhead \| ~`+dec+`-`+dec+`× from ~10 KB to 64 MiB at 1024-bit keys \(~`+num+`-`+num+`× \*\*Mode 1\*\* / ~`+dec+`-`+num+`× \*\*Mode 2\*\* for 0\.5-2\.5 KB payloads\) \|$`,
			w("expansion_min_10KB_64MiB", expansionMin), w("expansion_max_10KB_64MiB", fixed(f.ExpansionMax, 2)),
			w("expansion_m1_2500B", ex(a.Wire, 2500, 0)), w("expansion_m1_500B", ex(a.Wire, 500, 0)),
			w("expansion_m2_2500B", ex(b.Wire, 2500, 1)), w("expansion_m2_500B", ex(b.Wire, 500, 0))),
		expect("README.md", `^\| Key space \| Up to `+p2+` \|$`, w("max_key_space", pow2(itb.MaxKeyBits))),
		expect("README.md", `^\| \*\*Desynchronized Interlocked Barrier\*\* \| \*\*Layer I\*\* \(0x05 on startSeed1\.\.3\) dynamic K_r sub-region trajectories \(≈ `+p2d+` \*\*Mode 2\*\* / ≈ `+p2d+` \*\*Mode 1\*\* at K_r = 8 on 1024-bit ITB floors\) \+ \*\*Layer II\*\* \(0x06 on lockSeed\) cross-lane slot desynchronization \(β_0 ≠ β_1, \\\|Ω_chunk\\\| · M\^3 ≈ `+p2d+`–`+p2d+` in 48-bit and ≈ `+p2d+`–`+p2d+` in 168-bit, or ≈ `+p2d+`–`+p2d+` and ≈ `+p2d+`–`+p2d+` with 4 B fold at 1024-bit ITB floors\); 0 B wire overhead \| Stable \|$`,
			w("desync_traj_mode2_k8", "2^166.98"), w("desync_traj_mode1_k8", "2^224.04"),
			w("desync_lane48_mode2", "2^96.91"), w("desync_lane48_mode1", "2^101.53"),
			w("desync_lane168_mode2", "2^279.89"), w("desync_lane168_mode1", "2^284.51"),
			w("desync_lane48_fold_mode2", "2^128.91"), w("desync_lane48_fold_mode1", "2^133.53"),
			w("desync_lane168_fold_mode2", "2^311.89"), w("desync_lane168_fold_mode1", "2^316.51")),
		expect("README.md", `^\| \*\*Rank Barrier \(168-bit Interlock\)\*\* \| 21-byte chunk → 3 × 56-bit lanes; C\(168,56\)·C\(112,56\) ≈ `+p2d+` mask space; bias ≈ (2\^-\d+\.\d);`,
			w("log2_AB168", "2^"+log2AB168), w("bias168", "2^"+bias168)),
		expect("README.md", `^\| \*\*Rank Barrier \(48-bit Interlock, default\)\*\* \| 6-byte chunk → 3 × 16-bit lanes; C\(48,16\)·C\(32,16\) ≈ `+p2d+` mask space; bias ≈ (2\^-\d+\.\d);`,
			w("log2_AB", "2^"+log2AB), w("bias", "2^"+bias)),
		expect("README.md", `^\| Rank Barrier \| Per-chunk 48-bit keyed permutation over three regions \(C\(48, 16\) · C\(32, 16\) ≈ `+p2d+` balanced partitions, bias ≈ (2\^-\d+\.\d)\), or optional 168-bit permutation for 512-bit primitives \(C\(168, 56\) · C\(112, 56\) ≈ `+p2d+` balanced partitions, bias ≈ (2\^-\d+\.\d)\) \|$`,
			w("log2_AB", "2^"+log2AB), w("bias", "2^"+bias), w("log2_AB168", "2^"+log2AB168), w("bias168", "2^"+bias168)),
		expect("README.md", `^\| Pixel Barrier \| `+num+`-channel RGBWYOPA pixels \(`+num+` data bits \+ `+num+` noise bits per pixel across `+num+` channels, with per-pixel `+num+`-bit XOR masking, secret `+num+`-way bit rotation yielding 7\^P CCA-surviving configurations, and CSPRNG-seeded DRBG noise; \*\*Mode 1\*\* per-region and \*\*Mode 2\*\* per-container ambiguity floors\) \|$`,
			w("channels", plain(itb.Channels)), w("data_bits_per_pixel", plain(itb.DataBitsPerPixel)), w("noise_bits_per_pixel", plain(itb.Channels)),
			w("channels", plain(itb.Channels)), w("data_bits_per_pixel", plain(itb.DataBitsPerPixel)), w("rotation_way", plain(itb.DataBitsPerChannel))),
		expect("README.md", `The partition constants are .A₁₆₈ = C\(168, 56\) = `+num+`. \(.log₂ ≈ `+dec+`.\) and .B₁₆₈ = C\(112, 56\) = `+num+`. \(.log₂ ≈ `+dec+`.\), yielding a per-chunk mask space of .\|Ω_chunk,168\| = A₁₆₈ · B₁₆₈ = `+num+` ≈ `+p2d+`. balanced partitions\. With .⌊2\^512 / \(A₁₆₈ · B₁₆₈\)⌋ ≈ `+p2d+`. preimages per mask triple, the per-chunk bias is .≈ (2\^-\d+\.\d). \(.≈ (2\^-\d+\.\d). accumulated across a maximum 64 MiB message of .`+num+` ≈ `+p2d+`. chunks, requiring .1 / ε² ≈ `+p2d+`. chunk samples or .~`+p2+`. maximum-size messages for a statistical distinguisher\), and a single 168-bit \(21-byte\) crib leaves .≈ `+p2d+`. \(.≈ `+p2+`.\) compatible mask triples\.`,
			w("A168", commaBig(f.A168)), w("log2_A168", log2A168), w("B168", commaBig(f.B168)), w("log2_B168", log2B168),
			w("AB168", commaBig(f.AB168)), w("log2_AB168", "2^"+log2AB168), w("log2_preimages168", "2^"+log2Pre168),
			w("bias168", "2^"+bias168), w("accum_bias168", "2^"+accum168), w("max_chunks168", comma(f.MaxChunks168)), w("log2_chunks168", "2^"+chunks168),
			w("sample_budget168", "2^"+budget168), w("log2_messages168", msgs168), w("masks_per_crib168", crib168), w("masks_per_crib168_floor", crib168Floor)),
		expect("README.md", `deterministic two-step divmod unranking prevents the gcd\(A, B\) = `+num+` anti-collapse trap`, w("gcd", comma(gcd))),
		expect("README.md", `512-bit divmod unranking prevents the .gcd\(A₁₆₈, B₁₆₈\) = gcd\(C\(168, 56\), C\(112, 56\)\) = `+num+` = (.+?). trap, .log₂ ≈ `+dec+`., .1 / gcd ≈ ([\d.]+ × 10⁻..).\) without rejection sampling`,
			w("gcd168", gcd168Comma), w("gcd168_factors", f.GCD168Factors), w("log2_gcd168", log2GCD168), w("inv_gcd168", sci(invGCD168, 1))),
		expect("README.md", `^    ChunkSize: 1 << 20,\s+// 1 MiB \(default `+num+` MiB per profile\)`, w("default_chunk_mib", plain(f.DefaultChunkSize>>20))),
		expect("README.md", "default `itb.DefaultChunkSize` = "+num+" MiB", w("default_chunk_mib", plain(f.DefaultChunkSize>>20))),
		expect("KERNELS.md", `\|Ω_chunk,168\| = C\(168, 56\) · C\(112, 56\) ≈ `+p2d,
			w("log2_AB168", "2^"+log2AB168)),
		expect("HWTHREATS.md", `independent ≈ `+p2d+` \(48-bit mode, 6-byte chunks\) or ≈ `+p2d+` \(168-bit mode, 21-byte chunks\)`,
			w("log2_AB", "2^"+log2AB), w("log2_AB168", "2^"+log2AB168)),
	)

	// ----- FAQ.md -----------------------------------------------------
	add(
		sweep("FAQ.md", `512-byte plaintext, `+num+`×`+num+` = `+num+`-pixel container`,
			w("m1_side_512", plain(m1[512].Side)), w("m1_side_512", plain(m1[512].Side)), w("m1_P_512", plain(m1[512].P))),
		expect("FAQ.md", `512-byte plaintext, `+num+`×`+num+` container`,
			w("m1_side_512", plain(m1[512].Side)), w("m1_side_512", plain(m1[512].Side))),
		expect("FAQ.md", `draw from .C\(48, 16\) · C\(32, 16\) ≈ `+p2d+`. mask triples`,
			w("log2_AB", "2^"+log2AB)),
		expect("FAQ.md", `with .B = C\(32, 16\) = `+num+`. and .A = C\(48, 16\) = `+num+`.\).*avoid the .gcd\(A, B\) = `+num+`. CRT reduction trap`,
			w("B", commaBig(f.B)), w("A", commaBig(f.A)), w("gcd", comma(gcd))),
		expect("FAQ.md", `maps onto .Ω_chunk = A · B ≈ `+p2d+`. mask triples`,
			w("log2_AB", "2^"+log2AB)),
		expect("FAQ.md", `leave .≈ `+p2+`. compatible mask triples out of .`+p2d+`.`,
			w("masks_per_crib", "2^"+fixed(math.Floor(f.Log2AB-48), 0)), w("log2_AB", "2^"+log2AB)),
	)

	// ----- REDTEAM.md -------------------------------------------------
	add(
		expect("REDTEAM.md", `^\| Partition constants A = C\(48,16\), B = C\(32,16\) \| `+num+` · `+num+` \|$`, w("A", commaBig(f.A)), w("B", commaBig(f.B))),
		expect("REDTEAM.md", `^\| gcd\(A, B\) anti-collapse trap \| \*\*`+num+`\*\* = (.+) \|$`, w("gcd", comma(gcd)), w("gcd_factors", f.GCDFactors)),
		expect("REDTEAM.md", `^\| Per-chunk bias \| ≈ \*\*(2\^-\d+\.\d)\*\* \|$`, w("bias", "2^"+bias)),
		expect("REDTEAM.md", `^\| Per-message accumulated bias \| ≈ \*\*(2\^-\d+\.\d)\*\* \|$`, w("accum_bias", "2^"+accum)),
		expect("REDTEAM.md", `^\| Distinguisher sample budget \| ≈ \*\*(2\^\d+\.\d)\*\* chunks`, w("sample_budget", "2^"+budget)),
		expect("REDTEAM.md", `Derivation of the cascade .(2\^\d+\.\d+) → (2\^\d+\.\d+) → (2\^-\d+\.\d) → (2\^-\d+\.\d) → (2\^\d+\.\d).`,
			w("log2_AB", "2^"+log2AB), w("log2_preimages", "2^"+log2Pre), w("bias", "2^"+bias), w("accum_bias", "2^"+accum), w("sample_budget", "2^"+budget)),
		expect("REDTEAM.md", `from the interlock-nonce fragments \(`+num+` bytes at .NonceBits. `+num+`\)`, w("nonce_bytes", plain(f.NonceBytes)), w("nonce_bits", plain(f.NonceBits))),
		expect("REDTEAM.md", `the fraction landing on .idx0 ≡ idx1 \(mod `+num+`\). is .* consistent with the full-space expectation 1/`+num+` ≈ ([\d.]+ × 10⁻.) \(≈ `+dec+` draws\)`,
			w("gcd", plain(gcd)), w("gcd", plain(gcd)), w("inv_gcd_3", sci(invGCD, 3)), w("expected_draws_500k", fixed(500000*invGCD, 1))),
	)

	// ----- HARNESS.md -------------------------------------------------
	add(
		expect("HARNESS.md", `^  .idx0 ≡ idx1 \(mod `+num+`\). is .* at N = 500 000`, w("gcd", plain(gcd))),
		expect("HARNESS.md", `with the full-space expectation .1/`+num+` ≈ ([\d.]+ × 10⁻.). \(≈ `+dec+` draws\)`,
			w("gcd", plain(gcd)), w("inv_gcd_2", sci(invGCD, 2)), w("expected_draws_500k", fixed(500000*invGCD, 1))),
		sweep("HARNESS.md", `shapes \(?`+num+` / `+num+` / `+num+` B\b`, w("header_128", plain(f.HeaderSizes[128])), w("header_256", plain(f.HeaderSizes[256])), w("header_512", plain(f.HeaderSizes[512]))),
		expect("HARNESS.md", `r = `+num+` / `+num+` / `+num+` are the shipped cascade depths at 512 / 1024 / 2048-bit keys`,
			w("chain_rounds_512_w128", plain(chainRounds(512))), w("chain_rounds_1024_w128", plain(chainRounds(1024))), w("chain_rounds_2048_w128", plain(chainRounds(2048)))),
	)

	// ----- package documentation --------------------------------------
	add(
		expect("hashes/CONSTRUCTIONS.md", `per-pixel buffer widths \(`+num+` / `+num+` / `+num+` bytes = `+num+` / `+num+` / `+num+`-byte shapes\)`,
			w("header_128", plain(f.HeaderSizes[128])), w("header_256", plain(f.HeaderSizes[256])), w("header_512", plain(f.HeaderSizes[512])),
			w("header_128", plain(f.HeaderSizes[128])), w("header_256", plain(f.HeaderSizes[256])), w("header_512", plain(f.HeaderSizes[512]))),
		expect("hashes/CONSTRUCTIONS.md", `ITB feeds `+num+`- / `+num+`- / `+num+`-byte buffers per pixel`,
			w("header_128", plain(f.HeaderSizes[128])), w("header_256", plain(f.HeaderSizes[256])), w("header_512", plain(f.HeaderSizes[512]))),
		expect("hashes/CONSTRUCTIONS.md", `every byte of a `+num+`-byte input affects the digest output`, w("header_512", plain(f.HeaderSizes[512]))),
		expect("wrapper/README.md", `\(`+num+` bytes for PRF-counter / AES-CTR vs `+num+` bytes for ChaCha20\)`,
			w("wrapper_nonce_prf", plain(f.WrapperNonce[hashes.CipherAES128CTR])), w("wrapper_nonce_chacha20", plain(f.WrapperNonce[hashes.CipherChaCha20]))),
		expect("parallax/README.md", "initialised to `DefaultChunkSize` \\("+num+" MiB\\) to mirror ITB's `DefaultChunkSize`", w("default_chunk_mib", plain(f.DefaultChunkSize>>20))),
		expect("triple/doc.go", `for non-parallax messages under `+num+` MiB`, w("max_message_mib", plain(f.MaxMessage>>20))),
		expect("doc.go", `^// `+dec+`× overhead\.`, w("noise_overhead", fixed(float64(itb.Channels)/float64(itb.DataBitsPerChannel), 2))),
	)

	// ----- added coverage ---------------------------------------------
	ccaLeak := fixed(100*float64(itb.NoiseConfigBits)/float64(itb.NoiseConfigBits+itb.DataConfigBits), 1)
	add(
		expect("SCIENCE.md", "^- \\*\\*Without CCA \\(Core ITB / Silent Drop\\): `P_threshold = ⌈k / log₂ 56⌉ ≈ ⌈k / "+dec+"⌉`", w("log2_56", fixed(math.Log2(56), 3))),
		expect("SCIENCE.md", "Only noise-bit flips produce «accept» — uniform "+dec+" % across all pixels", w("noise_bits_pct", fixed(100.0/itb.Channels, 1))),
		// Landauer derivation (SCIENCE.md § 4) and its restatements.
		expect("SCIENCE.md", "erasing one bit costs `k_B T ln 2 ≈ ([\\d.]+ × 10⁻..) J`, so a mass-energy budget of ~4 × 10⁶⁹ J bounds irreversible operations at ~10([⁰¹²³⁴⁵⁶⁷⁸⁹]+) ≈ "+p2,
			w("landauer_bit_cost", sci(landauerBitCost, 1)), w("landauer_ten_exp", superscript(tenExp)), w("landauer", pow2(landauerExp))),
		sweep("SCIENCE.md", `Landauer bound on irreversible enumeration cost \(~`+p2+` ≈ 10([⁰¹²³⁴⁵⁶⁷⁸⁹]+)\)`, w("landauer", pow2(landauerExp)), w("landauer_ten_exp", superscript(tenExp))),
		expect("PROOFS.md", `Landauer bound on irreversible enumeration cost \(~`+p2+` ≈ 10([⁰¹²³⁴⁵⁶⁷⁸⁹]+)\)`, w("landauer", pow2(landauerExp)), w("landauer_ten_exp", superscript(tenExp))),
		// ChainHash cascade depth: Pixel Barrier keyBits / width,
		// Rank Barrier 1 + keyBits / width (ITB.md § 12).
		expect("SCIENCE.md", "^   - \\*\\*Pixel Barrier:\\*\\* depth `r = keyBits / width` \\("+num+" / "+num+" / "+num+" rounds at width "+num+" for 512 / 1024 / 2048-bit keys\\)",
			w("depth_512_w128", depthAt(512, narrowestWidth)), w("depth_1024_w128", depthAt(1024, narrowestWidth)), w("depth_2048_w128", depthAt(2048, narrowestWidth)), w("narrowest_width", plain(narrowestWidth))),
		expect("ITB.md", "Pixel Barrier operates directly over session components at depth `r = keyBits / width` \\("+num+" / "+num+" / "+num+" rounds at width 128 for 512 / 1024 / 2048-bit keys; "+num+" / "+num+" / "+num+" at width 256; "+num+" / "+num+" / "+num+" at width 512\\), without an intermediate key\\. The (?:Interlocked|Rank) Barrier operates at depth `r = 1 \\+ keyBits / width` \\("+num+" / "+num+" / "+num+" rounds at width 128; "+num+" / "+num+" / "+num+" at width 256; "+num+" / "+num+" / "+num+" at width 512\\)",
			depthWants()...),
		expect("README.md", "a 2048-bit key folds into "+num+" rounds at 128-bit, "+num+" rounds at 256-bit, or "+num+" rounds at 512-bit",
			w("depth_2048_w128", depthAt(2048, 128)), w("depth_2048_w256", depthAt(2048, 256)), w("depth_2048_w512", depthAt(2048, 512))),
		expect("doc.go", `^// width\): 2048-bit key at 128-bit width is `+num+` rounds, 2048-bit at$`, w("depth_2048_w128", depthAt(2048, 128))),
		expect("doc.go", `^// 512-bit width is `+num+` rounds\.`, w("depth_2048_w512", depthAt(2048, 512))),
		// CCA configuration leak, birthday bound and stream prefix restated.
		expect("ITB.md", `^CCA leaks (\d+)/(\d+) ≈ `+dec+` % of per-pixel configuration`,
			w("noise_config_bits", plain(itb.NoiseConfigBits)), w("config_bits", plain(itb.NoiseConfigBits+itb.DataConfigBits)), w("cca_leak_pct", ccaLeak)),
		expect("SECURITY.md", `^### Practical Value of `+dec+` % CCA Leak$`, w("cca_leak_pct", ccaLeak)),
		expect("ITB.md", `^At the default `+num+`-bit width, birthday collision on either slot requires ~`+p2+` messages`,
			w("nonce_bits", plain(f.NonceBits)), w("birthday_default", pow2(f.NonceBits/2))),
		expect("ITB.md", `^\*\*Decryption\.\*\* After the `+num+`-byte prefix`, w("prefix", plain(f.Prefix))),
		expect("doc.go", `^// behind its own `+num+`-byte prefix, so every record has the shape of a$`, w("prefix", plain(f.Prefix))),
		expect("doc.go", `^// chunk records, each a `+num+`-byte prefix followed by one chunk laid out$`, w("prefix", plain(f.Prefix))),
	)

	// ----- repeated constants, swept per file -------------------------
	// The leading digit in these patterns separates the two mask-space
	// exponents that share one spelling; a drift past that digit reports
	// NOT FOUND, which fails the check as a STALE figure would.
	add(
		// ----- POSTQUANTUM.md -----------------------------------------
		expect("POSTQUANTUM.md", `conservative Grover work factor is .√P × 2\^keyBits. \(~`+p2+` at 1024-bit keys for \*\*Mode 2\*\* P = `+num+` and theoretical floor P = `+num+`; ~`+p2+` at \*\*Mode 1\*\* P = `+num+`\)`,
			w("grover2_m2", bG1), w("m2_P", plain(b.P)), w("theo_P", plain(t.P)), w("grover2_m1", aG1), w("m1_P", plain(a.P))),
		expect("POSTQUANTUM.md", `giving a conservative Grover work factor of .√P × 2\^\(keyBits/2\). \(~`+p2+` at 1024-bit keys for \*\*Mode 2\*\* P = `+num+` and P = `+num+`; ~`+p2+` at \*\*Mode 1\*\* P = `+num+`\)`,
			w("grover1_m2", bG2), w("m2_P", plain(b.P)), w("theo_P", plain(t.P)), w("grover1_m1", aG2), w("m1_P", plain(a.P))),
		expect("POSTQUANTUM.md", `^\| Core ITB \(No MAC\) \| .* \| ~`+p2+` \| ~`+p2+` \|`,
			w("grover2_m2", bG1), w("grover2_m1", aG1)),
		expect("POSTQUANTUM.md", `^\| MAC \+ Silent Drop \[1\] \| .* \| ~`+p2+` \| ~`+p2+` \|`,
			w("grover2_m2", bG1), w("grover2_m1", aG1)),
		expect("POSTQUANTUM.md", `^\| MAC \+ Reveal \[2\] \| .* \| ~`+p2+` \| ~`+p2+` \|`,
			w("grover1_m2", bG2), w("grover1_m1", aG2)),
		expect("POSTQUANTUM.md", `^\|Ω_chunk\| = A · B = `+num+`\s+≈\s+`+p2d+`$`,
			w("AB", commaBig(f.AB)), w("log2_AB", "2^"+log2AB)),
		expect("POSTQUANTUM.md", `^\|Ω_chunk,168\| = A₁₆₈ · B₁₆₈ = `+num+`\s+≈\s+`+p2d+`$`,
			w("AB168", commaBig(f.AB168)), w("log2_AB168", "2^"+log2AB168)),
		expect("POSTQUANTUM.md", `.⌊2\^128 / \(A · B\)⌋ = `+num+` ≈ `+p2d+`. distinct 128-bit PRF output preimages`,
			w("preimages", commaBig(f.Preimages)), w("log2_preimages", "2^"+log2Pre)),
		expect("POSTQUANTUM.md", `.⌊2\^512 / \(A₁₆₈ · B₁₆₈\)⌋ = `+num+` ≈ `+p2d+`. distinct 512-bit PRF output preimages`,
			w("preimages168", commaBig(f.Preimages168)), w("log2_preimages168", "2^"+log2Pre168)),
		expect("POSTQUANTUM.md", `^\- \*\*Mode 1 \(`+"`"+num+x+num+"`"+`, `+"`P = "+num+"`"+`\):\*\* Noise barrier `+"`2\\^\\(8P\\) = "+p2+"`"+`; encoding ambiguity `+"`56\\^P ≈ "+p2+"`"+` \(without CCA\) and `+"`7\\^P ≈ "+p2+"`"+` \(under CCA\); configuration space `+"`2\\^\\(62P\\) = "+p2+"`"+`\.$`,
			w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)),
			w("noise_m1", pow2(noiseBarrier(a.P))), w("nocca_m1", pow2(nocca(a.P))), w("cca_m1", pow2(cca(a.P))), w("config_m1", pow2(configMap(a.P)))),
		expect("POSTQUANTUM.md", `^\- \*\*Mode 2 \(`+"`"+num+x+num+"`"+`, `+"`P = "+num+"`"+`\):\*\* Noise barrier `+"`2\\^\\(8P\\) = "+p2+"`"+`; encoding ambiguity `+"`56\\^P ≈ "+p2+"`"+` \(without CCA\) and `+"`7\\^P ≈ "+p2+"`"+` \(under CCA\); configuration space `+"`2\\^\\(62P\\) = "+p2+"`"+`\.$`,
			w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)),
			w("noise_m2", pow2(noiseBarrier(b.P))), w("nocca_m2", pow2(nocca(b.P))), w("cca_m2", pow2(cca(b.P))), w("config_m2", pow2(configMap(b.P)))),
		expect("POSTQUANTUM.md", `^\- \*\*Theoretical single-region floor \(`+"`"+num+x+num+"`"+`, `+"`P = "+num+"`"+`\):\*\* Noise barrier `+"`2\\^\\(8P\\) = "+p2+"`"+`; encoding ambiguity `+"`56\\^P ≈ "+p2+"`"+` \(without CCA\) and `+"`7\\^P ≈ "+p2+"`"+` \(under CCA\); configuration space `+"`2\\^\\(62P\\) = "+p2+"`"+`\.$`,
			w("theo_side", plain(t.Side)), w("theo_side", plain(t.Side)), w("theo_P", plain(t.P)),
			w("noise_theo", pow2(noiseBarrier(t.P))), w("nocca_theo", pow2(nocca(t.P))), w("cca_theo", pow2(cca(t.P))), w("config_theo", pow2(configMap(t.P)))),
		expect("POSTQUANTUM.md", `queries across .P = `+num+`. pixels vs\. .8P = `+num+`. exhaustive.*This leaks `+num+` bits per pixel \(`+dec+` % of the `+num+`-bit per-pixel configuration\)`,
			w("m1_P", plain(a.P)), w("noise_m1_exp", plain(noiseBarrier(a.P))),
			w("noise_config_bits", plain(itb.NoiseConfigBits)), w("cca_leak_pct", ccaLeak), w("config_bits", plain(itb.NoiseConfigBits+itb.DataConfigBits))),
		expect("POSTQUANTUM.md", `^\| Composition Mode \| .* \| 1024-bit Key \(\*\*Mode 2\*\*, P = `+num+` / Floor P = `+num+`\) \| 1024-bit Key \(\*\*Mode 1\*\*, P = `+num+`\) \|`,
			w("m2_P", plain(b.P)), w("theo_P", plain(t.P)), w("m1_P", plain(a.P))),
		expect("POSTQUANTUM.md", `\(default .DefaultNonceBits = `+num+`. bits each\)`,
			w("nonce_bits", plain(f.NonceBits))),
		expect("POSTQUANTUM.md", `.A = C\(48, 16\) = `+num+`. \(.log₂ ≈ `+dec+`.\).*and .m_1. is drawn from the .B = C\(32, 16\) = `+num+`. \(.log₂ ≈ `+dec+`.\)`,
			w("A", commaBig(f.A)), w("log2_A", fixed(f.Log2A, 2)), w("B", commaBig(f.B)), w("log2_B", fixed(f.Log2B, 2))),
		expect("POSTQUANTUM.md", `.A₁₆₈ = C\(168, 56\) = `+num+`. \(.log₂ ≈ `+dec+`.\) and .m_1. from .B₁₆₈ = C\(112, 56\) = `+num+`. \(.log₂ ≈ `+dec+`.\)`,
			w("A168", commaBig(f.A168)), w("log2_A168", log2A168), w("B168", commaBig(f.B168)), w("log2_B168", log2B168)),
		sweep("POSTQUANTUM.md", `(2\^22\.\d)\b`, w("masks_per_crib", crib48)),
		expect("POSTQUANTUM.md", `maximum 64 MiB message of .`+num+` ≈ `+p2d+`. chunks\).*chunks \(~`+p2+` maximum-size messages\) in 48-bit mode`,
			w("max_chunks", comma(f.MaxChunks)), w("log2_chunks", "2^"+chunks), w("log2_messages", "2^"+fixed(math.Round(f.Log2Messages), 0))),
		expect("POSTQUANTUM.md", `product space .\(A · B\)\^C ≈ 2\^\((\d+\.\d+) × C\). in 48-bit mode and .\(A₁₆₈ · B₁₆₈\)\^C ≈ 2\^\((\d+\.\d+) × C\). in 168-bit mode — which already exceeds .2\^512. at .C = 2. chunks \(`+num+` B, .`+p2d+` > 2\^512.\), .2\^1024. at .C = 4. chunks \(`+num+` B, .`+p2d+` > 2\^1024.\), and .2\^2048. at .C = 8. chunks \(`+num+` B, .`+p2d+` > 2\^2048.`,
			w("log2_AB", log2AB), w("log2_AB168", log2AB168),
			w("chunk168_bytes_x2", "42"), w("log2_AB168_x2", "2^"+fixed(2*f.Log2AB168, 1)),
			w("chunk168_bytes_x4", "84"), w("log2_AB168_x4", "2^"+fixed(4*f.Log2AB168, 1)),
			w("chunk168_bytes_x8", "168"), w("log2_AB168_x8", "2^"+fixed(8*f.Log2AB168, 1))),
		expect("POSTQUANTUM.md", `enforces .P ≥ MinPixels = ⌈k / log₂ 7⌉. \(`+num+`, `+num+`, `+num+` pixels for .k = 512, 1024, 2048. under CCA; vs\. .⌈k / log₂ 56⌉ = `+num+`, `+num+`, `+num+`. pixels without CCA\)`,
			w("minpixels_512", plain(f.MinPixels[512])), w("minpixels_1024", plain(mp)), w("minpixels_2048", plain(f.MinPixels[2048])),
			w("threshold_nocca_512", plain(f.ThresholdNoCCA[512])), w("threshold_nocca_1024", plain(f.ThresholdNoCCA[1024])), w("threshold_nocca_2048", plain(f.ThresholdNoCCA[2048]))),
		expect("POSTQUANTUM.md", `\(≥ `+num+` bytes at \*\*Mode 2\*\* .P = `+num+`., ≥ `+num+` bytes at \*\*Mode 1\*\* .P = `+num+`., ≥ `+num+` bytes at .P = `+num+`., \[Proof 10\]`,
			w("m2_residue", plain(b.Residue)), w("m2_P", plain(b.P)),
			w("m1_residue", plain(a.Residue)), w("m1_P", plain(a.P)),
			w("theo_residue", plain(t.Residue)), w("theo_P", plain(t.P))),
		expect("POSTQUANTUM.md", `^\| \*\*Grover Seed Search \(Full-Container Verification\)\*\* \| .* \| √P × 2\^keyBits \(Core ITB Full KPA / MAC \+ Silent Drop \[1\], ~`+p2+`–`+p2+` at 1024-bit\); √P × 2\^\(keyBits/2\) \(MAC \+ Reveal, ~`+p2+`–`+p2+` at 1024-bit\) \|$`,
			w("grover2_m2", bG1), w("grover2_m1", aG1), w("grover1_m2", bG2), w("grover1_m1", aG2)),
	)
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md", "ITB.md", "README.md", "FAQ.md", "REDTEAM.md", "HWTHREATS.md", "POSTQUANTUM.md", "doc.go"} {
		add(sweep(file, `(2\^7\d\.\d\d)`, w("log2_AB", "2^"+log2AB)))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md", "ITB.md", "FAQ.md", "REDTEAM.md", "POSTQUANTUM.md"} {
		add(sweep(file, `(2\^5\d\.\d\d)`, w("log2_preimages", "2^"+log2Pre)))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "ITB.md", "README.md", "FAQ.md", "REDTEAM.md", "POSTQUANTUM.md"} {
		add(sweep(file, `(2\^-5\d\.\d)\b`, w("bias", "2^"+bias)))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "ITB.md", "REDTEAM.md", "POSTQUANTUM.md"} {
		add(sweep(file, `(2\^-3\d\.\d)\b`, w("accum_bias", "2^"+accum)))
		add(sweep(file, `(2\^1\d\d\.\d)\b`, w("sample_budget", "2^"+budget)))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md", "POSTQUANTUM.md"} {
		add(sweep(file, `~(2\^3\d\d)\b`, w("landauer", pow2(landauerExp))))
	}
	for _, file := range []string{"SCIENCE.md", "ITB.md", "README.md", "FAQ.md", "REDTEAM.md", "SECURITY.md", "POSTQUANTUM.md"} {
		add(sweep(file, `\b(66,\d{3})\b`, w("gcd", comma(gcd))))
	}
	for _, file := range []string{"PROOFS.md", "REDTEAM.md", "HARNESS.md"} {
		add(sweep(file, `\b(66\d{3})\b`, w("gcd", plain(gcd))))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md", "ITB.md", "README.md", "REDTEAM.md", "KERNELS.md", "HWTHREATS.md", "POSTQUANTUM.md"} {
		add(sweep(file, `(2\^258\.\d\d)`, w("log2_AB168", "2^"+log2AB168)))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md", "ITB.md", "README.md", "REDTEAM.md", "POSTQUANTUM.md"} {
		add(sweep(file, `(2\^253\.\d\d)`, w("log2_preimages168", "2^"+log2Pre168)))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md", "ITB.md", "README.md", "POSTQUANTUM.md"} {
		add(sweep(file, `(2\^21\.\d\d)\b`, w("log2_chunks168", "2^"+chunks168)))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "ITB.md", "README.md", "POSTQUANTUM.md"} {
		add(sweep(file, `(2\^-253\.\d)\b`, w("bias168", "2^"+bias168)))
		add(sweep(file, `(2\^-231\.\d)\b`, w("accum_bias168", "2^"+accum168)))
		add(sweep(file, `(2\^506\.\d)\b`, w("sample_budget168", "2^"+budget168)))
		add(sweep(file, `~(2\^48\d)\b`, w("log2_messages168", msgs168)))
		add(sweep(file, `(2\^90\.\d)\b`, w("masks_per_crib168", crib168)))
		add(sweep(file, `\b(3,195,\d{3})\b`, w("max_chunks168", comma(f.MaxChunks168))))
	}
	for _, file := range []string{"SCIENCE.md", "SECURITY.md", "ITB.md", "README.md", "POSTQUANTUM.md"} {
		add(sweep(file, `\b(10,078,335,949,946,663,\d{3})\b`, w("gcd168", gcd168Comma)))
	}
	add(sweep("PROOFS.md", `\b(10078335949946663\d{3})\b`, w("gcd168", gcd168Plain)))
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "lean/README.md"} {
		add(sweep(file, `\b(3,176,\d{3})\b`, w("entry_pixels_mode2", "3,176,523")))
		add(sweep(file, `\b(68,083,\d{3})\b`, w("entry_pixels_mode1", "68,083,776")))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md", "ITB.md", "POSTQUANTUM.md", "README.md", "REDTEAM.md", "FAQ.md"} {
		add(sweep(file, `(2\^166\.\d\d)`, w("desync_traj_mode2_k8", "2^166.98")))
		add(sweep(file, `(2\^224\.\d\d)`, w("desync_traj_mode1_k8", "2^224.04")))
		add(sweep(file, `(2\^96\.\d\d)`, w("desync_lane48_mode2", "2^96.91")))
		add(sweep(file, `(2\^101\.\d\d)`, w("desync_lane48_mode1", "2^101.53")))
		add(sweep(file, `(2\^128\.\d\d)`, w("desync_lane48_fold_mode2", "2^128.91")))
		add(sweep(file, `(2\^133\.\d\d)`, w("desync_lane48_fold_mode1", "2^133.53")))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md", "ITB.md", "POSTQUANTUM.md", "README.md", "REDTEAM.md"} {
		add(sweep(file, `(2\^279\.\d\d)`, w("desync_lane168_mode2", "2^279.89")))
		add(sweep(file, `(2\^284\.\d\d)`, w("desync_lane168_mode1", "2^284.51")))
		add(sweep(file, `(2\^311\.\d\d)`, w("desync_lane168_fold_mode2", "2^311.89")))
		add(sweep(file, `(2\^316\.\d\d)`, w("desync_lane168_fold_mode1", "2^316.51")))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md", "README.md", "lean/README.md"} {
		add(sweep(file, `(2\^187\.\d\d)`, w("desync_traj_mode3_k8", "2^187.16")))
		add(sweep(file, `(2\^99\.\d\d)`, w("desync_lane48_mode3", "2^99.54")))
		add(sweep(file, `(2\^282\.\d\d)`, w("desync_lane168_mode3", "2^282.52")))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md", "README.md", "lean/README.md"} {
		add(sweep(file, `(2\^131\.\d\d)`, w("desync_lane48_fold_mode3", "2^131.54")))
		add(sweep(file, `(2\^314\.\d\d)`, w("desync_lane168_fold_mode3", "2^314.52")))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md", "lean/README.md"} {
		add(sweep(file, `\b(17,847,\d{3})\b`, w("entry_pixels_mode3", "17,847,702")))
	}
	add(
		// ----- Mode 3 (Gauss-Posit) container floors & theorem counts -----
		expect("README.md",
			`^- \*\*Gauss-Posit Container and Trajectory Mode \(Mode 3, `+"`0x05`"+`\)\*\*: an inscribed Gauss-circle container floor \(⌊\(6 · MinPixels\) / π_posit\(es=2\)⌋ \+ 1 = `+num+` / `+num+` / `+num+` pixels, yielding `+num+x+num+` = `+num+` / `+num+x+num+` = `+num+` / `+num+x+num+` = `+num+` pixel containers and a `+dec+`% wire floor reduction vs \*\*Mode 1\*\* at 1024-bit keys, ~`+dec+` KB vs ~`+dec+` KB\)`,
			w("m3_floor_px_512", plain(m3[512].FloorPixels)), w("m3_floor_px_1024", plain(c.FloorPixels)), w("m3_floor_px_2048", plain(m3[2048].FloorPixels)),
			w("m3_side_512", plain(m3[512].Side)), w("m3_side_512", plain(m3[512].Side)), w("m3_P_512", plain(m3[512].P)),
			w("m3_side_1024", plain(c.Side)), w("m3_side_1024", plain(c.Side)), w("m3_P_1024", plain(c.P)),
			w("m3_side_2048", plain(m3[2048].Side)), w("m3_side_2048", plain(m3[2048].Side)), w("m3_P_2048", plain(m3[2048].P)),
			w("m3_save_pct_128", m3SavePct128), w("m3_wire_kb_1024", kb(c.Wire)), w("m1_wire_kb_1024", kb(a.Wire)),
		),
		expect("README.md",
			`^- \*\*Mode 3: Gauss-Posit \(inscribed Gauss-circle floor \+ posit64/quire512 trajectory\)\.\*\* The three-region floor is scaled by the Gauss-circle ratio .⌊\(6 · MinPixels\) / π_posit\(es=2\)⌋ \+ 1. \(`+num+` / `+num+` / `+num+` pixels for 512 / 1024 / 2048-bit keys\) and rounded up to the smallest square plus the barrier margin: .⌈√`+num+`⌉ = `+num+` → \(`+num+` \+ 1\)² = `+num+x+num+` = `+num+`. px \(~`+dec+` KB\) at 512-bit keys, .⌈√`+num+`⌉ = `+num+` → \(`+num+` \+ 1\)² = `+num+x+num+` = `+num+`. px \(~`+dec+` KB, `+dec+`% smaller than the ~`+dec+` KB of \*\*Mode 1\*\*\) at 1024-bit keys, and .⌈√`+num+`⌉ = `+num+` → \(`+num+` \+ 1\)² = `+num+x+num+` = `+num+`. px \(~`+dec+` KB\) at 2048-bit keys`,
			w("m3_floor_px_512", plain(m3[512].FloorPixels)), w("m3_floor_px_1024", plain(c.FloorPixels)), w("m3_floor_px_2048", plain(m3[2048].FloorPixels)),
			w("m3_floor_px_512", plain(m3[512].FloorPixels)), w("m3_raw_512", plain(m3[512].RawSquare)), w("m3_raw_512", plain(m3[512].RawSquare)), w("m3_side_512", plain(m3[512].Side)), w("m3_side_512", plain(m3[512].Side)), w("m3_P_512", plain(m3[512].P)), w("m3_wire_kb_512", kb(m3[512].Wire)),
			w("m3_floor_px_1024", plain(c.FloorPixels)), w("m3_raw_1024", plain(c.RawSquare)), w("m3_raw_1024", plain(c.RawSquare)), w("m3_side_1024", plain(c.Side)), w("m3_side_1024", plain(c.Side)), w("m3_P_1024", plain(c.P)), w("m3_wire_kb_1024", kb(c.Wire)), w("m3_save_pct_128", m3SavePct128), w("m1_wire_kb_1024", kb(a.Wire)),
			w("m3_floor_px_2048", plain(m3[2048].FloorPixels)), w("m3_raw_2048", plain(m3[2048].RawSquare)), w("m3_raw_2048", plain(m3[2048].RawSquare)), w("m3_side_2048", plain(m3[2048].Side)), w("m3_side_2048", plain(m3[2048].Side)), w("m3_P_2048", plain(m3[2048].P)), w("m3_wire_kb_2048", kb(m3[2048].Wire)),
		),
		expect("README.md",
			"Formalization pillars \\(with `"+num+"` core mathematical, combinatorial, and bit-vector theorems — `"+num+"` across six `ITB/\\*\\.lean` core modules including `"+num+"` in `ITB/Desync\\.lean`, plus `"+num+"` in `Apps/ThreeToEight\\.lean` — accompanied by `"+num+"` \\*\\*Mode 3\\*\\* Gauss-Posit theorems in `ITB/Posit\\.lean` and `"+num+"` additional theorems",
			w("lean_total_theorems", "270"), w("lean_core_theorems", "239"), w("lean_desync_theorems", "40"), w("lean_kdf_theorems", "31"), w("lean_posit_theorems", "30"), w("lean_pipeline_theorems", "92"),
		),
		expect("ITB.md",
			`yielding a `+num+`-pixel floor and a `+num+x+num+` = `+num+`-pixel container or ~`+dec+` KB wire floor at 1024-bit keys — `+dec+`% smaller than \*\*Mode 1\*\* while keeping `+num+` pixels per region and ≥ `+num+` bytes of guaranteed DRBG residue, or `+num+` bytes at the `+num+`-pixel floor`,
			w("m3_floor_px", plain(c.FloorPixels)), w("m3_side", plain(c.Side)), w("m3_side", plain(c.Side)), w("m3_P", plain(c.P)), w("m3_wire_kb", kb(c.Wire)),
			w("m3_save_pct_128", m3SavePct128), w("m3_P0", plain(c.P/3)), w("m3_residue", plain(c.Residue)), w("m3_residue_floor", plain(c.ResidueAtFloor)), w("m3_floor_px", plain(c.FloorPixels)),
		),
		expect("PROOFS.md",
			`^\*\*Mode 3 \(Gauss-Posit\) Container Floor and Trajectory Variant\.\*\*.*⌊\(6 · MinPixels\) / π_posit\(es=2\)⌋ \+ 1 = `+num+` / `+num+` / `+num+` pixels at 512 / 1024 / 2048-bit keys, yielding `+num+x+num+` = `+num+`, `+num+x+num+` = `+num+`, and `+num+x+num+` = `+num+` pixel containers with `+"`DefaultBarrierFill = "+num+"`"+`, or `+num+` B vs `+num+` B in \*\*Mode 1\*\* at 1024-bit keys and 128-bit nonce and `+num+` B vs `+num+` B at 512-bit nonce, saving `+num+` B or `+dec+`% wire overhead with ≥ `+num+` B guaranteed DRBG residue and `+num+` B actual residue at the `+num+`-pixel floor.*encoding ambiguity 7\^`+num+` ≈ `+p2+` under CCA and 56\^`+num+` ≈ `+p2+` without CCA`,
			w("m3_floor_px_512", plain(m3[512].FloorPixels)), w("m3_floor_px_1024", plain(c.FloorPixels)), w("m3_floor_px_2048", plain(m3[2048].FloorPixels)),
			w("m3_side_512", plain(m3[512].Side)), w("m3_side_512", plain(m3[512].Side)), w("m3_P_512", plain(m3[512].P)),
			w("m3_side_1024", plain(c.Side)), w("m3_side_1024", plain(c.Side)), w("m3_P_1024", plain(c.P)),
			w("m3_side_2048", plain(m3[2048].Side)), w("m3_side_2048", plain(m3[2048].Side)), w("m3_P_2048", plain(m3[2048].P)),
			w("barrier_fill", plain(f.BarrierFill)),
			w("m3_wire_128", plain(m3Wire128)), w("m1_wire_128", plain(m1Wire128)), w("m3_wire_512", plain(c.Wire)), w("m1_wire_512", plain(a.Wire)),
			w("m3_save_bytes", plain(m3SaveBytes)), w("m3_save_pct_128", m3SavePct128),
			w("m3_residue", plain(c.Residue)), w("m3_residue_floor", plain(c.ResidueAtFloor)), w("m3_floor_px_1024", plain(c.FloorPixels)),
			w("m3_P_1024", plain(c.P)), w("cca_m3", pow2(cca(c.P))), w("m3_P_1024", plain(c.P)), w("nocca_m3", pow2(nocca(c.P))),
		),
		expect("SCIENCE.md",
			`^3\. \*\*Mode 3 \(Gauss-Posit\) Inscribed Circle Floor.*yielding `+num+`, `+num+`, and `+num+` px at 512 / 1024 / 2048-bit keys, and `+num+x+num+` = `+num+`, `+num+x+num+` = `+num+`, and `+num+x+num+` = `+num+` px containers with `+"`DefaultBarrierFill = "+num+"`"+`; `+num+` B vs `+num+` B wire floor at 1024-bit keys and 128-bit nonce, or `+num+` B vs `+num+` B at 512-bit nonce, saving `+num+` B / `+dec+`%.*≥ `+num+` B guaranteed / `+num+` B actual DRBG residue at the `+num+`-px floor`,
			w("m3_floor_px_512", plain(m3[512].FloorPixels)), w("m3_floor_px_1024", plain(c.FloorPixels)), w("m3_floor_px_2048", plain(m3[2048].FloorPixels)),
			w("m3_side_512", plain(m3[512].Side)), w("m3_side_512", plain(m3[512].Side)), w("m3_P_512", plain(m3[512].P)),
			w("m3_side_1024", plain(c.Side)), w("m3_side_1024", plain(c.Side)), w("m3_P_1024", plain(c.P)),
			w("m3_side_2048", plain(m3[2048].Side)), w("m3_side_2048", plain(m3[2048].Side)), w("m3_P_2048", plain(m3[2048].P)),
			w("barrier_fill", plain(f.BarrierFill)),
			w("m3_wire_128", plain(m3Wire128)), w("m1_wire_128", plain(m1Wire128)), w("m3_wire_512", plain(c.Wire)), w("m1_wire_512", plain(a.Wire)),
			w("m3_save_bytes", plain(m3SaveBytes)), w("m3_save_pct_128", m3SavePct128),
			w("m3_residue", plain(c.Residue)), w("m3_residue_floor", plain(c.ResidueAtFloor)), w("m3_floor_px_1024", plain(c.FloorPixels)),
		),
		expect("SECURITY.md",
			`^\*\*Note on Mode 3 \(Gauss-Posit\)\.\*\*.*⌊\(6 × `+num+`\) / π_posit\(es=2\)⌋ \+ 1 = `+num+` → `+num+x+num+` \(P = `+num+`, P_0 = P_1 = `+num+`, P_2 = `+num+`\) with `+"`DefaultBarrierFill = "+num+"`"+` \(`+num+` B wire floor at 128-bit nonce vs `+num+` B in \*\*Mode 1\*\*, or `+num+` B vs `+num+` B at 512-bit nonce, saving `+num+` B / `+dec+`%\): noise barrier 2\^\(8P\) = `+p2+` \(`+dec+`× the `+p2+` Landauer exponent\); encoding ambiguity 56\^`+num+` ≈ `+p2+` \(No CCA\) and 7\^`+num+` ≈ `+p2+` \(Under CCA\); guaranteed DRBG residue ≥ `+num+` bytes \(s = `+num+`, `+num+` bytes at the `+num+`-pixel floor\); config map space 2\^\(62P\) = `+p2,
			w("minpixels_1024", plain(mp)), w("m3_floor_px", plain(c.FloorPixels)), w("m3_side", plain(c.Side)), w("m3_side", plain(c.Side)), w("m3_P", plain(c.P)),
			w("m3_P0", plain(c.P/3)), w("m3_P2", plain(c.P-2*(c.P/3))), w("barrier_fill", plain(f.BarrierFill)),
			w("m3_wire_128", plain(m3Wire128)), w("m1_wire_128", plain(m1Wire128)), w("m3_wire_512", plain(c.Wire)), w("m1_wire_512", plain(a.Wire)),
			w("m3_save_bytes", plain(m3SaveBytes)), w("m3_save_pct_128", m3SavePct128),
			w("noise_m3", pow2(noiseBarrier(c.P))), w("noise_m3_vs_landauer", landauer(noiseBarrier(c.P))), w("landauer", pow2(landauerExp)),
			w("m3_P", plain(c.P)), w("nocca_m3", pow2(nocca(c.P))), w("m3_P", plain(c.P)), w("cca_m3", pow2(cca(c.P))),
			w("m3_residue", plain(c.Residue)), w("m3_s", plain(c.Side-1)), w("m3_residue_floor", plain(c.ResidueAtFloor)), w("m3_floor_px", plain(c.FloorPixels)),
			w("config_m3", pow2(configMap(c.P))),
		),
		expect("FAQ.md",
			"machine-checked across "+num+" core theorems plus "+num+" \\*\\*Mode 3\\*\\* Gauss-Posit theorems in `ITB/Posit\\.lean` and "+num+" executable \\*\\*Core ITB\\*\\* pipeline specification",
			w("lean_total_theorems", "270"), w("lean_posit_theorems", "30"), w("lean_pipeline_theorems", "92"),
		),
		expect("lean/README.md",
			"`"+num+"` theorems across the six `ITB/\\*\\.lean` core modules, plus `"+num+"` theorems in `Apps/ThreeToEight\\.lean`, totaling `"+num+"` machine-checked theorems; accompanied by `"+num+"` \\*\\*Mode 3\\*\\* Gauss-Posit theorems in \\[`ITB/Posit\\.lean`\\]\\(ITB/Posit\\.lean\\) and `"+num+"` additional pipeline specification",
			w("lean_core_theorems", "239"),
			w("lean_kdf_theorems", "31"),
			w("lean_total_theorems", "270"),
			w("lean_posit_theorems", "30"),
			w("lean_pipeline_theorems", "92"),
		),
		expect("lean/README.md",
			`\[ITB/Desync\.lean\]\(ITB/Desync\.lean\) \(`+num+` theorems\)`,
			w("lean_desync_theorems", "40"),
		),
		expect("lean/README.md",
			`\[ITB/Posit\.lean\]\(ITB/Posit\.lean\) \(`+num+` theorems & Go KATs\)`,
			w("lean_posit_theorems", "30"),
		),
		expect("lean/README.md",
			`\[ITB/PipelineSpec128\.lean\]\(ITB/PipelineSpec128\.lean\) \(`+num+` theorems & Go wire KATs\)`,
			w("lean_pipeline128_theorems", "30"),
		),
		expect("lean/README.md",
			`\[ITB/PipelineSpec256\.lean\]\(ITB/PipelineSpec256\.lean\) \(`+num+` theorems & Go wire KATs\)`,
			w("lean_pipeline256_theorems", "30"),
		),
		expect("lean/README.md",
			`\[ITB/PipelineSpec512\.lean\]\(ITB/PipelineSpec512\.lean\) \(`+num+` theorems & Go wire KATs\)`,
			w("lean_pipeline512_theorems", "32"),
		),
	)
	return exps
}

// wireOffsets registers the wire-format offset table a file carries:
// the prefix row, the main-nonce row at offset `prefix`, and the
// `prefix+N` / `prefix+2+N` / `prefix+4+N` rows for width, height and
// the pixel container.
func wireOffsets(file string, f *Figures, prefixLabel string) []Expectation {
	return []Expectation{
		expect(file, `^0\s+`+num+`\s+`+prefixLabel, w("prefix", plain(f.Prefix))),
		expect(file, `^`+num+`\s+N\s+Main nonce`, w("prefix", plain(f.Prefix))),
		expect(file, `^`+num+`\+N\s+2\s+Width`, w("prefix", plain(f.Prefix))),
		expect(file, `^`+num+`\+N\s+2\s+Height`, w("prefix+2", plain(f.Prefix+2))),
		expect(file, `^`+num+`\+N\s+W×H×8\s+Raw RGBWYOPA`, w("prefix+4", plain(f.Prefix+4))),
	}
}

// depthAt is the Pixel Barrier ChainHash depth `keyBits / width`.
func depthAt(keyBits, width int) string { return plain(keyBits / width) }

// depthWants lists the ChainHash depths ITB.md § 12 tabulates: the Pixel
// Barrier `keyBits / width` and the Interlocked Barrier
// `1 + keyBits / width`, for 512 / 1024 / 2048-bit keys at each shipped
// width, Pixel Barrier first.
func depthWants() []Want {
	var out []Want
	for _, extra := range []int{0, 1} {
		for _, wd := range shippedWidths {
			for _, k := range keySizes {
				key := fmt.Sprintf("depth_%d_w%d", k, wd)
				if extra == 1 {
					key = "interlock_" + key
				}
				out = append(out, w(key, plain(extra+k/wd)))
			}
		}
	}
	return out
}
