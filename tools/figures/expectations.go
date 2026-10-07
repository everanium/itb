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
	for _, k := range keySizes {
		m1[k] = f.Floor[k][1]
		m2[k] = f.Floor[k][2]
	}
	// The 1024-bit key is the documentation's worked example.
	a, b, t := m1[1024], m2[1024], f.Theoretical[1024]
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
	invGCDExp := -int(math.Floor(math.Log10(invGCD)))
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
			w("cca_64KiB", pow2c(cca(s64k.P))), w("cca_64KiB_vs_key", fixed(float64(cca(s64k.P))/1024, 1))),
		expect("SCIENCE.md", `^\|Ω_chunk\| = A · B = `+num+`\s+≈\s+`+p2d+`$`,
			w("AB", commaBig(f.AB)), w("log2_AB", "2^"+log2AB)),
		expect("SCIENCE.md", `defeats the .gcd\(A, B\) = `+num+`. collapse trap that would reduce the reachable space to .1 / `+num+` ≈ `+dec+` × 10\^-(\d).`,
			w("gcd", comma(gcd)), w("gcd", comma(gcd)), w("inv_gcd_mantissa", fixed(invGCD*math.Pow(10, float64(invGCDExp)), 1)), w("inv_gcd_exp", plain(invGCDExp))),
		expect("SCIENCE.md", `cyclic rotation by a per-pixel amount in .\[0, 6\]. derived from .dataSeed_i. \(.rotation_i = dataHash_i mod 7., providing log₂\(7\) ≈ `+dec+` bits of entropy\)`,
			w("log2_7", fixed(math.Log2(7), 3))),
	)
	add(wireOffsets("SCIENCE.md", f, `Stream prefix`)...)
	add(
		expect("SCIENCE.md", "For `P = "+num+"` \\(Mode 2 per-container floor at a 1024-bit key — joint floor `MinPixels = "+num+"`, square-rounded to `"+num+x+num+" = "+num+"` with `DefaultBarrierFill = "+num+"`\\): `7\\^"+num+" ≈ "+p2+"`. For `P = "+num+"` \\(Mode 1 per-region floor — `3"+x+num+" = "+num+"` total pixels, square-rounded to `"+num+x+num+" = "+num+"`\\): `7\\^"+num+" ≈ "+p2+"` observation-consistent candidate configurations \\(with `7\\^"+num+" ≈ "+p2+"`",
			w("m2_P", plain(b.P)), w("minpixels_1024", plain(mp)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)), w("barrier_fill", plain(f.BarrierFill)),
			w("m2_P", plain(b.P)), w("cca_m2", pow2(cca(b.P))),
			w("m1_P", plain(a.P)), w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)),
			w("m1_P", plain(a.P)), w("cca_m1", pow2(cca(a.P))),
			w("theo_P", plain(t.P)), w("cca_theo", pow2(cca(t.P)))),
		expect("SCIENCE.md", "≈ 2\\^\\((\\d+\\.\\d+) × C\\)` observation-consistent mask configurations",
			w("log2_AB", log2AB)),
		expect("SCIENCE.md", "For `keyBits = 1024`: joint floor `MinPixels = "+num+"`. In Mode 2 \\(per-container\\), the joint floor produces a `"+num+x+num+"` container \\(`P = "+num+"`\\), where the noise barrier is `"+p2+" ≫ "+p2+"` \\(a margin of `"+p2+"`\\). In Mode 1 \\(per-region\\), each region independently enforces `MinPixels = "+num+"`, requiring at least `3"+x+num+" = "+num+"` data pixels; square container rounding \\(`⌈√"+num+"⌉ = "+num+"`\\) plus `DefaultBarrierFill = "+num+"` yields `"+num+x+num+" = "+num+"` pixels, expanding the noise barrier to `"+p2+"` \\(a margin of `"+p2+"` over the key space\\)",
			w("minpixels_1024", plain(mp)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)),
			w("noise_m2", pow2(noiseBarrier(b.P))), w("key_space", pow2(1024)), w("noise_margin_m2", pow2(noiseBarrier(b.P)-1024)),
			w("minpixels_1024", plain(mp)), w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_raw_square", plain(a.RawSquare)), w("barrier_fill", plain(f.BarrierFill)),
			w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)),
			w("noise_m1", pow2(noiseBarrier(a.P))), w("noise_margin_m1", pow2(noiseBarrier(a.P)-1024))),
		expect("SCIENCE.md", `^CCA leak = (\d+) / (\d+) ≈ `+dec+` % of per-pixel configuration`,
			w("noise_config_bits", plain(itb.NoiseConfigBits)), w("config_bits", plain(itb.NoiseConfigBits+itb.DataConfigBits)),
			w("cca_leak_pct", fixed(100*float64(itb.NoiseConfigBits)/float64(itb.NoiseConfigBits+itb.DataConfigBits), 1))),
		expect("SCIENCE.md", `^- Mode 1 per-region container `+residueLine()+" \\(`\\("+num+" − "+num+"\\)"+x+"7 = "+num+" bytes` at the exact floor\\)",
			w("m1_s", plain(a.Side-1)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)), w("m1_s", plain(a.Side-1)), w("m1_residue", plain(a.Residue)),
			w("m1_P", plain(a.P)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_residue_floor", plain(a.ResidueAtFloor))),
		expect("SCIENCE.md", `^- Mode 2 per-container container `+residueLine()+" \\(`\\("+num+" − "+num+"\\)"+x+"7 = "+num+" bytes` at the exact floor\\)",
			w("m2_s", plain(b.Side-1)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)), w("m2_s", plain(b.Side-1)), w("m2_residue", plain(b.Residue)),
			w("m2_P", plain(b.P)), w("minpixels_1024", plain(mp)), w("m2_residue_floor", plain(b.ResidueAtFloor))),
		expect("SCIENCE.md", `^- Theoretical single-region floor `+residueLine()+" for payloads ≤ "+num+"² = "+num+" pixels, and `\\("+num+" − "+num+"\\)"+x+"7 = "+num+" bytes` at the exact "+num+"-pixel floor",
			w("theo_s", plain(t.Side-1)), w("theo_side", plain(t.Side)), w("theo_side", plain(t.Side)), w("theo_P", plain(t.P)), w("theo_s", plain(t.Side-1)), w("theo_residue", plain(t.Residue)),
			w("theo_s", plain(t.Side-1)), w("theo_s_sq", plain((t.Side-1)*(t.Side-1))),
			w("theo_P", plain(t.P)), w("minpixels_1024", plain(mp)), w("theo_residue_floor", plain(t.ResidueAtFloor)), w("minpixels_1024", plain(mp))),
		expect("SCIENCE.md", `^gcd\(A, B\) = gcd\(C\(48, 16\), C\(32, 16\)\) = `+num+` = (.+)$`,
			w("gcd", comma(gcd)), w("gcd_factors", f.GCDFactors)),
		expect("SCIENCE.md", `Its image in .\[0, A\) × \[0, B\). has cardinality .A · B / `+num+`.\..*the remaining .≈ `+dec+` %. of the mask space is structurally excluded.*would face a .`+num+`×.-restricted mask space — an erosion of .log₂ `+num+` ≈ `+dec+`. bits`,
			w("gcd", comma(gcd)), w("excluded_pct", trunc(100*(1-invGCD), 3)), w("gcd", comma(gcd)), w("gcd", comma(gcd)), w("log2_gcd", fixed(f.Log2GCD, 2))),
		// Barrier strength table (1024-bit key): Mode 2 | Mode 1 | theoretical.
		expect("SCIENCE.md", `^\| Container dimensions \| `+dimsP+` \| `+dimsP+` \| `+dimsP+` \|$`,
			w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)),
			w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", comma(a.P)),
			w("theo_side", plain(t.Side)), w("theo_side", plain(t.Side)), w("theo_P", plain(t.P))),
		expect("SCIENCE.md", `^\| MinPixels enforcement \| `+num+` joint → `+num+` \| 3`+x+num+` = `+num+` → `+num+` \| `+num+` → `+num+` \|$`,
			w("minpixels_1024", plain(mp)), w("m2_P", plain(b.P)), w("minpixels_1024", plain(mp)), w("m1_floor_px", comma(a.FloorPixels)), w("m1_P", comma(a.P)), w("minpixels_1024", plain(mp)), w("theo_P", plain(t.P))),
		expect("SCIENCE.md", "^\\| Noise barrier \\(`2\\^\\(8P\\)`\\) \\| "+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("noise_m2", pow2c(noiseBarrier(b.P))), w("noise_m1", pow2c(noiseBarrier(a.P))), w("noise_theo", pow2c(noiseBarrier(t.P)))),
		expect("SCIENCE.md", "^\\| Encoding ambiguity `56\\^P` \\(No CCA\\) \\| "+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("nocca_m2", pow2c(nocca(b.P))), w("nocca_m1", pow2c(nocca(a.P))), w("nocca_theo", pow2c(nocca(t.P)))),
		expect("SCIENCE.md", "^\\| Encoding ambiguity `7\\^P` \\(Under CCA\\) \\| "+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("cca_m2", pow2c(cca(b.P))), w("cca_m1", pow2c(cca(a.P))), w("cca_theo", pow2c(cca(t.P)))),
		expect("SCIENCE.md", `^\| DRBG residue \(Theorem 10\) \| ≥ `+num+` bytes \(s = `+num+`; `+num+` B at floor\) \| ≥ `+num+` bytes \(s = `+num+`; `+num+` B at floor\) \| ≥ `+num+` bytes \(s = `+num+`; `+num+` B at floor\) \|$`,
			w("m2_residue", plain(b.Residue)), w("m2_s", plain(b.Side-1)), w("m2_residue_floor", plain(b.ResidueAtFloor)),
			w("m1_residue", plain(a.Residue)), w("m1_s", plain(a.Side-1)), w("m1_residue_floor", plain(a.ResidueAtFloor)),
			w("theo_residue", plain(t.Residue)), w("theo_s", plain(t.Side-1)), w("theo_residue_floor", plain(t.ResidueAtFloor))),
		expect("SCIENCE.md", "^\\| Config map space \\(`2\\^\\(62P\\)`\\) \\| "+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("config_m2", pow2c(configMap(b.P))), w("config_m1", pow2c(configMap(a.P))), w("config_theo", pow2c(configMap(t.P)))),
		expect("SCIENCE.md", `^\| Key space \| `+p2+` \| `+p2+` \| `+p2+` \|$`,
			w("key_space", pow2c(1024)), w("key_space", pow2c(1024)), w("key_space", pow2c(1024))),
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
			w(fmt.Sprintf("m1_side_%d", k), plain(m1[k].Side)), w(fmt.Sprintf("m1_side_%d", k), plain(m1[k].Side)), w(fmt.Sprintf("m1_P_%d", k), comma(m1[k].P)),
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
		expect("SCIENCE.md", `Core ITB: .√P × 2\^keyBits. \(~`+p2+` at 1024-bit for Mode 2 P = `+num+` and theoretical floor P = `+num+`; ~`+p2+` at Mode 1 P = `+num+`\)\. MAC \+ Reveal: .√P × 2\^\(keyBits/2\). \(~`+p2+` at 1024-bit for P = `+num+` and P = `+num+`; ~`+p2+` at Mode 1 P = `+num+`\)`,
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
		return expect("SCIENCE.md", `^\| `+label+` \| `+num+" \\| `"+p2+"` \\| "+dec+"× \\| `"+p2+"` \\| "+dec+`× \|$`,
			w("P", pf(P)), w("cca", pow2c(cca(P))), w("cca_vs_key", ratioBare(float64(cca(P))/1024)),
			w("nocca", pow2c(nocca(P))), w("nocca_vs_key", ratioBare(float64(nocca(P))/1024)))
	}
	add(
		expect("SCIENCE.md", `^\| Mode 2 container floor \(payload ≤ ~`+dec+` KB\) \|`, w("m2_max_payload_kb", kb(b.MaxPayload))),
		expect("SCIENCE.md", `^\| Mode 1 container floor \(payload ≤ ~`+dec+` KB\) \|`, w("m1_max_payload_kb", kb(a.MaxPayload))),
		// The theoretical floor is not a shipped shape. Its container is
		// the Mode 2 raw square before the barrier margin, so the payloads
		// it holds are exactly those that fit the Mode 2 floor; the label
		// takes the Mode 2 measured fit while the two containers coincide.
		expect("SCIENCE.md", `^\| Theoretical single-region floor \(~`+dec+` KB\) \|`, w("theo_max_payload_kb", theoPayloadKB)),
		ambRow(`Mode 2 container floor \(payload ≤ ~[\d.]+ KB\)`, b.P, plain),
		ambRow(`Mode 1 container floor \(payload ≤ ~[\d.]+ KB\)`, a.P, comma),
		ambRow(`Theoretical single-region floor \(~[\d.]+ KB\)`, t.P, plain),
		ambRow(`64 KB`, s64k.P, comma),
		ambRow(`1 MB`, s1m.P, comma),
		expect("SCIENCE.md", "At 64 KB, encoding ambiguity alone is `"+p2+"`, whose exponent is "+dec+`× the 1024-bit key-space exponent. No computational model can perform \*\*blind enumeration\*\* of `+"`"+p2+"`",
			w("cca_64KiB", pow2c(cca(s64k.P))), w("cca_64KiB_vs_key", fixed(float64(cca(s64k.P))/1024, 1)), w("cca_64KiB", pow2c(cca(s64k.P)))),
		expect("SCIENCE.md", "At 64 MB \\(`P ≈ "+dec+" × 10⁶`\\), each candidate costs ~"+num+" million hash calls",
			w("P_64MiB_sci", fixed(float64(s64m.P)/1e6, 1)), w("hash_calls_64MiB_millions", plain(int(math.Round(float64(s64m.P*2*chainRounds(1024))/1e6))))),
		expect("SCIENCE.md", "Wire format: `prefix \\("+num+" bytes\\) ‖ main_nonce \\(N bytes\\) ‖ W \\(2 bytes\\) ‖ H \\(2 bytes\\) ‖ W × H × 8 raw RGBWYOPA` for a Single Message, with one chunk header of `N \\+ 4` bytes \\(`N` = the configured nonce width in bytes; default `DefaultNonceBits = "+num+"` bits, `N = "+num+"`\\)",
			w("prefix", plain(f.Prefix)), w("nonce_bits", plain(f.NonceBits)), w("nonce_bytes", plain(f.NonceBytes))),
		expect("SCIENCE.md", "Mode 1 enforces the per-region floor `MinPixels = "+num+"` across all three regions \\(`3"+x+num+" = "+num+"` square-rounded to `"+num+x+num+" = "+num+"` with `DefaultBarrierFill = "+num+"`\\), yielding barrier `"+p2+"`; Mode 2 enforces `MinPixels = "+num+"` jointly across the container \\(`"+num+x+num+" = "+num+"` with `DefaultBarrierFill = "+num+"`\\), yielding barrier `"+p2+"`.*\\(`≥ "+p2+"` at 1024-bit\\).*settles at `8/56 ≈ "+num+"%`",
			w("minpixels_1024", plain(mp)), w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)), w("barrier_fill", plain(f.BarrierFill)),
			w("noise_m1", pow2(noiseBarrier(a.P))), w("minpixels_1024", plain(mp)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)), w("barrier_fill", plain(f.BarrierFill)),
			w("noise_m2", pow2(noiseBarrier(b.P))), w("noise_margin_m1", pow2(noiseBarrier(a.P)-1024)),
			w("noise_overhead_pct", fixed(math.Round(100*float64(itb.Channels)/float64(itb.DataBitsPerPixel)), 0))),
		expect("SCIENCE.md", `relative deviation of ≈ (2\^-\d+\.\d).*maximum-size message of (2\^\d+\.\d+) chunks, the per-message deviation is bounded by ≈ (2\^-\d+\.\d)\..*1/ε² ≈ (2\^\d+\.\d). chunk samples`,
			w("bias", "2^"+bias), w("max_chunks", "2^"+chunks), w("accum_bias", "2^"+accum), w("sample_budget", "2^"+budget)),
	)

	// ----- PROOFS.md --------------------------------------------------
	add(
		expect("PROOFS.md", "^- Under Mode 1 \\(per-region floor `MinPixels = "+num+"` applied to each of three regions, `3"+x+num+" = "+num+"`, square-rounded to `"+num+x+num+" = "+num+"` with `DefaultBarrierFill = "+num+"`\\): `7\\^"+num+" ≈ "+p2+"`",
			w("minpixels_1024", plain(mp)), w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)), w("barrier_fill", plain(f.BarrierFill)), w("m1_P", plain(a.P)), w("cca_m1", pow2(cca(a.P)))),
		expect("PROOFS.md", "^- Under Mode 2 \\(per-container floor `MinPixels = "+num+"` evaluated across the container, square-rounded to `"+num+x+num+" = "+num+"` with `DefaultBarrierFill = "+num+"`\\): `7\\^"+num+" ≈ "+p2+"`",
			w("minpixels_1024", plain(mp)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)), w("barrier_fill", plain(f.BarrierFill)), w("m2_P", plain(b.P)), w("cca_m2", pow2(cca(b.P)))),
		expect("PROOFS.md", `The noise barrier \(`+p2+` for Mode 1, `+p2+` for Mode 2,`,
			w("noise_m1", pow2(noiseBarrier(a.P))), w("noise_m2", pow2(noiseBarrier(b.P)))),
		expect("PROOFS.md", `^MinPixels = MinPixelsAuth = ⌈1024 / log₂\(7\)⌉ = ⌈1024 / `+dec+`⌉ = `+num+` per region$`,
			w("log2_7", fixed(math.Log2(7), 3)), w("minpixels_1024", plain(mp))),
		expect("PROOFS.md", `^Total pixels = 3 × per-region floor = `+num+`; square container side = ⌈√`+num+`⌉ = `+num+`; with default barrier margin \(.DefaultBarrierFill = `+num+`.\) side = `+num+`; P = `+num+x+num+` = `+num+`\.$`,
			w("m1_floor_px", plain(a.FloorPixels)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_raw_square", plain(a.RawSquare)), w("barrier_fill", plain(f.BarrierFill)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P))),
		expect("PROOFS.md", `^2\^\(8`+x+num+`\) = `+p2+`$`, w("m1_P", plain(a.P)), w("noise_m1", pow2(noiseBarrier(a.P)))),
		expect("PROOFS.md", `^`+num+` > 1024  ⟹  `+p2+` > `+p2+`  ✓$`, w("noise_m1_exp", plain(noiseBarrier(a.P))), w("noise_m1", pow2(noiseBarrier(a.P))), w("key_space", pow2(1024))),
		expect("PROOFS.md", `^The barrier strictly exceeds the key space by a factor of `+p2+`\.$`, w("noise_margin_m1", pow2(noiseBarrier(a.P)-1024))),
		expect("PROOFS.md", "^- Mode 1 \\(per-region floor\\): `P ≥ 3 × ⌈keyBits / log₂\\(7\\)⌉`. For a 1024-bit key, `P = "+num+"`, yielding noise barrier `2\\^\\(8"+x+num+"\\) = "+p2+" > "+p2+"` \\(margin `"+p2+"`\\)",
			w("m1_P", plain(a.P)), w("m1_P", plain(a.P)), w("noise_m1", pow2(noiseBarrier(a.P))), w("key_space", pow2(1024)), w("noise_margin_m1", pow2(noiseBarrier(a.P)-1024))),
		expect("PROOFS.md", "^- Mode 2 \\(per-container floor\\): `P ≥ ⌈keyBits / log₂\\(7\\)⌉`. For a 1024-bit key, `P = "+num+"`, yielding noise barrier `2\\^\\(8"+x+num+"\\) = "+p2+" > "+p2+"` \\(margin `"+p2+"`\\)",
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
		add(expect("PROOFS.md", fmt.Sprintf("^\\| %d-bit \\| `P_region ≥ ", k)+num+" pixels` \\| `P_region ≥ "+num+" pixels` \\|$",
			w(fmt.Sprintf("minpixels_%d", k), plain(f.MinPixels[k])), w(fmt.Sprintf("threshold_nocca_%d", k), plain(f.ThresholdNoCCA[k]))))
	}
	add(
		expect("PROOFS.md", "^- Mode 1 composite container \\(per-region floor `MinPixels = "+num+"` × 3 regions = "+num+" total pixels, `s = ⌈√"+num+"⌉ = "+num+"`, container `"+num+x+num+" = "+num+"`\\): `gap ≥ \\(2"+x+num+" \\+ 1\\)"+x+"7 = "+num+" bytes`, and `\\("+num+" - "+num+"\\)"+x+"7 = "+num+" bytes` at the exact "+num+"-pixel floor",
			w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_s", plain(a.Side-1)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)),
			w("m1_s", plain(a.Side-1)), w("m1_residue", plain(a.Residue)), w("m1_P", plain(a.P)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_residue_floor", plain(a.ResidueAtFloor)), w("m1_floor_px", plain(a.FloorPixels))),
		expect("PROOFS.md", "^- Mode 2 compact container \\(per-container floor `MinPixels = "+num+"`, `s = ⌈√"+num+"⌉ = "+num+"`, container `"+num+x+num+" = "+num+"`\\): `gap ≥ \\(2"+x+num+" \\+ 1\\)"+x+"7 = "+num+" bytes` for payloads ≤ "+num+"² = "+num+" pixels \\(payload ≤ ~"+dec+" KB\\), and `\\("+num+" - "+num+"\\)"+x+"7 = "+num+" bytes` at the exact "+num+"-pixel floor",
			w("minpixels_1024", plain(mp)), w("minpixels_1024", plain(mp)), w("m2_s", plain(b.Side-1)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)),
			w("m2_s", plain(b.Side-1)), w("m2_residue", plain(b.Residue)), w("m2_s", plain(b.Side-1)), w("m2_s_sq", plain((b.Side-1)*(b.Side-1))), w("m2_max_payload_kb", kb(b.MaxPayload)),
			w("m2_P", plain(b.P)), w("minpixels_1024", plain(mp)), w("m2_residue_floor", plain(b.ResidueAtFloor)), w("minpixels_1024", plain(mp))),
		expect("PROOFS.md", `^\| Mode 2 per-container floor \(1024-bit key, P = `+num+`\) \| `+num+` \| `+num+` bytes \(`+num+` bytes at `+num+`-pixel floor\) \|$`,
			w("m2_P", plain(b.P)), w("m2_s", plain(b.Side-1)), w("m2_residue", plain(b.Residue)), w("m2_residue_floor", plain(b.ResidueAtFloor)), w("minpixels_1024", plain(mp))),
		expect("PROOFS.md", `^\| Mode 1 per-region floor \(1024-bit key, P = `+num+`\) \| `+num+` \| `+num+` bytes \(`+num+` bytes at `+num+`-pixel floor\) \|$`,
			w("m1_P", plain(a.P)), w("m1_s", plain(a.Side-1)), w("m1_residue", plain(a.Residue)), w("m1_residue_floor", plain(a.ResidueAtFloor)), w("m1_floor_px", plain(a.FloorPixels))),
		expect("PROOFS.md", `^\| 16 KB \| `+num+` \| `+num+` bytes \|$`, w("s_16KiB", plain(s16k.Side-1)), w("residue_16KiB", plain(s16k.Residue))),
		expect("PROOFS.md", `^\| 1 MB \| `+num+` \| `+num+` bytes \|$`, w("s_1MiB", plain(s1m.Side-1)), w("residue_1MiB", comma(s1m.Residue))),
		expect("PROOFS.md", `^\| 64 MB \| `+num+` \| `+num+` bytes \|$`, w("s_64MiB", comma(s64m.Side-1)), w("residue_64MiB", comma(s64m.Residue))),
		expect("PROOFS.md", `^- A = C\(48, 16\) = \*\*`+num+`\*\* \(log₂ ≈ `+dec+`\)`, w("A", comma(int(f.A.Int64()))), w("log2_A", fixed(f.Log2A, 2))),
		expect("PROOFS.md", `^- B = C\(32, 16\) = \*\*`+num+`\*\* \(log₂ ≈ `+dec+`\)`, w("B", comma(int(f.B.Int64()))), w("log2_B", fixed(f.Log2B, 2))),
		expect("PROOFS.md", `^\|Ω_chunk\| = A · B = `+num+`\s+≈\s+`+p2d+` \.$`, w("AB", commaBig(f.AB)), w("log2_AB", "2^"+log2AB)),
		expect("PROOFS.md", `^gcd\(A, B\) = gcd\(C\(48, 16\), C\(32, 16\)\) = `+num+` = (.+) \.$`, w("gcd", plain(gcd)), w("gcd_factors", f.GCDFactors)),
		expect("PROOFS.md", `cardinality .A · B / d = A · B / `+num+`.\..*\(1 − 1/`+num+`\)`, w("gcd", plain(gcd)), w("gcd", plain(gcd))),
		expect("PROOFS.md", `^1 / `+num+`  ≈  ([\d.]+ × 10⁻.) ,$`, w("gcd", plain(gcd)), w("inv_gcd", sci(invGCD, 1))),
		expect("PROOFS.md", `so ≈ `+dec+` % of the .A × B. mask space would be structurally excluded.*would face a `+num+`×-restricted mask space.*log₂ `+num+` ≈ `+dec+`.-bit erosion`,
			w("excluded_pct", trunc(100*(1-invGCD), 3)), w("gcd", plain(gcd)), w("gcd", plain(gcd)), w("log2_gcd", fixed(f.Log2GCD, 2))),
		expect("PROOFS.md", `relative deviation of \*\*≈ (2\^-\d+\.\d)\*\*.*maximum-size message of .(2\^\d+\.\d+). chunks, the per-message deviation is bounded by \*\*≈ (2\^-\d+\.\d)\*\*.*1 / ε² ≈ (2\^\d+\.\d). chunk samples`,
			w("bias", "2^"+bias), w("max_chunks", "2^"+chunks), w("accum_bias", "2^"+accum), w("sample_budget", "2^"+budget)),
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
		expect("SECURITY.md", `\(Mode 1, P = `+num+`\): classical ~`+p2+`, Grover ~`+p2+` \(under per-container Mode 2, P = `+num+`: classical ~`+p2+`, Grover ~`+p2+`\)`,
			w("m1_P", plain(a.P)), w("classical2_m1", aC1), w("grover2_m1", aG1), w("m2_P", plain(b.P)), w("classical2_m2", bC1), w("grover2_m2", bG1)),
		expect("SECURITY.md", `\(Mode 1, P = `+num+` = 3 × per-region floor `+num+`, square-rounded to `+num+x+num+` with DefaultBarrierFill = `+num+`\): classical ~`+p2+`, Grover ~`+p2+` \(under per-container Mode 2, P = `+num+`: classical ~`+p2+`, Grover ~`+p2+`\)`,
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
			w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", comma(a.P))),
		expect("ITB.md", `Small messages clamp to .MinPixels. total pixels, yielding a `+num+x+num+` container \(`+num+` pixels\) at 1024-bit keys`,
			w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P))),
		expect("ITB.md", "At 1024-bit keys \\(`MinPixels = "+num+"`\\), Mode 1 \\(per-region, `3"+x+num+" = "+num+"` pixels, `s = "+num+"`, container `"+num+x+num+" = "+num+"` pixels\\) yields `gap ≥ "+num+" bytes`; Mode 2 \\(per-container, `totalPixels = "+num+"`, `s = "+num+"`, container `"+num+x+num+" = "+num+"` pixels\\) yields `gap ≥ "+num+" bytes`",
			w("minpixels_1024", plain(mp)), w("minpixels_1024", plain(mp)), w("m1_floor_px", plain(a.FloorPixels)), w("m1_s", plain(a.Side-1)), w("m1_side", plain(a.Side)), w("m1_side", plain(a.Side)), w("m1_P", plain(a.P)), w("m1_residue", plain(a.Residue)),
			w("minpixels_1024", plain(mp)), w("m2_s", plain(b.Side-1)), w("m2_side", plain(b.Side)), w("m2_side", plain(b.Side)), w("m2_P", plain(b.P)), w("m2_residue", plain(b.Residue))),
		expect("ITB.md", "^- `A · B = "+num+"` \\(log₂ ≈ "+dec+"\\)\\.$", w("AB", commaBig(f.AB)), w("log2_AB", log2AB)),
		expect("ITB.md", `the number of preimages per mask triple is .⌊2\^128 / \(A · B\)⌋ ≈ `+p2d+`.`, w("log2_preimages", "2^"+log2Pre)),
		expect("ITB.md", `because .gcd\(A, B\) = gcd\(C\(48, 16\), C\(32, 16\)\) = `+num+` = (.+?)., which would restrict reachable pairs to .1 / `+num+` ≈ ([\d.]+ × 10⁻.). of the space \(eroding .log₂ `+num+` ≈ `+dec+`. bits of entropy\)`,
			w("gcd", comma(gcd)), w("gcd_factors", f.GCDFactors), w("gcd", comma(gcd)), w("inv_gcd", sci(invGCD, 1)), w("gcd", comma(gcd)), w("log2_gcd", fixed(f.Log2GCD, 2))),
		expect("ITB.md", `relative deviation of ≈ (2\^-\d+\.\d) per chunk.*maximum message of (2\^\d+\.\d+) chunks, deviation is bounded by ≈ (2\^-\d+\.\d)\. Detecting this would require ~(2\^\d+\.\d) chunk samples \(~(2\^\d+) maximum-size messages\)`,
			w("bias", "2^"+bias), w("max_chunks", "2^"+chunks), w("accum_bias", "2^"+accum), w("sample_budget", "2^"+budget), w("log2_messages", "2^"+fixed(math.Round(f.Log2Messages), 0))),
		expect("ITB.md", "requires `2\\^\\(62·P\\)` attempts \\(≈ "+p2+" for 1024-bit keys\\)", w("config_m1", pow2(configMap(a.P)))),
		expect("ITB.md", `^\| Min container \(Mode 1, payload ≤ ~`+dec+` KB, 1024-bit key\) \| `+num+` \|`, w("m1_max_payload_kb", kb(a.MaxPayload)), w("m1_P", comma(a.P))),
		expect("ITB.md", `^\| Min container \(Mode 2, payload ≤ ~`+dec+` KB, 1024-bit key\) \| `+num+` \|`, w("m2_max_payload_kb", kb(b.MaxPayload)), w("m2_P", plain(b.P))),
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
		expect("README.md", `^\| Storage overhead \| ~`+dec+`-`+dec+`× from ~10 KB to 64 MiB at 1024-bit keys \(~`+num+`-`+num+`× Mode 1 / ~`+dec+`-`+num+`× Mode 2 for 0\.5-2\.5 KB payloads; Mode 1 ciphertext floor ~`+dec+`KB at 1024-bit keys, ~`+dec+`KB at 512-bit; Mode 2 compact VPN floor ~`+dec+`KB at 1024-bit, ~`+dec+`KB at 512-bit\) \|$`,
			w("expansion_min_10KB_64MiB", expansionMin), w("expansion_max_10KB_64MiB", fixed(f.ExpansionMax, 2)),
			w("expansion_m1_2500B", ex(a.Wire, 2500, 0)), w("expansion_m1_500B", ex(a.Wire, 500, 0)),
			w("expansion_m2_2500B", ex(b.Wire, 2500, 1)), w("expansion_m2_500B", ex(b.Wire, 500, 0)),
			w("m1_wire_kb", kb(a.Wire)), w("m1_wire_kb_512", kb(m1[512].Wire)), w("m2_wire_kb", kb(b.Wire)), w("m2_wire_kb_512", kb(m2[512].Wire))),
		expect("README.md", `^\| Key space \| Up to `+p2+` \|$`, w("max_key_space", pow2(itb.MaxKeyBits))),
		expect("README.md", `deterministic two-step divmod unranking prevents the gcd\(A, B\) = `+num+` anti-collapse trap`, w("gcd", comma(gcd))),
		expect("README.md", `^    ChunkSize: 1 << 20,\s+// 1 MiB \(default `+num+` MiB per profile\)`, w("default_chunk_mib", plain(f.DefaultChunkSize>>20))),
		expect("README.md", "default `itb.DefaultChunkSize` = "+num+" MiB", w("default_chunk_mib", plain(f.DefaultChunkSize>>20))),
	)

	// ----- FAQ.md -----------------------------------------------------
	add(
		sweep("FAQ.md", `512-byte plaintext, `+num+`×`+num+` = `+num+`-pixel container`,
			w("m1_side_512", plain(m1[512].Side)), w("m1_side_512", plain(m1[512].Side)), w("m1_P_512", plain(m1[512].P))),
		expect("FAQ.md", `same 512-byte plaintext / `+num+`×`+num+` = `+num+`-pixel container as Question 1`,
			w("m1_side_512", plain(m1[512].Side)), w("m1_side_512", plain(m1[512].Side)), w("m1_P_512", plain(m1[512].P))),
		expect("FAQ.md", `same 512-byte plaintext / `+num+`×`+num+` container as Question 1`, w("m1_side_512", plain(m1[512].Side)), w("m1_side_512", plain(m1[512].Side))),
		expect("FAQ.md", `where .B = C\(32, 16\) = `+num+`. and .A = C\(48, 16\) = `+num+`.\..*because .gcd\(A, B\) = `+num+`., evaluating both indices directly as .rank mod A. and .rank mod B. would restrict reachable pairs to a `+num+`× smaller subspace \(~`+dec+` bits lost\)`,
			w("B", comma(int(f.B.Int64()))), w("A", comma(int(f.A.Int64()))), w("gcd", comma(gcd)), w("gcd", plain(gcd)), w("log2_gcd", fixed(f.Log2GCD, 2))),
		expect("FAQ.md", `mapping .2\^128. rank values into .`+p2d+`. mask triples`, w("log2_AB", "2^"+log2AB)),
		expect("FAQ.md", `the attacker gets 48 constraints on .≈ `+p2d+`. candidate masks — approximately .`+p2+`. masks remain consistent`,
			w("log2_AB", "2^"+log2AB), w("masks_per_crib", "2^"+fixed(math.Floor(f.Log2AB-48), 0))),
		expect("FAQ.md", `avoiding the .gcd\(A, B\) = `+num+`. anti-collapse trap`, w("gcd", comma(gcd))),
		expect("FAQ.md", `requires enumerating .C\(48, 16\) × C\(32, 16\) ≈ `+p2d+`. preimages`, w("log2_AB", "2^"+log2AB)),
	)

	// ----- REDTEAM.md -------------------------------------------------
	add(
		expect("REDTEAM.md", `^\| Partition constants A = C\(48,16\), B = C\(32,16\) \| `+num+` · `+num+` \|$`, w("A", comma(int(f.A.Int64()))), w("B", comma(int(f.B.Int64())))),
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
		expect("SCIENCE.md", "erasing one bit costs `k_B T ln 2 ≈ ([\\d.]+ × 10⁻..) J`, so a mass-energy budget of ~4 × 10\\^69 J bounds irreversible operations at ~10\\^(\\d+) ≈ "+p2,
			w("landauer_bit_cost", sci(landauerBitCost, 1)), w("landauer_ten_exp", plain(tenExp)), w("landauer", pow2(landauerExp))),
		sweep("SCIENCE.md", `Landauer bound on irreversible enumeration cost \(~`+p2+` ≈ 10\^(\d+)\)`, w("landauer", pow2(landauerExp)), w("landauer_ten_exp", plain(tenExp))),
		expect("PROOFS.md", `Landauer bound on irreversible enumeration cost \(~`+p2+` ≈ 10\^(\d+)\)`, w("landauer", pow2(landauerExp)), w("landauer_ten_exp", plain(tenExp))),
		// ChainHash cascade depth: Pixel Barrier keyBits / width,
		// Interlocked Barrier 1 + keyBits / width (ITB.md § 12).
		expect("SCIENCE.md", "^   - \\*\\*Pixel Barrier:\\*\\* depth `r = keyBits / width` \\("+num+" / "+num+" / "+num+" rounds at width "+num+" for 512 / 1024 / 2048-bit keys\\)",
			w("depth_512_w128", depthAt(512, narrowestWidth)), w("depth_1024_w128", depthAt(1024, narrowestWidth)), w("depth_2048_w128", depthAt(2048, narrowestWidth)), w("narrowest_width", plain(narrowestWidth))),
		expect("ITB.md", "Pixel Barrier operates directly over session components at depth `r = keyBits / width` \\("+num+" / "+num+" / "+num+" rounds at width 128 for 512 / 1024 / 2048-bit keys; "+num+" / "+num+" / "+num+" at width 256; "+num+" / "+num+" / "+num+" at width 512\\), without an intermediate key\\. The Interlocked Barrier operates at depth `r = 1 \\+ keyBits / width` \\("+num+" / "+num+" / "+num+" rounds at width 128; "+num+" / "+num+" / "+num+" at width 256; "+num+" / "+num+" / "+num+" at width 512\\)",
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
		expect("doc.go", `concatenated chunk stream one chunk at a time behind the `+num+`-byte$`, w("prefix", plain(f.Prefix))),
		expect("doc.go", `^// `+num+`-byte prefix and continues with one or more chunks`, w("prefix", plain(f.Prefix))),
	)

	// ----- repeated constants, swept per file -------------------------
	// The leading digit in these patterns separates the two mask-space
	// exponents that share one spelling; a drift past that digit reports
	// NOT FOUND, which fails the check as a STALE figure would.
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md", "ITB.md", "README.md", "FAQ.md", "REDTEAM.md", "HWTHREATS.md", "doc.go"} {
		add(sweep(file, `(2\^7\d\.\d\d)`, w("log2_AB", "2^"+log2AB)))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md", "ITB.md", "FAQ.md", "REDTEAM.md"} {
		add(sweep(file, `(2\^5\d\.\d\d)`, w("log2_preimages", "2^"+log2Pre)))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "ITB.md", "FAQ.md", "REDTEAM.md"} {
		add(sweep(file, `(2\^-5\d\.\d)\b`, w("bias", "2^"+bias)))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "ITB.md", "REDTEAM.md"} {
		add(sweep(file, `(2\^-3\d\.\d)\b`, w("accum_bias", "2^"+accum)))
		add(sweep(file, `(2\^1\d\d\.\d)\b`, w("sample_budget", "2^"+budget)))
	}
	for _, file := range []string{"SCIENCE.md", "PROOFS.md", "SECURITY.md"} {
		add(sweep(file, `~(2\^3\d\d)\b`, w("landauer", pow2(landauerExp))))
	}
	for _, file := range []string{"SCIENCE.md", "ITB.md", "README.md", "FAQ.md", "REDTEAM.md", "SECURITY.md"} {
		add(sweep(file, `\b(66,\d{3})\b`, w("gcd", comma(gcd))))
	}
	for _, file := range []string{"PROOFS.md", "FAQ.md", "REDTEAM.md", "HARNESS.md"} {
		add(sweep(file, `\b(66\d{3})\b`, w("gcd", plain(gcd))))
	}
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
