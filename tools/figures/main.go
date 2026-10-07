// Command figures computes every deterministic figure the documentation
// publishes — container floors, wire sizes, payload thresholds,
// ambiguity and noise-barrier exponents, DRBG residue, brute-force
// bounds, Rank Barrier mask-space constants — from the library itself,
// and checks the documentation against the computed values.
//
// Usage:
//
//	figures            print every figure, grouped, at the compiled-in defaults
//	figures -check     compare the documentation under -root against the
//	                   computed figures; one line per expectation, exit 1
//	                   on any STALE or NOT FOUND
//	figures -root DIR  repository root (default ".")
//
// Measured figures go through the public Single Message Encrypt API at
// [itb.DefaultNonceBits] / [itb.DefaultBarrierFill] under both
// container floor sizing modes; formula figures implement the
// documented formula once, with the source section named at the
// computation site. The checker holds a registry of expectations —
// file, a locator anchored on the surrounding text, and the exact
// spelling the site uses — and never edits a document.
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"text/tabwriter"

	"github.com/everanium/itb"
	"github.com/everanium/itb/wrapper"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("figures", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	check := fs.Bool("check", false, "check the documentation against the computed figures")
	root := fs.String("root", ".", "repository root the documentation is read from")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	f, err := Compute()
	if err != nil {
		fmt.Fprintf(os.Stderr, "figures: %v\n", err)
		return 2
	}
	if *check {
		results, ok := Check(*root, Registry(f))
		Report(os.Stdout, results)
		if !ok {
			return 1
		}
		return 0
	}
	Print(os.Stdout, f)
	return 0
}

// Print writes every figure as grouped tables.
func Print(out *os.File, f *Figures) {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	defer tw.Flush()
	row := func(cols ...any) {
		for i, c := range cols {
			if i > 0 {
				fmt.Fprint(tw, "\t")
			}
			fmt.Fprint(tw, c)
		}
		fmt.Fprintln(tw)
	}
	section := func(title string) {
		fmt.Fprintf(tw, "\n== %s\n", title)
	}

	section("Parameters")
	row("inner hash", innerHash)
	row("NonceBits", f.NonceBits, fmt.Sprintf("N = %d bytes", f.NonceBytes))
	row("BarrierFill", f.BarrierFill)
	row("stream prefix", fmt.Sprintf("%d B", f.Prefix))
	row("chunk header N + 4", fmt.Sprintf("%d B", f.HeaderSize))
	for bits := 128; bits <= 512; bits *= 2 {
		row(fmt.Sprintf("header / per-pixel buffer at %d-bit nonce", bits), fmt.Sprintf("%d B", f.HeaderSizes[bits]))
	}
	row("Single Message wire", "prefix + N + 4 + W·H·8")
	row("max Single Message payload", fmt.Sprintf("%d B (%d MiB)", f.MaxMessage, f.MaxMessage>>20))
	row("DefaultChunkSize", fmt.Sprintf("%d B (%d MiB)", f.DefaultChunkSize, f.DefaultChunkSize>>20))
	row("birthday bound at default nonce", "2^"+plain(f.NonceBits/2), "dual-slot 2^"+plain(f.NonceBits))

	section("Container floors (Single Message, wrapper and parallax off)")
	row("key", "MinPixels", "P_region ≥ (no CCA)", "mode", "floor px", "raw side", "side", "P", "wire", "wire KB", "max payload", "payload KB", "residue ≥", "at floor")
	for _, k := range keySizes {
		for _, mode := range modes {
			ff := f.Floor[k][mode]
			row(k, f.MinPixels[k], f.ThresholdNoCCA[k], mode, ff.FloorPixels, ff.RawSquare, dims(ff.Side), ff.P, ff.Wire, "~"+kb(ff.Wire)+" KB", ff.MaxPayload, "~"+kb(ff.MaxPayload)+" KB", ff.Residue, ff.ResidueAtFloor)
		}
		th := f.Theoretical[k]
		row(k, f.MinPixels[k], f.ThresholdNoCCA[k], "theoretical", th.FloorPixels, th.RawSquare, dims(th.Side), th.P, "–", "–", "–", "–", th.Residue, th.ResidueAtFloor)
	}
	row("Mode 2 vs Mode 1 wire")
	for _, k := range keySizes {
		row(k, pct(f.Floor[k][1].Wire, f.Floor[k][2].Wire)+"%")
	}
	row("512-bit Mode 2 at 1460 B payload", dims(f.MTU512.Side), f.MTU512.P, fmt.Sprintf("%d B", f.MTU512.Wire))

	section("Data-size rows (1024-bit key, Mode 1)")
	row("payload", "bytes", "side", "s", "P", "wire", "expansion", "residue ≥ (2s+1)·7", "7^P", "vs 2^1024", "56^P", "vs 2^1024", "2^(8P)")
	for _, r := range f.Sizes {
		row(r.Label, r.N, dims(r.Side), r.Side-1, comma(r.P), comma(r.Wire), fixed(float64(r.Wire)/float64(r.N), 3), comma(r.Residue),
			pow2c(log2Pow(7, r.P)), ratio(float64(log2Pow(7, r.P))/1024), pow2c(log2Pow(56, r.P)), ratio(float64(log2Pow(56, r.P))/1024), pow2c(noiseBarrier(r.P)))
	}

	row("expansion max over [10,000 B, 64 MiB]", fixed(f.ExpansionMax, 4), fmt.Sprintf("at %d B", f.ExpansionMaxAt))
	row("expansion min over [10,000 B, 64 MiB]", "≥ "+fixed(f.ExpansionMin, 4), "≤ "+fixed(f.ExpansionMinEnd, 4)+" (at 64 MiB)")

	section("Barrier strength at the 1024-bit floors")
	a, b, t := f.Floor[1024][1], f.Floor[1024][2], f.Theoretical[1024]
	row("metric", "Mode 2", "Mode 1", "theoretical")
	row("container", dims(b.Side), dims(a.Side), dims(t.Side))
	row("P", b.P, a.P, t.P)
	row("noise barrier 2^(8P)", pow2c(noiseBarrier(b.P)), pow2c(noiseBarrier(a.P)), pow2c(noiseBarrier(t.P)))
	row("margin over 2^1024", pow2c(noiseBarrier(b.P)-1024), pow2c(noiseBarrier(a.P)-1024), pow2c(noiseBarrier(t.P)-1024))
	row("56^P", pow2c(log2Pow(56, b.P)), pow2c(log2Pow(56, a.P)), pow2c(log2Pow(56, t.P)))
	row("7^P", pow2c(log2Pow(7, b.P)), pow2c(log2Pow(7, a.P)), pow2c(log2Pow(7, t.P)))
	row("config map 2^(62P)", pow2c(configMap(b.P)), pow2c(configMap(a.P)), pow2c(configMap(t.P)))
	row("residue ≥ / at floor", fmt.Sprintf("%d / %d", b.Residue, b.ResidueAtFloor), fmt.Sprintf("%d / %d", a.Residue, a.ResidueAtFloor), fmt.Sprintf("%d / %d", t.Residue, t.ResidueAtFloor))
	le := float64(landauerExp)
	row("vs Landauer "+pow2(landauerExp), ratio(float64(noiseBarrier(b.P))/le), ratio(float64(noiseBarrier(a.P))/le), ratio(float64(noiseBarrier(t.P))/le))
	for _, m := range []int{2, 1} {
		label := "Core ITB (2 seeds)"
		if m == 1 {
			label = "MAC + Reveal (1 seed)"
		}
		bc, bg := bruteForce(b.P, 1024, m)
		ac, ag := bruteForce(a.P, 1024, m)
		tc, tg := bruteForce(t.P, 1024, m)
		row(label+" classical", "~2^"+fixed(bc, 2), "~2^"+fixed(ac, 2), "~2^"+fixed(tc, 2))
		row(label+" Grover", "~2^"+fixed(bg, 2), "~2^"+fixed(ag, 2), "~2^"+fixed(tg, 2))
	}

	section("Per-pixel accounting")
	ch, db, nc, dc := itb.Channels, itb.DataBitsPerPixel, itb.NoiseConfigBits, itb.DataConfigBits
	row("channels / data bits / noise bits per pixel", ch, db, ch)
	row("noise share", fixed(100.0/float64(ch), 1)+" %", "data "+fixed(100-100.0/float64(ch), 1)+" %")
	row("config bits (noise + data = total)", nc, dc, nc+dc)
	row("CCA leak noise / total", fixed(100*float64(nc)/float64(nc+dc), 1)+" %")
	row("noise overhead 8/7", fixed(float64(ch)/float64(itb.DataBitsPerChannel), 2)+"×", "8/56 ≈ "+fixed(100*float64(ch)/float64(db), 1)+" %")
	row("log2(7)", fixed(math.Log2(7), 3), "8 / log2(7)", fixed(8/math.Log2(7), 3))
	for _, wd := range shippedWidths {
		row(fmt.Sprintf("ChainHash depth at width %d (Pixel / Interlocked)", wd),
			fmt.Sprintf("512: %d / %d", 512/wd, 1+512/wd), fmt.Sprintf("1024: %d / %d", 1024/wd, 1+1024/wd), fmt.Sprintf("2048: %d / %d", 2048/wd, 1+2048/wd))
	}
	row("Landauer: k_B T ln 2 at "+fixed(cmbKelvin, 1)+" K", sci(landauerBitCost, 3)+" J", "ops bound "+sci(landauerOps, 2), "log2 "+fixed(math.Log2(landauerOps), 2))

	section("Rank Barrier mask space")
	row("A = C(48, 16)", commaBig(f.A), "log2 "+fixed(f.Log2A, 2))
	row("B = C(32, 16)", commaBig(f.B), "log2 "+fixed(f.Log2B, 2))
	row("A · B", commaBig(f.AB), "2^"+fixed(f.Log2AB, 2))
	row("gcd(A, B)", commaBig(f.GCD), f.GCDFactors, "log2 "+fixed(f.Log2GCD, 2), "1/gcd "+sci(1/float64(f.GCD.Int64()), 3))
	row("excluded under naive double-mod", trunc(100*(1-1/float64(f.GCD.Int64())), 3)+" %")
	row("preimages ⌊2^128 / (A · B)⌋", commaBig(f.Preimages), "2^"+fixed(f.Log2Preimage, 2))
	row("per-chunk bias", "2^"+fixed(-f.Log2Preimage, 1))
	row("max chunks per message", comma(f.MaxChunks), "2^"+fixed(f.Log2Chunks, 2))
	row("accumulated bias", "2^"+fixed(f.AccumBias, 1))
	row("distinguisher sample budget", "2^"+fixed(f.SampleBudget, 1)+" chunks", "~2^"+fixed(f.Log2Messages, 1)+" messages")
	row("masks consistent with one 48-bit crib", "2^"+fixed(f.Log2AB-48, 1))

	section("Wrapper nonce per outer cipher")
	for _, name := range wrapper.CipherNames {
		row(name, fmt.Sprintf("%d B", f.WrapperNonce[name]))
	}
}
