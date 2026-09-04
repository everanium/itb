package main

// `itb3 genblob <mode> <hash>` folds every flag into a triple.Profile
// literal, registers it under a descriptive handle, builds a fresh
// triple.Pipeline against that handle, and writes the resulting blob
// to the output destination. The blob carries the resolved profile
// record itself, so a receiver reconstructs the full session shape
// with triple.Load without any side-channel.

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/spf13/cobra"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/triple"
)

// genblobOpts collects the values cobra populates for the genblob
// flag set. Kept as a struct so the handler is a plain function that
// takes explicit inputs rather than reading global mutable state.
type genblobOpts struct {
	chunkSizeMB int
	keyBits     int
	nonceBits   int
	barrierFill int
	mac         string
	palette     []string
	segment     int
	wrapper     string
	output      string
}

// genblobFlagsSet records which optional flags were explicitly
// supplied — the handler distinguishes "flag omitted" from "flag set
// to its default" for the toggles and the chunk size.
type genblobFlagsSet struct {
	chunk   bool
	segment bool
	palette bool
	wrapper bool
	mac     bool
}

// newGenblobCmd wires the `itb3 genblob` cobra command.
func newGenblobCmd() *cobra.Command {
	var opts genblobOpts
	cmd := &cobra.Command{
		Use:   "genblob <mode> <hash> [flags]",
		Short: "Generate a fresh session blob",
		Args:  cobra.ExactArgs(2),
		Long: `Build a fresh triple.Pipeline against the supplied <mode> and
<hash>, discard the Pipeline, and write the returned wrap-layer JSON
blob to -o (or stdout when the flag is omitted). The blob embeds the
resolved profile record, so any receiver reconstructs the session
with triple.Load (or itb3 encrypt / decrypt) without registering
anything.

<mode>
    mac      Single Message MAC             (singlemsg-mac)
    nomac    Single Message No MAC          (singlemsg-nomac)
    aead     Streaming AEAD                 (streaming-aead)
    noaead   Streaming Non-AEAD             (streaming-noaead)

<hash>
    A shipped primitive name (see itb3 hashes), OR one of the mixed
    pseudonyms:
      mixed128 / mixed256 / mixed512
    A mixed pseudonym selects a per-call random 8-slot MixedHashes
    constellation drawn uniformly from every width-matching primitive
    in hashes.Registry.

Flag semantics:

    -c 1..64      ChunkSize (MB) — only valid for aead/noaead
                  (default 16 MiB — inherited from
                  itb.DefaultChunkSize when the flag is omitted)
    -k 512|1024|2048   KeyBits (default 1024)
    -n 128|256|512     NonceBits (default 512)
    -b 1|2|4|8|16|32   BarrierFill (default 1)
    -m <mac>      MAC primitive — REQUIRED for mac/aead;
                  FORBIDDEN for nomac/noaead
    -p a,b,c      Parallax palette (comma-list of shipped cipher
                  names, size parallax.MinPaletteSize ..
                  parallax.MaxPaletteSize)
    -s <int>      Parallax segment size (positive, coprime with 504,
                  <= 65535); presets: 17, 257, 4093, 16381, 65531.
                  Requires -p to be present.
    -w <cipher>   Wrapper outer cipher — single name from ciphers.
    -o <file>     Output file (created with mode 0600). Omitted → stdout.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			set := genblobFlagsSet{
				chunk:   cmd.Flag("chunk").Changed,
				segment: cmd.Flag("segment").Changed,
				palette: cmd.Flag("palette").Changed,
				wrapper: cmd.Flag("wrapper").Changed,
				mac:     cmd.Flag("mac").Changed,
			}
			return runGenblob(args[0], args[1], opts, set)
		},
	}
	f := cmd.Flags()
	f.IntVarP(&opts.chunkSizeMB, "chunk", "c", 16, "chunk size in MB (1..64; default 16 MiB via itb.DefaultChunkSize), only for aead/noaead modes")
	f.IntVarP(&opts.keyBits, "keybits", "k", 1024, "KeyBits — 512|1024|2048")
	f.IntVarP(&opts.nonceBits, "noncebits", "n", 512, "NonceBits — 128|256|512")
	f.IntVarP(&opts.barrierFill, "barrier", "b", 1, "BarrierFill — 1|2|4|8|16|32")
	f.StringVarP(&opts.mac, "mac", "m", "", "MAC primitive name")
	f.StringSliceVarP(&opts.palette, "palette", "p", nil, "parallax palette (comma-list)")
	f.IntVarP(&opts.segment, "segment", "s", parallax.DefaultSegmentSize, "parallax segment size (positive, coprime-504)")
	f.StringVarP(&opts.wrapper, "wrapper", "w", "", "wrapper outer cipher")
	f.StringVarP(&opts.output, "output", "o", "", "output blob file (default stdout)")
	return cmd
}

// runGenblob is the handler body — split out of the RunE closure so
// the flag-parsing side stays boilerplate and the crypto path is
// linear.
func runGenblob(modeArg string, hashArg string, opts genblobOpts, set genblobFlagsSet) error {
	mode, err := parseCLIMode(modeArg)
	if err != nil {
		return usageErr("genblob", "%v", err)
	}
	isMAC := mode == "singlemsg-mac" || mode == "streaming-aead"
	isStreaming := isStreamingMode(mode)

	if isMAC && !set.mac {
		return usageErr("genblob", "mode %q requires `-m <mac>`", modeArg)
	}
	if !isMAC && set.mac {
		return usageErr("genblob", "mode %q rejects `-m` (No MAC by definition)", modeArg)
	}
	if !isStreaming && set.chunk {
		return usageErr("genblob", "chunk-size meaningless for message modes")
	}
	if set.segment && !set.palette {
		return usageErr("genblob", "`-s` supplied without `-p` — segment size only meaningful with parallax palette")
	}

	if err := validateKeyBits(opts.keyBits); err != nil {
		return usageErr("genblob", "%v", err)
	}
	if err := validateNonceBits(opts.nonceBits); err != nil {
		return usageErr("genblob", "%v", err)
	}
	if err := validateBarrierFill(opts.barrierFill); err != nil {
		return usageErr("genblob", "%v", err)
	}
	if isStreaming && set.chunk {
		if err := validateChunkSizeMB(opts.chunkSizeMB); err != nil {
			return usageErr("genblob", "%v", err)
		}
	}

	// Hash argument may be a shipped primitive name OR a mixed
	// pseudonym; the resolver returns the width plus either the single
	// primitive name or the 8-slot constellation.
	width, innerHash, mixedHashes, err := resolveHashPositional(hashArg)
	if err != nil {
		return usageErr("genblob", "%v", err)
	}

	// MAC primitive.
	macName := ""
	if isMAC {
		if _, ok := macs.Find(opts.mac); !ok {
			return usageErr("genblob", "MAC primitive %q not in shipped macs.Registry", opts.mac)
		}
		macName = opts.mac
	}

	// Wrapper toggle + outer cipher name.
	wrapperOn := set.wrapper
	outerCipher := ""
	if wrapperOn {
		if !isShippedCipher(opts.wrapper) {
			return usageErr("genblob", "cipher %q is not a shipped outer cipher", opts.wrapper)
		}
		outerCipher = opts.wrapper
	}

	// Parallax toggle + palette / segment size.
	parallaxOn := set.palette
	var palette []string
	segSize := 0
	if parallaxOn {
		if len(opts.palette) < parallax.MinPaletteSize {
			return usageErr("genblob", "parallax palette size %d below minimum %d",
				len(opts.palette), parallax.MinPaletteSize)
		}
		if len(opts.palette) > parallax.MaxPaletteSize {
			return usageErr("genblob", "parallax palette size %d exceeds parallax.MaxPaletteSize=%d",
				len(opts.palette), parallax.MaxPaletteSize)
		}
		for i, entry := range opts.palette {
			if !isShippedCipher(entry) {
				return usageErr("genblob", "palette[%d]: cipher %q is not a shipped outer cipher", i, entry)
			}
		}
		if opts.segment <= 0 || opts.segment > parallax.MaxSegmentSize {
			return usageErr("genblob", "segment %d out of range (1..%d)", opts.segment, parallax.MaxSegmentSize)
		}
		if !coprime504(opts.segment) {
			return usageErr("genblob", "segment %d not coprime with 504 (divisible by 2, 3, or 7)", opts.segment)
		}
		palette = append([]string(nil), opts.palette...)
		segSize = opts.segment
	}

	chunkBytes := 0
	if isStreaming && set.chunk {
		chunkBytes = opts.chunkSizeMB * 1024 * 1024
	}

	// Every structural field rides on the Profile record; only the
	// two Config-level knobs (NonceBits / BarrierFill) go through Opts.
	prof := triple.Profile{
		Mode:                mode,
		Width:               width,
		InnerHash:           innerHash,
		MixedHashes:         mixedHashes,
		KeyBits:             opts.keyBits,
		MacName:             macName,
		OuterCipher:         outerCipher,
		Wrapper:             wrapperOn,
		ParallaxPalette:     palette,
		ParallaxSegmentSize: segSize,
		Parallax:            parallaxOn,
		ChunkSize:           chunkBytes,
	}
	name, err := registerGenblobProfile(modeArg, hashArg, prof)
	if err != nil {
		return err
	}

	pipe, blob, err := triple.Init(name, triple.Opts{
		NonceBits:   opts.nonceBits,
		BarrierFill: opts.barrierFill,
	})
	if err != nil {
		return runtimeErr("genblob", "triple.Init: %v", err)
	}
	defer pipe.Close()
	defer clear(blob)

	if opts.output != "" {
		if err := pipe.SaveF(opts.output); err != nil {
			return runtimeErr("genblob", "write %q: %v", opts.output, err)
		}
		return nil
	}
	return writeOutputBytes("genblob", "", blob)
}

// registerGenblobProfile installs prof in the profile catalogue under
// the descriptive handle `itb3-<mode>-<hash>` and returns the name
// used. The handle is the label a receiver sees on the inspect
// profile line; it is never consulted on the reopen path. The CLI
// executes as a fresh process per invocation, so a collision on the
// handle only happens under in-process re-entry (unit tests,
// embedding) and surfaces as triple.ErrProfileExists.
func registerGenblobProfile(modeArg, hashArg string, prof triple.Profile) (string, error) {
	name := "itb3-" + modeArg + "-" + hashArg
	if err := triple.Register(name, prof); err != nil {
		return "", fmt.Errorf("triple.Register(%q): %w", name, err)
	}
	return name, nil
}

// parseCLIMode translates the CLI-visible mode token to the
// triple.Profile.Mode string the library dispatches on.
func parseCLIMode(name string) (string, error) {
	switch name {
	case "mac":
		return "singlemsg-mac", nil
	case "nomac":
		return "singlemsg-nomac", nil
	case "aead":
		return "streaming-aead", nil
	case "noaead":
		return "streaming-noaead", nil
	}
	return "", fmt.Errorf("unknown mode %q — accepted: mac, nomac, aead, noaead", name)
}

// isStreamingMode reports whether a triple.Profile.Mode string selects
// the streaming cipher surface.
func isStreamingMode(mode string) bool {
	return mode == "streaming-aead" || mode == "streaming-noaead"
}

// resolveHashPositional translates the <hash> argument to the Profile
// fields: the width plus either a single InnerHash name or a populated
// MixedHashes constellation. A mixed pseudonym triggers the random
// draw over the corresponding width-matching pool.
func resolveHashPositional(name string) (width int, innerHash string, mixed [8]string, err error) {
	if strings.HasPrefix(name, "mixed") {
		var w hashes.Width
		switch name {
		case "mixed128":
			w = hashes.W128
		case "mixed256":
			w = hashes.W256
		case "mixed512":
			w = hashes.W512
		default:
			err = fmt.Errorf("unknown mixed pseudonym %q — accepted: mixed128, mixed256, mixed512", name)
			return
		}
		mixed, err = randomMixedConstellation(w)
		return int(w), "", mixed, err
	}
	spec, ok := hashes.Find(name)
	if !ok {
		err = fmt.Errorf("hash %q not in shipped hashes.Registry", name)
		return
	}
	return int(spec.Width), name, mixed, nil
}

// randomMixedConstellation draws a uniform 8-slot random assignment
// from the width-matching pool via crypto/rand. Repeats across slots
// are permitted — the library's mixed-primitive constraint is
// uniform-width, not 8-distinct.
func randomMixedConstellation(w hashes.Width) ([8]string, error) {
	var out [8]string
	pool := filterHashesByWidth(w)
	if len(pool) == 0 {
		return out, fmt.Errorf("mixed pool for width %d is empty (no shipped primitive matches)", int(w))
	}
	max := big.NewInt(int64(len(pool)))
	for i := range out {
		nBig, err := rand.Int(rand.Reader, max)
		if err != nil {
			return out, fmt.Errorf("crypto/rand.Int: %w", err)
		}
		out[i] = pool[int(nBig.Int64())]
	}
	return out, nil
}

// isShippedCipher reports whether name is a shipped hashes.Registry
// entry (hashes.Names) — the outer cipher / palette alphabet.
// User-registered primitives are deliberately excluded: the ctr
// keystream constructors accept shipped names only.
func isShippedCipher(name string) bool {
	for _, n := range hashes.Names() {
		if n == name {
			return true
		}
	}
	return false
}

// validateKeyBits enforces the CLI-visible KeyBits enum.
func validateKeyBits(k int) error {
	switch k {
	case 512, 1024, 2048:
		return nil
	}
	return fmt.Errorf("keybits %d not in {512, 1024, 2048}", k)
}

// validateNonceBits enforces the CLI-visible NonceBits enum.
func validateNonceBits(n int) error {
	switch n {
	case 128, 256, 512:
		return nil
	}
	return fmt.Errorf("noncebits %d not in {128, 256, 512}", n)
}

// validateBarrierFill enforces the CLI-visible BarrierFill enum.
func validateBarrierFill(b int) error {
	switch b {
	case 1, 2, 4, 8, 16, 32:
		return nil
	}
	return fmt.Errorf("barrier %d not in {1, 2, 4, 8, 16, 32}", b)
}

// validateChunkSizeMB enforces the CLI-visible ChunkSize range (1..64 MB).
func validateChunkSizeMB(mb int) error {
	if mb < 1 || mb > 64 {
		return fmt.Errorf("chunk size %d MB out of range (1..64)", mb)
	}
	return nil
}

// coprime504 reports whether n is coprime with 504 — divisibility by
// 2, 3, or 7 is the disqualifier; anything else is accepted. Mirrors
// the same rule triple.Register applies.
func coprime504(n int) bool {
	if n <= 0 {
		return false
	}
	if n%2 == 0 || n%3 == 0 || n%7 == 0 {
		return false
	}
	return true
}
