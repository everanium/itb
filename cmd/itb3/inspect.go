package main

// `itb3 inspect blob.json [-o dump.json]` decodes the wrap-layer via
// triple.Inspect — no Pipeline is opened — and prints the embedded
// profile record as a human-readable metadata dump. Never emits secret
// material: the record carries no key bytes, and master presence is
// implied by the layer toggles (a producer emits a master iff the
// corresponding layer is on).

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/everanium/itb/triple"
)

// inspectOpts collects the inspect-subcommand flag values.
type inspectOpts struct {
	outputPath string
}

// newInspectCmd wires the `itb3 inspect` cobra command.
func newInspectCmd() *cobra.Command {
	var opts inspectOpts
	cmd := &cobra.Command{
		Use:   "inspect <blob.json> [flags]",
		Short: "Print blob metadata (no secret material)",
		Args:  cobra.ExactArgs(1),
		Long: `Decode the wrap-layer of <blob.json> and print the embedded profile
record as a human-readable metadata dump — one field: value pair per
line. No Pipeline is opened and no secret material is printed.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInspect(args[0], opts)
		},
	}
	cmd.Flags().StringVarP(&opts.outputPath, "output", "o", "", "output dump file (default stdout)")
	return cmd
}

// runInspect is the inspect handler body.
func runInspect(blobPath string, opts inspectOpts) error {
	blob, err := readBlobFile("inspect", blobPath)
	if err != nil {
		return err
	}
	defer clear(blob)
	prof, err := triple.Inspect(blob)
	if err != nil {
		return classifyLoadError("inspect", err)
	}
	dst, dstCloser, err := openOutputWriter("inspect", opts.outputPath)
	if err != nil {
		return err
	}
	if dstCloser != nil {
		defer dstCloser.Close()
	}
	renderInspect(prof, len(blob), dst)
	return nil
}

// renderInspect writes the profile record field by field to out.
// Optional fields the record leaves at zero are printed with an
// explicit "(default)" / "(none)" marker so a reader can tell an
// omitted value from a set one.
func renderInspect(prof triple.Profile, blobLen int, out io.Writer) {
	fmt.Fprintf(out, "profile: %s\n", prof.Name)
	fmt.Fprintf(out, "mode: %s\n", prof.Mode)
	fmt.Fprintf(out, "width: %d\n", prof.Width)
	if isMixedConstellation(prof.MixedHashes) {
		fmt.Fprintf(out, "mixed_hashes: %s\n", strings.Join(prof.MixedHashes[:], ","))
	} else {
		fmt.Fprintf(out, "inner_hash: %s\n", prof.InnerHash)
	}
	fmt.Fprintf(out, "key_bits: %d\n", prof.KeyBits)
	if prof.MacName != "" {
		fmt.Fprintf(out, "mac_name: %s\n", prof.MacName)
	} else {
		fmt.Fprintln(out, "mac_name: (none)")
	}
	if prof.TagStubSize > 0 {
		fmt.Fprintf(out, "tag_stub_size: %d\n", prof.TagStubSize)
	}
	if isStreamingMode(prof.Mode) {
		if prof.ChunkSize > 0 {
			fmt.Fprintf(out, "chunk_size: %d\n", prof.ChunkSize)
		} else {
			fmt.Fprintln(out, "chunk_size: (default)")
		}
	}
	fmt.Fprintf(out, "wrapper: %v\n", prof.Wrapper)
	if prof.Wrapper {
		fmt.Fprintf(out, "wrapper_cipher: %s\n", prof.OuterCipher)
	}
	fmt.Fprintf(out, "parallax: %v\n", prof.Parallax)
	if prof.Parallax {
		fmt.Fprintf(out, "parallax_palette: %s\n", strings.Join(prof.ParallaxPalette, ","))
		if prof.ParallaxSegmentSize > 0 {
			fmt.Fprintf(out, "parallax_segment_size: %d\n", prof.ParallaxSegmentSize)
		} else {
			fmt.Fprintln(out, "parallax_segment_size: (default)")
		}
	}
	fmt.Fprintf(out, "blob_bytes: %d\n", blobLen)
}

// isMixedConstellation reports whether any MixedHashes slot is
// populated — the record's mixed-vs-single dispatch discriminator.
func isMixedConstellation(slots [8]string) bool {
	for _, s := range slots {
		if s != "" {
			return true
		}
	}
	return false
}
