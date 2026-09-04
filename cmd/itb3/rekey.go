package main

// `itb3 rekey blob.json [-p] [-w] [-o ublob.json]` rotates the outer
// parallax / wrapper masters, leaving the eight inner ITB seeds and
// the MAC key untouched. The `-p` / `-w` toggles are assertions
// against the blob's recorded state; a mismatch is a hard error.

import (
	"crypto/rand"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/everanium/itb/parallax"
)

// rekeyOpts collects the rekey-subcommand flag values.
type rekeyOpts struct {
	parallax   bool
	wrapper    bool
	outputPath string
}

// newRekeyCmd wires the `itb3 rekey` cobra command.
func newRekeyCmd() *cobra.Command {
	var opts rekeyOpts
	cmd := &cobra.Command{
		Use:   "rekey <blob.json> [flags]",
		Short: "Rotate the outer parallax / wrapper masters",
		Args:  cobra.ExactArgs(1),
		Long: `Read the blob at <blob.json>, reconstruct the pipeline, invoke
Pipeline.Rekey with fresh masters drawn from crypto/rand, and write
the refreshed blob to -o (created with mode 0600; stdout when the
flag is omitted).

The -p / -w toggles are STRICT ASSERTIONS of the blob's recorded
layer state, not overrides. A mismatch is rejected:

    blob has parallax off  + -p supplied     → error
    blob has parallax on   + no -p           → error
    blob has wrapper  off  + -w supplied     → error
    blob has wrapper  on   + no -w           → error

The input path and -o path MAY be identical (the blob is read
fully into memory before the output file is opened).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRekey(args[0], opts)
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&opts.parallax, "parallax", "p", false, "assert blob has parallax ON (required when so; refused when not)")
	f.BoolVarP(&opts.wrapper, "wrapper", "w", false, "assert blob has wrapper ON (required when so; refused when not)")
	f.StringVarP(&opts.outputPath, "output", "o", "", "output refreshed blob file (default stdout)")
	return cmd
}

// runRekey is the rekey handler body.
func runRekey(blobPath string, opts rekeyOpts) error {
	pipe, prof, err := loadPipeline("rekey", blobPath)
	if err != nil {
		return err
	}
	defer pipe.Close()

	// Strict-assertion matrix — blob always wins.
	switch {
	case prof.Parallax && !opts.parallax:
		return usageErr("rekey", "parallax toggle assertion missing: blob has parallax on, `-p` required")
	case !prof.Parallax && opts.parallax:
		return usageErr("rekey", "parallax toggle mismatch: blob has parallax off, `-p` supplied")
	case prof.Wrapper && !opts.wrapper:
		return usageErr("rekey", "wrapper toggle assertion missing: blob has wrapper on, `-w` required")
	case !prof.Wrapper && opts.wrapper:
		return usageErr("rekey", "wrapper toggle mismatch: blob has wrapper off, `-w` supplied")
	}
	if !prof.Parallax && !prof.Wrapper {
		return usageErr("rekey", "no rotatable masters — this blob has both parallax and wrapper disabled; rekey is a no-op")
	}

	permMaster, wrapMaster, err := freshMasters(prof.Parallax, prof.Wrapper)
	if err != nil {
		return runtimeErr("rekey", "%v", err)
	}
	fresh, err := pipe.Rekey(permMaster, wrapMaster)
	if err != nil {
		return classifyCryptoError("rekey", err)
	}
	defer clear(fresh)

	// The Pipeline retains the refreshed blob, so SaveF writes exactly
	// the bytes Rekey returned.
	if opts.outputPath != "" {
		if err := pipe.SaveF(opts.outputPath); err != nil {
			return runtimeErr("rekey", "write %q: %v", opts.outputPath, err)
		}
		return nil
	}
	return writeOutputBytes("rekey", "", fresh)
}

// freshMasters draws a new parallax master + a new wrapper master
// from crypto/rand, one 32-byte wrapper master and a
// [parallax.GenerateMasterKey] parallax master.
func freshMasters(parallaxOn, wrapperOn bool) (perm []byte, wrap []byte, err error) {
	if parallaxOn {
		perm, err = parallax.GenerateMasterKey()
		if err != nil {
			return nil, nil, fmt.Errorf("parallax.GenerateMasterKey: %w", err)
		}
	}
	if wrapperOn {
		wrap = make([]byte, 32)
		if _, err = rand.Read(wrap); err != nil {
			return nil, nil, fmt.Errorf("crypto/rand: %w", err)
		}
	}
	return perm, wrap, nil
}
