package main

// `itb3 encrypt blob.json [-i FILE] [-o FILE]` reads plaintext from
// the input source, reconstructs the pipeline from the blob via
// triple.Load, dispatches to EncryptMessage or EncryptStream depending
// on the blob's profile mode, and writes ciphertext to the output
// destination.

import (
	"github.com/spf13/cobra"
)

// encryptOpts collects the encrypt-subcommand flag values.
type encryptOpts struct {
	inputPath  string
	outputPath string
}

// newEncryptCmd wires the `itb3 encrypt` cobra command.
func newEncryptCmd() *cobra.Command {
	var opts encryptOpts
	cmd := &cobra.Command{
		Use:   "encrypt <blob.json> [flags]",
		Short: "Encrypt input plaintext under a session blob",
		Args:  cobra.ExactArgs(1),
		Long: `Encrypt input plaintext under the session state stored in
<blob.json>. The blob's embedded profile record determines whether the
payload is routed through the Single Message or Streaming cipher
surface; the dispatch is automatic.

    -i <file>   input plaintext (default stdin; refused when stdin is a TTY)
    -o <file>   output ciphertext (default stdout)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEncrypt(args[0], opts)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&opts.inputPath, "input", "i", "", "input plaintext file (default stdin when piped)")
	f.StringVarP(&opts.outputPath, "output", "o", "", "output ciphertext file (default stdout)")
	return cmd
}

// runEncrypt is the encrypt handler body.
func runEncrypt(blobPath string, opts encryptOpts) error {
	pipe, prof, err := loadPipeline("encrypt", blobPath)
	if err != nil {
		return err
	}
	defer pipe.Close()

	if isStreamingMode(prof.Mode) {
		src, srcCloser, err := openInputReader("encrypt", opts.inputPath)
		if err != nil {
			return err
		}
		if srcCloser != nil {
			defer srcCloser.Close()
		}
		dst, dstCloser, err := openOutputWriter("encrypt", opts.outputPath)
		if err != nil {
			return err
		}
		if dstCloser != nil {
			defer dstCloser.Close()
		}
		if err := pipe.EncryptStream(src, dst); err != nil {
			return classifyCryptoError("encrypt", err)
		}
		return nil
	}

	plain, err := readInputBytes("encrypt", opts.inputPath)
	if err != nil {
		return err
	}
	wire, err := pipe.EncryptMessage(plain)
	if err != nil {
		return classifyCryptoError("encrypt", err)
	}
	return writeOutputBytes("encrypt", opts.outputPath, wire)
}
