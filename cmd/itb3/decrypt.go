package main

// `itb3 decrypt blob.json [-i FILE] [-o FILE]` — the mirror image of
// encrypt. Reads ciphertext, reconstructs the pipeline from the blob
// via triple.Load, dispatches to DecryptMessage or DecryptStream, and
// writes plaintext.

import (
	"github.com/spf13/cobra"
)

// decryptOpts collects the decrypt-subcommand flag values.
type decryptOpts struct {
	inputPath  string
	outputPath string
}

// newDecryptCmd wires the `itb3 decrypt` cobra command.
func newDecryptCmd() *cobra.Command {
	var opts decryptOpts
	cmd := &cobra.Command{
		Use:   "decrypt <blob.json> [flags]",
		Short: "Decrypt input ciphertext under a session blob",
		Args:  cobra.ExactArgs(1),
		Long: `Decrypt input ciphertext under the session state stored in
<blob.json>. The blob's embedded profile record determines whether the
wire is routed through the Single Message or Streaming cipher surface;
the dispatch is automatic. MAC failures surface with exit code 3 and a
neutral message so the CLI does not become an oracle.

    -i <file>   input ciphertext (default stdin; refused when stdin is a TTY)
    -o <file>   output plaintext  (default stdout)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDecrypt(args[0], opts)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&opts.inputPath, "input", "i", "", "input ciphertext file (default stdin when piped)")
	f.StringVarP(&opts.outputPath, "output", "o", "", "output plaintext file (default stdout)")
	return cmd
}

// runDecrypt is the decrypt handler body.
func runDecrypt(blobPath string, opts decryptOpts) error {
	pipe, prof, err := loadPipeline("decrypt", blobPath)
	if err != nil {
		return err
	}
	defer pipe.Close()

	if isStreamingMode(prof.Mode) {
		src, srcCloser, err := openInputReader("decrypt", opts.inputPath)
		if err != nil {
			return err
		}
		if srcCloser != nil {
			defer srcCloser.Close()
		}
		dst, dstCloser, err := openOutputWriter("decrypt", opts.outputPath)
		if err != nil {
			return err
		}
		if dstCloser != nil {
			defer dstCloser.Close()
		}
		if err := pipe.DecryptStream(src, dst); err != nil {
			return classifyCryptoError("decrypt", err)
		}
		return nil
	}

	wire, err := readInputBytes("decrypt", opts.inputPath)
	if err != nil {
		return err
	}
	plain, err := pipe.DecryptMessage(wire)
	if err != nil {
		return classifyCryptoError("decrypt", err)
	}
	return writeOutputBytes("decrypt", opts.outputPath, plain)
}
