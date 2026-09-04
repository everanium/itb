package main

// `itb3 verify blob.json` runs a structural + full-reconstruction
// validation pass. Exit 0 on valid, 2 on structural error, 3 on
// crypto-tier reconstruction error. Silent on success; a brief
// one-liner on failure.

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/everanium/itb/triple"
)

// newVerifyCmd wires the `itb3 verify` cobra command.
func newVerifyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "verify <blob.json>",
		Short: "Validate a stored blob (silent on success)",
		Args:  cobra.ExactArgs(1),
		Long: `Structural + full-reconstruction validation of the blob at
<blob.json>: the wrap-layer is decoded with triple.Inspect, then the
Pipeline is rebuilt with triple.Load and discarded.

Silent on success. On failure, a brief one-line diagnostic is
written to stdout and detailed information to stderr; the process
exits with a non-zero code:

    0   valid
    2   structural error (JSON parse, schema version, profile record,
        unknown primitive)
    3   crypto-level error (inner blob decode, masters, MAC key, ...)`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVerify(args[0])
		},
	}
}

// runVerify is the verify handler body.
func runVerify(blobPath string) error {
	blob, err := readBlobFile("verify", blobPath)
	if err != nil {
		reportInvalid("blob file unreadable")
		return err
	}
	defer clear(blob)

	// Metadata-only decode first so a schema-version mismatch or a
	// malformed wrap-layer is reported as such.
	if _, err := triple.Inspect(blob); err != nil {
		if errors.Is(err, triple.ErrBlobVersion) {
			reportInvalid("blob schema version unsupported (produced by an earlier release)")
		} else {
			reportInvalid("wrap-layer decode failed")
		}
		return classifyLoadError("verify", err)
	}

	// Full reconstruction: exercises every check in the library's
	// record validation + inner blob import path.
	pipe, err := triple.Load(blob)
	if err != nil {
		reportInvalid("triple.Load failed")
		if isStructuralLoadError(err) {
			return classifyLoadError("verify", err)
		}
		return cryptoErr("verify", "%v", err)
	}
	pipe.Close()
	// Silent success — no stdout on the happy path.
	return nil
}

// reportInvalid emits the brief one-liner to stdout on the failure
// path. The detailed message stays on stderr via the dispatcher.
func reportInvalid(reason string) {
	fmt.Println("blob invalid:", reason)
}

// isStructuralLoadError reports whether a triple.Load failure is a
// structural (exit 2) condition — schema, record, primitive
// availability, key-width envelope — as opposed to a crypto-tier
// reconstruction failure (exit 3).
func isStructuralLoadError(err error) bool {
	return errors.Is(err, triple.ErrBlobMalformed) ||
		errors.Is(err, triple.ErrBlobVersion) ||
		errors.Is(err, triple.ErrBlobMalformedRecipe) ||
		errors.Is(err, triple.ErrRecipePrimitiveUnknown) ||
		errors.Is(err, triple.ErrBadKeyBits)
}
