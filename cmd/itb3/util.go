package main

// Shared helpers for the itb3 subcommand handlers: exit-code
// contract, error printing, IO routing (input file / stdin fallback,
// output file / stdout fallback), and the isatty check that governs
// the "missing input" rejection on an interactive terminal.

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/everanium/itb"
	"github.com/everanium/itb/triple"
	"golang.org/x/term"
)

// Exit-code convention (matches openssl-family conventions).
const (
	exitOK       = 0
	exitUsage    = 1
	exitRuntime  = 2
	exitCrypto   = 3
	exitInternal = 64
)

// cliError is a subcommand-side error carrier tagging its terminating
// exit code alongside the message text. The main dispatcher unwraps
// it to compute the right os.Exit code.
type cliError struct {
	code int
	msg  string
}

func (e *cliError) Error() string { return e.msg }

// usageErr produces a Usage-tier cliError (exit 1) — flag validation,
// mode-vs-flag conflict, missing required positional, isatty stdin
// rejection, toggle-assertion mismatch.
func usageErr(subcmd string, format string, args ...any) error {
	return &cliError{code: exitUsage, msg: fmt.Sprintf("itb3: %s: ", subcmd) + fmt.Sprintf(format, args...)}
}

// runtimeErr produces a Runtime-tier cliError (exit 2) — file IO
// failure, wire parse failure, blob validation, oversized master.
func runtimeErr(subcmd string, format string, args ...any) error {
	return &cliError{code: exitRuntime, msg: fmt.Sprintf("itb3: %s: ", subcmd) + fmt.Sprintf(format, args...)}
}

// cryptoErr produces a Crypto-tier cliError (exit 3) — MAC failure,
// decrypt failure, [triple.ErrIdenticalMasters].
func cryptoErr(subcmd string, format string, args ...any) error {
	return &cliError{code: exitCrypto, msg: fmt.Sprintf("itb3: %s: ", subcmd) + fmt.Sprintf(format, args...)}
}

// dispatchExit resolves an error returned by a subcommand handler to
// the exit code the process should terminate with, printing the
// message to stderr.
func dispatchExit(err error) int {
	if err == nil {
		return exitOK
	}
	var ce *cliError
	if errors.As(err, &ce) {
		fmt.Fprintln(os.Stderr, ce.msg)
		return ce.code
	}
	// Sentinel mapping matches the spec table so a library-raised
	// error surfaces with the same exit code a hand-tagged CLI error
	// would carry.
	code := mapSentinel(err)
	fmt.Fprintf(os.Stderr, "itb3: %v\n", err)
	return code
}

// mapSentinel routes a library-level error to the corresponding
// CLI exit code per the spec's error-handling table.
func mapSentinel(err error) int {
	switch {
	case errors.Is(err, triple.ErrUnknownProfile):
		return exitUsage
	case errors.Is(err, triple.ErrProfileExists):
		return exitRuntime
	case errors.Is(err, triple.ErrMissingMasters):
		return exitUsage
	case errors.Is(err, triple.ErrMastersArity):
		return exitUsage
	case errors.Is(err, triple.ErrBadKeyBits):
		return exitUsage
	case errors.Is(err, triple.ErrProfileNoCipher):
		return exitRuntime
	case errors.Is(err, triple.ErrProfileNotStreaming):
		return exitRuntime
	case errors.Is(err, triple.ErrNotYetImplemented):
		return exitRuntime
	case errors.Is(err, triple.ErrBlobMalformed):
		return exitRuntime
	case errors.Is(err, triple.ErrBlobMalformedRecipe):
		return exitRuntime
	case errors.Is(err, triple.ErrRecipePrimitiveUnknown):
		return exitRuntime
	case errors.Is(err, triple.ErrBlobVersion):
		return exitRuntime
	case errors.Is(err, triple.ErrEmptyInput):
		return exitRuntime
	case errors.Is(err, triple.ErrClosed):
		return exitInternal
	case errors.Is(err, triple.ErrIdenticalMasters):
		return exitCrypto
	case errors.Is(err, itb.ErrMACFailure):
		return exitCrypto
	}
	return exitRuntime
}

// stdinIsTerminal reports whether stdin is attached to an interactive
// terminal. Piped input returns false, an interactive shell returns
// true. Used by the "missing input" rejection so the CLI does not
// hang on a bare invocation with no data source.
func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// readInputBytes returns the plaintext bytes an encrypt / decrypt
// call operates on. Precedence:
//
//	-i FILE supplied → read FILE (strict; missing file → error)
//	-i omitted, stdin piped → read stdin
//	-i omitted, stdin TTY → "missing input" error
func readInputBytes(subcmd string, inputPath string) ([]byte, error) {
	if inputPath != "" {
		data, err := os.ReadFile(inputPath)
		if err != nil {
			return nil, runtimeErr(subcmd, "read %q: %v", inputPath, err)
		}
		return data, nil
	}
	if stdinIsTerminal() {
		return nil, usageErr(subcmd, "input required but stdin is a TTY; use `-i FILE` or pipe stdin")
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, runtimeErr(subcmd, "read stdin: %v", err)
	}
	return data, nil
}

// openInputReader returns an [io.Reader] over the encrypt / decrypt
// input source. Same precedence as [readInputBytes]. The caller is
// responsible for closing the returned io.Closer (nil for stdin).
func openInputReader(subcmd string, inputPath string) (io.Reader, io.Closer, error) {
	if inputPath != "" {
		f, err := os.Open(inputPath)
		if err != nil {
			return nil, nil, runtimeErr(subcmd, "open %q: %v", inputPath, err)
		}
		return f, f, nil
	}
	if stdinIsTerminal() {
		return nil, nil, usageErr(subcmd, "input required but stdin is a TTY; use `-i FILE` or pipe stdin")
	}
	return os.Stdin, nil, nil
}

// openOutputWriter returns an [io.Writer] the subcommand emits to.
// An empty outputPath directs output to stdout; a set path opens the
// file for O_CREATE|O_TRUNC|O_WRONLY. The caller is responsible for
// closing the returned io.Closer (nil for stdout).
func openOutputWriter(subcmd string, outputPath string) (io.Writer, io.Closer, error) {
	if outputPath == "" {
		return os.Stdout, nil, nil
	}
	f, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, nil, runtimeErr(subcmd, "open %q for write: %v", outputPath, err)
	}
	return f, f, nil
}

// writeOutputBytes writes data either to outputPath (when set) or to
// stdout. Small-payload counterpart to [openOutputWriter] used by the
// subcommands that hold the whole output in memory.
func writeOutputBytes(subcmd string, outputPath string, data []byte) error {
	if outputPath == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			return runtimeErr(subcmd, "write stdout: %v", err)
		}
		return nil
	}
	if err := os.WriteFile(outputPath, data, 0o644); err != nil {
		return runtimeErr(subcmd, "write %q: %v", outputPath, err)
	}
	return nil
}

// classifyCryptoError decides whether a library-raised error should
// surface as a crypto-tier (exit 3) or runtime-tier (exit 2) failure.
// Kept here so the encrypt / decrypt handlers share one dispatch
// point.
func classifyCryptoError(subcmd string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, itb.ErrMACFailure) {
		return cryptoErr(subcmd, "authentic tag verification failed")
	}
	if errors.Is(err, triple.ErrIdenticalMasters) {
		return cryptoErr(subcmd, "permanent and wrapper masters are identical — reject")
	}
	if errors.Is(err, triple.ErrEmptyInput) {
		return runtimeErr(subcmd, "empty input — no zero-payload wire exists on the Pipeline surface")
	}
	if errors.Is(err, triple.ErrProfileNoCipher) {
		return runtimeErr(subcmd, "profile has no cipher surface — use `itb3 rekey` or the Go API")
	}
	if errors.Is(err, triple.ErrProfileNotStreaming) {
		return runtimeErr(subcmd, "profile does not expose a streaming cipher surface")
	}
	return runtimeErr(subcmd, "%v", err)
}

// readBlobFile reads the blob at path, bounded at itb.MaxBlobJSONSize
// so a hostile file cannot force a multi-megabyte JSON parse. The
// bytes are key material; callers clear them when done.
func readBlobFile(subcmd string, path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, runtimeErr(subcmd, "read %q: %v", path, err)
	}
	if info.Size() > int64(itb.MaxBlobJSONSize) {
		return nil, runtimeErr(subcmd, "read %q: blob exceeds itb.MaxBlobJSONSize=%d bytes", path, itb.MaxBlobJSONSize)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, runtimeErr(subcmd, "read %q: %v", path, err)
	}
	return data, nil
}

// loadPipeline reads the blob at path, decodes its embedded profile
// record via triple.Inspect (the cipher-surface dispatch key), and
// reconstructs the Pipeline via triple.Load. The caller owns the
// returned Pipeline and closes it.
func loadPipeline(subcmd string, path string) (*triple.Pipeline, triple.Profile, error) {
	blob, err := readBlobFile(subcmd, path)
	if err != nil {
		return nil, triple.Profile{}, err
	}
	defer clear(blob)
	prof, err := triple.Inspect(blob)
	if err != nil {
		return nil, triple.Profile{}, classifyLoadError(subcmd, err)
	}
	pipe, err := triple.Load(blob)
	if err != nil {
		return nil, triple.Profile{}, classifyLoadError(subcmd, err)
	}
	return pipe, prof, nil
}

// classifyLoadError maps a triple.Inspect / triple.Load failure to a
// CLI error with a message that names the cause a user can act on.
func classifyLoadError(subcmd string, err error) error {
	switch {
	case errors.Is(err, triple.ErrBlobVersion):
		return runtimeErr(subcmd, "blob schema version unsupported (produced by an earlier release)")
	case errors.Is(err, triple.ErrRecipePrimitiveUnknown):
		return runtimeErr(subcmd, "blob names a primitive this build lacks: %v", err)
	case errors.Is(err, triple.ErrIdenticalMasters):
		return cryptoErr(subcmd, "permanent and wrapper masters are identical — reject")
	}
	return runtimeErr(subcmd, "triple.Load: %v", err)
}
