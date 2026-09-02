// Command eitb is the fleet-common command-line demonstrator for the
// ITB Go native surface.
//
// Subcommands:
//
//	eitb version                                   library + binding versions
//	eitb hashes                                    shipped hash primitive roster
//	eitb encrypt <profile> <in-file> <out-file>    encrypt a file
//	eitb decrypt <profile> <blob-hex> <in-file> <out-file>
//
// `encrypt` prints the session blob to stderr as hex; feed that hex
// back to `decrypt` on the receiving side.
//
// The subcommand shape mirrors every language binding's eitb utility
// verbatim so cross-binding compatibility scripts can invoke any eitb
// through one dispatch.
//
// Profile dispatch is automatic: profiles whose name starts with
// "streaming-" route through [triple.Pipeline.EncryptStream] /
// [triple.Pipeline.DecryptStream] (one-shot buffered), and every other
// profile routes through [triple.Pipeline.EncryptMessage] /
// [triple.Pipeline.DecryptMessage]. The parent directory of the
// out-file is created recursively before the write so callers can pass
// paths under directory trees that do not yet exist.

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/triple"
)

// eitbGoVersion matches the shipped libitb ABI version reported by
// [github.com/everanium/itb/cmd/cshared] so the Go native tool prints
// the same "libitb X.Y.Z" line as every binding's eitb.
const eitbGoVersion = "0.3.4"

const usage = `usage: eitb version
       eitb hashes
       eitb encrypt <profile> <in-file> <out-file>
       eitb decrypt <profile> <blob-hex> <in-file> <out-file>`

func main() {
	args := os.Args[1:]
	rc := dispatch(args)
	os.Exit(rc)
}

func dispatch(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		cmdVersion()
		return 0
	case "hashes":
		if len(args) != 1 {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		cmdHashes()
		return 0
	case "encrypt":
		if len(args) != 4 {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		if err := cmdEncrypt(args[1], args[2], args[3]); err != nil {
			fmt.Fprintf(os.Stderr, "eitb: %v\n", err)
			return 1
		}
		return 0
	case "decrypt":
		if len(args) != 5 {
			fmt.Fprintln(os.Stderr, usage)
			return 2
		}
		if err := cmdDecrypt(args[1], args[2], args[3], args[4]); err != nil {
			fmt.Fprintf(os.Stderr, "eitb: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintln(os.Stderr, usage)
		return 2
	}
}

func cmdVersion() {
	fmt.Printf("libitb %s\n", eitbGoVersion)
	fmt.Printf("itb-go %s\n", eitbGoVersion)
}

func cmdHashes() {
	for i, spec := range hashes.Registry {
		fmt.Printf("%2d  %-12s %d bits\n", i, spec.Name, int(spec.Width))
	}
}

// isStreamingProfile reports whether the profile routes through the
// streaming cipher surface. Profiles whose canonical name begins with
// "streaming-" carry no [triple.Pipeline.EncryptMessage] path — the
// eitb dispatch therefore drives them through the one-shot streaming
// buffered pair instead.
func isStreamingProfile(profile string) bool {
	return strings.HasPrefix(profile, "streaming-")
}

// ensureParentDir creates the parent directory of out recursively,
// analogous to `mkdir -p $(dirname out)`. Silent if the directory
// already exists; propagates the error otherwise.
func ensureParentDir(out string) error {
	dir := filepath.Dir(out)
	if dir == "" || dir == "." {
		return nil
	}
	return os.MkdirAll(dir, 0o755)
}

func cmdEncrypt(profile, infile, outfile string) error {
	plain, err := os.ReadFile(infile)
	if err != nil {
		return err
	}
	pipe, blob, err := triple.Init(profile, triple.Opts{})
	if err != nil {
		return err
	}
	defer pipe.Close()

	var wire []byte
	if isStreamingProfile(profile) {
		var buf bytes.Buffer
		if err := pipe.EncryptStream(bytes.NewReader(plain), &buf); err != nil {
			return err
		}
		wire = buf.Bytes()
	} else {
		wire, err = pipe.EncryptMessage(plain)
		if err != nil {
			return err
		}
	}

	if err := ensureParentDir(outfile); err != nil {
		return err
	}
	if err := os.WriteFile(outfile, wire, 0o644); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, hex.EncodeToString(blob))
	fmt.Printf("encrypted %s -> %s (%d -> %d bytes)\n", infile, outfile, len(plain), len(wire))
	return nil
}

func cmdDecrypt(profile, blobHex, infile, outfile string) error {
	blob, err := hex.DecodeString(blobHex)
	if err != nil {
		return fmt.Errorf("blob hex: %w", err)
	}
	wire, err := os.ReadFile(infile)
	if err != nil {
		return err
	}
	pipe, err := triple.Open(profile, blob, triple.Opts{})
	if err != nil {
		return err
	}
	defer pipe.Close()

	var plain []byte
	if isStreamingProfile(profile) {
		var buf bytes.Buffer
		if err := pipe.DecryptStream(bytes.NewReader(wire), &buf); err != nil {
			return err
		}
		plain = buf.Bytes()
	} else {
		plain, err = pipe.DecryptMessage(wire)
		if err != nil {
			return err
		}
	}

	if err := ensureParentDir(outfile); err != nil {
		return err
	}
	if err := os.WriteFile(outfile, plain, 0o644); err != nil {
		return err
	}
	fmt.Printf("decrypted %s -> %s (%d -> %d bytes)\n", infile, outfile, len(wire), len(plain))
	return nil
}
