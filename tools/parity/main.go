// Command parity is the cross-build C ↔ pure-Go pixel parity harness.
//
// The utility compiles into two arms — CGO_ENABLED=1 (parity-cgo,
// dispatches into process_pixels.c Tier A / B / C) and CGO_ENABLED=0
// (parity-nocgo, pure-Go pixel path) — that exchange ciphertext
// produced under fixed seeds. A same-build encrypt→decrypt round-trip
// proves only self-inversion (a C tier applying permutation Q with its
// own inverse Q⁻¹ passes even when Q differs from the Go-specified
// permutation P); only a cross-build encrypt→decrypt matrix forces
// Q = P on the sampled inputs.
//
// Flags:
//
//	parity -mode=init    -profile=P -hash=H -seed-file=S [-nonce-bits=N]
//	parity -mode=encrypt -profile=P -hash=H -seed-file=S -in=plain.bin -out=wire.bin [-nonce-bits=N]
//	parity -mode=decrypt -profile=P -hash=H -seed-file=S -in=wire.bin  -out=back.bin [-nonce-bits=N]
//
// -nonce-bits (default 512) selects the on-wire nonce width (128 |
// 256 | 512) passed to [triple.Init] / [triple.Open]. The nonce width
// determines the per-pixel buf shape the inner hash absorbs (nonce
// bytes + 4 → 20 / 36 / 68 bytes; the dual-nonce wire header itself is
// 2·nonce + 4 → 36 / 68 / 132 bytes), so sweeping it drives every
// chain-absorb kernel width through the cross-build matrix. Every
// invocation against a given seed blob must repeat the -nonce-bits
// value the blob was initialised with.
//
// -mode=init calls [triple.Init] against the requested (profile, hash)
// pair and writes the session blob to -seed-file. Every subsequent
// -mode=encrypt / -mode=decrypt invocation on any build arm reads the
// blob and reconstructs the identical seed state via [triple.Open].
// The fixed-seeds contract is what makes cross-build parity comparable:
// the two arms observe the same PRF key material and per-slot Components
// on the same nonce space, so wire-shape divergence isolates to the
// pixel kernel itself.
//
// -hash=H cycles the inner primitive. At startup the helper registers
// one Single Message No MAC profile (parallax off, wrapper off) per
// shipped [hashes.Registry] entry under the name "parity-<hash>-v1";
// the pixel kernel is therefore exercised across every hash a C-side
// or asm change can touch, not only the default Areion-SoEM. The
// -profile flag accepts the derived parity-* name (typical) or any
// shipped profile name (opportunistic use).
//
// The utility uses standard library only. No dependency on bindings.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/triple"
)

// parityKeyBits is the per-seed PRF key width used by every registered
// parity-* profile. 1024 bits divides evenly into 128 / 256 / 512 (the
// three shipped hash widths) so the same constant covers every registry
// primitive.
const parityKeyBits = 1024

// parityMemoryLimitBytes / parityGCPercent apply the canonical Go
// runtime cap the ITB library exposes via [itb.SetMemoryLimit] and
// [itb.SetGCPercent]. Matches the binding-fleet standard so bench-scale
// FFI churn stays bounded even under repeated multi-MB fixture rounds.
const (
	parityMemoryLimitBytes int64 = 512 << 20
	parityGCPercent              = 20
)

// seedBlobV1 is the on-disk wrapper written by -mode=init and read by
// -mode=encrypt / -mode=decrypt. Wrapping the blob in a small JSON
// envelope carries the (profile, hash) pair used at Init time so a
// cross-build invocation can pick up the same registration deterministically
// even if the caller passes a shipped profile name whose hash label the
// blob would not otherwise expose.
type seedBlobV1 struct {
	Version int    `json:"v"`
	Profile string `json:"profile"`
	Hash    string `json:"hash"`
	// Blob is base64-encoded so the seed file is 7-bit ASCII and
	// diff-friendly; storage cost is negligible against the fixture
	// payload sizes.
	Blob string `json:"blob"`
}

const seedBlobVersion = 1

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("parity", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	mode := fs.String("mode", "", "one of: init, encrypt, decrypt")
	profile := fs.String("profile", "", "profile name (e.g. parity-areion512-v1 or a shipped profile)")
	hash := fs.String("hash", "", "inner hash primitive name (must resolve via hashes.Find)")
	seedFile := fs.String("seed-file", "", "path to the session blob produced by -mode=init")
	inFile := fs.String("in", "", "-mode=encrypt|decrypt: input path")
	outFile := fs.String("out", "", "-mode=encrypt|decrypt: output path")
	nonceBits := fs.Int("nonce-bits", 512, "on-wire nonce width in bits (128 | 256 | 512)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *mode == "" || *profile == "" || *hash == "" || *seedFile == "" {
		fmt.Fprintln(os.Stderr, "parity: -mode, -profile, -hash, -seed-file are required")
		fs.Usage()
		return 2
	}

	// Runtime cap — matches the ITB library binding-fleet standard.
	itb.SetMemoryLimit(parityMemoryLimitBytes)
	itb.SetGCPercent(parityGCPercent)

	// Ensure the requested profile is registered. Parity-* profile names
	// are auto-registered against the -hash primitive; shipped profile
	// names (streaming-*, singlemsg-*, blob-*) are consulted as-is.
	if err := ensureProfile(*profile, *hash); err != nil {
		fmt.Fprintf(os.Stderr, "parity: register profile %q: %v\n", *profile, err)
		return 1
	}

	switch *mode {
	case "init":
		if err := doInit(*profile, *hash, *seedFile, *nonceBits); err != nil {
			fmt.Fprintf(os.Stderr, "parity: init: %v\n", err)
			return 1
		}
	case "encrypt":
		if *inFile == "" || *outFile == "" {
			fmt.Fprintln(os.Stderr, "parity: -mode=encrypt requires -in and -out")
			return 2
		}
		if err := doEncrypt(*profile, *seedFile, *inFile, *outFile, *nonceBits); err != nil {
			fmt.Fprintf(os.Stderr, "parity: encrypt: %v\n", err)
			return 1
		}
	case "decrypt":
		if *inFile == "" || *outFile == "" {
			fmt.Fprintln(os.Stderr, "parity: -mode=decrypt requires -in and -out")
			return 2
		}
		if err := doDecrypt(*profile, *seedFile, *inFile, *outFile, *nonceBits); err != nil {
			fmt.Fprintf(os.Stderr, "parity: decrypt: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "parity: unknown -mode %q (want init | encrypt | decrypt)\n", *mode)
		return 2
	}
	return 0
}

// ensureProfile registers a parity-<hash>-v1 profile against the shipped
// hashes.Registry entry for -hash. Names that do not start with the
// "parity-" prefix are left untouched — the caller is expected to pass a
// shipped profile whose registration already lives in the triple.
// [triple.ErrProfileExists] on a second call is not an error (an earlier
// invocation of the same helper binary in the same test round already
// registered the same profile).
func ensureProfile(profileName, hashName string) error {
	if !strings.HasPrefix(profileName, "parity-") {
		return nil
	}
	spec, ok := hashes.Find(hashName)
	if !ok {
		return fmt.Errorf("unknown inner hash %q (not in hashes.Registry)", hashName)
	}
	prof := triple.Profile{
		Mode:       "singlemsg-nomac",
		Width:      int(spec.Width),
		InnerHash:  hashName,
		KeyBits:    parityKeyBits,
		ParallaxOn: false,
		WrapperOn:  false,
	}
	// parity-mac-* names register the MAC Authenticated variant with
	// the MAC pinned to kmac256, so the cross-build matrix also forces
	// tag agreement across the vendored AVX-512 Keccak-f[1600] tier
	// and the scalar tier (-tags noitbasm arm).
	if strings.HasPrefix(profileName, "parity-mac-") {
		prof.Mode = "singlemsg-mac"
		prof.MacName = "kmac256"
	}
	err := triple.RegisterProfile(profileName, prof)
	if err != nil && !errors.Is(err, triple.ErrProfileExists) {
		return err
	}
	return nil
}

// doInit constructs a fresh Pipeline against (profile, hash) using
// crypto/rand-drawn seed material, then serialises the session blob to
// -seed-file. Subsequent encrypt / decrypt calls on either build arm
// consume the same blob, so both arms observe the identical seed state.
// nonceBits selects the on-wire nonce width; the caller must pass the
// same value to every encrypt / decrypt invocation against the blob.
func doInit(profileName, hashName, seedPath string, nonceBits int) error {
	pipe, blob, err := triple.Init(profileName, triple.Opts{NonceBits: nonceBits})
	if err != nil {
		return fmt.Errorf("triple.Init(%q): %w", profileName, err)
	}
	defer pipe.Close()

	env := seedBlobV1{
		Version: seedBlobVersion,
		Profile: profileName,
		Hash:    hashName,
		Blob:    base64.StdEncoding.EncodeToString(blob),
	}
	buf, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal seed envelope: %w", err)
	}
	if err := os.WriteFile(seedPath, buf, 0o600); err != nil {
		return fmt.Errorf("write seed file %q: %w", seedPath, err)
	}
	// Sanity check: the CSPRNG entropy really came out of crypto/rand
	// (the library's Init already draws from crypto/rand; the following
	// discard read confirms rand is functional on this host, which
	// avoids masking a rare pathological case as a parity failure).
	var probe [1]byte
	if _, err := rand.Read(probe[:]); err != nil {
		return fmt.Errorf("crypto/rand probe: %w", err)
	}
	return nil
}

// doEncrypt reads the seed envelope, reconstructs the Pipeline via
// triple.Open, encrypts the -in file, and writes the wire to -out. The
// -profile flag must match the envelope's recorded profile (double-check
// against a wrong seed file being paired with a mismatched profile flag).
func doEncrypt(profileName, seedPath, inPath, outPath string, nonceBits int) error {
	pipe, err := openFromSeed(profileName, seedPath, nonceBits)
	if err != nil {
		return err
	}
	defer pipe.Close()

	plaintext, err := readFile(inPath)
	if err != nil {
		return fmt.Errorf("read %q: %w", inPath, err)
	}
	wire, err := pipe.EncryptMessage(plaintext)
	if err != nil {
		return fmt.Errorf("EncryptMessage: %w", err)
	}
	if err := writeFile(outPath, wire); err != nil {
		return fmt.Errorf("write %q: %w", outPath, err)
	}
	return nil
}

// doDecrypt reads the seed envelope, reconstructs the Pipeline, decrypts
// the -in wire, and writes recovered plaintext to -out. Wire produced by
// the opposite build arm's doEncrypt must round-trip byte-identically
// through this path; any mismatch localises to the pixel kernel.
func doDecrypt(profileName, seedPath, inPath, outPath string, nonceBits int) error {
	pipe, err := openFromSeed(profileName, seedPath, nonceBits)
	if err != nil {
		return err
	}
	defer pipe.Close()

	wire, err := readFile(inPath)
	if err != nil {
		return fmt.Errorf("read %q: %w", inPath, err)
	}
	plain, err := pipe.DecryptMessage(wire)
	if err != nil {
		return fmt.Errorf("DecryptMessage: %w", err)
	}
	if err := writeFile(outPath, plain); err != nil {
		return fmt.Errorf("write %q: %w", outPath, err)
	}
	return nil
}

// openFromSeed reads the seed envelope written by -mode=init and
// reconstructs the Pipeline. The envelope's Profile field is compared
// against the -profile flag so a wrong pairing surfaces fast rather
// than deep inside triple.Open's blob-mismatch path. nonceBits must
// match the value the blob was initialised with.
func openFromSeed(profileName, seedPath string, nonceBits int) (*triple.Pipeline, error) {
	buf, err := os.ReadFile(seedPath)
	if err != nil {
		return nil, fmt.Errorf("read seed file %q: %w", seedPath, err)
	}
	var env seedBlobV1
	if err := json.Unmarshal(buf, &env); err != nil {
		return nil, fmt.Errorf("parse seed envelope %q: %w", seedPath, err)
	}
	if env.Version != seedBlobVersion {
		return nil, fmt.Errorf("seed envelope %q version %d, want %d", seedPath, env.Version, seedBlobVersion)
	}
	if env.Profile != profileName {
		return nil, fmt.Errorf("seed envelope profile %q does not match -profile %q", env.Profile, profileName)
	}
	blob, err := base64.StdEncoding.DecodeString(env.Blob)
	if err != nil {
		return nil, fmt.Errorf("decode blob base64: %w", err)
	}
	pipe, err := triple.Open(profileName, blob, triple.Opts{NonceBits: nonceBits})
	if err != nil {
		return nil, fmt.Errorf("triple.Open(%q): %w", profileName, err)
	}
	return pipe, nil
}

// readFile is a small stdlib wrapper that returns the file contents with
// an error scope tag. os.ReadFile alone loses the caller-side stage so
// the wrapper preserves the site marker for the top-level dispatch.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// writeFile is the counterpart to readFile. Uses 0o600 for the produced
// files: seed material and its derived wire live under tmp/ which is
// already gitignored, but a tighter perm on the individual files keeps
// them unreadable to other users on multi-tenant hosts.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
