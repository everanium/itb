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
//	parity [-interlock=48|168] [-nonce-bits=N]
//	parity -mode=selftest [-interlock=48|168] [-nonce-bits=N]
//	parity -mode=init    -profile=P -hash=H -seed-file=S [-nonce-bits=N] [-interlock=48|168]
//	parity -mode=encrypt -profile=P -hash=H -seed-file=S -in=plain.bin -out=wire.bin [-nonce-bits=N] [-interlock=48|168]
//	parity -mode=decrypt -profile=P -hash=H -seed-file=S -in=wire.bin  -out=back.bin [-nonce-bits=N] [-interlock=48|168]
//
// When invoked with no -mode flag (or -mode=selftest), parity runs its
// built-in cross-tier and C-ABI parity suite covering the default 48-bit
// interlock across all registry primitives and explicit 168-bit interlock
// checks across areion512, blake2b512, and mixed 512-bit constellations
// (areion512,blake2b512,areion512) at message sizes 0, 1, 6, 20, 21, 22,
// 41, 42, 43, 63, 64, and 1024 bytes.
//
// -nonce-bits (default 512) selects the on-wire nonce width (128 |
// 256 | 512) passed to [triple.Init] by -mode=init. The nonce width
// determines the per-pixel buf shape the inner hash absorbs (nonce
// bytes + 4 → 20 / 36 / 68 bytes, the same size the wire header
// happens to be), so sweeping it drives every
// chain-absorb kernel width through the cross-build matrix. The
// session blob carries the width it was initialised with, so
// -mode=encrypt / -mode=decrypt accept the flag for invocation
// symmetry but take the width from the blob.
//
// -mode=init calls [triple.Init] against the requested (profile, hash)
// pair and writes the session blob to -seed-file. Every subsequent
// -mode=encrypt / -mode=decrypt invocation on any build arm reads the
// blob and reconstructs the identical seed state via [triple.Load].
// The fixed-seeds contract is what makes cross-build parity comparable:
// the two arms observe the same PRF key material and per-slot Components
// on the same nonce space, so wire-shape divergence isolates to the
// pixel kernel itself.
//
// -hash=H cycles the inner primitive. For "parity-*" profile names, the
// helper dynamically registers a Single Message No MAC profile (parallax
// off, wrapper off) for the requested [hashes.Registry] entry under the
// name "parity-<hash>-v1"; the pixel kernel is therefore exercised
// across every hash a C-side or asm change can touch, not only the default
// Areion-SoEM. The -profile flag accepts the derived parity-* name
// (typical) or any shipped profile name (opportunistic use).
//
// The utility uses standard library only. No dependency on bindings.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	parityMemoryLimitBytes int64 = 4 << 30
	parityGCPercent              = 100
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

	mode := fs.String("mode", "", "one of: selftest (default when no flags given), init, encrypt, decrypt")
	profile := fs.String("profile", "", "profile name (e.g. parity-areion512-v1 or a shipped profile)")
	hash := fs.String("hash", "", "inner hash primitive name or comma-separated mixed constellation (e.g. areion512,blake2b512,areion512)")
	seedFile := fs.String("seed-file", "", "path to the session blob produced by -mode=init")
	inFile := fs.String("in", "", "-mode=encrypt|decrypt: input path")
	outFile := fs.String("out", "", "-mode=encrypt|decrypt: output path")
	nonceBits := fs.Int("nonce-bits", 512, "on-wire nonce width in bits (128 | 256 | 512)")
	interlock := fs.String("interlock", "", "Interlocked Barrier chunk width (empty/48 default | 168 for 512-bit hashes)")
	workerDir := fs.String("worker-dir", "", "internal directory for -mode=selftest-tier-worker")
	workerTier := fs.String("worker-tier", "", "internal tier label for -mode=selftest-tier-worker")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Runtime cap — matches the ITB library binding-fleet standard.
	itb.SetMemoryLimit(parityMemoryLimitBytes)
	itb.SetGCPercent(parityGCPercent)

	if *mode == "selftest-tier-worker" {
		if err := runSelfTestTierWorker(*workerDir, *workerTier); err != nil {
			fmt.Fprintf(os.Stderr, "parity: selftest-tier-worker (%s): %v\n", *workerTier, err)
			return 1
		}
		return 0
	}

	if (*mode == "" && *profile == "" && *hash == "" && *seedFile == "") || *mode == "selftest" {
		if err := runSelfTest(*nonceBits, *interlock); err != nil {
			fmt.Fprintf(os.Stderr, "parity: selftest: %v\n", err)
			return 1
		}
		return 0
	}

	if *mode == "" || *profile == "" || *hash == "" || *seedFile == "" {
		fmt.Fprintln(os.Stderr, "parity: -mode, -profile, -hash, -seed-file are required")
		fs.Usage()
		return 2
	}

	// Ensure the requested profile is registered. Parity-* profile names
	// are auto-registered against the -hash primitive; shipped profile
	// names (streaming-*, singlemsg-*, blob-*) are consulted as-is.
	if err := ensureProfile(*profile, *hash); err != nil {
		fmt.Fprintf(os.Stderr, "parity: register profile %q: %v\n", *profile, err)
		return 1
	}

	switch *mode {
	case "init":
		if err := doInit(*profile, *hash, *seedFile, *nonceBits, *interlock); err != nil {
			fmt.Fprintf(os.Stderr, "parity: init: %v\n", err)
			return 1
		}
	case "encrypt":
		if *inFile == "" || *outFile == "" {
			fmt.Fprintln(os.Stderr, "parity: -mode=encrypt requires -in and -out")
			return 2
		}
		if err := doEncrypt(*profile, *seedFile, *inFile, *outFile); err != nil {
			fmt.Fprintf(os.Stderr, "parity: encrypt: %v\n", err)
			return 1
		}
	case "decrypt":
		if *inFile == "" || *outFile == "" {
			fmt.Fprintln(os.Stderr, "parity: -mode=decrypt requires -in and -out")
			return 2
		}
		if err := doDecrypt(*profile, *seedFile, *inFile, *outFile); err != nil {
			fmt.Fprintf(os.Stderr, "parity: decrypt: %v\n", err)
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "parity: unknown -mode %q (want selftest | init | encrypt | decrypt)\n", *mode)
		return 2
	}
	return 0
}

// ensureProfile registers a parity-<hash>-v1 profile against the shipped
// hashes.Registry entry for -hash (or a comma-separated mixed constellation
// such as "areion512,blake2b512,areion512"). Names that do not start with the
// "parity-" prefix are left untouched — the caller is expected to pass a
// shipped profile whose registration already lives in the Triple registry.
// [triple.ErrProfileExists] on a second call is not an error (an earlier
// invocation of the same helper binary in the same test round already
// registered the same profile).
func ensureProfile(profileName, hashName string) error {
	if !strings.HasPrefix(profileName, "parity-") {
		return nil
	}
	if hashName == "mixed512" {
		hashName = "areion512,blake2b512,areion512"
	}
	prof := triple.Profile{
		Mode:     "singlemsg-nomac",
		KeyBits:  parityKeyBits,
		Parallax: false,
		Wrapper:  false,
	}
	if strings.Contains(hashName, ",") {
		parts := strings.Split(hashName, ",")
		if len(parts) < 2 {
			return fmt.Errorf("mixed hash spec %q requires at least 2 primitives", hashName)
		}
		var width int
		for i, p := range parts {
			p = strings.TrimSpace(p)
			spec, ok := hashes.Find(p)
			if !ok {
				return fmt.Errorf("unknown inner hash %q in mixed spec %q", p, hashName)
			}
			if i == 0 {
				width = int(spec.Width)
			} else if int(spec.Width) != width {
				return fmt.Errorf("mixed hash %q width %d does not match %d", p, spec.Width, width)
			}
			parts[i] = p
		}
		prof.Width = width
		for i := range prof.MixedHashes {
			prof.MixedHashes[i] = parts[i%len(parts)]
		}
	} else {
		spec, ok := hashes.Find(hashName)
		if !ok {
			return fmt.Errorf("unknown inner hash %q (not in hashes.Registry)", hashName)
		}
		prof.Width = int(spec.Width)
		prof.InnerHash = hashName
	}
	// parity-mac-* names register the MAC Authenticated variant with
	// the MAC pinned to kmac256, so the cross-build matrix also forces
	// tag agreement across the vendored AVX-512 Keccak-f[1600] tier
	// and the scalar tier (-tags noitbasm arm).
	if strings.HasPrefix(profileName, "parity-mac-") {
		prof.Mode = "singlemsg-mac"
		prof.MacName = "kmac256"
	}
	err := triple.Register(profileName, prof)
	if err != nil && !errors.Is(err, triple.ErrProfileExists) {
		return err
	}
	return nil
}

// doInit constructs a fresh Pipeline against (profile, hash) using
// crypto/rand-drawn seed material, then serialises the session blob to
// -seed-file. Subsequent encrypt / decrypt calls on either build arm
// consume the same blob, so both arms observe the identical seed state.
// nonceBits selects the on-wire nonce width embedded into the session blob;
// subsequent encrypt / decrypt calls reconstruct this width via [triple.Load].
func doInit(profileName, hashName, seedPath string, nonceBits int, interlock string) error {
	pipe, blob, err := triple.Init(profileName, triple.Opts{NonceBits: nonceBits, Interlock: interlock})
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
	// Verification probe: confirm host crypto/rand is functional
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
// [triple.Load], encrypts the -in file, and writes the wire to -out.
// The -profile flag must match the envelope's recorded profile
// (double-check against a wrong seed file being paired with a
// mismatched profile flag).
func doEncrypt(profileName, seedPath, inPath, outPath string) error {
	pipe, err := openFromSeed(profileName, seedPath)
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
func doDecrypt(profileName, seedPath, inPath, outPath string) error {
	pipe, err := openFromSeed(profileName, seedPath)
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
// reconstructs the Pipeline via [triple.Load]. The envelope's Profile
// field is compared against the -profile flag so a wrong pairing
// surfaces fast: Load itself takes every structural parameter — nonce
// width included — from the blob and never consults the profile name.
func openFromSeed(profileName, seedPath string) (*triple.Pipeline, error) {
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
	pipe, err := triple.Load(blob)
	if err != nil {
		return nil, fmt.Errorf("triple.Load(%q): %w", profileName, err)
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
// files: seed material and its derived wire live in dedicated
// fixture / temporary output directories, but a tighter perm on the
// individual files keeps them unreadable to other users on multi-tenant hosts.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}

var (
	// selfTestIL48Sizes are the payload byte lengths exercised across every
	// registry primitive under the default 48-bit interlock (6-byte chunks).
	selfTestIL48Sizes = []int{0, 1, 6, 64, 1024}

	// selfTestIL168Sizes are the payload byte lengths exercised for selective
	// 168-bit interlock (21-byte chunks -> 3 x 7-byte lanes) parity on 512-bit
	// primitives, explicitly covering empty (0), sub-chunk (1, 6, 20), exact
	// 1-chunk (21), 1-chunk + 1 tail (22), 2-chunk boundaries (41, 42, 43),
	// 3-chunk boundaries (63, 64), and multi-chunk (1024) payloads.
	selfTestIL168Sizes = []int{0, 1, 6, 20, 21, 22, 41, 42, 43, 63, 64, 1024}
)

type selfTestTierSpec struct {
	Label     string
	Profile   string
	Hash      string
	Interlock string
}

var selfTestTierSpecs = []selfTestTierSpec{
	{
		Label:     "il48_areion512",
		Profile:   "parity-areion512-v1",
		Hash:      "areion512",
		Interlock: "48",
	},
	{
		Label:     "il168_areion512",
		Profile:   "parity-areion512-il168-v1",
		Hash:      "areion512",
		Interlock: "168",
	},
	{
		Label:     "il168_blake2b512",
		Profile:   "parity-blake2b512-il168-v1",
		Hash:      "blake2b512",
		Interlock: "168",
	},
	{
		Label:     "il168_mixed512",
		Profile:   "parity-mixed512-il168-v1",
		Hash:      "areion512,blake2b512,areion512",
		Interlock: "168",
	},
}

func deterministicPayload(size int, tag byte) []byte {
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte((i*131 + int(tag)*17 + 0x5a) & 0xff)
	}
	return buf
}

func deterministicMasterKeys(seed byte) [8][]byte {
	var keys [8][]byte
	for s := 0; s < 8; s++ {
		buf := make([]byte, 32)
		for i := range buf {
			buf[i] = byte((i*73 + s*29 + int(seed)*11 + 0x3c) & 0xff)
		}
		keys[s] = buf
	}
	return keys
}

func runSelfTest(nonceBits int, interlockFilter string) error {
	run48 := interlockFilter == "" || interlockFilter == "48"
	run168 := interlockFilter == "" || interlockFilter == "168"
	if !run48 && !run168 {
		return fmt.Errorf("unsupported -interlock %q (want empty, 48, or 168)", interlockFilter)
	}

	if run48 {
		fmt.Println("=== [1/3] parity: standard interlock=48 across all registry primitives + mixed profiles ===")
		for _, spec := range hashes.Registry {
			profName := "parity-" + spec.Name + "-v1"
			if err := ensureProfile(profName, spec.Name); err != nil {
				return fmt.Errorf("register %s: %w", profName, err)
			}
			if err := verifySingleMsgVectorSet(profName, "48", nonceBits, selfTestIL48Sizes); err != nil {
				return fmt.Errorf("il48 %s: %w", profName, err)
			}
		}
		for _, shipped := range []string{
			triple.ProfileSingleMsgTripleNoMACMixedV1,
			triple.ProfileSingleMsgTripleMACMixedV1,
		} {
			if err := verifySingleMsgVectorSet(shipped, "48", nonceBits, selfTestIL48Sizes); err != nil {
				return fmt.Errorf("il48 %s: %w", shipped, err)
			}
		}
		if err := verifyStreamingVectorSet(triple.ProfileStreamingAEADTripleMACMixedV1, "48", nonceBits, selfTestIL48Sizes); err != nil {
			return fmt.Errorf("il48 %s: %w", triple.ProfileStreamingAEADTripleMACMixedV1, err)
		}
		fmt.Printf("  PASS: %d registry primitives + 3 mixed profiles verified under interlock=48 (sizes %v)\n",
			len(hashes.Registry), selfTestIL48Sizes)
	}

	if run168 {
		fmt.Println("=== [2/3] parity: selective interlock=168 on 512-bit primitives (areion512, blake2b512, areion512,blake2b512,areion512) ===")
		il168Configs := []struct {
			label   string
			profile string
			hash    string
		}{
			{
				label:   "areion512 (nomac)",
				profile: "parity-areion512-il168-v1",
				hash:    "areion512",
			},
			{
				label:   "areion512 (kmac256)",
				profile: "parity-mac-areion512-il168-v1",
				hash:    "areion512",
			},
			{
				label:   "blake2b512 (nomac)",
				profile: "parity-blake2b512-il168-v1",
				hash:    "blake2b512",
			},
			{
				label:   "blake2b512 (kmac256)",
				profile: "parity-mac-blake2b512-il168-v1",
				hash:    "blake2b512",
			},
			{
				label:   "mixed_hashes=areion512,blake2b512,areion512 (nomac)",
				profile: "parity-mixed512-il168-v1",
				hash:    "areion512,blake2b512,areion512",
			},
			{
				label:   "mixed_hashes=areion512,blake2b512,areion512 (kmac256)",
				profile: "parity-mac-mixed512-il168-v1",
				hash:    "areion512,blake2b512,areion512",
			},
			{
				label:   "shipped singlemsg-triple-nomac-mixed-v1",
				profile: triple.ProfileSingleMsgTripleNoMACMixedV1,
				hash:    "areion512,blake2b512,areion512",
			},
			{
				label:   "shipped singlemsg-triple-mac-v1",
				profile: triple.ProfileSingleMsgTripleMACV1,
				hash:    "areion512",
			},
		}

		for idx, cfg := range il168Configs {
			if err := ensureProfile(cfg.profile, cfg.hash); err != nil {
				return fmt.Errorf("register %s: %w", cfg.profile, err)
			}
			if err := verifySingleMsgVectorSet(cfg.profile, "168", nonceBits, selfTestIL168Sizes); err != nil {
				return fmt.Errorf("il168 %s: %w", cfg.label, err)
			}
			if err := verifyInitKeysDeterminism(cfg.profile, "168", nonceBits, byte(idx+1), selfTestIL168Sizes); err != nil {
				return fmt.Errorf("il168 InitKeys %s: %w", cfg.label, err)
			}
			fmt.Printf("  PASS: %-52s sizes=%v\n", cfg.label, selfTestIL168Sizes)
		}

		if err := verifyStreamingVectorSet(triple.ProfileStreamingAEADTripleMACV1, "168", nonceBits, selfTestIL168Sizes); err != nil {
			return fmt.Errorf("il168 streaming %s: %w", triple.ProfileStreamingAEADTripleMACV1, err)
		}
		fmt.Printf("  PASS: %-52s sizes=%v\n", "shipped streaming-aead-triple-mac-v1 (stream)", selfTestIL168Sizes)

		// Negative guard: non-512-bit primitives must reject interlock=168.
		for _, non512 := range []string{"areion256", "blake3", "aesitb128"} {
			profName := "parity-" + non512 + "-v1"
			if err := ensureProfile(profName, non512); err != nil {
				return err
			}
			pipe, _, err := triple.Init(profName, triple.Opts{NonceBits: nonceBits, Interlock: "168"})
			if pipe != nil {
				pipe.Close()
			}
			if err == nil {
				return fmt.Errorf("expected error for %s with interlock=168, got nil", non512)
			}
		}
		fmt.Println("  PASS: non-512-bit primitives (areion256, blake3, aesitb128) reject interlock=168")
	}

	fmt.Println("=== [3/3] parity: cross-tier hardware matrix (ITB_FORCE_INTERLOCK_TIER vs scalar) ===")
	if err := runCrossTierSubprocessMatrix(nonceBits, interlockFilter); err != nil {
		return err
	}

	fmt.Println("parity: ALL CHECKS PASSED")
	return nil
}

func verifySingleMsgVectorSet(profileName, interlockMode string, nonceBits int, sizes []int) error {
	opts := triple.Opts{NonceBits: nonceBits, Interlock: interlockMode}
	encPipe, blob, err := triple.Init(profileName, opts)
	if err != nil {
		return fmt.Errorf("Init: %w", err)
	}
	defer encPipe.Close()

	inspected, err := triple.Inspect(blob)
	if err != nil {
		return fmt.Errorf("Inspect: %w", err)
	}
	wantIL := interlockMode
	if wantIL == "48" {
		wantIL = ""
	}
	if inspected.Interlock != wantIL {
		return fmt.Errorf("Inspect.Interlock = %q, want %q", inspected.Interlock, wantIL)
	}

	decPipe, err := triple.Load(blob)
	if err != nil {
		return fmt.Errorf("Load: %w", err)
	}
	defer decPipe.Close()

	for _, sz := range sizes {
		if sz == 0 {
			if got := encPipe.MaxWireSize(0); got != 0 {
				return fmt.Errorf("MaxWireSize(0) = %d, want 0", got)
			}
			if got := encPipe.MaxPlaintextSize(0); got != 0 {
				return fmt.Errorf("MaxPlaintextSize(0) = %d, want 0", got)
			}
			if _, err := encPipe.EncryptMessage(nil); !errors.Is(err, triple.ErrEmptyInput) {
				return fmt.Errorf("EncryptMessage(0 bytes): got %v, want ErrEmptyInput", err)
			}
			continue
		}
		plain := deterministicPayload(sz, byte(sz))
		wire, err := encPipe.EncryptMessage(plain)
		if err != nil {
			return fmt.Errorf("size %d EncryptMessage: %w", sz, err)
		}
		back, err := decPipe.DecryptMessage(wire)
		if err != nil {
			return fmt.Errorf("size %d DecryptMessage: %w", sz, err)
		}
		if !bytes.Equal(plain, back) {
			return fmt.Errorf("size %d round-trip mismatch", sz)
		}
	}

	// Verify Rekey preserves the interlock mode.
	permMaster := deterministicPayload(32, 0xa1)
	wrapMaster := deterministicPayload(32, 0xb2)
	rekeyBlob, err := encPipe.Rekey(permMaster, wrapMaster)
	if err != nil {
		return fmt.Errorf("Rekey: %w", err)
	}
	rekeyProf, err := triple.Inspect(rekeyBlob)
	if err != nil {
		return fmt.Errorf("Inspect(Rekey): %w", err)
	}
	if rekeyProf.Interlock != wantIL {
		return fmt.Errorf("Inspect(Rekey).Interlock = %q, want %q", rekeyProf.Interlock, wantIL)
	}
	return nil
}

func verifyInitKeysDeterminism(profileName, interlockMode string, nonceBits int, seed byte, sizes []int) error {
	keys := deterministicMasterKeys(seed)
	opts := triple.Opts{NonceBits: nonceBits, Interlock: interlockMode}

	p1, blob1, err := triple.InitKeys(profileName, opts, keys)
	if err != nil {
		return fmt.Errorf("InitKeys #1: %w", err)
	}
	defer p1.Close()

	p2, blob2, err := triple.InitKeys(profileName, opts, keys)
	if err != nil {
		return fmt.Errorf("InitKeys #2: %w", err)
	}
	defer p2.Close()

	if !bytes.Equal(blob1, blob2) {
		return fmt.Errorf("InitKeys produced non-identical session blobs for identical keys")
	}

	for _, sz := range sizes {
		if sz == 0 {
			continue
		}
		plain := deterministicPayload(sz, seed^byte(sz))
		wire, err := p1.EncryptMessage(plain)
		if err != nil {
			return fmt.Errorf("size %d p1.EncryptMessage: %w", sz, err)
		}
		back, err := p2.DecryptMessage(wire)
		if err != nil {
			return fmt.Errorf("size %d p2.DecryptMessage: %w", sz, err)
		}
		if !bytes.Equal(plain, back) {
			return fmt.Errorf("size %d cross-pipeline InitKeys mismatch", sz)
		}
	}
	return nil
}

func verifyStreamingVectorSet(profileName, interlockMode string, nonceBits int, sizes []int) error {
	opts := triple.Opts{NonceBits: nonceBits, Interlock: interlockMode}
	encPipe, blob, err := triple.Init(profileName, opts)
	if err != nil {
		return fmt.Errorf("Init: %w", err)
	}
	defer encPipe.Close()

	decPipe, err := triple.Load(blob)
	if err != nil {
		return fmt.Errorf("Load: %w", err)
	}
	defer decPipe.Close()

	for _, sz := range sizes {
		if sz == 0 {
			if _, err := encPipe.EncryptStreamBytes(nil); !errors.Is(err, triple.ErrEmptyInput) {
				return fmt.Errorf("EncryptStreamBytes(0 bytes): got %v, want ErrEmptyInput", err)
			}
			continue
		}
		plain := deterministicPayload(sz, byte(sz+3))
		wire, err := encPipe.EncryptStreamBytes(plain)
		if err != nil {
			return fmt.Errorf("size %d EncryptStreamBytes: %w", sz, err)
		}
		back, err := decPipe.DecryptStreamBytes(wire)
		if err != nil {
			return fmt.Errorf("size %d DecryptStreamBytes: %w", sz, err)
		}
		if !bytes.Equal(plain, back) {
			return fmt.Errorf("size %d streaming round-trip mismatch (got %d bytes, want %d)", sz, len(back), len(plain))
		}
	}
	return nil
}

func hostInterlockTiers() []string {
	switch runtime.GOARCH {
	case "amd64":
		return []string{"scalar", "bmi2", "avx2", "avx512", "avx512x8"}
	case "arm64":
		return []string{"scalar", "neon", "sve", "sve2"}
	default:
		return []string{"scalar"}
	}
}

func runCrossTierSubprocessMatrix(nonceBits int, interlockFilter string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable: %w", err)
	}
	tmpDir, err := os.MkdirTemp("", "itb-parity-selftest-*")
	if err != nil {
		return fmt.Errorf("MkdirTemp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Write plaintexts for all non-zero sizes in selfTestIL168Sizes.
	for _, sz := range selfTestIL168Sizes {
		if sz == 0 {
			continue
		}
		plainPath := filepath.Join(tmpDir, fmt.Sprintf("plain_%d.bin", sz))
		if err := writeFile(plainPath, deterministicPayload(sz, byte(sz^0x33))); err != nil {
			return err
		}
	}

	// Initialise seed files for each tier spec matching interlockFilter.
	var activeSpecs []selfTestTierSpec
	for _, spec := range selfTestTierSpecs {
		if interlockFilter != "" && spec.Interlock != interlockFilter {
			continue
		}
		if err := ensureProfile(spec.Profile, spec.Hash); err != nil {
			return err
		}
		seedPath := filepath.Join(tmpDir, "seed_"+spec.Label+".json")
		if err := doInit(spec.Profile, spec.Hash, seedPath, nonceBits, spec.Interlock); err != nil {
			return fmt.Errorf("doInit %s: %w", spec.Label, err)
		}
		activeSpecs = append(activeSpecs, spec)
	}

	tiers := hostInterlockTiers()
	// First run scalar to produce the reference ciphertexts.
	if err := invokeTierWorker(exe, tmpDir, "scalar"); err != nil {
		return fmt.Errorf("scalar reference worker: %w", err)
	}

	// Now run every hardware tier (and auto-dispatch), verifying both
	// decrypting scalar ciphertexts and encrypting ciphertexts that scalar
	// subsequently decrypts.
	for _, tier := range tiers {
		if tier == "scalar" {
			continue
		}
		if err := invokeTierWorker(exe, tmpDir, tier); err != nil {
			return fmt.Errorf("tier %s worker: %w", tier, err)
		}
		// Verify under forced scalar that ciphertexts produced by `tier`
		// decrypt back to the exact plaintexts.
		if err := invokeTierWorker(exe, tmpDir, "verify_"+tier); err != nil {
			return fmt.Errorf("scalar verify of tier %s: %w", tier, err)
		}
		fmt.Printf("  PASS: ITB_FORCE_INTERLOCK_TIER=%-8s <-> scalar across %d configs x %d sizes\n",
			tier, len(activeSpecs), len(selfTestIL168Sizes)-1)
	}
	return nil
}

func invokeTierWorker(exe, tmpDir, workerTier string) error {
	cmd := exec.Command(exe,
		"-mode=selftest-tier-worker",
		"-worker-dir="+tmpDir,
		"-worker-tier="+workerTier,
	)
	env := os.Environ()
	forceTier := workerTier
	if strings.HasPrefix(workerTier, "verify_") {
		forceTier = "scalar"
	}
	env = append(env, "ITB_FORCE_INTERLOCK_TIER="+forceTier)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runSelfTestTierWorker(tmpDir, workerTier string) error {
	if tmpDir == "" || workerTier == "" {
		return fmt.Errorf("missing -worker-dir or -worker-tier")
	}
	verifyTarget := strings.TrimPrefix(workerTier, "verify_")
	isVerify := verifyTarget != workerTier

	for _, spec := range selfTestTierSpecs {
		seedPath := filepath.Join(tmpDir, "seed_"+spec.Label+".json")
		if _, err := os.Stat(seedPath); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := ensureProfile(spec.Profile, spec.Hash); err != nil {
			return err
		}
		pipe, err := openFromSeed(spec.Profile, seedPath)
		if err != nil {
			return err
		}

		for _, sz := range selfTestIL168Sizes {
			if sz == 0 {
				continue
			}
			plainPath := filepath.Join(tmpDir, fmt.Sprintf("plain_%d.bin", sz))
			plain, err := readFile(plainPath)
			if err != nil {
				pipe.Close()
				return err
			}

			if isVerify {
				// Decrypt the wire produced by verifyTarget under forced scalar.
				wirePath := filepath.Join(tmpDir, fmt.Sprintf("wire_%s_%s_%d.bin", spec.Label, verifyTarget, sz))
				wire, err := readFile(wirePath)
				if err != nil {
					pipe.Close()
					return err
				}
				back, err := pipe.DecryptMessage(wire)
				if err != nil {
					pipe.Close()
					return fmt.Errorf("%s size %d decrypt (%s->scalar): %w", spec.Label, sz, verifyTarget, err)
				}
				if !bytes.Equal(plain, back) {
					pipe.Close()
					return fmt.Errorf("%s size %d plaintext mismatch (%s->scalar)", spec.Label, sz, verifyTarget)
				}
				continue
			}

			// Produce wire under workerTier.
			wire, err := pipe.EncryptMessage(plain)
			if err != nil {
				pipe.Close()
				return fmt.Errorf("%s size %d encrypt (%s): %w", spec.Label, sz, workerTier, err)
			}
			wirePath := filepath.Join(tmpDir, fmt.Sprintf("wire_%s_%s_%d.bin", spec.Label, workerTier, sz))
			if err := writeFile(wirePath, wire); err != nil {
				pipe.Close()
				return err
			}

			// If workerTier != "scalar", also decrypt the reference scalar wire.
			if workerTier != "scalar" {
				refWirePath := filepath.Join(tmpDir, fmt.Sprintf("wire_%s_scalar_%d.bin", spec.Label, sz))
				refWire, err := readFile(refWirePath)
				if err != nil {
					pipe.Close()
					return err
				}
				back, err := pipe.DecryptMessage(refWire)
				if err != nil {
					pipe.Close()
					return fmt.Errorf("%s size %d decrypt (scalar->%s): %w", spec.Label, sz, workerTier, err)
				}
				if !bytes.Equal(plain, back) {
					pipe.Close()
					return fmt.Errorf("%s size %d plaintext mismatch (scalar->%s)", spec.Label, sz, workerTier)
				}
			}
		}
		pipe.Close()
	}
	return nil
}
