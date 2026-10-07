// Package drbg provides the CSPRNG-seeded bulk fill of the ITB encrypt
// hot path, with the fill primitive selected by the operator.
//
// The two production consumers are the container fill in buildTripleWire3
// (three parallel goroutines each filling roughly a third of the wire
// container with noise bytes) and the DRBG tail fill of every
// Interlocked lane in the same fused function. The bytes produced are
// consumed as ciphertext-carrier noise or as DRBG residue trimmed
// against the plaintext-derived payload — they never re-appear as key
// material, seed components, or any output that survives beyond the
// encrypt call as an entropy source. Key / nonce / seed derivation
// stays on crypto/rand.Read (natural CSPRNG, not this DRBG expansion).
// The decrypt path never calls this package: the receiver reads the
// container geometry from the header and never reproduces the noise.
//
// Every expanding arm draws a fresh seed from crypto/rand.Read on entry
// and expands it over dst; no state persists across calls. The fill
// primitive is chosen by name ([FillWith]) from the set [Names]
// reports:
//
//   - "" (the default, [Fill]) — the auto tier: AES-256-CTR
//     (crypto/aes + cipher.NewCTR, AES-256 under a 48-byte seed) on
//     hosts with AES-NI / ARMv8-AES, ChaCha20 (RFC 8439, 44-byte seed)
//     everywhere else, decided at package init from the host feature
//     flags. The environment variable ITB_DRBG_TIER ("aes" / "aesctr" /
//     "aes-ctr" / "aescmac" or "chacha" / "chacha20") forces one of the
//     two for parity and diagnostic runs; an unrecognised or
//     unsupported token keeps the auto selection silently. The variable
//     is consulted on this path only — a named primitive is never
//     overridden from the environment.
//   - "aesitb128" — the AES-ITB noise filler (aesitb.FillNoise): a
//     counter-driven run of the primitive under a 16-byte key and a
//     32-byte nonce drawn per call. The primitive is Non-PRF standalone
//     and is admitted here because carrier noise needs uniformity, not
//     PRF security; the keystream packages keep refusing it.
//   - every keystream-eligible registry primitive, by its registry
//     name — a crypto/rand key and nonce of the primitive's own sizes
//     expanded through the ctr package's constructor. The arms are
//     installed by package ctr at init ([Register]); a program that
//     links only the itb root and hashes packages carries none of them
//     and [FillWith] reports the name as not installed. Every program
//     that links wrapper, parallax or triple carries them all.
//   - "csprng" — crypto/rand.Read over the whole buffer: no expansion,
//     the kernel's own generator at its own rate.
//
// dst must be zero on entry: the auto tier and the keystream arms XOR
// over it (the aesitb128 and csprng arms overwrite it). Both production
// call sites pass a zeroed buffer (a bufferPool checkout or a fresh
// make() slice).
//
// Fill is a performance choice as much as a policy one: on a host with
// hardware AES the AES-256-CTR tier runs several GB/s per goroutine, while
// a hash primitive in counter mode runs at that primitive's own rate.
// An operator selecting a slow fill under a fast inner primitive pays
// the difference on every encrypt.
package drbg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/aesitb"
)

// fillFn is the tier-specific fill worker. Every implementation reads
// its seed from crypto/rand.Read on entry, constructs its keystream
// state and XORs the keystream against dst in place. Returns the
// crypto/rand.Read error verbatim when seed acquisition fails.
type fillFn func(dst []byte) error

// Names of the two built-in arms that are not registry primitives.
const (
	// NameAESITB128 selects the AES-ITB noise filler arm.
	NameAESITB128 = "aesitb128"
	// NameCSPRNG selects the unexpanded crypto/rand.Read arm.
	NameCSPRNG = "csprng"
)

var (
	// selected is the fill worker picked at package init after
	// consulting ITB_DRBG_TIER and the host feature flags. Reads of
	// selected are single-writer / single-init and require no
	// synchronisation.
	selected fillFn
	// selectedName is the tier name for diagnostic reporting (never
	// consumed by the fill path itself; exposed via SelectedTier).
	selectedName string

	// registered holds the keystream arms installed through Register,
	// in installation order, keyed by registry name. Writes happen at
	// package init of the installing package; reads on the fill path
	// take the read lock.
	registeredMu sync.RWMutex
	registered   = map[string]fillFn{}
	registeredIn []string
)

func init() {
	selected, selectedName = pickTier()
}

// pickTier resolves the fill worker for this build's tier ladder. Env
// override wins when the requested tier is supported; otherwise the
// auto-select ladder chooses AES-256-CTR on hardware with AES acceleration
// and ChaCha20 everywhere else.
func pickTier() (fillFn, string) {
	forced := strings.ToLower(strings.TrimSpace(os.Getenv("ITB_DRBG_TIER")))
	hasAES := hostHasAES()
	switch forced {
	case "aes", "aesctr", "aes-ctr", "aescmac":
		if hasAES {
			return fillAesCTR, "aes"
		}
		// unsupported forced tier — fall through to auto
	case "chacha", "chacha20":
		return fillChaCha20, "chacha"
	}
	if hasAES {
		return fillAesCTR, "aes"
	}
	return fillChaCha20, "chacha"
}

// hostHasAES reports whether the host advertises hardware AES support
// on either supported architecture. crypto/aes falls back to a much
// slower Go generic path in its absence, at which point ChaCha20 (with
// its own SIMD path) is the better fallback.
func hostHasAES() bool {
	if cpu.X86.HasAES {
		return true
	}
	if cpu.ARM64.HasAES {
		return true
	}
	return false
}

// SelectedTier reports the fill tier the package selected at init
// ("aes" or "chacha"). Exposed for tests and diagnostic tools; not part
// of the hot-path contract.
func SelectedTier() string {
	return selectedName
}

// Fill overwrites dst with cryptographically pseudorandom bytes drawn
// from a fresh crypto/rand.Read seed and expanded through the auto
// tier's keystream cipher. The seed is pulled once per call; no state
// persists across calls. Fill is [FillWith] under the empty name.
//
// Not for key material, nonces, or seed components — callers requiring
// full-entropy OS randomness should use crypto/rand.Read directly.
//
// dst must be pre-zeroed for the output to be raw keystream. On the
// production call sites the buffers come from acquireBuffer or make()
// and are zero-initialised, so this is satisfied. When called on
// non-zero dst the output is keystream XOR'd against the incoming
// bytes, which is still unpredictable to an observer without seed
// knowledge but no longer equals the raw keystream.
//
// Fill returns nil on success, or the crypto/rand.Read error on seed
// acquisition failure.
func Fill(dst []byte) error {
	if len(dst) == 0 {
		return nil
	}
	return selected(dst)
}

// FillWith fills dst through the arm name selects: "" is the auto tier
// of [Fill], "aesitb128" the AES-ITB noise filler, "csprng" the
// unexpanded crypto/rand.Read, and any name installed through
// [Register] its keystream arm. An unknown name is an error naming the
// token, and dst is left untouched — never a fallback to another arm.
// A zero-length dst succeeds without consulting the name.
//
// dst must be zero on entry: the aesitb128 and csprng arms overwrite
// it, while the auto tier and the keystream arms XOR their keystream
// over it, so only a zeroed dst yields the raw fill on every arm. Both
// production call sites pass zeroed buffers; FillWith does not clear
// dst itself.
//
// Returns the crypto/rand.Read error on seed acquisition failure.
func FillWith(name string, dst []byte) error {
	if len(dst) == 0 {
		return nil
	}
	switch name {
	case "":
		return selected(dst)
	case NameAESITB128:
		return aesitb.FillNoise(dst)
	case NameCSPRNG:
		_, err := rand.Read(dst)
		return err
	}
	registeredMu.RLock()
	fn, ok := registered[name]
	registeredMu.RUnlock()
	if !ok {
		return fmt.Errorf("drbg: %q is not an installed DRBG fill primitive", name)
	}
	return fn(dst)
}

// Register installs a keystream arm under its registry name. Called by
// package ctr at init for every keystream-eligible registry primitive,
// in canonical registry order; a name that is already installed, one
// of the built-in names, or empty is refused. fn must follow the
// [Fill] contract: a fresh crypto/rand seed per call, the output XORed
// or written over dst, the crypto/rand error returned verbatim.
func Register(name string, fn func(dst []byte) error) error {
	if name == "" || name == NameAESITB128 || name == NameCSPRNG {
		return fmt.Errorf("drbg: Register: name %q is reserved", name)
	}
	if fn == nil {
		return fmt.Errorf("drbg: Register: nil fill for %q", name)
	}
	registeredMu.Lock()
	defer registeredMu.Unlock()
	if _, dup := registered[name]; dup {
		return fmt.Errorf("drbg: Register: %q already installed", name)
	}
	registered[name] = fn
	registeredIn = append(registeredIn, name)
	return nil
}

// Names reports every name [FillWith] accepts besides "": "aesitb128"
// first, then the installed keystream arms in installation order (the
// canonical registry order when package ctr installs them), then
// "csprng". The slice is a fresh copy on every call.
func Names() []string {
	registeredMu.RLock()
	defer registeredMu.RUnlock()
	out := make([]string, 0, len(registeredIn)+2)
	out = append(out, NameAESITB128)
	out = append(out, registeredIn...)
	out = append(out, NameCSPRNG)
	return out
}

// Known reports whether name is "" or one of [Names].
func Known(name string) bool {
	switch name {
	case "", NameAESITB128, NameCSPRNG:
		return true
	}
	registeredMu.RLock()
	defer registeredMu.RUnlock()
	_, ok := registered[name]
	return ok
}

// fillAesCTR seeds AES-256 in CTR mode from a fresh 48-byte crypto/rand
// draw and expands the keystream over dst.
func fillAesCTR(dst []byte) error {
	var seed [48]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return err
	}
	block, err := aes.NewCipher(seed[:32])
	if err != nil {
		return err
	}
	stream := cipher.NewCTR(block, seed[32:48])
	stream.XORKeyStream(dst, dst)
	return nil
}

// fillChaCha20 seeds ChaCha20 from a fresh 44-byte crypto/rand draw
// (32-byte key + 12-byte nonce, per RFC 8439) and expands the keystream
// over dst.
func fillChaCha20(dst []byte) error {
	var seed [chacha20.KeySize + chacha20.NonceSize]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return err
	}
	stream, err := chacha20.NewUnauthenticatedCipher(seed[:chacha20.KeySize], seed[chacha20.KeySize:])
	if err != nil {
		return err
	}
	stream.XORKeyStream(dst, dst)
	return nil
}
