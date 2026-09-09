// Package drbg provides a bulk-fill CSPRNG for the ITB encrypt hot path.
//
// The two production consumers are the container fill in buildTripleWire3
// (three parallel goroutines each filling roughly a third of the wire
// container with noise bytes) and the CSPRNG tail fill of every
// Interlocked lane in the same fused function. The bytes produced are
// consumed as ciphertext-carrier noise or as CSPRNG residue trimmed
// against the plaintext-derived payload — they never re-appear as key
// material, seed components, or any output that survives beyond the
// encrypt call as an entropy source. Key / nonce / seed derivation
// stays on crypto/rand.Read.
//
// Fill acquires a fresh 48-byte seed from crypto/rand.Read on every call
// (32-byte AES-256 key + 16-byte AES-CTR IV, or 32-byte key + 12-byte
// ChaCha20 nonce depending on tier) and expands the seed into a
// keystream that is XOR'd against dst in place. On the two production
// call sites dst is drawn from a bufferPool checkout or a fresh make()
// slice, both of which are zero-initialised — the XOR against zero
// yields raw keystream, matching the byte-for-byte semantic of
// rand.Read(buf).
//
// Tier selection is automatic at package init:
//
//   - amd64 with AES-NI     -> AES-CTR (crypto/aes + cipher.NewCTR)
//   - arm64 with ARMv8-AES  -> AES-CTR
//   - Everything else       -> ChaCha20 (golang.org/x/crypto/chacha20)
//
// On 11700K the AES-CTR tier hits ~6.7 GB/s per goroutine (measured in
// scratch/drbg-bench Phase A); the ChaCha20 tier matches crypto/rand's
// vgetrandom throughput on hardware without AES acceleration. Either
// tier is a strict throughput win over the syscall-backed baseline in
// the three-goroutine container-fill shape because per-goroutine cost is
// no longer serialised through the kernel's per-thread ChaCha20-DRBG
// state.
//
// The environment variable ITB_DRBG_TIER can force one of the two
// tiers ("aes" or "chacha") for parity / diagnostic purposes; an
// unrecognised or unsupported token falls back silently to the
// auto-selected tier and the package emits no output.
package drbg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"os"
	"strings"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/sys/cpu"
)

// fillFn is the tier-specific fill worker. Every implementation reads
// its seed from crypto/rand.Read on entry, constructs its keystream
// state and XORs the keystream against dst in place. Returns the
// crypto/rand.Read error verbatim when seed acquisition fails.
type fillFn func(dst []byte) error

var (
	// selected is the fill worker picked at package init after
	// consulting ITB_DRBG_TIER and the host feature flags. Reads of
	// selected are single-writer / single-init and require no
	// synchronisation.
	selected fillFn
	// selectedName is the tier name for diagnostic reporting (never
	// consumed by the fill path itself; exposed via SelectedTier).
	selectedName string
)

func init() {
	selected, selectedName = pickTier()
}

// pickTier resolves the fill worker for this build's tier ladder. Env
// override wins when the requested tier is supported; otherwise the
// auto-select ladder chooses AES-CTR on hardware with AES acceleration
// and ChaCha20 everywhere else.
func pickTier() (fillFn, string) {
	forced := strings.ToLower(strings.TrimSpace(os.Getenv("ITB_DRBG_TIER")))
	hasAES := hostHasAES()
	switch forced {
	case "aes", "aesctr", "aes-ctr":
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
// from a fresh crypto/rand.Read seed and expanded through the selected
// tier's keystream cipher. The seed is pulled once per call; no state
// persists across calls.
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
