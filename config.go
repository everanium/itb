package itb

import (
	"crypto/rand"
	"fmt"
	"slices"
)

// Config carries per-encryptor overrides for the previously-global
// dispatch settings that scope per encryptor: nonce size, barrier
// fill, and parallel-worker cap.
//
// Sentinel-valued fields signal "inherit the compile-in default";
// non-sentinel values signal that the encryptor has explicitly set
// the field. The sentinel value differs per field:
//
//   - NonceBits: 0 = inherit [DefaultNonceBits]; otherwise 128 / 256 /
//     512 (in bits).
//   - BarrierFill: 0 = inherit [DefaultBarrierFill]; otherwise
//     1 / 2 / 4 / 8 / 16 / 32.
//   - MaxWorkers: 0 = use runtime.NumCPU; otherwise 1..256. Values
//     above 256 are clamped at consumption.
//
// A nil *Config passed to a Cfg-suffixed entry point behaves as an
// all-zero Config — every field falls back to the compile-in default
// or the runtime.NumCPU cap.
type Config struct {
	NonceBits   int // 0 = inherit DefaultNonceBits; otherwise 128 / 256 / 512
	BarrierFill int // 0 = inherit DefaultBarrierFill; otherwise 1 / 2 / 4 / 8 / 16 / 32
	MaxWorkers  int // 0 = runtime.NumCPU; otherwise 1..256

	// MACIncremental is the optional multi-slice MAC arm consulted by
	// the authenticated entry points. When non-nil it must compute the
	// same tag as the macFunc passed to the same call, per the
	// [MACIncrementalFunc] contract; the entry points then absorb the
	// MAC input parts directly instead of concatenating them into a
	// scratch buffer first. nil (the zero value) keeps the legacy
	// concatenate-then-MAC path.
	MACIncremental MACIncrementalFunc
}

// DefaultNonceBits is the nonce width in bits used when [Config.NonceBits]
// is left at zero. Derived from [NonceSize] * 8 = 512 bits — chosen so
// the birthday-bound on collision under fresh-nonce generation is beyond
// any realistic deployment volume without the caller having to override.
const DefaultNonceBits = NonceSize * 8

// DefaultBarrierFill is the CSPRNG barrier fill margin used when
// [Config.BarrierFill] is left at zero. The default of 1 pixel is the
// minimum sufficient margin for the "guaranteed CSPRNG fill" invariant
// (Proof 10); larger values increase the barrier at wire-size cost.
const DefaultBarrierFill = 1

// currentNonceSizeCfg returns the nonce size in bytes the caller
// should use. Consults cfg when non-nil and the NonceBits field
// carries a non-zero value; otherwise falls back to [DefaultNonceBits].
//
// nil cfg is permitted — every Cfg-suffixed entry point accepts nil
// and resolves to the compile-in default via this path.
func currentNonceSizeCfg(cfg *Config) int {
	if cfg != nil && cfg.NonceBits > 0 {
		return cfg.NonceBits / 8
	}
	return DefaultNonceBits / 8
}

// currentBarrierFillCfg returns the barrier fill margin the caller
// should use. Consults cfg when non-nil and the BarrierFill field
// carries a non-zero value; otherwise falls back to
// [DefaultBarrierFill].
func currentBarrierFillCfg(cfg *Config) int {
	if cfg != nil && cfg.BarrierFill > 0 {
		return cfg.BarrierFill
	}
	return DefaultBarrierFill
}

// generateNonceCfg returns a fresh cryptographic nonce of the
// configured size. Resolves nonce size via [currentNonceSizeCfg]. The
// test-nonce override path ([testNonceOverride], set only by *_test.go
// fixtures) remains in effect for red-team probes.
func generateNonceCfg(cfg *Config) ([]byte, error) {
	if p := testNonceOverride.Load(); p != nil {
		return append([]byte(nil), *p...), nil
	}
	nonce := make([]byte, currentNonceSizeCfg(cfg))
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return nonce, nil
}

// generateInterlockNonceCfg returns a fresh cryptographic interlock
// nonce of the configured size — the second, independently drawn nonce
// of the dual-nonce wire header. Width is symmetric with the main
// nonce (resolved via [currentNonceSizeCfg]); the draw is a separate
// crypto/rand call so the two nonces share no derivation state. The
// interlock nonce keys the Interlocked Barrier overlay's per-chunk
// permutation derivation (via deriveInterLockSeed), while the main
// nonce keys the pixel-encoding derivations; simultaneous collision of
// both independent draws is required to reproduce a full reuse event.
// The test-nonce override path ([testInterlockNonceOverride], set only
// by *_test.go fixtures) remains in effect for red-team probes.
func generateInterlockNonceCfg(cfg *Config) ([]byte, error) {
	if p := testInterlockNonceOverride.Load(); p != nil {
		return append([]byte(nil), *p...), nil
	}
	nonce := make([]byte, currentNonceSizeCfg(cfg))
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return nonce, nil
}

// generateNoncePairCfg draws the dual-nonce header pair — main nonce
// and interlock nonce — guaranteed byte-distinct at the draw site.
// Distinctness is architecturally already provided by the separate
// domain tags on the downstream derivations (0x02 startPixel, 0x04
// interlock); the re-draw loop is belt-and-suspenders so the pair is
// provably distinct by construction as well.
//
// The loop fires only on the CSPRNG path: when either test override
// ([testNonceOverride] / [testInterlockNonceOverride]) is installed,
// the override values are respected literally so red-team fixtures can
// force any collision class (main-only / interlock-only / both). Under
// a working CSPRNG the per-iteration collision probability is
// 2^-nonceBits (128 minimum), so the loop terminates on the first
// iteration with overwhelming probability; no retry cap is needed.
//
// Edge case worth documenting: when only ONE override is installed
// (e.g. testNonceOverride is set, testInterlockNonceOverride is not),
// the CSPRNG-drawn other half may — with 2^-nonceBits probability —
// happen to equal the override half, and the pair returns byte-equal
// because the distinctness loop stays disabled under any-override.
// This does NOT weaken the three-axis independence of the two
// derivations: slot separation (lockSeed vs startSeed_i, byte-guaranteed
// distinct by checkEightSeeds) and domain-tag separation (0x04 vs
// 0x02) keep the ChainHash outputs independent under the PRF
// assumption even for a byte-equal nonce pair. The loop is a draw-site
// hygiene invariant, not a security dependency.
//
// The decrypt path never calls this — wire nonces arrive from the
// header and are consumed as-is.
func generateNoncePairCfg(cfg *Config) (mainNonce, ilNonce []byte, err error) {
	ilNonce, err = generateInterlockNonceCfg(cfg)
	if err != nil {
		return nil, nil, err
	}
	mainNonce, err = generateNonceCfg(cfg)
	if err != nil {
		return nil, nil, err
	}
	if testNonceOverride.Load() != nil || testInterlockNonceOverride.Load() != nil {
		return mainNonce, ilNonce, nil
	}
	for slices.Equal(mainNonce, ilNonce) {
		mainNonce, err = generateNonceCfg(cfg)
		if err != nil {
			return nil, nil, err
		}
	}
	return mainNonce, ilNonce, nil
}
