package itb

import (
	"crypto/rand"
	"fmt"
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
}

// DefaultNonceBits is the nonce width in bits used when [Config.NonceBits]
// is left at zero. Matches [NonceSize] * 8 for wire-compat with the
// pre-Cfg default.
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
