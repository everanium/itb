package itb

import (
	"crypto/rand"
	"fmt"
)

// Config carries per-encryptor overrides for the global-state settings
// that are safe to scope per encryptor: nonce size and barrier fill.
// The MaxWorkers global stays process-wide and is not represented
// here — effectiveWorkers is consulted from many internal paths and
// threading per-encryptor would expand the refactor without
// proportional benefit.
//
// Sentinel-valued fields signal "inherit the current global state at
// access time"; non-sentinel values signal that the encryptor has
// explicitly set the field. The sentinel value differs per field:
//
//   - NonceBits: 0 = inherit; otherwise 128 / 256 / 512 (in bits).
//   - BarrierFill: 0 = inherit; otherwise 1 / 2 / 4 / 8 / 16 / 32.
//
// The struct is unexported. The legacy public entry points
// (Encrypt3x512 etc.) pass nil to the Cfg-variant entry points and
// inherit the global state, preserving pre-refactor behaviour
// bit-exactly.
type Config struct {
	NonceBits   int // 0 = inherit; otherwise 128 / 256 / 512
	BarrierFill int // 0 = inherit; otherwise 1 / 2 / 4 / 8 / 16 / 32
}

// SnapshotGlobals returns a Config initialised from the current
// process-global setter state. The encryptor constructor invokes
// this at New3 time so the encryptor's effective Config matches the
// global state at construction. Subsequent mutations of either side
// (global setters or encryptor setters) do not cross — the encryptor
// owns its own Config copy and mutates only that.
//
// Every snapshotted field carries the global's actual value (not the
// inherit sentinel) — pinning the encryptor to the global state at
// New3 time. Subsequent global mutations therefore do not leak into
// existing encryptors; only encryptors constructed AFTER the global
// mutation see the new value.
func SnapshotGlobals() *Config {
	return &Config{
		NonceBits:   GetNonceBits(),
		BarrierFill: GetBarrierFill(),
	}
}

// currentNonceSizeCfg returns the nonce size in bytes the caller
// should use. Cfg variant of currentNonceSize: consults cfg when
// non-nil and the NonceBits field carries a non-zero value;
// otherwise falls through to currentNonceSize (the process-global
// accessor in seed.go).
//
// nil cfg is permitted — the legacy public entry points pass nil to
// inherit the global, preserving pre-refactor behaviour bit-exactly.
func currentNonceSizeCfg(cfg *Config) int {
	if cfg != nil && cfg.NonceBits > 0 {
		return cfg.NonceBits / 8
	}
	return currentNonceSize()
}

// currentBarrierFillCfg returns the barrier fill margin the caller
// should use. Cfg variant of currentBarrierFill: consults cfg when
// non-nil and the BarrierFill field carries a non-zero value;
// otherwise falls through to currentBarrierFill.
func currentBarrierFillCfg(cfg *Config) int {
	if cfg != nil && cfg.BarrierFill > 0 {
		return cfg.BarrierFill
	}
	return currentBarrierFill()
}

// generateNonceCfg returns a fresh cryptographic nonce of the
// configured size. Cfg variant of generateNonce: resolves nonce size
// via currentNonceSizeCfg(cfg), so a per-encryptor NonceBits override
// is honoured. The test-nonce override path
// (testNonceOverride atomic.Pointer) remains in effect — installed
// only by *_test.go fixtures, never by production callers.
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
