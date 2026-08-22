package itb

import (
	"encoding/binary"
)

// prependTripleLen returns [uint32_BE(len(data)):4] || data. The 4-byte
// big-endian length prefix is carried inside the plaintext across the
// bit-level split; after decrypt-side interleave, the first 4 bytes of
// the recovered stream give the exact plaintext length, enabling
// deterministic slicing without a separate header widening.
func prependTripleLen(data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(out[:4], uint32(len(data)))
	copy(out[4:], data)
	return out
}

// permSeedCfg128 returns the seed to use for inter-lock derivation,
// in this precedence:
//
//  1. cfg.LockSeedHandle if non-nil and type-narrows to *Seed128 —
//     the easy sub-package's per-encryptor explicit dedicated seed.
//  2. noiseSeed.AttachedLockSeed() if non-nil — the low-level
//     [Seed128.AttachLockSeed] mutator path.
//  3. noiseSeed itself — the pre-LockSeed default.
//
// A nil cfg, an absent handle, or a type-narrow mismatch all fall
// through to the AttachedLockSeed check, and from there to
// noiseSeed. The width-mismatch fallback in (1) is defensive only —
// the encryptor constructor enforces matching widths at LockSeed
// activation time.
func permSeedCfg128(cfg *Config, noiseSeed *Seed128) *Seed128 {
	if cfg != nil && cfg.LockSeedHandle != nil {
		if ls, ok := cfg.LockSeedHandle.(*Seed128); ok {
			return ls
		}
	}
	if ls := noiseSeed.AttachedLockSeed(); ls != nil {
		return ls
	}
	return noiseSeed
}

// permSeedCfg256 — 256-bit equivalent of [permSeedCfg128].
func permSeedCfg256(cfg *Config, noiseSeed *Seed256) *Seed256 {
	if cfg != nil && cfg.LockSeedHandle != nil {
		if ls, ok := cfg.LockSeedHandle.(*Seed256); ok {
			return ls
		}
	}
	if ls := noiseSeed.AttachedLockSeed(); ls != nil {
		return ls
	}
	return noiseSeed
}

// permSeedCfg512 — 512-bit equivalent of [permSeedCfg128].
func permSeedCfg512(cfg *Config, noiseSeed *Seed512) *Seed512 {
	if cfg != nil && cfg.LockSeedHandle != nil {
		if ls, ok := cfg.LockSeedHandle.(*Seed512); ok {
			return ls
		}
	}
	if ls := noiseSeed.AttachedLockSeed(); ls != nil {
		return ls
	}
	return noiseSeed
}
