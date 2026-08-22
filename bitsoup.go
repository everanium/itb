package itb

import (
	"encoding/binary"
	"sync/atomic"
)

// lockSoupEnabled controls the 48-bit interlock keyed-permutation
// overlay. Default 0 = off (byte-level split, no overlay). Non-zero =
// on (per-chunk PRF-keyed 16-of-48 mask triple, ~2^70 mask-space rank
// per 6-byte chunk).
//
// Stored in an atomic.Int32 so concurrent reads from parallel encrypt /
// decrypt goroutines are race-free. Each Encrypt* / Decrypt* call
// performs a single load at dispatch and uses that captured value for
// the entire operation.
var lockSoupEnabled atomic.Int32

// SetLockSoup configures the interlock keyed bit-permutation overlay
// for the whole process.
//
//	mode == 0 → off (default; ciphertext follows the byte-level round-robin split).
//	mode != 0 → on (per-chunk PRF-keyed 48-bit interlock).
//
// Applies uniformly to every Triple Ouroboros variant — [Encrypt3x128] /
// [Decrypt3x128], the 256- / 512-bit mirrors, [EncryptAuthenticated3x128] /
// [DecryptAuthenticated3x128] and their mirrors. Both sides of the
// channel must use the same mode; mismatched modes produce
// wrong-seed-style garbage (no error oracle, plausible-decryption
// invariant preserved).
//
// Deployment discipline: set the mode once at process startup before
// any encrypt or decrypt call; callers must agree on the mode across
// both sides of the channel.
//
// The 48-bit interlock overlay raises the attacker enumeration cost
// per 6-byte chunk to the C(48,16)·C(32,16) mask-space rank (~2^70.20),
// well above the per-primitive PRF bit-count. This is an opt-in
// defense-reserve mode that makes any SAT-tractable recovery path
// infeasible even for below-spec primitives.
func SetLockSoup(mode int32) {
	lockSoupEnabled.Store(mode)
}

// GetLockSoup returns the current interlock overlay mode (0 = off,
// non-zero = on). See [SetLockSoup].
func GetLockSoup() int32 { return lockSoupEnabled.Load() }

// isLockSoupEnabled is the internal dispatch check used by
// [splitForTriple48LockedCfg] / [interleaveForTriple48LockedCfg].
// Single atomic load. Called exactly once at entry of the locked
// dispatchers; the returned bool is captured in a local and the
// per-chunk loop branches on the local, not on this function.
func isLockSoupEnabled() bool { return lockSoupEnabled.Load() != 0 }

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
