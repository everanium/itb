package itb

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync/atomic"
)

// ErrLockSeedSelfAttach is the panic value raised by [Seed128.AttachLockSeed]
// / [Seed256.AttachLockSeed] / [Seed512.AttachLockSeed] when the receiver
// noiseSeed pointer is identical to the lockSeed argument. Self-attach
// would defeat the entire entropy-isolation purpose of the dedicated
// lockSeed (bit-permutation derivation would still consume noiseSeed
// material) and is rejected loudly rather than silently degraded.
var ErrLockSeedSelfAttach = errors.New("itb: AttachLockSeed: cannot attach a seed to itself")

// ErrLockSeedComponentAliasing is the panic value raised by
// [Seed128.AttachLockSeed] / [Seed256.AttachLockSeed] /
// [Seed512.AttachLockSeed] when the noiseSeed and lockSeed share the
// same Components backing array. Aliased Components carry identical
// uint64 values, again defeating the entropy-isolation purpose; the
// guard catches the case where a caller built lockSeed by copying
// noiseSeed and then re-pointed lockSeed.Components at noiseSeed's
// slice.
var ErrLockSeedComponentAliasing = errors.New("itb: AttachLockSeed: noiseSeed and lockSeed share the same Components backing array")

// ErrLockSeedAfterEncrypt is the panic value raised by
// [Seed128.AttachLockSeed] / [Seed256.AttachLockSeed] /
// [Seed512.AttachLockSeed] when AttachLockSeed is invoked on a
// noiseSeed that has already been used in a successful Encrypt path.
// Switching the dedicated lockSeed mid-session would break
// decryptability of pre-switch ciphertext; the guard rejects the
// switch loudly so callers correct the call ordering rather than
// shipping silently-wrong ciphertext.
var ErrLockSeedAfterEncrypt = errors.New("itb: AttachLockSeed: cannot attach lockSeed after first Encrypt")

// ErrLockSeedOverlayOff is the panic value raised by the bit-
// permutation PRF builders ([buildPermutePRF128] / [buildPermutePRF256]
// / [buildPermutePRF512] for Single Ouroboros, [buildLockPRF128] /
// [buildLockPRF256] / [buildLockPRF512] for Triple Ouroboros, plus the
// matching Cfg-suffixed variants) when the noiseSeed carries an
// attached dedicated lockSeed but neither the bit-soup nor the
// lock-soup overlay is engaged on the active dispatch path. The
// dedicated lockSeed has no observable effect on the wire output
// without one of the overlays — derivation is consulted only inside
// [splitForSingle] / [splitForTriple] / their Cfg counterparts, both
// of which short-circuit to an unchanged-data pass-through when both
// flags are off. Silently producing byte-level ciphertext while the
// caller has explicitly attached a dedicated lockSeed is an action-
// at-a-distance bug; the guard panics so callers either turn on the
// overlay (via [SetLockSoup] / [SetBitSoup] for the legacy path,
// per-encryptor cfg.LockSoup / cfg.BitSoup for the Cfg path, or
// [github.com/everanium/itb/easy.Encryptor.SetLockSeed] for the
// high-level surface which auto-couples both overlays) or remove the
// AttachLockSeed call.
//
// On-encrypt rather than on-attach: the guard fires every time a
// build-PRF function is invoked, so it catches the misuse regardless
// of call ordering — attach before SetLockSoup, attach after, or
// SetLockSoup(0) toggled between attach and Encrypt all surface as
// the same panic at the same point in the pipeline.
var ErrLockSeedOverlayOff = errors.New("itb: AttachedLockSeed installed but neither BitSoup nor LockSoup overlay is engaged")

// testNonceOverride is set only by test code (see setTestNonce in *_test.go).
// Production callers never set this — generateNonce falls through to crypto/rand.
// One atomic load per encryption in the hot path; negligible overhead in
// production, critical for nonce-reuse attack simulation in Probe 1 of the
// red-team plan.
var testNonceOverride atomic.Pointer[[]byte]

// NonceSize is the default per-message nonce size in bytes (128 bits).
// Use SetNonceBits to change. Birthday collision at ~2^(nonceBits/2) messages.
const NonceSize = 16

// nonceSizeOverride stores the configured nonce size in bytes (0 = use default NonceSize).
var nonceSizeOverride atomic.Int32

// SetNonceBits sets the nonce size in bits. Valid values: 128, 256, 512.
// Panics on invalid input — nonce misconfiguration is a security-critical bug.
// Both sender and receiver must use the same value.
// Thread-safe (atomic). Affects all subsequent Encrypt calls.
func SetNonceBits(n int) {
	switch n {
	case 128:
		nonceSizeOverride.Store(16)
	case 256:
		nonceSizeOverride.Store(32)
	case 512:
		nonceSizeOverride.Store(64)
	default:
		panic(fmt.Sprintf("itb: SetNonceBits(%d): valid values are 128, 256, 512", n))
	}
}

// GetNonceBits returns the current nonce size in bits.
func GetNonceBits() int {
	return currentNonceSize() * 8
}

// currentNonceSize returns the current nonce size in bytes.
func currentNonceSize() int {
	if n := int(nonceSizeOverride.Load()); n > 0 {
		return n
	}
	return NonceSize
}

// barrierFillOverride stores the configured barrier fill value (0 = use default 1).
var barrierFillOverride atomic.Int32

// SetBarrierFill sets the CSPRNG barrier fill margin added to the container side.
// Valid values: 1, 2, 4, 8, 16, 32. Default is 1.
// Panics on invalid input — barrier misconfiguration is a security-critical bug.
// Asymmetric: the receiver does not need the same value as the sender.
// Thread-safe (atomic). Affects all subsequent Encrypt calls.
func SetBarrierFill(n int) {
	switch n {
	case 1, 2, 4, 8, 16, 32:
		barrierFillOverride.Store(int32(n))
	default:
		panic(fmt.Sprintf("itb: SetBarrierFill(%d): valid values are 1, 2, 4, 8, 16, 32", n))
	}
}

// GetBarrierFill returns the current barrier fill value.
// Returns 1 if no override is set (default).
func GetBarrierFill() int {
	return currentBarrierFill()
}

// currentBarrierFill returns the current barrier fill value.
func currentBarrierFill() int {
	if n := int(barrierFillOverride.Load()); n > 0 {
		return n
	}
	return 1
}

// MaxKeyBits is the maximum supported key size in bits.
// Effective security depends on hash function's internal state width.
const MaxKeyBits = 2048

// generateNonce returns a fresh cryptographic nonce of current configured size.
// If a test has installed a fixed nonce via setTestNonce, returns a copy of
// that instead — used for nonce-reuse attack simulation. Production callers
// never hit the override branch (the setter is in *_test.go only).
func generateNonce() ([]byte, error) {
	if p := testNonceOverride.Load(); p != nil {
		return append([]byte(nil), *p...), nil
	}
	nonce := make([]byte, currentNonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return nonce, nil
}

// secureWipe zeroes a byte slice to minimize sensitive data exposure in memory.
// clear() lowers to runtime.memclrNoHeapPointers — an observable side-effect
// the compiler cannot elide, replacing the prior manual-loop + KeepAlive
// pattern with a single intrinsic that widens to vector stores on amd64.
func secureWipe(b []byte) {
	clear(b)
}

// generateRandomBytes returns n cryptographically random bytes.
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("itb: crypto/rand: %w", err)
	}
	return b, nil
}

// lockSeedEnabled controls whether the encryptor constructor
// allocates a dedicated lockSeed for bit-permutation derivation,
// separating that channel's entropy from the noiseSeed-driven
// noise-injection channel. Default 0 = off (bit-permutation derives
// from noiseSeed, the pre-LockSeed behaviour). Non-zero = on
// (dedicated lockSeed generated at construction; bit-permutation
// derives from it instead).
//
// Honoured only by the encryptor constructor. Low-level entry points
// (Encrypt512 etc.) consult neither the global flag nor a dedicated
// lockSeed — threading the extra seed through their signatures
// would break the public API. Low-level callers seeking equivalent
// entropy isolation use Triple Ouroboros.
//
// Stored in an atomic.Int32 so concurrent reads from parallel encrypt /
// decrypt goroutines are race-free.
var lockSeedEnabled atomic.Int32

// SetLockSeed enables or disables the dedicated lockSeed for
// bit-permutation derivation. Valid values: 0 = off (default,
// bit-permutation derives from noiseSeed), 1 = on. Panics on any
// other value.
//
// Auto-couples Lock Soup on the on-direction: when n == 1 this also
// calls [SetLockSoup](1), which through its existing coupling
// engages [SetBitSoup](1) too — the dedicated lockSeed has no
// observable effect on the wire output unless the bit-permutation
// overlay is engaged, so coupling the two flags spares callers a
// second setter call. The off-direction does not auto-disable the
// overlay; callers that explicitly enabled Lock Soup / Bit Soup
// alongside LockSeed and want to drop only LockSeed call
// SetLockSeed(0) without losing the underlying overlay.
//
// Two-tier consumption:
//
//   - The encryptor constructor in the easy sub-package reads this
//     flag at New / New3 time via [SnapshotGlobals]; encryptors built
//     after this call get a dedicated lockSeed allocated and wired
//     into cfg.LockSeedHandle automatically.
//   - The legacy itb root entry points (Encrypt{N} / Decrypt{N} /
//     Encrypt3x{N} / Decrypt3x{N} and friends) do NOT consume this
//     flag directly — they consult only [Seed128.AttachedLockSeed]
//     / [Seed256.AttachedLockSeed] / [Seed512.AttachedLockSeed] for
//     the dedicated-seed path. Callers that want LockSeed on the
//     legacy path call [Seed128.AttachLockSeed] / etc. on the
//     noiseSeed; the global flag still auto-enables the
//     bit-permutation overlay (so the output IS bit-soup-permuted)
//     but the keying material falls back to noiseSeed when no
//     attach has happened.
//
// Thread-safe (atomic). Affects encryptors constructed AFTER this
// call; existing encryptors are pinned at their construction
// snapshot.
func SetLockSeed(n int) {
	switch n {
	case 0, 1:
		lockSeedEnabled.Store(int32(n))
	default:
		panic(fmt.Sprintf("itb: SetLockSeed(%d): valid values are 0, 1", n))
	}
	if n == 1 {
		SetLockSoup(1)
	}
}

// GetLockSeed returns the current dedicated-lockSeed activation flag
// (0 = off, 1 = on). See [SetLockSeed].
func GetLockSeed() int32 { return lockSeedEnabled.Load() }

// isLockSeedActive is the internal dispatch check used by the
// encryptor constructor and by [isLockSeedActiveCfg] when the
// per-encryptor cfg field carries the "inherit" sentinel.
func isLockSeedActive() bool { return lockSeedEnabled.Load() != 0 }
