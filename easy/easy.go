// Package easy provides a high-level Encryptor / Decryptor object on
// top of the lower-level [itb.Encrypt{128,256,512}Cfg] / friends API.
// One constructor call ([New] or [New3]) replaces the existing
// 7-line setup ceremony — hash factory, three (or seven) seeds, MAC
// closure, container-config wiring — and returns an [Encryptor] that
// owns its own per-instance configuration so two encryptors with
// different settings can run in parallel goroutines without cross-
// contamination.
//
// Mixing PRF primitives across the noise / data / start seeds is
// not supported in this package; the encryptor accepts a single
// primitive name that is applied to every seed slot. Deployments
// requiring mixed primitives use the existing low-level path
// directly.
package easy

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
)

// ErrClosed indicates the encryptor's state has been zeroed by
// [Encryptor.Close]; subsequent method calls on the same instance
// return this error.
var ErrClosed = errors.New("itb/easy: encryptor is closed")

// ErrMalformed indicates the state blob passed to [Encryptor.Import]
// is structurally invalid — JSON parse failure, unknown kind tag,
// unsupported mode value, non-canonical lock_seed encoding, or any
// other shape the v1 decoder rejects before field-level validation.
var ErrMalformed = errors.New("itb/easy: malformed state blob")

// ErrVersionTooNew indicates the state blob carries a version number
// greater than the highest version this build understands. Strict-
// fail is the correct posture for a cipher state blob — silent
// feature loss on a too-new blob risks subtle mis-decryption.
var ErrVersionTooNew = errors.New("itb/easy: state blob version too new")

// ErrUnknownPrimitive indicates the state blob names a hash primitive
// not present in the local [hashes.Registry].
var ErrUnknownPrimitive = errors.New("itb/easy: unknown primitive in state blob")

// ErrUnknownMAC indicates the state blob names a MAC not present in
// the local [macs.Registry].
var ErrUnknownMAC = errors.New("itb/easy: unknown MAC in state blob")

// ErrBadKeyBits indicates the state blob's key_bits value is outside
// the supported {512, 1024, 2048} set or is not an integer multiple
// of the primitive's native width.
var ErrBadKeyBits = errors.New("itb/easy: invalid key_bits in state blob")

// ErrLockSeedAfterEncrypt indicates [Encryptor.SetLockSeed] was
// called after the encryptor produced its first ciphertext. The
// bit-permutation derivation path cannot change mid-session without
// breaking decryptability of previously-emitted ciphertext, so the
// switch is rejected.
var ErrLockSeedAfterEncrypt = errors.New("itb/easy: SetLockSeed after first Encrypt is not allowed")

// ErrStreamAuthNotImplemented is returned by
// [Encryptor.EncryptStreamAuth] and [Encryptor.DecryptStreamAuth]
// until the streaming-AEAD design ships. The signatures are reserved
// so v1 callers can interface-detect availability.
var ErrStreamAuthNotImplemented = errors.New("itb/easy: EncryptStreamAuth / DecryptStreamAuth is not yet implemented")

// ErrMismatch indicates the state blob disagrees with the receiver's
// bound configuration on a specific field. Field is the canonical
// JSON field name that triggered the rejection.
type ErrMismatch struct {
	Field string
}

// Error implements the error interface.
func (e *ErrMismatch) Error() string {
	return fmt.Sprintf("itb/easy: state blob field %q does not match encryptor configuration", e.Field)
}

// State-blob constants.
const (
	// kindEasy is the frozen "kind" tag for v1 state blobs. The
	// reader rejects any blob whose kind field disagrees.
	kindEasy = "itb-easy"

	// versionV1 is the current state-blob schema version. Future
	// schema bumps either remain backward-compatible (additive
	// fields) or require a new version number.
	versionV1 = 1
)

// Default constructor parameters.
const (
	defaultPrimitive = "areion512"
	defaultKeyBits   = 1024
	defaultMAC       = "kmac256"
)

// Encryptor is the high-level encrypt / decrypt object returned by
// [New] and [New3]. It owns a per-instance config snapshot taken at
// construction time, fixed PRF keys and seed components for each
// seed slot, a MAC closure bound to a fixed MAC key, and an optional
// dedicated lockSeed when LockSeed is active.
//
// The four exported fields (Primitive, KeyBits, Mode, MACName) are
// read-only after construction. Mutating them directly produces
// undefined behaviour; reads are safe. Subsequent configuration
// changes go through the [Encryptor.SetNonceBits],
// [Encryptor.SetBarrierFill], [Encryptor.SetBitSoup],
// [Encryptor.SetLockSoup], [Encryptor.SetLockSeed], and
// [Encryptor.SetChunkSize] methods, which mutate the encryptor's own
// config copy without touching process globals or other encryptors.
type Encryptor struct {
	// Primitive is the canonical [hashes.Registry] name the encryptor
	// is bound to.
	Primitive string

	// KeyBits is the per-seed key width in bits — one of 256, 512,
	// 1024, 2048. Must be an integer multiple of the primitive's
	// native hash width.
	KeyBits int

	// Mode selects Single Ouroboros (1, 3 seeds) or Triple Ouroboros
	// (3, 7 seeds). The integer encoding mirrors the Encrypt /
	// Encrypt3x distinction at the low-level API.
	Mode int

	// MACName is the canonical [macs.Registry] name the bound MAC
	// closure was derived from.
	MACName string

	// width caches the primitive's native hash width (128 / 256 /
	// 512) for the per-call dispatch in Encrypt / Decrypt and their
	// counterparts. Equal to int(hashes.Find(Primitive).Width) at
	// construction time.
	width int

	// cfg carries this encryptor's per-instance configuration —
	// snapshot of the global setter state at New / New3 time, plus
	// any subsequent setter mutations. Threaded into every Cfg-aware
	// itb-package entry point.
	cfg *itb.Config

	// seeds holds 3 (Single), 7 (Triple), 4 (Single + LockSeed), or
	// 8 (Triple + LockSeed) typed seed pointers in canonical order:
	// Single = [noise, data, start]; Triple = [noise, data1, data2,
	// data3, start1, start2, start3]; with LockSeed appended at the
	// end. Each entry is *itb.Seed128, *itb.Seed256, or *itb.Seed512
	// matching the primitive's native width.
	seeds []interface{}

	// prfKeys holds the per-seed fixed PRF key bytes parallel to
	// seeds. nil when the primitive has no fixed PRF key
	// (siphash24); otherwise len(prfKeys) == len(seeds) and each
	// entry is the primitive's native key size in bytes.
	prfKeys [][]byte

	// macKey is the fixed MAC key the bound MACFunc was derived from.
	// Held alongside macFunc for state serialization.
	macKey []byte

	// macFunc is the MAC closure bound to macKey at construction.
	// Consumed by EncryptAuth / DecryptAuth.
	macFunc itb.MACFunc

	// chunk is the streaming chunk-size override (0 = auto-detect via
	// [itb.ChunkSize]).
	chunk int

	// closed is the post-Close guard. Once Close has zeroed key
	// material, every subsequent method call returns ErrClosed.
	closed bool

	// firstEncryptCalled tracks whether any Encrypt / EncryptAuth /
	// EncryptStream call has succeeded on this encryptor. Used by
	// SetLockSeed to reject mid-session bit-permutation path
	// switches that would break decryptability of pre-switch
	// ciphertext.
	firstEncryptCalled bool

	// nonceBitsExplicit / barrierFillExplicit / bitSoupExplicit /
	// lockSoupExplicit track whether the corresponding cfg field
	// was set by an explicit [Encryptor.SetNonceBits] /
	// [Encryptor.SetBarrierFill] / [Encryptor.SetBitSoup] /
	// [Encryptor.SetLockSoup] call (or restored from a state blob
	// that carried the field). [SnapshotGlobals] pins cfg.* to
	// the process-global state at construction, so the cfg value
	// alone does not distinguish "user set" from "snapshot of
	// global"; the flags do. [Encryptor.Export] consults them to
	// decide whether to emit the optional nonce_bits /
	// barrier_fill / bit_soup / lock_soup fields in the blob.
	nonceBitsExplicit   bool
	barrierFillExplicit bool
	bitSoupExplicit     bool
	lockSoupExplicit    bool
}

// New constructs an [Encryptor] configured for Single Ouroboros
// (3 seeds — noise, data, start). args may include any of:
//
//   - One string matching [hashes.Registry] — selects the PRF
//     primitive; default "areion512".
//   - One string matching [macs.Registry] — selects the MAC; default
//     "kmac256".
//   - One int — selects key_bits; default 1024.
//
// Argument order is irrelevant; type-dispatch resolves each value to
// its role. Duplicates of the same kind, unknown names, unsupported
// argument types, key_bits outside {512, 1024, 2048} or not
// divisible by the primitive's native width all panic — security
// parameters are not recoverable, and surfacing them as Go errors
// invites code that ignores the value.
//
// crypto/rand failure during PRF / seed / MAC key generation is also
// a panic with the standard "itb: crypto/rand: ..." message — the
// same convention as the existing low-level constructors.
//
// The returned Encryptor's exported fields (Primitive, KeyBits,
// Mode, MACName) are read-only after construction; configuration
// changes go through the per-encryptor setters.
func New(args ...any) *Encryptor {
	return newEncryptor(1, args...)
}

// New3 constructs an [Encryptor] configured for Triple Ouroboros
// (7 seeds — noise plus three pairs of (data, start)). Variadic
// argument shape matches [New].
func New3(args ...any) *Encryptor {
	return newEncryptor(3, args...)
}

// newEncryptor is the shared body of [New] and [New3], parameterised
// on the seed-count mode (1 = Single / 3 seeds; 3 = Triple / 7
// seeds).
func newEncryptor(mode int, args ...any) *Encryptor {
	primitive, keyBits, macName := parseConstructorArgs(args)

	spec, ok := hashes.Find(primitive)
	if !ok {
		panic(fmt.Sprintf("itb/easy: unknown primitive %q", primitive))
	}
	switch keyBits {
	case 512, 1024, 2048:
	default:
		panic(fmt.Sprintf("itb/easy: key_bits=%d invalid (valid values: 512, 1024, 2048)", keyBits))
	}
	if keyBits%int(spec.Width) != 0 {
		panic(fmt.Sprintf("itb/easy: key_bits=%d not divisible by primitive %q width=%d",
			keyBits, primitive, int(spec.Width)))
	}

	macSpec, ok := macs.Find(macName)
	if !ok {
		panic(fmt.Sprintf("itb/easy: unknown MAC %q", macName))
	}

	nSeeds := 3
	if mode == 3 {
		nSeeds = 7
	}

	cfg := itb.SnapshotGlobals()

	enc := &Encryptor{
		Primitive: primitive,
		KeyBits:   keyBits,
		Mode:      mode,
		MACName:   macName,
		width:     int(spec.Width),
		cfg:       cfg,
	}

	// Generate one PRF key + one seed per slot.
	seeds := make([]interface{}, 0, nSeeds+1)
	prfKeysPerSlot := make([][]byte, 0, nSeeds+1)
	for i := 0; i < nSeeds; i++ {
		seed, key := allocSeed(primitive, keyBits, int(spec.Width))
		seeds = append(seeds, seed)
		prfKeysPerSlot = append(prfKeysPerSlot, key)
	}

	// LockSeed: when active in the snapshotted cfg (or after a
	// pre-Encrypt SetLockSeed(1) call processed by the setter), one
	// extra seed of the same primitive / width is allocated and
	// recorded as cfg.LockSeedHandle so the bit-permutation
	// derivation routes through it instead of noiseSeed.
	if cfg.LockSeed > 0 {
		seed, key := allocSeed(primitive, keyBits, int(spec.Width))
		seeds = append(seeds, seed)
		prfKeysPerSlot = append(prfKeysPerSlot, key)
		cfg.LockSeedHandle = seed
	}

	enc.seeds = seeds
	if primitive == "siphash24" {
		// SipHash-2-4 has no fixed PRF key — its keying material is
		// the per-call seed components. Storage matches the JSON
		// field-omitted convention (PRFKeys returns nil).
		enc.prfKeys = nil
	} else {
		enc.prfKeys = prfKeysPerSlot
	}

	// MAC fixed key + closure.
	macKey := make([]byte, macSpec.KeySize)
	if _, err := rand.Read(macKey); err != nil {
		panic(fmt.Sprintf("itb/easy: crypto/rand: %v", err))
	}
	macFunc, err := macs.Make(macName, macKey)
	if err != nil {
		panic(fmt.Sprintf("itb/easy: macs.Make(%q): %v", macName, err))
	}
	enc.macKey = macKey
	enc.macFunc = macFunc

	return enc
}

// parseConstructorArgs resolves the variadic constructor arguments to
// (primitive, keyBits, macName) by type-dispatch:
//
//   - string matching hashes.Registry → primitive
//   - string matching macs.Registry → MAC name
//   - int → key_bits
//
// Unset fields fall back to the documented defaults. Duplicates of
// the same kind, unknown names, and unsupported argument types
// panic.
func parseConstructorArgs(args []any) (primitive string, keyBits int, macName string) {
	primitive = defaultPrimitive
	keyBits = defaultKeyBits
	macName = defaultMAC

	seenPrimitive, seenMAC, seenKeyBits := false, false, false

	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			if _, ok := hashes.Find(v); ok {
				if seenPrimitive {
					panic("itb/easy: duplicate primitive name")
				}
				primitive = v
				seenPrimitive = true
				continue
			}
			if _, ok := macs.Find(v); ok {
				if seenMAC {
					panic("itb/easy: duplicate MAC name")
				}
				macName = v
				seenMAC = true
				continue
			}
			panic(fmt.Sprintf("itb/easy: unknown name %q", v))
		case int:
			if seenKeyBits {
				panic("itb/easy: duplicate key_bits")
			}
			keyBits = v
			seenKeyBits = true
		default:
			panic(fmt.Sprintf("itb/easy: unsupported argument type %T", arg))
		}
	}
	return
}

// allocSeed builds one fresh PRF key + matching seed for the given
// primitive / key_bits / width combination. The PRF closure is
// produced via [hashes.Make128Pair] / [hashes.Make256Pair] /
// [hashes.Make512Pair] so the batched arm is wired alongside the
// single arm; the returned seed has its BatchHash field assigned.
//
// For siphash24 the primitive has no fixed PRF key — the returned
// key slice is nil; the seed is still bound to a freshly-built
// closure (its keying material comes from the per-call seed
// components, not a fixed key).
//
// crypto/rand failure during the PRF factory's internal key
// generation propagates as a panic with the standard
// "itb/easy: crypto/rand: ..." prefix.
func allocSeed(primitive string, keyBits, width int) (seed interface{}, prfKey []byte) {
	switch width {
	case 128:
		single, batched, key, err := hashes.Make128Pair(primitive)
		if err != nil {
			panic(fmt.Sprintf("itb/easy: hashes.Make128Pair(%q): %v", primitive, err))
		}
		s, err := itb.NewSeed128(keyBits, single)
		if err != nil {
			panic(fmt.Sprintf("itb/easy: itb.NewSeed128: %v", err))
		}
		s.BatchHash = batched
		return s, key
	case 256:
		single, batched, key, err := hashes.Make256Pair(primitive)
		if err != nil {
			panic(fmt.Sprintf("itb/easy: hashes.Make256Pair(%q): %v", primitive, err))
		}
		s, err := itb.NewSeed256(keyBits, single)
		if err != nil {
			panic(fmt.Sprintf("itb/easy: itb.NewSeed256: %v", err))
		}
		s.BatchHash = batched
		return s, key
	case 512:
		single, batched, key, err := hashes.Make512Pair(primitive)
		if err != nil {
			panic(fmt.Sprintf("itb/easy: hashes.Make512Pair(%q): %v", primitive, err))
		}
		s, err := itb.NewSeed512(keyBits, single)
		if err != nil {
			panic(fmt.Sprintf("itb/easy: itb.NewSeed512: %v", err))
		}
		s.BatchHash = batched
		return s, key
	}
	panic(fmt.Sprintf("itb/easy: unsupported primitive width %d", width))
}
