package capi

import (
	"runtime/cgo"
	"sync/atomic"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// SeedHandle is the FFI-side handle representing one ITB seed. It
// erases the underlying Seed{128|256|512} type behind a uintptr that
// is stable across the cgo boundary, while keeping the actual *Seed
// pointer rooted on the Go heap (cgo.Handle pins the value against
// GC). Three handles together — noise, data, start — feed Encrypt
// and Decrypt; the underlying width must match across the trio.
type SeedHandle struct {
	width   hashes.Width
	hashStr string

	// hashKey is the fixed key the hash closure is bound to. For
	// random-key constructions (NewSeed), this is generated at
	// construction and stored here so the caller can retrieve it via
	// SeedHashKey for cross-process persistence. For explicit-key
	// constructions, this is the supplied key. Length depends on the
	// primitive: 16 (aescmac), 32 (chacha20 / blake2{s,b256} / blake3
	// / areion256), 64 (blake2b512 / areion512), or zero-length for
	// siphash24 (which has no internal fixed key).
	hashKey []byte

	seed128 *itb.Seed128
	seed256 *itb.Seed256
	seed512 *itb.Seed512
}

// HandleID is the opaque uintptr passed across the C ABI as a seed
// reference. Internally a runtime/cgo.Handle that maps back to a
// *SeedHandle on the Go heap.
type HandleID uintptr

// lastErr stores the last status emitted by any capi call, so the
// FFI ITB_LastError entry point can report a textual reason. The
// last-error pattern is process-wide and intentionally racy under
// concurrent failure paths — callers are expected to inspect
// LastError immediately after a non-OK return on the same thread,
// the standard errno idiom.
var lastErr atomic.Pointer[string]

func setLastErr(s Status) {
	v := s.String()
	lastErr.Store(&v)
}

// recoverPanic translates any Go panic crossing this point into the
// supplied fallback Status, preventing the panic from unwinding
// across the cgo boundary and tearing down the host process. Used
// at every FFI entry point to firewall transitive panic sources
// (crypto/rand failures inside hash factories, internal slice-
// bounds panics in the cipher core, primitive constructor errors).
//
// The caller pattern is `defer recoverPanic(&st, fallback)`. If
// recover() returns a non-nil value, *st is overwritten with the
// fallback Status and the last-error message is set to a generic
// "internal error" string.
func recoverPanic(st *Status, fallback Status) {
	if r := recover(); r != nil {
		setLastErr(fallback)
		*st = fallback
	}
}

// LastError returns the textual reason for the most recent non-OK
// status produced by any capi call.
func LastError() string {
	if p := lastErr.Load(); p != nil {
		return *p
	}
	return ""
}

// NewSeed builds a fresh seed for hashName at the requested ITB key
// width (512..2048, multiple of the primitive's native hash width).
// The native hash width is looked up in hashes.Registry; the
// resulting Seed{128|256|512} is rooted behind a cgo.Handle and
// exposed as an opaque HandleID.
//
// The factory invokes the named hash primitive's WithKey-less
// constructor, which calls crypto/rand.Read to materialise a fresh
// fixed key. crypto/rand failures (chrooted /dev/urandom etc.) are
// rare but possible; the deferred recoverPanic translates them
// into StatusInternal rather than letting a panic cross the cgo
// boundary.
func NewSeed(hashName string, keyBits int) (id HandleID, st Status) {
	defer recoverPanic(&st, StatusInternal)

	spec, ok := hashes.Find(hashName)
	if !ok {
		setLastErr(StatusBadHash)
		return 0, StatusBadHash
	}
	if keyBits < 512 || keyBits > itb.MaxKeyBits {
		setLastErr(StatusBadKeyBits)
		return 0, StatusBadKeyBits
	}
	if keyBits%int(spec.Width) != 0 {
		setLastErr(StatusBadKeyBits)
		return 0, StatusBadKeyBits
	}

	h := &SeedHandle{width: spec.Width, hashStr: hashName}

	switch spec.Width {
	case hashes.W128:
		hf, bf, hashKey, err := hashes.Make128Pair(hashName)
		if err != nil {
			setLastErr(StatusBadHash)
			return 0, StatusBadHash
		}
		s, err := itb.NewSeed128(keyBits, hf)
		if err != nil {
			setLastErr(StatusBadKeyBits)
			return 0, StatusBadKeyBits
		}
		if bf != nil {
			s.BatchHash = bf
		}
		h.seed128 = s
		h.hashKey = hashKey
	case hashes.W256:
		hf, bf, hashKey, err := hashes.Make256Pair(hashName)
		if err != nil {
			setLastErr(StatusBadHash)
			return 0, StatusBadHash
		}
		s, err := itb.NewSeed256(keyBits, hf)
		if err != nil {
			setLastErr(StatusBadKeyBits)
			return 0, StatusBadKeyBits
		}
		if bf != nil {
			s.BatchHash = bf
		}
		h.seed256 = s
		h.hashKey = hashKey
	case hashes.W512:
		hf, bf, hashKey, err := hashes.Make512Pair(hashName)
		if err != nil {
			setLastErr(StatusBadHash)
			return 0, StatusBadHash
		}
		s, err := itb.NewSeed512(keyBits, hf)
		if err != nil {
			setLastErr(StatusBadKeyBits)
			return 0, StatusBadKeyBits
		}
		if bf != nil {
			s.BatchHash = bf
		}
		h.seed512 = s
		h.hashKey = hashKey
	default:
		setLastErr(StatusInternal)
		return 0, StatusInternal
	}

	return HandleID(cgo.NewHandle(h)), StatusOK
}

// FreeSeed releases the cgo.Handle, allowing the *Seed to be
// garbage-collected. The handle must not be used after this call;
// repeat calls return StatusBadHandle (cgo.Handle.Delete panics on
// a stale handle, the deferred recover translates that into a clean
// FFI error code).
func FreeSeed(id HandleID) (st Status) {
	if id == 0 {
		setLastErr(StatusBadHandle)
		return StatusBadHandle
	}
	defer func() {
		if r := recover(); r != nil {
			setLastErr(StatusBadHandle)
			st = StatusBadHandle
		}
	}()
	cgo.Handle(id).Delete()
	return StatusOK
}

// resolve returns the *SeedHandle behind an opaque HandleID, or
// (nil, StatusBadHandle) if the handle is zero or stale.
// cgo.Handle.Value() panics on a stale handle; the deferred recover
// translates that into a clean StatusBadHandle return so FFI callers
// get an error code instead of a process-wide panic.
func resolve(id HandleID) (h *SeedHandle, st Status) {
	if id == 0 {
		setLastErr(StatusBadHandle)
		return nil, StatusBadHandle
	}
	defer func() {
		if r := recover(); r != nil {
			setLastErr(StatusBadHandle)
			h, st = nil, StatusBadHandle
		}
	}()
	v := cgo.Handle(id).Value()
	hh, ok := v.(*SeedHandle)
	if !ok || hh == nil {
		setLastErr(StatusBadHandle)
		return nil, StatusBadHandle
	}
	return hh, StatusOK
}

// SeedWidth returns the native hash width of an existing seed handle.
func SeedWidth(id HandleID) (hashes.Width, Status) {
	h, st := resolve(id)
	if st != StatusOK {
		return 0, st
	}
	return h.width, StatusOK
}

// SeedHashName returns the canonical hash name an existing seed
// handle was built with.
func SeedHashName(id HandleID) (string, Status) {
	h, st := resolve(id)
	if st != StatusOK {
		return "", st
	}
	return h.hashStr, StatusOK
}

// SeedHashKey returns the fixed key the underlying hash closure is
// bound to. The bytes returned are the random key NewSeed* /
// NewSeedFromComponents* generated at construction (or the explicit
// key the caller supplied, on the persistence-restore path) — save
// them across processes alongside the seed components for
// encrypt-today / decrypt-tomorrow flows.
//
// SipHash-2-4 has no internal fixed key (its keying material is the
// per-call seed components), so the returned slice is empty for
// "siphash24" — callers can detect this via len(key) == 0 and rely
// on SeedComponents alone for SipHash persistence.
func SeedHashKey(id HandleID) ([]byte, Status) {
	h, st := resolve(id)
	if st != StatusOK {
		return nil, st
	}
	out := make([]byte, len(h.hashKey))
	copy(out, h.hashKey)
	return out, StatusOK
}

// SeedComponents returns the seed's underlying key components as a
// slice of uint64. Length is keyBits/64 (8..32). Counterpart of the
// caller-supplied components passed to NewSeedFromComponents — save
// these alongside SeedHashKey for cross-process restore.
func SeedComponents(id HandleID) ([]uint64, Status) {
	h, st := resolve(id)
	if st != StatusOK {
		return nil, st
	}
	switch h.width {
	case hashes.W128:
		out := make([]uint64, len(h.seed128.Components))
		copy(out, h.seed128.Components)
		return out, StatusOK
	case hashes.W256:
		out := make([]uint64, len(h.seed256.Components))
		copy(out, h.seed256.Components)
		return out, StatusOK
	case hashes.W512:
		out := make([]uint64, len(h.seed512.Components))
		copy(out, h.seed512.Components)
		return out, StatusOK
	}
	setLastErr(StatusInternal)
	return nil, StatusInternal
}

// NewSeedFromComponents builds a seed for hashName from caller-
// supplied uint64 components (deterministic counterpart of NewSeed
// which generates the components from crypto/rand). The hashKey
// argument is optional — pass an empty slice for a CSPRNG-generated
// hash key (the random-key path), or a slice of the primitive's
// native fixed-key length for the persistence-restore path.
//
// Component count must be in [8, MaxKeyBits/64] and a multiple of 8.
// hashKey, when non-empty, must be exactly the primitive's native
// key size (16 for aescmac, 32 for areion256/blake2{s,b256}/blake3/
// chacha20, 64 for areion512/blake2b512). hashKey is ignored for
// "siphash24" (must be empty).
//
// The resulting handle is rooted behind a cgo.Handle; SeedHashKey
// returns the fixed key in use (the supplied one if hashKey was
// non-empty, otherwise the freshly generated one).
func NewSeedFromComponents(hashName string, components []uint64, hashKey []byte) (id HandleID, st Status) {
	defer recoverPanic(&st, StatusInternal)

	spec, ok := hashes.Find(hashName)
	if !ok {
		setLastErr(StatusBadHash)
		return 0, StatusBadHash
	}
	if len(components) < 8 || len(components)*64 > itb.MaxKeyBits {
		setLastErr(StatusBadKeyBits)
		return 0, StatusBadKeyBits
	}
	if len(components)%8 != 0 {
		setLastErr(StatusBadKeyBits)
		return 0, StatusBadKeyBits
	}
	keyBits := len(components) * 64
	if keyBits%int(spec.Width) != 0 {
		setLastErr(StatusBadKeyBits)
		return 0, StatusBadKeyBits
	}

	// Optional hashKey is forwarded to the registry as a variadic
	// argument when non-empty; the registry validates the size.
	var keyArgs [][]byte
	if len(hashKey) > 0 {
		keyArgs = [][]byte{hashKey}
	}

	h := &SeedHandle{width: spec.Width, hashStr: hashName}

	switch spec.Width {
	case hashes.W128:
		hf, bf, generatedKey, err := hashes.Make128Pair(hashName, keyArgs...)
		if err != nil {
			setLastErr(StatusBadHash)
			return 0, StatusBadHash
		}
		s, err := itb.SeedFromComponents128(hf, components...)
		if err != nil {
			setLastErr(StatusBadKeyBits)
			return 0, StatusBadKeyBits
		}
		if bf != nil {
			s.BatchHash = bf
		}
		h.seed128 = s
		h.hashKey = generatedKey
	case hashes.W256:
		hf, bf, generatedKey, err := hashes.Make256Pair(hashName, keyArgs...)
		if err != nil {
			setLastErr(StatusBadHash)
			return 0, StatusBadHash
		}
		s, err := itb.SeedFromComponents256(hf, components...)
		if err != nil {
			setLastErr(StatusBadKeyBits)
			return 0, StatusBadKeyBits
		}
		if bf != nil {
			s.BatchHash = bf
		}
		h.seed256 = s
		h.hashKey = generatedKey
	case hashes.W512:
		hf, bf, generatedKey, err := hashes.Make512Pair(hashName, keyArgs...)
		if err != nil {
			setLastErr(StatusBadHash)
			return 0, StatusBadHash
		}
		s, err := itb.SeedFromComponents512(hf, components...)
		if err != nil {
			setLastErr(StatusBadKeyBits)
			return 0, StatusBadKeyBits
		}
		if bf != nil {
			s.BatchHash = bf
		}
		h.seed512 = s
		h.hashKey = generatedKey
	default:
		setLastErr(StatusInternal)
		return 0, StatusInternal
	}

	return HandleID(cgo.NewHandle(h)), StatusOK
}
