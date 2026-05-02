package capi

import (
	"errors"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// AttachLockSeed wires a dedicated lockSeed handle (the bit-permutation
// derivation key source) onto an existing noise seed handle, exposing
// the low-level [Seed128.AttachLockSeed] / [Seed256.AttachLockSeed] /
// [Seed512.AttachLockSeed] mutators across the C ABI.
//
// The two handles must share the same native hash width; mixing
// widths returns StatusSeedWidthMix. The underlying seed mutator
// panics in three documented misuse cases — self-attach, component-
// array aliasing, and post-Encrypt switching — plus the bit-soup-
// builder ErrLockSeedOverlayOff guard fires later on Encrypt time
// if neither BitSoup nor LockSoup is engaged on the active dispatch
// path. The deferred recover here translates the three attach-time
// panics to StatusBadInput; the overlay-off guard panics elsewhere
// (build*PRF) and is not visible from this entry point.
//
// The lockSeed handle remains owned by the caller — AttachLockSeed
// only records the pointer on the noise seed; releasing the lockSeed
// via FreeSeed before the noise seed is used invalidates the dedicated
// derivation path. The standard pairing is: keep lockSeed alive for
// the lifetime of the noise seed.
//
// Bindings exposing AttachLockSeed must engage the bit-permutation
// overlay (set_bit_soup(1) or set_lock_soup(1) at the global setter
// level for the legacy entry points; cfg.LockSoup / cfg.BitSoup for
// the Cfg variants) before the first Encrypt call, otherwise the
// overlay-off guard inside the build-PRF closure raises
// itb.ErrLockSeedOverlayOff.
func AttachLockSeed(noise, lock HandleID) (st Status) {
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok {
				switch {
				case errors.Is(err, itb.ErrLockSeedSelfAttach),
					errors.Is(err, itb.ErrLockSeedComponentAliasing),
					errors.Is(err, itb.ErrLockSeedAfterEncrypt):
					setLastErr(StatusBadInput)
					st = StatusBadInput
					return
				}
			}
			setLastErr(StatusInternal)
			st = StatusInternal
		}
	}()

	ns, st := resolve(noise)
	if st != StatusOK {
		return st
	}
	ls, st := resolve(lock)
	if st != StatusOK {
		return st
	}
	if ns.width != ls.width {
		setLastErr(StatusSeedWidthMix)
		return StatusSeedWidthMix
	}

	switch ns.width {
	case hashes.W128:
		ns.seed128.AttachLockSeed(ls.seed128)
	case hashes.W256:
		ns.seed256.AttachLockSeed(ls.seed256)
	case hashes.W512:
		ns.seed512.AttachLockSeed(ls.seed512)
	default:
		setLastErr(StatusInternal)
		return StatusInternal
	}
	return StatusOK
}
