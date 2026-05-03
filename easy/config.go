package easy

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/everanium/itb"
)

// SetNonceBits overrides the nonce size for this encryptor's
// subsequent encrypt / decrypt calls. Valid values: 128, 256, 512.
// Panics on invalid input — nonce misconfiguration is a security-
// critical bug.
//
// Mutates only the encryptor's own [itb.Config] copy; the
// process-global [itb.SetNonceBits] is unaffected. Both sender and
// receiver must use the same value (the value is captured into the
// state blob via [Encryptor.Export] under future schemas; v1 leaves
// nonce_bits as a deployment-config concern).
//
// Not safe for concurrent invocation with an in-flight encrypt /
// decrypt on the same encryptor — caller serialises if it needs
// concurrency on a single instance. Different encryptors run in
// parallel goroutines without cross-contamination.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) SetNonceBits(n int) {
	if e.closed {
		panic(ErrClosed)
	}
	switch n {
	case 128, 256, 512:
		e.cfg.NonceBits = n
		e.nonceBitsExplicit = true
	default:
		panic(fmt.Sprintf("itb/easy: SetNonceBits(%d): valid values are 128, 256, 512", n))
	}
}

// SetBarrierFill overrides the CSPRNG barrier-fill margin for this
// encryptor. Valid values: 1, 2, 4, 8, 16, 32. Panics on invalid
// input — barrier misconfiguration is a security-critical bug.
//
// Mutates only the encryptor's own [itb.Config] copy. Asymmetric:
// the receiver does not need the same value as the sender.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) SetBarrierFill(n int) {
	if e.closed {
		panic(ErrClosed)
	}
	switch n {
	case 1, 2, 4, 8, 16, 32:
		e.cfg.BarrierFill = n
		e.barrierFillExplicit = true
	default:
		panic(fmt.Sprintf("itb/easy: SetBarrierFill(%d): valid values are 1, 2, 4, 8, 16, 32", n))
	}
}

// SetBitSoup overrides the bit-soup mode for this encryptor.
// 0 = byte-level split (default); non-zero = bit-level "bit soup"
// split. Mutates only the encryptor's own [itb.Config] copy.
//
// Auto-couple guard: when a dedicated lockSeed is active on this
// encryptor (cfg.LockSeed == 1, set either by
// [Encryptor.SetLockSeed](1) or by [NewMixed] / [NewMixed3] with a
// non-empty PrimitiveL), passing mode == 0 is silently overridden
// to mode == 1. The bit-permutation overlay must stay engaged
// while the dedicated lockSeed is allocated; allowing
// SetBitSoup(0) here would let a subsequent encrypt panic with
// ErrLockSeedOverlayOff inside the build-PRF closure when LockSoup
// is also off. Drop the dedicated lockSeed via [Encryptor.SetLockSeed](0)
// first if a fully-overlay-off configuration is the goal.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) SetBitSoup(mode int32) {
	if e.closed {
		panic(ErrClosed)
	}
	if mode == 0 && e.cfg.LockSeed == 1 {
		mode = 1
	}
	e.cfg.BitSoup = mode
	e.bitSoupExplicit = true
}

// SetLockSoup overrides the Lock Soup overlay for this encryptor.
// 0 = off (default); non-zero = on. A non-zero value also coerces
// BitSoup to 1 on this encryptor, mirroring the existing global
// [itb.SetLockSoup] behaviour: the Lock Soup overlay layers on top
// of bit soup, so engaging the overlay engages bit soup as well.
//
// Auto-couple guard mirrors [Encryptor.SetBitSoup]: when a
// dedicated lockSeed is active on this encryptor, passing mode == 0
// is silently overridden to mode == 1 so the bit-permutation
// overlay stays engaged. Drop the dedicated lockSeed via
// [Encryptor.SetLockSeed](0) first if a fully-overlay-off
// configuration is the goal.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) SetLockSoup(mode int32) {
	if e.closed {
		panic(ErrClosed)
	}
	if mode == 0 && e.cfg.LockSeed == 1 {
		mode = 1
	}
	e.cfg.LockSoup = mode
	e.lockSoupExplicit = true
	if mode != 0 {
		e.cfg.BitSoup = 1
		e.bitSoupExplicit = true
	}
}

// SetLockSeed enables or disables the dedicated lockSeed for
// bit-permutation derivation on this encryptor. Valid values:
// 0 = off (default; bit-permutation derives from noiseSeed),
// 1 = on (a dedicated lockSeed of the same primitive / width is
// allocated lazily on the first SetLockSeed(1) call after
// construction; bit-permutation derives from the dedicated seed
// instead). Panics on any other value.
//
// Auto-couples Lock Soup on the on-direction: when mode == 1 this
// also calls [Encryptor.SetLockSoup](1) on the same encryptor,
// which through its own coupling engages BitSoup=1 — the
// dedicated lockSeed has no observable effect on the wire output
// unless the bit-permutation overlay is engaged, so coupling the
// two flags spares callers a second setter call. The off-
// direction does not auto-disable the overlay; callers that want
// to drop only the dedicated seed but keep the overlay engaged
// call SetLockSeed(0) without losing the Lock Soup / Bit Soup
// settings.
//
// Calling SetLockSeed after the encryptor has produced its first
// ciphertext panics with [ErrLockSeedAfterEncrypt] — the bit-
// permutation derivation path cannot change mid-session without
// breaking decryptability of pre-switch ciphertext. Pre-Encrypt
// switching is allowed; mode toggles freely until the first encrypt.
//
// Activating from the off state allocates a fresh CSPRNG-backed
// seed via the same factory used at New / New3 time and appends it
// to the encryptor's seeds + prfKeys slices. Deactivating zeroes
// the dedicated seed's components and PRF key, drops the
// LockSeedHandle from the [itb.Config], and shrinks the slices
// back to 3 (Single) or 7 (Triple).
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) SetLockSeed(mode int32) {
	if e.closed {
		panic(ErrClosed)
	}
	if mode != 0 && mode != 1 {
		panic(fmt.Sprintf("itb/easy: SetLockSeed(%d): valid values are 0, 1", mode))
	}
	if e.firstEncryptCalled {
		panic(ErrLockSeedAfterEncrypt)
	}

	if mode == 1 {
		// Activate: allocate a dedicated lockSeed if not already
		// present, and wire it onto the noiseSeed via the width-
		// typed AttachLockSeed mutator so the build-PRF closure
		// in bitsoup.go sees AttachedLockSeed() != nil for both
		// the cfg-driven (Easy Mode) and the seed-driven (native)
		// dispatch paths. The native attach is symmetric with the
		// Mixed-mode path which already attaches at construction.
		if e.cfg.LockSeedHandle == nil {
			seed, key := allocSeed(e.Primitive, e.KeyBits, e.width)
			e.seeds = append(e.seeds, seed)
			if e.prfKeys != nil {
				e.prfKeys = append(e.prfKeys, key)
			}
			e.cfg.LockSeedHandle = seed
			if len(e.seeds) > 0 {
				attachNoiseSeedLockSeed(e.seeds[0], seed, e.width)
			}
		}
		e.cfg.LockSeed = 1
		// Auto-couple Lock Soup (which itself couples Bit Soup) so
		// the bit-permutation overlay is actually engaged and
		// consumes the dedicated lockSeed. The auto-couple is an
		// explicit user-driven choice — flag both overlays as
		// explicit so [Encryptor.Export] emits them in the state
		// blob alongside the mandatory lock_seed:true field.
		e.cfg.LockSoup = 1
		e.cfg.BitSoup = 1
		e.lockSoupExplicit = true
		e.bitSoupExplicit = true
	} else {
		// Deactivate: zero dedicated lockSeed material and shrink
		// slices back to the Single / Triple base shape.
		if e.cfg.LockSeedHandle != nil {
			zeroSeedComponents(e.cfg.LockSeedHandle, e.width)
			if e.prfKeys != nil && len(e.prfKeys) > 0 {
				clear(e.prfKeys[len(e.prfKeys)-1])
				e.prfKeys = e.prfKeys[:len(e.prfKeys)-1]
			}
			if len(e.seeds) > 0 {
				e.seeds = e.seeds[:len(e.seeds)-1]
			}
			// Mixed-mode encryptors track per-slot primitive names
			// in e.primitives parallel to e.seeds; shrink alongside
			// so post-deactivation Export does not emit a stale
			// trailing primitive entry that the receiver would
			// reject as a length mismatch.
			if len(e.primitives) > len(e.seeds) {
				e.primitives = e.primitives[:len(e.seeds)]
			}
		}
		// Detach the dedicated lockSeed pointer from the noiseSeed
		// so the bit-permutation overlay's build-PRF closure sees
		// AttachedLockSeed() == nil on subsequent Encrypt calls.
		// Without this detach a Mixed-mode SetLockSeed(0) followed
		// by SetBitSoup(0) + SetLockSoup(0) panics with
		// ErrLockSeedOverlayOff inside the build-PRF closure
		// because the noiseSeed still carries the attach from
		// NewMixed / NewMixed3 construction time.
		if len(e.seeds) > 0 {
			detachNoiseSeedLockSeed(e.seeds[0], e.width)
		}
		e.cfg.LockSeedHandle = nil
		e.cfg.LockSeed = 0
	}
}

// SetChunkSize overrides the streaming chunk size for this
// encryptor's subsequent [Encryptor.EncryptStream] calls. 0 selects
// the auto-detect heuristic from [itb.ChunkSize]. The value is
// ignored on the decrypt side — chunk extents are recovered from
// the wire-format header per chunk.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) SetChunkSize(n int) {
	if e.closed {
		panic(ErrClosed)
	}
	e.chunk = n
}

// PRFKeys returns a defensive copy of the per-seed fixed PRF keys.
// One entry per seed slot in canonical order: Single =
// [noise, data, start]; Triple = [noise, data1, data2, data3,
// start1, start2, start3]; with the dedicated lockSeed appended at
// the end when [Encryptor.SetLockSeed](1) is active.
//
// Returns nil for siphash24 — the primitive has no fixed PRF key
// (its keying material is the per-call seed components themselves).
//
// Mutating the returned slice does not affect the encryptor; each
// call allocates fresh copies.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) PRFKeys() [][]byte {
	if e.closed {
		panic(ErrClosed)
	}
	if e.prfKeys == nil {
		return nil
	}
	out := make([][]byte, len(e.prfKeys))
	for i, k := range e.prfKeys {
		out[i] = append([]byte(nil), k...)
	}
	return out
}

// SeedComponents returns a defensive copy of the per-seed component
// vectors. One entry per seed slot in canonical order matching
// [Encryptor.PRFKeys]; each inner slice has length key_bits / 64.
//
// Mutating the returned slice does not affect the encryptor; each
// call allocates fresh copies.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) SeedComponents() [][]uint64 {
	if e.closed {
		panic(ErrClosed)
	}
	out := make([][]uint64, len(e.seeds))
	for i, s := range e.seeds {
		switch v := s.(type) {
		case *itb.Seed128:
			out[i] = append([]uint64(nil), v.Components...)
		case *itb.Seed256:
			out[i] = append([]uint64(nil), v.Components...)
		case *itb.Seed512:
			out[i] = append([]uint64(nil), v.Components...)
		}
	}
	return out
}

// MACKey returns a defensive copy of the encryptor's bound MAC fixed
// key. Mutating the returned slice does not affect the encryptor.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) MACKey() []byte {
	if e.closed {
		panic(ErrClosed)
	}
	return append([]byte(nil), e.macKey...)
}

// NonceBits returns the nonce size in bits configured for this
// encryptor — either the value installed by the most recent
// [Encryptor.SetNonceBits] call, or the process-wide
// [itb.GetNonceBits] reading at construction time when no
// per-instance override has been issued.
//
// The internal Config field cfg.NonceBits is unexported and stays
// that way — callers read the value through this getter, mirroring
// the read-only [Encryptor.Primitive] / [Encryptor.KeyBits] /
// [Encryptor.Mode] / [Encryptor.MACName] surface. Read-only access
// only; the exported field-level path through cfg would let a
// caller mutate cfg.LockSeedHandle / cfg.LockSeed directly and
// break the bit-permutation derivation invariants enforced by
// [Encryptor.SetLockSeed].
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) NonceBits() int {
	if e.closed {
		panic(ErrClosed)
	}
	if e.cfg.NonceBits > 0 {
		return e.cfg.NonceBits
	}
	return itb.GetNonceBits()
}

// HeaderSize returns the per-instance ciphertext-chunk header size
// in bytes — nonce + 2-byte width + 2-byte height. Tracks this
// encryptor's own [Encryptor.NonceBits], NOT the process-wide
// [itb.GetNonceBits] reading.
//
// Use this when slicing a chunk header off the front of a
// ciphertext stream produced by this encryptor or when sizing a
// tamper region for an authenticated-decrypt test. Callers that
// nibble through a ciphertext stream chunk-by-chunk instead of
// going through [Encryptor.EncryptStream] / [Encryptor.DecryptStream]
// pair this with [Encryptor.ParseChunkLen] to walk the wire format
// without touching the process-wide accessors.
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) HeaderSize() int {
	return e.NonceBits()/8 + 4
}

// ParseChunkLen reports the total wire length of one ciphertext
// chunk after inspecting only the fixed-size header at the front of
// the supplied buffer. Per-instance counterpart of
// [itb.ParseChunkLen]: consults [Encryptor.NonceBits] instead of
// the process-wide [itb.GetNonceBits], so a chunk produced by this
// encryptor under a non-default nonce size is parsed correctly
// regardless of the global state.
//
// Buffer convention identical to [itb.ParseChunkLen]: only the
// header bytes need be present; the body bytes do not. Returns an
// error on too-short buffer, zero dimensions, or width × height
// overflow against the container pixel cap.
//
// Streaming consumers walk the wire format with the standard
// per-chunk loop:
//
//	header := make([]byte, enc.HeaderSize())
//	for {
//	    if _, err := io.ReadFull(in, header); err == io.EOF {
//	        return
//	    }
//	    chunkLen, err := enc.ParseChunkLen(header)
//	    if err != nil { return err }
//	    body := make([]byte, chunkLen-enc.HeaderSize())
//	    if _, err := io.ReadFull(in, body); err != nil { return err }
//	    chunk := append(header, body...)
//	    pt, err := enc.Decrypt(chunk)
//	    if err != nil { return err }
//	    out.Write(pt)
//	}
//
// Panics with [ErrClosed] when called after [Encryptor.Close].
func (e *Encryptor) ParseChunkLen(header []byte) (int, error) {
	if e.closed {
		panic(ErrClosed)
	}
	nonceSz := e.NonceBits() / 8
	headerSz := nonceSz + 4
	if len(header) < headerSz {
		return 0, fmt.Errorf("itb/easy: ParseChunkLen: header buffer too short (have %d, need %d)",
			len(header), headerSz)
	}
	width := int(binary.BigEndian.Uint16(header[nonceSz:]))
	height := int(binary.BigEndian.Uint16(header[nonceSz+2:]))
	if width == 0 || height == 0 {
		return 0, fmt.Errorf("itb/easy: ParseChunkLen: zero chunk dimensions (width=%d, height=%d)",
			width, height)
	}
	if width > math.MaxInt/height {
		return 0, fmt.Errorf("itb/easy: ParseChunkLen: dimensions overflow (%d × %d)",
			width, height)
	}
	totalPixels := width * height
	if totalPixels > math.MaxInt/itb.Channels {
		return 0, fmt.Errorf("itb/easy: ParseChunkLen: pixel count overflow (%d pixels × %d channels)",
			totalPixels, itb.Channels)
	}
	// Container pixel-count cap mirrors the upstream
	// itb.ParseChunkLen limit. Without this cap a hostile chunk
	// header announcing width × height ≈ 7 GB could drive a binding
	// to allocate that much before the underlying Decrypt rejects.
	if totalPixels > maxParseChunkPixels {
		return 0, fmt.Errorf("itb/easy: ParseChunkLen: pixel count exceeds cap (%d > %d)",
			totalPixels, maxParseChunkPixels)
	}
	return headerSz + totalPixels*itb.Channels, nil
}

// maxParseChunkPixels mirrors the unexported itb.maxTotalPixels
// constant for the per-instance ParseChunkLen path. A maliciously-
// large chunk header announcing more pixels than this is rejected
// before any caller-side buffer allocation.
const maxParseChunkPixels = 10_000_000

// zeroSeedComponents clears the Components slice of a typed seed
// pointer of the given primitive width. Used by [Encryptor.Close]
// and by SetLockSeed(0) to wipe key material before the encryptor
// drops its handle.
func zeroSeedComponents(handle interface{}, width int) {
	switch width {
	case 128:
		if s, ok := handle.(*itb.Seed128); ok {
			clear(s.Components)
		}
	case 256:
		if s, ok := handle.(*itb.Seed256); ok {
			clear(s.Components)
		}
	case 512:
		if s, ok := handle.(*itb.Seed512); ok {
			clear(s.Components)
		}
	}
}

// detachNoiseSeedLockSeed clears the attached-lockSeed pointer on a
// noiseSeed via the width-typed [itb.Seed{N}.DetachLockSeed]
// mutator. Used by [Encryptor.SetLockSeed](0) to keep the
// noiseSeed's attach state in sync with the cfg.LockSeedHandle
// drop. No-op when the handle is the wrong type or the seed has no
// attach to begin with.
func detachNoiseSeedLockSeed(handle interface{}, width int) {
	switch width {
	case 128:
		if s, ok := handle.(*itb.Seed128); ok {
			s.DetachLockSeed()
		}
	case 256:
		if s, ok := handle.(*itb.Seed256); ok {
			s.DetachLockSeed()
		}
	case 512:
		if s, ok := handle.(*itb.Seed512); ok {
			s.DetachLockSeed()
		}
	}
}

// attachNoiseSeedLockSeed wires the lockSeed pointer onto the
// noiseSeed via the width-typed [itb.Seed{N}.AttachLockSeed]
// mutator. Used by [Encryptor.SetLockSeed](1) and by Import on
// the rawLockSeed branch to keep the noiseSeed's attach state in
// sync with the cfg.LockSeedHandle field. No-op when either
// handle is the wrong type for the supplied width.
func attachNoiseSeedLockSeed(noise, lock interface{}, width int) {
	switch width {
	case 128:
		ns, nsOK := noise.(*itb.Seed128)
		ls, lsOK := lock.(*itb.Seed128)
		if nsOK && lsOK {
			ns.AttachLockSeed(ls)
		}
	case 256:
		ns, nsOK := noise.(*itb.Seed256)
		ls, lsOK := lock.(*itb.Seed256)
		if nsOK && lsOK {
			ns.AttachLockSeed(ls)
		}
	case 512:
		ns, nsOK := noise.(*itb.Seed512)
		ls, lsOK := lock.(*itb.Seed512)
		if nsOK && lsOK {
			ns.AttachLockSeed(ls)
		}
	}
}
