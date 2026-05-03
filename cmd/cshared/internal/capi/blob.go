package capi

import (
	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
)

// BlobSetKey stores the hash key bytes for the requested slot on
// the blob handle. The slot is one of the BlobSlot* constants;
// the bytes must match the width-native fixed-key length for the
// 256 / 512 widths (32 / 64 bytes), or be empty / 16 bytes for the
// 128 width (siphash24 has no internal key, aescmac is 16 bytes).
//
// The key is copied into the handle, so the caller may release the
// source buffer immediately. Subsequent BlobGetKey calls on the
// same slot return a fresh copy of the stored bytes.
//
// Returns StatusBadInput on an unknown slot or wrong key length.
// Subsequent BlobExport / BlobExport3 calls read from the slots
// the caller populated; unset slots are treated as zero / empty
// at Export time.
func BlobSetKey(id BlobHandleID, slot int, key []byte) (st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveBlob(id)
	if st != StatusOK {
		return st
	}
	switch h.width {
	case hashes.W128:
		// 128-bit width carries variable-length keys: empty for
		// siphash24 (no internal fixed key), 16 bytes for aescmac.
		// The blob struct stores []byte directly without size
		// validation; downstream Make128Pair on Import enforces
		// the correct length per primitive.
		buf := append([]byte(nil), key...)
		switch slot {
		case BlobSlotN:
			h.blob128.KeyN = buf
		case BlobSlotD:
			h.blob128.KeyD = buf
		case BlobSlotS:
			h.blob128.KeyS = buf
		case BlobSlotL:
			h.blob128.KeyL = buf
		case BlobSlotD1:
			h.blob128.KeyD1 = buf
		case BlobSlotD2:
			h.blob128.KeyD2 = buf
		case BlobSlotD3:
			h.blob128.KeyD3 = buf
		case BlobSlotS1:
			h.blob128.KeyS1 = buf
		case BlobSlotS2:
			h.blob128.KeyS2 = buf
		case BlobSlotS3:
			h.blob128.KeyS3 = buf
		default:
			setLastErr(StatusBadInput)
			return StatusBadInput
		}
		return StatusOK
	case hashes.W256:
		// 256-bit width carries fixed [32]byte keys. The size is
		// enforced here rather than at Export time to surface the
		// error at the offending Set call.
		if len(key) != 32 {
			setLastErr(StatusBadInput)
			return StatusBadInput
		}
		var arr [32]byte
		copy(arr[:], key)
		switch slot {
		case BlobSlotN:
			h.blob256.KeyN = arr
		case BlobSlotD:
			h.blob256.KeyD = arr
		case BlobSlotS:
			h.blob256.KeyS = arr
		case BlobSlotL:
			h.blob256.KeyL = arr
		case BlobSlotD1:
			h.blob256.KeyD1 = arr
		case BlobSlotD2:
			h.blob256.KeyD2 = arr
		case BlobSlotD3:
			h.blob256.KeyD3 = arr
		case BlobSlotS1:
			h.blob256.KeyS1 = arr
		case BlobSlotS2:
			h.blob256.KeyS2 = arr
		case BlobSlotS3:
			h.blob256.KeyS3 = arr
		default:
			setLastErr(StatusBadInput)
			return StatusBadInput
		}
		return StatusOK
	case hashes.W512:
		// 512-bit width carries fixed [64]byte keys.
		if len(key) != 64 {
			setLastErr(StatusBadInput)
			return StatusBadInput
		}
		var arr [64]byte
		copy(arr[:], key)
		switch slot {
		case BlobSlotN:
			h.blob512.KeyN = arr
		case BlobSlotD:
			h.blob512.KeyD = arr
		case BlobSlotS:
			h.blob512.KeyS = arr
		case BlobSlotL:
			h.blob512.KeyL = arr
		case BlobSlotD1:
			h.blob512.KeyD1 = arr
		case BlobSlotD2:
			h.blob512.KeyD2 = arr
		case BlobSlotD3:
			h.blob512.KeyD3 = arr
		case BlobSlotS1:
			h.blob512.KeyS1 = arr
		case BlobSlotS2:
			h.blob512.KeyS2 = arr
		case BlobSlotS3:
			h.blob512.KeyS3 = arr
		default:
			setLastErr(StatusBadInput)
			return StatusBadInput
		}
		return StatusOK
	}
	setLastErr(StatusInternal)
	return StatusInternal
}

// BlobGetKey copies the hash key bytes from the requested slot into
// out and returns the number of bytes that were available on the
// handle. The caller-allocated-buffer convention applies: a probe
// pass with len(out) == 0 returns the required capacity in n with
// st == StatusBufferTooSmall, so bindings can size their buffer
// in two phases.
//
// For the 128-bit width the slot may carry zero bytes (siphash24
// path) — n == 0 then signals "no key", not "buffer too small".
// The discriminator is len(out) on the call: if out is nil and the
// slot is empty, returns (0, StatusOK).
func BlobGetKey(id BlobHandleID, slot int, out []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveBlob(id)
	if st != StatusOK {
		return 0, st
	}
	var src []byte
	switch h.width {
	case hashes.W128:
		switch slot {
		case BlobSlotN:
			src = h.blob128.KeyN
		case BlobSlotD:
			src = h.blob128.KeyD
		case BlobSlotS:
			src = h.blob128.KeyS
		case BlobSlotL:
			src = h.blob128.KeyL
		case BlobSlotD1:
			src = h.blob128.KeyD1
		case BlobSlotD2:
			src = h.blob128.KeyD2
		case BlobSlotD3:
			src = h.blob128.KeyD3
		case BlobSlotS1:
			src = h.blob128.KeyS1
		case BlobSlotS2:
			src = h.blob128.KeyS2
		case BlobSlotS3:
			src = h.blob128.KeyS3
		default:
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
	case hashes.W256:
		var arr [32]byte
		switch slot {
		case BlobSlotN:
			arr = h.blob256.KeyN
		case BlobSlotD:
			arr = h.blob256.KeyD
		case BlobSlotS:
			arr = h.blob256.KeyS
		case BlobSlotL:
			arr = h.blob256.KeyL
		case BlobSlotD1:
			arr = h.blob256.KeyD1
		case BlobSlotD2:
			arr = h.blob256.KeyD2
		case BlobSlotD3:
			arr = h.blob256.KeyD3
		case BlobSlotS1:
			arr = h.blob256.KeyS1
		case BlobSlotS2:
			arr = h.blob256.KeyS2
		case BlobSlotS3:
			arr = h.blob256.KeyS3
		default:
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		src = arr[:]
	case hashes.W512:
		var arr [64]byte
		switch slot {
		case BlobSlotN:
			arr = h.blob512.KeyN
		case BlobSlotD:
			arr = h.blob512.KeyD
		case BlobSlotS:
			arr = h.blob512.KeyS
		case BlobSlotL:
			arr = h.blob512.KeyL
		case BlobSlotD1:
			arr = h.blob512.KeyD1
		case BlobSlotD2:
			arr = h.blob512.KeyD2
		case BlobSlotD3:
			arr = h.blob512.KeyD3
		case BlobSlotS1:
			arr = h.blob512.KeyS1
		case BlobSlotS2:
			arr = h.blob512.KeyS2
		case BlobSlotS3:
			arr = h.blob512.KeyS3
		default:
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		src = arr[:]
	default:
		setLastErr(StatusInternal)
		return 0, StatusInternal
	}
	if len(src) > len(out) {
		setLastErr(StatusBufferTooSmall)
		return len(src), StatusBufferTooSmall
	}
	copy(out, src)
	return len(src), StatusOK
}

// BlobSetComponents stores the seed components for the requested
// slot on the blob handle. The components slice is copied into the
// handle (the underlying *Seed{N} is constructed if it does not
// exist yet on this slot). Component count must satisfy the same
// 8..MaxKeyBits/64 multiple-of-8 invariants as NewSeedFromComponents
// — the validation is deferred to Export / Import where blob.go
// applies it consistently.
func BlobSetComponents(id BlobHandleID, slot int, comps []uint64) (st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveBlob(id)
	if st != StatusOK {
		return st
	}
	cp := append([]uint64(nil), comps...)
	switch h.width {
	case hashes.W128:
		switch slot {
		case BlobSlotN:
			h.blob128.NS = &itb.Seed128{Components: cp}
		case BlobSlotD:
			h.blob128.DS = &itb.Seed128{Components: cp}
		case BlobSlotS:
			h.blob128.SS = &itb.Seed128{Components: cp}
		case BlobSlotL:
			h.blob128.LS = &itb.Seed128{Components: cp}
		case BlobSlotD1:
			h.blob128.DS1 = &itb.Seed128{Components: cp}
		case BlobSlotD2:
			h.blob128.DS2 = &itb.Seed128{Components: cp}
		case BlobSlotD3:
			h.blob128.DS3 = &itb.Seed128{Components: cp}
		case BlobSlotS1:
			h.blob128.SS1 = &itb.Seed128{Components: cp}
		case BlobSlotS2:
			h.blob128.SS2 = &itb.Seed128{Components: cp}
		case BlobSlotS3:
			h.blob128.SS3 = &itb.Seed128{Components: cp}
		default:
			setLastErr(StatusBadInput)
			return StatusBadInput
		}
		return StatusOK
	case hashes.W256:
		switch slot {
		case BlobSlotN:
			h.blob256.NS = &itb.Seed256{Components: cp}
		case BlobSlotD:
			h.blob256.DS = &itb.Seed256{Components: cp}
		case BlobSlotS:
			h.blob256.SS = &itb.Seed256{Components: cp}
		case BlobSlotL:
			h.blob256.LS = &itb.Seed256{Components: cp}
		case BlobSlotD1:
			h.blob256.DS1 = &itb.Seed256{Components: cp}
		case BlobSlotD2:
			h.blob256.DS2 = &itb.Seed256{Components: cp}
		case BlobSlotD3:
			h.blob256.DS3 = &itb.Seed256{Components: cp}
		case BlobSlotS1:
			h.blob256.SS1 = &itb.Seed256{Components: cp}
		case BlobSlotS2:
			h.blob256.SS2 = &itb.Seed256{Components: cp}
		case BlobSlotS3:
			h.blob256.SS3 = &itb.Seed256{Components: cp}
		default:
			setLastErr(StatusBadInput)
			return StatusBadInput
		}
		return StatusOK
	case hashes.W512:
		switch slot {
		case BlobSlotN:
			h.blob512.NS = &itb.Seed512{Components: cp}
		case BlobSlotD:
			h.blob512.DS = &itb.Seed512{Components: cp}
		case BlobSlotS:
			h.blob512.SS = &itb.Seed512{Components: cp}
		case BlobSlotL:
			h.blob512.LS = &itb.Seed512{Components: cp}
		case BlobSlotD1:
			h.blob512.DS1 = &itb.Seed512{Components: cp}
		case BlobSlotD2:
			h.blob512.DS2 = &itb.Seed512{Components: cp}
		case BlobSlotD3:
			h.blob512.DS3 = &itb.Seed512{Components: cp}
		case BlobSlotS1:
			h.blob512.SS1 = &itb.Seed512{Components: cp}
		case BlobSlotS2:
			h.blob512.SS2 = &itb.Seed512{Components: cp}
		case BlobSlotS3:
			h.blob512.SS3 = &itb.Seed512{Components: cp}
		default:
			setLastErr(StatusBadInput)
			return StatusBadInput
		}
		return StatusOK
	}
	setLastErr(StatusInternal)
	return StatusInternal
}

// BlobGetComponents copies the seed components from the requested
// slot into out and returns the number of uint64 elements that were
// available on the handle. Same caller-allocated-buffer probe pattern
// as BlobGetKey: len(out) == 0 returns the required capacity in n
// with st == StatusBufferTooSmall.
//
// An unset slot returns (0, StatusOK) — distinguishable from the
// buffer-too-small case by the status code, not by n alone.
func BlobGetComponents(id BlobHandleID, slot int, out []uint64) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveBlob(id)
	if st != StatusOK {
		return 0, st
	}
	var src []uint64
	switch h.width {
	case hashes.W128:
		var s *itb.Seed128
		switch slot {
		case BlobSlotN:
			s = h.blob128.NS
		case BlobSlotD:
			s = h.blob128.DS
		case BlobSlotS:
			s = h.blob128.SS
		case BlobSlotL:
			s = h.blob128.LS
		case BlobSlotD1:
			s = h.blob128.DS1
		case BlobSlotD2:
			s = h.blob128.DS2
		case BlobSlotD3:
			s = h.blob128.DS3
		case BlobSlotS1:
			s = h.blob128.SS1
		case BlobSlotS2:
			s = h.blob128.SS2
		case BlobSlotS3:
			s = h.blob128.SS3
		default:
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		if s != nil {
			src = s.Components
		}
	case hashes.W256:
		var s *itb.Seed256
		switch slot {
		case BlobSlotN:
			s = h.blob256.NS
		case BlobSlotD:
			s = h.blob256.DS
		case BlobSlotS:
			s = h.blob256.SS
		case BlobSlotL:
			s = h.blob256.LS
		case BlobSlotD1:
			s = h.blob256.DS1
		case BlobSlotD2:
			s = h.blob256.DS2
		case BlobSlotD3:
			s = h.blob256.DS3
		case BlobSlotS1:
			s = h.blob256.SS1
		case BlobSlotS2:
			s = h.blob256.SS2
		case BlobSlotS3:
			s = h.blob256.SS3
		default:
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		if s != nil {
			src = s.Components
		}
	case hashes.W512:
		var s *itb.Seed512
		switch slot {
		case BlobSlotN:
			s = h.blob512.NS
		case BlobSlotD:
			s = h.blob512.DS
		case BlobSlotS:
			s = h.blob512.SS
		case BlobSlotL:
			s = h.blob512.LS
		case BlobSlotD1:
			s = h.blob512.DS1
		case BlobSlotD2:
			s = h.blob512.DS2
		case BlobSlotD3:
			s = h.blob512.DS3
		case BlobSlotS1:
			s = h.blob512.SS1
		case BlobSlotS2:
			s = h.blob512.SS2
		case BlobSlotS3:
			s = h.blob512.SS3
		default:
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		if s != nil {
			src = s.Components
		}
	default:
		setLastErr(StatusInternal)
		return 0, StatusInternal
	}
	if len(src) > len(out) {
		setLastErr(StatusBufferTooSmall)
		return len(src), StatusBufferTooSmall
	}
	copy(out, src)
	return len(src), StatusOK
}

// BlobSetMACKey stores the optional MAC key bytes on the handle.
// The bytes are copied; pass an empty slice to clear a previously-set
// key. BlobExport / BlobExport3 only emits the MAC section when the
// caller supplies BlobOptMAC in the option bitmask AND the MAC key
// on the handle is non-empty.
func BlobSetMACKey(id BlobHandleID, key []byte) (st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveBlob(id)
	if st != StatusOK {
		return st
	}
	buf := append([]byte(nil), key...)
	switch h.width {
	case hashes.W128:
		h.blob128.MACKey = buf
	case hashes.W256:
		h.blob256.MACKey = buf
	case hashes.W512:
		h.blob512.MACKey = buf
	default:
		setLastErr(StatusInternal)
		return StatusInternal
	}
	return StatusOK
}

// BlobGetMACKey copies the MAC key from the handle into out using
// the standard caller-allocated-buffer probe pattern.
func BlobGetMACKey(id BlobHandleID, out []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveBlob(id)
	if st != StatusOK {
		return 0, st
	}
	var src []byte
	switch h.width {
	case hashes.W128:
		src = h.blob128.MACKey
	case hashes.W256:
		src = h.blob256.MACKey
	case hashes.W512:
		src = h.blob512.MACKey
	default:
		setLastErr(StatusInternal)
		return 0, StatusInternal
	}
	if len(src) > len(out) {
		setLastErr(StatusBufferTooSmall)
		return len(src), StatusBufferTooSmall
	}
	copy(out, src)
	return len(src), StatusOK
}

// BlobSetMACName stores the optional MAC name on the handle (e.g.
// "kmac256", "hmac-blake3"). Pass an empty string to clear a
// previously-set name. Like the MAC key, the name is only emitted
// in the blob when BlobOptMAC is supplied to BlobExport / BlobExport3
// AND the name is non-empty.
func BlobSetMACName(id BlobHandleID, name string) (st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveBlob(id)
	if st != StatusOK {
		return st
	}
	switch h.width {
	case hashes.W128:
		h.blob128.MACName = name
	case hashes.W256:
		h.blob256.MACName = name
	case hashes.W512:
		h.blob512.MACName = name
	default:
		setLastErr(StatusInternal)
		return StatusInternal
	}
	return StatusOK
}

// BlobGetMACName returns the MAC name from the handle, or "" if no
// MAC is associated with this blob.
func BlobGetMACName(id BlobHandleID) (name string, st Status) {
	defer recoverPanic(&st, StatusInternal)
	h, st := resolveBlob(id)
	if st != StatusOK {
		return "", st
	}
	switch h.width {
	case hashes.W128:
		return h.blob128.MACName, StatusOK
	case hashes.W256:
		return h.blob256.MACName, StatusOK
	case hashes.W512:
		return h.blob512.MACName, StatusOK
	}
	setLastErr(StatusInternal)
	return "", StatusInternal
}

// BlobExport serialises the handle's Single-Ouroboros state (3 seeds
// + 3 hash keys, plus optional dedicated lockSeed and MAC) into a
// JSON blob. Mirrors itb.Blob{N}.Export — the bitmask flags
// (BlobOptLockSeed / BlobOptMAC) opt the matching sections in.
//
// Caller-allocated-buffer convention: pass len(out) == 0 to probe
// for the required size, then resize and retry.
//
// Mode on the underlying blob is stamped to 1 (Single) on success,
// matching the Import path so post-Export inspection via
// [BlobMode] reports the correct value. Bits in optsBitmask outside
// the documented BlobOptLockSeed / BlobOptMAC range are rejected
// with StatusBadInput before any serialisation runs — future-
// incompatibility guard against bindings setting an unknown bit
// expecting an option that doesn't exist yet.
func BlobExport(id BlobHandleID, optsBitmask int, out []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	if optsBitmask&^(BlobOptLockSeed|BlobOptMAC) != 0 {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	h, st := resolveBlob(id)
	if st != StatusOK {
		return 0, st
	}
	var blob []byte
	var err error
	switch h.width {
	case hashes.W128:
		opts, optsOK := buildBlob128Opts(h.blob128, optsBitmask)
		if !optsOK {
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		b := h.blob128
		if b.NS == nil || b.DS == nil || b.SS == nil {
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		blob, err = b.Export(b.KeyN, b.KeyD, b.KeyS,
			b.NS, b.DS, b.SS, opts)
	case hashes.W256:
		opts, optsOK := buildBlob256Opts(h.blob256, optsBitmask)
		if !optsOK {
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		b := h.blob256
		if b.NS == nil || b.DS == nil || b.SS == nil {
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		blob, err = b.Export(b.KeyN, b.KeyD, b.KeyS,
			b.NS, b.DS, b.SS, opts)
	case hashes.W512:
		opts, optsOK := buildBlob512Opts(h.blob512, optsBitmask)
		if !optsOK {
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		b := h.blob512
		if b.NS == nil || b.DS == nil || b.SS == nil {
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		blob, err = b.Export(b.KeyN, b.KeyD, b.KeyS,
			b.NS, b.DS, b.SS, opts)
	default:
		setLastErr(StatusInternal)
		return 0, StatusInternal
	}
	if err != nil {
		s := mapBlobError(err)
		setLastErr(s)
		return 0, s
	}
	if len(blob) > len(out) {
		setLastErr(StatusBufferTooSmall)
		return len(blob), StatusBufferTooSmall
	}
	copy(out, blob)
	return len(blob), StatusOK
}

// BlobExport3 serialises the handle's Triple-Ouroboros state (1
// noise + 3 data + 3 start seeds + 7 hash keys, plus optional
// lockSeed and MAC). Mirrors itb.Blob{N}.Export3. Bits outside the
// documented BlobOptLockSeed / BlobOptMAC range are rejected with
// StatusBadInput; Mode on the underlying blob is stamped to 3 on
// success.
func BlobExport3(id BlobHandleID, optsBitmask int, out []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	if optsBitmask&^(BlobOptLockSeed|BlobOptMAC) != 0 {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	h, st := resolveBlob(id)
	if st != StatusOK {
		return 0, st
	}
	var blob []byte
	var err error
	switch h.width {
	case hashes.W128:
		opts, optsOK := buildBlob128Opts(h.blob128, optsBitmask)
		if !optsOK {
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		b := h.blob128
		if b.NS == nil || b.DS1 == nil || b.DS2 == nil || b.DS3 == nil ||
			b.SS1 == nil || b.SS2 == nil || b.SS3 == nil {
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		blob, err = b.Export3(b.KeyN,
			b.KeyD1, b.KeyD2, b.KeyD3,
			b.KeyS1, b.KeyS2, b.KeyS3,
			b.NS, b.DS1, b.DS2, b.DS3, b.SS1, b.SS2, b.SS3, opts)
	case hashes.W256:
		opts, optsOK := buildBlob256Opts(h.blob256, optsBitmask)
		if !optsOK {
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		b := h.blob256
		if b.NS == nil || b.DS1 == nil || b.DS2 == nil || b.DS3 == nil ||
			b.SS1 == nil || b.SS2 == nil || b.SS3 == nil {
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		blob, err = b.Export3(b.KeyN,
			b.KeyD1, b.KeyD2, b.KeyD3,
			b.KeyS1, b.KeyS2, b.KeyS3,
			b.NS, b.DS1, b.DS2, b.DS3, b.SS1, b.SS2, b.SS3, opts)
	case hashes.W512:
		opts, optsOK := buildBlob512Opts(h.blob512, optsBitmask)
		if !optsOK {
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		b := h.blob512
		if b.NS == nil || b.DS1 == nil || b.DS2 == nil || b.DS3 == nil ||
			b.SS1 == nil || b.SS2 == nil || b.SS3 == nil {
			setLastErr(StatusBadInput)
			return 0, StatusBadInput
		}
		blob, err = b.Export3(b.KeyN,
			b.KeyD1, b.KeyD2, b.KeyD3,
			b.KeyS1, b.KeyS2, b.KeyS3,
			b.NS, b.DS1, b.DS2, b.DS3, b.SS1, b.SS2, b.SS3, opts)
	default:
		setLastErr(StatusInternal)
		return 0, StatusInternal
	}
	if err != nil {
		s := mapBlobError(err)
		setLastErr(s)
		return 0, s
	}
	if len(blob) > len(out) {
		setLastErr(StatusBufferTooSmall)
		return len(blob), StatusBufferTooSmall
	}
	copy(out, blob)
	return len(blob), StatusOK
}

// BlobImport parses a Single-Ouroboros JSON blob produced by a prior
// Export call (Go-side or FFI-side), populates the handle's slots,
// and applies the captured globals via SetNonceBits / SetBarrierFill
// / SetBitSoup / SetLockSoup. Mirrors itb.Blob{N}.Import — same
// transactional semantics: on error the pre-Import state is preserved.
//
// Returns StatusBlobModeMismatch when the blob is mode=3 (call
// BlobImport3 instead), StatusBlobMalformed on parse / shape failure,
// StatusBlobVersionTooNew on a version field higher than this build
// supports.
func BlobImport(id BlobHandleID, data []byte) (st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveBlob(id)
	if st != StatusOK {
		return st
	}
	var err error
	switch h.width {
	case hashes.W128:
		err = h.blob128.Import(data)
	case hashes.W256:
		err = h.blob256.Import(data)
	case hashes.W512:
		err = h.blob512.Import(data)
	default:
		setLastErr(StatusInternal)
		return StatusInternal
	}
	if err != nil {
		s := mapBlobError(err)
		setLastErr(s)
		return s
	}
	return StatusOK
}

// BlobImport3 is the Triple-Ouroboros counterpart of BlobImport.
// Same error contract; mirrors itb.Blob{N}.Import3.
func BlobImport3(id BlobHandleID, data []byte) (st Status) {
	defer recoverPanic(&st, StatusInternal)

	h, st := resolveBlob(id)
	if st != StatusOK {
		return st
	}
	var err error
	switch h.width {
	case hashes.W128:
		err = h.blob128.Import3(data)
	case hashes.W256:
		err = h.blob256.Import3(data)
	case hashes.W512:
		err = h.blob512.Import3(data)
	default:
		setLastErr(StatusInternal)
		return StatusInternal
	}
	if err != nil {
		s := mapBlobError(err)
		setLastErr(s)
		return s
	}
	return StatusOK
}

// buildBlob{128,256,512}Opts assembles the variadic options struct
// for itb.Blob{N}.Export / Export3 from the handle's optional slots
// (KeyL / LS / MACKey / MACName) gated by the caller-supplied
// bitmask. Returns ok=false when a bit is set but the matching slot
// is unpopulated — the caller surfaces this as StatusBadInput
// before any serialisation runs. Silently dropping the flag would
// produce a blob that lacks the section the caller asked for, with
// no diagnostic at the FFI seam — receiver-side decryption would
// then fail in a way that's hard to attribute back to sender-side
// misuse.
func buildBlob128Opts(b *itb.Blob128, optsBitmask int) (itb.Blob128Opts, bool) {
	var o itb.Blob128Opts
	if optsBitmask&BlobOptLockSeed != 0 {
		if b.LS == nil {
			return o, false
		}
		o.KeyL = b.KeyL
		o.LS = b.LS
	}
	if optsBitmask&BlobOptMAC != 0 {
		if len(b.MACKey) == 0 {
			return o, false
		}
		o.MACKey = b.MACKey
		o.MACName = b.MACName
	}
	return o, true
}

func buildBlob256Opts(b *itb.Blob256, optsBitmask int) (itb.Blob256Opts, bool) {
	var o itb.Blob256Opts
	if optsBitmask&BlobOptLockSeed != 0 {
		if b.LS == nil {
			return o, false
		}
		o.KeyL = b.KeyL
		o.LS = b.LS
	}
	if optsBitmask&BlobOptMAC != 0 {
		if len(b.MACKey) == 0 {
			return o, false
		}
		o.MACKey = b.MACKey
		o.MACName = b.MACName
	}
	return o, true
}

func buildBlob512Opts(b *itb.Blob512, optsBitmask int) (itb.Blob512Opts, bool) {
	var o itb.Blob512Opts
	if optsBitmask&BlobOptLockSeed != 0 {
		if b.LS == nil {
			return o, false
		}
		o.KeyL = b.KeyL
		o.LS = b.LS
	}
	if optsBitmask&BlobOptMAC != 0 {
		if len(b.MACKey) == 0 {
			return o, false
		}
		o.MACKey = b.MACKey
		o.MACName = b.MACName
	}
	return o, true
}
