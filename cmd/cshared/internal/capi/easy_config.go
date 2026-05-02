package capi

// Per-instance configuration setters mirroring the Encryptor.Set*
// methods on the easy side. Each call mutates only the encryptor's
// own itb.Config copy; the process-global setters (SetBitSoup,
// SetLockSoup, SetLockSeed, SetNonceBits, SetBarrierFill) are not
// touched and other encryptors built before / after this call are
// not affected.
//
// Every setter routes through recoverEasyPanic so that easy-side
// panics on out-of-range input (SetNonceBits / SetBarrierFill /
// SetLockSeed) translate cleanly into the matching FFI Status code
// rather than tearing down the host process.

// EasySetNonceBits forwards to Encryptor.SetNonceBits. Valid values:
// 128, 256, 512. Any other value yields StatusBadInput.
func EasySetNonceBits(id EasyHandleID, n int) (st Status) {
	defer recoverEasyPanic(&st, StatusBadInput)
	h, st := resolveEasy(id)
	if st != StatusOK {
		return st
	}
	h.enc.SetNonceBits(n)
	return StatusOK
}

// EasySetBarrierFill forwards to Encryptor.SetBarrierFill. Valid
// values: 1, 2, 4, 8, 16, 32. Any other value yields StatusBadInput.
func EasySetBarrierFill(id EasyHandleID, n int) (st Status) {
	defer recoverEasyPanic(&st, StatusBadInput)
	h, st := resolveEasy(id)
	if st != StatusOK {
		return st
	}
	h.enc.SetBarrierFill(n)
	return StatusOK
}

// EasySetBitSoup forwards to Encryptor.SetBitSoup. 0 = byte-level
// split (default); non-zero = bit-level Bit Soup split.
func EasySetBitSoup(id EasyHandleID, mode int) (st Status) {
	defer recoverEasyPanic(&st, StatusBadInput)
	h, st := resolveEasy(id)
	if st != StatusOK {
		return st
	}
	h.enc.SetBitSoup(int32(mode))
	return StatusOK
}

// EasySetLockSoup forwards to Encryptor.SetLockSoup. Non-zero values
// auto-couple BitSoup=1 on the encryptor (mirroring the global
// itb.SetLockSoup contract).
func EasySetLockSoup(id EasyHandleID, mode int) (st Status) {
	defer recoverEasyPanic(&st, StatusBadInput)
	h, st := resolveEasy(id)
	if st != StatusOK {
		return st
	}
	h.enc.SetLockSoup(int32(mode))
	return StatusOK
}

// EasySetLockSeed forwards to Encryptor.SetLockSeed. Valid values:
// 0 (off), 1 (on). Any other value yields StatusBadInput. Calling
// this method after the encryptor has produced its first ciphertext
// yields StatusEasyLockSeedAfterEncrypt — the bit-permutation
// derivation path cannot change mid-session without breaking
// decryptability of pre-switch ciphertext.
func EasySetLockSeed(id EasyHandleID, mode int) (st Status) {
	defer recoverEasyPanic(&st, StatusBadInput)
	h, st := resolveEasy(id)
	if st != StatusOK {
		return st
	}
	h.enc.SetLockSeed(int32(mode))
	return StatusOK
}

// EasySetChunkSize forwards to Encryptor.SetChunkSize. 0 selects the
// auto-detect heuristic from itb.ChunkSize.
func EasySetChunkSize(id EasyHandleID, n int) (st Status) {
	defer recoverEasyPanic(&st, StatusBadInput)
	h, st := resolveEasy(id)
	if st != StatusOK {
		return st
	}
	h.enc.SetChunkSize(n)
	return StatusOK
}

// EasyClose zeroes the encryptor's PRF keys, MAC key, and seed
// components and marks the instance closed. Subsequent method calls
// on the same handle return StatusEasyClosed.
//
// Idempotent — multiple Close calls return StatusOK without panic.
// The handle itself remains valid (Close does not delete the
// cgo.Handle); use FreeEasy to release the handle slot.
func EasyClose(id EasyHandleID) (st Status) {
	defer recoverEasyPanic(&st, StatusInternal)
	h, st := resolveEasy(id)
	if st != StatusOK {
		return st
	}
	if err := h.enc.Close(); err != nil {
		setLastErr(StatusInternal)
		return StatusInternal
	}
	return StatusOK
}

// ─── Read-only field getters (Primitive / KeyBits / Mode / MACName) ──

// EasyPrimitive returns the canonical hash primitive name the
// encryptor was constructed with. Mirrors the read-only Primitive
// field on the Go struct.
func EasyPrimitive(id EasyHandleID) (string, Status) {
	h, st := resolveEasy(id)
	if st != StatusOK {
		return "", st
	}
	return h.enc.Primitive, StatusOK
}

// EasyKeyBits returns the per-seed key width in bits — one of 512,
// 1024, 2048.
func EasyKeyBits(id EasyHandleID) (int, Status) {
	h, st := resolveEasy(id)
	if st != StatusOK {
		return 0, st
	}
	return h.enc.KeyBits, StatusOK
}

// EasyMode returns 1 (Single Ouroboros, 3 seeds) or 3 (Triple
// Ouroboros, 7 seeds). The integer encoding mirrors the Encrypt /
// Encrypt3x distinction at the low-level API.
func EasyMode(id EasyHandleID) (int, Status) {
	h, st := resolveEasy(id)
	if st != StatusOK {
		return 0, st
	}
	return h.enc.Mode, StatusOK
}

// EasyMACName returns the canonical MAC primitive name the encryptor
// was constructed with.
func EasyMACName(id EasyHandleID) (string, Status) {
	h, st := resolveEasy(id)
	if st != StatusOK {
		return "", st
	}
	return h.enc.MACName, StatusOK
}

// ─── Material getters (defensive copies) ────────────────────────────

// EasySeedCount returns the number of seed slots held by the
// encryptor: 3 (Single without LockSeed), 4 (Single with LockSeed),
// 7 (Triple without LockSeed), 8 (Triple with LockSeed). Used by
// bindings to determine the valid range for the slot index passed to
// EasySeedComponents / EasyPRFKey.
func EasySeedCount(id EasyHandleID) (int, Status) {
	h, st := resolveEasy(id)
	if st != StatusOK {
		return 0, st
	}
	return len(h.enc.SeedComponents()), StatusOK
}

// EasySeedComponents returns the uint64 components for one seed slot
// (defensive copy). Slot index follows the canonical ordering:
// Single = [noise, data, start]; Triple = [noise, data1, data2,
// data3, start1, start2, start3]; the dedicated lockSeed slot is
// appended at the end (index 3 / 7) when LockSeed is active.
//
// Save these alongside EasyPRFKey output for cross-process restore
// via Encryptor.Import (the FFI-side path goes through EasyExport /
// EasyImport instead, which packs all material into one JSON blob).
func EasySeedComponents(id EasyHandleID, slot int) ([]uint64, Status) {
	h, st := resolveEasy(id)
	if st != StatusOK {
		return nil, st
	}
	all := h.enc.SeedComponents()
	if slot < 0 || slot >= len(all) {
		setLastErr(StatusBadInput)
		return nil, StatusBadInput
	}
	return all[slot], StatusOK
}

// EasyHasPRFKeys returns 1 when the encryptor's primitive uses fixed
// PRF keys per seed slot (every shipped primitive except siphash24),
// 0 otherwise. Bindings consult this before iterating slot indices
// against EasyPRFKey, mirroring the easy.Encryptor.PRFKeys() == nil
// check on the Go side.
func EasyHasPRFKeys(id EasyHandleID) (int, Status) {
	h, st := resolveEasy(id)
	if st != StatusOK {
		return 0, st
	}
	if h.enc.PRFKeys() == nil {
		return 0, StatusOK
	}
	return 1, StatusOK
}

// EasyPRFKey returns the fixed PRF key bytes for one seed slot
// (defensive copy). Returns StatusBadInput when the primitive has no
// fixed PRF keys (siphash24 — caller should consult EasyHasPRFKeys
// first) or when slot is out of range.
func EasyPRFKey(id EasyHandleID, slot int) ([]byte, Status) {
	h, st := resolveEasy(id)
	if st != StatusOK {
		return nil, st
	}
	all := h.enc.PRFKeys()
	if all == nil {
		setLastErr(StatusBadInput)
		return nil, StatusBadInput
	}
	if slot < 0 || slot >= len(all) {
		setLastErr(StatusBadInput)
		return nil, StatusBadInput
	}
	return all[slot], StatusOK
}

// EasyMACKey returns a defensive copy of the encryptor's bound MAC
// fixed key. Save these bytes alongside the seed components for
// cross-process restore via the EasyExport / EasyImport JSON path.
func EasyMACKey(id EasyHandleID) ([]byte, Status) {
	h, st := resolveEasy(id)
	if st != StatusOK {
		return nil, st
	}
	return h.enc.MACKey(), StatusOK
}

// ─── Per-instance nonce / chunk introspection ──────────────────────

// EasyNonceBits forwards to Encryptor.NonceBits — the per-instance
// nonce size in bits (128 / 256 / 512). Falls back to the global
// itb.GetNonceBits reading when no per-instance override has been
// installed via EasySetNonceBits.
func EasyNonceBits(id EasyHandleID) (int, Status) {
	h, st := resolveEasy(id)
	if st != StatusOK {
		return 0, st
	}
	return h.enc.NonceBits(), StatusOK
}

// EasyHeaderSize forwards to Encryptor.HeaderSize — the per-instance
// ciphertext-chunk header size in bytes (nonce + 2-byte width +
// 2-byte height). Tracks the encryptor's own NonceBits, NOT the
// process-wide HeaderSize() reading.
func EasyHeaderSize(id EasyHandleID) (int, Status) {
	h, st := resolveEasy(id)
	if st != StatusOK {
		return 0, st
	}
	return h.enc.HeaderSize(), StatusOK
}

// EasyParseChunkLen forwards to Encryptor.ParseChunkLen — the
// per-instance chunk-length parser. Reports the total wire length
// of one ciphertext chunk after inspecting only the fixed-size
// header at the front of the supplied buffer. Returns
// StatusBadInput on too-short buffer, zero dimensions, or
// width × height overflow.
func EasyParseChunkLen(id EasyHandleID, header []byte) (int, Status) {
	h, st := resolveEasy(id)
	if st != StatusOK {
		return 0, st
	}
	n, err := h.enc.ParseChunkLen(header)
	if err != nil {
		setLastErr(StatusBadInput)
		return 0, StatusBadInput
	}
	return n, StatusOK
}
