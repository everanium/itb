package capi

import "github.com/everanium/itb"

// Process-wide runtime configuration. All five settings are atomic
// integers in the underlying itb package; setting them here is a
// pure delegation. Changing them is process-wide and takes effect
// for every subsequent Encrypt / Decrypt call on the shared library.
//
// SetNonceBits and SetBarrierFill panic in the underlying itb
// package when given out-of-range values (security-critical
// validation: nonce-size and barrier misconfiguration are silent
// security degradations). The FFI layer must not propagate panics
// across the cgo boundary — they would tear down the host process
// running the .so. The Go-side wrappers below catch the panic and
// translate to StatusBadInput, returning a clean error code that
// the C caller can inspect via ITB_LastError.

func SetBitSoup(mode int) Status {
	itb.SetBitSoup(int32(mode))
	return StatusOK
}

func GetBitSoup() int { return int(itb.GetBitSoup()) }

func SetLockSoup(mode int) Status {
	itb.SetLockSoup(int32(mode))
	return StatusOK
}

func GetLockSoup() int { return int(itb.GetLockSoup()) }

func SetMaxWorkers(n int) Status {
	itb.SetMaxWorkers(n)
	return StatusOK
}

func GetMaxWorkers() int { return itb.GetMaxWorkers() }

// SetNonceBits accepts 128, 256, or 512. Any other value yields
// StatusBadInput; the underlying itb panic is recovered.
func SetNonceBits(n int) (st Status) {
	defer func() {
		if r := recover(); r != nil {
			setLastErr(StatusBadInput)
			st = StatusBadInput
		}
	}()
	itb.SetNonceBits(n)
	return StatusOK
}

func GetNonceBits() int { return itb.GetNonceBits() }

// SetBarrierFill accepts 1, 2, 4, 8, 16, 32. Any other value yields
// StatusBadInput; the underlying itb panic is recovered.
func SetBarrierFill(n int) (st Status) {
	defer func() {
		if r := recover(); r != nil {
			setLastErr(StatusBadInput)
			st = StatusBadInput
		}
	}()
	itb.SetBarrierFill(n)
	return StatusOK
}

func GetBarrierFill() int { return itb.GetBarrierFill() }

// MaxKeyBits returns the maximum supported ITB key width in bits
// (build-time constant, currently 2048). Read-only — there is no
// matching setter.
func MaxKeyBits() int { return itb.MaxKeyBits }

// Channels returns the number of channels per pixel in the RGBWYOPA
// container layout (build-time constant, currently 8). Read-only.
func Channels() int { return itb.Channels }

// HeaderSize returns the current ciphertext-chunk header size in
// bytes (nonce + 2-byte width + 2-byte height). Tracks the active
// nonce-size override set via ITB_SetNonceBits / SetNonceBits, so
// streaming consumers always know how many bytes to read before
// calling ITB_ParseChunkLen on a fresh chunk.
//
// Default configuration: 16 (nonce) + 4 (dimensions) = 20 bytes.
// Under SetNonceBits(256): 32 + 4 = 36 bytes.
// Under SetNonceBits(512): 64 + 4 = 68 bytes.
func HeaderSize() int { return itb.GetNonceBits()/8 + 4 }
