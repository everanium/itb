package capi

import (
	"os"

	itb "github.com/everanium/itb"
)

// memProfileEnv names the environment variable [WriteHeapProfile]
// falls back to when the caller passes an empty path. It is the
// ITB-prefixed analogue of the -memprofile flag the Go tooling uses
// for the same artefact, alongside ITB_GOMEMLIMIT / ITB_GOGC /
// ITB_GOMAXPROCS for the other runtime knobs.
const memProfileEnv = "ITB_MEMPROFILE"

// SetGOMAXPROCS is the FFI-side entry of [itb.SetGOMAXPROCS]: n <= 0
// queries the current value without changing it, a positive n
// installs it; the previous value is returned either way.
func SetGOMAXPROCS(n int) int {
	return itb.SetGOMAXPROCS(n)
}

// WriteHeapProfile is the FFI-side entry of [itb.WriteHeapProfile]
// with the C-side path convention folded in: an empty path (a NULL
// or empty C string) falls back to the ITB_MEMPROFILE environment
// variable, and a path that is still empty, or any file-system
// failure, maps to StatusBadInput with the diagnostic in [LastError].
func WriteHeapProfile(path string) (st Status) {
	defer recoverPanic(&st, StatusInternal)

	if path == "" {
		path = os.Getenv(memProfileEnv)
	}
	if path == "" {
		setLastErrMessage("heap profile path is empty and " + memProfileEnv + " is unset")
		return StatusBadInput
	}
	if err := itb.WriteHeapProfile(path); err != nil {
		setLastErrMessage(err.Error())
		return StatusBadInput
	}
	return StatusOK
}

// PoolStatsLen is the FFI-side entry of [itb.PoolStatsLen].
func PoolStatsLen() int {
	return itb.PoolStatsLen()
}

// PoolStats is the FFI-side entry of [itb.PoolStats] under the
// caller-allocated-buffer convention of the rest of the package with
// the capacity counted in slots: n reports the slots written on
// success, or the required count on StatusBufferTooSmall (the probe
// form, a nil dst, reports the requirement without writing). The slot
// layout is the one [itb.PoolStats] documents — the vector crosses
// the C ABI unchanged.
func PoolStats(dst []int64) (n int, st Status) {
	need := itb.PoolStatsLen()
	if len(dst) < need {
		setLastErr(StatusBufferTooSmall)
		return need, StatusBufferTooSmall
	}
	return itb.PoolStats(dst), StatusOK
}

// setLastErrMessage stores a raw diagnostic under the shared lastErr
// slot for the runtime-family entries, which have no triple-side
// error to map and therefore no "triple:" prefix to carry.
func setLastErrMessage(msg string) {
	v := msg
	lastErr.Store(&v)
}
