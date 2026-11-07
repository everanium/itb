package forcetier

import (
	"os"
	"strings"
)

// BarriersDesyncOffWarning is the mandatory warning message displayed
// whenever the Desynchronized Interlocked Barrier (Desync) override is
// documented or exposed via CLI flags.
const BarriersDesyncOffWarning = "WARNING: DO NOT DISABLE DESYNC FOR PRODUCTION USE — FOR SYNCHRONOUS WIRE CONVERSION / DECRYPTION AND RESEARCH BASELINES ONLY."

// BarriersDesyncOff reports whether ITB_BARRIERS_DESYNC is set to a
// disabling value ("0", "off", "false", "no"). By default (when unset or
// set to "1", "on", "true", "yes"), Desync is active across both Layer I
// (0x05 sub-region trajectory schedule) and Layer II (0x06 cross-lane
// chunk-slot desynchronization).
//
// WARNING: DO NOT DISABLE DESYNC FOR PRODUCTION USE — FOR SYNCHRONOUS
// WIRE CONVERSION / DECRYPTION AND RESEARCH BASELINES ONLY.
//
// The variable is read on every query so conversion utilities and test
// harnesses can toggle it between calls within one process.
func BarriersDesyncOff() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ITB_BARRIERS_DESYNC"))) {
	case "0", "off", "false", "no":
		return true
	}
	return false
}
