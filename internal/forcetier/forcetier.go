// Package forcetier parses the dispatch-forcing environment variables
// consumed by the per-primitive assembly packages' runtime capability
// flags. The variables serve the cross-build parity harness
// (scripts/parity/cross-build-parity.sh): on a host whose auto-dispatch
// selects the widest available tier, forcing a narrower tier makes the
// narrower kernels reachable end-to-end, so every shipped arm can be
// validated on a single machine. All arms are bit-exact by
// construction; forcing is a dispatch-selection knob, not a behaviour
// change.
//
// Recognised variables:
//
//	ITB_FORCE_HASH_TIER      = avx512 | vaesavx2 | avx2 | aesni | scalar
//	ITB_FORCE_INTERLOCK_TIER = avx512 | avx2 | scalar
//
// An empty or unset variable keeps auto-dispatch (the production
// default — no visible change). An unknown value keeps auto-dispatch
// and emits a one-line stderr warning, so a harness typo cannot
// silently produce a hollow sweep. A recognised value that names an
// arm a given package does not implement, or that the silicon cannot
// execute, is handled per package (see each package's
// forcetier_amd64.go init) and reported via [Warnf]; the parity
// script's skip matrix avoids those pairings up front.
//
// The always-on env read follows the established pattern of
// ITB_MICROBATCH_TIERS (microbatch.go), ITB_HASHPOOL_STARTERS
// (process_cgo.go), and ITB_GOMEMLIMIT / ITB_GOGC
// (internal/runtimecfg/cfg.go).
package forcetier

import (
	"fmt"
	"os"
	"strings"
)

// hashTier / interlockTier are resolved once at package init. Package
// initialisation order guarantees these are populated before any
// importing assembly package's init runs its flag override.
var (
	hashTier      = parse("ITB_FORCE_HASH_TIER", "avx512", "vaesavx2", "avx2", "aesni", "scalar")
	interlockTier = parse("ITB_FORCE_INTERLOCK_TIER", "avx512", "avx2", "scalar")
)

// parse validates the named environment variable against the allowed
// value set. Empty / unset returns "" (auto-dispatch). An unknown
// value returns "" after a one-line stderr warning.
func parse(name string, allowed ...string) string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	if v == "" {
		return ""
	}
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	fmt.Fprintf(os.Stderr,
		"itb: %s=%q unknown value (want one of %s); keeping auto-dispatch\n",
		name, v, strings.Join(allowed, "|"))
	return ""
}

// HashTier returns the validated ITB_FORCE_HASH_TIER value, or "" for
// auto-dispatch.
func HashTier() string { return hashTier }

// InterlockTier returns the validated ITB_FORCE_INTERLOCK_TIER value,
// or "" for auto-dispatch.
func InterlockTier() string { return interlockTier }

// Warnf emits a one-line "itb: forcetier: ..." note to stderr. Used by
// the per-package init overrides to report a forced arm the package
// does not implement or the silicon cannot execute.
func Warnf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "itb: forcetier: "+format+"\n", args...)
}
