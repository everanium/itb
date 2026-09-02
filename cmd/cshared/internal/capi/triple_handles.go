package capi

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"runtime/cgo"
	"strconv"
	"strings"

	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/triple"
)

// TripleHandle wraps a single *triple.Pipeline behind an opaque
// uintptr crossing the cgo boundary. The Pipeline owns its own eight
// ITB seeds, per-instance [github.com/everanium/itb.Config] snapshot,
// optional parallax + wrapper layers, and MAC closure — the FFI
// layer just pins it via runtime/cgo.Handle so the value survives
// across the C boundary without leaking the internal type.
//
// Mirrors the SeedHandle / MACHandle / BlobHandle pattern in
// handles.go / macs.go / blob_handles.go — one TripleHandle replaces
// the (8 seeds + MAC + parallax + wrapper) constructor ceremony of
// the low-level surface.
type TripleHandle struct {
	pipe *triple.Pipeline
}

// TripleHandleID is the opaque uintptr passed across the C ABI as a
// Pipeline reference. Internally a runtime/cgo.Handle that maps back
// to a *TripleHandle on the Go heap.
type TripleHandleID uintptr

// resolveTriple returns the *TripleHandle behind an opaque
// TripleHandleID, or (nil, StatusBadHandle) on a stale or zero
// handle. cgo.Handle.Value() panics on a stale handle; the deferred
// recover translates that into a clean StatusBadHandle return so FFI
// callers get an error code instead of a process-wide panic.
func resolveTriple(id TripleHandleID) (h *TripleHandle, st Status) {
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
	hh, ok := v.(*TripleHandle)
	if !ok || hh == nil {
		setLastErr(StatusBadHandle)
		return nil, StatusBadHandle
	}
	return hh, StatusOK
}

// parseTripleOpts parses a URL-query-formatted opts string into a
// triple.Opts struct. Empty input returns a zero-value Opts (all
// profile defaults). Unknown keys are rejected with a descriptive
// error rather than silently ignored — silently-ignored keys are the
// classic source of "why is my override not taking effect" bugs on
// the binding-side.
//
// Accepted keys (mirror the [triple.Opts] fields):
//
//   - profile   — informational (ignored; the profile name is a
//     separate argument to Init / Open).
//   - pm        — hex-encoded parallax master (PermMaster).
//   - wm        — hex-encoded wrapper master (WrapMaster).
//   - withParallax / withWrapper — "true" / "false" three-state
//     override; absent = nil (profile default).
//   - maxWorkers, nonceBits, barrierFill, chunkSize, keyBits,
//     parallaxSegmentSize, tagStubSize — decimal integer overrides.
//     tagStubSize overrides the profile's No MAC stub reservation
//     size (see [triple.Opts.TagStubSize]); accepted values are 0
//     or 16..64 inclusive; absent = 0 (profile default, falling
//     through to the MacName auto-probe or the 32-byte default).
//   - innerHash, macName, outerCipher — canonical primitive-name
//     overrides.
//   - innerHashes — comma-separated eight-entry per-slot primitive
//     constellation override for the mixed-primitive dispatch path.
//     Slot ordering matches [triple.Opts.MixedHashes]. Exactly 8
//     entries required when non-empty; mutually exclusive with
//     innerHash (mixed dispatch wins per the resolver rule). Empty
//     value defers to the profile default. Same key name and shape
//     the profile-registration parser already accepts, kept
//     symmetric so a call site that shares an opts-string helper
//     can reuse it in both contexts.
//   - parallaxPalette — comma-separated primitive names for the
//     parallax palette (empty = profile default).
func parseTripleOpts(query string) (triple.Opts, error) {
	var opts triple.Opts
	if query == "" {
		return opts, nil
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return opts, fmt.Errorf("parse opts query: %w", err)
	}
	for k, vs := range values {
		if len(vs) == 0 {
			continue
		}
		v := vs[0]
		switch k {
		case "profile":
			// Informational only — the profile name is a separate
			// argument to Init / Open. Accept the key silently so a
			// binding that echoes it back does not trip the unknown
			// key check.
		case "pm":
			b, herr := hex.DecodeString(v)
			if herr != nil {
				return opts, fmt.Errorf("opts pm: %w", herr)
			}
			opts.PermMaster = b
		case "wm":
			b, herr := hex.DecodeString(v)
			if herr != nil {
				return opts, fmt.Errorf("opts wm: %w", herr)
			}
			opts.WrapMaster = b
		case "withParallax":
			b, berr := parseBoolOpt(v)
			if berr != nil {
				return opts, fmt.Errorf("opts withParallax: %w", berr)
			}
			opts.WithParallax = &b
		case "withWrapper":
			b, berr := parseBoolOpt(v)
			if berr != nil {
				return opts, fmt.Errorf("opts withWrapper: %w", berr)
			}
			opts.WithWrapper = &b
		case "maxWorkers":
			n, ierr := strconv.Atoi(v)
			if ierr != nil {
				return opts, fmt.Errorf("opts maxWorkers: %w", ierr)
			}
			if n < 0 {
				return opts, fmt.Errorf("opts maxWorkers=%d must be >= 0", n)
			}
			opts.MaxWorkers = n
		case "nonceBits":
			n, ierr := strconv.Atoi(v)
			if ierr != nil {
				return opts, fmt.Errorf("opts nonceBits: %w", ierr)
			}
			switch n {
			case 0, 128, 256, 512:
			default:
				return opts, fmt.Errorf("opts nonceBits=%d must be 0 or one of {128, 256, 512}", n)
			}
			opts.NonceBits = n
		case "barrierFill":
			n, ierr := strconv.Atoi(v)
			if ierr != nil {
				return opts, fmt.Errorf("opts barrierFill: %w", ierr)
			}
			switch n {
			case 0, 1, 2, 4, 8, 16, 32:
			default:
				return opts, fmt.Errorf("opts barrierFill=%d must be 0 or one of {1, 2, 4, 8, 16, 32}", n)
			}
			opts.BarrierFill = n
		case "chunkSize":
			n, ierr := strconv.Atoi(v)
			if ierr != nil {
				return opts, fmt.Errorf("opts chunkSize: %w", ierr)
			}
			if n < 0 || n > parallax.MaxChunkSize {
				return opts, fmt.Errorf("opts chunkSize=%d must be in [0, %d]", n, parallax.MaxChunkSize)
			}
			opts.ChunkSize = n
		case "keyBits":
			n, ierr := strconv.Atoi(v)
			if ierr != nil {
				return opts, fmt.Errorf("opts keyBits: %w", ierr)
			}
			if n < 0 {
				return opts, fmt.Errorf("opts keyBits=%d must be >= 0", n)
			}
			opts.KeyBits = n
		case "tagStubSize":
			n, ierr := strconv.Atoi(v)
			if ierr != nil {
				return opts, fmt.Errorf("opts tagStubSize: %w", ierr)
			}
			if n != 0 && (n < 16 || n > 64) {
				return opts, fmt.Errorf("opts tagStubSize=%d must be 0 or in [16, 64]", n)
			}
			opts.TagStubSize = n
		case "parallaxSegmentSize":
			n, ierr := strconv.Atoi(v)
			if ierr != nil {
				return opts, fmt.Errorf("opts parallaxSegmentSize: %w", ierr)
			}
			if n < 0 || n > parallax.MaxSegmentSize {
				return opts, fmt.Errorf("opts parallaxSegmentSize=%d must be in [0, %d]", n, parallax.MaxSegmentSize)
			}
			opts.ParallaxSegmentSize = n
		case "macName":
			opts.MacName = v
		case "innerHash":
			opts.InnerHash = v
		case "innerHashes":
			if v == "" {
				continue
			}
			entries := strings.Split(v, ",")
			if len(entries) != 8 {
				return opts, fmt.Errorf("opts innerHashes: got %d entries, want exactly 8", len(entries))
			}
			for i, name := range entries {
				opts.MixedHashes[i] = name
			}
		case "outerCipher":
			opts.OuterCipher = v
		case "parallaxPalette":
			if v == "" {
				continue
			}
			opts.ParallaxPalette = strings.Split(v, ",")
		default:
			return opts, fmt.Errorf("opts: unknown key %q", k)
		}
	}
	return opts, nil
}

// parseBoolOpt accepts "true" / "false" (case-sensitive) as the two
// valid three-state override values. Rejects everything else so a
// typoed value ("yes" / "1" / "on") surfaces as a clean error rather
// than silently coercing to false.
func parseBoolOpt(v string) (bool, error) {
	switch v {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("value %q not in {true, false}", v)
}
