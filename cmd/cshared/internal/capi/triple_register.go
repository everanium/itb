package capi

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/everanium/itb/triple"
)

// TripleRegisterProfile installs a user-defined [triple.Profile]
// under name so subsequent [TripleInit] / [TripleOpen] calls resolve
// name to the newly-registered record.
//
// The opts argument is a URL-query-encoded string parsed by
// [parseTripleRegisterOpts] — the shape mirrors the [parseTripleOpts]
// URL-query used by [TripleInit] and [TripleOpen] but with profile-
// shape keys instead of per-call overrides.
//
// Accepted keys (mirror the [triple.Profile] fields):
//
//   - mode                 — one of streaming-aead / streaming-noaead
//     / singlemsg-mac / singlemsg-nomac / blob-only.
//   - width                — 128 / 256 / 512 decimal integer.
//   - innerHash            — canonical ITB hash primitive name.
//   - keyBits              — positive integer multiple of width.
//   - macName              — canonical MAC primitive name (empty for
//     No-MAC profiles).
//   - outerCipher          — canonical wrapper cipher name; required
//     when wrapperOn=true.
//   - parallaxPalette      — comma-separated wrapper cipher names.
//   - parallaxSegmentSize  — decimal integer segment byte count
//     (0 = defer to parallax.DefaultSegmentSize).
//   - chunkSize            — decimal integer chunk byte budget
//     (0 = defer to itb.DefaultChunkSize).
//   - parallaxOn           — "true" / "false".
//   - wrapperOn            — "true" / "false".
//
// Unknown keys are rejected with StatusBadInput. Duplicate name
// returns StatusProfileExists; every other validation failure returns
// StatusBadInput. The name argument itself must match the
// [triple.RegisterProfile] name pattern
// (`^[a-z][a-z0-9-]{2,63}$`) and must not use one of the shipped
// reserved prefixes (streaming- / singlemsg- / blob-).
func TripleRegisterProfile(name string, opts string) (st Status) {
	defer recoverPanic(&st, StatusInternal)

	prof, err := parseTripleRegisterOpts(opts)
	if err != nil {
		setLastErrMessageTriple(err.Error())
		return StatusBadInput
	}
	if err := triple.RegisterProfile(name, prof); err != nil {
		if errors.Is(err, triple.ErrProfileExists) {
			setLastErrMessageTriple(err.Error())
			return StatusProfileExists
		}
		setLastErrMessageTriple(err.Error())
		return StatusBadInput
	}
	return StatusOK
}

// parseTripleRegisterOpts parses a URL-query-formatted opts string
// into a [triple.Profile] shape. Empty input returns a zero-value
// Profile — RegisterProfile will reject it via the field-validation
// path, keeping the "everything mandatory" invariant explicit rather
// than silently substituting defaults for missing keys.
//
// Every accepted key is documented on [TripleRegisterProfile]; unknown
// keys are rejected with a descriptive error, matching the
// silently-ignored-key stance already codified in
// [parseTripleOpts].
func parseTripleRegisterOpts(query string) (triple.Profile, error) {
	var prof triple.Profile
	if query == "" {
		return prof, nil
	}
	values, err := url.ParseQuery(query)
	if err != nil {
		return prof, fmt.Errorf("parse register-profile opts query: %w", err)
	}
	for k, vs := range values {
		if len(vs) == 0 {
			continue
		}
		v := vs[0]
		switch k {
		case "mode":
			prof.Mode = v
		case "width":
			n, ierr := strconv.Atoi(v)
			if ierr != nil {
				return prof, fmt.Errorf("register-profile opts width: %w", ierr)
			}
			prof.Width = n
		case "innerHash":
			prof.InnerHash = v
		case "keyBits":
			n, ierr := strconv.Atoi(v)
			if ierr != nil {
				return prof, fmt.Errorf("register-profile opts keyBits: %w", ierr)
			}
			prof.KeyBits = n
		case "macName":
			prof.MacName = v
		case "outerCipher":
			prof.OuterCipher = v
		case "parallaxPalette":
			if v == "" {
				continue
			}
			prof.ParallaxPalette = strings.Split(v, ",")
		case "parallaxSegmentSize":
			n, ierr := strconv.Atoi(v)
			if ierr != nil {
				return prof, fmt.Errorf("register-profile opts parallaxSegmentSize: %w", ierr)
			}
			prof.ParallaxSegmentSize = n
		case "chunkSize":
			n, ierr := strconv.Atoi(v)
			if ierr != nil {
				return prof, fmt.Errorf("register-profile opts chunkSize: %w", ierr)
			}
			prof.ChunkSize = n
		case "parallaxOn":
			b, berr := parseBoolOpt(v)
			if berr != nil {
				return prof, fmt.Errorf("register-profile opts parallaxOn: %w", berr)
			}
			prof.ParallaxOn = b
		case "wrapperOn":
			b, berr := parseBoolOpt(v)
			if berr != nil {
				return prof, fmt.Errorf("register-profile opts wrapperOn: %w", berr)
			}
			prof.WrapperOn = b
		default:
			return prof, fmt.Errorf("register-profile opts: unknown key %q", k)
		}
	}
	return prof, nil
}
