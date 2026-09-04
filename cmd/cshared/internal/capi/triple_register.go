package capi

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/everanium/itb/triple"
)

// TripleRegister installs a user-defined [triple.Profile] under name
// so subsequent [TripleInit] / [TripleLookup] calls resolve name to
// the newly-registered record.
//
// profileJSON is the [triple.Profile] JSON record — the same encoding
// [TripleInspect] emits and the blob's wrap-layer carries (see
// [triple.Profile.MarshalJSON] for the key set). The decoder is
// strict: an unknown key, a hashes array whose length is neither 0
// nor 8, or trailing content is StatusBadInput. A name key inside the
// JSON, if present, must be empty or equal to the name argument, else
// StatusBadInput.
//
// Duplicate name returns StatusProfileExists; every other validation
// failure (name pattern, reserved prefix, field rules) returns
// StatusBadInput with the diagnostic in [LastError].
func TripleRegister(name string, profileJSON string) (st Status) {
	defer recoverPanic(&st, StatusInternal)

	prof, err := parseProfileJSON(profileJSON)
	if err != nil {
		setLastErrMessageTriple(err.Error())
		return StatusBadInput
	}
	if prof.Name != "" && prof.Name != name {
		setLastErrMessageTriple(fmt.Sprintf("register: profile JSON name %q disagrees with name argument %q", prof.Name, name))
		return StatusBadInput
	}
	prof.Name = ""
	if err := triple.Register(name, prof); err != nil {
		if errors.Is(err, triple.ErrProfileExists) {
			setLastErrMessageTriple(err.Error())
			return StatusProfileExists
		}
		setLastErrMessageTriple(err.Error())
		return StatusBadInput
	}
	return StatusOK
}

// parseProfileJSON decodes a [triple.Profile] JSON record through the
// profile codec. Empty input is refused — every structural field is
// mandatory and the field-validation path inside [triple.Register]
// reports which one is missing only for an object that decoded.
func parseProfileJSON(profileJSON string) (triple.Profile, error) {
	var prof triple.Profile
	if profileJSON == "" {
		return prof, errors.New("register: profile JSON is empty")
	}
	if err := json.Unmarshal([]byte(profileJSON), &prof); err != nil {
		return prof, fmt.Errorf("register: %w", err)
	}
	return prof, nil
}

// TripleLookup returns the [triple.Profile] registered under name —
// a shipped catalogue entry or a prior [TripleRegister] registration
// — as its JSON record, written into jsonOut under the same
// caller-allocated-buffer convention as [TripleInspect]. An unknown
// name is StatusUnknownProfile.
func TripleLookup(name string, jsonOut []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	prof, err := triple.Lookup(name)
	if err != nil {
		s := mapTripleError(err)
		setLastErr(s)
		return 0, s
	}
	return writeJSONOut(prof, jsonOut)
}

// TripleProfiles returns the sorted list of every registered profile
// name — the shipped catalogue plus prior [TripleRegister] calls — as
// a JSON array of strings, written into jsonOut under the
// caller-allocated-buffer convention (StatusBufferTooSmall with n =
// the required capacity).
func TripleProfiles(jsonOut []byte) (n int, st Status) {
	defer recoverPanic(&st, StatusInternal)

	return writeJSONOut(triple.Profiles(), jsonOut)
}

// writeJSONOut marshals v and copies the bytes into out under the
// caller-allocated-buffer convention shared by every string-returning
// Triple entry: n reports the bytes written on success or the required
// capacity on StatusBufferTooSmall.
func writeJSONOut(v any, out []byte) (n int, st Status) {
	data, err := json.Marshal(v)
	if err != nil {
		setLastErrMessageTriple(err.Error())
		return 0, StatusInternal
	}
	if len(data) > len(out) {
		setLastErr(StatusBufferTooSmall)
		return len(data), StatusBufferTooSmall
	}
	copy(out, data)
	return len(data), StatusOK
}
