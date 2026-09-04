package triple

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
)

// blobFileMode is the permission mask [Pipeline.SaveF] creates a blob
// file with: owner read / write only. The blob is key material.
const blobFileMode = 0o600

// Load reconstructs a [Pipeline] from a self-describing blob produced
// by [Init], [Pipeline.Save], or [Pipeline.Rekey]. The blob's
// wrap-layer carries the sender's resolved [Profile] record; Load
// decodes it, verifies every primitive it names is available locally,
// and rebuilds the Pipeline from the record, the inner Blob{N}, and
// the blob's masters. The profile registry is not consulted and not
// modified; the record's Name is an opaque label.
//
// The trailing masters variadic is the rekey-on-import path: 0 = use
// the blob's masters, 2 = (permMaster, wrapMaster) replace them, any
// other arity returns [ErrMastersArity]. The Pipeline's retained blob
// (see [Pipeline.Save]) is re-marshalled with the resolved masters, so
// the bytes it returns after a master override describe the keys the
// Pipeline runs with.
//
// There is no Opts argument. The blob describes the sender's exact
// shape — primitives, key width, MAC, outer cipher, palette, chunk
// and segment sizes, and which layers are engaged — and a receiver
// that deviated from any of it could not decrypt the sender's wires.
// Runtime tuning is applied after construction: [Pipeline.MaxWorkers]
// sets the per-Pipeline worker cap (a loaded Pipeline starts at
// auto); [itb.SetMemoryLimit] / [itb.SetGCPercent] govern the process.
//
// Concurrency: safe for concurrent invocation with itself and with
// every other package entry point.
//
// Errors: [ErrBlobMalformed] (size cap exceeded, JSON parse failure,
// unknown key, trailing content, missing record or inner blob),
// [ErrBlobVersion] (wrap-layer version other than 2 — blobs produced
// by earlier releases included), [ErrBlobMalformedRecipe] (the record
// fails the profile field rules, or disagrees with the inner blob's
// MAC name or key width), [ErrRecipePrimitiveUnknown] (the record
// names a primitive absent from the local hashes / macs / wrapper
// registries), [ErrMissingMasters], [ErrIdenticalMasters],
// [ErrMastersArity], [ErrBadKeyBits], and the inner Blob{N} import
// failures (wrapping [itb.ErrBlobMalformed] and friends).
func Load(blob []byte, masters ...[]byte) (*Pipeline, error) {
	if len(masters) != 0 && len(masters) != 2 {
		return nil, ErrMastersArity
	}
	wrap, err := parseBlobWrap(blob)
	if err != nil {
		return nil, err
	}
	if err := checkRecipeProfile(wrap.Profile); err != nil {
		return nil, err
	}
	return openWrap(wrap, masters)
}

// LoadF is [Load] for a blob stored in a file: the path is normalised
// with [filepath.Clean], the file is read with [os.ReadFile], and the
// bytes go through Load with the same masters semantics. A file larger
// than [itb.MaxBlobJSONSize] is refused with [ErrBlobMalformed] before
// it is read. os.Stat / os.ReadFile errors are wrapped via %w so
// errors.Is against [os.ErrNotExist] / [os.ErrPermission] matches;
// every other error is Load's.
func LoadF(path string, masters ...[]byte) (*Pipeline, error) {
	if len(masters) != 0 && len(masters) != 2 {
		return nil, ErrMastersArity
	}
	clean := filepath.Clean(path)
	info, err := os.Stat(clean)
	if err != nil {
		return nil, fmt.Errorf("triple: LoadF: %w", err)
	}
	if info.Size() > int64(itb.MaxBlobJSONSize) {
		return nil, ErrBlobMalformed
	}
	data, err := os.ReadFile(clean)
	if err != nil {
		return nil, fmt.Errorf("triple: LoadF: %w", err)
	}
	return Load(data, masters...)
}

// Save returns a copy of the wrap-layer blob describing this
// Pipeline's current session state: the bytes [Init] produced, the
// bytes [Load] / [LoadF] re-marshalled from the record and the
// resolved masters (a rekey-on-import override folded in), or the
// bytes the most recent [Pipeline.Rekey] produced — whichever happened
// last. The result is exactly what a peer needs for [Load]. Init's
// second return value is Save() of the freshly built Pipeline.
//
// The copy carries key material (masters, inner seed components, MAC
// key); callers zero it when done. After [Pipeline.Close] the
// retained blob has been wiped and Save returns nil — [Pipeline.SaveF]
// reports that case as [ErrClosed] and is the recommended persist
// call.
func (p *Pipeline) Save() []byte {
	if p.isClosed() || p.blob == nil {
		return nil
	}
	return append([]byte(nil), p.blob...)
}

// SaveF writes [Pipeline.Save] to path with restrictive file
// permissions (0600 on POSIX; the closest equivalent under the Go
// stdlib's file-mode mapping on Windows) — the blob is key material
// and is not safe to leave world-readable. The file is created if
// missing and truncated if existing; the containing directory must
// exist (no mkdir-p; callers invoke [os.MkdirAll] separately); the
// path is normalised via [filepath.Clean] before the write.
//
// Symmetric partner to [LoadF]:
//
//	err := pipe.SaveF("session.blob")
//	...
//	pipe2, err := triple.LoadF("session.blob")
//
// Returns [ErrClosed] after [Pipeline.Close]; os.WriteFile errors are
// wrapped via %w so a caller can errors.Is-match against
// [os.ErrPermission] / [os.ErrNotExist] and friends.
func (p *Pipeline) SaveF(path string) error {
	blob := p.Save()
	if blob == nil {
		return ErrClosed
	}
	defer clear(blob)
	if err := os.WriteFile(filepath.Clean(path), blob, blobFileMode); err != nil {
		return fmt.Errorf("triple: SaveF: %w", err)
	}
	return nil
}

// Inspect decodes the wrap-layer of blob and returns the embedded
// [Profile] record — every structural field the sender's Pipeline was
// built with, Init-time Opts overrides folded in, Name carrying the
// sender's profile label. No Pipeline is opened.
//
// Inspect is a pure decode: it does not read the profile registry,
// does not probe primitive availability, does not run the profile
// field rules, does not open the inner blob, and registers nothing.
// Primitive names the local build lacks are returned unchanged so a
// metadata viewer can display them; availability and field validity
// are enforced by [Load]. Callers who want the record registered call
// [Register] with prof.Name and the result.
//
// Errors: [ErrBlobMalformed] (size cap, JSON parse failure, unknown
// key, trailing content, record not decodable), [ErrBlobVersion]
// (wrap-layer version other than 2).
//
// Concurrency: safe for concurrent invocation; touches no shared
// state.
func Inspect(blob []byte) (Profile, error) {
	wrap, err := parseBlobWrap(blob)
	if err != nil {
		return Profile{}, err
	}
	return wrap.Profile, nil
}

// parseBlobWrap decodes the wrap-layer bytes into a [blobWrapV2]. The
// size cap ([itb.MaxBlobJSONSize]) runs first; a lenient version probe
// then classifies any schema other than version 2 as [ErrBlobVersion]
// (so a blob from an earlier release reports its version rather than a
// field-shape mismatch); the strict full decode — unknown keys and
// trailing content refused — runs on version 2 only, followed by the
// presence check on the record and the inner blob. Every failure
// other than the version mismatch is [ErrBlobMalformed]. The inner
// blob is not descended into here; its own strict decoder runs inside
// [openWrap].
func parseBlobWrap(blob []byte) (blobWrapV2, error) {
	var wrap blobWrapV2
	if len(blob) > itb.MaxBlobJSONSize {
		return wrap, ErrBlobMalformed
	}
	var probe struct {
		Version int `json:"v"`
	}
	if err := json.Unmarshal(blob, &probe); err != nil {
		return wrap, ErrBlobMalformed
	}
	if probe.Version != blobWrapVersionV2 {
		return wrap, ErrBlobVersion
	}
	dec := json.NewDecoder(bytes.NewReader(blob))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wrap); err != nil {
		return blobWrapV2{}, ErrBlobMalformed
	}
	if dec.More() {
		return blobWrapV2{}, ErrBlobMalformed
	}
	if wrap.Profile.Mode == "" || len(wrap.Inner) == 0 {
		return blobWrapV2{}, ErrBlobMalformed
	}
	return wrap, nil
}

// checkRecipeProfile validates a record decoded from a blob ahead of
// the build. Availability probes run first so a missing primitive is
// reported as [ErrRecipePrimitiveUnknown] naming it, not as a
// malformed record; the profile field rules — the same set [Register]
// applies — then run, with any failure wrapped in
// [ErrBlobMalformedRecipe]; finally the resolved key width is checked
// against the [itb.MaxKeyBits] envelope ([ErrBadKeyBits]).
func checkRecipeProfile(prof Profile) error {
	if len(prof.Name) > ProfileNameMaxLen {
		return fmt.Errorf("%w: name length %d exceeds ProfileNameMaxLen=%d", ErrBlobMalformedRecipe, len(prof.Name), ProfileNameMaxLen)
	}
	if isMixedProfile(prof) {
		for i, name := range prof.MixedHashes {
			if name == "" {
				continue
			}
			if _, ok := hashes.Find(name); !ok {
				return fmt.Errorf("%w: hashes[%d] %q", ErrRecipePrimitiveUnknown, i, name)
			}
		}
	} else if prof.InnerHash != "" {
		if _, ok := hashes.Find(prof.InnerHash); !ok {
			return fmt.Errorf("%w: hash %q", ErrRecipePrimitiveUnknown, prof.InnerHash)
		}
	}
	if prof.MacName != "" {
		if _, ok := macs.Find(prof.MacName); !ok {
			return fmt.Errorf("%w: mac %q", ErrRecipePrimitiveUnknown, prof.MacName)
		}
	}
	if prof.Wrapper && prof.OuterCipher != "" && !isKnownWrapperCipher(prof.OuterCipher) {
		return fmt.Errorf("%w: outer %q", ErrRecipePrimitiveUnknown, prof.OuterCipher)
	}
	if prof.Parallax {
		for i, entry := range prof.ParallaxPalette {
			if entry != "" && !isKnownWrapperCipher(entry) {
				return fmt.Errorf("%w: palette[%d] %q", ErrRecipePrimitiveUnknown, i, entry)
			}
		}
	}
	if err := validateProfileFields(prof); err != nil {
		return fmt.Errorf("%w: %w", ErrBlobMalformedRecipe, err)
	}
	if err := validateResolvedKeyBits("Load", prof); err != nil {
		return err
	}
	return nil
}
