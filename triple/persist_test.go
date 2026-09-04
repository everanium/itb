package triple

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/parallax"
)

// persistProfiles enumerates every shipped profile — single-primitive
// and mixed — for the persistence round-trip matrix.
func persistProfiles() []string {
	return append(allProfiles(),
		ProfileStreamingAEADTripleMACMixedV1,
		ProfileStreamingNoAEADTripleMixedV1,
		ProfileSingleMsgTripleMACMixedV1,
		ProfileSingleMsgTripleNoMACMixedV1,
	)
}

// wrapFields decodes the wrap-layer into its top-level keys so a test
// can edit one field and re-marshal without going through the strict
// decoder.
func wrapFields(t *testing.T, blob []byte) map[string]json.RawMessage {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatalf("wrapFields: %v", err)
	}
	return m
}

// marshalFields is the inverse of wrapFields.
func marshalFields(t *testing.T, m map[string]json.RawMessage) []byte {
	t.Helper()
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshalFields: %v", err)
	}
	return out
}

// editRecord decodes the wrap-layer record into a generic map, lets
// the caller mutate it, and re-marshals the blob.
func editRecord(t *testing.T, blob []byte, edit func(p map[string]any)) []byte {
	t.Helper()
	m := wrapFields(t, blob)
	var p map[string]any
	if err := json.Unmarshal(m["p"], &p); err != nil {
		t.Fatalf("editRecord: %v", err)
	}
	edit(p)
	pb, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("editRecord marshal: %v", err)
	}
	m["p"] = pb
	return marshalFields(t, m)
}

// editInner decodes the inner blob into a generic map, lets the caller
// mutate it, and re-marshals the wrap-layer around it.
func editInner(t *testing.T, blob []byte, edit func(ib map[string]json.RawMessage)) []byte {
	t.Helper()
	m := wrapFields(t, blob)
	var ib map[string]json.RawMessage
	if err := json.Unmarshal(m["ib"], &ib); err != nil {
		t.Fatalf("editInner: %v", err)
	}
	edit(ib)
	ibb, err := json.Marshal(ib)
	if err != nil {
		t.Fatalf("editInner marshal: %v", err)
	}
	m["ib"] = ibb
	return marshalFields(t, m)
}

// roundTripMessage encrypts under tx and decrypts under rx, failing
// the test on any mismatch. Blob-only profiles are skipped.
func roundTripMessage(t *testing.T, tx, rx *Pipeline) {
	t.Helper()
	if hasNoCipherSurface(tx.resolved.Mode) {
		return
	}
	plain := []byte("persist round-trip payload")
	wire, err := tx.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := rx.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch")
	}
}

// TestLoadRoundTripAllProfiles covers Init → Load under every shipped
// profile shape, then a message round-trip in both directions and a
// record comparison between the two Pipelines.
func TestLoadRoundTripAllProfiles(t *testing.T) {
	for _, name := range persistProfiles() {
		t.Run(name, func(t *testing.T) {
			tx, blob, err := Init(name, Opts{})
			if err != nil {
				t.Fatalf("Init: %v", err)
			}
			defer tx.Close()
			rx, err := Load(blob)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			defer rx.Close()
			if !reflect.DeepEqual(tx.resolved, rx.resolved) {
				t.Fatalf("resolved record differs:\n tx %+v\n rx %+v", tx.resolved, rx.resolved)
			}
			if rx.resolved.Name != name {
				t.Fatalf("record label %q, want %q", rx.resolved.Name, name)
			}
			if err := seedsEqual(tx, rx); err != nil {
				t.Fatalf("seeds: %v", err)
			}
			roundTripMessage(t, tx, rx)
			roundTripMessage(t, rx, tx)
		})
	}
}

// TestLoadStructuralOptsOverride pins the record as the resolved
// (post-Opts) shape: structural Opts overrides at Init travel in the
// blob, Load reproduces them without the receiver repeating them, and
// Inspect reports them.
func TestLoadStructuralOptsOverride(t *testing.T) {
	opts := Opts{
		KeyBits:             2048,
		InnerHash:           "blake2b512",
		ParallaxPalette:     []string{"blake3", "chacha20", "siphash24"},
		ParallaxSegmentSize: 1021,
		ChunkSize:           1 << 20,
		OuterCipher:         "aescmac",
		MacName:             "hmac-blake3",
	}
	tx, blob, err := Init(ProfileSingleMsgTripleMACV1, opts)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer tx.Close()

	prof, err := Inspect(blob)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if prof.KeyBits != 2048 || prof.InnerHash != "blake2b512" || prof.Width != 512 ||
		prof.ParallaxSegmentSize != 1021 || prof.ChunkSize != 1<<20 || prof.OuterCipher != "aescmac" ||
		!reflect.DeepEqual(prof.ParallaxPalette, []string{"blake3", "chacha20", "siphash24"}) {
		t.Fatalf("Inspect does not report the overrides: %+v", prof)
	}

	rx, err := Load(blob)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer rx.Close()
	if !reflect.DeepEqual(tx.resolved, rx.resolved) {
		t.Fatalf("resolved record differs:\n tx %+v\n rx %+v", tx.resolved, rx.resolved)
	}
	if rx.width != 512 || len(seedComponentsFor(rx.seeds[0], 512)) != 2048/64 {
		t.Fatalf("receiver width / key width not reproduced")
	}
	roundTripMessage(t, tx, rx)
}

// TestLoadInnerHashOverrideChangesWidth pins the record's Width as the
// width actually in force when an Opts.InnerHash override selects a
// primitive of a different width than the profile default.
func TestLoadInnerHashOverrideChangesWidth(t *testing.T) {
	tx, blob, err := Init(ProfileSingleMsgTripleMACV1, Opts{InnerHash: "blake3"})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer tx.Close()
	prof, err := Inspect(blob)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if prof.Width != 256 || prof.InnerHash != "blake3" {
		t.Fatalf("record width/hash = %d/%q, want 256/blake3", prof.Width, prof.InnerHash)
	}
	rx, err := Load(blob)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer rx.Close()
	roundTripMessage(t, tx, rx)
}

// TestLoadUnregisteredLabel confirms the label inside the record is
// opaque: a blob whose name is registered nowhere loads, and the
// registry is untouched before and after.
func TestLoadUnregisteredLabel(t *testing.T) {
	_, blob, err := Init(ProfileSingleMsgTripleNoMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	edited := editRecord(t, blob, func(p map[string]any) {
		p["name"] = "label-registered-nowhere"
	})
	before := Profiles()
	rx, err := Load(edited)
	if err != nil {
		t.Fatalf("Load with unregistered label: %v", err)
	}
	defer rx.Close()
	if rx.resolved.Name != "label-registered-nowhere" {
		t.Fatalf("label = %q", rx.resolved.Name)
	}
	if _, err := Lookup("label-registered-nowhere"); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("Load registered the label: err=%v", err)
	}
	if !reflect.DeepEqual(before, Profiles()) {
		t.Fatalf("Profiles changed across Load")
	}
	// A blob with no label at all loads too.
	noName := editRecord(t, blob, func(p map[string]any) { delete(p, "name") })
	rx2, err := Load(noName)
	if err != nil {
		t.Fatalf("Load without name: %v", err)
	}
	rx2.Close()
}

// TestLoadCustomProfileRoundTrip installs a custom profile via
// Register, builds a Pipeline, and reopens it through Load; the
// Inspect result can be re-registered under a new name.
func TestLoadCustomProfileRoundTrip(t *testing.T) {
	const name = "userns-persist-custom-v1"
	prof := Profile{
		Mode:                modeSingleMsgMAC,
		Width:               256,
		InnerHash:           "blake2s",
		KeyBits:             1024,
		MacName:             "hmac-blake3",
		OuterCipher:         "blake3",
		ParallaxPalette:     []string{"aescmac", "siphash24", "blake3"},
		ParallaxSegmentSize: 4093,
		Parallax:            true,
		Wrapper:             true,
		TagStubSize:         32,
	}
	if err := Register(name, prof); err != nil && !errors.Is(err, ErrProfileExists) {
		t.Fatalf("Register: %v", err)
	}
	tx, blob, err := Init(name, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer tx.Close()
	rx, err := Load(blob)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer rx.Close()
	roundTripMessage(t, tx, rx)

	got, err := Inspect(blob)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if err := Register("userns-persist-custom-copy-v1", got); err != nil && !errors.Is(err, ErrProfileExists) {
		t.Fatalf("Register(Inspect result): %v", err)
	}
	if _, err := Lookup("userns-persist-custom-copy-v1"); err != nil {
		t.Fatalf("Lookup after re-register: %v", err)
	}
}

// TestLoadRuntimeRegisteredPrimitive registers a primitive at runtime
// under a new name, builds a Pipeline naming it, and confirms the
// blob loads while the primitive is registered; a record naming a
// primitive absent from every registry fails Load with
// ErrRecipePrimitiveUnknown while Inspect returns the name unchanged.
func TestLoadRuntimeRegisteredPrimitive(t *testing.T) {
	const hashName = "custom512t"
	err := hashes.Register(hashes.Spec{
		Name:  hashName,
		Width: hashes.W512,
		Make512Pair: func(key ...[]byte) (itb.HashFunc512, itb.BatchHashFunc512, []byte, error) {
			return hashes.Make512Pair("blake2b512", key...)
		},
	})
	if err != nil && !errors.Is(err, hashes.ErrHashExists) {
		t.Fatalf("hashes.Register: %v", err)
	}
	tx, blob, err := Init(ProfileSingleMsgTripleMACV1, Opts{InnerHash: hashName})
	if err != nil {
		t.Fatalf("Init with runtime primitive: %v", err)
	}
	defer tx.Close()
	rx, err := Load(blob)
	if err != nil {
		t.Fatalf("Load with runtime primitive: %v", err)
	}
	defer rx.Close()
	roundTripMessage(t, tx, rx)

	cases := []struct {
		label string
		edit  func(p map[string]any)
	}{
		{"hash", func(p map[string]any) { p["hash"] = "nosuchhash" }},
		{"mac", func(p map[string]any) { p["mac"] = "nosuchmac" }},
		{"outer", func(p map[string]any) { p["outer"] = "nosuchouter" }},
		{"palette", func(p map[string]any) { p["palette"] = []string{"aescmac", "nosuchpal", "blake3"} }},
		{"hashes", func(p map[string]any) {
			delete(p, "hash")
			p["hashes"] = []string{"areion512", "nosuchhash", "areion512", "blake2b512", "areion512", "blake2b512", "areion512", "blake2b512"}
		}},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			edited := editRecord(t, blob, c.edit)
			if _, err := Load(edited); !errors.Is(err, ErrRecipePrimitiveUnknown) {
				t.Fatalf("Load: got %v, want ErrRecipePrimitiveUnknown", err)
			}
			if _, err := Inspect(edited); err != nil {
				t.Fatalf("Inspect must not probe availability: %v", err)
			}
		})
	}
}

// TestLoadConcurrent runs many concurrent Load calls on one blob.
func TestLoadConcurrent(t *testing.T) {
	tx, blob, err := Init(ProfileSingleMsgTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer tx.Close()
	const n = 100
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p, err := Load(blob)
			if err != nil {
				errs[i] = err
				return
			}
			if !bytes.Equal(p.Save(), blob) {
				errs[i] = errors.New("Save differs from input")
			}
			p.Close()
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("goroutine %d: %v", i, err)
		}
	}
}

// TestLoadInspectErrorSurface walks the malformed-blob classes and
// pins the sentinel each one maps to, from both Load and Inspect.
func TestLoadInspectErrorSurface(t *testing.T) {
	_, blob, err := Init(ProfileSingleMsgTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	v1 := `{"p":"singlemsg-triple-mac-v1","v":1,"pm":"AAAA","wm":"AAAB","ib":"e30=","wp":true,"ww":true}`
	cases := []struct {
		label   string
		blob    []byte
		want    error
		inspect error // nil = same as want
	}{
		{"v1_blob", []byte(v1), ErrBlobVersion, nil},
		{"v3_blob", func() []byte {
			m := wrapFields(t, blob)
			m["v"] = json.RawMessage("3")
			return marshalFields(t, m)
		}(), ErrBlobVersion, nil},
		{"missing_v", func() []byte {
			m := wrapFields(t, blob)
			delete(m, "v")
			return marshalFields(t, m)
		}(), ErrBlobVersion, nil},
		{"not_json", []byte("not json at all"), ErrBlobMalformed, nil},
		{"empty", nil, ErrBlobMalformed, nil},
		{"oversized", bytes.Repeat([]byte{'{'}, itb.MaxBlobJSONSize+1), ErrBlobMalformed, nil},
		{"trailing_content", append(append([]byte(nil), blob...), []byte(" {}")...), ErrBlobMalformed, nil},
		{"no_p", func() []byte {
			m := wrapFields(t, blob)
			delete(m, "p")
			return marshalFields(t, m)
		}(), ErrBlobMalformed, nil},
		{"null_p", func() []byte {
			m := wrapFields(t, blob)
			m["p"] = json.RawMessage("null")
			return marshalFields(t, m)
		}(), ErrBlobMalformed, nil},
		{"no_ib", func() []byte {
			m := wrapFields(t, blob)
			delete(m, "ib")
			return marshalFields(t, m)
		}(), ErrBlobMalformed, nil},
		{"unknown_wrap_key", func() []byte {
			m := wrapFields(t, blob)
			m["wp"] = json.RawMessage("true")
			return marshalFields(t, m)
		}(), ErrBlobMalformed, nil},
		{"unknown_record_key", editRecord(t, blob, func(p map[string]any) { p["extra"] = 1 }), ErrBlobMalformed, nil},
		{"hashes_len_3", editRecord(t, blob, func(p map[string]any) {
			p["hashes"] = []string{"areion512", "blake2b512", "areion512"}
		}), ErrBlobMalformed, nil},
		{"keybits_not_multiple", editRecord(t, blob, func(p map[string]any) { p["keybits"] = 1000 }), ErrBlobMalformedRecipe, ErrBlobMalformed},
		{"keybits_inner_mismatch", editRecord(t, blob, func(p map[string]any) { p["keybits"] = 2048 }), ErrBlobMalformedRecipe, ErrBlobMalformed},
		{"keybits_out_of_range", editRecord(t, blob, func(p map[string]any) { p["keybits"] = 512 * 8 }), ErrBadKeyBits, ErrBlobMalformed},
		{"mac_mismatch", editRecord(t, blob, func(p map[string]any) { p["mac"] = otherMACName(t) }), ErrBlobMalformedRecipe, ErrBlobMalformed},
		{"mac_dropped", editRecord(t, blob, func(p map[string]any) { delete(p, "mac") }), ErrBlobMalformedRecipe, ErrBlobMalformed},
		{"bad_mode", editRecord(t, blob, func(p map[string]any) { p["mode"] = "nonsense" }), ErrBlobMalformedRecipe, ErrBlobMalformed},
		{"bad_width", editRecord(t, blob, func(p map[string]any) { p["width"] = 1024 }), ErrBlobMalformedRecipe, ErrBlobMalformed},
		{"segment_not_coprime", editRecord(t, blob, func(p map[string]any) { p["segment"] = 504 }), ErrBlobMalformedRecipe, ErrBlobMalformed},
		{"ib_base64_string", func() []byte {
			m := wrapFields(t, blob)
			var raw json.RawMessage = m["ib"]
			enc := base64.StdEncoding.EncodeToString(raw)
			m["ib"] = json.RawMessage(`"` + enc + `"`)
			return marshalFields(t, m)
		}(), itb.ErrBlobMalformed, ErrBlobMalformed},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			_, err := Load(c.blob)
			if !errors.Is(err, c.want) {
				t.Fatalf("Load: got %v, want %v", err, c.want)
			}
			_, ierr := Inspect(c.blob)
			switch {
			case c.inspect == nil:
				if !errors.Is(ierr, c.want) {
					t.Fatalf("Inspect: got %v, want %v", ierr, c.want)
				}
			case c.inspect == ErrBlobMalformed && (c.want == ErrBlobMalformedRecipe || c.want == ErrBadKeyBits || c.want == itb.ErrBlobMalformed):
				// Inspect does not run the field rules and does not open
				// the inner blob — a record-level or inner-level failure
				// is invisible to it.
				if ierr != nil {
					t.Fatalf("Inspect: got %v, want nil (pure decode)", ierr)
				}
			default:
				if !errors.Is(ierr, c.inspect) {
					t.Fatalf("Inspect: got %v, want %v", ierr, c.inspect)
				}
			}
		})
	}
}

// otherMACName returns a registered MAC name other than the shipped
// default so a record / inner-blob MAC disagreement can be staged.
func otherMACName(t *testing.T) string {
	t.Helper()
	for _, spec := range macs.Registry {
		if spec.Name != defaultMacName {
			return spec.Name
		}
	}
	t.Skip("macs.Registry carries a single MAC")
	return ""
}

// TestLoadMasterOverrideSave covers rekey-on-import: Load with a
// master pair re-marshals the retained blob with those masters, and
// the re-emitted blob interoperates with a sender rekeyed to the same
// pair.
func TestLoadMasterOverrideSave(t *testing.T) {
	tx, blob, err := Init(ProfileSingleMsgTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer tx.Close()
	perm2 := freshBytes(t, 32)
	wrap2 := freshBytes(t, 32)

	rx, err := Load(blob, perm2, wrap2)
	if err != nil {
		t.Fatalf("Load with override: %v", err)
	}
	defer rx.Close()
	saved := rx.Save()
	if bytes.Equal(saved, blob) {
		t.Fatalf("Save after override equals input blob")
	}
	m := wrapFields(t, saved)
	var pm, wm []byte
	if err := json.Unmarshal(m["pm"], &pm); err != nil {
		t.Fatalf("pm: %v", err)
	}
	if err := json.Unmarshal(m["wm"], &wm); err != nil {
		t.Fatalf("wm: %v", err)
	}
	if !bytes.Equal(pm, perm2) || !bytes.Equal(wm, wrap2) {
		t.Fatalf("Save does not carry the override masters")
	}

	// Sender rotates to the same pair; the receiver's re-emitted blob
	// then interoperates with it.
	if _, err := tx.Rekey(perm2, wrap2); err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	rx2, err := Load(saved)
	if err != nil {
		t.Fatalf("Load(saved): %v", err)
	}
	defer rx2.Close()
	roundTripMessage(t, tx, rx2)
	roundTripMessage(t, tx, rx)
}

// TestSaveSemantics pins the retained-blob contract: Save after Init
// equals Init's second return, after Rekey equals Rekey's return,
// the returned copy is independent of the Pipeline, Save after Close
// is nil, and SaveF after Close is ErrClosed.
func TestSaveSemantics(t *testing.T) {
	p, blob, err := Init(ProfileSingleMsgTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	s1 := p.Save()
	if !bytes.Equal(s1, blob) {
		t.Fatalf("Save after Init differs from Init's blob")
	}
	s1[0] ^= 0xff
	if !bytes.Equal(p.Save(), blob) {
		t.Fatalf("Save returned an alias of the retained blob")
	}

	fresh, err := p.Rekey(freshBytes(t, 32), freshBytes(t, 32))
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	if !bytes.Equal(p.Save(), fresh) {
		t.Fatalf("Save after Rekey differs from Rekey's blob")
	}
	if bytes.Equal(fresh, blob) {
		t.Fatalf("Rekey blob equals Init blob")
	}

	keep := p.Save()
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if p.Save() != nil {
		t.Fatalf("Save after Close is not nil")
	}
	if !bytes.Equal(keep, fresh) {
		t.Fatalf("copy returned before Close was zeroed by Close")
	}
	if err := p.SaveF(filepath.Join(t.TempDir(), "closed.blob")); !errors.Is(err, ErrClosed) {
		t.Fatalf("SaveF after Close: got %v, want ErrClosed", err)
	}
}

// TestLoadFSaveF covers the file forms: SaveF + LoadF round trip on a
// temp path, POSIX mode 0600, LoadF equivalence with Load, and the
// %w-wrapped os errors on a missing file / missing directory.
func TestLoadFSaveF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "session.blob")

	tx, blob, err := Init(ProfileSingleMsgTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer tx.Close()
	if err := tx.SaveF(path); err != nil {
		t.Fatalf("SaveF: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("SaveF mode = %o, want 0600", info.Mode().Perm())
		}
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(onDisk, blob) {
		t.Fatalf("SaveF wrote bytes that differ from Save")
	}

	rx, err := LoadF(path)
	if err != nil {
		t.Fatalf("LoadF: %v", err)
	}
	defer rx.Close()
	roundTripMessage(t, tx, rx)
	rxB, err := Load(blob)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer rxB.Close()
	if !reflect.DeepEqual(rx.resolved, rxB.resolved) || !bytes.Equal(rx.Save(), rxB.Save()) {
		t.Fatalf("LoadF and Load produced different Pipelines")
	}

	// Truncate-on-write: a second SaveF over the same path after Rekey
	// leaves exactly the new bytes.
	fresh, err := tx.Rekey(freshBytes(t, 32), freshBytes(t, 32))
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	if err := tx.SaveF(path); err != nil {
		t.Fatalf("SaveF again: %v", err)
	}
	if again, _ := os.ReadFile(path); !bytes.Equal(again, fresh) {
		t.Fatalf("second SaveF did not truncate / replace")
	}

	// Missing file → os.ErrNotExist through the %w chain.
	if _, err := LoadF(filepath.Join(dir, "nonexistent.blob")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadF missing: got %v, want os.ErrNotExist", err)
	}
	// Missing directory → os.ErrNotExist (no mkdir-p).
	if err := tx.SaveF(filepath.Join(dir, "no", "such", "dir", "x.blob")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("SaveF missing dir: got %v, want os.ErrNotExist", err)
	}
	// Arity is checked before the file is read.
	if _, err := LoadF(path, freshBytes(t, 32)); !errors.Is(err, ErrMastersArity) {
		t.Fatalf("LoadF arity 1: got %v, want ErrMastersArity", err)
	}
	// A file over the size cap is refused before decoding.
	big := filepath.Join(dir, "big.blob")
	if err := os.WriteFile(big, bytes.Repeat([]byte{'{'}, itb.MaxBlobJSONSize+1), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadF(big); !errors.Is(err, ErrBlobMalformed) {
		t.Fatalf("LoadF oversized: got %v, want ErrBlobMalformed", err)
	}
}

// TestInspectShippedEqualsLookup pins Inspect against the registry:
// for every shipped profile the record equals the resolved Lookup
// result with the width fixed up and inert fields cleared.
func TestInspectShippedEqualsLookup(t *testing.T) {
	for _, name := range persistProfiles() {
		t.Run(name, func(t *testing.T) {
			_, blob, err := Init(name, Opts{})
			if err != nil {
				t.Fatalf("Init: %v", err)
			}
			got, err := Inspect(blob)
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}
			reg, err := Lookup(name)
			if err != nil {
				t.Fatalf("Lookup: %v", err)
			}
			want := resolveProfile(reg, Opts{})
			if !want.Wrapper {
				want.OuterCipher = ""
			}
			if !want.Parallax {
				want.ParallaxPalette, want.ParallaxSegmentSize = nil, 0
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Inspect:\n got  %+v\n want %+v", got, want)
			}
		})
	}
}

// TestProfileCodecRoundTrip pins the JSON codec on every shipped
// profile and on boundary values, and the absence of a hashes key on
// a single-primitive record.
func TestProfileCodecRoundTrip(t *testing.T) {
	boundary := Profile{
		Name:                "userns-codec-boundary",
		Mode:                modeStreamingAEAD,
		Width:               512,
		InnerHash:           "areion512",
		KeyBits:             2048,
		MacName:             "hmac-blake3",
		TagStubSize:         64,
		ChunkSize:           parallax.MaxChunkSize,
		Wrapper:             true,
		OuterCipher:         "chacha20",
		Parallax:            true,
		ParallaxSegmentSize: parallax.MaxSegmentSize,
	}
	for i := 0; i < parallax.MaxPaletteSize; i++ {
		boundary.ParallaxPalette = append(boundary.ParallaxPalette, "aescmac")
	}
	profiles := []Profile{boundary, {Mode: modeBlobOnly, Width: 128, InnerHash: "aescmac", KeyBits: 512}}
	for _, name := range persistProfiles() {
		p, err := Lookup(name)
		if err != nil {
			t.Fatalf("Lookup(%q): %v", name, err)
		}
		profiles = append(profiles, p)
	}
	for _, p := range profiles {
		data, err := json.Marshal(p)
		if err != nil {
			t.Fatalf("Marshal %q: %v", p.Name, err)
		}
		var back Profile
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("Unmarshal %q: %v", p.Name, err)
		}
		if len(p.ParallaxPalette) == 0 {
			p.ParallaxPalette = nil
		}
		if !reflect.DeepEqual(p, back) {
			t.Fatalf("codec round-trip %q:\n in   %+v\n back %+v\n json %s", p.Name, p, back, data)
		}
		if !isMixedProfile(p) && bytes.Contains(data, []byte(`"hashes"`)) {
			t.Fatalf("single-primitive record carries hashes: %s", data)
		}
		if isMixedProfile(p) && bytes.Contains(data, []byte(`"hash"`+`:`)) {
			t.Fatalf("mixed record carries hash: %s", data)
		}
	}
	// Key order and presence on a shipped record.
	data, _ := json.Marshal(profiles[len(profiles)-1])
	for _, key := range []string{`"mode"`, `"width"`, `"keybits"`, `"wrapper"`, `"parallax"`} {
		if !bytes.Contains(data, []byte(key)) {
			t.Fatalf("record lacks always-present key %s: %s", key, data)
		}
	}
	// Strictness: unknown key, hashes of length 3, trailing content.
	for _, bad := range []string{
		`{"mode":"blob-only","width":128,"keybits":512,"wrapper":false,"parallax":false,"extra":1}`,
		`{"mode":"blob-only","width":128,"keybits":512,"wrapper":false,"parallax":false,"hashes":["a","b","c"]}`,
		`{"mode":"blob-only","width":128,"keybits":512,"wrapper":false,"parallax":false} {}`,
	} {
		var p Profile
		if err := json.Unmarshal([]byte(bad), &p); err == nil {
			t.Fatalf("codec accepted %s", bad)
		}
	}
	// null leaves the value untouched.
	keep := Profile{Mode: "x"}
	if err := json.Unmarshal([]byte("null"), &keep); err != nil || keep.Mode != "x" {
		t.Fatalf("null handling: err=%v keep=%+v", err, keep)
	}
}

// TestLookupCopy pins Lookup's copy semantics and the miss sentinel.
func TestLookupCopy(t *testing.T) {
	a, err := Lookup(ProfileSingleMsgTripleMACV1)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	a.ParallaxPalette[0] = "mutated"
	b, err := Lookup(ProfileSingleMsgTripleMACV1)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if b.ParallaxPalette[0] == "mutated" {
		t.Fatalf("Lookup returned an alias of the registry palette")
	}
	if _, err := Lookup("no-such-profile-xyz"); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("Lookup unknown: got %v, want ErrUnknownProfile", err)
	}
	names := Profiles()
	if len(names) < len(persistProfiles()) || !sortedStrings(names) {
		t.Fatalf("Profiles: %v", names)
	}
}

// sortedStrings reports whether s is in ascending order.
func sortedStrings(s []string) bool {
	for i := 1; i < len(s); i++ {
		if s[i-1] > s[i] {
			return false
		}
	}
	return true
}

// TestMaxWorkers walks the clamp table at both sites, confirms the
// cap never reaches the blob, that a loaded Pipeline starts at auto,
// that the accessor is a no-op after Close, and that a blob carrying
// a max_workers key inside the inner globals is refused by Load while
// Inspect still succeeds.
func TestMaxWorkers(t *testing.T) {
	for _, c := range []struct{ in, want int }{{-3, 0}, {0, 0}, {1, 1}, {4, 4}, {256, 256}, {257, 256}, {300, 256}} {
		if got := clampWorkers(c.in); got != c.want {
			t.Fatalf("clampWorkers(%d) = %d, want %d", c.in, got, c.want)
		}
		p, blob, err := Init(ProfileSingleMsgTripleNoMACV1, Opts{MaxWorkers: c.in})
		if err != nil {
			t.Fatalf("Init(MaxWorkers=%d): %v", c.in, err)
		}
		if p.cfg.MaxWorkers != c.want {
			t.Fatalf("Init(MaxWorkers=%d): cfg = %d, want %d", c.in, p.cfg.MaxWorkers, c.want)
		}
		if bytes.Contains(blob, []byte("max_workers")) {
			t.Fatalf("blob carries max_workers")
		}
		p.Close()
	}

	tx, blob, err := Init(ProfileSingleMsgTripleMACV1, Opts{MaxWorkers: 4})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer tx.Close()
	rx, err := Load(blob)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer rx.Close()
	if rx.cfg.MaxWorkers != 0 {
		t.Fatalf("loaded Pipeline MaxWorkers = %d, want 0 (auto)", rx.cfg.MaxWorkers)
	}

	for _, p := range []*Pipeline{tx, rx} {
		for _, c := range []struct{ in, want int }{{8, 8}, {0, 0}, {-1, 0}, {257, 256}} {
			p.MaxWorkers(c.in)
			if p.cfg.MaxWorkers != c.want {
				t.Fatalf("MaxWorkers(%d): cfg = %d, want %d", c.in, p.cfg.MaxWorkers, c.want)
			}
		}
		p.MaxWorkers(8)
		roundTripMessage(t, tx, rx)
	}
	// The cap never reaches the blob: ib is byte-identical before and
	// after an accessor change, on Save and on Rekey.
	before := wrapFields(t, tx.Save())["ib"]
	tx.MaxWorkers(3)
	if !bytes.Equal(before, wrapFields(t, tx.Save())["ib"]) {
		t.Fatalf("Save ib changed after MaxWorkers")
	}
	rekeyed, err := tx.Rekey(freshBytes(t, 32), freshBytes(t, 32))
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	if !bytes.Equal(before, wrapFields(t, rekeyed)["ib"]) {
		t.Fatalf("Rekey ib changed after MaxWorkers")
	}

	// Closed Pipeline: accessor is a no-op, next cipher call ErrClosed.
	closed, _, err := Init(ProfileSingleMsgTripleMACV1, Opts{MaxWorkers: 2})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	closed.Close()
	closed.MaxWorkers(9)
	if closed.cfg.MaxWorkers != 2 {
		t.Fatalf("MaxWorkers after Close mutated cfg")
	}
	if _, err := closed.EncryptMessage([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("cipher call after Close: %v", err)
	}

	// A hand-edited max_workers key inside ib is an unknown key to the
	// inner strict decoder.
	injected := editInner(t, blob, func(ib map[string]json.RawMessage) {
		var g map[string]any
		if err := json.Unmarshal(ib["globals"], &g); err != nil {
			t.Fatalf("globals: %v", err)
		}
		g["max_workers"] = 7
		gb, _ := json.Marshal(g)
		ib["globals"] = gb
	})
	if _, err := Load(injected); !errors.Is(err, itb.ErrBlobMalformed) {
		t.Fatalf("Load with max_workers in ib: got %v, want itb.ErrBlobMalformed", err)
	}
	if _, err := Inspect(injected); err != nil {
		t.Fatalf("Inspect with max_workers in ib: %v", err)
	}
}

// TestNonceBitsBarrierFillIsolation builds three Pipelines with
// distinct NonceBits (and three with distinct BarrierFill) in one
// process and confirms each blob carries its own value, each Load
// reproduces it regardless of construction order, and each pair
// interoperates.
func TestNonceBitsBarrierFillIsolation(t *testing.T) {
	type cell struct {
		opts        Opts
		nonceBits   int
		barrierFill int
	}
	cells := []cell{
		{Opts{NonceBits: 128}, 128, itb.DefaultBarrierFill},
		{Opts{NonceBits: 256}, 256, itb.DefaultBarrierFill},
		{Opts{}, itb.DefaultNonceBits, itb.DefaultBarrierFill},
		{Opts{BarrierFill: 4}, itb.DefaultNonceBits, 4},
		{Opts{BarrierFill: 32}, itb.DefaultNonceBits, 32},
	}
	var txs []*Pipeline
	var blobs [][]byte
	for _, c := range cells {
		tx, blob, err := Init(ProfileSingleMsgTripleMACV1, c.opts)
		if err != nil {
			t.Fatalf("Init(%+v): %v", c.opts, err)
		}
		defer tx.Close()
		if tx.cfg.NonceBits != c.nonceBits || tx.cfg.BarrierFill != c.barrierFill {
			t.Fatalf("Init(%+v): cfg = %d/%d", c.opts, tx.cfg.NonceBits, tx.cfg.BarrierFill)
		}
		var ib struct {
			Globals struct {
				NonceBits   int `json:"nonce_bits"`
				BarrierFill int `json:"barrier_fill"`
			} `json:"globals"`
		}
		if err := json.Unmarshal(wrapFields(t, blob)["ib"], &ib); err != nil {
			t.Fatalf("ib: %v", err)
		}
		if ib.Globals.NonceBits != c.nonceBits || ib.Globals.BarrierFill != c.barrierFill {
			t.Fatalf("blob globals = %+v, want %d/%d", ib.Globals, c.nonceBits, c.barrierFill)
		}
		txs = append(txs, tx)
		blobs = append(blobs, blob)
	}
	// Load in reverse construction order.
	for i := len(cells) - 1; i >= 0; i-- {
		rx, err := Load(blobs[i])
		if err != nil {
			t.Fatalf("Load cell %d: %v", i, err)
		}
		defer rx.Close()
		if rx.cfg.NonceBits != cells[i].nonceBits || rx.cfg.BarrierFill != cells[i].barrierFill {
			t.Fatalf("Load cell %d: cfg = %d/%d", i, rx.cfg.NonceBits, rx.cfg.BarrierFill)
		}
		roundTripMessage(t, txs[i], rx)
		roundTripMessage(t, rx, txs[i])
	}
	// Wires from a 128-bit Pipeline are shorter than from a 512-bit one
	// for the same plaintext (two nonces of 16 vs 64 bytes each).
	w128, err := txs[0].EncryptMessage([]byte("nonce width probe"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	w512, err := txs[2].EncryptMessage([]byte("nonce width probe"))
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	if len(w512)-len(w128) < 2*(64-16) {
		t.Fatalf("wire lengths %d (128) vs %d (512) do not reflect the nonce width", len(w128), len(w512))
	}
}

// TestBlobSizeGuard pins the compact wire size of the default profile
// blob so an accidental base64 wrapping or duplicated field shows up.
func TestBlobSizeGuard(t *testing.T) {
	_, blob, err := Init(ProfileSingleMsgTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	if len(blob) >= 5000 {
		t.Fatalf("blob is %d bytes, want < 5000", len(blob))
	}
	if !strings.HasPrefix(string(blob), `{"v":2,"p":{`) {
		t.Fatalf("blob does not start with the v2 wrap-layer: %.40s", blob)
	}
	m := wrapFields(t, blob)
	for _, key := range []string{"v", "p", "ib", "pm", "wm"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("blob lacks key %q", key)
		}
	}
	if len(m) != 5 {
		t.Fatalf("blob carries %d keys, want 5", len(m))
	}
	// A disabled layer drops its master and inert record fields.
	off := false
	_, blob2, err := Init(ProfileSingleMsgTripleMACV1, Opts{WithParallax: &off, WithWrapper: &off})
	if err != nil {
		t.Fatalf("Init both off: %v", err)
	}
	m2 := wrapFields(t, blob2)
	if _, ok := m2["pm"]; ok {
		t.Fatalf("parallax-off blob carries pm")
	}
	if _, ok := m2["wm"]; ok {
		t.Fatalf("wrapper-off blob carries wm")
	}
	prof, err := Inspect(blob2)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if prof.OuterCipher != "" || prof.ParallaxPalette != nil || prof.ParallaxSegmentSize != 0 {
		t.Fatalf("inert fields not cleared: %+v", prof)
	}
}

// TestLoadAppliesTagStubFromRecord pins the No MAC stub reservation
// on the reopen path: a record with an explicit tagstub lands in the
// receiver's Config, and a MAC-carrying record without one is
// auto-populated from the MAC's tag length.
func TestLoadAppliesTagStubFromRecord(t *testing.T) {
	tx, blob, err := Init(ProfileSingleMsgTripleNoMACV1, Opts{TagStubSize: 48})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer tx.Close()
	rx, err := Load(blob)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer rx.Close()
	if rx.cfg.TagStubSize != 48 {
		t.Fatalf("TagStubSize = %d, want 48", rx.cfg.TagStubSize)
	}
	roundTripMessage(t, tx, rx)

	txM, blobM, err := Init(ProfileSingleMsgTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer txM.Close()
	rxM, err := Load(blobM)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer rxM.Close()
	if rxM.cfg.TagStubSize != txM.cfg.TagStubSize || rxM.cfg.TagStubSize == 0 {
		t.Fatalf("TagStubSize tx %d rx %d", txM.cfg.TagStubSize, rxM.cfg.TagStubSize)
	}
}
