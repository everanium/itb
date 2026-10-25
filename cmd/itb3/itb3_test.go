package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/drbg"
	"github.com/everanium/itb/triple"
)

// TestGenblobLoadRoundTrip drives the genblob handler in-process and
// reopens the written blob with triple.LoadF — the same path itb3
// encrypt / decrypt take — then checks a Single Message round trip
// and the Inspect record.
func TestGenblobLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.blob")
	opts := genblobOpts{
		keyBits:     1024,
		nonceBits:   512,
		barrierFill: 1,
		blobMode:    1,
		mac:         "hmac-blake3",
		palette:     []string{"aescmac", "chacha20", "siphash24"},
		segment:     257,
		wrapper:     "chacha20",
		output:      path,
	}
	set := genblobFlagsSet{mac: true, palette: true, segment: true, wrapper: true}
	if err := runGenblob("mac", "areion512", opts, set); err != nil {
		t.Fatalf("runGenblob: %v", err)
	}

	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	prof, err := triple.Inspect(blob)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if prof.Name != "itb3-mac-areion512" || prof.Mode != "singlemsg-mac" || prof.Width != 512 ||
		prof.InnerHash != "areion512" || prof.KeyBits != 1024 || prof.MacName != "hmac-blake3" ||
		!prof.Wrapper || prof.OuterCipher != "chacha20" || !prof.Parallax ||
		prof.ParallaxSegmentSize != 257 || len(prof.ParallaxPalette) != 3 {
		t.Fatalf("unexpected record: %+v", prof)
	}

	pipe, err := triple.LoadF(path)
	if err != nil {
		t.Fatalf("LoadF: %v", err)
	}
	defer pipe.Close()
	plain := []byte("itb3 in-process round trip")
	wire, err := pipe.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := pipe.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: got %q", got)
	}
}

// TestGenblobRegisterCollision registers the same <mode>/<hash> pair
// twice in one process. The CLI executes as a fresh process per
// invocation and is not expected to reuse a handle; a duplicate under
// in-process re-entry (this test, embedding) surfaces cleanly as
// triple.ErrProfileExists rather than being masked by a fallback.
func TestGenblobRegisterCollision(t *testing.T) {
	dir := t.TempDir()
	opts := genblobOpts{keyBits: 512, nonceBits: 512, barrierFill: 1, blobMode: 1}

	opts.output = filepath.Join(dir, "b0.blob")
	if err := runGenblob("nomac", "blake2s", opts, genblobFlagsSet{}); err != nil {
		t.Fatalf("first runGenblob: %v", err)
	}
	blob, err := os.ReadFile(opts.output)
	if err != nil {
		t.Fatal(err)
	}
	prof, err := triple.Inspect(blob)
	if err != nil {
		t.Fatal(err)
	}
	if prof.Name != "itb3-nomac-blake2s" {
		t.Fatalf("first: name %q, want itb3-nomac-blake2s", prof.Name)
	}

	opts.output = filepath.Join(dir, "b1.blob")
	err = runGenblob("nomac", "blake2s", opts, genblobFlagsSet{})
	if err == nil {
		t.Fatalf("second runGenblob: expected ErrProfileExists, got nil")
	}
	if !errors.Is(err, triple.ErrProfileExists) {
		t.Fatalf("second runGenblob: expected ErrProfileExists, got %v", err)
	}
}

// TestRekeyAssertions checks the strict-assertion matrix: the blob's
// recorded toggles win, and a mismatching -p / -w is a usage error.
func TestRekeyAssertions(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "wo.blob")
	opts := genblobOpts{keyBits: 1024, nonceBits: 512, barrierFill: 1, blobMode: 1, wrapper: "blake3", output: src}
	if err := runGenblob("noaead", "blake2b256", opts, genblobFlagsSet{wrapper: true}); err != nil {
		t.Fatalf("runGenblob: %v", err)
	}
	cases := []struct {
		name string
		o    rekeyOpts
		want int
	}{
		{"missing -w", rekeyOpts{}, exitUsage},
		{"stray -p", rekeyOpts{parallax: true, wrapper: true}, exitUsage},
		{"exact", rekeyOpts{wrapper: true}, exitOK},
	}
	for _, c := range cases {
		c.o.outputPath = filepath.Join(dir, c.name+".blob")
		err := runRekey(src, c.o)
		if c.want == exitOK {
			if err != nil {
				t.Fatalf("%s: unexpected error %v", c.name, err)
			}
			pipe, err := triple.LoadF(c.o.outputPath)
			if err != nil {
				t.Fatalf("%s: LoadF rekeyed blob: %v", c.name, err)
			}
			pipe.Close()
			continue
		}
		var ce *cliError
		if !errors.As(err, &ce) || ce.code != c.want {
			t.Fatalf("%s: got %v, want exit %d", c.name, err, c.want)
		}
	}
}

// TestRandomMixedConstellation checks every drawn slot is a shipped
// primitive of the requested width.
func TestRandomMixedConstellation(t *testing.T) {
	for _, w := range []hashes.Width{hashes.W128, hashes.W256, hashes.W512} {
		slots, err := randomMixedConstellation(w)
		if err != nil {
			t.Fatalf("width %d: %v", int(w), err)
		}
		for i, name := range slots {
			spec, ok := hashes.Find(name)
			if !ok || spec.Width != w {
				t.Fatalf("width %d slot %d: %q not a width-%d shipped primitive", int(w), i, name, int(w))
			}
		}
	}
}

// TestVerifyRejectsUnsupportedSchema confirms an unsupported (version-1)
// wrap-layer is reported as a structural (exit 2) failure by verify.
func TestVerifyRejectsUnsupportedSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v1.blob")
	if err := os.WriteFile(path, []byte(`{"v":1,"p":"singlemsg-triple-mac-v1","ib":"e30="}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := runVerify(path)
	var ce *cliError
	if !errors.As(err, &ce) || ce.code != exitRuntime {
		t.Fatalf("got %v, want exit %d", err, exitRuntime)
	}
}

// TestGenblobBlobMode2AndInspect verifies generating a blob with Mode 2
// (per-container floor), inspecting it with runInspect, and roundtripping
// encryption and decryption through the loaded pipeline.
func TestGenblobBlobMode2AndInspect(t *testing.T) {
	dir := t.TempDir()
	pathMode2 := filepath.Join(dir, "mode2.blob")
	opts2 := genblobOpts{
		keyBits:     512,
		nonceBits:   512,
		barrierFill: 1,
		blobMode:    2,
		output:      pathMode2,
	}
	if err := runGenblob("nomac", "blake3", opts2, genblobFlagsSet{}); err != nil {
		t.Fatalf("runGenblob mode=2: %v", err)
	}

	blob2, err := os.ReadFile(pathMode2)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	prof2, err := triple.Inspect(blob2)
	if err != nil {
		t.Fatalf("Inspect mode=2: %v", err)
	}
	if prof2.ContainerMode != 2 {
		t.Fatalf("prof2.ContainerMode = %d, want 2", prof2.ContainerMode)
	}

	var buf bytes.Buffer
	renderInspect(prof2, len(blob2), &buf)
	inspectText := buf.String()
	if !strings.Contains(inspectText, "container_mode: per-container (2)") {
		t.Fatalf("inspectText does not contain 'container_mode: per-container (2)':\n%s", inspectText)
	}

	pipe2, err := triple.LoadF(pathMode2)
	if err != nil {
		t.Fatalf("LoadF mode=2: %v", err)
	}
	defer pipe2.Close()

	plain := []byte("testing mode 2 network tunnel container sizing")
	ct, err := pipe2.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := pipe2.DecryptMessage(ct)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(plain, got) {
		t.Fatalf("payload mismatch: got %q, want %q", got, plain)
	}

	// Verify Mode 1 default inspect output
	pathMode1 := filepath.Join(dir, "mode1.blob")
	opts1 := genblobOpts{
		keyBits:     512,
		nonceBits:   512,
		barrierFill: 1,
		blobMode:    1,
		output:      pathMode1,
	}
	if err := runGenblob("nomac", "blake2b512", opts1, genblobFlagsSet{}); err != nil {
		t.Fatalf("runGenblob mode=1: %v", err)
	}
	blob1, err := os.ReadFile(pathMode1)
	if err != nil {
		t.Fatalf("ReadFile mode=1: %v", err)
	}
	prof1, err := triple.Inspect(blob1)
	if err != nil {
		t.Fatalf("Inspect mode=1: %v", err)
	}
	if prof1.ContainerMode != 1 {
		t.Fatalf("prof1.ContainerMode = %d, want 1", prof1.ContainerMode)
	}
	buf.Reset()
	renderInspect(prof1, len(blob1), &buf)
	if !strings.Contains(buf.String(), "container_mode: per-region (1)") {
		t.Fatalf("inspectText does not contain 'container_mode: per-region (1)':\n%s", buf.String())
	}
}

// TestGenblobRejectsBlobModeOutOfRange pins the --blob-mode gate: 0 and
// 3 are usage errors (exit 1) raised before any pipeline is built.
func TestGenblobRejectsBlobModeOutOfRange(t *testing.T) {
	for _, mode := range []int{0, 3} {
		opts := genblobOpts{keyBits: 512, nonceBits: 512, barrierFill: 1, blobMode: mode}
		err := runGenblob("nomac", "blake3", opts, genblobFlagsSet{})
		var ce *cliError
		if !errors.As(err, &ce) || ce.code != exitUsage {
			t.Fatalf("--blob-mode %d: got %v, want exit %d", mode, err, exitUsage)
		}
	}
}

// TestGenblobDRBGFlag pins the --drbg surface: the chosen fill
// primitive lands in the blob's recipe and on the inspect line, a
// blob without the key inspects as "(default)", every listed name
// encrypts and decrypts under the handle genblob registered, and an
// unknown name is a usage error raised before any pipeline is built.
// The <mode>/<hash> pairs are distinct from every other test's so the
// per-process handle registration does not collide.
func TestGenblobDRBGFlag(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csprng.blob")
	opts := genblobOpts{keyBits: 512, nonceBits: 512, barrierFill: 1, blobMode: 1, drbg: "csprng", output: path}
	if err := runGenblob("nomac", "siphash24", opts, genblobFlagsSet{}); err != nil {
		t.Fatalf("runGenblob --drbg csprng: %v", err)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	prof, err := triple.Inspect(blob)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if prof.DRBG != "csprng" {
		t.Fatalf("prof.DRBG = %q, want csprng", prof.DRBG)
	}
	var buf bytes.Buffer
	renderInspect(prof, len(blob), &buf)
	if !strings.Contains(buf.String(), "drbg: csprng\n") {
		t.Fatalf("inspect output lacks the drbg line:\n%s", buf.String())
	}
	pipe, err := triple.LoadF(path)
	if err != nil {
		t.Fatalf("LoadF: %v", err)
	}
	plain := []byte("itb3 --drbg round trip")
	wire, err := pipe.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := pipe.DecryptMessage(wire)
	pipe.Close()
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("DecryptMessage: %v", err)
	}

	// Default blob: no key in the recipe, "(default)" on the inspect line.
	defPath := filepath.Join(dir, "default.blob")
	defOpts := genblobOpts{keyBits: 512, nonceBits: 512, barrierFill: 1, blobMode: 1, output: defPath}
	if err := runGenblob("nomac", "chacha20", defOpts, genblobFlagsSet{}); err != nil {
		t.Fatalf("runGenblob default: %v", err)
	}
	defBlob, err := os.ReadFile(defPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(defBlob, []byte(`"drbg"`)) {
		t.Fatalf("default blob carries a drbg key")
	}
	defProf, err := triple.Inspect(defBlob)
	if err != nil {
		t.Fatalf("Inspect default: %v", err)
	}
	buf.Reset()
	renderInspect(defProf, len(defBlob), &buf)
	if !strings.Contains(buf.String(), "drbg: (auto: "+itb.DRBGAutoTier()+" on this host)\n") {
		t.Fatalf("default inspect output lacks the auto-tier drbg line:\n%s", buf.String())
	}

	// Every listed name encrypts and decrypts under the registered
	// handle — the same Opts path genblob takes for each --drbg value.
	names := drbg.Names()
	if len(names) < 2 || names[0] != "aesitb128" || names[len(names)-1] != "csprng" {
		t.Fatalf("drbg.Names() = %v", names)
	}
	for _, name := range names {
		p, _, ierr := triple.Init("itb3-nomac-siphash24", triple.Opts{NonceBits: 512, BarrierFill: 1, DRBG: name})
		if ierr != nil {
			t.Fatalf("Init(--drbg %s): %v", name, ierr)
		}
		if rec, _ := triple.Inspect(p.Save()); rec.DRBG != name {
			t.Fatalf("%s: recipe carries %q", name, rec.DRBG)
		}
		wire, eerr := p.EncryptMessage(plain)
		if eerr != nil {
			t.Fatalf("%s: EncryptMessage: %v", name, eerr)
		}
		got, derr := p.DecryptMessage(wire)
		p.Close()
		if derr != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%s: DecryptMessage: %v", name, derr)
		}
	}

	// Unknown name: usage error (exit 1) before Init — no handle is
	// registered, so the same pair is reusable below.
	bad := genblobOpts{keyBits: 512, nonceBits: 512, barrierFill: 1, blobMode: 1, drbg: "invalid"}
	err = runGenblob("nomac", "aescmac", bad, genblobFlagsSet{})
	var ce *cliError
	if !errors.As(err, &ce) || ce.code != exitUsage {
		t.Fatalf("--drbg invalid: got %v, want exit %d", err, exitUsage)
	}
	if _, lerr := triple.Lookup("itb3-nomac-aescmac"); lerr == nil {
		t.Fatal("usage error registered a handle")
	}
}

// TestGenblobInterlockFlag pins the --interlock surface: 168 on a
// 512-bit hash and on mixed512 lands in the blob recipe and on the
// inspect line and round-trips through LoadF, a default / 48-bit blob
// omits the recipe key and inspects as "interlock: 48 (default)", and
// an invalid value or a 128/256-bit hash under --interlock 168 is a
// usage error raised before any handle is registered.
func TestGenblobInterlockFlag(t *testing.T) {
	dir := t.TempDir()

	// 1. --interlock 168 with 512-bit hash (areion512).
	path168 := filepath.Join(dir, "il168.blob")
	opts168 := genblobOpts{
		keyBits:     1024,
		nonceBits:   512,
		barrierFill: 1,
		blobMode:    1,
		interlock:   "168",
		output:      path168,
	}
	if err := runGenblob("nomac", "areion512", opts168, genblobFlagsSet{}); err != nil {
		t.Fatalf("runGenblob --interlock 168 areion512: %v", err)
	}
	blob168, err := os.ReadFile(path168)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Contains(blob168, []byte(`"interlock":"168"`)) {
		t.Fatalf("168 blob lacks interlock key")
	}
	prof168, err := triple.Inspect(blob168)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if prof168.Interlock != "168" {
		t.Fatalf("prof168.Interlock = %q, want 168", prof168.Interlock)
	}
	var buf bytes.Buffer
	renderInspect(prof168, len(blob168), &buf)
	if !strings.Contains(buf.String(), "interlock: 168\n") {
		t.Fatalf("inspect output lacks interlock: 168:\n%s", buf.String())
	}
	pipe168, err := triple.LoadF(path168)
	if err != nil {
		t.Fatalf("LoadF: %v", err)
	}
	plain := []byte("itb3 --interlock 168 round trip payload across multiple 21-byte chunks")
	wire, err := pipe168.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := pipe168.DecryptMessage(wire)
	pipe168.Close()
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("DecryptMessage: %v", err)
	}

	// 2. --interlock 168 with mixed512.
	pathMix := filepath.Join(dir, "mix512-168.blob")
	optsMix := genblobOpts{
		keyBits:     1024,
		nonceBits:   512,
		barrierFill: 1,
		blobMode:    1,
		interlock:   "168",
		output:      pathMix,
	}
	if err := runGenblob("nomac", "mixed512", optsMix, genblobFlagsSet{}); err != nil {
		t.Fatalf("runGenblob --interlock 168 mixed512: %v", err)
	}
	blobMix, err := os.ReadFile(pathMix)
	if err != nil {
		t.Fatalf("ReadFile mixed512: %v", err)
	}
	profMix, err := triple.Inspect(blobMix)
	if err != nil {
		t.Fatalf("Inspect mixed512: %v", err)
	}
	if profMix.Interlock != "168" {
		t.Fatalf("profMix.Interlock = %q, want 168", profMix.Interlock)
	}
	pipeMix, err := triple.LoadF(pathMix)
	if err != nil {
		t.Fatalf("LoadF mixed512: %v", err)
	}
	wireMix, err := pipeMix.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("EncryptMessage mixed512: %v", err)
	}
	gotMix, err := pipeMix.DecryptMessage(wireMix)
	pipeMix.Close()
	if err != nil || !bytes.Equal(gotMix, plain) {
		t.Fatalf("DecryptMessage mixed512: %v", err)
	}

	// 3. Explicit --interlock 48 normalises to default (no key in recipe, "48 (default)" on inspect).
	path48 := filepath.Join(dir, "il48.blob")
	opts48 := genblobOpts{
		keyBits:     1024,
		nonceBits:   512,
		barrierFill: 1,
		blobMode:    1,
		interlock:   "48",
		output:      path48,
	}
	if err := runGenblob("noaead", "blake2b512", opts48, genblobFlagsSet{}); err != nil {
		t.Fatalf("runGenblob --interlock 48: %v", err)
	}
	blob48, err := os.ReadFile(path48)
	if err != nil {
		t.Fatalf("ReadFile 48: %v", err)
	}
	if bytes.Contains(blob48, []byte(`"interlock"`)) {
		t.Fatalf("48 blob carries an interlock key")
	}
	prof48, err := triple.Inspect(blob48)
	if err != nil {
		t.Fatalf("Inspect 48: %v", err)
	}
	if prof48.Interlock != "" {
		t.Fatalf("prof48.Interlock = %q, want empty", prof48.Interlock)
	}
	buf.Reset()
	renderInspect(prof48, len(blob48), &buf)
	if !strings.Contains(buf.String(), "interlock: 48 (default)\n") {
		t.Fatalf("default inspect output lacks interlock: 48 (default):\n%s", buf.String())
	}

	// 4. Rejections: invalid value and non-512-bit hashes fail with exitUsage before registration.
	rejectCases := []struct {
		label string
		hash  string
		il    string
	}{
		{"invalid value", "areion512", "96"},
		{"width 128", "aesitb128", "168"},
		{"width 256", "areion256", "168"},
		{"mixed256", "mixed256", "168"},
	}
	for _, rc := range rejectCases {
		badOpts := genblobOpts{keyBits: 512, nonceBits: 512, barrierFill: 1, blobMode: 1, interlock: rc.il}
		rerr := runGenblob("noaead", rc.hash, badOpts, genblobFlagsSet{})
		var ce *cliError
		if !errors.As(rerr, &ce) || ce.code != exitUsage {
			t.Fatalf("%s: got %v, want exit %d", rc.label, rerr, exitUsage)
		}
		if _, lerr := triple.Lookup("itb3-noaead-" + rc.hash); lerr == nil {
			t.Fatalf("%s: usage error registered handle itb3-noaead-%s", rc.label, rc.hash)
		}
	}
}
