package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/everanium/itb/hashes"
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
	opts := genblobOpts{keyBits: 512, nonceBits: 128, barrierFill: 1}

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
	opts := genblobOpts{keyBits: 1024, nonceBits: 512, barrierFill: 1, wrapper: "blake3", output: src}
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

// TestVerifyRejectsEarlierSchema confirms a version-1 wrap-layer is
// reported as a structural (exit 2) failure by verify.
func TestVerifyRejectsEarlierSchema(t *testing.T) {
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
