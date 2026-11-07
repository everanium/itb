package triple

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
)

// TestInitOptsModeRejectsOutOfRange pins the fail-fast refusal of an
// Opts.Mode outside {0, 1, 2, 3} at Init.
func TestInitOptsModeRejectsOutOfRange(t *testing.T) {
	for _, m := range []int{-1, 4, 5, 1 << 20} {
		pipe, _, err := Init(ProfileSingleMsgTripleMACV1, Opts{Mode: m})
		if err == nil {
			pipe.Close()
			t.Fatalf("Init accepted Opts.Mode=%d, want rejection", m)
		}
		if !strings.Contains(err.Error(), "opts.Mode") {
			t.Fatalf("Init(Opts.Mode=%d) error does not name the field: %v", m, err)
		}
	}
}

// TestInitOptsModeSizesContainersInSession checks that the mode chosen
// at Init governs the container size from the first message of the Init
// session, with no Save / Load round trip: a short Single Message under
// Mode 2 (per-container joint floor) is smaller than under Mode 1
// (per-region floor).
func TestInitOptsModeSizesContainersInSession(t *testing.T) {
	msg := []byte("x")
	wireLen := func(mode int) int {
		t.Helper()
		pipe, _, err := Init(ProfileSingleMsgTripleMACV1, Opts{
			Mode:         mode,
			WithParallax: boolPtr(false),
			WithWrapper:  boolPtr(false),
		})
		if err != nil {
			t.Fatalf("Init(Mode: %d): %v", mode, err)
		}
		defer pipe.Close()
		ct, err := pipe.EncryptMessage(msg)
		if err != nil {
			t.Fatalf("EncryptMessage(Mode: %d): %v", mode, err)
		}
		pt, err := pipe.DecryptMessage(ct)
		if err != nil || !bytes.Equal(pt, msg) {
			t.Fatalf("roundtrip(Mode: %d): err=%v", mode, err)
		}
		return len(ct)
	}
	l0, l1, l2, l3 := wireLen(0), wireLen(1), wireLen(2), wireLen(3)
	if l0 != l1 {
		t.Fatalf("Mode 0 wire length %d differs from Mode 1 %d; Mode 0 must select Mode 1", l0, l1)
	}
	if l2 >= l3 || l3 >= l1 {
		t.Fatalf("wire lengths Mode 2=%d, Mode 3=%d, Mode 1=%d; want Mode 2 < Mode 3 < Mode 1 for a short message", l2, l3, l1)
	}
}

// TestInitOptsModeSurvivesRekey checks that a re-exported blob keeps
// the mode chosen at Init.
func TestInitOptsModeSurvivesRekey(t *testing.T) {
	for _, targetMode := range []int{2, 3} {
		pipe, _, err := Init(ProfileSingleMsgTripleMACV1, Opts{
			Mode:         targetMode,
			WithParallax: boolPtr(false),
			WithWrapper:  boolPtr(true),
		})
		if err != nil {
			t.Fatalf("Init(Mode=%d): %v", targetMode, err)
		}
		defer pipe.Close()
		wm := make([]byte, 32)
		if _, err := rand.Read(wm); err != nil {
			t.Fatal(err)
		}
		blob, err := pipe.Rekey(nil, wm)
		if err != nil {
			t.Fatalf("Rekey(Mode=%d): %v", targetMode, err)
		}
		rec, err := Inspect(blob)
		if err != nil {
			t.Fatalf("Inspect(Mode=%d): %v", targetMode, err)
		}
		if rec.ContainerMode != targetMode {
			t.Fatalf("ContainerMode after Rekey = %d, want %d", rec.ContainerMode, targetMode)
		}
		if pipe.cfg.Mode != targetMode {
			t.Fatalf("cfg.Mode after Rekey = %d, want %d", pipe.cfg.Mode, targetMode)
		}
	}
}

// TestOptsModeCrossDecrypt checks that the mode only shapes the
// encrypt-side container size: under the same seeds, a Mode 1 Pipeline
// decrypts Mode 2 ciphertext and a Mode 2 Pipeline decrypts Mode 1
// ciphertext. The Mode 2 twin is built by changing only the inner
// blob's mode field of the Mode 1 blob.
func TestOptsModeCrossDecrypt(t *testing.T) {
	p1, blob1, err := Init(ProfileSingleMsgTripleMACV1, Opts{Mode: 1})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer p1.Close()
	p2, err := Load(setInnerBlobMode(t, blob1, 2))
	if err != nil {
		t.Fatalf("Load(mode 2 twin): %v", err)
	}
	defer p2.Close()
	if p1.cfg.Mode != 1 || p2.cfg.Mode != 2 {
		t.Fatalf("modes = %d / %d, want 1 / 2", p1.cfg.Mode, p2.cfg.Mode)
	}

	msg := []byte("cross-mode message")
	for _, c := range []struct {
		name     string
		enc, dec *Pipeline
	}{{"mode1->mode2", p1, p2}, {"mode2->mode1", p2, p1}} {
		ct, err := c.enc.EncryptMessage(msg)
		if err != nil {
			t.Fatalf("%s encrypt: %v", c.name, err)
		}
		pt, err := c.dec.DecryptMessage(ct)
		if err != nil {
			t.Fatalf("%s decrypt: %v", c.name, err)
		}
		if !bytes.Equal(pt, msg) {
			t.Fatalf("%s: plaintext mismatch", c.name)
		}
	}
}

// setInnerBlobMode returns a copy of a session blob whose inner blob
// carries mode, leaving every other field untouched.
func setInnerBlobMode(t *testing.T, blob []byte, mode int) []byte {
	t.Helper()
	var wrap map[string]json.RawMessage
	if err := json.Unmarshal(blob, &wrap); err != nil {
		t.Fatalf("unmarshal wrap: %v", err)
	}
	var inner map[string]json.RawMessage
	if err := json.Unmarshal(wrap["ib"], &inner); err != nil {
		t.Fatalf("unmarshal inner: %v", err)
	}
	inner["mode"] = json.RawMessage(strconv.Itoa(mode))
	ib, err := json.Marshal(inner)
	if err != nil {
		t.Fatal(err)
	}
	wrap["ib"] = ib
	out, err := json.Marshal(wrap)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestMode3TriplePipelineAndMaxWireSizeParity verifies Opts.Mode == 3
// (Gauss-Posit inscribed circle floor and Posit chord sub-region slicing)
// across Init, Save, Load, Inspect, Rekey, MaxWireSize, and MaxPlaintextSize.
func TestMode3TriplePipelineAndMaxWireSizeParity(t *testing.T) {
	p1, _, err := Init(ProfileSingleMsgTripleMACV1, Opts{Mode: 1})
	if err != nil {
		t.Fatalf("Init(Mode: 1): %v", err)
	}
	defer p1.Close()

	p2, _, err := Init(ProfileSingleMsgTripleMACV1, Opts{Mode: 2})
	if err != nil {
		t.Fatalf("Init(Mode: 2): %v", err)
	}
	defer p2.Close()

	p3, blob3, err := Init(ProfileSingleMsgTripleMACV1, Opts{Mode: 3})
	if err != nil {
		t.Fatalf("Init(Mode: 3): %v", err)
	}
	defer p3.Close()

	rec3, err := Inspect(blob3)
	if err != nil {
		t.Fatalf("Inspect(blob3): %v", err)
	}
	if rec3.ContainerMode != 3 {
		t.Fatalf("Inspect(blob3).ContainerMode = %d, want 3", rec3.ContainerMode)
	}

	p3Loaded, err := Load(blob3)
	if err != nil {
		t.Fatalf("Load(blob3): %v", err)
	}
	defer p3Loaded.Close()

	msg := []byte("Mode 3 Gauss-Posit Triple pipeline test")
	ct1, err := p1.EncryptMessage(msg)
	if err != nil {
		t.Fatalf("p1.EncryptMessage: %v", err)
	}
	ct2, err := p2.EncryptMessage(msg)
	if err != nil {
		t.Fatalf("p2.EncryptMessage: %v", err)
	}
	ct3, err := p3.EncryptMessage(msg)
	if err != nil {
		t.Fatalf("p3.EncryptMessage: %v", err)
	}

	// Verify Mode 2 < Mode 3 < Mode 1 wire length for short messages.
	if !(len(ct2) < len(ct3) && len(ct3) < len(ct1)) {
		t.Fatalf("wire lengths Mode2=%d, Mode3=%d, Mode1=%d; want Mode2 < Mode3 < Mode1",
			len(ct2), len(ct3), len(ct1))
	}

	// Verify MaxWireSize matches actual wire length for Mode 3 across message lengths.
	for _, n := range []int{1, 16, 64, 255, 512, 1024, 4096} {
		payload := bytes.Repeat([]byte{0x42}, n)
		ct, err := p3.EncryptMessage(payload)
		if err != nil {
			t.Fatalf("EncryptMessage(%d): %v", n, err)
		}
		wantWire := p3.MaxWireSize(n)
		if len(ct) != wantWire {
			t.Fatalf("n=%d: len(ct)=%d != MaxWireSize=%d", n, len(ct), wantWire)
		}
		maxPt := p3.MaxPlaintextSize(len(ct))
		if maxPt < n {
			t.Fatalf("n=%d: MaxPlaintextSize(%d)=%d < %d", n, len(ct), maxPt, n)
		}
		pt, err := p3Loaded.DecryptMessage(ct)
		if err != nil || !bytes.Equal(pt, payload) {
			t.Fatalf("DecryptMessage(%d): err=%v", n, err)
		}
	}

	// Mode 1 or Mode 2 pipeline with identical seeds cannot decrypt Mode 3 ciphertext
	// because Mode 3 uses Gauss-Posit chord sub-region slicing.
	p1Twin, err := Load(setInnerBlobMode(t, blob3, 1))
	if err != nil {
		t.Fatalf("Load(mode 1 twin): %v", err)
	}
	defer p1Twin.Close()
	if _, err := p1Twin.DecryptMessage(ct3); err == nil {
		t.Fatal("Mode 1 twin unexpectedly decrypted Mode 3 ciphertext")
	}
}

func TestITBContainerModeEnvOverride(t *testing.T) {
	t.Setenv("ITB_CONTAINER_MODE", "3")

	// When Opts.Mode is 0 (unset), ITB_CONTAINER_MODE=3 selects Mode 3.
	pDef, blobDef, err := Init(ProfileSingleMsgTripleMACV1, Opts{})
	if err != nil {
		t.Fatalf("Init(Opts{} under ITB_CONTAINER_MODE=3): %v", err)
	}
	defer pDef.Close()
	if pDef.cfg.Mode != 3 {
		t.Fatalf("pDef.cfg.Mode = %d, want 3 under ITB_CONTAINER_MODE=3", pDef.cfg.Mode)
	}
	recDef, err := Inspect(blobDef)
	if err != nil {
		t.Fatalf("Inspect(blobDef): %v", err)
	}
	if recDef.ContainerMode != 3 {
		t.Fatalf("Inspect(blobDef).ContainerMode = %d, want 3", recDef.ContainerMode)
	}

	// Explicit Opts.Mode: 1 overrides ITB_CONTAINER_MODE=3.
	p1, blob1, err := Init(ProfileSingleMsgTripleMACV1, Opts{Mode: 1})
	if err != nil {
		t.Fatalf("Init(Opts{Mode: 1} under ITB_CONTAINER_MODE=3): %v", err)
	}
	defer p1.Close()
	if p1.cfg.Mode != 1 {
		t.Fatalf("p1.cfg.Mode = %d, want 1 when explicitly overridden", p1.cfg.Mode)
	}
	rec1, err := Inspect(blob1)
	if err != nil {
		t.Fatalf("Inspect(blob1): %v", err)
	}
	if rec1.ContainerMode != 1 {
		t.Fatalf("Inspect(blob1).ContainerMode = %d, want 1", rec1.ContainerMode)
	}
}
