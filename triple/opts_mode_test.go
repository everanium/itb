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
// Opts.Mode outside {0, 1, 2} at Init.
func TestInitOptsModeRejectsOutOfRange(t *testing.T) {
	for _, m := range []int{-1, 3, 4, 1 << 20} {
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
	l0, l1, l2 := wireLen(0), wireLen(1), wireLen(2)
	if l0 != l1 {
		t.Fatalf("Mode 0 wire length %d differs from Mode 1 %d; Mode 0 must select Mode 1", l0, l1)
	}
	if l2 >= l1 {
		t.Fatalf("Mode 2 wire length %d not below Mode 1 %d for a short message", l2, l1)
	}
}

// TestInitOptsModeSurvivesRekey checks that a re-exported blob keeps
// the mode chosen at Init.
func TestInitOptsModeSurvivesRekey(t *testing.T) {
	pipe, _, err := Init(ProfileSingleMsgTripleMACV1, Opts{
		Mode:         2,
		WithParallax: boolPtr(false),
		WithWrapper:  boolPtr(true),
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer pipe.Close()
	wm := make([]byte, 32)
	if _, err := rand.Read(wm); err != nil {
		t.Fatal(err)
	}
	blob, err := pipe.Rekey(nil, wm)
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	rec, err := Inspect(blob)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if rec.ContainerMode != 2 {
		t.Fatalf("ContainerMode after Rekey = %d, want 2", rec.ContainerMode)
	}
	if pipe.cfg.Mode != 2 {
		t.Fatalf("cfg.Mode after Rekey = %d, want 2", pipe.cfg.Mode)
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
