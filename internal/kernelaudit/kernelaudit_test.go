package kernelaudit

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
	"testing"
)

// modelEval evaluates a strong keyed mixer per lane; the defect knobs
// reproduce the kernel failure classes the audit exists to catch.
type modelEval struct {
	dropDataTail bool // the lane bytes past the eighth are not absorbed
	dropWord     int  // this component word is not absorbed (-1: none)
	dropKeyByte  int  // this key byte is not absorbed (-1: none)
	dropBaseHigh bool // the group index base is absorbed at 32 bits
	leakLane     bool // lane 0 also absorbs lane 1's bytes
	stuckLane    int  // this lane returns a constant (-1: none)
}

func (m modelEval) eval(in *Inputs) [][2]uint64 {
	out := make([][2]uint64, len(in.Lanes))
	for l := range in.Lanes {
		h := sha256.New()
		key := in.Key
		if m.dropKeyByte >= 0 && m.dropKeyByte < len(key) {
			key = append(append([]byte{}, key[:m.dropKeyByte]...), key[m.dropKeyByte+1:]...)
		}
		h.Write(key)
		var w [8]byte
		for i, c := range in.Comps {
			if i == m.dropWord {
				continue
			}
			binary.LittleEndian.PutUint64(w[:], c)
			h.Write(w[:])
		}
		data := in.Lanes[l]
		if m.dropDataTail && len(data) > 8 {
			data = data[:8]
		}
		h.Write(data)
		if m.leakLane && l == 0 && len(in.Lanes) > 1 {
			h.Write(in.Lanes[1])
		}
		base := in.Base
		if len(data) == 0 {
			// A synthesising fill kernel: lane l is group base+l.
			base += uint64(l)
		}
		if m.dropBaseHigh {
			base &= 0xFFFFFFFF
		}
		binary.LittleEndian.PutUint64(w[:], base)
		h.Write(w[:])
		sum := h.Sum(nil)
		if l == m.stuckLane {
			sum = make([]byte, 32)
		}
		out[l] = [2]uint64{binary.LittleEndian.Uint64(sum), binary.LittleEndian.Uint64(sum[8:])}
	}
	return out
}

func sound() modelEval { return modelEval{dropWord: -1, dropKeyByte: -1, stuckLane: -1} }

var pixelCfg = Config{Label: "model-pixel", KeyBytes: 16, Words: 6, Lanes: 4, N: 36}
var fillCfg = Config{Label: "model-fill", KeyBytes: 16, Words: 6, Lanes: 8, Base: true}

// TestDifferentialAcceptsSoundModel pins the audit silent on a mixer that
// absorbs every input bit.
func TestDifferentialAcceptsSoundModel(t *testing.T) {
	for _, cfg := range []Config{pixelCfg, fillCfg} {
		if f := Differential(cfg, sound().eval); len(f) != 0 {
			t.Fatalf("%s: sound model flagged: %v", cfg.Label, f)
		}
	}
}

// TestDifferentialCatchesDefects pins one failure category per defect
// class.
func TestDifferentialCatchesDefects(t *testing.T) {
	cases := []struct {
		name     string
		cfg      Config
		model    modelEval
		category string
	}{
		{"data tail dropped", pixelCfg, func() modelEval { m := sound(); m.dropDataTail = true; return m }(), "data bit ignored"},
		{"component word dropped", pixelCfg, func() modelEval { m := sound(); m.dropWord = 5; return m }(), "component bit ignored"},
		{"key byte dropped", pixelCfg, func() modelEval { m := sound(); m.dropKeyByte = 15; return m }(), "key bit ignored"},
		{"base narrowed", fillCfg, func() modelEval { m := sound(); m.dropBaseHigh = true; return m }(), "base bit ignored"},
		{"lane leak", pixelCfg, func() modelEval { m := sound(); m.leakLane = true; return m }(), "lane isolation"},
		{"stuck lane", pixelCfg, func() modelEval { m := sound(); m.stuckLane = 2; return m }(), "data bit ignored"},
	}
	for _, tc := range cases {
		f := Differential(tc.cfg, tc.model.eval)
		if len(f) == 0 {
			t.Fatalf("%s: defect not flagged", tc.name)
		}
		if !strings.Contains(strings.Join(f, "\n"), tc.category) {
			t.Fatalf("%s: category %q missing from %v", tc.name, tc.category, f)
		}
	}
}

// TestDifferentialLaneChecks pins the rotation and base-shift checks: a
// model that keys the mixer on the lane position rather than the lane
// content fails them.
func TestDifferentialLaneChecks(t *testing.T) {
	positional := func(in *Inputs) [][2]uint64 {
		out := sound().eval(in)
		for l := range out {
			out[l][0] ^= uint64(l) * 0x9E3779B97F4A7C15
		}
		return out
	}
	joined := strings.Join(Differential(pixelCfg, positional), "\n")
	if !strings.Contains(joined, "lane rotation") {
		t.Fatalf("positional pixel model not flagged by the rotation check: %s", joined)
	}
	joined = strings.Join(Differential(fillCfg, positional), "\n")
	if !strings.Contains(joined, "base shift") {
		t.Fatalf("positional fill model not flagged by the base-shift check: %s", joined)
	}
}

// TestDifferentialRef pins the reference check: a sound kernel against
// itself is silent, and a kernel that diverges from the reference on
// one input bit is reported as a reference divergence while the
// structural checks stay silent.
func TestDifferentialRef(t *testing.T) {
	if f := DifferentialRef(pixelCfg, sound().eval, sound().eval); len(f) != 0 {
		t.Fatalf("sound kernel against itself flagged: %v", f)
	}
	// A kernel that absorbs one extra bit the reference ignores: both
	// absorb every input bit, so no structural check fires, but they
	// disagree whenever that bit is set.
	kernel := func(in *Inputs) [][2]uint64 {
		out := sound().eval(in)
		for l := range out {
			if in.Lanes[l][5]&0x10 != 0 {
				out[l][1] ^= 1
			}
		}
		return out
	}
	f := DifferentialRef(pixelCfg, kernel, sound().eval)
	joined := strings.Join(f, "\n")
	if !strings.Contains(joined, "reference divergence") {
		t.Fatalf("divergent kernel not flagged: %s", joined)
	}
	for _, category := range []string{"data bit ignored", "lane isolation", "component bit ignored", "key bit ignored", "lane rotation"} {
		if strings.Contains(joined, category) {
			t.Fatalf("structural check %q fired on a divergent but complete kernel: %s", category, joined)
		}
	}
}
