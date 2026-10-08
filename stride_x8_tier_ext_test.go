//go:build amd64 && !purego && !noitbasm

package itb_test

// Eight-pixel stride of the pixel pipeline over the shipped registry
// entries on the x86 fused tiers. Every entry carries the eight-lane
// hook whenever a SIMD fused tier is selected — the AVX-512 tier, and
// the AVX2-class tiers reached on an AVX-512 host through
// ITB_FORCE_HASH_TIER — so a constellation of any entries takes the
// stride on every (noise, data) pair, the mixed constellations
// included. The stride changes the evaluation order of the per-pixel
// cascade and nothing else: the wire of a hooked constellation decrypts
// through its hook-free (four-pixel stride) and sequential twins and
// vice versa. The forcing variables are read at init, so the tier
// matrix re-executes the test binary once per environment state and
// exchanges wires between the states.

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	aes "github.com/jedisct1/go-aes"
	"golang.org/x/sys/cpu"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/internal/forcetier"
)

const (
	strideX8ChildEnv = "ITB_STRIDE_X8_CHILD"
	strideX8ModeEnv  = "ITB_STRIDE_X8_MODE"
	strideX8DirEnv   = "ITB_STRIDE_X8_WIRE_DIR"
	strideX8Plain    = 4096
)

// strideX8Expected reports whether the process state must carry the
// eight-lane hook on every registry entry: a host with AVX2 (every AVX2
// host of the registry's AES families carries AES-NI), the fused tier
// not forced to the GPR or scalar arm, and neither disarm knob set. A
// tier token a family does not implement keeps that family on its
// auto-selected SIMD tier, so the condition holds under every token
// but gpr and scalar.
func strideX8Expected() bool {
	if !cpu.X86.HasAVX2 || forcetier.ChainHashSeq() || forcetier.ChainHashX4() {
		return false
	}
	switch forcetier.HashTier() {
	case "gpr", "scalar":
		return false
	}
	return true
}

// strideX8EntryExpected reports whether the process state must carry
// the eight-lane hook on the named entry: strideX8Expected, except that
// ITB_FORCE_HASH_TIER=avx2 is the arms-only probe of the Areion
// families on VAES + AVX2 silicon — their fused cascade is off under
// that token, so no fused hook of any lane count attaches.
func strideX8EntryExpected(name string) bool {
	if !strideX8Expected() {
		return false
	}
	if strings.HasPrefix(name, "areion") && forcetier.HashTier() == "avx2" && aes.CPU.HasVAES && aes.CPU.HasAVX2 {
		return false
	}
	return true
}

func strideX8Skip(t *testing.T) {
	t.Helper()
	if !strideX8Expected() {
		t.Skip("no eight-lane arm on this host or under this environment")
	}
}

// strideX8Names lists the registry entries of a width in registry order.
func strideX8Names(w hashes.Width) []string {
	var names []string
	for _, spec := range hashes.Registry {
		if spec.Width == w {
			names = append(names, spec.Name)
		}
	}
	return names
}

// TestStrideX8EveryRegistryEntry asserts that, wherever the stride is
// expected, a name-keyed seed of every registry entry carries the
// four-lane batch arm and the eight-lane hook at every width (the
// Areion entries excepted under their arms-only probe token).
func TestStrideX8EveryRegistryEntry(t *testing.T) {
	strideX8Skip(t)
	for _, spec := range hashes.Registry {
		t.Run(spec.Name, func(t *testing.T) {
			switch spec.Width {
			case hashes.W128:
				s, _, err := hashes.NewSeed128(spec.Name, 512)
				if err != nil {
					t.Fatal(err)
				}
				if s.BatchHash == nil || (s.BatchFusedChain8() != nil) != strideX8EntryExpected(spec.Name) {
					t.Fatalf("batch arm %v, eight-lane hook %v, want hook %v", s.BatchHash != nil, s.BatchFusedChain8() != nil, strideX8EntryExpected(spec.Name))
				}
			case hashes.W256:
				s, _, err := hashes.NewSeed256(spec.Name, 1024)
				if err != nil {
					t.Fatal(err)
				}
				if s.BatchHash == nil || (s.BatchFusedChain8() != nil) != strideX8EntryExpected(spec.Name) {
					t.Fatalf("batch arm %v, eight-lane hook %v, want hook %v", s.BatchHash != nil, s.BatchFusedChain8() != nil, strideX8EntryExpected(spec.Name))
				}
			case hashes.W512:
				s, _, err := hashes.NewSeed512(spec.Name, 2048)
				if err != nil {
					t.Fatal(err)
				}
				if s.BatchHash == nil || (s.BatchFusedChain8() != nil) != strideX8EntryExpected(spec.Name) {
					t.Fatalf("batch arm %v, eight-lane hook %v, want hook %v", s.BatchHash != nil, s.BatchFusedChain8() != nil, strideX8EntryExpected(spec.Name))
				}
			}
		})
	}
}

// strideX8Fill fills b with a fixed pseudo-random sequence (a 64-bit
// LCG over the seed), so every process of the tier matrix derives the
// same seeds and plaintexts.
func strideX8Fill(b []byte, seed uint64) {
	x := seed
	for i := range b {
		x = x*6364136223846793005 + 1442695040888963407
		b[i] = byte(x >> 56)
	}
}

// strideX8Comps returns n fixed component words of a seed slot.
func strideX8Comps(n int, slot, width int) []uint64 {
	buf := make([]byte, 8*n)
	strideX8Fill(buf, uint64(0x5151<<32)|uint64(width)<<8|uint64(slot))
	comps := make([]uint64, n)
	for i := range comps {
		comps[i] = binary.LittleEndian.Uint64(buf[8*i:])
	}
	return comps
}

// strideX8Key returns the fixed key of a slot at the length the entry's
// arms take (the length a name-keyed construction draws).
func strideX8Key(t *testing.T, name string, width hashes.Width, slot int) []byte {
	t.Helper()
	var n int
	var err error
	switch width {
	case hashes.W128:
		var k []byte
		_, k, err = hashes.NewSeed128(name, 512)
		n = len(k)
	case hashes.W256:
		var k []byte
		_, k, err = hashes.NewSeed256(name, 1024)
		n = len(k)
	case hashes.W512:
		var k []byte
		_, k, err = hashes.NewSeed512(name, 2048)
		n = len(k)
	}
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, n)
	strideX8Fill(key, uint64(0x4b45<<32)|uint64(width)<<8|uint64(slot))
	return key
}

// strideX8Slots assigns the registry entries of a width to the eight
// seed slots of constellation i: entry i in the noise slot, the entries
// after it (cyclically) in the lock, data and start slots, so every
// entry serves as the noise seed of one constellation and as a data
// seed of the others.
func strideX8Slots(names []string, i int) [8]string {
	var slots [8]string
	for k := range slots {
		slots[k] = names[(i+k)%len(names)]
	}
	return slots
}

// strideX8Variant selects the evaluation path of a constellation's
// seeds: the eight-lane hook (the eight-pixel stride), the fused
// four-lane arms alone (the four-pixel stride), or the sequential
// cascade.
type strideX8Variant int

const (
	strideX8Hooked strideX8Variant = iota
	strideX8FourLane
	strideX8Sequential
)

var strideX8VariantNames = map[strideX8Variant]string{strideX8Hooked: "x8", strideX8FourLane: "x4", strideX8Sequential: "seq"}

// strideX8Seeds128 builds the fixed width-128 seeds of constellation i
// in the given variant; calls counts the eight-lane hook invocations of
// every slot.
func strideX8Seeds128(t *testing.T, names [8]string, v strideX8Variant, calls *[8]atomic.Int64) [8]*itb.Seed128 {
	t.Helper()
	var out [8]*itb.Seed128
	for slot, name := range names {
		s, err := hashes.SeedFromComponents128(name, strideX8Key(t, name, hashes.W128, slot), strideX8Comps(8, slot, 128)...)
		if err != nil {
			t.Fatal(err)
		}
		switch v {
		case strideX8Hooked:
			if hook := s.BatchFusedChain8(); hook != nil {
				slot := slot
				s.SetBatchFusedChain8(func(c []uint64, data *[8][]byte) ([8][2]uint64, bool) {
					calls[slot].Add(1)
					return hook(c, data)
				})
			}
		case strideX8FourLane:
			s.SetBatchFusedChain8(nil)
		case strideX8Sequential:
			s.SetBatchFusedChain8(nil)
			s.FusedChain, s.BatchFusedChain = nil, nil
		}
		out[slot] = s
	}
	return out
}

func strideX8Seeds256(t *testing.T, names [8]string, v strideX8Variant, calls *[8]atomic.Int64) [8]*itb.Seed256 {
	t.Helper()
	var out [8]*itb.Seed256
	for slot, name := range names {
		s, err := hashes.SeedFromComponents256(name, strideX8Key(t, name, hashes.W256, slot), strideX8Comps(16, slot, 256)...)
		if err != nil {
			t.Fatal(err)
		}
		switch v {
		case strideX8Hooked:
			if hook := s.BatchFusedChain8(); hook != nil {
				slot := slot
				s.SetBatchFusedChain8(func(c []uint64, data *[8][]byte) ([8][4]uint64, bool) {
					calls[slot].Add(1)
					return hook(c, data)
				})
			}
		case strideX8FourLane:
			s.SetBatchFusedChain8(nil)
		case strideX8Sequential:
			s.SetBatchFusedChain8(nil)
			s.FusedChain, s.BatchFusedChain = nil, nil
		}
		out[slot] = s
	}
	return out
}

func strideX8Seeds512(t *testing.T, names [8]string, v strideX8Variant, calls *[8]atomic.Int64) [8]*itb.Seed512 {
	t.Helper()
	var out [8]*itb.Seed512
	for slot, name := range names {
		s, err := hashes.SeedFromComponents512(name, strideX8Key(t, name, hashes.W512, slot), strideX8Comps(32, slot, 512)...)
		if err != nil {
			t.Fatal(err)
		}
		switch v {
		case strideX8Hooked:
			if hook := s.BatchFusedChain8(); hook != nil {
				slot := slot
				s.SetBatchFusedChain8(func(c []uint64, data *[8][]byte) ([8][8]uint64, bool) {
					calls[slot].Add(1)
					return hook(c, data)
				})
			}
		case strideX8FourLane:
			s.SetBatchFusedChain8(nil)
		case strideX8Sequential:
			s.SetBatchFusedChain8(nil)
			s.FusedChain, s.BatchFusedChain = nil, nil
		}
		out[slot] = s
	}
	return out
}

// strideX8Codec is one width's encrypt / decrypt pair over a
// constellation in a variant.
type strideX8Codec struct {
	encrypt func(t *testing.T, cfg *itb.Config, names [8]string, v strideX8Variant, calls *[8]atomic.Int64, plain []byte) []byte
	decrypt func(t *testing.T, cfg *itb.Config, names [8]string, v strideX8Variant, wire []byte) ([]byte, error)
}

func strideX8Codecs() map[hashes.Width]strideX8Codec {
	return map[hashes.Width]strideX8Codec{
		hashes.W128: {
			encrypt: func(t *testing.T, cfg *itb.Config, names [8]string, v strideX8Variant, calls *[8]atomic.Int64, plain []byte) []byte {
				s := strideX8Seeds128(t, names, v, calls)
				wire, err := itb.Encrypt3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], plain)
				if err != nil {
					t.Fatal(err)
				}
				return wire
			},
			decrypt: func(t *testing.T, cfg *itb.Config, names [8]string, v strideX8Variant, wire []byte) ([]byte, error) {
				var calls [8]atomic.Int64
				s := strideX8Seeds128(t, names, v, &calls)
				return itb.Decrypt3x128Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], wire)
			},
		},
		hashes.W256: {
			encrypt: func(t *testing.T, cfg *itb.Config, names [8]string, v strideX8Variant, calls *[8]atomic.Int64, plain []byte) []byte {
				s := strideX8Seeds256(t, names, v, calls)
				wire, err := itb.Encrypt3x256Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], plain)
				if err != nil {
					t.Fatal(err)
				}
				return wire
			},
			decrypt: func(t *testing.T, cfg *itb.Config, names [8]string, v strideX8Variant, wire []byte) ([]byte, error) {
				var calls [8]atomic.Int64
				s := strideX8Seeds256(t, names, v, &calls)
				return itb.Decrypt3x256Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], wire)
			},
		},
		hashes.W512: {
			encrypt: func(t *testing.T, cfg *itb.Config, names [8]string, v strideX8Variant, calls *[8]atomic.Int64, plain []byte) []byte {
				s := strideX8Seeds512(t, names, v, calls)
				wire, err := itb.Encrypt3x512Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], plain)
				if err != nil {
					t.Fatal(err)
				}
				return wire
			},
			decrypt: func(t *testing.T, cfg *itb.Config, names [8]string, v strideX8Variant, wire []byte) ([]byte, error) {
				var calls [8]atomic.Int64
				s := strideX8Seeds512(t, names, v, &calls)
				return itb.Decrypt3x512Cfg(cfg, s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7], wire)
			},
		},
	}
}

var strideX8Widths = []hashes.Width{hashes.W128, hashes.W256, hashes.W512}

// TestStrideX8MixedConstellations builds, at every width, one
// constellation per registry entry in the noise slot with the other
// entries of the width in the data slots, and asserts: every seed's
// eight-lane hook is consulted by an encrypt (the stride engages on
// every (noise, data) pair), and the wire decrypts through the
// four-pixel-stride and sequential twins of the constellation while
// their wires decrypt through the hooked one.
func TestStrideX8MixedConstellations(t *testing.T) {
	strideX8Skip(t)
	codecs := strideX8Codecs()
	for _, w := range strideX8Widths {
		names := strideX8Names(w)
		for i := range names {
			slots := strideX8Slots(names, i)
			t.Run(fmt.Sprintf("w%d/noise=%s", w, slots[0]), func(t *testing.T) {
				for _, nb := range []int{128, 256, 512} {
					cfg := &itb.Config{NonceBits: nb}
					plain := make([]byte, strideX8Plain)
					rand.Read(plain)
					var calls [8]atomic.Int64
					wire := codecs[w].encrypt(t, cfg, slots, strideX8Hooked, &calls, plain)
					// The stride engages per (noise, data) pair when both
					// seeds carry the hook, so the noise hook is consulted
					// whenever any data seed carries one and a data hook
					// whenever the noise seed does.
					var hooked [8]bool
					for slot := range slots {
						hooked[slot] = strideX8EntryExpected(slots[slot])
					}
					for _, slot := range []int{0, 2, 3, 4} {
						want := hooked[0] && hooked[slot]
						if slot == 0 {
							want = hooked[0] && (hooked[2] || hooked[3] || hooked[4])
						}
						if (calls[slot].Load() > 0) != want {
							t.Fatalf("nb=%d: slot %d (%s) eight-lane hook consulted %d times, want consulted %v", nb, slot, slots[slot], calls[slot].Load(), want)
						}
					}
					t.Logf("nb=%d: eight-lane hook calls per slot noise=%d lock=%d data=%d/%d/%d start=%d/%d/%d (%d plaintext bytes, eight pixels per call)", nb,
						calls[0].Load(), calls[1].Load(), calls[2].Load(), calls[3].Load(), calls[4].Load(), calls[5].Load(), calls[6].Load(), calls[7].Load(), strideX8Plain)
					for _, v := range []strideX8Variant{strideX8FourLane, strideX8Sequential} {
						got, err := codecs[w].decrypt(t, cfg, slots, v, wire)
						if err != nil || !bytes.Equal(got, plain) {
							t.Fatalf("nb=%d: x8 wire through the %s twin: err=%v match=%v", nb, strideX8VariantNames[v], err, bytes.Equal(got, plain))
						}
						var twinCalls [8]atomic.Int64
						twin := codecs[w].encrypt(t, cfg, slots, v, &twinCalls, plain)
						got, err = codecs[w].decrypt(t, cfg, slots, strideX8Hooked, twin)
						if err != nil || !bytes.Equal(got, plain) {
							t.Fatalf("nb=%d: %s wire through the x8 constellation: err=%v match=%v", nb, strideX8VariantNames[v], err, bytes.Equal(got, plain))
						}
					}
				}
			})
		}
	}
}

// TestStrideX8WireExchangeChild is the child half of the tier matrix:
// in the encrypt mode it writes the wires of every constellation under
// the process's dispatch state into the wire directory, in the decrypt
// mode it decrypts every wire of every state's directory under its own
// state. A no-op unless the parent set the child marker.
func TestStrideX8WireExchangeChild(t *testing.T) {
	if os.Getenv(strideX8ChildEnv) == "" {
		t.Skip("child half of TestStrideX8TierMatrix")
	}
	dir := os.Getenv(strideX8DirEnv)
	codecs := strideX8Codecs()
	plain := make([]byte, strideX8Plain)
	strideX8Fill(plain, 0x504c41494e)
	cfg := &itb.Config{NonceBits: 256}
	for _, w := range strideX8Widths {
		names := strideX8Names(w)
		for i := range names {
			slots := strideX8Slots(names, i)
			file := fmt.Sprintf("w%d_%d.wire", w, i)
			switch os.Getenv(strideX8ModeEnv) {
			case "encrypt":
				var calls [8]atomic.Int64
				wire := codecs[w].encrypt(t, cfg, slots, strideX8Hooked, &calls, plain)
				if err := os.WriteFile(filepath.Join(dir, file), wire, 0o644); err != nil {
					t.Fatal(err)
				}
			case "decrypt":
				paths, err := filepath.Glob(filepath.Join(dir, "*", file))
				if err != nil || len(paths) == 0 {
					t.Fatalf("no wires %s under %s: %v", file, dir, err)
				}
				for _, path := range paths {
					wire, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					got, err := codecs[w].decrypt(t, cfg, slots, strideX8Hooked, wire)
					if err != nil || !bytes.Equal(got, plain) {
						t.Fatalf("%s (noise %s): err=%v match=%v", path, slots[0], err, bytes.Equal(got, plain))
					}
				}
			default:
				t.Fatalf("unknown mode %q", os.Getenv(strideX8ModeEnv))
			}
		}
	}
}

// strideX8State is one environment state of the tier matrix.
type strideX8State struct {
	name string
	env  map[string]string
}

func strideX8States() []strideX8State {
	states := []strideX8State{{"auto", nil}}
	for _, tier := range []string{"avx512", "vaesavx2", "avx2", "vex", "aesni"} {
		states = append(states,
			strideX8State{tier, map[string]string{"ITB_FORCE_HASH_TIER": tier}},
			strideX8State{tier + "+x4", map[string]string{"ITB_FORCE_HASH_TIER": tier, "ITB_FORCE_CHAINHASH_X4": "1"}},
			strideX8State{tier + "+seq", map[string]string{"ITB_FORCE_HASH_TIER": tier, "ITB_FORCE_CHAINHASH_SEQ": "1"}})
	}
	return states
}

// runStrideX8Child re-executes the test binary with the given variables
// set (every ITB_FORCE_* variable of the parent environment removed)
// and returns its verbose output.
func runStrideX8Child(t *testing.T, run string, vars map[string]string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run="+run, "-test.v")
	env := []string{strideX8ChildEnv + "=1"}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "ITB_FORCE_") || strings.HasPrefix(kv, strideX8ChildEnv+"=") || strings.HasPrefix(kv, strideX8ModeEnv+"=") || strings.HasPrefix(kv, strideX8DirEnv+"=") {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range vars {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child %v: %v\n%s", vars, err, out)
	}
	return string(out)
}

// TestStrideX8TierMatrix is the parent half: under every environment
// state the host can take, the registry and constellation tests must
// run (not skip) wherever the state leaves an eight-lane arm, and the
// wires written under every state decrypt under every state — the
// eight-pixel stride of any tier, the four-pixel stride and the
// sequential cascade produce one wire format.
func TestStrideX8TierMatrix(t *testing.T) {
	if os.Getenv(strideX8ChildEnv) != "" {
		t.Skip("running as a matrix child")
	}
	if testing.Short() {
		t.Skip("spawns one process per matrix cell")
	}
	if !cpu.X86.HasAVX2 {
		t.Skip("requires AVX2")
	}
	states := strideX8States()
	root := t.TempDir()
	for _, st := range states {
		t.Run("engage/"+st.name, func(t *testing.T) {
			out := runStrideX8Child(t, "^(TestStrideX8EveryRegistryEntry|TestStrideX8MixedConstellations)$", st.env)
			_, x4 := st.env["ITB_FORCE_CHAINHASH_X4"]
			_, seq := st.env["ITB_FORCE_CHAINHASH_SEQ"]
			if skipped := strings.Contains(out, "--- SKIP: TestStrideX8EveryRegistryEntry") || strings.Contains(out, "--- SKIP: TestStrideX8MixedConstellations"); skipped != (x4 || seq) {
				t.Fatalf("state %s: skipped=%v, want %v\n%s", st.name, skipped, x4 || seq, out)
			}
		})
	}
	for _, st := range states {
		dir := filepath.Join(root, st.name)
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		env := map[string]string{strideX8ModeEnv: "encrypt", strideX8DirEnv: dir}
		for k, v := range st.env {
			env[k] = v
		}
		runStrideX8Child(t, "^TestStrideX8WireExchangeChild$", env)
	}
	for _, st := range states {
		t.Run("exchange/"+st.name, func(t *testing.T) {
			env := map[string]string{strideX8ModeEnv: "decrypt", strideX8DirEnv: root}
			for k, v := range st.env {
				env[k] = v
			}
			runStrideX8Child(t, "^TestStrideX8WireExchangeChild$", env)
		})
	}
}
