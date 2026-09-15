//go:build amd64 && !purego && !noitbasm

package hashes

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"

	aes "github.com/jedisct1/go-aes"
	"golang.org/x/sys/cpu"

	"github.com/everanium/itb/hashes/internal/aescmacasm"
	"github.com/everanium/itb/hashes/internal/blake2basm"
	"github.com/everanium/itb/hashes/internal/blake2sasm"
	"github.com/everanium/itb/hashes/internal/blake3asm"
	"github.com/everanium/itb/hashes/internal/chacha20asm"
	"github.com/everanium/itb/hashes/internal/siphashasm"
	"github.com/everanium/itb/internal/aesitbasm"
	"github.com/everanium/itb/internal/areionasm"
	"github.com/everanium/itb/internal/forcetier"
)

// dispatch_env_matrix_test.go — the cross-primitive audit of the
// dispatch-forcing environment: every kernel package of the registry ×
// every ITB_FORCE_* variable × every token, one process per cell. The
// variables are read once at init, so the parent test re-executes the
// test binary per cell with the variable set and reads back a snapshot
// of every dispatch flag; a baseline child without any variable gives
// the auto-dispatch state the inapplicable tokens must keep. Expected
// states are data (matrixExpect): a token that names an arm the family
// implements and the host can execute selects it, a token that names an
// arm the family lacks or the host cannot run keeps auto-dispatch with
// a stderr note, an unknown token keeps auto-dispatch with the
// forcetier warning, and the disarm knobs leave the flags alone while
// the registry hooks follow them (checked in the child by
// TestRegistryFusedHooksFollowDisarmKnobs).

const matrixChildEnv = "ITB_DISPATCH_MATRIX_CHILD"

// matrixFamily is one kernel package: its name (the prefix of its stderr
// notes) and its dispatch flags by name.
type matrixFamily struct {
	name  string
	class string // "aes" (aesitbasm / aescmacasm), "areion", "gpr" (the five GPR families)
	flags map[string]*bool
}

func matrixFamilies() []matrixFamily {
	gpr := func(name string, f512, f2, fg, x16_512, x16_2, x16g, x8 *bool) matrixFamily {
		return matrixFamily{name, "gpr", map[string]*bool{
			"FusedHasAVX512": f512, "FusedHasAVX2": f2, "FusedHasGPR": fg,
			"HasAVX512X16": x16_512, "HasAVX2X16": x16_2, "HasGPRX16": x16g, "FusedHasAVX512X8": x8}}
	}
	return []matrixFamily{
		{"aesitbasm", "aes", map[string]*bool{
			"FusedHasVAESAVX512": &aesitbasm.FusedHasVAESAVX512, "FusedHasVAESAVX2": &aesitbasm.FusedHasVAESAVX2,
			"FusedHasAVXAESNI": &aesitbasm.FusedHasAVXAESNI, "FusedHasAESNI": &aesitbasm.FusedHasAESNI,
			"HasVAESAVX512X16": &aesitbasm.HasVAESAVX512X16, "HasVAESAVX2X16": &aesitbasm.HasVAESAVX2X16,
			"HasAVXAESNIX16": &aesitbasm.HasAVXAESNIX16, "HasAESNIX16": &aesitbasm.HasAESNIX16,
			"FusedHasVAESAVX512X8": &aesitbasm.FusedHasVAESAVX512X8}},
		{"aescmacasm", "aes", map[string]*bool{
			"FusedHasVAESAVX512": &aescmacasm.FusedHasVAESAVX512, "FusedHasVAESAVX2": &aescmacasm.FusedHasVAESAVX2,
			"FusedHasAVXAESNI": &aescmacasm.FusedHasAVXAESNI, "FusedHasAESNI": &aescmacasm.FusedHasAESNI,
			"HasVAESAVX512X16": &aescmacasm.HasVAESAVX512X16, "HasVAESAVX2X16": &aescmacasm.HasVAESAVX2X16,
			"HasAVXAESNIX16": &aescmacasm.HasAVXAESNIX16, "HasAESNIX16": &aescmacasm.HasAESNIX16,
			"FusedHasVAESAVX512X8": &aescmacasm.FusedHasVAESAVX512X8}},
		{"areionasm", "areion", map[string]*bool{
			"HasVAESAVX512": &areionasm.HasVAESAVX512, "HasVAESAVX2NoAVX512": &areionasm.HasVAESAVX2NoAVX512, "HasARMAESBatched": &areionasm.HasARMAESBatched,
			"FusedHasVAESAVX512": &areionasm.FusedHasVAESAVX512, "FusedHasVAESAVX2": &areionasm.FusedHasVAESAVX2, "FusedHasAESNI": &areionasm.FusedHasAESNI,
			"HasVAESAVX512X16": &areionasm.HasVAESAVX512X16, "HasVAESAVX2X16": &areionasm.HasVAESAVX2X16, "HasAESNIX16": &areionasm.HasAESNIX16,
			"FusedHasVAESAVX512X8": &areionasm.FusedHasVAESAVX512X8}},
		gpr("blake2basm", &blake2basm.FusedHasAVX512, &blake2basm.FusedHasAVX2, &blake2basm.FusedHasGPR, &blake2basm.HasAVX512X16, &blake2basm.HasAVX2X16, &blake2basm.HasGPRX16, &blake2basm.FusedHasAVX512X8),
		gpr("blake2sasm", &blake2sasm.FusedHasAVX512, &blake2sasm.FusedHasAVX2, &blake2sasm.FusedHasGPR, &blake2sasm.HasAVX512X16, &blake2sasm.HasAVX2X16, &blake2sasm.HasGPRX16, &blake2sasm.FusedHasAVX512X8),
		gpr("blake3asm", &blake3asm.FusedHasAVX512, &blake3asm.FusedHasAVX2, &blake3asm.FusedHasGPR, &blake3asm.HasAVX512X16, &blake3asm.HasAVX2X16, &blake3asm.HasGPRX16, &blake3asm.FusedHasAVX512X8),
		gpr("chacha20asm", &chacha20asm.FusedHasAVX512, &chacha20asm.FusedHasAVX2, &chacha20asm.FusedHasGPR, &chacha20asm.HasAVX512X16, &chacha20asm.HasAVX2X16, &chacha20asm.HasGPRX16, &chacha20asm.FusedHasAVX512X8),
		gpr("siphashasm", &siphashasm.FusedHasAVX512, &siphashasm.FusedHasAVX2, &siphashasm.FusedHasGPR, &siphashasm.HasAVX512X16, &siphashasm.HasAVX2X16, &siphashasm.HasGPRX16, &siphashasm.FusedHasAVX512X8),
	}
}

// snapshot is the flag state of one child process: "family.flag" → value.
type snapshot map[string]bool

// TestDispatchEnvMatrixChild is the child half: it prints every dispatch
// flag and the disarm knobs of the process it runs in and, when a disarm
// knob is set, runs the registry hook assertions. It is a no-op unless
// the parent set the child marker.
func TestDispatchEnvMatrixChild(t *testing.T) {
	if os.Getenv(matrixChildEnv) == "" {
		t.Skip("child half of TestDispatchEnvMatrix")
	}
	for _, fam := range matrixFamilies() {
		names := make([]string, 0, len(fam.flags))
		for n := range fam.flags {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Printf("FLAG %s.%s=%v\n", fam.name, n, *fam.flags[n])
		}
	}
	fmt.Printf("KNOB seq=%v x4=%v fillseq=%v fillx1=%v fillx4=%v fillx16=%v\n", forcetier.ChainHashSeq(), forcetier.ChainHashX4(), forcetier.InterlockPRFFillSeq(), forcetier.InterlockPRFFillX1(), forcetier.InterlockPRFFillX4(), forcetier.InterlockPRFFillX16())
	if forcetier.ChainHashSeq() || forcetier.ChainHashX4() {
		TestRegistryFusedHooksFollowDisarmKnobs(t)
	}
}

// runMatrixChild re-executes the test binary with the given variables
// set (every ITB_FORCE_* variable of the parent environment removed) and
// returns the flag snapshot, the knob line and the combined stderr.
func runMatrixChild(t *testing.T, vars map[string]string) (snapshot, string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDispatchEnvMatrixChild$", "-test.v")
	env := []string{matrixChildEnv + "=1"}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "ITB_FORCE_") || strings.HasPrefix(kv, matrixChildEnv+"=") {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range vars {
		env = append(env, k+"="+v)
	}
	cmd.Env = env
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("child %v: %v\nstdout:\n%s\nstderr:\n%s", vars, err, out, stderr.String())
	}
	snap := snapshot{}
	knob := ""
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "FLAG "):
			kv := strings.SplitN(strings.TrimPrefix(line, "FLAG "), "=", 2)
			snap[kv[0]] = kv[1] == "true"
		case strings.HasPrefix(line, "KNOB "):
			knob = strings.TrimPrefix(line, "KNOB ")
		}
	}
	if len(snap) == 0 {
		t.Fatalf("child %v printed no flags:\n%s", vars, out)
	}
	return snap, knob, stderr.String()
}

// matrixExpect is the expected state of one family under one (variable,
// token) cell: nil flags means "auto-dispatch kept" (the baseline
// snapshot); otherwise every named flag must carry the given value and
// every unnamed flag its baseline value. note asks for a stderr line of
// the family that mentions keeping auto-dispatch.
type matrixExpect struct {
	flags map[string]bool
	note  bool
}

var (
	auto     = matrixExpect{}
	autoNote = matrixExpect{note: true}
)

func on(pairs ...string) matrixExpect {
	m := map[string]bool{}
	for _, p := range pairs {
		kv := strings.SplitN(p, "=", 2)
		m[kv[0]] = kv[1] == "1"
	}
	return matrixExpect{flags: m}
}

// Host capability predicates: a token whose arm the host cannot execute
// keeps auto-dispatch with a note in every family.
var (
	hostVAES512 = aes.CPU.HasVAES && aes.CPU.HasAVX512
	hostVAES2   = aes.CPU.HasVAES && aes.CPU.HasAVX2
	hostAESNI2  = aes.CPU.HasAESNI && aes.CPU.HasAVX2
	hostAESNI   = aes.CPU.HasAESNI
	hostAVX512F = cpu.X86.HasAVX512F
	hostAVX2    = cpu.X86.HasAVX2
)

// expectHashTier is the ITB_FORCE_HASH_TIER map of every family class.
func expectHashTier(class, token string) matrixExpect {
	need := func(ok bool, e matrixExpect) matrixExpect {
		if !ok {
			return autoNote
		}
		return e
	}
	switch class {
	case "aes":
		switch token {
		case "avx512":
			return need(hostVAES512, on("FusedHasVAESAVX512=1", "FusedHasVAESAVX2=0", "FusedHasAVXAESNI=0", "FusedHasAESNI=0"))
		case "vaesavx2", "avx2":
			return need(hostVAES2, on("FusedHasVAESAVX512=0", "FusedHasVAESAVX2=1", "FusedHasAVXAESNI=0", "FusedHasAESNI=0"))
		case "vex":
			return need(hostAESNI2, on("FusedHasVAESAVX512=0", "FusedHasVAESAVX2=0", "FusedHasAVXAESNI=1", "FusedHasAESNI=0"))
		case "aesni":
			return need(hostAESNI, on("FusedHasVAESAVX512=0", "FusedHasVAESAVX2=0", "FusedHasAVXAESNI=0", "FusedHasAESNI=1"))
		case "scalar":
			return on("FusedHasVAESAVX512=0", "FusedHasVAESAVX2=0", "FusedHasAVXAESNI=0", "FusedHasAESNI=0",
				"HasVAESAVX512X16=0", "HasVAESAVX2X16=0", "HasAVXAESNIX16=0", "HasAESNIX16=0")
		}
	case "areion":
		switch token {
		case "avx512":
			return need(hostVAES512, on("HasVAESAVX512=1", "HasVAESAVX2NoAVX512=0", "HasARMAESBatched=0", "FusedHasVAESAVX512=1", "FusedHasVAESAVX2=0", "FusedHasAESNI=0", "HasVAESAVX512X16=1", "HasVAESAVX2X16=0", "HasAESNIX16=0"))
		case "vaesavx2":
			return need(hostVAES2, on("HasVAESAVX512=0", "HasVAESAVX2NoAVX512=1", "HasARMAESBatched=0", "FusedHasVAESAVX512=0", "FusedHasVAESAVX2=1", "FusedHasAESNI=0", "HasVAESAVX512X16=0", "HasVAESAVX2X16=1", "HasAESNIX16=0"))
		case "avx2":
			return need(hostVAES2, on("HasVAESAVX512=0", "HasVAESAVX2NoAVX512=1", "HasARMAESBatched=0", "FusedHasVAESAVX512=0", "FusedHasVAESAVX2=0", "FusedHasAESNI=0", "HasVAESAVX512X16=0", "HasVAESAVX2X16=0", "HasAESNIX16=0"))
		case "vex", "aesni":
			return need(hostAESNI, on("HasVAESAVX512=0", "HasVAESAVX2NoAVX512=0", "HasARMAESBatched=0", "FusedHasVAESAVX512=0", "FusedHasVAESAVX2=0", "FusedHasAESNI=1", "HasVAESAVX512X16=0", "HasVAESAVX2X16=0", "HasAESNIX16=1"))
		case "scalar":
			return on("HasVAESAVX512=0", "HasVAESAVX2NoAVX512=0", "HasARMAESBatched=0", "FusedHasVAESAVX512=0", "FusedHasVAESAVX2=0", "FusedHasAESNI=0", "HasVAESAVX512X16=0", "HasVAESAVX2X16=0", "HasAESNIX16=0")
		}
	case "gpr":
		switch token {
		case "avx512":
			return need(hostAVX512F, on("FusedHasAVX512=1", "FusedHasAVX2=0", "FusedHasGPR=1", "HasAVX512X16=1", "HasAVX2X16=0", "HasGPRX16=1"))
		case "avx2", "vex":
			return need(hostAVX2, on("FusedHasAVX512=0", "FusedHasAVX2=1", "FusedHasGPR=1", "HasAVX512X16=0", "HasAVX2X16=1", "HasGPRX16=1"))
		case "aesni", "vaesavx2":
			return autoNote
		case "gpr":
			return on("FusedHasAVX512=0", "FusedHasAVX2=0", "FusedHasGPR=1", "HasAVX512X16=0", "HasAVX2X16=0", "HasGPRX16=1")
		case "scalar":
			return on("FusedHasAVX512=0", "FusedHasAVX2=0", "FusedHasGPR=0", "HasAVX512X16=0", "HasAVX2X16=0", "HasGPRX16=0")
		}
	}
	// The arm64 tokens keep auto-dispatch with a note in every family.
	return autoNote
}

// expectFillTier is the ITB_FORCE_INTERLOCK_PRF_FILL_TIER map of every
// family class; the fused flags stay at their auto-dispatch values.
func expectFillTier(class, token string) matrixExpect {
	need := func(ok bool, e matrixExpect) matrixExpect {
		if !ok {
			return autoNote
		}
		return e
	}
	switch class {
	case "aes":
		switch token {
		case "avx512":
			return need(hostVAES512, on("HasVAESAVX512X16=1", "HasVAESAVX2X16=0", "HasAVXAESNIX16=0", "HasAESNIX16=0"))
		case "vaesavx2":
			return need(hostVAES2, on("HasVAESAVX512X16=0", "HasVAESAVX2X16=1", "HasAVXAESNIX16=0", "HasAESNIX16=0"))
		case "vex":
			return need(hostAESNI2, on("HasVAESAVX512X16=0", "HasVAESAVX2X16=0", "HasAVXAESNIX16=1", "HasAESNIX16=0"))
		case "aesni":
			return need(hostAESNI, on("HasVAESAVX512X16=0", "HasVAESAVX2X16=0", "HasAVXAESNIX16=0", "HasAESNIX16=1"))
		case "avx2", "neon":
			return autoNote
		case "scalar":
			return on("HasVAESAVX512X16=0", "HasVAESAVX2X16=0", "HasAVXAESNIX16=0", "HasAESNIX16=0")
		}
	case "areion":
		switch token {
		case "avx512":
			return need(hostVAES512, on("HasVAESAVX512X16=1", "HasVAESAVX2X16=0", "HasAESNIX16=0"))
		case "vaesavx2":
			return need(hostVAES2, on("HasVAESAVX512X16=0", "HasVAESAVX2X16=1", "HasAESNIX16=0"))
		case "avx2":
			// The arms-only probe of areionasm: the fill flags clear so the
			// fill runs through the arms (a stderr note names the choice).
			return on("HasVAESAVX512X16=0", "HasVAESAVX2X16=0", "HasAESNIX16=0")
		case "vex", "aesni":
			return need(hostAESNI, on("HasVAESAVX512X16=0", "HasVAESAVX2X16=0", "HasAESNIX16=1"))
		case "neon":
			return autoNote
		case "scalar":
			return on("HasVAESAVX512X16=0", "HasVAESAVX2X16=0", "HasAESNIX16=0")
		}
	case "gpr":
		switch token {
		case "avx512":
			return need(hostAVX512F, on("HasAVX512X16=1", "HasAVX2X16=0", "HasGPRX16=1"))
		case "avx2", "vex":
			return need(hostAVX2, on("HasAVX512X16=0", "HasAVX2X16=1", "HasGPRX16=1"))
		case "aesni", "vaesavx2", "neon":
			return autoNote
		case "gpr":
			return on("HasAVX512X16=0", "HasAVX2X16=0", "HasGPRX16=1")
		case "scalar":
			return on("HasAVX512X16=0", "HasAVX2X16=0", "HasGPRX16=0")
		}
	}
	return autoNote
}

// checkFamily compares one family's flags in snap against the
// expectation and the baseline.
func checkFamily(t *testing.T, label string, fam matrixFamily, exp matrixExpect, snap, base snapshot, stderr string) {
	t.Helper()
	for name := range fam.flags {
		key := fam.name + "." + name
		got, ok := snap[key]
		if !ok {
			t.Fatalf("%s: child snapshot lacks %s", label, key)
		}
		want, forced := exp.flags[name]
		if !forced {
			want = base[key]
		}
		if got != want {
			t.Errorf("%s: %s = %v, want %v (forced: %v)", label, key, got, want, forced)
		}
	}
	if exp.note {
		found := false
		for _, line := range strings.Split(stderr, "\n") {
			if strings.Contains(line, fam.name+":") && strings.Contains(line, "keeping auto-dispatch") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: no auto-dispatch note of %s on stderr:\n%s", label, fam.name, stderr)
		}
	}
}

// TestDispatchEnvMatrix is the parent half: one child process per
// (variable, token) cell over every kernel package of the registry.
func TestDispatchEnvMatrix(t *testing.T) {
	if os.Getenv(matrixChildEnv) != "" {
		t.Skip("running as a matrix child")
	}
	if testing.Short() {
		t.Skip("spawns one process per matrix cell")
	}
	base, _, _ := runMatrixChild(t, nil)
	fams := matrixFamilies()

	for _, tok := range []string{"avx512", "vaesavx2", "avx2", "vex", "aesni", "gpr", "sve2", "sve", "neon", "scalar"} {
		t.Run("HASH_TIER="+tok, func(t *testing.T) {
			snap, _, stderr := runMatrixChild(t, map[string]string{"ITB_FORCE_HASH_TIER": tok})
			for _, fam := range fams {
				checkFamily(t, "ITB_FORCE_HASH_TIER="+tok, fam, expectHashTier(fam.class, tok), snap, base, stderr)
			}
		})
	}
	for _, tok := range []string{"avx512", "vaesavx2", "avx2", "vex", "aesni", "gpr", "neon", "scalar"} {
		t.Run("FILL_TIER="+tok, func(t *testing.T) {
			snap, _, stderr := runMatrixChild(t, map[string]string{"ITB_FORCE_INTERLOCK_PRF_FILL_TIER": tok})
			for _, fam := range fams {
				checkFamily(t, "ITB_FORCE_INTERLOCK_PRF_FILL_TIER="+tok, fam, expectFillTier(fam.class, tok), snap, base, stderr)
			}
		})
	}
	for _, v := range []string{"ITB_FORCE_HASH_TIER", "ITB_FORCE_INTERLOCK_PRF_FILL_TIER"} {
		t.Run(v+"=unknown", func(t *testing.T) {
			snap, _, stderr := runMatrixChild(t, map[string]string{v: "no_such_tier"})
			for _, fam := range fams {
				checkFamily(t, v+"=no_such_tier", fam, auto, snap, base, stderr)
			}
			if !strings.Contains(stderr, v+`="no_such_tier" unknown value`) {
				t.Errorf("unknown token: no forcetier warning on stderr:\n%s", stderr)
			}
		})
	}
	// Disarm knobs: the tier flags stay at auto-dispatch (the eight-lane
	// arm flags clear under X4); the child asserts the registry hooks.
	knobs := []struct {
		env  map[string]string
		want string
		x8   bool
	}{
		{map[string]string{"ITB_FORCE_CHAINHASH_SEQ": "1"}, "seq=true x4=false fillseq=false fillx1=false fillx4=false fillx16=false", true},
		{map[string]string{"ITB_FORCE_CHAINHASH_X4": "1"}, "seq=false x4=true fillseq=false fillx1=false fillx4=false fillx16=false", false},
		{map[string]string{"ITB_FORCE_INTERLOCK_PRF_FILL_SEQ": "1"}, "seq=false x4=false fillseq=true fillx1=false fillx4=false fillx16=false", true},
		{map[string]string{"ITB_FORCE_INTERLOCK_PRF_FILL_X1": "1"}, "seq=false x4=false fillseq=false fillx1=true fillx4=false fillx16=false", true},
		{map[string]string{"ITB_FORCE_INTERLOCK_PRF_FILL_X4": "1"}, "seq=false x4=false fillseq=false fillx1=false fillx4=true fillx16=false", true},
		{map[string]string{"ITB_FORCE_INTERLOCK_PRF_FILL_X16": "1"}, "seq=false x4=false fillseq=false fillx1=false fillx4=false fillx16=true", true},
	}
	for _, k := range knobs {
		name := ""
		for v := range k.env {
			name = v
		}
		t.Run(name, func(t *testing.T) {
			snap, knob, stderr := runMatrixChild(t, k.env)
			if knob != k.want {
				t.Errorf("%s: knobs %q, want %q", name, knob, k.want)
			}
			for _, fam := range fams {
				exp := auto
				if !k.x8 {
					exp = matrixExpect{flags: map[string]bool{}}
					for n := range fam.flags {
						if strings.HasSuffix(n, "X8") {
							exp.flags[n] = false
						}
					}
				}
				checkFamily(t, name, fam, exp, snap, base, stderr)
			}
		})
	}
}
