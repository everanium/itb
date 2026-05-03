package easy

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
)

// ErrEasyMixedWidth indicates that one or more primitive names in a
// [MixedSpec] / [MixedSpec3] resolve to a different native hash
// width than the noiseSeed primitive. The Go type system requires
// every seed slot in one encryptor to share the same width — mixing
// widths is rejected at construction time before any seed is
// allocated.
var ErrEasyMixedWidth = errors.New("itb/easy: mixed-mode primitives must share the same native hash width")

// MixedPrimitive is the canonical [Encryptor.Primitive] string for
// encryptors built via [NewMixed] / [NewMixed3]. Single-primitive
// encryptors built via [New] / [New3] carry the primitive name
// directly in this field; mixed-mode encryptors set it to the
// "mixed" literal and expose the per-slot primitive through
// [Encryptor.PrimitiveAt].
const MixedPrimitive = "mixed"

// MixedSpec describes the per-slot primitive selection for a
// Single-Ouroboros encryptor built via [NewMixed]. PrimitiveN /
// PrimitiveD / PrimitiveS are the canonical [hashes.Registry] names
// for the noise / data / start seed slots; PrimitiveL is the
// optional dedicated lockSeed primitive (empty string = no lockSeed
// allocation, behaves like [New] without [Encryptor.SetLockSeed]).
//
// All four primitive names must resolve to the same native hash
// width — mixing widths in one Encryptor is forbidden by Go's seed
// type system and rejected with [ErrEasyMixedWidth] before any
// allocation runs.
//
// KeyBits selects the per-seed key width in bits (one of 512, 1024,
// 2048; multiple of the resolved native width). MACName selects the
// MAC primitive across the encryptor (one MAC per encryptor, same
// as [New] / [New3]).
type MixedSpec struct {
	PrimitiveN string
	PrimitiveD string
	PrimitiveS string
	PrimitiveL string
	KeyBits    int
	MACName    string
}

// MixedSpec3 describes the per-slot primitive selection for a
// Triple-Ouroboros encryptor built via [NewMixed3]. PrimitiveN
// covers the shared noiseSeed slot; PrimitiveD1 / PrimitiveD2 /
// PrimitiveD3 cover the three dataSeed rings; PrimitiveS1 /
// PrimitiveS2 / PrimitiveS3 cover the three startSeed rings.
// PrimitiveL is the optional dedicated lockSeed primitive — empty
// string skips the lockSeed allocation (behaves like [New3] without
// [Encryptor.SetLockSeed]).
//
// All eight primitive names (seven slots plus the optional lockSeed)
// must resolve to the same native hash width; otherwise the
// constructor panics with [ErrEasyMixedWidth] before any allocation
// runs.
type MixedSpec3 struct {
	PrimitiveN  string
	PrimitiveD1 string
	PrimitiveD2 string
	PrimitiveD3 string
	PrimitiveS1 string
	PrimitiveS2 string
	PrimitiveS3 string
	PrimitiveL  string
	KeyBits     int
	MACName     string
}

// NewMixed constructs a Single-Ouroboros [Encryptor] with per-slot
// PRF primitive selection. Allows the noise / data / start seeds to
// run different PRFs within the same native hash width — the
// freedom the lower-level [itb.Encrypt256] path already supports,
// surfaced through Easy Mode without forcing the caller off the
// high-level API.
//
// The optional dedicated lockSeed (PrimitiveL non-empty) is
// allocated as a 4th seed slot under its own primitive choice;
// BitSoup / LockSoup are auto-coupled on the on-direction and the
// noiseSeed [itb.Seed{N}.AttachLockSeed] mutator is invoked so the
// bit-permutation overlay routes through the dedicated seed
// immediately. Empty PrimitiveL leaves the encryptor in the same
// 3-slot state [New] would produce.
//
// Validation panics on the same conditions as [New] (unknown
// primitive / MAC, invalid KeyBits, KeyBits not divisible by
// primitive width) plus [ErrEasyMixedWidth] when slot primitives
// disagree on native width. crypto/rand failures during PRF / seed
// / MAC key generation panic with the standard "itb/easy:
// crypto/rand: ..." prefix.
func NewMixed(spec MixedSpec) *Encryptor {
	return newEncryptorMixed(1,
		[]string{spec.PrimitiveN, spec.PrimitiveD, spec.PrimitiveS},
		spec.PrimitiveL, spec.KeyBits, spec.MACName,
	)
}

// NewMixed3 constructs a Triple-Ouroboros [Encryptor] with per-slot
// PRF primitive selection. See [NewMixed] for the construction
// contract; the slot count grows from 3 to 7 (1 noise + 3 data + 3
// start) plus the optional dedicated lockSeed slot.
func NewMixed3(spec MixedSpec3) *Encryptor {
	return newEncryptorMixed(3,
		[]string{
			spec.PrimitiveN,
			spec.PrimitiveD1, spec.PrimitiveD2, spec.PrimitiveD3,
			spec.PrimitiveS1, spec.PrimitiveS2, spec.PrimitiveS3,
		},
		spec.PrimitiveL, spec.KeyBits, spec.MACName,
	)
}

// newEncryptorMixed is the shared constructor body. mode is 1
// (Single, 3 main slots) or 3 (Triple, 7 main slots); slotPrims
// carries one canonical primitive name per slot in canonical order;
// lockPrim is the optional dedicated lockSeed primitive (empty
// string = no lockSeed allocation).
//
// Width is taken from the noiseSeed primitive (slotPrims[0]) and
// every other slot — including the optional lockSeed — must agree.
// The MAC primitive is independent and may belong to a different
// width family.
func newEncryptorMixed(mode int, slotPrims []string, lockPrim string, keyBits int, macName string) *Encryptor {
	// Resolve the noiseSeed primitive first to pin the expected
	// native width; every other slot is validated against it.
	if len(slotPrims) == 0 {
		panic("itb/easy: NewMixed: empty slot primitive list")
	}
	specs := make([]hashes.Spec, len(slotPrims))
	for i, p := range slotPrims {
		hs, ok := hashes.Find(p)
		if !ok {
			panic(fmt.Sprintf("itb/easy: NewMixed: unknown primitive %q at slot %d", p, i))
		}
		specs[i] = hs
	}
	width := int(specs[0].Width)
	for i := 1; i < len(specs); i++ {
		if int(specs[i].Width) != width {
			panic(fmt.Errorf("itb/easy: %w: slot %d %q is %d-bit, noiseSeed slot %q is %d-bit",
				ErrEasyMixedWidth, i, slotPrims[i], int(specs[i].Width), slotPrims[0], width))
		}
	}

	// Optional lockSeed primitive — must share the same width.
	var lockSpec hashes.Spec
	if lockPrim != "" {
		var ok bool
		lockSpec, ok = hashes.Find(lockPrim)
		if !ok {
			panic(fmt.Sprintf("itb/easy: NewMixed: unknown lockSeed primitive %q", lockPrim))
		}
		if int(lockSpec.Width) != width {
			panic(fmt.Errorf("itb/easy: %w: lockSeed primitive %q is %d-bit, noiseSeed slot %q is %d-bit",
				ErrEasyMixedWidth, lockPrim, int(lockSpec.Width), slotPrims[0], width))
		}
	}

	// KeyBits validation — same shape as [newEncryptor].
	switch keyBits {
	case 512, 1024, 2048:
	default:
		panic(fmt.Sprintf("itb/easy: NewMixed: key_bits=%d invalid (valid values: 512, 1024, 2048)", keyBits))
	}
	if keyBits%width != 0 {
		panic(fmt.Sprintf("itb/easy: NewMixed: key_bits=%d not divisible by primitive width %d",
			keyBits, width))
	}

	// MAC validation.
	macSpec, ok := macs.Find(macName)
	if !ok {
		panic(fmt.Sprintf("itb/easy: NewMixed: unknown MAC %q", macName))
	}

	expectedMain := 3
	if mode == 3 {
		expectedMain = 7
	}
	if len(slotPrims) != expectedMain {
		panic(fmt.Sprintf("itb/easy: NewMixed: mode %d expects %d slot primitives, got %d",
			mode, expectedMain, len(slotPrims)))
	}

	cfg := itb.SnapshotGlobals()

	enc := &Encryptor{
		Primitive: MixedPrimitive,
		KeyBits:   keyBits,
		Mode:      mode,
		MACName:   macName,
		width:     width,
		cfg:       cfg,
	}

	// Per-slot allocation. SipHash24 returns nil PRF key bytes; for
	// every other primitive the key is the freshly-generated CSPRNG
	// fixed key. prfKeys parallels seeds; entries for siphash24
	// slots are nil (zero-length slice).
	seeds := make([]interface{}, 0, len(slotPrims)+1)
	prfKeys := make([][]byte, 0, len(slotPrims)+1)
	primNames := make([]string, 0, len(slotPrims)+1)
	for i, p := range slotPrims {
		seed, key := allocSeed(p, keyBits, width)
		seeds = append(seeds, seed)
		prfKeys = append(prfKeys, key)
		primNames = append(primNames, p)
		_ = i
	}

	// Optional lockSeed slot: allocate, attach to noiseSeed, and
	// auto-couple BitSoup + LockSoup so the bit-permutation overlay
	// has wire effect immediately. Mirrors the on-direction of
	// [Encryptor.SetLockSeed] but routes through the
	// caller-specified PrimitiveL instead of the noiseSeed primitive.
	if lockPrim != "" {
		lockSeed, lockKey := allocSeed(lockPrim, keyBits, width)
		seeds = append(seeds, lockSeed)
		prfKeys = append(prfKeys, lockKey)
		primNames = append(primNames, lockPrim)

		cfg.LockSeed = 1
		cfg.LockSeedHandle = lockSeed
		if cfg.BitSoup <= 0 {
			cfg.BitSoup = 1
		}
		if cfg.LockSoup <= 0 {
			cfg.LockSoup = 1
		}
		enc.bitSoupExplicit = true
		enc.lockSoupExplicit = true

		// Wire the dedicated lockSeed onto the noiseSeed (slot 0).
		// Type-switch is necessary because seeds is []interface{};
		// the width discriminator is shared so the cast is safe.
		switch ns := seeds[0].(type) {
		case *itb.Seed128:
			ns.AttachLockSeed(lockSeed.(*itb.Seed128))
		case *itb.Seed256:
			ns.AttachLockSeed(lockSeed.(*itb.Seed256))
		case *itb.Seed512:
			ns.AttachLockSeed(lockSeed.(*itb.Seed512))
		}
	}

	enc.seeds = seeds
	enc.prfKeys = prfKeys
	enc.primitives = primNames

	// MAC fixed key + closure.
	macKey := make([]byte, macSpec.KeySize)
	if _, err := rand.Read(macKey); err != nil {
		panic(fmt.Sprintf("itb/easy: NewMixed: crypto/rand: %v", err))
	}
	macFunc, err := macs.Make(macName, macKey)
	if err != nil {
		panic(fmt.Sprintf("itb/easy: NewMixed: macs.Make(%q): %v", macName, err))
	}
	enc.macKey = macKey
	enc.macFunc = macFunc

	return enc
}

// PrimitiveAt returns the canonical [hashes.Registry] name bound to
// the seed at the given slot index. Slot ordering is canonical
// across the package:
//
//   - Single mode: 0 = noiseSeed, 1 = dataSeed, 2 = startSeed.
//   - Triple mode: 0 = noiseSeed, 1..3 = dataSeed1..3, 4..6 =
//     startSeed1..3.
//   - Optional dedicated lockSeed (when active) sits at the last
//     index — len(seeds)-1.
//
// For encryptors built via [New] / [New3] every slot returns the
// same name [Encryptor.Primitive] is bound to. For encryptors built
// via [NewMixed] / [NewMixed3] each slot can carry an independently
// chosen primitive within the shared native hash width.
//
// Out-of-range slot indices return the empty string. Closed
// encryptors panic with [ErrClosed], matching the rest of the
// Encryptor surface.
func (e *Encryptor) PrimitiveAt(slot int) string {
	if e.closed {
		panic(ErrClosed)
	}
	if slot < 0 || slot >= len(e.seeds) {
		return ""
	}
	if len(e.primitives) > slot {
		return e.primitives[slot]
	}
	// Single-primitive encryptor — Primitive applies to every slot.
	return e.Primitive
}

// IsMixed reports whether the encryptor was constructed via
// [NewMixed] / [NewMixed3] (per-slot primitive selection) or via
// [New] / [New3] (single primitive across all slots).
//
// Equivalent to checking [Encryptor.Primitive] == [MixedPrimitive],
// surfaced as a typed predicate for code that prefers a boolean
// over a string comparison.
func (e *Encryptor) IsMixed() bool {
	if e.closed {
		panic(ErrClosed)
	}
	return e.primitives != nil
}
