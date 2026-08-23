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
// encryptors built via [NewMixed3]. Single-primitive encryptors
// built via [New3] carry the primitive name directly in this field;
// mixed-mode encryptors set it to the "mixed" literal and expose the
// per-slot primitive through [Encryptor.PrimitiveAt].
const MixedPrimitive = "mixed"

// MixedSpec3 describes the per-slot primitive selection for a
// Triple-Ouroboros encryptor built via [NewMixed3]. PrimitiveN
// covers the shared noiseSeed slot; PrimitiveL covers the dedicated
// lockSeed slot (empty string adopts the noiseSeed primitive);
// PrimitiveD1 / PrimitiveD2 / PrimitiveD3 cover the three dataSeed
// rings; PrimitiveS1 / PrimitiveS2 / PrimitiveS3 cover the three
// startSeed rings.
//
// All eight primitive names must resolve to the same native hash
// width; otherwise the constructor panics with [ErrEasyMixedWidth]
// before any allocation runs.
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

// NewMixed3 constructs a Triple-Ouroboros [Encryptor] with per-slot
// PRF primitive selection. Allows the noise / lock / data / start
// seeds to run different PRFs within the same native hash width —
// surfaced through Easy Mode without forcing the caller off the
// high-level API.
//
// The lockSeed slot always exists (Triple pipeline requires eight
// seeds). Empty PrimitiveL adopts the noiseSeed's primitive; a
// non-empty PrimitiveL keys the lockSeed slot independently, giving
// algorithm diversity on the bit-permutation channel.
//
// Validation panics on the same conditions as [New3] (unknown
// primitive / MAC, invalid KeyBits, KeyBits not divisible by
// primitive width) plus [ErrEasyMixedWidth] when slot primitives
// disagree on native width. crypto/rand failures during PRF / seed
// / MAC key generation panic with the standard "itb/easy:
// crypto/rand: ..." prefix.
func NewMixed3(spec MixedSpec3) *Encryptor {
	return newEncryptorMixed(
		[]string{
			spec.PrimitiveN,
			spec.PrimitiveD1, spec.PrimitiveD2, spec.PrimitiveD3,
			spec.PrimitiveS1, spec.PrimitiveS2, spec.PrimitiveS3,
		},
		spec.PrimitiveL, spec.KeyBits, spec.MACName,
	)
}

// newEncryptorMixed is the shared constructor body for
// [NewMixed3]. slotPrims carries one canonical primitive name per
// slot in main-slot canonical order (1 noiseSeed + 3 dataSeeds +
// 3 startSeeds = 7 entries); lockPrim is the dedicated lockSeed
// primitive (empty string adopts the noiseSeed primitive).
//
// Width is taken from the noiseSeed primitive (slotPrims[0]) and
// every other slot — including the lockSeed — must agree. The MAC
// primitive is independent and may belong to a different width
// family.
//
// The final seed slot layout is
// [noise, lockSeed, data1, data2, data3, start1, start2, start3] —
// eight entries, mirroring the low-level Triple entry-point
// argument order.
func newEncryptorMixed(slotPrims []string, lockPrim string, keyBits int, macName string) *Encryptor {
	const mode = 3
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

	// Dedicated lockSeed — always allocated; empty PrimitiveL adopts
	// the noiseSeed primitive. Non-empty PrimitiveL must share the
	// same native width.
	if lockPrim == "" {
		lockPrim = slotPrims[0]
	}
	lockSpec, ok := hashes.Find(lockPrim)
	if !ok {
		panic(fmt.Sprintf("itb/easy: NewMixed: unknown lockSeed primitive %q", lockPrim))
	}
	if int(lockSpec.Width) != width {
		panic(fmt.Errorf("itb/easy: %w: lockSeed primitive %q is %d-bit, noiseSeed slot %q is %d-bit",
			ErrEasyMixedWidth, lockPrim, int(lockSpec.Width), slotPrims[0], width))
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

	const expectedMain = 7
	if len(slotPrims) != expectedMain {
		panic(fmt.Sprintf("itb/easy: NewMixed: expects %d slot primitives, got %d",
			expectedMain, len(slotPrims)))
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

	// Per-slot allocation in canonical Triple order:
	// [noise, lockSeed, data1, data2, data3, start1, start2, start3].
	// SipHash24 returns nil PRF key bytes; every other primitive
	// yields a freshly-generated CSPRNG fixed key. prfKeys parallels
	// seeds; entries for siphash24 slots are nil (zero-length slice).
	seeds := make([]interface{}, 0, 8)
	prfKeys := make([][]byte, 0, 8)
	primNames := make([]string, 0, 8)

	noiseSeed, noiseKey := allocSeed(slotPrims[0], keyBits, width)
	seeds = append(seeds, noiseSeed)
	prfKeys = append(prfKeys, noiseKey)
	primNames = append(primNames, slotPrims[0])

	lockSeed, lockKey := allocSeed(lockPrim, keyBits, width)
	seeds = append(seeds, lockSeed)
	prfKeys = append(prfKeys, lockKey)
	primNames = append(primNames, lockPrim)

	for i := 1; i < len(slotPrims); i++ {
		seed, key := allocSeed(slotPrims[i], keyBits, width)
		seeds = append(seeds, seed)
		prfKeys = append(prfKeys, key)
		primNames = append(primNames, slotPrims[i])
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
// across the package: 0 = noiseSeed, 1 = lockSeed, 2..4 =
// dataSeed1..3, 5..7 = startSeed1..3.
//
// For encryptors built via [New3] every slot returns the same name
// [Encryptor.Primitive] is bound to. For encryptors built via
// [NewMixed3] each slot can carry an independently chosen primitive
// within the shared native hash width.
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
// [NewMixed3] (per-slot primitive selection) or via [New3] (single
// primitive across all slots).
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
