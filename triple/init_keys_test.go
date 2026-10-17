package triple_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/parallax"
	"github.com/everanium/itb/triple"
)

func testDistinctMasters(size int) [8][]byte {
	var m [8][]byte
	for i := 0; i < 8; i++ {
		buf := make([]byte, size)
		for b := range buf {
			buf[b] = byte((i+1)*37 + b*13 + 7)
		}
		binary.LittleEndian.PutUint64(buf, uint64(0x0102030405060708)*(uint64(i)+1))
		m[i] = buf
	}
	return m
}

func TestInitKeysDeterminismAndInteroperabilityAllProfiles(t *testing.T) {
	masters := testDistinctMasters(32)
	plain := []byte("deterministic InitKeys round-trip payload across all shipped profiles")

	for _, name := range triple.Profiles() {
		t.Run(name, func(t *testing.T) {
			p1, blob1, err := triple.InitKeys(name, triple.Opts{}, masters)
			if err != nil {
				t.Fatalf("InitKeys #1(%q): %v", name, err)
			}
			defer p1.Close()

			p2, blob2, err := triple.InitKeys(name, triple.Opts{}, masters)
			if err != nil {
				t.Fatalf("InitKeys #2(%q): %v", name, err)
			}
			defer p2.Close()

			if !bytes.Equal(blob1, blob2) {
				t.Fatalf("InitKeys(%q) blobs differ across identical calls", name)
			}
			if !bytes.Equal(p1.Save(), blob1) {
				t.Fatalf("p1.Save() != blob1 for %q", name)
			}

			loaded, err := triple.Load(blob1)
			if err != nil {
				t.Fatalf("Load(blob1) for %q: %v", name, err)
			}
			defer loaded.Close()

			prof, err := triple.Inspect(blob1)
			if err != nil {
				t.Fatalf("Inspect(blob1) for %q: %v", name, err)
			}

			switch {
			case strings.HasPrefix(prof.Mode, "singlemsg-"):
				wire, err := p1.EncryptMessage(plain)
				if err != nil {
					t.Fatalf("p1.EncryptMessage(%q): %v", name, err)
				}
				got2, err := p2.DecryptMessage(wire)
				if err != nil {
					t.Fatalf("p2.DecryptMessage(%q): %v", name, err)
				}
				if !bytes.Equal(got2, plain) {
					t.Fatalf("p2 decrypted mismatch for %q", name)
				}
				gotLoaded, err := loaded.DecryptMessage(wire)
				if err != nil {
					t.Fatalf("loaded.DecryptMessage(%q): %v", name, err)
				}
				if !bytes.Equal(gotLoaded, plain) {
					t.Fatalf("loaded decrypted mismatch for %q", name)
				}
			case strings.HasPrefix(prof.Mode, "streaming-"):
				wire, err := p1.EncryptStreamBytes(plain)
				if err != nil {
					t.Fatalf("p1.EncryptStreamBytes(%q): %v", name, err)
				}
				got2, err := p2.DecryptStreamBytes(wire)
				if err != nil {
					t.Fatalf("p2.DecryptStreamBytes(%q): %v", name, err)
				}
				if !bytes.Equal(got2, plain) {
					t.Fatalf("p2 stream decrypted mismatch for %q", name)
				}
				gotLoaded, err := loaded.DecryptStreamBytes(wire)
				if err != nil {
					t.Fatalf("loaded.DecryptStreamBytes(%q): %v", name, err)
				}
				if !bytes.Equal(gotLoaded, plain) {
					t.Fatalf("loaded stream decrypted mismatch for %q", name)
				}
			}
		})
	}
}

func TestInitKeysAllShippedPrimitives(t *testing.T) {
	plain := []byte("per-primitive InitKeys verification across all 10 registry primitives")
	for _, spec := range hashes.Registry {
		t.Run(spec.Name, func(t *testing.T) {
			minBytes := 32
			if spec.Width == hashes.W128 {
				minBytes = 16
			}
			masters := testDistinctMasters(minBytes)
			opts := triple.Opts{
				InnerHash: spec.Name,
				KeyBits:   1024,
			}
			p1, blob1, err := triple.InitKeys(triple.ProfileSingleMsgTripleMACV1, opts, masters)
			if err != nil {
				t.Fatalf("InitKeys(%q): %v", spec.Name, err)
			}
			defer p1.Close()

			p2, blob2, err := triple.InitKeys(triple.ProfileSingleMsgTripleMACV1, opts, masters)
			if err != nil {
				t.Fatalf("InitKeys #2(%q): %v", spec.Name, err)
			}
			defer p2.Close()

			if !bytes.Equal(blob1, blob2) {
				t.Fatalf("blobs differ for primitive %q", spec.Name)
			}

			wire, err := p1.EncryptMessage(plain)
			if err != nil {
				t.Fatalf("EncryptMessage(%q): %v", spec.Name, err)
			}
			got, err := p2.DecryptMessage(wire)
			if err != nil {
				t.Fatalf("DecryptMessage(%q): %v", spec.Name, err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("round-trip mismatch for %q", spec.Name)
			}
		})
	}
}

func TestInitKeysValidationErrors(t *testing.T) {
	// 1. Empty master in any slot -> ErrMissingMasters.
	for slot := 0; slot < 8; slot++ {
		m := testDistinctMasters(32)
		m[slot] = nil
		_, _, err := triple.InitKeys(triple.ProfileSingleMsgTripleMACV1, triple.Opts{}, m)
		if !errors.Is(err, triple.ErrMissingMasters) {
			t.Fatalf("slot %d nil master: got %v, want ErrMissingMasters", slot, err)
		}
	}

	// 2. Short master (< 32 bytes for 256-bit slot, < 16 bytes for 128-bit slot).
	mShort256 := testDistinctMasters(32)
	mShort256[3] = mShort256[3][:31]
	if _, _, err := triple.InitKeys(triple.ProfileSingleMsgTripleMACV1, triple.Opts{}, mShort256); err == nil {
		t.Fatal("expected error for 31-byte master on 256-bit profile")
	}

	mShort128 := testDistinctMasters(16)
	mShort128[5] = mShort128[5][:15]
	if _, _, err := triple.InitKeys(triple.ProfileSingleMsgAESITBMACV1, triple.Opts{}, mShort128); err == nil {
		t.Fatal("expected error for 15-byte master on 128-bit profile")
	}

	// 3. Oversized master (> parallax.MaxMasterKeySize = 128).
	mOver := testDistinctMasters(32)
	mOver[7] = make([]byte, parallax.MaxMasterKeySize+1)
	if _, _, err := triple.InitKeys(triple.ProfileSingleMsgTripleMACV1, triple.Opts{}, mOver); err == nil {
		t.Fatal("expected error for oversized master")
	}

	// 4. Pairwise identical masters -> ErrIdenticalMasters.
	mDup := testDistinctMasters(32)
	mDup[6] = append([]byte(nil), mDup[2]...)
	if _, _, err := triple.InitKeys(triple.ProfileSingleMsgTripleMACV1, triple.Opts{}, mDup); !errors.Is(err, triple.ErrIdenticalMasters) {
		t.Fatalf("identical masters: got %v, want ErrIdenticalMasters", err)
	}

	// 5. Pairwise identical KDF-consumed prefix (first 32 bytes equal, trailing bytes differ) -> ErrIdenticalMasters.
	mPrefix := testDistinctMasters(64)
	copy(mPrefix[4][:32], mPrefix[1][:32])
	mPrefix[4][63] ^= 0xFF
	if _, _, err := triple.InitKeys(triple.ProfileSingleMsgTripleMACV1, triple.Opts{}, mPrefix); !errors.Is(err, triple.ErrIdenticalMasters) {
		t.Fatalf("identical 32-byte prefix masters: got %v, want ErrIdenticalMasters", err)
	}
}

func TestInitKeysAllEightSlotsContribute(t *testing.T) {
	baseMasters := testDistinctMasters(32)
	basePipe, baseBlob, err := triple.InitKeys(triple.ProfileSingleMsgTripleMACV1, triple.Opts{}, baseMasters)
	if err != nil {
		t.Fatalf("base InitKeys: %v", err)
	}
	defer basePipe.Close()

	plain := []byte("slot-sensitivity probe message")
	baseWire, err := basePipe.EncryptMessage(plain)
	if err != nil {
		t.Fatalf("base EncryptMessage: %v", err)
	}

	for slot := 0; slot < 8; slot++ {
		modMasters := testDistinctMasters(32)
		modMasters[slot][0] ^= 0x01
		modPipe, modBlob, err := triple.InitKeys(triple.ProfileSingleMsgTripleMACV1, triple.Opts{}, modMasters)
		if err != nil {
			t.Fatalf("slot %d InitKeys: %v", slot, err)
		}
		if bytes.Equal(baseBlob, modBlob) {
			modPipe.Close()
			t.Fatalf("slot %d bit flip did not change derived blob", slot)
		}
		if _, err := modPipe.DecryptMessage(baseWire); err == nil {
			modPipe.Close()
			t.Fatalf("slot %d bit flip still decrypted baseWire under MAC profile", slot)
		}
		modPipe.Close()
	}
}
