package triple

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/everanium/itb"
)

func boolPtr168(b bool) *bool { return &b }

// TestTripleInterlock168LifecycleAndRoundTrips tests Init, Load, Inspect,
// EncryptMessage / DecryptMessage, EncryptMessageTo / DecryptMessageTo,
// EncryptStream / DecryptStream, EncryptStreamBytes / DecryptStreamBytes,
// and MaxWireSize / MaxPlaintextSize under Interlock="168" across both
// 512-bit primitives (areion512, blake2b512), the 512-bit mixed profile
// ProfileSingleMsgTripleNoMACMixedV1, Mode 1 and Mode 2, and Parallax /
// Wrapper toggle combinations.
func TestTripleInterlock168LifecycleAndRoundTrips(t *testing.T) {
	sizes := []int{1, 21, 100, 1024, 4096}

	for _, hashName := range []string{"areion512", "blake2b512"} {
		for _, mode := range []int{1, 2} {
			for _, px := range []bool{true, false} {
				for _, wr := range []bool{true, false} {
					opts := Opts{
						InnerHash:    hashName,
						Interlock:    itb.Interlock168,
						Mode:         mode,
						ChunkSize:    4096,
						WithParallax: boolPtr168(px),
						WithWrapper:  boolPtr168(wr),
					}
					sender, blob, err := Init(ProfileStreamingAEADTripleMACV1, opts)
					if err != nil {
						t.Fatalf("Init(%s, mode=%d, px=%v, wr=%v): %v", hashName, mode, px, wr, err)
					}

					prof, err := Inspect(blob)
					if err != nil {
						sender.Close()
						t.Fatalf("Inspect: %v", err)
					}
					if prof.Interlock != itb.Interlock168 || prof.InnerHash != hashName {
						sender.Close()
						t.Fatalf("Inspect got Interlock=%q InnerHash=%q", prof.Interlock, prof.InnerHash)
					}

					receiver, err := Load(blob)
					if err != nil {
						sender.Close()
						t.Fatalf("Load: %v", err)
					}

					for _, sz := range sizes {
						pt := make([]byte, sz)
						if _, err := rand.Read(pt); err != nil {
							t.Fatal(err)
						}

						// 1. EncryptMessage / DecryptMessage + MaxWireSize / MaxPlaintextSize bounds.
						wire, err := sender.EncryptMessage(pt)
						if err != nil {
							t.Fatalf("EncryptMessage(sz=%d): %v", sz, err)
						}
						maxWire := sender.MaxWireSize(sz)
						if len(wire) > maxWire {
							t.Fatalf("sz=%d: wire len %d > MaxWireSize %d", sz, len(wire), maxWire)
						}
						maxPt := receiver.MaxPlaintextSize(len(wire))
						if sz > maxPt {
							t.Fatalf("sz=%d > MaxPlaintextSize %d", sz, maxPt)
						}
						got, err := receiver.DecryptMessage(wire)
						if err != nil {
							t.Fatalf("DecryptMessage(sz=%d): %v", sz, err)
						}
						if !bytes.Equal(got, pt) {
							t.Fatalf("DecryptMessage(sz=%d): round-trip mismatch", sz)
						}

						// 2. EncryptMessageTo / DecryptMessageTo.
						wireDst, err := sender.EncryptMessageTo(nil, pt)
						if err != nil {
							t.Fatalf("EncryptMessageTo(sz=%d): %v", sz, err)
						}
						gotDst, err := receiver.DecryptMessageTo(nil, wireDst)
						if err != nil {
							t.Fatalf("DecryptMessageTo(sz=%d): %v", sz, err)
						}
						if !bytes.Equal(gotDst, pt) {
							t.Fatalf("DecryptMessageTo(sz=%d): round-trip mismatch", sz)
						}

						// 3. EncryptStreamBytes / DecryptStreamBytes.
						sWire, err := sender.EncryptStreamBytes(pt)
						if err != nil {
							t.Fatalf("EncryptStreamBytes(sz=%d): %v", sz, err)
						}
						sGot, err := receiver.DecryptStreamBytes(sWire)
						if err != nil {
							t.Fatalf("DecryptStreamBytes(sz=%d): %v", sz, err)
						}
						if !bytes.Equal(sGot, pt) {
							t.Fatalf("DecryptStreamBytes(sz=%d): round-trip mismatch", sz)
						}

						// 4. EncryptStream / DecryptStream.
						var streamWire bytes.Buffer
						if err := sender.EncryptStream(bytes.NewReader(pt), &streamWire); err != nil {
							t.Fatalf("EncryptStream(sz=%d): %v", sz, err)
						}
						var streamPlain bytes.Buffer
						if err := receiver.DecryptStream(bytes.NewReader(streamWire.Bytes()), &streamPlain); err != nil {
							t.Fatalf("DecryptStream(sz=%d): %v", sz, err)
						}
						if !bytes.Equal(streamPlain.Bytes(), pt) {
							t.Fatalf("DecryptStream(sz=%d): round-trip mismatch", sz)
						}
					}

					receiver.Close()
					sender.Close()
				}
			}
		}
	}

	// 512-bit mixed profile (ProfileSingleMsgTripleNoMACMixedV1: areion512 + blake2b512).
	mixedSender, mixedBlob, err := Init(ProfileSingleMsgTripleNoMACMixedV1, Opts{
		Interlock: itb.Interlock168,
		ChunkSize: 4096,
	})
	if err != nil {
		t.Fatalf("Init(%s, Interlock=168): %v", ProfileSingleMsgTripleNoMACMixedV1, err)
	}
	defer mixedSender.Close()
	mixedReceiver, err := Load(mixedBlob)
	if err != nil {
		t.Fatalf("Load(%s): %v", ProfileSingleMsgTripleNoMACMixedV1, err)
	}
	defer mixedReceiver.Close()
	pt := bytes.Repeat([]byte("mixed-512-il168-"), 32)
	wire, err := mixedSender.EncryptMessage(pt)
	if err != nil {
		t.Fatalf("mixed EncryptMessage: %v", err)
	}
	got, err := mixedReceiver.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("mixed DecryptMessage: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("mixed 512-bit Interlock=168 round-trip mismatch")
	}
}

// TestTripleInterlock168InitKeysAndRegister tests InitKeys and Register with
// Interlock="168".
func TestTripleInterlock168InitKeysAndRegister(t *testing.T) {
	var masters [8][]byte
	for i := range masters {
		buf := make([]byte, 32)
		for b := range buf {
			buf[b] = byte((i+1)*37 + b*13 + 7)
		}
		binary.LittleEndian.PutUint64(buf, uint64(0x0102030405060708)*(uint64(i)+1))
		masters[i] = buf
	}
	sender, blob, err := InitKeys(ProfileSingleMsgTripleMACV1, Opts{
		InnerHash: "blake2b512",
		Interlock: itb.Interlock168,
	}, masters)
	if err != nil {
		t.Fatalf("InitKeys: %v", err)
	}
	defer sender.Close()

	receiver, err := Load(blob)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defer receiver.Close()

	pt := []byte("InitKeys 168-bit interlock test message")
	wire, err := sender.EncryptMessage(pt)
	if err != nil {
		t.Fatalf("EncryptMessage: %v", err)
	}
	got, err := receiver.DecryptMessage(wire)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("InitKeys round-trip mismatch")
	}

	// Register a custom 512-bit profile with Interlock="168".
	customName := "custom-singlemsg-512-il168-v1"
	err = Register(customName, Profile{
		Mode:                modeSingleMsgMAC,
		Width:               512,
		InnerHash:           "areion512",
		Interlock:           itb.Interlock168,
		KeyBits:             1024,
		ChunkSize:           itb.DefaultChunkSize,
		MacName:             defaultMacName,
		OuterCipher:         defaultOuterCipher,
		ParallaxPalette:     defaultParallaxPalette(),
		ParallaxSegmentSize: 503,
		Parallax:            true,
		Wrapper:             true,
	})
	if err != nil {
		t.Fatalf("Register(%s): %v", customName, err)
	}
	cPipe, cBlob, err := Init(customName, Opts{})
	if err != nil {
		t.Fatalf("Init(%s): %v", customName, err)
	}
	defer cPipe.Close()
	cProf, err := Inspect(cBlob)
	if err != nil {
		t.Fatalf("Inspect(%s): %v", customName, err)
	}
	if cProf.Interlock != itb.Interlock168 {
		t.Fatalf("Inspect(%s): got Interlock=%q, want 168", customName, cProf.Interlock)
	}

	// Register must reject Interlock="168" on 128-bit and 256-bit hashes, and unknown Interlock values.
	for i, bad := range []Profile{
		{
			Mode: modeSingleMsgMAC, Width: 128, InnerHash: "siphash24", Interlock: itb.Interlock168,
			KeyBits: 1024, MacName: defaultMacName,
		},
		{
			Mode: modeSingleMsgMAC, Width: 256, InnerHash: "areion256", Interlock: itb.Interlock168,
			KeyBits: 1024, MacName: defaultMacName,
		},
		{
			Mode: modeSingleMsgMAC, Width: 512, InnerHash: "areion512", Interlock: "96",
			KeyBits: 1024, MacName: defaultMacName,
		},
	} {
		if err := Register("custom-bad-il-"+string(rune('a'+i)), bad); err == nil {
			t.Fatalf("Register(bad #%d) succeeded, want error", i)
		}
	}
}

// TestTripleInterlock168ValidationAndRejections verifies that Init and Load
// reject Interlock="168" on 128-bit and 256-bit recipes and reject unknown
// Interlock strings.
func TestTripleInterlock168ValidationAndRejections(t *testing.T) {
	// 128-bit hash + Interlock="168" -> rejected.
	if _, _, err := Init(ProfileSingleMsgTripleMACV1, Opts{InnerHash: "siphash24", Interlock: itb.Interlock168}); err == nil {
		t.Fatal("Init(siphash24 + Interlock=168) succeeded, want error")
	}
	if _, _, err := Init(ProfileSingleMsgAESITBMACV1, Opts{Interlock: itb.Interlock168}); err == nil {
		t.Fatal("Init(AESITB128 + Interlock=168) succeeded, want error")
	}
	// 256-bit hash + Interlock="168" -> rejected.
	for _, h := range []string{"areion256", "blake3", "blake2b256", "blake2s", "chacha20"} {
		if _, _, err := Init(ProfileSingleMsgTripleMACV1, Opts{InnerHash: h, Interlock: itb.Interlock168}); err == nil {
			t.Fatalf("Init(%s + Interlock=168) succeeded, want error", h)
		}
	}
	// 128-bit and 256-bit mixed profiles + Interlock="168" -> rejected.
	for _, mp := range []string{
		ProfileStreamingAEADTripleMACMixedV1,
		ProfileStreamingNoAEADTripleMixedV1,
		ProfileSingleMsgTripleMACMixedV1,
	} {
		if _, _, err := Init(mp, Opts{Interlock: itb.Interlock168}); err == nil {
			t.Fatalf("Init(%s + Interlock=168) succeeded, want error", mp)
		}
	}
	// Unknown Interlock string -> rejected.
	if _, _, err := Init(ProfileSingleMsgTripleMACV1, Opts{InnerHash: "blake2b512", Interlock: "96"}); err == nil {
		t.Fatal("Init(Interlock=96) succeeded, want error")
	}

	// Tampered v2 blob tests on Load.
	sender, blob, err := Init(ProfileSingleMsgTripleMACV1, Opts{
		InnerHash: "blake2b512",
		Interlock: itb.Interlock168,
	})
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer sender.Close()

	tamper := func(mut func(p map[string]any)) []byte {
		var wrap map[string]json.RawMessage
		if err := json.Unmarshal(blob, &wrap); err != nil {
			t.Fatal(err)
		}
		var pMap map[string]any
		if err := json.Unmarshal(wrap["p"], &pMap); err != nil {
			t.Fatal(err)
		}
		mut(pMap)
		pb, err := json.Marshal(pMap)
		if err != nil {
			t.Fatal(err)
		}
		wrap["p"] = pb
		out, err := json.Marshal(wrap)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	badIL := tamper(func(p map[string]any) { p["interlock"] = "96" })
	if _, err := Load(badIL); !errors.Is(err, ErrBlobMalformedRecipe) {
		t.Fatalf("Load(interlock=96): got %v, want ErrBlobMalformedRecipe", err)
	}

	badHash := tamper(func(p map[string]any) {
		p["hash"] = "siphash24"
		p["width"] = 128
	})
	if _, err := Load(badHash); !errors.Is(err, ErrBlobMalformedRecipe) {
		t.Fatalf("Load(hash=siphash24 + interlock=168): got %v, want ErrBlobMalformedRecipe", err)
	}
}
