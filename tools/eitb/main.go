// Command eitb runs every triple.Pipeline example, also wrapping the
// ITB ciphertext in one of the supported outer stream ciphers (see
// wrapper.CipherNames) so the on-wire bytes look like generic outer
// cipher output rather than ITB native output. Outer CTR mode cipher
// hides ITB nonce, WxH and 32-byte streamID prefix under AEAD mode.
//
// Usage:
//
//	./eitb       # run every example x every cipher
//	./eitb -help # print help
//
// Every run encrypts a non-trivial random plaintext (~1 KiB or ~64 KiB
// depending on the example), wraps the ITB ciphertext under the chosen
// outer cipher, hands the wrapped bytes to a "receiver" path that
// unwraps and decrypts, and verifies sha256 + byte-equality of the
// recovered plaintext against the original plaintext.
//
// The wrapping never modifies the ITB call sites - every example calls
// into ITB exactly as the README.md documents. The wrap layer sits
// strictly between the ITB output and the wire (or between the wire
// and the ITB input on the receive side). ITB's content-deniability
// guarantee is unchanged; the wrap adds the property that the wire
// looks like generic outer stream cipher output rather than ITB
// format pixel containers.
//
// The demo exercises the Triple Ouroboros surface only through the
// [triple.Pipeline] facade: every example call passes through
// [triple.Init] / [triple.Open] against one of the shipped profiles,
// with parallax and wrapper toggles chosen per example so the demo
// covers both the toggle-off (pure Low-Level pass-through) and
// toggle-on (full-stack) shapes.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/everanium/itb"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/triple"
	"github.com/everanium/itb/wrapper"
)

// example is one example wrapped under one outer cipher.
type example struct {
	name        string // example identifier, e.g. "aead-triple-io"
	description string
	plaintextN  int // bytes
	run         func(cipherName string, plaintext []byte) (recovered []byte, wireBytes int, err error)
}

func main() {
	exampleFilter := flag.String("example", "", "run only examples whose name contains this substring")
	cipherFilter := flag.String("cipher", "", "run only the given outer cipher")
	verbose := flag.Bool("v", false, "print per-run details")
	flag.Parse()

	examples := []example{
		{name: "aead-triple-io", description: "Streaming AEAD Triple (MAC Authenticated, IO-Driven, full stack)", plaintextN: 64 * 1024, run: runAEADTripleIO},
		{name: "aead-lowlevel-io", description: "Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)", plaintextN: 64 * 1024, run: runAEADLowLevelIO},
		{name: "noaead-triple-io", description: "Streaming Triple (No MAC, IO-Driven, full stack)", plaintextN: 64 * 1024, run: runNoAEADTripleIO},
		{name: "noaead-lowlevel-io", description: "Streaming Low-Level (No MAC, IO-Driven)", plaintextN: 64 * 1024, run: runNoAEADLowLevelIO},
		{name: "noaead-lowlevel-userloop", description: "Streaming Low-Level (No MAC, User-Driven Loop)", plaintextN: 64 * 1024, run: runNoAEADLowLevelUserLoop},
		{name: "message-triple-nomac", description: "Triple: Areion-SoEM-512 (No MAC, Single Message)", plaintextN: 1024, run: runMessageTripleNoMAC},
		{name: "message-triple-auth", description: "Triple: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)", plaintextN: 1024, run: runMessageTripleAuth},
		{name: "message-lowlevel-nomac", description: "Low-Level: Areion-SoEM-512 (No MAC, Single Message)", plaintextN: 1024, run: runMessageLowLevelNoMAC},
		{name: "message-lowlevel-auth", description: "Low-Level: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)", plaintextN: 1024, run: runMessageLowLevelAuth},
	}

	type result struct {
		example string
		cipher  string
		ok      bool
		err     error
		wireN   int
		ptN     int
	}

	var results []result
	pass, fail := 0, 0
	for _, ex := range examples {
		if *exampleFilter != "" && !strings.Contains(ex.name, *exampleFilter) {
			continue
		}
		for _, cn := range wrapper.CipherNames {
			if *cipherFilter != "" && cn != *cipherFilter {
				continue
			}
			plaintext := make([]byte, ex.plaintextN)
			if _, err := rand.Read(plaintext); err != nil {
				panic(err)
			}
			ptHash := sha256.Sum256(plaintext)
			recovered, wireN, err := ex.run(cn, plaintext)
			ok := err == nil && bytes.Equal(plaintext, recovered)
			r := result{example: ex.name, cipher: cn, ok: ok, err: err, wireN: wireN, ptN: ex.plaintextN}
			if ok {
				pass++
			} else {
				fail++
				if err == nil {
					rcvHash := sha256.Sum256(recovered)
					r.err = fmt.Errorf("plaintext hash mismatch: pt=%s rcv=%s", hex.EncodeToString(ptHash[:8]), hex.EncodeToString(rcvHash[:8]))
				}
			}
			results = append(results, r)
			tag := "PASS"
			if !ok {
				tag = "FAIL"
			}
			line := fmt.Sprintf("[%s] %-26s + %-8s   pt=%d wire=%d", tag, ex.name, cn, r.ptN, r.wireN)
			if !ok {
				line += fmt.Sprintf("  err: %v", r.err)
			}
			fmt.Println(line)
			if *verbose && ok {
				ptH := sha256.Sum256(plaintext)
				rcvH := sha256.Sum256(recovered)
				fmt.Printf("       pt sha256:  %s\n", hex.EncodeToString(ptH[:]))
				fmt.Printf("       rcv sha256: %s\n", hex.EncodeToString(rcvH[:]))
			}
		}
	}

	fmt.Println()
	fmt.Printf("=== Summary: %d PASS, %d FAIL ===\n", pass, fail)
	// Stable matrix print
	sort.Slice(results, func(i, j int) bool {
		if results[i].example != results[j].example {
			return results[i].example < results[j].example
		}
		return results[i].cipher < results[j].cipher
	})
	if fail > 0 {
		os.Exit(1)
	}
}

// eightSeeds512 constructs the eight *Seed512 handles that every Triple
// Ouroboros entry point takes: noiseSeed, lockSeed, dataSeed1..3,
// startSeed1..3. Every seed is allocated under the same primitive here
// for demonstration simplicity; the API allows mixing primitives across
// slots so long as every seed carries the same native width.
func eightSeeds512(primitive string, bits int) (noise, lock, data1, data2, data3, start1, start2, start3 *itb.Seed512, err error) {
	hashFn, _, err := hashes.Make512(primitive)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, nil, nil, err
	}
	seeds := make([]*itb.Seed512, 8)
	for i := range seeds {
		s, err := itb.NewSeed512(bits, hashFn)
		if err != nil {
			return nil, nil, nil, nil, nil, nil, nil, nil, err
		}
		seeds[i] = s
	}
	return seeds[0], seeds[1], seeds[2], seeds[3], seeds[4], seeds[5], seeds[6], seeds[7], nil
}

// tripleOpts512 returns the [triple.Opts] shape the eitb demonstrator
// runs pin: 512-bit nonce, barrier-fill 4, and the requested outer
// cipher. Every eitb-side triple.Init call feeds the same knobs so the
// wire shape matches the Low-Level runs' explicit [itb.Config]
// (NonceBits=512, BarrierFill=4).
func tripleOpts512(cipherName string) triple.Opts {
	return triple.Opts{
		NonceBits:   512,
		BarrierFill: 4,
		OuterCipher: cipherName,
	}
}

// lowLevelCfg512 returns the *itb.Config the Low-Level demonstrator
// paths pass to every Cfg-suffixed entry point so the wire shape
// matches the triple.Pipeline runs' Opts (NonceBits=512, BarrierFill=4).
func lowLevelCfg512() *itb.Config {
	return &itb.Config{NonceBits: 512, BarrierFill: 4}
}

// ---------------------------------------------------------------------------
// Streaming AEAD Triple (MAC Authenticated) - IO-Driven, full stack.
//
// Sender builds a Streaming AEAD Triple Pipeline with the default
// full-stack profile (parallax on + wrapper on + MAC on) — the outer
// cipher chosen here is what the Pipeline's built-in wrapper layer
// uses, so no external Wrap step is needed. The Pipeline's wire bytes
// already carry the outer cipher keystream envelope.
// ---------------------------------------------------------------------------

func runAEADTripleIO(cipherName string, plaintext []byte) ([]byte, int, error) {
	opts := tripleOpts512(cipherName)
	sender, blob, err := triple.Init(triple.ProfileStreamingAEADTripleMACV1, opts)
	if err != nil {
		return nil, 0, err
	}
	defer sender.Close()

	receiver, err := triple.Open(triple.ProfileStreamingAEADTripleMACV1, blob, opts)
	if err != nil {
		return nil, 0, err
	}
	defer receiver.Close()

	var wireBuf bytes.Buffer
	if err := sender.EncryptStream(bytes.NewReader(plaintext), &wireBuf); err != nil {
		return nil, 0, err
	}
	wire := wireBuf.Bytes()

	var dstBuf bytes.Buffer
	if err := receiver.DecryptStream(bytes.NewReader(wire), &dstBuf); err != nil {
		return nil, len(wire), err
	}
	return dstBuf.Bytes(), len(wire), nil
}

// ---------------------------------------------------------------------------
// Streaming AEAD Low-Level (MAC Authenticated) - IO-Driven.
//
// Drives itb.EncryptStreamAuth3x / itb.DecryptStreamAuth3x over the
// wrap-writer / unwrap-reader. Eight explicit *Seed512 handles (noise, lock,
// dataSeed1..3, startSeed1..3) + macs.Make("hmac-blake3").
// ---------------------------------------------------------------------------

func runAEADLowLevelIO(cipherName string, plaintext []byte) ([]byte, int, error) {
	cfg := lowLevelCfg512()

	noise, lock, data1, data2, data3, start1, start2, start3, err := eightSeeds512("areion512", 1024)
	if err != nil {
		return nil, 0, err
	}

	macKey := make([]byte, 32)
	if _, err := rand.Read(macKey); err != nil {
		return nil, 0, err
	}
	macFunc, err := macs.Make("hmac-blake3", macKey)
	if err != nil {
		return nil, 0, err
	}

	outerKey, err := wrapper.GenerateKey(cipherName)
	if err != nil {
		return nil, 0, err
	}

	var wireBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cipherName, outerKey, &wireBuf)
	if err != nil {
		return nil, 0, err
	}
	chunkSize := 16 * 1024
	if err := itb.EncryptStreamAuth3xCfg(cfg, noise, lock, data1, data2, data3, start1, start2, start3, bytes.NewReader(plaintext), wrapWriter, macFunc, chunkSize); err != nil {
		return nil, 0, err
	}

	wrappedWire := wireBuf.Bytes()
	unwrapReader, err := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wrappedWire))
	if err != nil {
		return nil, len(wrappedWire), err
	}
	var dstBuf bytes.Buffer
	if err := itb.DecryptStreamAuth3xCfg(cfg, noise, lock, data1, data2, data3, start1, start2, start3, unwrapReader, &dstBuf, macFunc); err != nil {
		return nil, len(wrappedWire), err
	}
	return dstBuf.Bytes(), len(wrappedWire), nil
}

// ---------------------------------------------------------------------------
// Streaming Triple (No MAC) - IO-Driven, full stack.
//
// Streaming Non-AEAD Triple Pipeline with parallax on + wrapper on.
// No MAC ITB has no integrity protection by design; the outer cipher
// contributes format-deniability only. The Pipeline's own wrapper
// layer produces the outer cipher envelope.
// ---------------------------------------------------------------------------

func runNoAEADTripleIO(cipherName string, plaintext []byte) ([]byte, int, error) {
	opts := tripleOpts512(cipherName)
	sender, blob, err := triple.Init(triple.ProfileStreamingNoAEADTripleV1, opts)
	if err != nil {
		return nil, 0, err
	}
	defer sender.Close()

	receiver, err := triple.Open(triple.ProfileStreamingNoAEADTripleV1, blob, opts)
	if err != nil {
		return nil, 0, err
	}
	defer receiver.Close()

	var wireBuf bytes.Buffer
	if err := sender.EncryptStream(bytes.NewReader(plaintext), &wireBuf); err != nil {
		return nil, 0, err
	}
	wire := wireBuf.Bytes()

	var dstBuf bytes.Buffer
	if err := receiver.DecryptStream(bytes.NewReader(wire), &dstBuf); err != nil {
		return nil, len(wire), err
	}
	return dstBuf.Bytes(), len(wire), nil
}

// ---------------------------------------------------------------------------
// Streaming Low-Level (No MAC) - IO-Driven.
// ---------------------------------------------------------------------------

func runNoAEADLowLevelIO(cipherName string, plaintext []byte) ([]byte, int, error) {
	cfg := lowLevelCfg512()

	noise, lock, data1, data2, data3, start1, start2, start3, err := eightSeeds512("areion512", 1024)
	if err != nil {
		return nil, 0, err
	}

	outerKey, err := wrapper.GenerateKey(cipherName)
	if err != nil {
		return nil, 0, err
	}
	var wireBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cipherName, outerKey, &wireBuf)
	if err != nil {
		return nil, 0, err
	}
	chunkSize := 16 * 1024
	if err := itb.EncryptStream3xCfg(cfg, noise, lock, data1, data2, data3, start1, start2, start3, bytes.NewReader(plaintext), wrapWriter, chunkSize); err != nil {
		return nil, 0, err
	}

	wrappedWire := wireBuf.Bytes()
	unwrapReader, err := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wrappedWire))
	if err != nil {
		return nil, len(wrappedWire), err
	}
	var dstBuf bytes.Buffer
	if err := itb.DecryptStream3xCfg(cfg, noise, lock, data1, data2, data3, start1, start2, start3, unwrapReader, &dstBuf); err != nil {
		return nil, len(wrappedWire), err
	}
	return dstBuf.Bytes(), len(wrappedWire), nil
}

// ---------------------------------------------------------------------------
// Streaming Low-Level (No MAC) - User-Driven Loop.
//
// The README's "Alternative - User-Driven Loop" Low-Level variant: per-chunk
// itb.Encrypt3x / itb.Decrypt3x with caller-side framing. Format-deniability
// emits each chunk through NewWrapWriter as `u32_LE_len || ct`; the length
// prefix and the body XOR through the keystream together, so neither appears
// in cleartext on the wire.
// ---------------------------------------------------------------------------

func runNoAEADLowLevelUserLoop(cipherName string, plaintext []byte) ([]byte, int, error) {
	cfg := lowLevelCfg512()

	noise, lock, data1, data2, data3, start1, start2, start3, err := eightSeeds512("areion512", 1024)
	if err != nil {
		return nil, 0, err
	}

	outerKey, err := wrapper.GenerateKey(cipherName)
	if err != nil {
		return nil, 0, err
	}

	// Sender - encrypt each chunk and emit `u32_LE_len || ct` through the
	// wrap-writer.
	var wireBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cipherName, outerKey, &wireBuf)
	if err != nil {
		return nil, 0, err
	}
	chunkSize := 16 * 1024
	src := bytes.NewReader(plaintext)
	buf := make([]byte, chunkSize)
	for {
		n, rerr := io.ReadFull(src, buf)
		if rerr == io.EOF {
			break
		}
		if rerr != nil && rerr != io.ErrUnexpectedEOF {
			return nil, 0, rerr
		}
		ct, err := itb.Encrypt3x512Cfg(cfg, noise, lock, data1, data2, data3, start1, start2, start3, buf[:n])
		if err != nil {
			return nil, 0, err
		}
		if err := binary.Write(wrapWriter, binary.LittleEndian, uint32(len(ct))); err != nil {
			return nil, 0, err
		}
		if _, err := wrapWriter.Write(ct); err != nil {
			return nil, 0, err
		}
		if rerr == io.ErrUnexpectedEOF {
			break
		}
	}

	// Receiver - read u32_LE length then body through the unwrap-reader,
	// looping until EOF on the length-prefix read.
	wrappedWire := wireBuf.Bytes()
	unwrapReader, err := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wrappedWire))
	if err != nil {
		return nil, len(wrappedWire), err
	}
	var pt bytes.Buffer
	for {
		var ctLen uint32
		if err := binary.Read(unwrapReader, binary.LittleEndian, &ctLen); err != nil {
			if err == io.EOF {
				break
			}
			return nil, len(wrappedWire), err
		}
		ctBuf := make([]byte, ctLen)
		if _, err := io.ReadFull(unwrapReader, ctBuf); err != nil {
			return nil, len(wrappedWire), err
		}
		dec, err := itb.Decrypt3x512Cfg(cfg, noise, lock, data1, data2, data3, start1, start2, start3, ctBuf)
		if err != nil {
			return nil, len(wrappedWire), err
		}
		pt.Write(dec)
	}
	return pt.Bytes(), len(wrappedWire), nil
}

// ---------------------------------------------------------------------------
// Single Message - Triple: Areion-SoEM-512 (No MAC), full stack.
//
// One EncryptMessage call -> one wire. The Pipeline runs with parallax
// on + wrapper on + No MAC — the outer cipher chosen here is what the
// Pipeline's internal wrapper layer keystream-XORs the wire with, so
// no external Wrap step is needed.
// ---------------------------------------------------------------------------

func runMessageTripleNoMAC(cipherName string, plaintext []byte) ([]byte, int, error) {
	opts := tripleOpts512(cipherName)
	sender, blob, err := triple.Init(triple.ProfileSingleMsgTripleNoMACV1, opts)
	if err != nil {
		return nil, 0, err
	}
	defer sender.Close()

	receiver, err := triple.Open(triple.ProfileSingleMsgTripleNoMACV1, blob, opts)
	if err != nil {
		return nil, 0, err
	}
	defer receiver.Close()

	wire, err := sender.EncryptMessage(plaintext)
	if err != nil {
		return nil, 0, err
	}
	pt, err := receiver.DecryptMessage(wire)
	if err != nil {
		return nil, len(wire), err
	}
	return pt, len(wire), nil
}

// ---------------------------------------------------------------------------
// Single Message - Triple: Areion-SoEM-512 + HMAC-BLAKE3 (MAC), full stack.
//
// EncryptMessage / DecryptMessage on a Single Message MAC-authenticated
// Triple Pipeline. The Pipeline's outer wrapper covers the wire in
// exactly one keystream envelope; the internal MAC verifies on decrypt
// as usual.
// ---------------------------------------------------------------------------

func runMessageTripleAuth(cipherName string, plaintext []byte) ([]byte, int, error) {
	opts := tripleOpts512(cipherName)
	sender, blob, err := triple.Init(triple.ProfileSingleMsgTripleMACV1, opts)
	if err != nil {
		return nil, 0, err
	}
	defer sender.Close()

	receiver, err := triple.Open(triple.ProfileSingleMsgTripleMACV1, blob, opts)
	if err != nil {
		return nil, 0, err
	}
	defer receiver.Close()

	wire, err := sender.EncryptMessage(plaintext)
	if err != nil {
		return nil, 0, err
	}
	pt, err := receiver.DecryptMessage(wire)
	if err != nil {
		return nil, len(wire), err
	}
	return pt, len(wire), nil
}

// ---------------------------------------------------------------------------
// Single Message - Low-Level: Areion-SoEM-512 (No MAC).
//
// Drives the width-less itb.Encrypt3x / itb.Decrypt3x helpers with eight
// explicit *Seed512 handles (noise, lock, dataSeed1..3, startSeed1..3) built
// from the Areion-SoEM-512 hash factory at the same 2048-bit seed width used
// by the Triple Single Message variant. One Encrypt3x call -> one ITB blob;
// Wrap seals the whole blob: nonce || ks-XOR(blob).
// ---------------------------------------------------------------------------

func runMessageLowLevelNoMAC(cipherName string, plaintext []byte) ([]byte, int, error) {
	cfg := lowLevelCfg512()

	noise, lock, data1, data2, data3, start1, start2, start3, err := eightSeeds512("areion512", 2048)
	if err != nil {
		return nil, 0, err
	}

	encrypted, err := itb.Encrypt3x512Cfg(cfg, noise, lock, data1, data2, data3, start1, start2, start3, plaintext)
	if err != nil {
		return nil, 0, err
	}

	outerKey, err := wrapper.GenerateKey(cipherName)
	if err != nil {
		return nil, 0, err
	}
	nonce, err := wrapper.WrapInPlace(cipherName, outerKey, encrypted)
	if err != nil {
		return nil, 0, err
	}
	wire := append(nonce, encrypted...)

	recovered, err := wrapper.UnwrapInPlace(cipherName, outerKey, wire)
	if err != nil {
		return nil, len(wire), err
	}
	pt, err := itb.Decrypt3x512Cfg(cfg, noise, lock, data1, data2, data3, start1, start2, start3, recovered)
	if err != nil {
		return nil, len(wire), err
	}
	return pt, len(wire), nil
}

// ---------------------------------------------------------------------------
// Single Message - Low-Level: Areion-SoEM-512 + HMAC-BLAKE3
// (MAC Authenticated).
//
// Drives the width-less itb.EncryptAuth3x / itb.DecryptAuth3x helpers with
// eight explicit *Seed512 handles (noise, lock, dataSeed1..3, startSeed1..3)
// plus a macs.Make("hmac-blake3", key) closure. Wrap shape mirrors the No MAC
// variant - one ITB blob, sealed in toto by the outer cipher. ITB-internal MAC
// verifies on decrypt; outer cipher contributes format-deniability only.
// ---------------------------------------------------------------------------

func runMessageLowLevelAuth(cipherName string, plaintext []byte) ([]byte, int, error) {
	cfg := lowLevelCfg512()

	noise, lock, data1, data2, data3, start1, start2, start3, err := eightSeeds512("areion512", 2048)
	if err != nil {
		return nil, 0, err
	}

	macKey := make([]byte, 32)
	if _, err := rand.Read(macKey); err != nil {
		return nil, 0, err
	}
	macFunc, err := macs.Make("hmac-blake3", macKey)
	if err != nil {
		return nil, 0, err
	}

	encrypted, err := itb.EncryptAuth3x512Cfg(cfg, noise, lock, data1, data2, data3, start1, start2, start3, plaintext, macFunc)
	if err != nil {
		return nil, 0, err
	}

	outerKey, err := wrapper.GenerateKey(cipherName)
	if err != nil {
		return nil, 0, err
	}
	nonce, err := wrapper.WrapInPlace(cipherName, outerKey, encrypted)
	if err != nil {
		return nil, 0, err
	}
	wire := append(nonce, encrypted...)

	recovered, err := wrapper.UnwrapInPlace(cipherName, outerKey, wire)
	if err != nil {
		return nil, len(wire), err
	}
	pt, err := itb.DecryptAuth3x512Cfg(cfg, noise, lock, data1, data2, data3, start1, start2, start3, recovered, macFunc)
	if err != nil {
		return nil, len(wire), err
	}
	return pt, len(wire), nil
}
