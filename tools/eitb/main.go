// Command eitb runs every example, also wrapping the ITB ciphertext
// in one of three outer stream ciphers (AES-128-CTR, ChaCha20, SipHash-2-4 in CTR mode)
// so the on-wire bytes look like generic outer cipher output rather than ITB native output.
// Outer CTR mode cipher hides ITB nonce, WxH and 32-byte streamID prefix under AEAD mode.
//
// Usage:
//
//	./eitb       # run every example × every cipher
//	./eitb -help # print help
//
// Every run encrypts a non-trivial random plaintext (~1 KiB or ~64 KiB
// depending on the example), wraps the ITB ciphertext under the chosen outer
// cipher, hands the wrapped bytes to a "receiver" path that unwraps and
// decrypts, and verifies sha256 + byte-equality of the recovered plaintext
// against the original plaintext.
//
// The wrapping never modifies the ITB call sites — every example calls into
// ITB exactly as the README.md documents. The wrap layer sits strictly between
// the ITB output and the wire (or between the wire and the ITB input on the
// receive side). ITB's content-deniability guarantee is unchanged; the wrap
// adds the property that the wire looks like AES-128-CTR / ChaCha20 / SipHash-CTR
// output rather than ITB format pixel containers.

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
	"github.com/everanium/itb/easy"
	"github.com/everanium/itb/hashes"
	"github.com/everanium/itb/macs"
	"github.com/everanium/itb/wrapper"
)

// example is one example wrapped under one outer cipher.
type example struct {
	name        string // example identifier, e.g. "aead-easy-io"
	description string
	plaintextN  int // bytes
	run         func(cipherName string, plaintext []byte) (recovered []byte, wireBytes int, err error)
}

func main() {
	exampleFilter := flag.String("example", "", "run only examples whose name contains this substring")
	cipherFilter := flag.String("cipher", "", "run only the given outer cipher")
	verbose := flag.Bool("v", false, "print per-run details")
	flag.Parse()

	itb.SetMaxWorkers(0) // process-wide; harmless for the easy.Encryptor path too

	examples := []example{
		{name: "aead-easy-io", description: "Streaming AEAD Easy (MAC Authenticated, IO-Driven)", plaintextN: 64 * 1024, run: runAEADEasyIO},
		{name: "aead-lowlevel-io", description: "Streaming AEAD Low-Level (MAC Authenticated, IO-Driven)", plaintextN: 64 * 1024, run: runAEADLowLevelIO},
		{name: "noaead-easy-io", description: "Streaming Easy (No MAC, IO-Driven)", plaintextN: 64 * 1024, run: runNoAEADEasyIO},
		{name: "noaead-easy-userloop", description: "Streaming Easy (No MAC, User-Driven Loop)", plaintextN: 64 * 1024, run: runNoAEADEasyUserLoop},
		{name: "noaead-lowlevel-io", description: "Streaming Low-Level (No MAC, IO-Driven)", plaintextN: 64 * 1024, run: runNoAEADLowLevelIO},
		{name: "noaead-lowlevel-userloop", description: "Streaming Low-Level (No MAC, User-Driven Loop)", plaintextN: 64 * 1024, run: runNoAEADLowLevelUserLoop},
		{name: "message-easy-nomac", description: "Easy: Areion-SoEM-512 (No MAC, Single Message)", plaintextN: 1024, run: runMessageEasyNoMAC},
		{name: "message-easy-auth", description: "Easy: Areion-SoEM-512 + HMAC-BLAKE3 (MAC Authenticated, Single Message)", plaintextN: 1024, run: runMessageEasyAuth},
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

// ---------------------------------------------------------------------------
// Streaming AEAD Easy (MAC Authenticated) — IO-Driven.
//
// Sender uses easy.Encryptor.EncryptStreamAuthIO (writes the 32-byte stream
// prefix + per-chunk wire to the inner io.Writer). The format-deniability
// wrap intercepts via NewWrapWriter: ITB writes its bytestream into the
// wrap-writer, which prefixes a fresh outer cipher nonce on the wire and
// XOR-encrypts every byte under (key, nonce). Receiver reverses with
// NewUnwrapReader feeding DecryptStreamAuthIO.
// ---------------------------------------------------------------------------

func runAEADEasyIO(cipherName string, plaintext []byte) ([]byte, int, error) {
	enc := easy.New("areion512", 1024, "hmac-blake3")
	defer enc.Close()
	enc.SetNonceBits(512)
	enc.SetBarrierFill(4)
	enc.SetBitSoup(1)
	enc.SetLockSoup(1)
	enc.SetLockBatch(1)

	outerKey, err := wrapper.GenerateKey(cipherName)
	if err != nil {
		return nil, 0, err
	}

	// Encrypt + wrap
	var wireBuf bytes.Buffer
	wrapWriter, err := wrapper.NewWrapWriter(cipherName, outerKey, &wireBuf)
	if err != nil {
		return nil, 0, err
	}
	chunkSize := 16 * 1024
	if err := enc.EncryptStreamAuthIO(bytes.NewReader(plaintext), wrapWriter, chunkSize); err != nil {
		return nil, 0, err
	}

	// Unwrap + decrypt
	wrappedWire := wireBuf.Bytes()
	unwrapReader, err := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wrappedWire))
	if err != nil {
		return nil, len(wrappedWire), err
	}
	var dstBuf bytes.Buffer
	if err := enc.DecryptStreamAuthIO(unwrapReader, &dstBuf); err != nil {
		return nil, len(wrappedWire), err
	}
	return dstBuf.Bytes(), len(wrappedWire), nil
}

// ---------------------------------------------------------------------------
// Streaming AEAD Low-Level (MAC Authenticated) — IO-Driven.
//
// Drives itb.EncryptStreamAuth / itb.DecryptStreamAuth over the wrap-writer /
// unwrap-reader. Three explicit *Seed512 handles + macs.Make("hmac-blake3").
// ---------------------------------------------------------------------------

func runAEADLowLevelIO(cipherName string, plaintext []byte) ([]byte, int, error) {
	itb.SetNonceBits(512)
	itb.SetBarrierFill(4)
	itb.SetBitSoup(1)
	itb.SetLockSoup(1)
	itb.SetLockBatch(1)

	hashFn, _, _ := hashes.Make512("areion512")
	noise, err := itb.NewSeed512(1024, hashFn)
	if err != nil {
		return nil, 0, err
	}
	data, err := itb.NewSeed512(1024, hashFn)
	if err != nil {
		return nil, 0, err
	}
	start, err := itb.NewSeed512(1024, hashFn)
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
	if err := itb.EncryptStreamAuth(noise, data, start, bytes.NewReader(plaintext), wrapWriter, macFunc, chunkSize); err != nil {
		return nil, 0, err
	}

	wrappedWire := wireBuf.Bytes()
	unwrapReader, err := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wrappedWire))
	if err != nil {
		return nil, len(wrappedWire), err
	}
	var dstBuf bytes.Buffer
	if err := itb.DecryptStreamAuth(noise, data, start, unwrapReader, &dstBuf, macFunc); err != nil {
		return nil, len(wrappedWire), err
	}
	return dstBuf.Bytes(), len(wrappedWire), nil
}

// ---------------------------------------------------------------------------
// Streaming Easy (No MAC) — IO-Driven.
//
// easy.Encryptor.EncryptStreamIO / DecryptStreamIO with the wrap layer in
// between. No MAC ITB has no integrity protection by design; the outer cipher
// is for format-deniability ONLY — does not add integrity.
// ---------------------------------------------------------------------------

func runNoAEADEasyIO(cipherName string, plaintext []byte) ([]byte, int, error) {
	enc := easy.New("areion512", 1024)
	defer enc.Close()
	enc.SetNonceBits(512)
	enc.SetBarrierFill(4)
	enc.SetBitSoup(1)
	enc.SetLockSoup(1)
	enc.SetLockBatch(1)

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
	if err := enc.EncryptStreamIO(bytes.NewReader(plaintext), wrapWriter, chunkSize); err != nil {
		return nil, 0, err
	}

	wrappedWire := wireBuf.Bytes()
	unwrapReader, err := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wrappedWire))
	if err != nil {
		return nil, len(wrappedWire), err
	}
	var dstBuf bytes.Buffer
	if err := enc.DecryptStreamIO(unwrapReader, &dstBuf); err != nil {
		return nil, len(wrappedWire), err
	}
	return dstBuf.Bytes(), len(wrappedWire), nil
}

// ---------------------------------------------------------------------------
// Streaming Easy (No MAC) — User-Driven Loop.
//
// The README's "Alternative — User-Driven Loop" pattern: each chunk is one
// independent enc.Encrypt() call. Format-deniability sends every chunk
// through NewWrapWriter — the per-chunk u32_LE length prefix and the chunk
// body are both written into the wrapped writer, so they pass through the
// keystream XOR together. The receiver reads u32_LE then the body through
// NewUnwrapReader; no length appears in cleartext on the wire.
// ---------------------------------------------------------------------------

func runNoAEADEasyUserLoop(cipherName string, plaintext []byte) ([]byte, int, error) {
	enc := easy.New("areion512", 1024)
	defer enc.Close()
	enc.SetNonceBits(512)
	enc.SetBarrierFill(4)
	enc.SetBitSoup(1)
	enc.SetLockSoup(1)
	enc.SetLockBatch(1)

	outerKey, err := wrapper.GenerateKey(cipherName)
	if err != nil {
		return nil, 0, err
	}

	// Sender — encrypt each chunk and emit `u32_LE_len || ct` through the
	// wrap-writer so both the length and the body XOR through the keystream.
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
		ct, err := enc.Encrypt(buf[:n])
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

	// Receiver — read u32_LE length then body through the unwrap-reader,
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
		dec, err := enc.Decrypt(ctBuf)
		if err != nil {
			return nil, len(wrappedWire), err
		}
		pt.Write(dec)
	}
	return pt.Bytes(), len(wrappedWire), nil
}

// ---------------------------------------------------------------------------
// Streaming Low-Level (No MAC) — IO-Driven.
// ---------------------------------------------------------------------------

func runNoAEADLowLevelIO(cipherName string, plaintext []byte) ([]byte, int, error) {
	itb.SetNonceBits(512)
	itb.SetBarrierFill(4)
	itb.SetBitSoup(1)
	itb.SetLockSoup(1)
	itb.SetLockBatch(1)

	hashFn, _, _ := hashes.Make512("areion512")
	noise, _ := itb.NewSeed512(1024, hashFn)
	data, _ := itb.NewSeed512(1024, hashFn)
	start, _ := itb.NewSeed512(1024, hashFn)

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
	if err := itb.EncryptStream(noise, data, start, bytes.NewReader(plaintext), wrapWriter, chunkSize); err != nil {
		return nil, 0, err
	}

	wrappedWire := wireBuf.Bytes()
	unwrapReader, err := wrapper.NewUnwrapReader(cipherName, outerKey, bytes.NewReader(wrappedWire))
	if err != nil {
		return nil, len(wrappedWire), err
	}
	var dstBuf bytes.Buffer
	if err := itb.DecryptStream(noise, data, start, unwrapReader, &dstBuf); err != nil {
		return nil, len(wrappedWire), err
	}
	return dstBuf.Bytes(), len(wrappedWire), nil
}

// ---------------------------------------------------------------------------
// Streaming Low-Level (No MAC) — User-Driven Loop.
//
// The README's "Alternative — User-Driven Loop" Low-Level variant: per-chunk
// itb.Encrypt() / itb.Decrypt() with caller-side framing. Format-deniability
// emits each chunk through NewWrapWriter as `u32_LE_len || ct`; the length
// prefix and the body XOR through the keystream together, so neither appears
// in cleartext on the wire.
// ---------------------------------------------------------------------------

func runNoAEADLowLevelUserLoop(cipherName string, plaintext []byte) ([]byte, int, error) {
	itb.SetNonceBits(512)
	itb.SetBarrierFill(4)
	itb.SetBitSoup(1)
	itb.SetLockSoup(1)
	itb.SetLockBatch(1)

	hashFn, _, _ := hashes.Make512("areion512")
	noise, _ := itb.NewSeed512(1024, hashFn)
	data, _ := itb.NewSeed512(1024, hashFn)
	start, _ := itb.NewSeed512(1024, hashFn)

	outerKey, err := wrapper.GenerateKey(cipherName)
	if err != nil {
		return nil, 0, err
	}

	// Sender — encrypt each chunk and emit `u32_LE_len || ct` through the
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
		ct, err := itb.Encrypt(noise, data, start, buf[:n])
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

	// Receiver — read u32_LE length then body through the unwrap-reader,
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
		dec, err := itb.Decrypt(noise, data, start, ctBuf)
		if err != nil {
			return nil, len(wrappedWire), err
		}
		pt.Write(dec)
	}
	return pt.Bytes(), len(wrappedWire), nil
}

// ---------------------------------------------------------------------------
// Single Message — Easy: Areion-SoEM-512 (No MAC).
//
// One enc.Encrypt() call → one ITB blob. Wrap seals the whole blob:
// nonce || ks-XOR(blob). Wire shape mirrors any "AES-CTR with a fresh nonce
// and an opaque payload" pattern.
// ---------------------------------------------------------------------------

func runMessageEasyNoMAC(cipherName string, plaintext []byte) ([]byte, int, error) {
	enc := easy.New("areion512", 2048)
	defer enc.Close()
	enc.SetNonceBits(512)
	enc.SetBarrierFill(4)
	enc.SetBitSoup(1)
	enc.SetLockSoup(1)
	enc.SetLockBatch(1)

	encrypted, err := enc.Encrypt(plaintext)
	if err != nil {
		return nil, 0, err
	}

	outerKey, err := wrapper.GenerateKey(cipherName)
	if err != nil {
		return nil, 0, err
	}
	// Wrap respects immutability of `encrypted` (allocates a fresh wire buffer).
	// wire, err := wrapper.Wrap(cipherName, outerKey, encrypted)
	// if err != nil {
	// 	return nil, 0, err
	// }
	nonce, err := wrapper.WrapInPlace(cipherName, outerKey, encrypted)
	if err != nil {
		return nil, 0, err
	}
	wire := append(nonce, encrypted...)

	// Receiver
	// Unwrap respects immutability of `wire` (allocates a fresh recovered buffer).
	// recovered, err := wrapper.Unwrap(cipherName, outerKey, wire)
	// if err != nil {
	// 	return nil, len(wire), err
	// }
	recovered, err := wrapper.UnwrapInPlace(cipherName, outerKey, wire)
	if err != nil {
		return nil, len(wire), err
	}
	pt, err := enc.Decrypt(recovered)
	if err != nil {
		return nil, len(wire), err
	}
	return pt, len(wire), nil
}

// ---------------------------------------------------------------------------
// Single Message — Easy: Areion-SoEM-512 + HMAC-BLAKE3
// (MAC Authenticated).
//
// EncryptAuth / DecryptAuth pair, again Wrap over the whole ITB output.
// ITB-internal MAC verifies on decrypt; outer cipher contributes
// format-deniability only.
// ---------------------------------------------------------------------------

func runMessageEasyAuth(cipherName string, plaintext []byte) ([]byte, int, error) {
	enc := easy.New("areion512", 2048, "hmac-blake3")
	defer enc.Close()
	enc.SetNonceBits(512)
	enc.SetBarrierFill(4)
	enc.SetBitSoup(1)
	enc.SetLockSoup(1)
	enc.SetLockBatch(1)

	encrypted, err := enc.EncryptAuth(plaintext)
	if err != nil {
		return nil, 0, err
	}

	outerKey, err := wrapper.GenerateKey(cipherName)
	if err != nil {
		return nil, 0, err
	}
	// Wrap respects immutability of `encrypted` (allocates a fresh wire buffer).
	// wire, err := wrapper.Wrap(cipherName, outerKey, encrypted)
	// if err != nil {
	// 	return nil, 0, err
	// }
	nonce, err := wrapper.WrapInPlace(cipherName, outerKey, encrypted)
	if err != nil {
		return nil, 0, err
	}
	wire := append(nonce, encrypted...)

	// Unwrap respects immutability of `wire` (allocates a fresh recovered buffer).
	// recovered, err := wrapper.Unwrap(cipherName, outerKey, wire)
	// if err != nil {
	// 	return nil, len(wire), err
	// }
	recovered, err := wrapper.UnwrapInPlace(cipherName, outerKey, wire)
	if err != nil {
		return nil, len(wire), err
	}
	pt, err := enc.DecryptAuth(recovered)
	if err != nil {
		return nil, len(wire), err
	}
	return pt, len(wire), nil
}

// ---------------------------------------------------------------------------
// Single Message — Low-Level: Areion-SoEM-512 (No MAC).
//
// Drives the width-less itb.Encrypt / itb.Decrypt helpers with three explicit
// *Seed512 handles built from the Areion-SoEM-512 hash factory at the same
// 2048-bit seed width used by the Easy Single Message variant. One Encrypt call
// → one ITB blob; Wrap seals the whole blob: nonce || ks-XOR(blob).
// ---------------------------------------------------------------------------

func runMessageLowLevelNoMAC(cipherName string, plaintext []byte) ([]byte, int, error) {
	itb.SetNonceBits(512)
	itb.SetBarrierFill(4)
	itb.SetBitSoup(1)
	itb.SetLockSoup(1)
	itb.SetLockBatch(1)

	hashFn, _, _ := hashes.Make512("areion512")
	noise, err := itb.NewSeed512(2048, hashFn)
	if err != nil {
		return nil, 0, err
	}
	data, err := itb.NewSeed512(2048, hashFn)
	if err != nil {
		return nil, 0, err
	}
	start, err := itb.NewSeed512(2048, hashFn)
	if err != nil {
		return nil, 0, err
	}

	encrypted, err := itb.Encrypt(noise, data, start, plaintext)
	if err != nil {
		return nil, 0, err
	}

	outerKey, err := wrapper.GenerateKey(cipherName)
	if err != nil {
		return nil, 0, err
	}
	// Wrap respects immutability of `encrypted` (allocates a fresh wire buffer).
	// wire, err := wrapper.Wrap(cipherName, outerKey, encrypted)
	// if err != nil {
	// 	return nil, 0, err
	// }
	nonce, err := wrapper.WrapInPlace(cipherName, outerKey, encrypted)
	if err != nil {
		return nil, 0, err
	}
	wire := append(nonce, encrypted...)

	// Receiver
	// Unwrap respects immutability of `wire` (allocates a fresh recovered buffer).
	// recovered, err := wrapper.Unwrap(cipherName, outerKey, wire)
	// if err != nil {
	// 	return nil, len(wire), err
	// }
	recovered, err := wrapper.UnwrapInPlace(cipherName, outerKey, wire)
	if err != nil {
		return nil, len(wire), err
	}
	pt, err := itb.Decrypt(noise, data, start, recovered)
	if err != nil {
		return nil, len(wire), err
	}
	return pt, len(wire), nil
}

// ---------------------------------------------------------------------------
// Single Message — Low-Level: Areion-SoEM-512 + HMAC-BLAKE3
// (MAC Authenticated).
//
// Drives the width-less itb.EncryptAuth / itb.DecryptAuth helpers with three
// explicit *Seed512 handles plus a macs.Make("hmac-blake3", key) closure.
// Wrap shape mirrors the No MAC variant — one ITB blob, sealed in toto by
// the outer cipher. ITB-internal MAC verifies on decrypt; outer cipher
// contributes format-deniability only.
// ---------------------------------------------------------------------------

func runMessageLowLevelAuth(cipherName string, plaintext []byte) ([]byte, int, error) {
	itb.SetNonceBits(512)
	itb.SetBarrierFill(4)
	itb.SetBitSoup(1)
	itb.SetLockSoup(1)
	itb.SetLockBatch(1)

	hashFn, _, _ := hashes.Make512("areion512")
	noise, err := itb.NewSeed512(2048, hashFn)
	if err != nil {
		return nil, 0, err
	}
	data, err := itb.NewSeed512(2048, hashFn)
	if err != nil {
		return nil, 0, err
	}
	start, err := itb.NewSeed512(2048, hashFn)
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

	encrypted, err := itb.EncryptAuth(noise, data, start, plaintext, macFunc)
	if err != nil {
		return nil, 0, err
	}

	outerKey, err := wrapper.GenerateKey(cipherName)
	if err != nil {
		return nil, 0, err
	}
	// Wrap respects immutability of `encrypted` (allocates a fresh wire buffer).
	// wire, err := wrapper.Wrap(cipherName, outerKey, encrypted)
	// if err != nil {
	// 	return nil, 0, err
	// }
	nonce, err := wrapper.WrapInPlace(cipherName, outerKey, encrypted)
	if err != nil {
		return nil, 0, err
	}
	wire := append(nonce, encrypted...)

	// Receiver
	// Unwrap respects immutability of `wire` (allocates a fresh recovered buffer).
	// recovered, err := wrapper.Unwrap(cipherName, outerKey, wire)
	// if err != nil {
	// 	return nil, len(wire), err
	// }
	recovered, err := wrapper.UnwrapInPlace(cipherName, outerKey, wire)
	if err != nil {
		return nil, len(wire), err
	}
	pt, err := itb.DecryptAuth(noise, data, start, recovered, macFunc)
	if err != nil {
		return nil, len(wire), err
	}
	return pt, len(wire), nil
}
