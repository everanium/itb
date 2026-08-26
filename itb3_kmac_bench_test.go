// KMAC256-profile Triple facade benchmarks. Companion cohort to
// itb3_ext_test.go: where the ExtTriple benches sweep the inner-hash
// primitive dimension, this file pins one canonical cipher
// configuration (Areion-SoEM-512 inner hash, 1024-bit keys, 512-bit
// nonce, parallax off, wrapper off) and turns the MAC dimension to
// KMAC256, so the AVX-512 Keccak-f[1600] tier in
// macs/internal/keccakasm is measured end-to-end through both wire
// shapes (Single Message MAC and Streaming AEAD MAC), both
// directions, at 1 / 16 / 64 MB. Build with -tags noitbasm for the
// scalar-tier baseline of the same twelve cells.
package itb_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/everanium/itb/triple"
)

// kmacBenchPipeline builds the canonical KMAC256 bench Pipeline for
// the given profile: Areion-SoEM-512 inner hash, 1024-bit key,
// 512-bit nonce, MAC pinned to kmac256, parallax and wrapper forced
// off.
func kmacBenchPipeline(b *testing.B, profile string) *triple.Pipeline {
	b.Helper()
	off := false
	p, _, err := triple.Init(profile, triple.Opts{
		InnerHash:    "areion512",
		KeyBits:      1024,
		NonceBits:    512,
		MacName:      "kmac256",
		WithParallax: &off,
		WithWrapper:  &off,
	})
	if err != nil {
		b.Fatalf("triple.Init(%s): %v", profile, err)
	}
	return p
}

func benchKMAC256MsgEncrypt(b *testing.B, size int) {
	p := kmacBenchPipeline(b, triple.ProfileSingleMsgTripleMACV1)
	defer p.Close()
	plain := bytes.Repeat([]byte{0xA7}, size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.EncryptMessage(plain); err != nil {
			b.Fatal(err)
		}
	}
}

func benchKMAC256MsgDecrypt(b *testing.B, size int) {
	p := kmacBenchPipeline(b, triple.ProfileSingleMsgTripleMACV1)
	defer p.Close()
	plain := bytes.Repeat([]byte{0xA7}, size)
	wire, err := p.EncryptMessage(plain)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.DecryptMessage(wire); err != nil {
			b.Fatal(err)
		}
	}
}

func benchKMAC256StreamEncrypt(b *testing.B, size int) {
	p := kmacBenchPipeline(b, triple.ProfileStreamingAEADTripleMACV1)
	defer p.Close()
	plain := bytes.Repeat([]byte{0xA7}, size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := p.EncryptStream(bytes.NewReader(plain), io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func benchKMAC256StreamDecrypt(b *testing.B, size int) {
	p := kmacBenchPipeline(b, triple.ProfileStreamingAEADTripleMACV1)
	defer p.Close()
	plain := bytes.Repeat([]byte{0xA7}, size)
	var wire bytes.Buffer
	if err := p.EncryptStream(bytes.NewReader(plain), &wire); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := p.DecryptStream(bytes.NewReader(wire.Bytes()), io.Discard); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExtKMAC256_Msg_Encrypt_1MB(b *testing.B)  { benchKMAC256MsgEncrypt(b, 1<<20) }
func BenchmarkExtKMAC256_Msg_Encrypt_16MB(b *testing.B) { benchKMAC256MsgEncrypt(b, 16<<20) }
func BenchmarkExtKMAC256_Msg_Encrypt_64MB(b *testing.B) { benchKMAC256MsgEncrypt(b, 64<<20) }
func BenchmarkExtKMAC256_Msg_Decrypt_1MB(b *testing.B)  { benchKMAC256MsgDecrypt(b, 1<<20) }
func BenchmarkExtKMAC256_Msg_Decrypt_16MB(b *testing.B) { benchKMAC256MsgDecrypt(b, 16<<20) }
func BenchmarkExtKMAC256_Msg_Decrypt_64MB(b *testing.B) { benchKMAC256MsgDecrypt(b, 64<<20) }

func BenchmarkExtKMAC256_Stream_Encrypt_1MB(b *testing.B)  { benchKMAC256StreamEncrypt(b, 1<<20) }
func BenchmarkExtKMAC256_Stream_Encrypt_16MB(b *testing.B) { benchKMAC256StreamEncrypt(b, 16<<20) }
func BenchmarkExtKMAC256_Stream_Encrypt_64MB(b *testing.B) { benchKMAC256StreamEncrypt(b, 64<<20) }
func BenchmarkExtKMAC256_Stream_Decrypt_1MB(b *testing.B)  { benchKMAC256StreamDecrypt(b, 1<<20) }
func BenchmarkExtKMAC256_Stream_Decrypt_16MB(b *testing.B) { benchKMAC256StreamDecrypt(b, 16<<20) }
func BenchmarkExtKMAC256_Stream_Decrypt_64MB(b *testing.B) { benchKMAC256StreamDecrypt(b, 64<<20) }
