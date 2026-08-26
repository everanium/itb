package macs

import (
	"bytes"
	"math/rand"
	"testing"

	"golang.org/x/crypto/sha3"
	xcpu "golang.org/x/sys/cpu"

	"github.com/everanium/itb/macs/internal/keccakasm"
)

// refKMAC256 computes KMAC256(K, X, 256, S) through x/crypto's
// cSHAKE256 directly — an in-test reference arm independent of the
// dispatch inside KMAC256WithCustomization, used as the parity oracle
// for the AVX-512 tier.
func refKMAC256(key, customization, data []byte) []byte {
	h := sha3.NewCShake256([]byte("KMAC"), customization)
	h.Write(bytepad(encodeString(key), 136))
	h.Write(data)
	h.Write(rightEncode(256))
	out := make([]byte, 32)
	h.Read(out)
	return out
}

// TestKMAC256AsmPathSelected pins the dispatcher: on a host whose
// CPUID carries the AVX-512 F/BW/VL/DQ baseline (and on a build that
// compiled the kernel in), the vendored path must be engaged — a
// silent scalar fallback on capable hosts would leave the kernel
// untested everywhere.
func TestKMAC256AsmPathSelected(t *testing.T) {
	cpuHas := xcpu.X86.HasAVX512F && xcpu.X86.HasAVX512BW &&
		xcpu.X86.HasAVX512VL && xcpu.X86.HasAVX512DQ
	if cpuHas && isASMBuild() && !keccakasm.HasAVX512Fused {
		t.Fatal("AVX-512 baseline present but keccakasm.HasAVX512Fused is false: silent scalar fallback")
	}
	t.Logf("keccakasm.HasAVX512Fused=%v (cpu baseline=%v)", keccakasm.HasAVX512Fused, cpuHas)
}

// TestKMAC256ParityVsReference cross-checks the shipped factory
// (vendored AVX-512 sponge where the gate is open, x/crypto scalar
// otherwise) against the in-test x/crypto reference arm on 200 random
// (key, customization, message) fixtures. Message lengths sweep the
// sponge-rate boundaries (0, 135, 136, 137, multi-block) plus random
// jitter.
func TestKMAC256ParityVsReference(t *testing.T) {
	rng := rand.New(rand.NewSource(0x1600))
	msgLens := []int{0, 1, 7, 64, 135, 136, 137, 271, 272, 273, 1000, 8192}
	for i := 0; i < 200; i++ {
		key := make([]byte, 16+rng.Intn(49))
		rng.Read(key)
		var custom []byte
		if rng.Intn(2) == 1 {
			custom = make([]byte, 1+rng.Intn(32))
			rng.Read(custom)
		}
		msg := make([]byte, msgLens[i%len(msgLens)]+rng.Intn(32))
		rng.Read(msg)

		mac, err := KMAC256WithCustomization(key, custom)
		if err != nil {
			t.Fatalf("fixture %d: %v", i, err)
		}
		got := mac(msg)
		want := refKMAC256(key, custom, msg)
		if !bytes.Equal(got, want) {
			t.Fatalf("fixture %d (|K|=%d |S|=%d |X|=%d):\ngot  %x\nwant %x",
				i, len(key), len(custom), len(msg), got, want)
		}
	}
}

// TestKMAC256BitSensitivity flips every bit of a 32-byte key (256
// bits) and every bit of a 64-byte message (512 bits) and checks the
// tag changes each time.
func TestKMAC256BitSensitivity(t *testing.T) {
	key := bytes.Repeat([]byte{0x5A}, 32)
	msg := bytes.Repeat([]byte{0xC3}, 64)

	mac, err := KMAC256(key)
	if err != nil {
		t.Fatal(err)
	}
	base := mac(msg)

	for bit := 0; bit < len(key)*8; bit++ {
		k := append([]byte(nil), key...)
		k[bit/8] ^= 1 << uint(bit%8)
		m, err := KMAC256(k)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(m(msg), base) {
			t.Fatalf("key bit %d flip left tag unchanged", bit)
		}
	}
	for bit := 0; bit < len(msg)*8; bit++ {
		x := append([]byte(nil), msg...)
		x[bit/8] ^= 1 << uint(bit%8)
		if bytes.Equal(mac(x), base) {
			t.Fatalf("message bit %d flip left tag unchanged", bit)
		}
	}
}

// ─── KMAC256 message-level benches (tier follows the build/CPU) ────

func benchKMAC256(b *testing.B, size int) {
	key := bytes.Repeat([]byte{0x42}, 32)
	mac, err := KMAC256(key)
	if err != nil {
		b.Fatal(err)
	}
	msg := make([]byte, size)
	rand.New(rand.NewSource(7)).Read(msg)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = mac(msg)
	}
}

func BenchmarkKMAC256_1MB(b *testing.B)  { benchKMAC256(b, 1<<20) }
func BenchmarkKMAC256_16MB(b *testing.B) { benchKMAC256(b, 16<<20) }
func BenchmarkKMAC256_64MB(b *testing.B) { benchKMAC256(b, 64<<20) }
