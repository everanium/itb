package aes

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from the reference Zig implementation
func TestAreion256Permutation(t *testing.T) {
	// Test vector 1: all zeros
	var state Areion256
	for i := range state {
		state[i] = 0
	}

	state.Permute()

	expectedHex := "2812a72465b26e9fca7583f6e4123aa1490e35e7d5203e4ba2e927b0482f4db8"
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatalf("Failed to decode expected hex: %v", err)
	}

	if !bytes.Equal(state[:], expected) {
		t.Errorf("Areion256 permutation failed\nGot:      %x\nExpected: %x", state[:], expected)
	}
}

func TestAreion256PermutationSequential(t *testing.T) {
	// Test vector 2: sequential bytes 0..31
	var state Areion256
	for i := range state {
		state[i] = byte(i)
	}

	state.Permute()

	expectedHex := "68845f132ee4616066c702d942a3b2c3a377f65b13bb05c7cd1fb29c89afa185"
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatalf("Failed to decode expected hex: %v", err)
	}

	if !bytes.Equal(state[:], expected) {
		t.Errorf("Areion256 sequential permutation failed\nGot:      %x\nExpected: %x", state[:], expected)
	}
}

func TestAreion512Permutation(t *testing.T) {
	// Test vector 1: all zeros
	var state Areion512
	for i := range state {
		state[i] = 0
	}

	state.Permute()

	expectedHex := "b2adb04fa91f901559367122cb3c96a978cf3ee4b73c6a543fe6dc85779102e7e3f5501016ceed1dd2c48d0bc212fb07ad168794bd96cff35909cdd8e2274928"
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatalf("Failed to decode expected hex: %v", err)
	}

	if !bytes.Equal(state[:], expected) {
		t.Errorf("Areion512 permutation failed\nGot:      %x\nExpected: %x", state[:], expected)
	}
}

func TestAreion512PermutationSequential(t *testing.T) {
	// Test vector 2: sequential bytes 0..63
	var state Areion512
	for i := range state {
		state[i] = byte(i)
	}

	state.Permute()

	expectedHex := "b690b88297ec470b07dda92b91959cff135e9ac5fc3dc9b647a43f4daa8da7a4e0afbdd8e6e255c24527736b298bd61de460bab9ea7915c6d6ddbe05fe8dde40"
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		t.Fatalf("Failed to decode expected hex: %v", err)
	}

	if !bytes.Equal(state[:], expected) {
		t.Errorf("Areion512 sequential permutation failed\nGot:      %x\nExpected: %x", state[:], expected)
	}
}

// Test that permute and inverse permute are inverses of each other
func TestAreion256Roundtrip(t *testing.T) {
	var original, state Areion256
	for i := range original {
		original[i] = byte(i * 3)
	}
	copy(state[:], original[:])

	state.Permute()
	state.InversePermute()

	if !bytes.Equal(original[:], state[:]) {
		t.Errorf("Areion256 roundtrip failed\nOriginal: %x\nRoundtrip: %x", original[:], state[:])
	}
}

func TestAreion512Roundtrip(t *testing.T) {
	var original, state Areion512
	for i := range original {
		original[i] = byte(i * 5)
	}
	copy(state[:], original[:])

	state.Permute()
	state.InversePermute()

	if !bytes.Equal(original[:], state[:]) {
		t.Errorf("Areion512 roundtrip failed\nOriginal: %x\nRoundtrip: %x", original[:], state[:])
	}
}

// Test hardware vs software implementation consistency
func TestAreion256HardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	var stateHW, stateSW Areion256
	for i := range stateHW {
		stateHW[i] = byte(i ^ 0xAA)
	}
	copy(stateSW[:], stateHW[:])

	// Hardware
	areion256PermuteAsm(&stateHW)

	// Software
	areion256PermuteSoftware(&stateSW)

	if !bytes.Equal(stateHW[:], stateSW[:]) {
		t.Errorf("Areion256 hardware/software mismatch\nHardware: %x\nSoftware: %x", stateHW[:], stateSW[:])
	}
}

func TestAreion512HardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	var stateHW, stateSW Areion512
	for i := range stateHW {
		stateHW[i] = byte(i ^ 0x55)
	}
	copy(stateSW[:], stateHW[:])

	// Hardware
	areion512PermuteAsm(&stateHW)

	// Software
	areion512PermuteSoftware(&stateSW)

	if !bytes.Equal(stateHW[:], stateSW[:]) {
		t.Errorf("Areion512 hardware/software mismatch\nHardware: %x\nSoftware: %x", stateHW[:], stateSW[:])
	}
}

func TestAreion256InverseHardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	var stateHW, stateSW Areion256
	for i := range stateHW {
		stateHW[i] = byte(i * 7)
	}
	copy(stateSW[:], stateHW[:])

	// Hardware
	areion256InversePermuteAsm(&stateHW)

	// Software
	areion256InversePermuteSoftware(&stateSW)

	if !bytes.Equal(stateHW[:], stateSW[:]) {
		t.Errorf("Areion256 inverse hardware/software mismatch\nHardware: %x\nSoftware: %x", stateHW[:], stateSW[:])
	}
}

func TestAreion512InverseHardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	var stateHW, stateSW Areion512
	for i := range stateHW {
		stateHW[i] = byte(i * 11)
	}
	copy(stateSW[:], stateHW[:])

	// Hardware
	areion512InversePermuteAsm(&stateHW)

	// Software
	areion512InversePermuteSoftware(&stateSW)

	if !bytes.Equal(stateHW[:], stateSW[:]) {
		t.Errorf("Areion512 inverse hardware/software mismatch\nHardware: %x\nSoftware: %x", stateHW[:], stateSW[:])
	}
}

// Areion256-DM tests (test vectors from reference C implementation)
func TestAreion256DM(t *testing.T) {
	// Test vector 1: all zeros
	var input [32]byte
	out := Areion256DM(&input)
	expected, _ := hex.DecodeString("2812a72465b26e9fca7583f6e4123aa1490e35e7d5203e4ba2e927b0482f4db8")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("Areion256DM(zeros) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}

	// Test vector 2: sequential bytes 0..31
	for i := range input {
		input[i] = byte(i)
	}
	out = Areion256DM(&input)
	expected, _ = hex.DecodeString("68855d102ae167676ece08d24eaebcccb366e44807ae13d0d506a88795b2bf9a")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("Areion256DM(sequential) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}
}

func TestAreion512DM(t *testing.T) {
	// Test vector 1: all zeros
	var input [64]byte
	out := Areion512DM(&input)
	expected, _ := hex.DecodeString("59367122cb3c96a93fe6dc85779102e7e3f5501016ceed1dad168794bd96cff3")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("Areion512DM(zeros) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}

	// Test vector 2: sequential bytes 0..63
	for i := range input {
		input[i] = byte(i)
	}
	out = Areion512DM(&input)
	expected, _ = hex.DecodeString("0fd4a3209d9892f05fbd2556b690b9bbc08e9ffbc2c773e5d451888ade4c23f1")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("Areion512DM(sequential) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}
}

// Even-Mansour tests

func TestAreion256EMRoundtrip(t *testing.T) {
	var key [32]byte
	var plaintext [32]byte
	for i := range key {
		key[i] = byte(i * 3)
	}
	for i := range plaintext {
		plaintext[i] = byte(i * 7)
	}

	ciphertext := Areion256EM(&key, &plaintext)
	if bytes.Equal(ciphertext[:], plaintext[:]) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted := Areion256EMDecrypt(&key, &ciphertext)
	if !bytes.Equal(decrypted[:], plaintext[:]) {
		t.Errorf("Areion256EM roundtrip failed\nPlaintext:  %x\nDecrypted:  %x", plaintext[:], decrypted[:])
	}
}

func TestAreion512EMRoundtrip(t *testing.T) {
	var key [64]byte
	var plaintext [64]byte
	for i := range key {
		key[i] = byte(i * 3)
	}
	for i := range plaintext {
		plaintext[i] = byte(i * 7)
	}

	ciphertext := Areion512EM(&key, &plaintext)
	if bytes.Equal(ciphertext[:], plaintext[:]) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted := Areion512EMDecrypt(&key, &ciphertext)
	if !bytes.Equal(decrypted[:], plaintext[:]) {
		t.Errorf("Areion512EM roundtrip failed\nPlaintext:  %x\nDecrypted:  %x", plaintext[:], decrypted[:])
	}
}

func TestAreion256EMZeroKey(t *testing.T) {
	var key [32]byte
	var plaintext [32]byte
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	// With zero key, EM reduces to just the permutation
	ciphertext := Areion256EM(&key, &plaintext)

	var state Areion256
	copy(state[:], plaintext[:])
	state.Permute()

	if !bytes.Equal(ciphertext[:], state[:]) {
		t.Errorf("Areion256EM with zero key should equal bare permutation\nEM:   %x\nPerm: %x", ciphertext[:], state[:])
	}
}

func TestAreion512EMZeroKey(t *testing.T) {
	var key [64]byte
	var plaintext [64]byte
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	ciphertext := Areion512EM(&key, &plaintext)

	var state Areion512
	copy(state[:], plaintext[:])
	state.Permute()

	if !bytes.Equal(ciphertext[:], state[:]) {
		t.Errorf("Areion512EM with zero key should equal bare permutation\nEM:   %x\nPerm: %x", ciphertext[:], state[:])
	}
}

func TestAreion256EMKnownAnswer(t *testing.T) {
	var key [32]byte
	var plaintext [32]byte

	// Generate a known-answer test vector
	ciphertext := Areion256EM(&key, &plaintext)
	expected, _ := hex.DecodeString("2812a72465b26e9fca7583f6e4123aa1490e35e7d5203e4ba2e927b0482f4db8")
	if !bytes.Equal(ciphertext[:], expected) {
		t.Errorf("Areion256EM(zeros) failed\nGot:      %x\nExpected: %x", ciphertext[:], expected)
	}
}

func TestAreion512EMKnownAnswer(t *testing.T) {
	var key [64]byte
	var plaintext [64]byte

	ciphertext := Areion512EM(&key, &plaintext)
	expected, _ := hex.DecodeString("b2adb04fa91f901559367122cb3c96a978cf3ee4b73c6a543fe6dc85779102e7e3f5501016ceed1dd2c48d0bc212fb07ad168794bd96cff35909cdd8e2274928")
	if !bytes.Equal(ciphertext[:], expected) {
		t.Errorf("Areion512EM(zeros) failed\nGot:      %x\nExpected: %x", ciphertext[:], expected)
	}
}

// Sum of Even-Mansour tests

func TestAreionSoEM256(t *testing.T) {
	// All-zeros key and input
	var key [64]byte
	var input [32]byte
	out := AreionSoEM256(&key, &input)
	expected, _ := hex.DecodeString("e135afb2be0dee2857cc14aa4de7f022acd1e6489d8c1e53a20c99c4bf48f392")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("AreionSoEM256(zeros) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}

	// Sequential key and input
	for i := range key {
		key[i] = byte(i)
	}
	for i := range input {
		input[i] = byte(i + 64)
	}
	out = AreionSoEM256(&key, &input)
	expected, _ = hex.DecodeString("7d988f8b9974656d7573b291fe378d7a6c5f9a9c0d71f4510953a27cc23a6baf")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("AreionSoEM256(seq) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}
}

func TestAreionSoEM512(t *testing.T) {
	// All-zeros key and input
	var key [128]byte
	var input [64]byte
	out := AreionSoEM512(&key, &input)
	expected, _ := hex.DecodeString("4ac61c79b8575a64a2a037a267e37375951aa9f1dc09ce4df0686488e48a0712d1d684bc003d906940e5a2d5c1eae993409b10d864da8886404c73f63890e07a")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("AreionSoEM512(zeros) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}

	// Sequential key and input
	for i := range key {
		key[i] = byte(i)
	}
	for i := range input {
		input[i] = byte(i + 128)
	}
	out = AreionSoEM512(&key, &input)
	expected, _ = hex.DecodeString("6970032eb5721f8d819a49a2ee8ca7a0416977cf58666de3848c6449315c6a05ee6c30d2de89bee708db8f9f2a045dbd71e8f5291f4912ca033364402989a6be")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("AreionSoEM512(seq) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}
}

func TestAreionSoEM256DifferentKeys(t *testing.T) {
	var key1, key2 [64]byte
	var input [32]byte
	for i := range input {
		input[i] = byte(i)
	}
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 1)
	}
	out1 := AreionSoEM256(&key1, &input)
	out2 := AreionSoEM256(&key2, &input)
	if bytes.Equal(out1[:], out2[:]) {
		t.Error("AreionSoEM256: different keys should produce different outputs")
	}
}

func TestAreionSoEM512DifferentKeys(t *testing.T) {
	var key1, key2 [128]byte
	var input [64]byte
	for i := range input {
		input[i] = byte(i)
	}
	for i := range key1 {
		key1[i] = byte(i)
		key2[i] = byte(i + 1)
	}
	out1 := AreionSoEM512(&key1, &input)
	out2 := AreionSoEM512(&key2, &input)
	if bytes.Equal(out1[:], out2[:]) {
		t.Error("AreionSoEM512: different keys should produce different outputs")
	}
}

func TestAreionSoEM256DifferentInputs(t *testing.T) {
	var key [64]byte
	var input1, input2 [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range input1 {
		input1[i] = byte(i)
		input2[i] = byte(i + 1)
	}
	out1 := AreionSoEM256(&key, &input1)
	out2 := AreionSoEM256(&key, &input2)
	if bytes.Equal(out1[:], out2[:]) {
		t.Error("AreionSoEM256: different inputs should produce different outputs")
	}
}

// Benchmarks

func BenchmarkAreionSoEM256(b *testing.B) {
	var key [64]byte
	var input [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range input {
		input[i] = byte(i + 64)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AreionSoEM256(&key, &input)
	}
}

func BenchmarkAreionSoEM512(b *testing.B) {
	var key [128]byte
	var input [64]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range input {
		input[i] = byte(i + 128)
	}

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AreionSoEM512(&key, &input)
	}
}

func BenchmarkAreion256EM(b *testing.B) {
	var key [32]byte
	var block [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range block {
		block[i] = byte(i + 32)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Areion256EM(&key, &block)
	}
}

func BenchmarkAreion512EM(b *testing.B) {
	var key [64]byte
	var block [64]byte
	for i := range key {
		key[i] = byte(i)
	}
	for i := range block {
		block[i] = byte(i + 64)
	}

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Areion512EM(&key, &block)
	}
}

func BenchmarkAreion256DM(b *testing.B) {
	var input [32]byte
	for i := range input {
		input[i] = byte(i)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Areion256DM(&input)
	}
}

func BenchmarkAreion512DM(b *testing.B) {
	var input [64]byte
	for i := range input {
		input[i] = byte(i)
	}

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Areion512DM(&input)
	}
}

func BenchmarkAreion256Permute(b *testing.B) {
	var state Areion256
	for i := range state {
		state[i] = byte(i)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state.Permute()
	}
}

func BenchmarkAreion256InversePermute(b *testing.B) {
	var state Areion256
	for i := range state {
		state[i] = byte(i)
	}

	b.SetBytes(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state.InversePermute()
	}
}

func BenchmarkAreion512Permute(b *testing.B) {
	var state Areion512
	for i := range state {
		state[i] = byte(i)
	}

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state.Permute()
	}
}

func BenchmarkAreion512InversePermute(b *testing.B) {
	var state Areion512
	for i := range state {
		state[i] = byte(i)
	}

	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state.InversePermute()
	}
}

// TestAreionSoEMNoKeyShiftSymmetry checks that F(m) != F(m XOR k1 XOR k2): a sum
// of two calls to the same permutation would satisfy it for every m.
func TestAreionSoEMNoKeyShiftSymmetry(t *testing.T) {
	var k256 [64]byte
	var m256, s256 [32]byte
	for i := range k256 {
		k256[i] = byte(7*i + 1)
	}
	for i := range m256 {
		m256[i] = byte(3 * i)
		s256[i] = m256[i] ^ k256[i] ^ k256[32+i]
	}
	if AreionSoEM256(&k256, &m256) == AreionSoEM256(&k256, &s256) {
		t.Error("AreionSoEM256: F(m) == F(m XOR k1 XOR k2)")
	}

	var k512 [128]byte
	var m512, s512 [64]byte
	for i := range k512 {
		k512[i] = byte(7*i + 1)
	}
	for i := range m512 {
		m512[i] = byte(3 * i)
		s512[i] = m512[i] ^ k512[i] ^ k512[64+i]
	}
	if AreionSoEM512(&k512, &m512) == AreionSoEM512(&k512, &s512) {
		t.Error("AreionSoEM512: F(m) == F(m XOR k1 XOR k2)")
	}
}

// TestAreionPermute2KnownAnswer pins the second Areion permutation (round
// constants areionRoundConstants2) used by the SoEM branch keyed with k2.
func TestAreionPermute2KnownAnswer(t *testing.T) {
	var state256 Areion256
	areion256Permute2(&state256)
	expected, _ := hex.DecodeString("c9270896dbbf80b79db9975ca9f5ca83e5dfd3af48ac201800e5be74f767be2a")
	if !bytes.Equal(state256[:], expected) {
		t.Errorf("Areion256 second permutation (zeros) failed\nGot:      %x\nExpected: %x", state256[:], expected)
	}
	for i := range state256 {
		state256[i] = byte(i)
	}
	areion256Permute2(&state256)
	expected, _ = hex.DecodeString("2a105b2728271062195d5711cbfc592cafbe71252fb872fcdfd5b91b668be331")
	if !bytes.Equal(state256[:], expected) {
		t.Errorf("Areion256 second permutation (seq) failed\nGot:      %x\nExpected: %x", state256[:], expected)
	}

	var state512 Areion512
	areion512Permute2(&state512)
	expected, _ = hex.DecodeString("f86bac361148ca71fb964680acdfe5dcedd597156b35a419cf8eb80d931b05f53223d4ac16f37d7492212fde03f81294ed8d974cd94c47751945be2edab7a952")
	if !bytes.Equal(state512[:], expected) {
		t.Errorf("Areion512 second permutation (zeros) failed\nGot:      %x\nExpected: %x", state512[:], expected)
	}
	for i := range state512 {
		state512[i] = byte(i)
	}
	areion512Permute2(&state512)
	expected, _ = hex.DecodeString("d2581b6f5b464de84bb66ce14f1310f38de46e1781633cd4fcbcc6c49e26fcf4e90764efc7e9fddf4083c1aafa5017c45dd2d429de57bbbf6df5e82934458645")
	if !bytes.Equal(state512[:], expected) {
		t.Errorf("Areion512 second permutation (seq) failed\nGot:      %x\nExpected: %x", state512[:], expected)
	}
}

// TestAreionPermute2HardwareSoftwareMatch checks the assembly path of the
// second Areion permutation against the software path.
func TestAreionPermute2HardwareSoftwareMatch(t *testing.T) {
	if !CPU.HasAESNI && !CPU.HasARMCrypto {
		t.Skip("No hardware AES support available")
	}

	for _, seed := range []byte{0x00, 0x5a, 0xa5, 0xff} {
		var hw256, sw256 Areion256
		for i := range hw256 {
			hw256[i] = byte(i*5) ^ seed
		}
		copy(sw256[:], hw256[:])
		areion256PermuteRCAsm(&hw256, &areionRoundConstants2)
		areion256PermuteSoftwareRC(&sw256, &areionRoundConstants2)
		if !bytes.Equal(hw256[:], sw256[:]) {
			t.Errorf("Areion256 second permutation hardware/software mismatch (seed %#x)\nHardware: %x\nSoftware: %x", seed, hw256[:], sw256[:])
		}

		var hw512, sw512 Areion512
		for i := range hw512 {
			hw512[i] = byte(i*5) ^ seed
		}
		copy(sw512[:], hw512[:])
		areion512PermuteRCAsm(&hw512, &areionRoundConstants2)
		areion512PermuteSoftwareRC(&sw512, &areionRoundConstants2)
		if !bytes.Equal(hw512[:], sw512[:]) {
			t.Errorf("Areion512 second permutation hardware/software mismatch (seed %#x)\nHardware: %x\nSoftware: %x", seed, hw512[:], sw512[:])
		}
	}
}
