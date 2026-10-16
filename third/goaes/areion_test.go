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
	expected, _ := hex.DecodeString("bc4b0a2d16987c40a216a53b568387a35b37830bd4ff779ca360255a41687f3c")
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
	expected, _ = hex.DecodeString("308aee3b62aae1b45265caedfec59750809019a0e0212e763720078b0959e2a8")
	if !bytes.Equal(out[:], expected) {
		t.Errorf("AreionSoEM256(seq) failed\nGot:      %x\nExpected: %x", out[:], expected)
	}
}

func TestAreionSoEM512(t *testing.T) {
	// All-zeros key and input
	var key [128]byte
	var input [64]byte
	out := AreionSoEM512(&key, &input)
	expected, _ := hex.DecodeString("581f0632baade730452d4690acca763c952a3df2741f2cb64074985a248e93b3fe0b9de5d02abf8f6fd43c21c56cf314a7f5f5fba3b532bbb28e1e455122a7c0")
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
	expected, _ = hex.DecodeString("271fa05a95f4539759121ffeef462a7f21fd9ef9ae6e8e779c2ec80a5ed18a84bb0f5f9b8ca4bfd82cea7f000c16c71991c32aa31c1657f40890b12a51d2bcf1")
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
	expected, _ := hex.DecodeString("9459ad09732a12df686326cdb291bd021239b6ec01df49d7018902ea09473284")
	if !bytes.Equal(state256[:], expected) {
		t.Errorf("Areion256 second permutation (zeros) failed\nGot:      %x\nExpected: %x", state256[:], expected)
	}
	for i := range state256 {
		state256[i] = byte(i)
	}
	areion256Permute2(&state256)
	expected, _ = hex.DecodeString("b59b22ce1537d50db949a4222621e9171525fcd650cae441a7c66162675e65e6")
	if !bytes.Equal(state256[:], expected) {
		t.Errorf("Areion256 second permutation (seq) failed\nGot:      %x\nExpected: %x", state256[:], expected)
	}

	var state512 Areion512
	areion512Permute2(&state512)
	expected, _ = hex.DecodeString("eab2b67d13b277251c1b37b267f6e095ede50316c32346e27f9244df531f91541dfecdf5c6e45292bd10b12a077e08130ae3726f1e23fd48eb87d39db305eee8")
	if !bytes.Equal(state512[:], expected) {
		t.Errorf("Areion512 second permutation (zeros) failed\nGot:      %x\nExpected: %x", state512[:], expected)
	}
	for i := range state512 {
		state512[i] = byte(i)
	}
	areion512Permute2(&state512)
	expected, _ = hex.DecodeString("bad430e7c4a11e8cfec7cc58a45915da0e88f49615200c41a45fea75e1725fb9f59818f3a300cb89abd6ed7e50ba5cc5b8c78e5240faeff2aed7233682bc296d")
	if !bytes.Equal(state512[:], expected) {
		t.Errorf("Areion512 second permutation (seq) failed\nGot:      %x\nExpected: %x", state512[:], expected)
	}
}
