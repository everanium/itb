package aes

// Areion256 represents a 256-bit (32-byte) state for the Areion256 permutation.
// Areion256 is a wide-block cryptographic permutation built from AES round
// functions, designed for hash functions and authenticated encryption. The state
// consists of two 128-bit AES blocks processed through 10 rounds. The permutation
// uses round constants derived from the digits of pi and is hardware-accelerated
// on platforms with AES-NI or ARM Crypto Extensions.
type Areion256 [32]byte

// Areion512 represents a 512-bit (64-byte) state for the Areion512 permutation.
// Areion512 is a wide-block cryptographic permutation providing higher throughput
// than Areion256 for large constructions. The state consists of four 128-bit AES
// blocks processed through 15 rounds. Like Areion256, it uses pi-based round
// constants and is hardware-accelerated on platforms with AES-NI or ARM Crypto.
type Areion512 [64]byte

// Round constants for Areion (digits of pi in little-endian format).
// The first 10 constants are used by Areion256, all 15 are used by Areion512.
var areionRoundConstants = [15][16]byte{
	// 0x243f6a8885a308d313198a2e03707344
	{0x44, 0x73, 0x70, 0x03, 0x2e, 0x8a, 0x19, 0x13, 0xd3, 0x08, 0xa3, 0x85, 0x88, 0x6a, 0x3f, 0x24},
	// 0xa4093822299f31d0082efa98ec4e6c89
	{0x89, 0x6c, 0x4e, 0xec, 0x98, 0xfa, 0x2e, 0x08, 0xd0, 0x31, 0x9f, 0x29, 0x22, 0x38, 0x09, 0xa4},
	// 0x452821e638d01377be5466cf34e90c6c
	{0x6c, 0x0c, 0xe9, 0x34, 0xcf, 0x66, 0x54, 0xbe, 0x77, 0x13, 0xd0, 0x38, 0xe6, 0x21, 0x28, 0x45},
	// 0xc0ac29b7c97c50dd3f84d5b5b5470917
	{0x17, 0x09, 0x47, 0xb5, 0xb5, 0xd5, 0x84, 0x3f, 0xdd, 0x50, 0x7c, 0xc9, 0xb7, 0x29, 0xac, 0xc0},
	// 0x9216d5d98979fb1bd1310ba698dfb5ac
	{0xac, 0xb5, 0xdf, 0x98, 0xa6, 0x0b, 0x31, 0xd1, 0x1b, 0xfb, 0x79, 0x89, 0xd9, 0xd5, 0x16, 0x92},
	// 0x2ffd72dbd01adfb7b8e1afed6a267e96
	{0x96, 0x7e, 0x26, 0x6a, 0xed, 0xaf, 0xe1, 0xb8, 0xb7, 0xdf, 0x1a, 0xd0, 0xdb, 0x72, 0xfd, 0x2f},
	// 0xba7c9045f12c7f9924a19947b3916cf7
	{0xf7, 0x6c, 0x91, 0xb3, 0x47, 0x99, 0xa1, 0x24, 0x99, 0x7f, 0x2c, 0xf1, 0x45, 0x90, 0x7c, 0xba},
	// 0x801f2e2858efc16636920d871574e690
	{0x90, 0xe6, 0x74, 0x15, 0x87, 0x0d, 0x92, 0x36, 0x66, 0xc1, 0xef, 0x58, 0x28, 0x2e, 0x1f, 0x80},
	// 0xa458fea3f4933d7e0d95748f728eb658
	{0x58, 0xb6, 0x8e, 0x72, 0x8f, 0x74, 0x95, 0x0d, 0x7e, 0x3d, 0x93, 0xf4, 0xa3, 0xfe, 0x58, 0xa4},
	// 0x718bcd5882154aee7b54a41dc25a59b5
	{0xb5, 0x59, 0x5a, 0xc2, 0x1d, 0xa4, 0x54, 0x7b, 0xee, 0x4a, 0x15, 0x82, 0x58, 0xcd, 0x8b, 0x71},
	// Areion512-only constants:
	// 0x9c30d5392af26013c5d1b023286085f0
	{0xf0, 0x85, 0x60, 0x28, 0x23, 0xb0, 0xd1, 0xc5, 0x13, 0x60, 0xf2, 0x2a, 0x39, 0xd5, 0x30, 0x9c},
	// 0xca417918b8db38ef8e79dcb0603a180e
	{0x0e, 0x18, 0x3a, 0x60, 0xb0, 0xdc, 0x79, 0x8e, 0xef, 0x38, 0xdb, 0xb8, 0x18, 0x79, 0x41, 0xca},
	// 0x6c9e0e8bb01e8a3ed71577c1bd314b27
	{0x27, 0x4b, 0x31, 0xbd, 0xc1, 0x77, 0x15, 0xd7, 0x3e, 0x8a, 0x1e, 0xb0, 0x8b, 0x0e, 0x9e, 0x6c},
	// 0x78af2fda55605c60e65525f3aa55ab94
	{0x94, 0xab, 0x55, 0xaa, 0xf3, 0x25, 0x55, 0xe6, 0x60, 0x5c, 0x60, 0x55, 0xda, 0x2f, 0xaf, 0x78},
	// 0x5748986263e8144055ca396a2aab10b6
	{0xb6, 0x10, 0xab, 0x2a, 0x6a, 0x39, 0xca, 0x55, 0x40, 0x14, 0xe8, 0x63, 0x62, 0x98, 0x48, 0x57},
}

// Round constants of the second Areion permutation, used by the SoEM branch
// keyed with k2: the 15 128-bit words of the hexadecimal digits of pi that
// follow those of areionRoundConstants, in the same little-endian format. A
// permutation with different round constants is modelled as independent of
// the first.
var areionRoundConstants2 = [15][16]byte{
	// 0xb4cc5c341141e8cea15486af7c72e993
	{0x93, 0xe9, 0x72, 0x7c, 0xaf, 0x86, 0x54, 0xa1, 0xce, 0xe8, 0x41, 0x11, 0x34, 0x5c, 0xcc, 0xb4},
	// 0xb3ee1411636fbc2a2ba9c55d741831f6
	{0xf6, 0x31, 0x18, 0x74, 0x5d, 0xc5, 0xa9, 0x2b, 0x2a, 0xbc, 0x6f, 0x63, 0x11, 0x14, 0xee, 0xb3},
	// 0xce5c3e169b87931eafd6ba336c24cf5c
	{0x5c, 0xcf, 0x24, 0x6c, 0x33, 0xba, 0xd6, 0xaf, 0x1e, 0x93, 0x87, 0x9b, 0x16, 0x3e, 0x5c, 0xce},
	// 0x7a325381289586773b8f48986b4bb9af
	{0xaf, 0xb9, 0x4b, 0x6b, 0x98, 0x48, 0x8f, 0x3b, 0x77, 0x86, 0x95, 0x28, 0x81, 0x53, 0x32, 0x7a},
	// 0xc4bfe81b6628219361d809ccfb21a991
	{0x91, 0xa9, 0x21, 0xfb, 0xcc, 0x09, 0xd8, 0x61, 0x93, 0x21, 0x28, 0x66, 0x1b, 0xe8, 0xbf, 0xc4},
	// 0x487cac605dec8032ef845d5de98575b1
	{0xb1, 0x75, 0x85, 0xe9, 0x5d, 0x5d, 0x84, 0xef, 0x32, 0x80, 0xec, 0x5d, 0x60, 0xac, 0x7c, 0x48},
	// 0xdc262302eb651b8823893e81d396acc5
	{0xc5, 0xac, 0x96, 0xd3, 0x81, 0x3e, 0x89, 0x23, 0x88, 0x1b, 0x65, 0xeb, 0x02, 0x23, 0x26, 0xdc},
	// 0x0f6d6ff383f442392e0b4482a4842004
	{0x04, 0x20, 0x84, 0xa4, 0x82, 0x44, 0x0b, 0x2e, 0x39, 0x42, 0xf4, 0x83, 0xf3, 0x6f, 0x6d, 0x0f},
	// 0x69c8f04a9e1f9b5e21c66842f6e96c9a
	{0x9a, 0x6c, 0xe9, 0xf6, 0x42, 0x68, 0xc6, 0x21, 0x5e, 0x9b, 0x1f, 0x9e, 0x4a, 0xf0, 0xc8, 0x69},
	// 0x670c9c61abd388f06a51a0d2d8542f68
	{0x68, 0x2f, 0x54, 0xd8, 0xd2, 0xa0, 0x51, 0x6a, 0xf0, 0x88, 0xd3, 0xab, 0x61, 0x9c, 0x0c, 0x67},
	// 0x960fa728ab5133a36eef0b6c137a3be4
	{0xe4, 0x3b, 0x7a, 0x13, 0x6c, 0x0b, 0xef, 0x6e, 0xa3, 0x33, 0x51, 0xab, 0x28, 0xa7, 0x0f, 0x96},
	// 0xba3bf0507efb2a98a1f1651d39af0176
	{0x76, 0x01, 0xaf, 0x39, 0x1d, 0x65, 0xf1, 0xa1, 0x98, 0x2a, 0xfb, 0x7e, 0x50, 0xf0, 0x3b, 0xba},
	// 0x66ca593e82430e888cee8619456f9fb4
	{0xb4, 0x9f, 0x6f, 0x45, 0x19, 0x86, 0xee, 0x8c, 0x88, 0x0e, 0x43, 0x82, 0x3e, 0x59, 0xca, 0x66},
	// 0x7d84a5c33b8b5ebee06f75d885c12073
	{0x73, 0x20, 0xc1, 0x85, 0xd8, 0x75, 0x6f, 0xe0, 0xbe, 0x5e, 0x8b, 0x3b, 0xc3, 0xa5, 0x84, 0x7d},
	// 0x401a449f56c16aa64ed3aa62363f7706
	{0x06, 0x77, 0x3f, 0x36, 0x62, 0xaa, 0xd3, 0x4e, 0xa6, 0x6a, 0xc1, 0x56, 0x9f, 0x44, 0x1a, 0x40},
}

// Permute applies the 10-round Areion256 permutation in-place. The permutation
// transforms the 32-byte state using AES round functions and pi-based constants.
// Automatically uses hardware acceleration (AES-NI or ARM Crypto) when available,
// otherwise falls back to software implementation. The permutation is designed
// to be secure for cryptographic applications like hash functions and MACs.
func (state *Areion256) Permute() {
	areion256Permute(state)
}

// InversePermute applies the inverse of the Areion256 permutation in-place.
// This inverts the transformation performed by Permute, satisfying
// InversePermute(Permute(state)) == state. Like Permute, it automatically
// uses hardware acceleration when available.
func (state *Areion256) InversePermute() {
	areion256InversePermute(state)
}

// Permute applies the 15-round Areion512 permutation in-place. The permutation
// transforms the 64-byte state using AES round functions and pi-based constants,
// providing higher throughput than Areion256 for applications processing large
// amounts of data. Automatically uses hardware acceleration when available.
func (state *Areion512) Permute() {
	areion512Permute(state)
}

// InversePermute applies the inverse of the Areion512 permutation in-place.
// This inverts the transformation performed by Permute, satisfying
// InversePermute(Permute(state)) == state. Like Permute, it automatically
// uses hardware acceleration when available.
func (state *Areion512) InversePermute() {
	areion512InversePermute(state)
}

// Software implementation of Areion256 permutation
func areion256PermuteSoftware(state *Areion256) {
	areion256PermuteSoftwareRC(state, &areionRoundConstants)
}

// areion256PermuteSoftwareRC is the software Areion256 permutation under the
// round constants rcs.
func areion256PermuteSoftwareRC(state *Areion256, rcs *[15][16]byte) {
	x0 := (*[16]byte)(state[0:16])
	x1 := (*[16]byte)(state[16:32])

	for r := 0; r < 10; r++ {
		rc := rcs[r]

		if r%2 == 0 {
			var temp [16]byte
			copy(temp[:], x0[:])
			RoundNoKey((*Block)(&temp))
			XorBlock((*Block)(&temp), (*Block)(&temp), (*Block)(&rc))
			RoundNoKey((*Block)(&temp))
			XorBlock((*Block)(&temp), (*Block)(&temp), (*Block)(x1))
			FinalRoundNoKey((*Block)(x0))
			copy(x1[:], temp[:])
		} else {
			var temp [16]byte
			copy(temp[:], x1[:])
			RoundNoKey((*Block)(&temp))
			XorBlock((*Block)(&temp), (*Block)(&temp), (*Block)(&rc))
			RoundNoKey((*Block)(&temp))
			XorBlock((*Block)(&temp), (*Block)(&temp), (*Block)(x0))
			FinalRoundNoKey((*Block)(x1))
			copy(x0[:], temp[:])
		}
	}
}

// Software implementation of Areion256 inverse permutation
func areion256InversePermuteSoftware(state *Areion256) {
	x0 := (*[16]byte)(state[0:16])
	x1 := (*[16]byte)(state[16:32])

	for i := 0; i < 10; i += 2 {
		rc := areionRoundConstants[9-i]
		InvFinalRoundNoKey((*Block)(x1))
		var temp [16]byte
		copy(temp[:], x1[:])
		RoundNoKey((*Block)(&temp))
		XorBlock((*Block)(&temp), (*Block)(&temp), (*Block)(&rc))
		RoundNoKey((*Block)(&temp))
		XorBlock((*Block)(x0), (*Block)(&temp), (*Block)(x0))

		rc = areionRoundConstants[8-i]
		InvFinalRoundNoKey((*Block)(x0))
		copy(temp[:], x0[:])
		RoundNoKey((*Block)(&temp))
		XorBlock((*Block)(&temp), (*Block)(&temp), (*Block)(&rc))
		RoundNoKey((*Block)(&temp))
		XorBlock((*Block)(x1), (*Block)(&temp), (*Block)(x1))
	}
}

// Software implementation of Areion512 permutation
func areion512PermuteSoftware(state *Areion512) {
	areion512PermuteSoftwareRC(state, &areionRoundConstants)
}

// areion512PermuteSoftwareRC is the software Areion512 permutation under the
// round constants rcs.
func areion512PermuteSoftwareRC(state *Areion512, rcs *[15][16]byte) {
	x0 := (*[16]byte)(state[0:16])
	x1 := (*[16]byte)(state[16:32])
	x2 := (*[16]byte)(state[32:48])
	x3 := (*[16]byte)(state[48:64])

	areion512Round := func(a, b, c, d *[16]byte, rc *[16]byte) {
		var temp1 [16]byte
		copy(temp1[:], a[:])
		RoundNoKey((*Block)(&temp1))
		XorBlock((*Block)(b), (*Block)(&temp1), (*Block)(b))

		var temp2 [16]byte
		copy(temp2[:], c[:])
		RoundNoKey((*Block)(&temp2))
		XorBlock((*Block)(d), (*Block)(&temp2), (*Block)(d))

		FinalRoundNoKey((*Block)(a))
		FinalRoundNoKey((*Block)(c))
		XorBlock((*Block)(c), (*Block)(c), (*Block)(rc))
		RoundNoKey((*Block)(c))
	}

	// Main 12 rounds
	for i := 0; i < 12; i += 4 {
		areion512Round(x0, x1, x2, x3, &rcs[i+0])
		areion512Round(x1, x2, x3, x0, &rcs[i+1])
		areion512Round(x2, x3, x0, x1, &rcs[i+2])
		areion512Round(x3, x0, x1, x2, &rcs[i+3])
	}

	// Final 3 rounds
	areion512Round(x0, x1, x2, x3, &rcs[12])
	areion512Round(x1, x2, x3, x0, &rcs[13])
	areion512Round(x2, x3, x0, x1, &rcs[14])

	// Final rotation: temp=x0; x0=x3; x3=x2; x2=x1; x1=temp
	var temp [16]byte
	copy(temp[:], x0[:])
	copy(x0[:], x3[:])
	copy(x3[:], x2[:])
	copy(x2[:], x1[:])
	copy(x1[:], temp[:])
}

// Software implementation of Areion512 inverse permutation
func areion512InversePermuteSoftware(state *Areion512) {
	x0 := (*[16]byte)(state[0:16])
	x1 := (*[16]byte)(state[16:32])
	x2 := (*[16]byte)(state[32:48])
	x3 := (*[16]byte)(state[48:64])

	// Reverse the final rotation: temp=x0; x0=x1; x1=x2; x2=x3; x3=temp
	var temp [16]byte
	copy(temp[:], x0[:])
	copy(x0[:], x1[:])
	copy(x1[:], x2[:])
	copy(x2[:], x3[:])
	copy(x3[:], temp[:])

	areion512InvRound := func(a, b, c, d *[16]byte, rc *[16]byte) {
		InvFinalRoundNoKey((*Block)(a))
		InvMixColumns((*Block)(c))
		InvFinalRoundNoKey((*Block)(c))
		XorBlock((*Block)(c), (*Block)(c), (*Block)(rc))
		InvFinalRoundNoKey((*Block)(c))

		var temp1 [16]byte
		copy(temp1[:], a[:])
		RoundNoKey((*Block)(&temp1))
		XorBlock((*Block)(b), (*Block)(&temp1), (*Block)(b))

		var temp2 [16]byte
		copy(temp2[:], c[:])
		RoundNoKey((*Block)(&temp2))
		XorBlock((*Block)(d), (*Block)(&temp2), (*Block)(d))
	}

	// Last 3 inverse rounds
	areion512InvRound(x2, x3, x0, x1, &areionRoundConstants[14])
	areion512InvRound(x1, x2, x3, x0, &areionRoundConstants[13])
	areion512InvRound(x0, x1, x2, x3, &areionRoundConstants[12])

	// Main 12 inverse rounds
	for i := 0; i < 12; i += 4 {
		areion512InvRound(x3, x0, x1, x2, &areionRoundConstants[11-i])
		areion512InvRound(x2, x3, x0, x1, &areionRoundConstants[10-i])
		areion512InvRound(x1, x2, x3, x0, &areionRoundConstants[9-i])
		areion512InvRound(x0, x1, x2, x3, &areionRoundConstants[8-i])
	}
}

// Areion256EM encrypts a 32-byte block using the single-key Even-Mansour construction
// with the Areion256 permutation: E_k(m) = P(m ⊕ k) ⊕ k.
func Areion256EM(key *[32]byte, block *[32]byte) [32]byte {
	var state Areion256
	for i := range state {
		state[i] = block[i] ^ key[i]
	}
	state.Permute()
	for i := range state {
		state[i] ^= key[i]
	}
	return [32]byte(state)
}

// Areion256EMDecrypt decrypts a 32-byte block using the single-key Even-Mansour construction
// with the Areion256 inverse permutation: D_k(c) = P^{-1}(c ⊕ k) ⊕ k.
func Areion256EMDecrypt(key *[32]byte, block *[32]byte) [32]byte {
	var state Areion256
	for i := range state {
		state[i] = block[i] ^ key[i]
	}
	state.InversePermute()
	for i := range state {
		state[i] ^= key[i]
	}
	return [32]byte(state)
}

// Areion512EM encrypts a 64-byte block using the single-key Even-Mansour construction
// with the Areion512 permutation: E_k(m) = P(m ⊕ k) ⊕ k.
func Areion512EM(key *[64]byte, block *[64]byte) [64]byte {
	var state Areion512
	for i := range state {
		state[i] = block[i] ^ key[i]
	}
	state.Permute()
	for i := range state {
		state[i] ^= key[i]
	}
	return [64]byte(state)
}

// Areion512EMDecrypt decrypts a 64-byte block using the single-key Even-Mansour construction
// with the Areion512 inverse permutation: D_k(c) = P^{-1}(c ⊕ k) ⊕ k.
func Areion512EMDecrypt(key *[64]byte, block *[64]byte) [64]byte {
	var state Areion512
	for i := range state {
		state[i] = block[i] ^ key[i]
	}
	state.InversePermute()
	for i := range state {
		state[i] ^= key[i]
	}
	return [64]byte(state)
}

// AreionSoEM256 computes a PRF using Sum of Even-Mansour with two Areion256
// permutations: F(k1, k2, m) = P1(m XOR k1) XOR P2(m XOR k2) XOR k1 XOR k2,
// where P1 is the Areion256 permutation and P2 is Areion256 with the round
// constants areionRoundConstants2, modelled as an independent permutation.
// With two independent permutations and two independent subkeys this is SoEM22
// of Chen, Lambooij and Mennink (CRYPTO 2019; ePrint 2019/554, Eq. (4) and
// Theorem 1), a PRF up to about 2^(2n/3) queries (~170-bit PRF security) in
// the random-permutation model.
// Key is 64 bytes: two 32-byte subkeys k1 || k2, both secret and
// independently random. Input and output are 32 bytes.
func AreionSoEM256(key *[64]byte, input *[32]byte) [32]byte {
	var state1, state2 Areion256
	for i := range state1 {
		state1[i] = input[i] ^ key[i]
		state2[i] = input[i] ^ key[32+i]
	}
	state1.Permute()
	areion256Permute2(&state2)
	for i := range state1 {
		state1[i] ^= state2[i] ^ key[i] ^ key[32+i]
	}
	return [32]byte(state1)
}

// AreionSoEM512 computes a PRF using Sum of Even-Mansour with two Areion512
// permutations: F(k1, k2, m) = P1(m XOR k1) XOR P2(m XOR k2) XOR k1 XOR k2,
// where P1 is the Areion512 permutation and P2 is Areion512 with the round
// constants areionRoundConstants2, modelled as an independent permutation.
// With two independent permutations and two independent subkeys this is SoEM22
// of Chen, Lambooij and Mennink (CRYPTO 2019; ePrint 2019/554, Eq. (4) and
// Theorem 1), a PRF up to about 2^(2n/3) queries (~341-bit PRF security) in
// the random-permutation model.
// Key is 128 bytes: two 64-byte subkeys k1 || k2, both secret and
// independently random. Input and output are 64 bytes.
func AreionSoEM512(key *[128]byte, input *[64]byte) [64]byte {
	var state1, state2 Areion512
	for i := range state1 {
		state1[i] = input[i] ^ key[i]
		state2[i] = input[i] ^ key[64+i]
	}
	state1.Permute()
	areion512Permute2(&state2)
	for i := range state1 {
		state1[i] ^= state2[i] ^ key[i] ^ key[64+i]
	}
	return [64]byte(state1)
}

// Areion256DM computes the Areion256-DM short fixed-input hash of a 32-byte input.
// It applies the Davies-Meyer construction: h = P(m) XOR m, returning the full
// 32-byte result as the digest.
func Areion256DM(input *[32]byte) [32]byte {
	var state Areion256
	copy(state[:], input[:])
	state.Permute()
	for i := range state {
		state[i] ^= input[i]
	}
	return [32]byte(state)
}

// Areion512DM computes the Areion512-DM short fixed-input hash of a 64-byte input.
// It applies the Davies-Meyer construction: h = P(m) XOR m, then extracts 32 bytes
// from specific positions in the state as the digest.
func Areion512DM(input *[64]byte) [32]byte {
	var state Areion512
	copy(state[:], input[:])
	state.Permute()
	for i := range state {
		state[i] ^= input[i]
	}
	var out [32]byte
	copy(out[0:8], state[8:16])
	copy(out[8:16], state[24:32])
	copy(out[16:24], state[32:40])
	copy(out[24:32], state[48:56])
	return out
}
