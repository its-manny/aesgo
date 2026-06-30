package main

// State - AES 4×4 byte matrix. Uses column-major order.
type State [4][4]byte

func stateFromBlock(s *State, block [16]byte) {
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			s[row][col] = block[row+4*col]
		}
	}
}

func stateToBlock(s *State) [16]byte {
	var block [16]byte
	for col := 0; col < 4; col++ {
		for row := 0; row < 4; row++ {
			block[row+4*col] = s[row][col]
		}
	}
	return block
}

// expandKey returns a full set of round key words.
//
// Key length of the key (specifically number of words, Nk) determines the number of rounds (Nr):
//   - 16 bytes = AES-128 (Nk=4, Nr=10, 44w)
//   - 24 bytes = AES-192 (Nk=6, Nr=12, 52w)
//   - 32 bytes = AES-256 (Nk=8, Nr=14, 60w)
//
// See FIPS 197 (Section 5.2) and https://en.wikipedia.org/wiki/AES_key_schedule
func expandKey(key []byte) []uint32 {
	Nk := len(key) / 4 // number of 32-bit words in the key
	Nr := Nk + 6       // number of rounds
	w := make([]uint32, 4*(Nr+1))

	// Load the key bytes into the first Nk words (MSB first).
	for i := 0; i < Nk; i++ {
		w[i] = uint32(key[4*i])<<24 | uint32(key[4*i+1])<<16 |
			uint32(key[4*i+2])<<8 | uint32(key[4*i+3])
	}

	// Derive each remaining word from Nk preceeding words.
	for i := Nk; i < len(w); i++ {
		temp := w[i-1]
		if i%Nk == 0 {
			// Every Nk-th word: rotate left, substitute with S-box, XOR round constant.
			temp = subWord(rotWord(temp)) ^ rcon[i/Nk]
		} else if Nk > 6 && i%Nk == 4 {
			// AES-256 only: extra SubWord step every 4 words within an Nk-word group.
			temp = subWord(temp)
		}
		w[i] = w[i-Nk] ^ temp
	}
	return w
}

// rotWord rotates a 32-bit word left by one byte (circular):
//
// See https://en.wikipedia.org/wiki/AES_key_schedule
func rotWord(w uint32) uint32 {
	return (w << 8) | (w >> 24)
}

// subWord applies the S-box independently to each byte of a 32-bit word.
//
// See FIPS 197 (Section 5.2)
func subWord(w uint32) uint32 {
	return uint32(sbox[w>>24])<<24 |
		uint32(sbox[(w>>16)&0xff])<<16 |
		uint32(sbox[(w>>8)&0xff])<<8 |
		uint32(sbox[w&0xff])
}

// encryptBlock encrypts a single 16-byte block with the given round keys (From expandKey).
//
// Encryption steps. See FIPS 197 (Section 5.1):
//  1. Initial AddRoundKey
//  2. Nr-1 full rounds:
//     2.1 SubBytes
//     2.2 ShiftRows
//     2.3 MixColumns
//     2.4 AddRoundKey
//  3. Final round:
//     3.1 SubBytes
//     3.2 ShiftRows
//     3.3 AddRoundKey (MixColumns not needed)
func encryptBlock(block [16]byte, roundKeys []uint32) [16]byte {
	Nr := len(roundKeys)/4 - 1 // inferred from number or round key words

	var s State
	stateFromBlock(&s, block)

	addRoundKey(&s, roundKeys, 0)

	for round := 1; round < Nr; round++ {
		subBytes(&s)
		shiftRows(&s)
		mixColumns(&s)
		addRoundKey(&s, roundKeys, round)
	}

	// Final round
	subBytes(&s)
	shiftRows(&s)
	addRoundKey(&s, roundKeys, Nr)

	return stateToBlock(&s)
}

// decryptBlock decrypts a single 16-byte block with the given round keys.
//
// Disassembly is the reverse of assembly (FIPS 197 Section 5.3):
//  1. Initial AddRoundKey (with last round key)
//  2. Nr-1 full rounds:
//     2.1 InvShiftRows
//     2.2 InvSubBytes
//     2.3 AddRoundKey
//     2.4 InvMixColumns
//  3. Final round:
//     3.1 InvShiftRows
//     3.2 InvSubBytes
//     3.3 AddRoundKey (InvMixColumns not needed)
func decryptBlock(block [16]byte, roundKeys []uint32) [16]byte {
	Nr := len(roundKeys)/4 - 1

	var s State
	stateFromBlock(&s, block)

	addRoundKey(&s, roundKeys, Nr)

	for round := Nr - 1; round >= 1; round-- {
		invShiftRows(&s)
		invSubBytes(&s)
		addRoundKey(&s, roundKeys, round)
		invMixColumns(&s)
	}

	// Final round
	invShiftRows(&s)
	invSubBytes(&s)
	addRoundKey(&s, roundKeys, 0)

	return stateToBlock(&s)
}

// subBytes replaces each byte with its S-box value.
func subBytes(s *State) {
	for row := range s {
		for col := range s[row] {
			s[row][col] = sbox[s[row][col]]
		}
	}
}

// invSubBytes is the inverse of subBytes.
func invSubBytes(s *State) {
	for row := range s {
		for col := range s[row] {
			s[row][col] = invSbox[s[row][col]]
		}
	}
}

// shiftRows cyclically shifts row r of the state left by r positions.
//
//	Row 0 - ignored
//	Row 1 - shift left 1
//	Row 2 - shift left 2
//	Row 3 - shift left 3
//
//	See FIPS 197 (Section 5.1.2, Fig. 3)
func shiftRows(s *State) {
	s[1][0], s[1][1], s[1][2], s[1][3] = s[1][1], s[1][2], s[1][3], s[1][0]
	s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
	s[3][0], s[3][1], s[3][2], s[3][3] = s[3][3], s[3][0], s[3][1], s[3][2]
}

// invShiftRows is the inverse of shiftRows
func invShiftRows(s *State) {
	s[1][0], s[1][1], s[1][2], s[1][3] = s[1][3], s[1][0], s[1][1], s[1][2]
	s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
	s[3][0], s[3][1], s[3][2], s[3][3] = s[3][1], s[3][2], s[3][3], s[3][0]
}

// mixColumns multiplies each column of the state by a fixed matrix.
// See FIPS 197, Section 5.1.3, example 5.8
//
//	[2 3 1 1]
//	[1 2 3 1]
//	[1 1 2 3]
//	[3 1 1 2]
func mixColumns(s *State) {
	for col := 0; col < 4; col++ {
		a, b, c, d := s[0][col], s[1][col], s[2][col], s[3][col]
		s[0][col] = gmul(2, a) ^ gmul(3, b) ^ c ^ d
		s[1][col] = a ^ gmul(2, b) ^ gmul(3, c) ^ d
		s[2][col] = a ^ b ^ gmul(2, c) ^ gmul(3, d)
		s[3][col] = gmul(3, a) ^ b ^ c ^ gmul(2, d)
	}
}

// invMixColumns undoes mixColumns using an inverse fixed matrix.
// See FIPS 197 Section 5.3.3
//
//	[14 11 13  9]
//	[ 9 14 11 13]
//	[13  9 14 11]
//	[11 13  9 14]
func invMixColumns(s *State) {
	for col := 0; col < 4; col++ {
		a, b, c, d := s[0][col], s[1][col], s[2][col], s[3][col]
		s[0][col] = gmul(14, a) ^ gmul(11, b) ^ gmul(13, c) ^ gmul(9, d)
		s[1][col] = gmul(9, a) ^ gmul(14, b) ^ gmul(11, c) ^ gmul(13, d)
		s[2][col] = gmul(13, a) ^ gmul(9, b) ^ gmul(14, c) ^ gmul(11, d)
		s[3][col] = gmul(11, a) ^ gmul(13, b) ^ gmul(9, c) ^ gmul(14, d)
	}
}

// addRoundKey XORs the state with the round key for the given round.
//
// Round keys are stored as 4 consecutive words in roundKeys, starting at
// index round*4. Each word encodes one column, MSB = row 0, LSB = row 3.
//
// See FIPS 197 Section 5.4
func addRoundKey(s *State, roundKeys []uint32, round int) {
	for col := 0; col < 4; col++ {
		w := roundKeys[round*4+col]
		s[0][col] ^= byte(w >> 24)
		s[1][col] ^= byte(w >> 16)
		s[2][col] ^= byte(w >> 8)
		s[3][col] ^= byte(w)
	}
}
