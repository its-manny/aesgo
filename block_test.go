package main

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// WARNING: Gratuitous AI-generated tests below. Seem OK though...

// decodeHex is a test helper that decodes a hex string or fails the test.
func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// makeKey returns a key of n bytes with values 1, 2, …, n.
func makeKey(n int) []byte {
	k := make([]byte, n)
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// TestFIPS197Vectors tests the AES block cipher against known-answer test
// vectors from FIPS 197. These exercise encryptBlock and decryptBlock directly,
// bypassing padding and ECB mode, so they test the cipher core in isolation.
//
// Sources:
//   - Appendix B:   https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf §B
//   - Appendix C.1: ibid §C.1 (AES-128)
//   - Appendix C.2: ibid §C.2 (AES-192)
//   - Appendix C.3: ibid §C.3 (AES-256)
func TestFIPS197Vectors(t *testing.T) {
	type vector struct {
		name   string
		keyHex string
		ptHex  string
		ctHex  string
	}
	vectors := []vector{
		{
			name:   "Appendix B (AES-128)",
			keyHex: "2b7e151628aed2a6abf7158809cf4f3c",
			ptHex:  "3243f6a8885a308d313198a2e0370734",
			ctHex:  "3925841d02dc09fbdc118597196a0b32",
		},
		{
			name:   "Appendix C.1 (AES-128)",
			keyHex: "000102030405060708090a0b0c0d0e0f",
			ptHex:  "00112233445566778899aabbccddeeff",
			ctHex:  "69c4e0d86a7b0430d8cdb78070b4c55a",
		},
		{
			name:   "Appendix C.2 (AES-192)",
			keyHex: "000102030405060708090a0b0c0d0e0f1011121314151617",
			ptHex:  "00112233445566778899aabbccddeeff",
			ctHex:  "dda97ca4864cdfe06eaf70a0ec0d7191",
		},
		{
			name:   "Appendix C.3 (AES-256)",
			keyHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			ptHex:  "00112233445566778899aabbccddeeff",
			ctHex:  "8ea2b7ca516745bfeafc49904b496089",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			key := decodeHex(t, v.keyHex)
			pt := decodeHex(t, v.ptHex)
			wantCT := decodeHex(t, v.ctHex)

			roundKeys := expandKey(key)

			var block [16]byte
			copy(block[:], pt)
			ct := encryptBlock(block, roundKeys)
			if !bytes.Equal(ct[:], wantCT) {
				t.Errorf("encryptBlock\n got  %x\n want %x", ct, wantCT)
			}

			copy(block[:], wantCT)
			got := decryptBlock(block, roundKeys)
			if !bytes.Equal(got[:], pt) {
				t.Errorf("decryptBlock\n got  %x\n want %x", got, pt)
			}
		})
	}
}

// TestNISTVectors tests the AES block cipher against GFSBox Known-Answer Test
// vectors from the NIST AES Algorithm Validation Suite (AESAVS). These use an
// all-zero key with non-trivial plaintexts chosen to exercise the GF(2^8) logic.
//
// Source: NIST AESAVS, ECBGFSbox128/192/256.rsp
func TestNISTVectors(t *testing.T) {
	type vector struct {
		name   string
		keyHex string
		ptHex  string
		ctHex  string
	}
	vectors := []vector{
		{
			name:   "AESAVS GFSBox AES-128",
			keyHex: "00000000000000000000000000000000",
			ptHex:  "f34481ec3cc627bacd5dc3fb08f273e6",
			ctHex:  "0336763e966d92595a567cc9ce537f5e",
		},
		{
			name:   "AESAVS GFSBox AES-192",
			keyHex: "000000000000000000000000000000000000000000000000",
			ptHex:  "1b077a6af4b7f98229de786d7516b639",
			ctHex:  "275cfc0413d8ccb70513c3859b1d0f72",
		},
		{
			name:   "AESAVS GFSBox AES-256",
			keyHex: "0000000000000000000000000000000000000000000000000000000000000000",
			ptHex:  "014730f80ac625fe84f026c60bfd547d",
			ctHex:  "5c9d844ed46f9885085e5d6a4f94c7d7",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			key := decodeHex(t, v.keyHex)
			pt := decodeHex(t, v.ptHex)
			wantCT := decodeHex(t, v.ctHex)

			roundKeys := expandKey(key)

			var block [16]byte
			copy(block[:], pt)
			ct := encryptBlock(block, roundKeys)
			if !bytes.Equal(ct[:], wantCT) {
				t.Errorf("encryptBlock\n got  %x\n want %x", ct, wantCT)
			}

			copy(block[:], wantCT)
			got := decryptBlock(block, roundKeys)
			if !bytes.Equal(got[:], pt) {
				t.Errorf("decryptBlock\n got  %x\n want %x", got, pt)
			}
		})
	}
}
