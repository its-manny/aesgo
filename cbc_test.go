package main

import (
	"bytes"
	"testing"
)

// WARNING: Gratuitous AI-generated tests below. Seem OK though...

// TestCBCVectors tests cbcEncrypt and cbcDecrypt against the NIST SP 800-38A
// Appendix F.2 Known-Answer Test vectors. Using a fixed IV makes the output
// deterministic and directly comparable to the published values.
//
// Each test case covers a 4-block (64-byte) message to exercise chaining
// across multiple blocks.
//
// Source: NIST SP 800-38A, §F.2
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
func TestCBCVectors(t *testing.T) {
	type vector struct {
		name   string
		keyHex string
		ivHex  string
		ptHex  string // 4 concatenated blocks
		ctHex  string // 4 concatenated blocks
	}

	vectors := []vector{
		{
			name:   "F.2.1/F.2.2 AES-128-CBC",
			keyHex: "2b7e151628aed2a6abf7158809cf4f3c",
			ivHex:  "000102030405060708090a0b0c0d0e0f",
			ptHex: "6bc1bee22e409f96e93d7e117393172a" +
				"ae2d8a571e03ac9c9eb76fac45af8e51" +
				"30c81c46a35ce411e5fbc1191a0a52ef" +
				"f69f2445df4f9b17ad2b417be66c3710",
			ctHex: "7649abac8119b246cee98e9b12e9197d" +
				"5086cb9b507219ee95db113a917678b2" +
				"73bed6b8e3c1743b7116e69e22229516" +
				"3ff1caa1681fac09120eca307586e1a7",
		},
		{
			name:   "F.2.3/F.2.4 AES-192-CBC",
			keyHex: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
			ivHex:  "000102030405060708090a0b0c0d0e0f",
			ptHex: "6bc1bee22e409f96e93d7e117393172a" +
				"ae2d8a571e03ac9c9eb76fac45af8e51" +
				"30c81c46a35ce411e5fbc1191a0a52ef" +
				"f69f2445df4f9b17ad2b417be66c3710",
			ctHex: "4f021db243bc633d7178183a9fa071e8" +
				"b4d9ada9ad7dedf4e5e738763f69145a" +
				"571b242012fb7ae07fa9baac3df102e0" +
				"08b0e27988598881d920a9e64f5615cd",
		},
		{
			name:   "F.2.5/F.2.6 AES-256-CBC",
			keyHex: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
			ivHex:  "000102030405060708090a0b0c0d0e0f",
			ptHex: "6bc1bee22e409f96e93d7e117393172a" +
				"ae2d8a571e03ac9c9eb76fac45af8e51" +
				"30c81c46a35ce411e5fbc1191a0a52ef" +
				"f69f2445df4f9b17ad2b417be66c3710",
			ctHex: "f58c4c04d6e5f1ba779eabfb5f7bfbd6" +
				"9cfc4e967edb808d679f777bc6702c7d" +
				"39f23369a9d9bacfa530e26304231461" +
				"b2eb05e2c39be9fcda6c19078c6a9d1b",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			key := decodeHex(t, v.keyHex)
			iv := decodeHex(t, v.ivHex)
			pt := decodeHex(t, v.ptHex)
			wantCT := decodeHex(t, v.ctHex)

			// The NIST vectors use unpadded block-aligned plaintext.
			ct, err := cbcEncrypt(key, iv, pt)
			if err != nil {
				t.Fatalf("cbcEncrypt: %v", err)
			}
			if !bytes.Equal(ct, wantCT) {
				t.Errorf("cbcEncrypt\n got  %x\n want %x", ct, wantCT)
			}

			got, err := cbcDecrypt(key, iv, wantCT)
			if err != nil {
				t.Fatalf("cbcDecrypt: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Errorf("cbcDecrypt\n got  %x\n want %x", got, pt)
			}
		})
	}
}

// TestCBCSymmetry verifies that CBCEncrypt and CBCDecrypt are inverses of each
// other across all supported key sizes and a range of plaintext lengths.
//
// CBCEncrypt generates a fresh random IV on each call and embeds it in the
// output. This test confirms the IV is correctly recovered by CBCDecrypt.
func TestCBCSymmetry(t *testing.T) {
	keys := []struct {
		name string
		key  []byte
	}{
		{"AES-128", makeKey(16)},
		{"AES-192", makeKey(24)},
		{"AES-256", makeKey(32)},
	}

	plaintexts := []struct {
		name string
		data []byte
	}{
		{"empty (0 bytes)", []byte{}},
		{"1 byte", []byte{0x42}},
		{"15 bytes (one short of block)", bytes.Repeat([]byte{0xab}, 15)},
		{"16 bytes (exact block)", bytes.Repeat([]byte{0xcd}, 16)},
		{"17 bytes (one over block)", bytes.Repeat([]byte{0xef}, 17)},
		{"32 bytes (two full blocks)", bytes.Repeat([]byte{0x12}, 32)},
		{"47 bytes (nearly three blocks)", bytes.Repeat([]byte{0x34}, 47)},
	}

	for _, kc := range keys {
		for _, pc := range plaintexts {
			name := kc.name + " / " + pc.name
			t.Run(name, func(t *testing.T) {
				ct, err := CBCEncrypt(kc.key, pc.data)
				if err != nil {
					t.Fatalf("CBCEncrypt: %v", err)
				}

				// Output must be: IV (16 bytes) + padded ciphertext.
				if len(ct) < 2*blockSize {
					t.Errorf("ciphertext too short: got %d bytes, want >= %d", len(ct), 2*blockSize)
				}
				if (len(ct)-blockSize)%blockSize != 0 {
					t.Errorf("ciphertext body length %d is not a multiple of %d", len(ct)-blockSize, blockSize)
				}

				got, err := CBCDecrypt(kc.key, ct)
				if err != nil {
					t.Fatalf("CBCDecrypt: %v", err)
				}

				if !bytes.Equal(got, pc.data) {
					t.Errorf("round-trip mismatch\n got  %x\n want %x", got, pc.data)
				}
			})
		}
	}
}

// TestCBCChainingEffect verifies that changing one ciphertext block affects
// the decryption of that block and the next, but no others — this is a
// fundamental property of CBC mode.
func TestCBCChainingEffect(t *testing.T) {
	key := makeKey(16)
	iv := make([]byte, blockSize) // all-zero IV

	// 3-block plaintext (48 bytes, no padding needed for this raw test).
	pt := bytes.Repeat([]byte{0x00}, 48)
	ct, err := cbcEncrypt(key, iv, pt)
	if err != nil {
		t.Fatalf("cbcEncrypt: %v", err)
	}

	// Corrupt the middle ciphertext block (block 1, bytes 16–31).
	corrupted := make([]byte, len(ct))
	copy(corrupted, ct)
	corrupted[16] ^= 0xff

	got, err := cbcDecrypt(key, iv, corrupted)
	if err != nil {
		t.Fatalf("cbcDecrypt: %v", err)
	}

	block0 := got[:16]
	block1 := got[16:32]
	block2 := got[32:48]

	// Block 0: decrypted from intact C[0] XOR IV → should match original.
	if !bytes.Equal(block0, pt[:16]) {
		t.Errorf("block 0 should be unaffected by corruption of block 1")
	}
	// Block 1: decrypted from corrupted C[1] → should be garbled.
	if bytes.Equal(block1, pt[16:32]) {
		t.Errorf("block 1 should be corrupted (decrypted from the corrupted ciphertext block)")
	}
	// Block 2: decrypted from intact C[2] XOR corrupted C[1] → should be garbled.
	if bytes.Equal(block2, pt[32:48]) {
		t.Errorf("block 2 should be affected (XOR'd with corrupted C[1])")
	}
}

// Ensure decodeHex and makeKey are available (defined in block_test.go).
var _ = decodeHex
