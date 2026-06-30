package main

import (
	"bytes"
	"testing"
)

// WARNING: Gratuitous AI-generated tests below. Seem OK though...

// TestECBSymmetry verifies that ECBEncrypt and ECBDecrypt are inverses of each
// other across all supported key sizes and a range of plaintext lengths.
//
// This exercises the full ECB pipeline including PKCS#7 padding, ensuring that
// messages shorter than, equal to, and longer than the block size all round-trip
// correctly.
func TestECBSymmetry(t *testing.T) {
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
				ct, err := ECBEncrypt(kc.key, pc.data)
				if err != nil {
					t.Fatalf("ECBEncrypt: %v", err)
				}

				// Ciphertext must be a multiple of the block size.
				if len(ct)%blockSize != 0 {
					t.Errorf("ciphertext length %d is not a multiple of %d", len(ct), blockSize)
				}

				got, err := ECBDecrypt(kc.key, ct)
				if err != nil {
					t.Fatalf("ECBDecrypt: %v", err)
				}

				if !bytes.Equal(got, pc.data) {
					t.Errorf("round-trip mismatch\n got  %x\n want %x", got, pc.data)
				}
			})
		}
	}
}
