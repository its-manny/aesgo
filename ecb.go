package main

import (
	"errors"
	"fmt"
)

const blockSize = 16 // AES block size is always 16 bytes, regardless of key size.

// ECBEncrypt encrypts plaintext using AES in ECB (Electronic Codebook) mode.
//
// Plaintext is padded to a block boundary with PKCS#7 then each 16-byte block
// is encrypted independently with the same key.
//
// See NIST SP 800-38A (Section 6.1) and https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#ECB
func ECBEncrypt(key, plaintext []byte) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	roundKeys := expandKey(key)
	padded := pkcs7Pad(plaintext, blockSize)

	ciphertext := make([]byte, len(padded))
	for i := 0; i < len(padded); i += blockSize {
		var block [16]byte
		copy(block[:], padded[i:i+blockSize])
		encrypted := encryptBlock(block, roundKeys)
		copy(ciphertext[i:], encrypted[:])
	}
	return ciphertext, nil
}

// ECBDecrypt decrypts ciphertext using AES in ECB mode.
//
// Each 16-byte block is decrypted independently then PKCS#7 padding is removed.
// The ciphertext length must be a non-zero multiple of 16 bytes.
//
// See NIST SP 800-38A (Section 6.1)
func ECBDecrypt(key, ciphertext []byte) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext is empty")
	}
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length (%d) is not a multiple of block size (%d)", len(ciphertext), blockSize)
	}

	roundKeys := expandKey(key)
	plaintext := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += blockSize {
		var block [16]byte
		copy(block[:], ciphertext[i:i+blockSize])
		decrypted := decryptBlock(block, roundKeys)
		copy(plaintext[i:], decrypted[:])
	}
	return pkcs7Unpad(plaintext)
}

// validateKey returns an error if the key length is not valid for AES.
func validateKey(key []byte) error {
	switch len(key) {
	case 16, 24, 32:
		return nil
	default:
		return fmt.Errorf("key must be 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes; got %d", len(key))
	}
}
