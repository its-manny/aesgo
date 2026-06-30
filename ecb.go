package main

import (
	"errors"
	"fmt"
)

const blockSize = 16 // AES block size is always 16 bytes, regardless of key size.

// ECBEncrypt encrypts plaintext using AES in ECB (Electronic Codebook) mode.
//
// In ECB mode each 16-byte block is encrypted independently with the same key.
// The plaintext is padded to a block boundary with PKCS#7 before encryption.
//
// The key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
// The returned ciphertext has the same length as the padded plaintext.
//
// Note: ECB mode is deterministic — identical plaintext blocks always produce
// identical ciphertext blocks, which leaks structural information. It is used
// here for educational purposes.
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
// Each 16-byte block is decrypted independently. PKCS#7 padding is removed
// from the resulting plaintext.
//
// The key must be 16, 24, or 32 bytes. The ciphertext length must be a
// non-zero multiple of 16 bytes.
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
