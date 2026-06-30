package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// cbcEncrypt encrypts plaintext using AES-CBC with a caller-supplied IV.
//
// The plaintext must already be padded to a multiple of blockSize bytes.
// Each plaintext block is XORed with the previous ciphertext block (or the
// IV for the first block) before being encrypted:
//
//	C[0] = Encrypt(P[0] XOR IV)
//	C[i] = Encrypt(P[i] XOR C[i-1])
//
// This function is internal so that tests can supply a fixed IV for
// deterministic verification against known test vectors.
func cbcEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV must be %d bytes; got %d", blockSize, len(iv))
	}
	if len(plaintext)%blockSize != 0 {
		return nil, fmt.Errorf("plaintext length (%d) is not a multiple of block size (%d); pad before calling cbcEncrypt", len(plaintext), blockSize)
	}

	roundKeys := expandKey(key)
	ciphertext := make([]byte, len(plaintext))
	prev := iv

	for i := 0; i < len(plaintext); i += blockSize {
		var block [16]byte
		// XOR plaintext block with previous ciphertext block (or IV).
		for j := 0; j < blockSize; j++ {
			block[j] = plaintext[i+j] ^ prev[j]
		}
		encrypted := encryptBlock(block, roundKeys)
		copy(ciphertext[i:], encrypted[:])
		prev = ciphertext[i : i+blockSize]
	}
	return ciphertext, nil
}

// cbcDecrypt decrypts ciphertext using AES-CBC with a caller-supplied IV.
//
// Each ciphertext block is decrypted, then XORed with the previous ciphertext
// block (or the IV for the first block):
//
//	P[0] = Decrypt(C[0]) XOR IV
//	P[i] = Decrypt(C[i]) XOR C[i-1]
//
// The returned plaintext is still padded; call pkcs7Unpad to strip it.
func cbcDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if len(iv) != blockSize {
		return nil, fmt.Errorf("IV must be %d bytes; got %d", blockSize, len(iv))
	}
	if len(ciphertext) == 0 {
		return nil, errors.New("ciphertext is empty")
	}
	if len(ciphertext)%blockSize != 0 {
		return nil, fmt.Errorf("ciphertext length (%d) is not a multiple of block size (%d)", len(ciphertext), blockSize)
	}

	roundKeys := expandKey(key)
	plaintext := make([]byte, len(ciphertext))
	prev := iv

	for i := 0; i < len(ciphertext); i += blockSize {
		var block [16]byte
		copy(block[:], ciphertext[i:i+blockSize])
		decrypted := decryptBlock(block, roundKeys)
		// XOR decrypted block with previous ciphertext block (or IV).
		for j := 0; j < blockSize; j++ {
			plaintext[i+j] = decrypted[j] ^ prev[j]
		}
		prev = ciphertext[i : i+blockSize]
	}
	return plaintext, nil
}

// CBCEncrypt encrypts plaintext using AES-CBC mode.
//
// A random 16-byte IV is generated and prepended to the returned ciphertext:
//
//	output = [ IV (16 bytes) | encrypted blocks... ]
//
// The caller does not need to manage the IV; CBCDecrypt will extract it
// automatically from the same output.
//
// The key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
func CBCEncrypt(key, plaintext []byte) ([]byte, error) {
	iv := make([]byte, blockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}
	padded := pkcs7Pad(plaintext, blockSize)
	ct, err := cbcEncrypt(key, iv, padded)
	if err != nil {
		return nil, err
	}
	// Prepend the IV so the receiver can decrypt without a separate channel.
	return append(iv, ct...), nil
}

// CBCDecrypt decrypts ciphertext produced by CBCEncrypt.
//
// It expects the first 16 bytes to be the IV, followed by the encrypted blocks:
//
//	input = [ IV (16 bytes) | encrypted blocks... ]
//
// The key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256.
func CBCDecrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 2*blockSize {
		return nil, fmt.Errorf("ciphertext too short: must be at least %d bytes (IV + one block)", 2*blockSize)
	}
	iv := ciphertext[:blockSize]
	ct := ciphertext[blockSize:]
	padded, err := cbcDecrypt(key, iv, ct)
	if err != nil {
		return nil, err
	}
	return pkcs7Unpad(padded)
}
