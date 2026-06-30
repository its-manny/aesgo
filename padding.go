package main

import (
	"errors"
	"fmt"
)

// pkcs7Pad appends PKCS#7 padding to data so its length becomes a multiple of blockSize.
//
// Adds a full block of paddinf if the data is already a mutiple of blockSize
// See RFC 2315 (Section 10.3) - https://www.rfc-editor.org/info/rfc2315/
func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}
	return padded
}

// pkcs7Unpad removes PKCS#7 padding from data, returs an error if the padding is wrong
// or the data empty.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7Unpad: data is empty")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > len(data) {
		return nil, fmt.Errorf("pkcs7Unpad: invalid padding length %d", padLen)
	}
	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return nil, fmt.Errorf("pkcs7Unpad: invalid padding byte at position %d", i)
		}
	}
	return data[:len(data)-padLen], nil
}
