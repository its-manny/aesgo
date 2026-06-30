package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("error: ")

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "encrypt":
		runEncrypt(os.Args[2:])
	case "decrypt":
		runDecrypt(os.Args[2:])
	default:
		log.Fatalf("unknown command %q\n\nRun 'aesgo' with no arguments for usage.", os.Args[1])
	}
}

func runEncrypt(args []string) {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	key := fs.String("key", "", "Encryption key (16, 24, or 32 bytes for AES-128/192/256)")
	plaintext := fs.String("plaintext", "", "Plaintext to encrypt")
	mode := fs.String("mode", "ecb", "Cipher mode: ecb or cbc")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: aesgo encrypt -key <key> -plaintext <text> [-mode ecb|cbc]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *key == "" || *plaintext == "" {
		log.Fatal("-key and -plaintext are required")
	}

	encryptFn, ok := map[string]func([]byte, []byte) ([]byte, error){
		"ecb": ECBEncrypt,
		"cbc": CBCEncrypt,
	}[*mode]
	if !ok {
		log.Fatalf("unknown mode %q (want ecb or cbc)", *mode)
	}

	ciphertext, err := encryptFn([]byte(*key), []byte(*plaintext))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(ciphertext))
}

func runDecrypt(args []string) {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	key := fs.String("key", "", "Decryption key (16, 24, or 32 bytes for AES-128/192/256)")
	ciphertext := fs.String("ciphertext", "", "Hex-encoded ciphertext to decrypt")
	mode := fs.String("mode", "ecb", "Cipher mode: ecb or cbc")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: aesgo decrypt -key <key> -ciphertext <hex> [-mode ecb|cbc]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *key == "" || *ciphertext == "" {
		log.Fatal("-key and -ciphertext are required")
	}

	ctBytes, err := hex.DecodeString(*ciphertext)
	if err != nil {
		log.Fatalf("invalid hex ciphertext: %v", err)
	}

	decryptFn, ok := map[string]func([]byte, []byte) ([]byte, error){
		"ecb": ECBDecrypt,
		"cbc": CBCDecrypt,
	}[*mode]
	if !ok {
		log.Fatalf("unknown mode %q (want ecb or cbc)", *mode)
	}

	plaintext, err := decryptFn([]byte(*key), ctBytes)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(plaintext))
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `aesgo — AES encryption/decryption (educational implementation)

Usage:
  aesgo encrypt -key <key> -plaintext <text> [-mode ecb|cbc]
  aesgo decrypt -key <key> -ciphertext <hex> [-mode ecb|cbc]

The key must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256).
Ciphertext is expected/printed as hex.
Default mode is EBC. CBC mode genereates and prepends a random IV to the ciphertext.`)
}
