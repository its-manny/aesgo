# aesgo

An implementation of AES (Advanced Encryption Standard) ECB and CBC modes in Go, without `crypto/aes` or other external dependencies (well, apart from `rand` for easy IV generation in CBC mode, but I'm not counting that).

The goal here was to better understand the AES algorithm as part of my postgraduate cryptography studies, so the implementation focuses on clarity rather than performance (or necessarily robust security). As a result, method comments have links to the documentation I referenced during implementation.

Supports **AES-128, AES-192, and AES-256** in **ECB** and **CBC** modes, with a CLI for encrypting and decrypting text.

> **_FOR LEARNING PURPOSES:_**  Don't use this for real-world applications obviously.

*ps. yes, the tests are AI-generated. They are at least reasonably robust. So much to do, so little time...*

---

## Build & Run

```sh
cd /path/to/aesgo
go build -o aesgo .
```

Run the tests (FIPS 197, NIST AESAVS, symmetry and CBC chaining):

```sh
go test -v
```

---

## Usage

```
```
aesgo encrypt -key <key> -plaintext <text> [-mode ecb|cbc]
aesgo decrypt -key <key> -ciphertext <hex> [-mode ecb|cbc]
```
```

The key is passed as a UTF-8 string and must be 16, 24, or 32 bytes long. The app will determine the appropriate AES variant and number of rounds as follows:

| Key length | Variant  | Rounds |
|------------|----------|--------|
| 16 bytes   | AES-128  | 10     |
| 24 bytes   | AES-192  | 12     |
| 32 bytes   | AES-256  | 14     |

Both encryption and decryption commands accept a `-mode` flag to select the cipher mode:

| Flag | Mode | Notes |
|------|------|-------|
| `-mode ecb` | ECB (default) | Each block encrypted independently |
| `-mode cbc` | CBC | Random IV prepended to ciphertext |

### ECB (Electronic Codebook) mode

```sh
aesgo encrypt -key "mysecretkey12345" -plaintext "Hello, World!!!"
# → 0e8a766ad5546838c83a79ae08b1e6ed

aesgo decrypt -key "mysecretkey12345" -ciphertext "0e8a766ad5546838c83a79ae08b1e6ed"
# → Hello, World!!!
```

> **Note on ECB mode:** ECB encrypts each 16-byte block independently, so identical plaintext blocks always produce identical ciphertext blocks. For more info on this weakness see [Wikipedia: Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB))

### CBC (Cipher Block Chaining) mode

```sh
./aesgo encrypt -key "mysecretkey12345" -plaintext "Hello, World!!!" -mode cbc
# → e.g. a3f1...9c (32 bytes: 16-byte random IV + 16-byte ciphertext, hex-encoded)

./aesgo decrypt -key "mysecretkey12345" -ciphertext "<hex from above>" -mode cbc
# → Hello, World!!!
```

In CBC mode a random IV is embedded in the ciphertext output (first 16 bytes) and extracted automatically on decryption.

---

## Implementation

The source is split into six files, each with a single focused concern:

| File          | Contents |
|---------------|----------|
| `sbox.go`     | S-box and inverse S-box lookup tables, GF(2⁸) multiplication (`gmul`), round constants (`rcon`) |
| `aes.go`      | `State` type, key schedule (`expandKey`), block encrypt/decrypt, all round functions |
| `ecb.go`      | ECB mode (`ECBEncrypt` / `ECBDecrypt`), key validation |
| `cbc.go`      | CBC mode (`CBCEncrypt` / `CBCDecrypt`), internal `cbcEncrypt` / `cbcDecrypt` with explicit IV |
| `padding.go`  | PKCS#7 padding and unpadding |
| `aesgo.go`    | CLI entry point (`encrypt` / `decrypt` subcommands with `-mode` flag) |

---

## One day...

I'd like to add more modes of operation to this implementaion:
- Cipher Feedback (CFB) and Output Feedback (OFB) modes
- Counter (CTR) mode
- Galois Counter Mode (GCM), and perhaps GCM-SIV (I don't understand the maths behind Galois/finite fields well enough yet for this one).

---

## References

- [FIPS 197 — Advanced Encryption Standard (AES)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) — The spec used for implementation; Appendix B and C contain the block cipher test vectors
- [NIST SP 800-38A — Recommendation for Block Cipher Modes of Operation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf) — Explains the modes of operation; Appendix F.2 contains the CBC test vectors
- [NIST AESAVS — AES Algorithm Validation Suite](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers) — source of the GFSBox Known-Answer Test vectors
- [RFC 5652 §6.3 — PKCS#7 Content Encryption](https://www.rfc-editor.org/rfc/rfc5652#section-6.3) — padding scheme specification
- [Wikipedia: Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) — accessible overview of the algorithm
- [Wikipedia: Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) — explains ECB, CBC, and other modes, shout-out to the EBC penguin
- [Wikipedia: Finite field arithmetic](https://en.wikipedia.org/wiki/Finite_field_arithmetic) — background on GF(2⁸) arithmetic used in MixColumns
