# Week 3 — ChaCha20 and Password-Based Encryption

## Overview

File encryption with ChaCha20, a controlled ciphertext modification attack, and key derivation from a passphrase using PBKDF2. These exercises explore confidentiality, nonce reuse, and the absence of integrity protection in an unauthenticated stream cipher.

## Implemented Programs

| File | Description |
|---|---|
| `cfich_chacha20.py` | Generates a 32-byte key and encrypts or decrypts binary files. |
| `chacha20_int_attack.py` | Changes a known plaintext fragment by modifying the corresponding ciphertext bytes without knowing the key. |
| `pbenc_chacha20.py` | Derives a 32-byte key from a passphrase using PBKDF2-HMAC-SHA256, a random 16-byte salt, and 1,200,000 iterations. |

## Requirements

Python 3 and the `cryptography` library:

```bash
python3 -m pip install cryptography
```

Run the examples from `week03/`.

## File Formats

| Program | Stored fields, in order |
|---|---|
| `cfich_chacha20.py` | 16-byte counter/nonce header, ciphertext |
| `pbenc_chacha20.py` | 16-byte salt, 16-byte counter/nonce header, ciphertext |

The low-level ChaCha20 API used here takes an 8-byte little-endian counter followed by an 8-byte nonce. Encryption starts the counter at zero and generates a fresh random nonce. The salt and nonce are public information needed for decryption; neither needs to be secret. Neither format includes an authentication tag.

## Usage

### File Encryption

```bash
printf 'Transfer 100 euros' > message.txt
python3 cfich_chacha20.py setup file.key
python3 cfich_chacha20.py enc message.txt file.key
python3 cfich_chacha20.py dec message.txt.enc file.key
```

The recovered file is `message.txt.enc.dec` and should match `message.txt` byte for byte.

### Controlled Modification

Using the ciphertext from the previous example:

```bash
python3 chacha20_int_attack.py message.txt.enc 9 100 900
python3 cfich_chacha20.py dec message.txt.enc.attck file.key
```

The resulting `message.txt.enc.attck.dec` contains `Transfer 900 euros`. The attack preserves the header and changes only the selected ciphertext bytes.

Positions are zero-based byte offsets in the plaintext, excluding the 16-byte header. Fragments are encoded as UTF-8. A shorter replacement is padded with ASCII spaces to preserve the original byte length; longer replacements and out-of-range positions are rejected. The original fragment must be known correctly: the attack cannot verify it without the key. This script targets the format produced by `cfich_chacha20.py`.

### Password-Based Encryption

```bash
python3 pbenc_chacha20.py enc message.txt
python3 pbenc_chacha20.py dec message.txt.enc
```

Enter the same passphrase at each prompt. The program reads it from standard input using `input()`; terminal input is visible. Encryption writes `message.txt.enc`, and decryption writes `message.txt.enc.dec`. This example overwrites the encrypted file from the earlier example with the password-based format.

## Security Analysis

### Q2 — What happens if the nonce is fixed?

Reusing the same key, nonce, and initial counter repeats the keystream. If `C1 = P1 XOR S` and `C2 = P2 XOR S`, then:

```text
C1 XOR C2 = P1 XOR P2
```

A known plaintext fragment reveals the corresponding keystream bytes and therefore the same positions in another message encrypted with that keystream. A fixed nonce is especially dangerous when the key is reused; a public or all-zero nonce is not inherently a secret that has been disclosed.

The nonce must not repeat under the same key. Random generation makes collisions unlikely for a small exercise, but an 8-byte random nonce does not guarantee uniqueness and collision risk grows with the number of encryptions.

### Q3 — Can one flipped bit alter the entire file?

In the ciphertext payload, flipping one bit flips only the corresponding plaintext bit because decryption computes `P = C XOR S`. It does not propagate through the remaining plaintext. This enables a controlled replacement with:

```text
C' = C XOR P XOR P'
```

Here `P` is the known fragment and `P'` is the desired replacement. Without authentication, decryption accepts the modified ciphertext.

The stored file also contains a header. Changing the nonce or counter there changes the keystream and can corrupt the entire recovered payload. Thus, for the complete `.enc` file, a header bit change can have a much broader effect than a payload bit change; it does not provide the same controlled replacement. The attack script preserves this header.

### Passphrases and Authentication

PBKDF2 derives a key for every supplied passphrase. A wrong passphrase produces a different key, and ChaCha20 then produces incorrect bytes without detecting the mistake. The program has no reliable wrong-passphrase or tampering check.

The salt prevents identical passphrases from routinely producing identical derived keys across files, while the iteration count increases the cost of password guessing. Neither provides integrity protection or compensates for a weak passphrase.

These exercises deliberately use unauthenticated ChaCha20 to demonstrate this limitation. An authenticated construction such as ChaCha20-Poly1305 would be appropriate when integrity and authenticity are required.
