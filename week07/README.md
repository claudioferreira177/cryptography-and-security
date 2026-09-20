# Week 7 — Non-Interactive Diffie–Hellman File Encryption

## Overview

`cfich_nike.py` combines Diffie–Hellman key agreement, HKDF-SHA256 and AES-GCM to encrypt a file for a recipient using only their public key. The sender generates an ephemeral DH key pair for each encryption and includes its public key in the encrypted file.

## Requirements and Usage

Python 3 and `cryptography`:

```bash
python3 -m pip install cryptography
```

Run from this directory:

```bash
python3 cfich_nike.py setup bob
printf 'Hello Bob!\n' > message.txt
python3 cfich_nike.py enc bob message.txt
python3 cfich_nike.py dec bob message.txt.enc
```

| Command | Inputs | Output |
| --- | --- | --- |
| `setup <user>` | User name or path prefix | `<user>.pk` and `<user>.sk` |
| `enc <user> <file>` | Recipient's public key and plaintext file | `<file>.enc` |
| `dec <user> <file>` | Recipient's private key and encrypted file | `<file>.dec` |

The example recovers the message in `message.txt.enc.dec`. The suffix is always appended, so an encrypted input does not need to be named with `.enc`. Successful encryption or decryption overwrites an existing output with that name. Failed authentication or invalid input does not create or overwrite the decrypted output.

Setup refuses to run if either key file already exists. Use another user name to generate a separate pair. The private key is stored as unencrypted PKCS8 PEM and the public key as SubjectPublicKeyInfo PEM. Generated private keys (`*.sk`) are excluded by the repository's `.gitignore`.

## How It Works

1. Bob creates a long-term DH key pair using the fixed parameters included in the program.
2. Alice loads Bob's public key and generates an ephemeral key pair using its parameters.
3. Alice computes the DH shared secret and derives a 32-byte AES key with HKDF-SHA256 (`salt=None`, `info=None`).
4. Alice encrypts the file with AES-GCM and a fresh 12-byte nonce, then stores her ephemeral public key alongside the encrypted payload.
5. Bob combines his private key with the included public key to derive the same AES key and authenticate/decrypt the payload.

Alice's ephemeral private key is not saved. Encryption requires only Bob's `.pk` file; decryption requires his `.sk` file. Both operations use the same fixed AAD value, `authenticated but unencrypted data`, defined in the program. It is not an identity claim or user-supplied metadata.

## Encrypted File Format

| Component | Size / encoding |
| --- | --- |
| Length of ephemeral public key | 2 bytes, unsigned little-endian |
| Ephemeral DH public key | PEM, variable length |
| AES-GCM nonce | 12 bytes |
| Ciphertext and authentication tag | Plaintext length plus a 16-byte tag |

`mkpair` stores the public key and encrypted payload together; `unpair` extracts them using the length prefix. The program checks the prefix, component lengths and loaded key types before performing the corresponding cryptographic operations. Empty plaintext files are supported.

Wrong recipient keys or altered encrypted data fail authentication. Malformed files, invalid keys and file access errors produce an error message and a nonzero exit status.

## Security Scope

This is an educational hybrid encryption exercise. Bob's public key must be obtained through a trusted channel: the program does not establish who owns a supplied key.

AES-GCM authenticates the encrypted message under the derived session key, but **does not authenticate Alice's identity**. Anyone holding Bob's public key can create a valid encrypted file for him; no signature is included.

Bob's private key is stored without password protection and must be kept private. The scheme does not provide forward secrecy against later compromise of that long-term key: an attacker with it and previously saved encrypted files can recompute their shared secrets from the included ephemeral public keys.
