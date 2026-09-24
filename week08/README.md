# Week 8 — Digital Signatures and DH File Encryption

## Overview

`cfich_nikesig.py` extends Week 7 with RSA signatures. The recipient's DH public key is signed using their RSA private key, and the sender signs the message before encrypting it. The program combines DH, HKDF-SHA256, AES-GCM and RSA-PSS with SHA-256.

## Requirements and Usage

Python 3 and `cryptography`:

```bash
python3 -m pip install cryptography
```

Run from this directory:

```bash
python3 cfich_nikesig.py setup bob
python3 cfich_nikesig.py setup alice
printf 'Hello Bob!\n' > message.txt
python3 cfich_nikesig.py enc bob alice message.txt
python3 cfich_nikesig.py dec bob alice message.txt.enc
```

The recovered file is `message.txt.enc.dec`.

| Command | Required files | Output |
| --- | --- | --- |
| `setup <user>` | None | `<user>.dhpk`, `<user>.dhsk`, `<user>.rsapk`, `<user>.rsask` |
| `enc <user> <me> <file>` | Recipient's `.dhpk` and `.rsapk`; sender's `.rsask`; plaintext | `<file>.enc` |
| `dec <me> <user> <file>` | Recipient's `.dhsk`; sender's `.rsapk`; encrypted file | `<file>.dec` |

For encryption, the recipient comes first and the sender second. For decryption, the recipient still comes first: `<me>` is now the person decrypting, and `<user>` is the expected sender.

Setup refuses to run if any of its four output paths already exists. Private keys are unencrypted PKCS8 PEM; standalone public keys are SubjectPublicKeyInfo PEM. The `.dhpk` file is a binary pair containing a PEM public key and its signature, rather than a standalone PEM file. The repository ignores `*.dhsk` and `*.rsask`.

Output suffixes are always appended. Successful encryption or decryption replaces an existing output of the same name. Invalid inputs or failed cryptographic checks do not create or overwrite that output. File-system write failures are reported but writes are not transactional.

## How It Works

1. Each user generates a DH pair using the program's fixed parameters and an RSA-2048 pair with public exponent 65537. Their RSA private key signs the serialized DH public key.
2. Alice verifies Bob's DH public-key signature against Bob's trusted RSA public key before loading and using the DH key.
3. Alice generates a fresh ephemeral DH pair, computes the shared secret and derives a 32-byte AES key using HKDF-SHA256 (`salt=None`, `info=None`).
4. Alice signs the original message with her RSA private key using PSS, MGF1-SHA256, SHA-256 and `PSS.MAX_LENGTH`.
5. Alice packs the signature and message together, then encrypts that payload using AES-GCM with a fresh 12-byte nonce. The ephemeral DH public key is included in the outer file.
6. Bob derives the same AES key, authenticates and decrypts the payload, and verifies Alice's RSA signature using the expected sender's trusted public key. Only then is the recovered message written.

The fixed AAD is `authenticated but unencrypted data`. It is a shared program constant, not a sender identity. Alice's ephemeral DH private key is not saved.

## File Formats

`mkpair(x, y)` encodes `len(x)` as two unsigned little-endian bytes, followed by `x` and `y`. The first component must contain 1–65,535 bytes; the second occupies the remaining bytes.

| Structure | First component | Second component |
| --- | --- | --- |
| Signed DH public key (`.dhpk`) | DH public key in PEM | RSA signature over those exact PEM bytes |
| Payload before encryption | RSA signature over the message | Original message |
| Encrypted file | Ephemeral DH public key in PEM | AES-GCM nonce, ciphertext and tag |

AES-GCM stores a 12-byte nonce followed by ciphertext and a 16-byte tag. An RSA-2048 signature is 256 bytes. Putting the signature first in the inner pair avoids restricting messages to 65,535 bytes. Empty and binary messages are supported; files are processed in memory.

The program validates pair boundaries, the minimum AES-GCM length and loaded key types. Invalid RSA signatures, failed AES-GCM authentication, malformed inputs and file-access errors return a nonzero exit status. A wrong recipient or altered encrypted data may fail at parsing, key agreement or authentication depending on the change.

## Security Scope

This is an educational sign-then-encrypt construction. **RSA public keys must be obtained through a trusted channel.** A signature on a DH public key binds it to the RSA key used for verification; it does not independently establish the owner's real-world identity. Replacing both recipient public-key files with an attacker's matching pair defeats an untrusted distribution process.

Unlike Week 7, decryption verifies a signature from the expected sender as well as AES-GCM authentication. Anyone can still encrypt data to Bob using his public keys, but cannot produce Alice's valid message signature without her signing key (assuming the signature scheme remains secure).

The message signature does not explicitly bind the recipient or a unique communication identifier. The exercise does not provide replay protection or a complete messaging protocol. In particular, a recipient can re-encrypt a signed message for someone else without changing its signature.

Private keys are stored without passwords and must be kept private. Later compromise of Bob's long-term DH private key permits decryption of previously saved encrypted files: the scheme does not provide forward secrecy against that compromise. Signing keys and DH keys have distinct roles; compromise of a signing key enables impersonation, while compromise of the recipient's DH key exposes confidentiality.

## References

- [RSA signing and verification — cryptography](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/rsa/)
- [AES-GCM — cryptography](https://cryptography.io/en/stable/hazmat/primitives/aead/)
