# Week 4 — Authenticated Encryption and CBC-MAC

## Overview

This week extends password-based file encryption with integrity protection, combining AES-CTR with HMAC and using two authenticated encryption primitives. It also explores CBC-MAC and demonstrates why its IV must be fixed.

## Programs

| File | Purpose |
| --- | --- |
| `pbenc_aes_ctr_hmac.py` | AES-CTR with HMAC-SHA256 using encrypt-then-MAC. |
| `pbenc_aes_gcm.py` | Password-based AES-GCM encryption with associated data. |
| `pbenc_chacha20_poly1305.py` | Password-based ChaCha20-Poly1305 encryption with associated data. |
| `cbc_mac.py` | CBC-MAC generation and verification with a fixed zero IV. |
| `cbc_mac_rnd.py` | Deliberately vulnerable CBC-MAC variant with a random IV. |

## Requirements

Python 3 and the `cryptography` library:

```bash
python3 -m pip install cryptography
```

Run the examples from this directory.

## Authenticated File Encryption

All three encryption programs derive keys using PBKDF2-HMAC-SHA256 with 1,200,000 iterations and a fresh 16-byte salt. AES-CTR/HMAC splits the 32 derived bytes into separate 16-byte encryption and MAC keys. The AEAD programs use a 32-byte key.

```bash
printf 'Transfer 100 EUR!' > message.txt
python3 pbenc_aes_ctr_hmac.py enc message.txt
python3 pbenc_aes_ctr_hmac.py dec message.txt.enc
```

Enter the same passphrase at both prompts. Encryption produces `<file>.enc`; decryption appends `.dec` to its input name, producing `message.txt.enc.dec` in this example.

Use either `pbenc_aes_gcm.py` or `pbenc_chacha20_poly1305.py` in place of `pbenc_aes_ctr_hmac.py` for the AEAD versions. During encryption, these also prompt for associated data (AAD); press Enter for empty AAD. AAD is stored in cleartext and authenticated, so it must not contain secrets. Decryption reads it from the file.

| Program | Binary file layout, in order |
| --- | --- |
| AES-CTR/HMAC | Salt (16 bytes), nonce (16), HMAC (32), ciphertext. |
| Both AEAD programs | AAD length (4 bytes, unsigned little-endian), salt (16), AAD, nonce (12), ciphertext including its 16-byte tag. |

The HMAC covers the salt, nonce and ciphertext, and is verified before decryption. The AEAD primitives verify authentication before returning plaintext. Authentication failure or malformed input terminates without creating or overwriting the decrypted output.

### Q1 — What happens to the Week 3 integrity attack?

Unauthenticated stream encryption is malleable: changing ciphertext bits changes the corresponding plaintext bits. In an authenticated scheme, that modification also invalidates the authentication tag. Without the key, the attacker cannot compute a valid replacement tag, so decryption rejects the modified file instead of releasing altered plaintext (except with negligible forgery probability).

The Week 3 attack script assumes a different file layout. Its offsets must be adapted to target ciphertext in these formats; running it unchanged does not demonstrate a change at the same plaintext position.

For example, after the AES-CTR/HMAC commands above, flip the first ciphertext byte (offset 64):

```bash
python3 - <<'PY'
from pathlib import Path

ciphertext = bytearray(Path('message.txt.enc').read_bytes())
ciphertext[64] ^= 1
Path('message.txt.tampered').write_bytes(ciphertext)
PY
python3 pbenc_aes_ctr_hmac.py dec message.txt.tampered
```

With the original passphrase, verification fails. No `message.txt.tampered.dec` is produced. The same principle applies to AES-GCM and ChaCha20-Poly1305, including changes to their associated data.

## CBC-MAC

Both programs accept a UTF-8 key of exactly 16, 24 or 32 bytes and apply PKCS7 padding. Here the command-line key is used directly as an AES key; it is not a passphrase processed by a KDF.

```bash
python3 cbc_mac.py tag 0123456789abcdef message.txt
python3 cbc_mac.py verify 0123456789abcdef message.txt message.txt.tag
```

The fixed-IV version writes a 16-byte tag. The random-IV version uses the same commands but writes 32 bytes: the IV followed by the final ciphertext block. Successful verification exits with status zero; an invalid tag raises `InvalidTag` internally, reported as `InvalidTag` with a nonzero exit status by the command-line entry point.

These are educational constructions. Plain CBC-MAC requires a fixed message length for its security guarantee; adding PKCS7 padding does not make it secure for arbitrary message lengths. The random-IV version has an additional weakness even when lengths remain fixed.

### Q2 — Forging CBC-MAC with a random IV

The first CBC block is computed as `C1 = AES_K(M1 XOR IV)`. Given a valid message/tag pair, choose a replacement first block `M1'` and set:

`IV' = IV XOR M1 XOR M1'`

Then `M1' XOR IV' = M1 XOR IV`, so the first ciphertext block stays identical. Keeping the remaining message blocks and message length unchanged also preserves the padding, every subsequent ciphertext block and the final MAC. The attacker needs no key.

This example changes a 16-byte message while preserving verification:

```bash
printf 'Transfer 100 EUR!' > original.txt
python3 cbc_mac_rnd.py tag 0123456789abcdef original.txt

python3 - <<'PY'
from pathlib import Path

original = Path('original.txt').read_bytes()
replacement = b'Transfer 900 EUR!'
tag = Path('original.txt.tag').read_bytes()
forged_iv = bytes(iv ^ old ^ new
                  for iv, old, new in zip(tag[:16], original, replacement))
Path('forged.txt').write_bytes(replacement)
Path('forged.txt.tag').write_bytes(forged_iv + tag[16:])
PY

python3 cbc_mac_rnd.py verify 0123456789abcdef forged.txt forged.txt.tag
```

Verification succeeds despite the changed amount. The key appears only in the legitimate generation and verification commands; the forgery itself uses only the original message/tag pair. A fixed zero IV prevents this specific attack because the verifier does not accept an attacker-supplied IV.
