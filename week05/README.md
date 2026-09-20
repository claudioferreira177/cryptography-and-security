# Week 5 — CBC Padding Oracle

## Overview

This week demonstrates how a padding validity check can reveal plaintext encrypted with AES-CBC. Starting from PKCS7 padding, the exercises implement a local padding oracle, determine the padding length and recover the final plaintext block without accessing the encryption key.

## Programs

| File | Purpose |
| --- | --- |
| `cbc_pad_orcl.py` | AES-CBC encryption, PKCS7 padding and a boolean padding oracle. Includes valid and invalid input examples and the answer to Q1. |
| `pad_orcl_attck_lastbyte.py` | Determines the original padding length using only oracle queries. |
| `pad_orcl_attck.py` | Recovers the complete final 16-byte plaintext block, including padding. |

## Requirements and Usage

Python 3 and `cryptography`:

```bash
python3 -m pip install cryptography
```

Run each demonstration from this directory:

```bash
python3 cbc_pad_orcl.py
python3 pad_orcl_attck_lastbyte.py
python3 pad_orcl_attck.py
```

The oracle demonstration reports `True` for a valid ciphertext and `False` for invalid padding, truncated input and empty input. The attacks use `b'Ola Mundo'`, recover a padding length of 7 and return the final block followed by its unpadded content, `b'Ola Mundo'`.

Each demonstration generates its own ciphertext and queries the oracle in the same process. The oracle module creates a fresh AES key when loaded; these scripts do not store keys or exchange ciphertext files between executions. The ciphertext format is `IV || ciphertext`, with a 16-byte IV and one or more 16-byte ciphertext blocks.

## Q1 — Invalid Padding with a Valid Block Length

PKCS7 adds between 1 and 16 bytes for AES. Each added byte contains the number of padding bytes. A message already aligned to 16 bytes receives a complete padding block.

A block can have the correct length but invalid padding:

```python
from cbc_pad_orcl import pad, unpad

invalid = pad(b"abc")[:15] + b"\x00"
assert len(invalid) == 16
try:
    unpad(invalid)
except ValueError:
    print("Invalid padding despite a valid block length.")
```

The original padding consists of thirteen `0x0d` bytes. Replacing its final byte with `0x00` preserves the block length but violates PKCS7, which never uses zero-length padding.

## How the Attack Works

For the last CBC block, `P[n] = D_K(C[n]) XOR C[n-1]`. When there is only one ciphertext block, the IV takes the place of `C[n-1]`.

The attacker changes bytes in the preceding block and submits the modified ciphertext to the oracle. The oracle exposes only whether decryption produces valid padding; it returns neither plaintext nor the key.

1. Try each possible value for the final byte of the preceding block until the oracle accepts padding `0x01`. Changing the second-to-last byte confirms that the response does not merely preserve a longer valid padding sequence.
2. Recover the original last plaintext byte, which gives the original PKCS7 padding length. This attack starts from a valid ciphertext.
3. Use the known padding bytes to recover the corresponding intermediate decryption bytes. Then force padding `0x02 0x02`, `0x03 0x03 0x03`, and so on, starting at the first unknown byte and continuing until the entire block is recovered.

The attack functions take a ciphertext and an oracle callable. Only the demonstration setup calls encryption; the attack itself does not import or access the key or decryption function. Invalid starting ciphertexts and unsuccessful recovery raise `ValueError` instead of returning a partial result.

## Scope and Connection to Week 4

The result is a 16-byte `bytes` value containing the final plaintext block **with padding**. Applying `unpad` to that block gives only the message bytes in that block, not the whole message. If the original message length is a multiple of 16, the recovered block consists entirely of padding and its unpadded content is empty. Binary data is preserved without assuming a text encoding.

This is a deliberately vulnerable local demonstration. The weakness comes from exposing padding validity for unauthenticated ciphertexts. The authenticated constructions explored in Week 4 reject tampering before releasing plaintext; for CBC with encrypt-then-MAC, verifying authentication before decryption and padding checks prevents this oracle from being exposed to unauthenticated modifications.
