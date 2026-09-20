# Week 6 — Cryptographic Security Games

## Overview

This week models confidentiality and integrity games in Python and implements concrete adversaries against insecure constructions. The examples distinguish between guessing a hidden message and forging an accepted message.

## Programs

| File | Purpose |
| --- | --- |
| `indcpa.py` | IND-CPA game with the Identity cipher and ChaCha20, using a direct distinguisher and a random adversary. |
| `indcpa_attck.py` | Distinguishes two-block AES-ECB messages through repeated ciphertext blocks. |
| `indcca_attck.py` | Recovers an AES-CTR challenge message through a modified-ciphertext decryption query. |
| `intptxt_attck.py` | Forges a new accepted message when an unkeyed SHA-256 hash is used as a MAC. |

## Requirements and Usage

Python 3 and `cryptography`:

```bash
python3 -m pip install cryptography
```

Run from this directory:

```bash
python3 indcpa.py
python3 indcpa_attck.py
python3 indcca_attck.py
python3 intptxt_attck.py
```

Each demonstration runs 1,000 trials. The confidentiality games generate a fresh key and challenge bit per trial. Imports do not execute the demonstrations.

| Experiment | Expected success |
| --- | --- |
| Identity cipher with direct comparison | 100% |
| ChaCha20 with an independent random guess | Approximately 50% |
| AES-ECB with repeated blocks | 100% |
| AES-CTR with a modified-ciphertext query | 100% |
| Unkeyed hash with a new-message forgery | 100% |

## IND-CPA: Chosen-Plaintext Confidentiality

The adversary chooses two messages of equal length. The challenger encrypts one according to a hidden random bit, and the adversary guesses that bit. An encryption oracle is available during message selection and guessing. The examples use fixed message lengths; unequal lengths raise `ValueError`.

The Identity cipher returns the plaintext unchanged, so its adversary identifies the message directly. ChaCha20 uses a fresh random 8-byte nonce per encryption, preceded by an 8-byte little-endian counter initially set to zero. This 16-byte header is stored before the ciphertext. The random adversary ignores the ciphertext and guesses a bit.

For the distinguishing games, the scripts report the empirical advantage:

`2 * abs(success_rate - 0.5)`

Perfect distinguishers have advantage 1 (100%). An independent random guess has theoretical success probability 1/2 and advantage zero, but finite samples fluctuate. A result near 50% against ChaCha20 is **not a security proof**: the same random adversary would also score near 50% against an insecure cipher. These simulations demonstrate specific attacks, not security against every possible adversary. Random nonces also have a collision probability; the demonstration is not a general-purpose nonce-management system.

## AES-ECB: Repeated Blocks

The adversary chooses `A || A` and `A || B`, where each letter represents a distinct 16-byte block. AES-ECB encrypts identical blocks identically, while distinct blocks under the same key produce distinct ciphertext blocks. Comparing the two encrypted blocks identifies the selected message exactly.

This is the multi-block ECB example (option 1). It already breaks IND without any oracle queries. Running it inside the IND-CPA game also demonstrates failure in that stronger model. It is not the separate single-block chosen-plaintext attack. No padding is needed because the chosen messages contain exactly two AES blocks.

## IND-CCA: Unauthenticated AES-CTR

The adversary can query a decryption oracle after receiving the challenge, but querying the **exact challenge ciphertext is forbidden** and raises `ValueError`. This demonstration exposes only the post-challenge decryption queries needed for the attack; it does not model a separate pre-challenge decryption phase. The attack therefore also applies when that additional capability is available.

The ciphertext format is a 16-byte initial counter block followed by the encrypted message. The adversary flips the first encrypted byte at index 16, submits this different ciphertext for decryption, then reverses the same XOR on the returned plaintext at index 0. It recovers the original message and identifies the challenge bit.

The modified query respects the game restriction. The weakness is CTR's malleability without authentication, connecting this exercise to the authenticated encryption introduced in Week 4.

## INT-PTXT: An Unkeyed Hash Is Not a MAC

The deliberately insecure construction stores `SHA256(message) || message`. Verification recomputes the hash and returns the message only if it matches. This construction provides no confidentiality and uses no secret key.

The game records every plaintext submitted to the legitimate oracle. The adversary wins only if its final submission is accepted and yields a plaintext absent from that record. Replaying an oracle response does not win.

The adversary requests a tag for `Acesso Negado!!`, then independently computes SHA-256 for the new message `Acesso Aceite!!`. Its forged digest/message pair passes verification without an oracle query for that message. No collision or weakness in SHA-256 is needed: anyone can compute an unkeyed hash.

This experiment measures forgery success directly. It does not use a hidden challenge bit or the 50% guessing baseline of IND games. The correct model name here is **INT-PTXT**, reflecting plaintext integrity.
