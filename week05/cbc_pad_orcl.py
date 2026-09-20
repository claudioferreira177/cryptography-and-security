import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives import padding

BLOCK_SIZE = 128  # bits
key = os.urandom(16)


def pad(ptxt):
    padder = padding.PKCS7(BLOCK_SIZE).padder()
    return padder.update(ptxt) + padder.finalize()


def unpad(padded):
    unpadder = padding.PKCS7(BLOCK_SIZE).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def enc(mensagem):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), CBC(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(pad(mensagem)) + encryptor.finalize()


def dec(ctxt):
    if len(ctxt) < 32 or len(ctxt) % 16:
        raise ValueError("Criptograma deve conter IV e blocos completos de AES.")
    cipher = Cipher(algorithms.AES(key), CBC(ctxt[:16]))
    decryptor = cipher.decryptor()
    return decryptor.update(ctxt[16:]) + decryptor.finalize()


def pad_orcl(ctxt):
    try:
        unpad(dec(ctxt))
    except ValueError:
        return False
    return True


if __name__ == "__main__":
    print("PKCS7 de 'abc':", list(pad(b"abc")))
    # Q1: mantém 16 bytes, mas 0x00 não é um tamanho válido de padding.
    invalid_padding = pad(b"abc")[:15] + b"\x00"
    try:
        unpad(invalid_padding)
    except ValueError:
        print("Q1: padding inválido num bloco de 16 bytes.")

    ctxt = enc(b"Ola Mundo")  # sete bytes de padding
    altered = bytearray(ctxt)
    altered[15] ^= 7  # IV: transforma o último byte do plaintext em 0x00
    print("Criptograma válido:", pad_orcl(ctxt))
    print("Padding adulterado:", pad_orcl(bytes(altered)))
    print("Criptograma truncado:", pad_orcl(ctxt[:len(ctxt) - 1]))
    print("Criptograma vazio:", pad_orcl(b""))
