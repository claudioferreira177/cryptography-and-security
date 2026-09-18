import os
import struct
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def enc_chacha20(key, mensagem_origem, salt):
    nonce = os.urandom(8)
    counter = 0
    fullnonce = struct.pack("<Q",counter) + nonce
    algorithm = algorithms.ChaCha20(key, fullnonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(mensagem_origem)
    return salt + fullnonce + ciphertext

def dec_chacha20(key, nonce, ciphertext):
    algorithm = algorithms.ChaCha20(key, nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)

def pbenc_chacha20(argv):
    if len(argv) != 3 or argv[1] not in ("enc", "dec"):
        print("python pbenc_chacha20.py dec <ficheiro>")
        print("python pbenc_chacha20.py enc <ficheiro>")
        sys.exit(1)

    comando = argv[1]
    fich_origem = argv[2]

    pass_phrase = input('Digite a passe: ').encode()

    if comando == 'enc':
        with open(fich_origem, "rb") as file:
            mensagem_origem = file.read()
        
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1_200_000,
        )
        key = kdf.derive(pass_phrase)

        cifra = enc_chacha20(key, mensagem_origem, salt)

        with open(fich_origem + '.enc', 'wb') as file:
            file.write(cifra)
    
    elif comando == 'dec':
        with open(fich_origem, "rb") as file:
            mensagem_enc = file.read()

        salt = mensagem_enc[0:16]
        nonce = mensagem_enc[16:32]
        ciphertext = mensagem_enc[32:] 

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1_200_000,
        )

        key = kdf.derive(pass_phrase)
        mensagem = dec_chacha20(key, nonce, ciphertext)

        fich_final = fich_origem + '.dec'
        with open(fich_final, 'wb') as file:
            file.write(mensagem)

if __name__ == "__main__":
    pbenc_chacha20(sys.argv)
