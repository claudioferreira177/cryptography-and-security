# Encrypt_then_MAC
import sys
import os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def dec_AES(key,mensagem):
    if len(mensagem) < 64:
        sys.exit("Ficheiro cifrado incompleto.")
    salt = mensagem[:16]
    nonce = mensagem[16:32]
    signature = mensagem[32:64]
    ct = mensagem[64:]

    key_1 = key[0:16]
    key_2 = key[16:]

    h = hmac.HMAC(key_2, hashes.SHA256())
    h.update(salt + nonce + ct)

    try:
        h.verify(signature)
    except InvalidSignature:
        print("Passphrase incorreta ou dados adulterados.")
        sys.exit(1)
    
    algorithm = algorithms.AES(key_1)
    cipher = Cipher(algorithm,mode=CTR(nonce))
    decryptor = cipher.decryptor()

    return decryptor.update(ct) + decryptor.finalize()
    
def enc_AES(salt,key,mensagem):
    key_1 = key[0:16]
    key_2 = key[16:]

    nonce = os.urandom(16)
    algorithm = algorithms.AES(key_1)
    cipher = Cipher(algorithm,mode=CTR(nonce))
    encryptor = cipher.encryptor()
    ct = encryptor.update(mensagem) + encryptor.finalize()

    h = hmac.HMAC(key_2, hashes.SHA256())
    h.update(salt + nonce + ct)
    signature = h.finalize()

    return salt + nonce + signature + ct



def pbenc_AES(argv):
    if len(argv) != 3 or argv[1] not in ("enc", "dec"):
        print("python pbenc_aes_ctr_hmac.py dec <ficheiro>")
        print("python pbenc_aes_ctr_hmac.py enc <ficheiro>")
        sys.exit(1)

    comando = argv[1]
    fich_origem = argv[2]

    pass_phrase = input('Digite a passe: ').encode()

    if comando == 'enc':
        with open(fich_origem,'rb') as file:
            mensagem = file.read()
        
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1_200_000,
        )
        key = kdf.derive(pass_phrase)

        mensagem_enc = enc_AES(salt,key,mensagem)

        fich_final = fich_origem + '.enc'
        with open(fich_final, 'wb') as file:
            file.write(mensagem_enc)

    elif comando == 'dec':
        with open(fich_origem,'rb') as file:
            mensagem = file.read()
        
        if len(mensagem) < 64:
            sys.exit("Ficheiro cifrado incompleto.")
        salt = mensagem[0:16]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1_200_000,
        )
        key = kdf.derive(pass_phrase)

        mensagem_dec = dec_AES(key,mensagem)

        fich_final = fich_origem + '.dec'
        with open(fich_final, 'wb') as file:
            file.write(mensagem_dec)

if __name__ == "__main__":
    pbenc_AES(sys.argv)
