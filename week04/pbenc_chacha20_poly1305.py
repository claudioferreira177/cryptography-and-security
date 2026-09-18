import os
import sys
import struct
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def enc_chacha20_poly1305(key, aad, mensagem_origem):
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ct = chacha.encrypt(nonce, mensagem_origem, aad)
    return nonce + ct

def pbenc_chacha20_poly1305(argv):
    if len(argv) != 3 or argv[1] not in ("enc", "dec"):
        print("python pbenc_chacha20_poly1305.py enc <ficheiro>")
        print("python pbenc_chacha20_poly1305.py dec <ficheiro>")
        sys.exit(1)

    comando = argv[1]
    fich_origem = argv[2]

    pass_phrase = input('Digite a passe: ').encode()

    if comando == 'enc':
        with open(fich_origem, "rb") as file:
            mensagem_origem = file.read()

        aad = input('Digite o AAD: ').encode()

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1_200_000,
        )
        key = kdf.derive(pass_phrase)

        cifra = enc_chacha20_poly1305(key, aad, mensagem_origem)
        tamanho_aad = struct.pack('<I', len(aad))

        with open(fich_origem + '.enc', 'wb') as file:
            file.write(tamanho_aad + salt + aad + cifra)
    
    elif comando == 'dec':
        with open(fich_origem, "rb") as file:
            mensagem_enc = file.read()

        if len(mensagem_enc) < 48:
            sys.exit("Ficheiro cifrado incompleto.")
        tamanho_aad = struct.unpack('<I',mensagem_enc[0:4])[0]
        if tamanho_aad > len(mensagem_enc) - 48:
            sys.exit("Comprimento de AAD inválido.")

        salt = mensagem_enc[4:20]
        aad = mensagem_enc[20:20+tamanho_aad]
        nonce = mensagem_enc[20+tamanho_aad:32+tamanho_aad]
        ct = mensagem_enc[32+tamanho_aad:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1_200_000,
        )

        key = kdf.derive(pass_phrase)
        try:
            mensagem = ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
        except InvalidTag:
            sys.exit("Passphrase incorreta ou dados adulterados.")

        with open(fich_origem + '.dec', 'wb') as file:
            file.write(mensagem)


if __name__ == "__main__":
    pbenc_chacha20_poly1305(sys.argv)
