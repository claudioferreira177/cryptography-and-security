import sys
import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

def gerar_chave():
    return os.urandom(32)

def enc_chacha20(chave, mensagem):
    nonce = os.urandom(8)
    counter = 0
    fullnonce = struct.pack("<Q",counter) + nonce
    algorithm = algorithms.ChaCha20(chave, fullnonce)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(mensagem)
    return fullnonce + ciphertext

def dec_chacha20(chave, dados_encriptados):
    nonce = dados_encriptados[0:16]
    ciphertext = dados_encriptados[16:]
    
    algorithm = algorithms.ChaCha20(chave, nonce)
    cipher = Cipher(algorithm, mode=None)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)

def cha_cha20(argv):
    if not ((len(argv) == 3 and argv[1] == "setup") or
            (len(argv) == 4 and argv[1] in ("enc", "dec"))):
        print("setup: python3 cfich_chacha20.py setup <fkey>")
        print("enc:   python3 cfich_chacha20.py enc <fich_origem> <fkey>")
        print("dec:   python3 cfich_chacha20.py dec <fich_enc> <fkey>")
        sys.exit(1)
    
    comando = argv[1]

    if comando == "setup":
        nome_chave = argv[2]
        chave = gerar_chave()
        with open(nome_chave, "wb") as f:
            f.write(chave)

    elif comando == "enc":
        fich_entrada = argv[2]
        fich_chave = argv[3]
        
        with open(fich_entrada, "rb") as f:
            mensagem = f.read()
        with open(fich_chave, "rb") as f:
            chave = f.read()
            
        dados_encriptados = enc_chacha20(chave, mensagem)
        
        with open(fich_entrada + ".enc", "wb") as f:
            f.write(dados_encriptados)

    elif comando == "dec":
        fich_encriptado = argv[2]
        fich_chave = argv[3]
        
        with open(fich_encriptado, "rb") as f:
            dados = f.read()
        with open(fich_chave, "rb") as f:
            chave = f.read()
            
        texto_limpo = dec_chacha20(chave, dados)
        nome_saida = fich_encriptado + ".dec"
        with open(nome_saida, "wb") as f:
            f.write(texto_limpo)

if __name__ == "__main__":
    cha_cha20(sys.argv)
