import sys
import random
import os

def seed_expand(x):
    r = x
    for _ in range(14):
        y = x >> 8
        x ^= y
        r ^= x
        x = y
    return r

def my_prng(n):
    """ a ?SECURE? pseudo-random number generator """
    myseed = os.urandom(16)
    random.seed(seed_expand(int.from_bytes(myseed, byteorder='little')))
    return random.randbytes(n)

def enc_dec_otp(chave,mensagem):
    if len(mensagem) > len(chave):
        print("Erro: Chave muito curta!")
        sys.exit(1)
        
    resultado = []
    for i in range(len(mensagem)):
        byte_msg = mensagem[i]
        byte_chave = chave[i]

        byte_res = byte_msg ^ byte_chave
        resultado.append(byte_res)
    
    res = bytes(resultado)
    return res

def otp(argv):
    if len(argv) != 4:
        print("Deve-se usar assim:\nsetup: python my_otp.py setup numero otp.key\nenc: python my_otp.py enc ptxt.txt otp.key\ndec: python my_otp.py dec ptxt.txt.enc otp.key")
        sys.exit(1)
    
    comando = argv[1]

    if comando == "setup":
        numero_bytes = int(argv[2])
        nome_ficheiro = argv[3]
        chave = my_prng(numero_bytes)
        with open(nome_ficheiro, "wb") as file:
            file.write(chave)

    elif comando == "enc":
        ficheiro_mensagem = argv[2]
        ficheiro_chave = argv[3]
        with open(ficheiro_mensagem, "rb") as file:
            mensagem = file.read()
        
        with open(ficheiro_chave, "rb") as file:
            chave = file.read()
        
        ficheiro_novo = ficheiro_mensagem + ".enc"
        res = enc_dec_otp(chave,mensagem)
        with open(ficheiro_novo, "wb") as file:
            file.write(res)


    elif comando == "dec":
        ficheiro_mensagem = argv[2]
        with open(ficheiro_mensagem, "rb") as file:
            mensagem = file.read()
        
        ficheiro_chave = argv[3]
        with open(ficheiro_chave, "rb") as file:
            chave = file.read()
        
        ficheiro_novo = ficheiro_mensagem + ".dec"
        res = enc_dec_otp(chave, mensagem)
        with open(ficheiro_novo, "wb") as file:
            file.write(res)

if __name__ == "__main__":
    otp(sys.argv)
