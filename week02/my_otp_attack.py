import sys
import random

def enc_dec(chave, mensagem):  
    return bytes([b_m ^ b_c for b_m, b_c in zip(mensagem, chave)])

def otp_attack(argv):
    ficheiro = argv[1]
    palavras = [p.encode("utf-8") for p in argv[2:]]

    with open(ficheiro, "rb") as file:
        cifra = file.read()

    LIMITE_SEMENTE = 2**16
    
    for semente in range(LIMITE_SEMENTE):
        random.seed(semente)
        chave = random.randbytes(len(cifra))

        tentativa = enc_dec(chave, cifra)
        
        if any(p in tentativa for p in palavras):
            print(tentativa.decode("utf-8", errors="ignore"))
            return

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso: python3 my_otp_attack.py ptxt.txt.enc palavra1 palavra2")
        sys.exit(1)

    otp_attack(sys.argv)
