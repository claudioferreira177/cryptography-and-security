import sys
from cesar import cesar, preproc

def cesar_attack(texto, seq):
    texto = preproc(texto)
    for i in range(26):
        letra = chr(ord('A') + i)
        res = cesar("dec", letra, texto)
        for palavra in seq:
            palavra = palavra.upper()
            if palavra in res:
                print(letra)
                print(res)
                return

if __name__ == "__main__":
    argv = sys.argv
    if len(argv) < 3:
      print("Uso: python3 cesar_attack.py ex:IGXZGMUKYZGTUVGVU palavra1 palavra2 ...")
      sys.exit(1)
    palavras = argv[2:]
    cesar_attack(argv[1], palavras)
