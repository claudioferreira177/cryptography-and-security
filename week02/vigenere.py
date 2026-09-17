import sys

def preproc(texto):
    l = []
    for c in texto:
        if c.isalpha():
            l.append(c.upper())
    return "".join(l)

def vigenere(opr, key, texto):
    texto = preproc(texto)
    key = preproc(key)

    key_vals = []
    for c in key:
        key_vals.append(ord(c) - ord('A'))

    res = []

    for i, c in enumerate(texto):
        posicao_atual = ord(c) - ord('A')
        deslocamento = key_vals[i % len(key_vals)]

        if opr == "enc":
            nova_posicao = (posicao_atual + deslocamento) % 26
        elif opr == "dec":
            nova_posicao = (posicao_atual - deslocamento) % 26
        else:
            print("Operação inválida")
            sys.exit(1)

        letra = chr(nova_posicao + ord('A'))
        res.append(letra)

    return "".join(res)


if __name__ == "__main__":
    argv = sys.argv

    if len(argv) != 4:
        print("Uso: python vigenere.py enc|dec CHAVE TEXTO")
        sys.exit(1)

    print(vigenere(argv[1], argv[2], argv[3]))
