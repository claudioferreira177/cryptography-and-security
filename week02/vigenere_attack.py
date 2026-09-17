import sys
import itertools
from vigenere import vigenere, preproc

letras_freq = "AEOS"


def letra_mais_frequente(texto):
    melhor_letra = None
    melhor_contagem = -1

    for letra in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        contagem = texto.count(letra)
        if contagem > melhor_contagem:
            melhor_contagem = contagem
            melhor_letra = letra

    return melhor_letra


def vigenere_attack(tamanho, texto, seq):
    texto = preproc(texto)
    palavras = [preproc(p) for p in seq]

    letras_freq_fatias = []

    for i in range(tamanho):
        fatia = texto[i:len(texto):tamanho]
        letra_freq = letra_mais_frequente(fatia)
        letras_freq_fatias.append(letra_freq)


    for combo in itertools.product(letras_freq, repeat=tamanho):
        key = ""

        for i in range(tamanho):
            letra_freq = letras_freq_fatias[i]
            letra_comum = combo[i]

            pos_cifrada = ord(letra_freq) - ord('A')
            pos_real = ord(letra_comum) - ord('A')

            deslocamento = (pos_cifrada - pos_real) % 26
            letra_key = chr(deslocamento + ord('A'))

            key += letra_key

        res = vigenere("dec", key, texto)

        for palavra in palavras:
            if palavra in res:
                print(key)
                print(res)
                return


if __name__ == "__main__":
    argv = sys.argv

    if len(argv) < 4:
        print("Uso: python3 vigenere_attack.py TAMANHO CRIPTOGRAMA palavra1 palavra2 ...")
        sys.exit(1)

    tamanho = int(argv[1])
    texto = argv[2]
    palavras = argv[3:]

    vigenere_attack(tamanho, texto, palavras)
