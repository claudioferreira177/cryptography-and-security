import sys


def cha_cha20_attack(mensagem_criptografada, ptxtAtPos, newPtxtAtPos, pos):
    for i in range(len(ptxtAtPos)):
        mensagem_criptografada[pos + i] ^= ptxtAtPos[i] ^ newPtxtAtPos[i]
    return mensagem_criptografada


def cha_cha20_preparacao(argv):
    if len(argv) != 5:
        sys.exit("Uso: python3 chacha20_int_attack.py fctxt pos ptxtAtPos newPtxtAtPos")

    try:
        pos = int(argv[2])
    except ValueError:
        sys.exit("A posição deve ser um número inteiro.")

    ptxtAtPos = argv[3].encode("utf-8")
    newPtxtAtPos = argv[4].encode("utf-8")
    if len(newPtxtAtPos) > len(ptxtAtPos):
        sys.exit("O novo texto deve ter o mesmo tamanho ou ser menor, em bytes.")

    ficheiro_com_criptograma = argv[1]
    with open(ficheiro_com_criptograma, "rb") as file:
        dados = file.read()
    if len(dados) < 16:
        sys.exit("O ficheiro não contém um cabeçalho ChaCha20 completo.")

    nonce = dados[:16]
    mensagem_criptografada = bytearray(dados[16:])
    if pos < 0 or pos + len(ptxtAtPos) > len(mensagem_criptografada):
        sys.exit("O fragmento está fora dos limites do criptograma.")

    newPtxtAtPos = newPtxtAtPos.ljust(len(ptxtAtPos), b" ")
    mensagem_criptografada = cha_cha20_attack(
        mensagem_criptografada, ptxtAtPos, newPtxtAtPos, pos
    )
    with open(ficheiro_com_criptograma + ".attck", "wb") as file:
        file.write(nonce + mensagem_criptografada)


if __name__ == "__main__":
    cha_cha20_preparacao(sys.argv)
