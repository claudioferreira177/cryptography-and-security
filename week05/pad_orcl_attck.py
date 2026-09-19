from pad_orcl_attck_lastbyte import pad_orcl_attck_lastbyte


def pad_orcl_attck(ctxt, oracle):
    tamanho_padding = pad_orcl_attck_lastbyte(ctxt, oracle)
    bloco_decifrado = [0] * 16
    texto_limpo_bloco = bytearray(16)
    id_bloco_anterior = len(ctxt) - 32

    for i in range(1, tamanho_padding + 1):
        pos = 16 - i
        bloco_decifrado[pos] = tamanho_padding ^ ctxt[id_bloco_anterior + pos]
        texto_limpo_bloco[pos] = tamanho_padding

    for k in range(tamanho_padding + 1, 17):
        teste_ctxt = bytearray(ctxt)
        for i in range(1, k):
            pos = 16 - i
            teste_ctxt[id_bloco_anterior + pos] = bloco_decifrado[pos] ^ k

        pos = 16 - k
        for candidato in range(256):
            teste_ctxt[id_bloco_anterior + pos] = candidato
            if oracle(bytes(teste_ctxt)):
                bloco_decifrado[pos] = candidato ^ k
                texto_limpo_bloco[pos] = bloco_decifrado[pos] ^ ctxt[id_bloco_anterior + pos]
                break
        else:
            raise ValueError(f"Não foi possível recuperar o byte {pos}.")

    return bytes(texto_limpo_bloco)


if __name__ == "__main__":
    from cbc_pad_orcl import enc, pad_orcl, unpad

    ctxt = enc(b"Ola Mundo")
    ultimo_bloco = pad_orcl_attck(ctxt, pad_orcl)
    print("Último bloco com padding:", ultimo_bloco)
    print("Conteúdo sem padding:", unpad(ultimo_bloco))
