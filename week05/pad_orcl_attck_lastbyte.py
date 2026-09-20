def pad_orcl_attck_lastbyte(ct, oracle):
    if len(ct) < 32 or len(ct) % 16:
        raise ValueError("Criptograma deve conter IV e blocos completos de AES.")
    if not oracle(ct):
        raise ValueError("O ataque requer um criptograma com padding válido.")

    id_bloco_anterior = len(ct) - 32
    ct_alterado = bytearray(ct)
    for candidato in range(256):
        ct_alterado[id_bloco_anterior + 15] = candidato
        if oracle(bytes(ct_alterado)):
            # Distingue 0x01 de um padding válido com vários bytes.
            ct_alterado[id_bloco_anterior + 14] ^= 0xff
            valid = oracle(bytes(ct_alterado))
            ct_alterado[id_bloco_anterior + 14] ^= 0xff
            if valid:
                tamanho_padding = 0x01 ^ candidato ^ ct[id_bloco_anterior + 15]
                if 1 <= tamanho_padding <= 16:
                    return tamanho_padding
    raise ValueError("Não foi possível determinar o tamanho do padding.")


if __name__ == "__main__":
    from cbc_pad_orcl import enc, pad_orcl

    ctxt = enc(b"Ola Mundo")
    print("Tamanho do padding:", pad_orcl_attck_lastbyte(ctxt, pad_orcl))
