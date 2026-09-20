from cryptography.hazmat.primitives import hashes


class SimpleHashCipher:
    # Construção deliberadamente sem chave e sem confidencialidade.
    def enc(self, text: bytes) -> bytes:
        h = hashes.Hash(hashes.SHA256())
        h.update(text)
        return h.finalize() + text

    def dec(self, ciphertext: bytes):
        if len(ciphertext) < 32:
            return None
        digest_recebido = ciphertext[:32]
        text = ciphertext[32:]
        h = hashes.Hash(hashes.SHA256())
        h.update(text)
        if digest_recebido == h.finalize():
            return text
        return None


def INT_PTXT(C, A) -> bool:
    mensagens = set()

    def enc_oracle(ptxt):
        mensagens.add(ptxt)
        return C.enc(ptxt)

    forgery = A.forge(enc_oracle)
    ptxt = C.dec(forgery)
    return ptxt is not None and ptxt not in mensagens


class SimpleHashAdversary:
    def forge(self, enc_oracle):
        enc_oracle(b'Acesso Negado!!')
        nova_mensagem = b'Acesso Aceite!!'
        # O atacante calcula o hash publicamente, sem consultar o oracle
        # para a mensagem que pretende falsificar.
        h = hashes.Hash(hashes.SHA256())
        h.update(nova_mensagem)
        return h.finalize() + nova_mensagem


if __name__ == "__main__":
    C = SimpleHashCipher()
    A = SimpleHashAdversary()
    limite = 1000
    sucesso = sum(INT_PTXT(C, A) for _ in range(limite)) / limite
    print(f"[Hash sem chave INT-PTXT] Sucesso de falsificação: {sucesso:.1%}")
