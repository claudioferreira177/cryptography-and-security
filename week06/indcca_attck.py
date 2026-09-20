import random
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from indcpa import Cipher_

# Cifra AES-CTR

class AES_CTR_Cipher(Cipher_):
    def keygen(self) -> bytes:
        return os.urandom(32)

    def enc(self, key: bytes, text: bytes) -> bytes:
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), mode=modes.CTR(nonce))
        encryptor = cipher.encryptor()
        ct = encryptor.update(text) + encryptor.finalize()
        return nonce + ct

    def dec(self, key: bytes, ciphertext: bytes) -> bytes:
        if len(ciphertext) < 16:
            raise ValueError("Criptograma sem nonce completo.")
        nonce = ciphertext[:16]
        ct = ciphertext[16:]
        cipher = Cipher(algorithms.AES(key), mode=modes.CTR(nonce))
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()


#Jogo IND-CCA (adversário tem oráculo de decifra)

def IND_CCA(C: Cipher_, A) -> bool:
    k = C.keygen()
    enc_oracle = lambda ptxt: C.enc(k, ptxt)
    m0, m1 = A.choose(enc_oracle)
    if len(m0) != len(m1):
        raise ValueError("As mensagens devem ter o mesmo tamanho.")
    b = random.randint(0, 1)
    c = C.enc(k, m1 if b else m0)
    def dec_oracle(ctxt):
        if ctxt == c:
            raise ValueError("Não é permitido decifrar o desafio.")
        return C.dec(k, ctxt)

    b_prime = A.guess(dec_oracle, enc_oracle, c)
    return b == b_prime


#Adversário IND-CCA

class CTR_CCA_Adversary:
    def choose(self, enc_oracle):
        self.m0 = b'Acesso Negado!!'
        self.m1 = b'Acesso Aceite!!'
        return self.m0, self.m1

    def guess(self, dec_oracle, enc_oracle, ciphertext):
        delta = 0xFF
        c_mod = bytearray(ciphertext)
        c_mod[16] ^= delta  # primeiro byte após o nonce            

        m_mod = dec_oracle(bytes(c_mod))

        m_orig = bytearray(m_mod)
        m_orig[0] ^= delta

        return 0 if bytes(m_orig) == self.m0 else 1


if __name__ == "__main__":
    C = AES_CTR_Cipher()
    A = CTR_CCA_Adversary()
    limite = 1000
    sucesso = sum(IND_CCA(C, A) for _ in range(limite)) / limite
    print(f"[AES-CTR IND-CCA] Sucesso: {sucesso:.1%}; "
          f"vantagem empírica: {2 * abs(sucesso - 0.5):.1%}")
