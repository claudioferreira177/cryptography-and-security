import os
import random
import struct
from abc import ABC, abstractmethod
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms


class Cipher_(ABC):
    @abstractmethod
    def keygen(self) -> bytes:
        pass

    @abstractmethod
    def enc(self, key: bytes, text: bytes) -> bytes:
        pass

    @abstractmethod
    def dec(self, key: bytes, ciphertext: bytes) -> bytes:
        pass

class INDCPA_Adv(ABC):
    @abstractmethod
    def choose(self, oracle):
        pass

    @abstractmethod
    def guess(self, oracle, ciphertext: bytes) -> int:
        pass

def IND_CPA(C: Cipher_, A: INDCPA_Adv) -> bool:
    k = C.keygen()
    enc_oracle = lambda ptxt: C.enc(k, ptxt)
    m0, m1 = A.choose(enc_oracle)
    if len(m0) != len(m1):
        raise ValueError("As mensagens devem ter o mesmo tamanho.")
    b = random.randint(0, 1)
    c = C.enc(k, m1 if b else m0)
    b_prime = A.guess(enc_oracle, c)
    return b == b_prime

#1. Cifra Identidade

class IdentityCipher(Cipher_):
    def keygen(self) -> bytes:
        return b''

    def enc(self, key: bytes, text: bytes) -> bytes:
        return text

    def dec(self, key: bytes, ciphertext: bytes) -> bytes:
        return ciphertext


class IdentityAdversary(INDCPA_Adv):

    def choose(self, oracle):
        self.m0 = b'message_A'
        self.m1 = b'message_B'
        return self.m0, self.m1

    def guess(self, oracle, ciphertext):
        return 1 if ciphertext == self.m1 else 0



# 2. ChaCha20


class ChaCha20Cipher(Cipher_):
    def keygen(self) -> bytes:
        return os.urandom(32)

    def enc(self, key: bytes, text: bytes) -> bytes:
        nonce = os.urandom(8)
        counter = 0
        full_nonce = struct.pack("<Q", counter) + nonce  # 16 bytes: 8 contador + 8 nonce
        algorithm = algorithms.ChaCha20(key, full_nonce)
        cipher = Cipher(algorithm, mode=None)
        encryptor = cipher.encryptor()
        ct = encryptor.update(text) + encryptor.finalize()
        return full_nonce + ct

    def dec(self, key: bytes, ciphertext: bytes) -> bytes:
        if len(ciphertext) < 16:
            raise ValueError("Criptograma sem cabeçalho ChaCha20 completo.")
        full_nonce = ciphertext[:16]
        ct = ciphertext[16:]
        algorithm = algorithms.ChaCha20(key, full_nonce)
        cipher = Cipher(algorithm, mode=None)
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()


class RandomAdversary(INDCPA_Adv):

    def choose(self, oracle):
        self.m0 = b'message_A'
        self.m1 = b'message_B'
        return self.m0, self.m1

    def guess(self, oracle, ciphertext):
        return random.randint(0, 1)  



if __name__ == "__main__":
    limite = 1000
    for nome, C, A in [
        ("Identidade", IdentityCipher(), IdentityAdversary()),
        ("ChaCha20 / resposta aleatória", ChaCha20Cipher(), RandomAdversary()),
    ]:
        sucesso = sum(IND_CPA(C, A) for _ in range(limite)) / limite
        vantagem = 2 * abs(sucesso - 0.5)
        print(f"[{nome}] Sucesso: {sucesso:.1%}; vantagem empírica: {vantagem:.1%}")
