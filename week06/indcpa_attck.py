import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from indcpa import Cipher_, INDCPA_Adv, IND_CPA

# Cifra AES-ECB

class AES_ECB_Cipher(Cipher_):
    def keygen(self) -> bytes:
        return os.urandom(32)

    def enc(self, key: bytes, text: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), mode=modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(text) + encryptor.finalize()

    def dec(self, key: bytes, ciphertext: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), mode=modes.ECB())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


# Adversário IND-ECB

class ECB_Adversary(INDCPA_Adv):

    def choose(self, oracle):
        self.m0 = b'A' * 16 + b'A' * 16   # dois blocos iguais
        self.m1 = b'A' * 16 + b'B' * 16   # dois blocos diferentes
        return self.m0, self.m1

    def guess(self, oracle, ciphertext):
        bloco1 = ciphertext[0:16]
        bloco2 = ciphertext[16:32]
        # Se os blocos do CT são iguais → foi cifrado m0 (b=0)
        return 0 if bloco1 == bloco2 else 1


if __name__ == "__main__":
    C = AES_ECB_Cipher()
    A = ECB_Adversary()
    limite = 1000
    sucesso = sum(IND_CPA(C, A) for _ in range(limite)) / limite
    print(f"[AES-ECB / blocos repetidos] Sucesso: {sucesso:.1%}; "
          f"vantagem empírica: {2 * abs(sucesso - 0.5):.1%}")
