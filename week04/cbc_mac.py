import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.modes import CBC


from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import padding
from hmac import compare_digest

def cbc_mac(argv):
    if not ((len(argv) == 4 and argv[1] == "tag") or
            (len(argv) == 5 and argv[1] == "verify")):
        sys.exit("Uso: python3 cbc_mac.py tag <key> <file> | verify <key> <file> <tag>")
    comando = argv[1]
    key = argv[2].encode("utf-8")
    if len(key) not in (16, 24, 32):
        sys.exit("A chave deve ter 16, 24 ou 32 bytes.")

    iv = bytes(16)
    
    algorithm = algorithms.AES(key)
    cipher = Cipher(algorithm, mode=CBC(iv))
    
    if len(argv) == 4 and comando == "tag": 
        file_name = argv[3]
        with open(file_name, 'rb') as file:
            mensagem = file.read()
            
        padder = padding.PKCS7(128).padder()
        mensagem = padder.update(mensagem) + padder.finalize()
        
        encryptor = cipher.encryptor()
        ct = encryptor.update(mensagem) + encryptor.finalize()
        tag_calculada = ct[-16:]

        with open(file_name + '.tag', 'wb') as file:
            file.write(tag_calculada)
        print(f"Tag gerado em {file_name}.tag")

    elif len(argv) == 5 and comando == "verify":
        file_name = argv[3] 
        tag_file = argv[4] 

        with open(file_name, 'rb') as file:
            mensagem = file.read()
            
        padder = padding.PKCS7(128).padder()
        mensagem = padder.update(mensagem) + padder.finalize()

        with open(tag_file, 'rb') as file:
            tag = file.read()
        
        encryptor = cipher.encryptor()
        ct = encryptor.update(mensagem) + encryptor.finalize()
        tag_calculada = ct[-16:]

        if len(tag) != 16 or not compare_digest(tag, tag_calculada):
            raise InvalidTag()
        else:
            print('Tag válido')
            return
    else:
        print('python cbc_mac.py tag <key> <file>')
        print('python cbc_mac.py verify <key> <file> <tag>') 
        sys.exit(1)
    
if __name__ == "__main__":
    try:
        cbc_mac(sys.argv)
    except InvalidTag:
        print("InvalidTag")
        sys.exit(1)
