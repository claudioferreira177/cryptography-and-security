import os
import sys

from cryptography.exceptions import InvalidSignature, InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def mkpair(x, y):
    len_x = len(x)
    if not 0 < len_x <= 65535:
        raise ValueError("Comprimento do primeiro campo inválido.")
    len_x_bytes = len_x.to_bytes(2, 'little')
    return len_x_bytes + x + y


def unpair(xy):
    if len(xy) < 2:
        raise ValueError('Cabeçalho do par incompleto.')
    len_x = int.from_bytes(xy[:2], 'little')
    if len_x == 0 or len_x > len(xy) - 2:
        raise ValueError('Comprimento do primeiro campo inválido.')
    x = xy[2:len_x+2]
    y = xy[len_x+2:]
    return x, y


def enc_AES_GCM(key, mensagem, aad):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, mensagem, aad)
    return nonce + ct


def dec_AES_GCM(key, mensagem, aad):
    if len(mensagem) < 28:
        raise ValueError("Componente AES-GCM incompleta.")
    nonce = mensagem[:12]
    ct = mensagem[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, aad)


def cfich_nikesig(argv):
    if len(argv) < 2:
        print("Uso: python cfich_nikesig.py setup|enc|dec ...")
        sys.exit(1)

    comando = argv[1]

    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    g = 2
    aad = b"authenticated but unencrypted data"

    if comando == 'setup':
        if len(argv) != 3:
            print('python cfich_nikesig.py setup <user>')
            sys.exit(1)

        user = argv[2]
        if any(os.path.lexists(f'{user}.{suffix}')
               for suffix in ('dhpk', 'dhsk', 'rsask', 'rsapk')):
            raise FileExistsError('Já existe uma chave para este utilizador; setup cancelado.')

        parameters = dh.DHParameterNumbers(p, g).parameters()

        dh_private_key = parameters.generate_private_key()
        dh_public_key = dh_private_key.public_key()

        dh_sk_bytes = dh_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        dh_pk_bytes = dh_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        rsa_public_key = rsa_private_key.public_key()

        rsa_sk_bytes = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        rsa_pk_bytes = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        dh_signature = rsa_private_key.sign(
            dh_pk_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        dhpk_content = mkpair(dh_pk_bytes, dh_signature)

        with open(f'{user}.dhpk', 'xb') as f:
            f.write(dhpk_content)

        with open(f'{user}.dhsk', 'xb') as f:
            f.write(dh_sk_bytes)

        with open(f'{user}.rsask', 'xb') as f:
            f.write(rsa_sk_bytes)

        with open(f'{user}.rsapk', 'xb') as f:
            f.write(rsa_pk_bytes)

    elif comando == 'enc':
        if len(argv) != 5:
            print('python cfich_nikesig.py enc <user> <me> <fich>')
            sys.exit(1)

        user = argv[2]      
        me = argv[3]        
        ficheiro = argv[4]

        with open(f'{user}.dhpk', 'rb') as f:
            dhpk_content = f.read()

        user_dh_pk_bytes, user_dh_signature = unpair(dhpk_content)

        with open(f'{user}.rsapk', 'rb') as f:
            user_rsa_pk_bytes = f.read()

        user_rsa_pk = serialization.load_pem_public_key(user_rsa_pk_bytes)
        if not isinstance(user_rsa_pk, rsa.RSAPublicKey):
            raise ValueError("A chave pública de assinatura deve ser RSA.")

        user_rsa_pk.verify(
            user_dh_signature,
            user_dh_pk_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        user_dh_pk = serialization.load_pem_public_key(user_dh_pk_bytes)
        if not isinstance(user_dh_pk, dh.DHPublicKey):
            raise ValueError("A chave pública do destinatário deve ser DH.")

        parameters = user_dh_pk.parameters()

        eph_private_key = parameters.generate_private_key()
        eph_public_key = eph_private_key.public_key()

        shared_secret = eph_private_key.exchange(user_dh_pk)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
        )

        k = hkdf.derive(shared_secret)

        with open(ficheiro, 'rb') as f:
            mensagem = f.read()

        with open(f'{me}.rsask', 'rb') as f:
            me_rsa_sk_bytes = f.read()

        me_rsa_sk = serialization.load_pem_private_key(
            me_rsa_sk_bytes,
            password=None
        )

        if not isinstance(me_rsa_sk, rsa.RSAPrivateKey):
            raise ValueError("A chave privada de assinatura deve ser RSA.")

        assinatura = me_rsa_sk.sign(
            mensagem,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        payload = mkpair(assinatura, mensagem)

        mensagem_cifrada = enc_AES_GCM(k, payload, aad)

        eph_pk_bytes = eph_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        final_content = mkpair(eph_pk_bytes, mensagem_cifrada)

        with open(ficheiro + '.enc', 'wb') as f:
            f.write(final_content)

    elif comando == 'dec':
        if len(argv) != 5:
            print('python cfich_nikesig.py dec <me> <user> <fich>')
            sys.exit(1)

        me = argv[2]              
        user = argv[3]            
        cripto_ficheiro = argv[4]

        with open(cripto_ficheiro, 'rb') as f:
            final_content = f.read()

        eph_pk_bytes, mensagem_cifrada = unpair(final_content)

        with open(f'{me}.dhsk', 'rb') as f:
            me_dh_sk_bytes = f.read()

        me_dh_sk = serialization.load_pem_private_key(
            me_dh_sk_bytes,
            password=None
        )

        eph_public_key = serialization.load_pem_public_key(eph_pk_bytes)
        if not isinstance(me_dh_sk, dh.DHPrivateKey) or not isinstance(eph_public_key, dh.DHPublicKey):
            raise ValueError("As chaves do acordo de segredo devem ser DH.")

        shared_secret = me_dh_sk.exchange(eph_public_key)

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=None,
        )

        k = hkdf.derive(shared_secret)

        payload = dec_AES_GCM(k, mensagem_cifrada, aad)

        assinatura, mensagem_original = unpair(payload)

        with open(f'{user}.rsapk', 'rb') as f:
            user_rsa_pk_bytes = f.read()

        user_rsa_pk = serialization.load_pem_public_key(user_rsa_pk_bytes)
        if not isinstance(user_rsa_pk, rsa.RSAPublicKey):
            raise ValueError("A chave pública de assinatura deve ser RSA.")

        user_rsa_pk.verify(
            assinatura,
            mensagem_original,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        mensagem_final = cripto_ficheiro + '.dec'

        with open(mensagem_final, 'wb') as f:
            f.write(mensagem_original)

    else:
        print('Comando inválido!')
        sys.exit(1)


if __name__ == "__main__":
    try:
        cfich_nikesig(sys.argv)
    except InvalidSignature:
        sys.exit("Falha de verificação da assinatura RSA.")
    except InvalidTag:
        sys.exit("Falha de autenticação: chave incorreta ou dados adulterados.")
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        sys.exit(f"Erro: {exc}")
