import sys

def preproc(texto):
  l = []
  for c in texto:
      if c.isalpha():
          l.append(c.upper())
  return "".join(l)

def cesar(opr, key, texto):
  texto = preproc(texto)
  key = key.upper()
  deslocamento = ord(key) - ord('A')
  res = []
  for c in texto:
    posicao_atual = ord(c) - ord('A')
    if opr == "enc":
        nova_posicao = (posicao_atual + deslocamento) % 26
    elif opr == "dec":
        nova_posicao = (posicao_atual - deslocamento) % 26
    else:
        print("Operação inválida")
        sys.exit(1)
    res.append(chr(nova_posicao + ord('A')))
  return "".join(res)

if __name__ == "__main__":
    argv = sys.argv
    if len(argv) != 4:
      print("Uso: python programa.py enc|dec CHAVE TEXTO")
      sys.exit(1)
    res = cesar(argv[1], argv[2], argv[3])
    print(res)
