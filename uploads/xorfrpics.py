from binascii import unhexlify

with open("lemur.png", mode='rb') as fl:
    lemur = fl.read()
    

with open("flag.png", mode='rb') as ff:
    flag = ff.read()

d = b''
for b1, b2 in zip(lemur, flag):
    d += bytes([b1^b2])

with open("new.png", mode='wb') as fn:
    fn.write(d)