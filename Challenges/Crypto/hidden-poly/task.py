from Crypto.Util.Padding import pad
from Crypto.Util.number import *
from Crypto.Cipher import AES
import os


q = 264273181570520944116363476632762225021
key = os.urandom(16)
iv = os.urandom(16)
root = 122536272320154909907460423807891938232
f = sum([a*root**i for i,a in enumerate(key)])
assert key.isascii()
assert f % q == 0

with open('flag.txt','rb') as f:
    flag = f.read()

cipher = AES.new(key,AES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(flag,16)).hex()

with open('output.txt','w') as f:
    f.write(f"{iv = }" + "\n")
    f.write(f"{ciphertext = }" + "\n")
