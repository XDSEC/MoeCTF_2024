from Crypto.Util.number import *
from secret import flag
import random


p = 2050446265000552948792079248541986570794560388346670845037360320379574792744856498763181701382659864976718683844252858211123523214530581897113968018397826268834076569364339813627884756499465068203125112750486486807221544715872861263738186430034771887175398652172387692870928081940083735448965507812844169983643977
assert len(flag) == 42


def encode(msg):
    return bin(bytes_to_long(msg))[2:].zfill(8*len(msg))


def genkey(len):
    sums = 0
    keys = []
    for i in range(len):
        k = random.randint(1,7777)
        x = sums + k
        keys.append(x)
        sums += x
    return keys


key = genkey(42*8)


def enc(m, keys):
    msg = encode(m)
    print(len(keys))
    print(len(msg))
    assert len(msg) == len(keys)
    s = sum((k if (int(p,2) == 1) else 1) for p, k in zip(msg, keys))
    print(msg)
    for p0,k in zip(msg,keys):
        print(int(p0,2))
    return pow(7,s,p)


cipher = enc(flag,key)

with open("output.txt", "w") as fs:
    fs.write(str(key)+'\n')
    fs.write(str(cipher))
