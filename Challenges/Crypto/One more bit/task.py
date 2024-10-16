from Crypto.Util.number import getStrongPrime, bytes_to_long, GCD, inverse
from Crypto.Util.Padding import pad
from secret import flag
import random


def genKey(nbits,dbits):
    p = getStrongPrime(nbits//2)
    q = getStrongPrime(nbits//2)
    n = p*q
    phi = (p-1)*(q-1)
    while True:
        d = random.getrandbits(dbits)
        if d.bit_length() == dbits:
            if GCD(d, phi) == 1:
                e = inverse(d, phi)
                pk = (n, e)
                sk = (p, q, d)
                return pk, sk


nbits = 1024
dbits = 258
message = pad(flag,16)
msg = pad(message, 16)
m = bytes_to_long(msg)
pk= genKey(nbits, dbits)[0]
n, e = pk
ciphertext = pow(m, e, n)

with open("data.txt","w") as f:
    f.write(f"pk = {pk}\n")
    f.write(f"ciphertext = {ciphertext}\n")
    f.close()