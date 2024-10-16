from Crypto.Util.number import *
from secret import flag


p = getPrime(512)
q = getPrime(512)
n = p*q
e = 0x1001
d = inverse(e, (p-1)*(q-1))
bit_leak = 400
d_leak = d & ((1<<bit_leak)-1)
msg = bytes_to_long(flag)
cipher = pow(msg,e,n)
pk = (n, e)

with open('output.txt','w') as f:
    f.write(f"pk = {pk}\n")
    f.write(f"cipher = {cipher}\n")
    f.write(f"hint = {d_leak}\n")
    f.close()

