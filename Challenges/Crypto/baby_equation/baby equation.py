from Crypto.Util.number import *
from secret import flag


l = len(flag)
m1, m2 = flag[:l//2], flag[l//2:]
a = bytes_to_long(m1)
b = bytes_to_long(m2)
k = 0x2227e398fc6ffcf5159863a345df85ba50d6845f8c06747769fee78f598e7cb1bcf875fb9e5a69ddd39da950f21cb49581c3487c29b7c61da0f584c32ea21ce1edda7f09a6e4c3ae3b4c8c12002bb2dfd0951037d3773a216e209900e51c7d78a0066aa9a387b068acbd4fb3168e915f306ba40
assert ((a**2 + 1)*(b**2 + 1) - 2*(a - b)*(a*b - 1)) == 4*(k + a*b)

