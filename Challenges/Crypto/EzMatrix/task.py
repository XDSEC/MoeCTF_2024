from Crypto.Util.number import *
from secret import FLAG,secrets,SECERT_T


assert len(secrets) == 16
assert FLAG == b'moectf{' + secrets + b'}'
assert len(SECERT_T) <= 127


class LFSR:
    def __init__(self):
        self._s = list(map(int,list("{:0128b}".format(bytes_to_long(secrets)))))
        for _ in range(8*len(secrets)):
            self.clock()
    
    def clock(self):
        b = self._s[0]
        c = 0
        for t in SECERT_T:c ^= self._s[t]
        self._s = self._s[1:] + [c]
        return b
    
    def stream(self, length):
        return [self.clock() for _ in range(length)]


c = LFSR()
stream = c.stream(256)
print("".join(map(str,stream))[:-5])
# 11111110011011010000110110100011110110110101111000101011001010110011110011000011110001101011001100000011011101110000111001100111011100010111001100111101010011000110110101011101100001010101011011101000110001111110100000011110010011010010100100000000110
