#!/usr/bin/python3
from Crypto.Util.number import getPrime, long_to_bytes, inverse
from binascii import unhexlify
import gmpy2
#flag = open('flag.txt', 'r').read().strip().encode()
flag = open('output.txt', 'r').read().strip().encode()

class RSA:
    def __init__(self):
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.e = 3
        self.n = self.p * self.q
        self.d = inverse(self.e, (self.p-1)*(self.q-1))
    def encrypt(self, data: bytes) -> bytes:
        pt = int(data.hex(), 16)
        ct = pow(pt, self.e, self.n)
        return long_to_bytes(ct)
    def decrypt(self, data: bytes) -> bytes:
        ct = int(data.hex(), 16)
        pt = pow(ct, self.d, self.n)
        return long_to_bytes(pt)
        
def chineseremaindertheorem(dq, dp, p, q, c):
      
    # Message part 1
    m1 = gmpy2.powmod(c, dp, p)
      
    # Message part 2
    m2 = gmpy2.powmod(c, dq, q)
      
    qinv = gmpy2.invert(q, p)
    h = gmpy2.f_mod((qinv * (m1 - m2)), p)
    m = m2 + h * q
    return m
  
def main():
    crypto = RSA()   
     
    encrypt_text = flag.decode().split(" ")[1]
    encrypt_text = int(encrypt_text.encode(), 16)
    dp = gmpy2.powmod(crypto.d, 1, crypto.p - 1)
    dq = gmpy2.powmod(crypto.d, 1, crypto.q - 1)
    pt = chineseremaindertheorem(dq, dp, crypto.p, crypto.q, encrypt_text)
    pt = hex(pt).split("x")[1].encode()
    print(unhexlify(pt))

    #print ('Flag:', crypto.encrypt(flag).hex())

main()
