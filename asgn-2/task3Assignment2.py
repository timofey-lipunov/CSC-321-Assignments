import secrets
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number

def encrypt(k, m):
    iv = b"\x00"*16
    return AES.new(k, AES.MODE_CBC, iv).encrypt(pad(m, 16))

def decrypt(k, c):
    iv = b"\x00"*16
    return unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(c), 16)

def gen_keys(bits=1024):
    p = number.getPrime(bits//2)
    q = number.getPrime(bits//2)
    n = p * q
    phi = (p-1)*(q-1)
    e = 65537
    d = number.inverse(e, phi)
    print("Generated RSA key pair:")
    print("modulus n =", n)
    print("public exponent e =", e)
    print("private exponent d =", d)
    return n, e, d

def exchange_malleability():
    n, e, d = gen_keys(512)
    s = secrets.randbelow(n)
    c = pow(s, e, n)
    r = secrets.randbelow(n)
    c2 = (pow(r, e, n) * c) % n
    s2 = pow(c2, d, n)
    print("Original s =", s)
    print("Random r =", r)
    print("Recovered s2 =", s2)
    k = hashlib.sha256(int.to_bytes(s2, (s2.bit_length()+7)//8, 'big')).digest()[:16]
    print("Derived AES key k =", k.hex())
    print(decrypt(k, encrypt(k, b"Hi Bob!")))

def signature_malleability():
    n, e, d = gen_keys(512)
    m1 = 123
    m2 = 456
    s1 = pow(m1, d, n)
    s2 = pow(m2, d, n)
    s3 = (s1 * s2) % n
    print("m1 =", m1, "signature s1 =", s1)
    print("m2 =", m2, "signature s2 =", s2)
    print("combined signature s3 =", s3)
    print("Verification (s3^e mod n) == (m1*m2 mod n)?", pow(s3, e, n) == (m1*m2) % n)

if __name__ == "__main__":
    exchange_malleability()
    signature_malleability()
