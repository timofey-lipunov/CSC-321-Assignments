import secrets
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt(k, m):
    iv = b"\x00"*16
    return AES.new(k, AES.MODE_CBC, iv).encrypt(pad(m, 16))

def decrypt(k, c):
    iv = b"\x00"*16
    return unpad(AES.new(k, AES.MODE_CBC, iv).decrypt(c), 16)

def fix_public(q, alpha):
    k = hashlib.sha256(b"\x00").digest()[:16]
    c = encrypt(k, b"Hi Bob!")
    print(decrypt(k, c))

def fix_generator(alpha, q):
    s = {1:1, q:0, q-1:1}[alpha] if alpha in (1, q, q-1) else None
    k = hashlib.sha256(int.to_bytes(s, (s.bit_length()+7)//8, 'big')).digest()[:16]
    c = encrypt(k, b"MITM Attack")
    print(decrypt(k, c))

if __name__ == "__main__":
    fix_public(37, 5)
    fix_generator(1, 37)
    fix_generator(37, 37)
    fix_generator(36, 37)
