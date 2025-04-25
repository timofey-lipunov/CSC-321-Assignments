import os
import urllib.parse
from Crypto.Cipher import AES

# Global settings: BLOCK_SIZE, KEY, IV
BLOCK_SIZE = 16
KEY = os.urandom(BLOCK_SIZE)  # random AES key (16 bytes)
IV  = os.urandom(BLOCK_SIZE)  # random IV for CBC (16 bytes)

# PKCS#7 Padding Functions
def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]

# Manual CBC Encryption and Decryption
def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    ciphertext = b""
    previous = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i : i + BLOCK_SIZE]
        xored = bytes(b1 ^ b2 for b1, b2 in zip(block, previous))
        enc_block = cipher.encrypt(xored)
        ciphertext += enc_block
        previous = enc_block
    return ciphertext

def cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = b""
    previous = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i : i + BLOCK_SIZE]
        decrypted = cipher.decrypt(block)
        plaintext += bytes(b1 ^ b2 for b1, b2 in zip(decrypted, previous))
        previous = block
    return pkcs7_unpad(plaintext)

# formats and encrypts the input data
def submit(user_input: str) -> bytes:
    safe_input = urllib.parse.quote(user_input)
    plaintext_str = f"userid=456;userdata={safe_input};session-id=31337"
    plaintext = plaintext_str.encode("utf-8")
    return cbc_encrypt(plaintext, KEY, IV)

# checks for ';admin=true;' in the decrypted plaintext
def verify(ciphertext: bytes) -> bool:
    decrypted = cbc_decrypt(ciphertext, KEY, IV)
    return b";admin=true;" in decrypted

def bit_flipping_attack() -> bytes:
    user_input = "A" * 12 + "X" * 16
    ciphertext = submit(user_input)
    
    blocks = [ciphertext[i: i + BLOCK_SIZE] for i in range(0, len(ciphertext), BLOCK_SIZE)]
    target_block_index = 2
    
    desired_plain = b";admin=true;AAAA"  # 16 bytes: ';admin=true;' (12 bytes) + 'AAAA' (4 bytes)
    original_plain = b"X" * 16  # original plaintext in the controlled block
    
    xor_diff = bytes(orig ^ targ for orig, targ in zip(original_plain, desired_plain))
    
    modified_prev_block = bytearray(blocks[target_block_index - 1])
    for i in range(BLOCK_SIZE):
        modified_prev_block[i] ^= xor_diff[i]
    blocks[target_block_index - 1] = bytes(modified_prev_block)
    
    modified_ciphertext = b"".join(blocks)
    return modified_ciphertext

# Runs the bit flipping attack.
def run_attack_demo():
    modified_ciphertext = bit_flipping_attack()
    
    if verify(modified_ciphertext):
        print("Attack succeeded: ';admin=true;' was injected into the plaintext")
    else:
        print("Attack failed")
    
    plaintext = cbc_decrypt(modified_ciphertext, KEY, IV)
    print("Decrypted plaintext:")
    print(plaintext.decode("utf-8", errors="replace"))
    
if __name__ == "__main__":
    run_attack_demo()
