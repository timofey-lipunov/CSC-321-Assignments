import os
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt
import numpy as np

BLOCK_SIZE = 16
BMP_HEADER_SIZE = 54

def pkcs7_pad(data, block_size):
    pad_len = block_size - (len(data) % block_size)
    padding = bytes([pad_len] * pad_len)
    return data + padding

def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len > BLOCK_SIZE:
        raise ValueError("wrong padding")
    return data[:-pad_len]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def read_bmp(filepath):
    with open(filepath, 'rb') as f:
        header = f.read(BMP_HEADER_SIZE)
        pixel_data = f.read()
    return header, pixel_data

def write_bmp(filepath, header, data):
    with open(filepath, 'wb') as f:
        f.write(header)
        f.write(data)

def aes_ecb_encrypt_block(key, block):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)

def encrypt_ecb(key, data):
    padded_data = pkcs7_pad(data, BLOCK_SIZE)
    ciphertext = b''
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i+BLOCK_SIZE]
        ciphertext += aes_ecb_encrypt_block(key, block)
    return ciphertext

def encrypt_cbc(key, data, iv):
    padded_data = pkcs7_pad(data, BLOCK_SIZE)
    ciphertext = b''
    previous = iv
    for i in range(0, len(padded_data), BLOCK_SIZE):
        block = padded_data[i:i+BLOCK_SIZE]
        block = xor_bytes(block, previous)
        encrypted_block = aes_ecb_encrypt_block(key, block)
        ciphertext += encrypted_block
        previous = encrypted_block
    return ciphertext

def display_images(image_paths, titles):
    fig, axes = plt.subplots(1, len(image_paths), figsize=(15, 5))
    for ax, img_path, title in zip(axes, image_paths, titles):
        with open(img_path, 'rb') as f:
            content = f.read()
        #header = content[:BMP_HEADER_SIZE]
        #data = content[BMP_HEADER_SIZE:]
        try:
            img = np.frombuffer(content, dtype=np.uint8)
            img = img.reshape((100, 100, 3))
        except Exception as e:
            img = None
        ax.imshow(img)
        ax.set_title(title)
        ax.axis('off')
    plt.show()

def main():
    bmp_path = 'cp-logo.bmp'
    header, pixel_data = read_bmp(bmp_path)
    print(f"Read BMP header {BMP_HEADER_SIZE} bytes and pixel data {len(pixel_data)} bytes.")

    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    print("AES Key (hex):", key.hex())
    print("CBC IV (hex):", iv.hex())

    print("Sample original pixel data 32 bytes:", pixel_data[:32].hex())

    ecb_ciphertext = encrypt_ecb(key, pixel_data)
    ecb_output = 'encrypted_ecb.bmp'
    write_bmp(ecb_output, header, ecb_ciphertext)
    print("ECB encryption written to:", ecb_output)

    cbc_ciphertext = encrypt_cbc(key, pixel_data, iv)
    cbc_output = 'encrypted_cbc.bmp'
    write_bmp(cbc_output, header, cbc_ciphertext)
    print("CBC encryption written to:", cbc_output)

    #image_files = [bmp_path, ecb_output, cbc_output]
    #titles = ["Original Image", "ECB Encrypted Image", "CBC Encrypted Image"]
    #display_images(image_files, titles)

if __name__ == "__main__":
    main()
