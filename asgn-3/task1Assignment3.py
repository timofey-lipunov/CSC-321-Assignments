import hashlib
import time
import random
import sys
import matplotlib.pyplot as plt

def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()

def truncate_digest_bits(hex_digest, bits):
    digest = bytes.fromhex(hex_digest)
    total_bytes = (bits + 7) // 8
    truncated = digest[:total_bytes]
    truncated_int = int.from_bytes(truncated, 'big')
    extra_bits = total_bytes * 8 - bits
    if extra_bits:
        truncated_int >>= extra_bits
    return truncated_int

def flip_random_bit(data):
    b = bytearray(data)
    bit_index = random.randrange(len(b) * 8)
    byte_index = bit_index // 8
    bit_in_byte = bit_index % 8
    b[byte_index] ^= 1 << bit_in_byte
    return bytes(b)

def part_a(strings):
    for s in strings:
        print(sha256_hex(s.encode()))

def part_b(strings):
    for s in strings:
        data = s.encode()
        flipped = flip_random_bit(data)
        print(sha256_hex(data), sha256_hex(flipped))

def find_collision(bits):
    seen = {}
    i = 0
    while True:
        msg = str(i).encode()
        h = truncate_digest_bits(sha256_hex(msg), bits)
        if h in seen:
            return seen[h], i
        seen[h] = i
        i += 1

def part_c():
    sizes = list(range(8, 52, 2))
    times = []
    counts = []
    for bits in sizes:
        start = time.time()
        m0, m1 = find_collision(bits)
        elapsed = time.time() - start
        times.append(elapsed)
        counts.append(max(m0, m1) + 1)
        print(f"{bits} bits: collision at {m0} and {m1} after {counts[-1]} hashes in {elapsed:.2f} seconds")
    plt.figure()
    plt.plot(sizes, times)
    plt.xlabel('Digest Size (bits)')
    plt.ylabel('Collision Time (s)')
    plt.savefig('time_vs_size.png')
    plt.figure()
    plt.plot(sizes, counts)
    plt.xlabel('Digest Size (bits)')
    plt.ylabel('Number of Hashes')
    plt.savefig('count_vs_size.png')
    print('Saved graphs: time_vs_size.png, count_vs_size.png')
    plt.show()

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'a':
        part_a(sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] == 'b':
        part_b(sys.argv[2:])
    else:
        part_c()
