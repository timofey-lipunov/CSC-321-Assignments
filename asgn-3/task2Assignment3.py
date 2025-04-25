import os
import time
import bcrypt
import nltk
from nltk.corpus import words
from multiprocessing import Pool, cpu_count

SHADOW_PATH = "shadow.txt"

# Generate a bcrypt hash for each user from shadow.txt
def load_shadow(path):
    entries = []
    with open(path, 'r') as f:
        for line in f:
            user, hashed = line.strip().split(':', 1)
            entries.append((user, hashed.encode('utf-8')))
    return entries

# Download NTLK words list if not already present
def init_nltk():
    nltk.download('words', quiet=True)

# Makes a list of candidate words (lowercase 6-10 char words)
def make_candidates():
    all_words = words.words()
    return [w.lower() for w in all_words if 6 <= len(w) <= 10]

# Parallel worker function to check if a word matches the hash
def worker(args):
    chunk, hashed = args
    for w in chunk:
        if bcrypt.checkpw(w.encode('utf-8'), hashed):
            return w
    return None


# Use multiprocessing to crack the password in parallel
def crack_user_parallel(user, hashed, candidates):
    nprocs = cpu_count()
    chunk_size = len(candidates) // nprocs + 1
    chunks = [candidates[i:i + chunk_size] for i in range(0, len(candidates), chunk_size)]
    args = [(chunk, hashed) for chunk in chunks]

    start = time.perf_counter()
    with Pool(nprocs) as pool:
        for result in pool.imap_unordered(worker, args):
            if result:
                elapsed = time.perf_counter() - start
                print(f"{user} -> {result}  (in {elapsed:.2f} s)")
                pool.terminate()
                return
    elapsed = time.perf_counter() - start
    print(f"{user} not cracked after {elapsed:.2f} s")

def main():
    init_nltk()
    candidates = make_candidates()
    shadow = load_shadow(SHADOW_PATH)

    print(f"Loaded {len(candidates)} candidate words, using {cpu_count()} cores.\n")
    for user, hashed in shadow:
        print(f"Cracking {user} (workfactor = {hashed.decode().split('$')[2]})...")
        crack_user_parallel(user, hashed, candidates)
        print()

if __name__ == "__main__":
    main()
