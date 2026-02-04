# Assignment 4 Task 1

from Crypto.Hash import SHA256
import os
import time


def hash_sha256_from_string(input_string) ->str:

    # encode string to bytes
    encoded_string = input_string.encode("utf-8")

    # create hash object
    hash_object = SHA256.new(data=encoded_string)

    return hash_object.hexdigest()

def hash_sha256_from_bytes(data: bytes) -> str:
    return SHA256.new(data=data).hexdigest()


# return copy of data with exactly one bit flipped ("Hash two strings (of any length) whose 
# Hamming distance is exactly 1 bit")
def flip_one_bit(data: bytes, byte_index: int, bit_index: int) -> bytes:
    b = bytearray(data)
    b[byte_index] ^= ( 1 << bit_index)
    return bytes(b)


# bit level hamming distance between two equal-length byte strings
# formula retrieved from stackOverflow
def hamming_distance(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("Inputs must have the same length")

    return sum((b1 ^ b2).bit_count() for b1, b2 in zip(a, b))


# collisions (two string that have same digest)
# limit domain between 8-50 bits for sha256

# some code generation using ChatGPT
def hash_sha256_trunc_bits(data: bytes, nbits: int) -> int:
    digest = SHA256.new(data=data).digest() # 32 bytes
    digest_int = int.from_bytes(digest, "big") # 256-bit int
    return digest_int >> (256 - nbits) # keep top nbits

# some code generation using ChatGPT
def find_collision_birthday(nbits: int, msg_len: int = 16) -> tuple[bytes, bytes, int, int, float]:
    
    seen = {}  # maps digest_value -> first message that produced it
    input_count = 0
    start_time = time.perf_counter()

    while True:
        input_count += 1
        m1 = os.urandom(msg_len)
        digest = hash_sha256_trunc_bits(m1, nbits)

        if digest in seen:
            m0 = seen[digest]
            if m1 != m0:
                seconds = time.perf_counter() - start_time
                return m0, m1, digest, input_count, seconds
        else:
            seen[digest] = m1


def run_birthday_experiments():
    digest_sizes = []
    num_inputs = []
    collision_times = []

    for bits in range(8, 52, 2):  
        print(f"Running birthday collision for {bits} bits...")
        m0, m1, digest_value, attempts, elapsed_time = find_collision_birthday(bits)
        digest_sizes.append(bits)
        num_inputs.append(attempts)
        collision_times.append(elapsed_time)

    return digest_sizes, num_inputs, collision_times

if __name__ == "__main__":
    
    digest_sizes, num_inputs, collision_times = run_birthday_experiments()
    print("Digest sizes:", digest_sizes)
    print("Number of inputs:", num_inputs)
    print("Collision times:", collision_times)


