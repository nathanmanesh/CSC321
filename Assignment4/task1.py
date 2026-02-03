# Assignment 4 Task 1

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number
import hashlib

def hash_sha256_from_string(input_string) ->str:

    # encode string to bytes
    encoded_string = input_string.encode("utf-8")

    # create hash object
    hash_object = hashlib.sha256(encoded_string)

    print(hash_object.hexdigest()) 

def hash_sha256_from_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest


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


