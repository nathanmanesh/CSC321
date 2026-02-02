# Assignment 4 Task 1

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util import number
import hashlib

def hash_sha256(input_string):

    # encode string to bytes
    encoded_string = input_string.encode("utf-8")

    # create hash object
    hash_object = hashlib.sha256(encoded_string)

    print(hash_object.hexdigest()) 


def hamming_distance(chaine1: bytes, chaine2: bytes) -> int:
    if len(chaine1) != len(chaine2):
        raise ValueError("Inputs must have the same length")

    return sum((b1 ^ b2).bit_count() for b1, b2 in zip(chaine1, chaine2))


