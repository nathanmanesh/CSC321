# Assignment 3 Task 1

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Random.random import randint


def int_to_bytes(n: int) -> bytes:
    length = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(length, "big")


# derive a 16 byte AES key from Diffie-Hellman shared secret
def aes_key_from_shared_secret(s: int) -> bytes:

    #  hash shared secreate and truncate to 16 bytes for AES128
    hash_bytes = SHA256.new(int_to_bytes(s)).digest()

    return hash_bytes[:16]

# encrypt a message using AES in CBC mode
def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv = iv)

    return cipher.encrypt(pad(plaintext, AES.block_size))

# decrypt a message using AES in CBC mode
def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv = iv)

    return unpad(cipher.decrypt(ciphertext), AES.block_size)

