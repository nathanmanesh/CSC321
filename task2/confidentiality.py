# Assignment 2 Task 2

from task1.CBC import *
from task1.EBC import *

from Crypto.Random import get_random_bytes

from urllib.parse import quote

AES_BLOCK_SIZE = 16  # bytes (128 bits) for AES

KEY = get_random_bytes(16)

PREFIX = "userid=456;userdata="
SUFFIX = ";session-id=31337"

def submit(string: str) -> bytes:


    # URL encode any ‘;’ and ‘=’ characters that appear in the user provided string; 
    safe_string = quote(string, safe="")

    # prepend and append to user provided string
    message_str = PREFIX + safe_string + SUFFIX

    # convert to bytes for crypto
    message = message_str.encode("utf-8")

    # pad for PKCS#7
    padded = pad_pkcs7(message, AES_BLOCK_SIZE)

    ciphertext = ecb_encrypt(padded, KEY)
    return ciphertext


def verify():
    pass





