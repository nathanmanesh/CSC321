# Assignment 2 Task 2

from task1.CBC import *
from task1.EBC import *

from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES

from urllib.parse import unquote
from urllib.parse import quote

AES_BLOCK_SIZE = 16  # bytes (128 bits) for AES

KEY = get_random_bytes(16)
IV = get_random_bytes(16)

PREFIX = "userid=456;userdata="
SUFFIX = ";session-id=31337"

def submit(string: str) -> bytes:

    safe_user = string.replace(";", "%3B").replace("=", "%3D")

    # prepend and append to user provided string
    message_str = PREFIX + safe_user + SUFFIX

    # convert to bytes for crypto
    message = message_str.encode("utf-8")

    # pad for PKCS#7
    padded = pad_pkcs7(message, AES_BLOCK_SIZE)

    ciphertext = cbc_encrypt(padded, KEY, IV)
    return ciphertext

def pkcs7_unpad(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:

    if len(data) == 0 or (len(data) % block_size) != 0:
        raise ValueError("invalid padded length")
    
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("invalid PKCS#7 padding bytes")
    
    return data[:-pad_len]


def verify(ciphertext: bytes) -> bool:

    try:

        # create a cipher object with the same key used for encryption
        cipher = AES.new(KEY, AES.MODE_CBC, iv = IV)


        # decrypt to get padded plaintext bytes 
        padded = cipher.decrypt(ciphertext)

        # remove PKCS#7 padding 
        plaintext = pkcs7_unpad(padded, AES_BLOCK_SIZE)

        # parse string for the pattern and return true if string exists
        text = plaintext.decode("utf-8", errors="ignore")

        return ";admin=true;" in text

    # return false if string doesnt exist
    except Exception:

        return False
    
def verify_return_true() -> bytes:

    # put block we control into plaintext
    # later flip ":" -> ";" and "<" -> "="
    wanted = b";admin=true;"
    given = b":admin<true:" # no ";" or "=" so submit() wont encode it

    prefix_len = len(PREFIX.encode("utf-8"))

    
    filler_len = (-prefix_len) % AES_BLOCK_SIZE
    user_input = ("A" * filler_len) + given.decode("utf-8") + "XXXX" # 16 bytes


    ciphertext = submit(user_input)
    ciphertext_mut = bytearray(ciphertext)

    # figure out which plaintext block contains "given"
    start_offset = prefix_len + filler_len
    block_index = start_offset // AES_BLOCK_SIZE

    # modify ciphertext block (block_index - 1) to affect plaintext block block_index
    prev_block_start = (block_index - 1) * AES_BLOCK_SIZE

    # flip bytes in ciphertext block 0 so decrypted plaintext block 1 changes from "given" to wanted
    for i in range(len(wanted)):
        ciphertext_mut[prev_block_start + i] ^= given[i] ^ wanted[i]

    
    return bytes(ciphertext_mut)



return_true = verify_return_true()
print(verify(return_true))
