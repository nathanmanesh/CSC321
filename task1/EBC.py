# Assignment 2 Task 1: EBC

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

AES_BLOCK_SIZE = 16 # bytes (128 bits) for AES

BMP_HEADER_SIZE = 54 # bytes

# padding for pkcs7
def pad_pkcs7(data: bytes, block_size: int = AES_BLOCK_SIZE) -> bytes:

    if block_size <= 0 or block_size > 255:
        raise ValueError("block size must be in between 1 and 255")

    pad_len = block_size - (len(data) % block_size)
    padding = bytes([pad_len]) * pad_len
    return data + padding 

# manual ecb encryption: encrypt one 16-byte block at a time
def ecb_encrypt(plaintext: bytes, key: bytes) -> bytes:

    # create new cipher opbject and pad plaintext
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad_pkcs7(plaintext, AES_BLOCK_SIZE)

    # loop over padded data in steps of 16 bytes.
    # encrypt each block and append to output
    out = bytearray()
    for i in range(0, len(padded), AES_BLOCK_SIZE):
        block = padded[i: i + AES_BLOCK_SIZE]
        out.extend(cipher.encrypt(block)) # encrypt exactly 16 bytes
    
    return bytes(out)


# encrypt a generic file (no special header handling for bmp)
def encrypt_ecb_file(in_path: str, out_path: str):
    key = get_random_bytes(16) #AES-128 key

    with open(in_path, "rb") as file:
        plaintext = file.read()

    ciphertext = ecb_encrypt(plaintext, key)

    with open(out_path, "wb") as file:
        file.write(ciphertext)

# encrypt a bmp while preserving the header
def encrypt_ecb_bmp(in_bmp:str, out_bmp: str, header_size: int = BMP_HEADER_SIZE):
    key = get_random_bytes(16) # AES-128 key

    with open(in_bmp, "rb") as file:
        bmp = file.read()
    
    header = bmp[:header_size] # keep original bmp header
    pixel_data = bmp[header_size:] # only encrypt pixel data

    ciphertext_pixels = ecb_encrypt(pixel_data, key)

    with open(out_bmp, "wb") as file:
        file.write(header + ciphertext_pixels) # header stays plaintext, pixels become ciphertext


# encrypt_ecb_bmp("mustang.bmp", "output.bmp", BMP_HEADER_SIZE)

        