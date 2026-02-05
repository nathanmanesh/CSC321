# Assignment 3 Task 3 Part 2

from RSA import *
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, GCD, long_to_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def alice_keygen():
    # generate p and q
    p, q = get_randoms()

    # generate keys
    private, public = keygen(p, q)

    return private, public

def bob(public_key: tuple[int, int]) -> int:
    e, n = public_key
    while True:
        # Sample a random integer with about the same size as n
        s = bytes_to_long(get_random_bytes((n.bit_length() + 7) // 8))

        if not (1 <= s < n):
            continue

        # Enforce membership in Z_n^* (invertible mod n)
        if GCD(s, n) != 1:
            continue

        c = encryption(s, public_key)

        return c

def mallory_mitm(public_key: tuple[int, int]) -> tuple[int, int]:
    e, n = public_key

    sM = 1      # always coprime, always in range
    c_prime = encryption(sM, public_key)

    return c_prime, sM      # need to save sM for decryption

def alice_2(c_prime: int, alice_private: tuple[int, int]) -> tuple[int, int]:
    d, n = alice_private
    
    s = decryption(c_prime, alice_private)
    k = SHA256.new(long_to_bytes(s, (n.bit_length() + 7) // 8)).digest()

    message = "Hi Bob!"
    iv = get_random_bytes(16)

    cipher = AES.new(k, AES.MODE_CBC, iv)
    c0 = cipher.encrypt(pad(message.encode("ascii"), AES.block_size))

    return c0, iv

def mallory_decrypt(c0, iv, sM, public_key):
    e, n = public_key

    kM = SHA256.new(long_to_bytes(sM, (n.bit_length() + 7) // 8)).digest()

    cipher = AES.new(kM, AES.MODE_CBC, iv)
    message = unpad(cipher.decrypt(c0), AES.block_size)

    return message.decode("ascii")
    

def main():
    # Alice generates keys (and "sends" public key to Bob)
    alice_private, alice_public = alice_keygen()

    # Bob generates random s and sends encrypted s to Alice
    c = bob(alice_public)

    # Mallory intercepts and modifies encrypted s
    c_prime, sM = mallory_mitm(alice_public)

    # Alice decrypts received encrypted s (modified by Mallory)
    c0, iv = alice_2(c_prime, alice_private)

    # Mallory decrypts Alice's message using sM
    message = mallory_decrypt(c0, iv, sM, alice_public)

    print("Mallory's decrypted message:", message)

if __name__ == "__main__":
    main()