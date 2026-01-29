# Assignment 3 Task 3 Part 1

from Crypto.Util.number import getPrime

def get_randoms() -> tuple[int, int]:
    # generate p and q, variable lengths up to 2048 bits
    p = getPrime(2048)
    q = getPrime(2048)

    assert p != q

    return p, q

# GitHub Copilot helped with some of the code generation below
def keygen(p: int, q: int) -> tuple[tuple[int, int], tuple[int, int]]:
    # compute n
    n = p * q

    # compute totient
    phi = (p - 1) * (q - 1)

    # choose e
    e = 65537  # common choice for e

    # compute d
    d = pow(e, -1, phi)

    private = (d, n)
    public = (e, n)

    return private, public

def encryption(m: int, public: tuple[int, int]) -> int:
    e, n = public

    # c -> ciphertext
    c = pow(m, e, n)

    return c

def decryption(c: int, private: tuple[int, int]) -> int:
    d, n = private

    # m -> plaintext
    m = pow(c, d, n)

    return m

# helper function to convert ASCII string to integer
# used ChatGPT to make this function
def ascii_to_int(s: str) -> int:
    # ASCII string → bytes
    b = s.encode("ascii")

    # bytes → hex string
    h = b.hex()

    # hex string → integer
    return int(h, 16)

# helper function to convert integer to ASCII string
# used ChatGPT to make this function
def int_to_ascii(x: int) -> str:
    if x < 0:
        raise ValueError("x must be non-negative")

    # int → hex string (strip '0x')
    h = format(x, "x")

    # ensure even number of hex digits (full bytes)
    if len(h) % 2 != 0:
        h = "0" + h

    # hex → bytes
    b = bytes.fromhex(h)

    # bytes → ASCII string
    return b.decode("ascii")


if __name__ == "__main__":
    p, q = get_randoms()
    private, public = keygen(p, q)

    message = "My name is Nathan!"
    message_int = ascii_to_int(message)
    print (f"Message: {message}")

    ciphertext = encryption(message_int, public)
    print (f"Ciphertext: {ciphertext}")

    plaintext = decryption(ciphertext, private)
    print (f"Plaintext: {plaintext}")

    print(f"Message == Plaintext: {message_int == plaintext}")

    decrypted_message = int_to_ascii(plaintext)
    print (f"Decrypted Message: {decrypted_message}")