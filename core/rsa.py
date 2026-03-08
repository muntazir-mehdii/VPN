import random
from .cipher_interface import CipherInterface

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    d = 0
    x1, x2, x3 = 1, 0, phi
    y1, y2, y3 = 0, 1, e
    while y3 > 1:
        q = x3 // y3
        y2, y3 = y2 - q * y2, y3 - q * y3
        x2, x3 = x2 - q * x2, x3 - q * x3
    while y2 < 0:
        y2 += phi
    return y2

def is_prime(n, k=5):
    if n <= 1: return False
    if n <= 3: return True
    for _ in range(k):
        a = random.randint(2, n - 2)
        if pow(a, n - 1, n) != 1:
            return False
    return True

def generate_keypair(bits=1024):
    """
    Generates an RSA keypair.
    Returns ((e, n), (d, n))
    """
    # Simply simulate large primes for demo speed/reliability
    # In production, use `secrets` and rigorous primality tests
    p = _generate_prime(bits // 2)
    q = _generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))

def _generate_prime(bits):
    while True:
        num = random.getrandbits(bits)
        if num % 2 == 0: continue
        if is_prime(num):
            return num

class RSA:
    """
    Textbook RSA Implementation (Educational).
    WARNING: No padding (OAEP/PKCS1) implemented in raw functions.
    Vulnerable to textbook attacks. Use for demo only.
    """
    
    @staticmethod
    def encrypt(message_int: int, pub_key: tuple) -> int:
        e, n = pub_key
        return pow(message_int, e, n)

    @staticmethod
    def decrypt(cipher_int: int, priv_key: tuple) -> int:
        d, n = priv_key
        return pow(cipher_int, d, n)
    
    @staticmethod
    def encrypt_bytes(data: bytes, pub_key: tuple) -> bytes:
        # Naive conversion: Bytes -> Int -> Encrypt -> Int -> Bytes
        m = int.from_bytes(data, 'big')
        e, n = pub_key
        # Check size
        if m >= n:
            raise ValueError("Data too large for key size")
        c = pow(m, e, n)
        # Return bytes (length of modulus)
        key_len = (n.bit_length() + 7) // 8
        return c.to_bytes(key_len, 'big')

    @staticmethod
    def decrypt_bytes(data: bytes, priv_key: tuple) -> bytes:
        c = int.from_bytes(data, 'big')
        d, n = priv_key
        m = pow(c, d, n)
        # Try to fit back into bytes
        msg_len = (m.bit_length() + 7) // 8
        return m.to_bytes(msg_len, 'big')
