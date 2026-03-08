from .rsa import RSA
from .hashing import sha256_hash, SHA256

class DigitalSignature:
    """
    Implements Digital Signatures.
    Sign: Hash(m) -> Decrypt(Hash) with PrivKey
    Verify: Encrypt(Signature) with PubKey == Hash(m)
    """
    
    def __init__(self):
        self.rsa = RSA()

    def sign(self, message: bytes, priv_key: tuple) -> bytes:
        # 1. Hash the message
        h_hex = sha256_hash(message)
        h_bytes = bytes.fromhex(h_hex)
        
        # 2. Encrypt hash with Private Key (Signing)
        # In RSA, "Decrypting" with private key is mathematically same op: m^d mod n
        # Our RSA.decrypt class method does exactly this: pow(c, d, n)
        # Ideally, signatures use padding (PSS), omitting for education.
        
        h_int = int.from_bytes(h_bytes, 'big')
        d, n = priv_key
        
        signature_int = pow(h_int, d, n)
        
        key_len = (n.bit_length() + 7) // 8
        return signature_int.to_bytes(key_len, 'big')

    def verify(self, message: bytes, signature: bytes, pub_key: tuple) -> bool:
        # 1. Decrypt signature with Public Key to get hash
        # Our RSA.encrypt does pow(m, e, n)
        s_int = int.from_bytes(signature, 'big')
        e, n = pub_key
        
        recovered_hash_int = pow(s_int, e, n)
        
        # 2. Hash the message ourselves
        target_hash = sha256_hash(message)
        target_int = int(target_hash, 16)
        
        return recovered_hash_int == target_int
