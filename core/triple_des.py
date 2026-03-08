from .cipher_interface import CipherInterface
from .des import DES

class TripleDES(CipherInterface):
    """
    Triple DES (3DES) Implementation.
    Mode: EDE (Encrypt-Decrypt-Encrypt) using 3 separate keys (Option 1) or 2 keys (Option 2).
    Key Size: 24 bytes (192 bits) - Option 1
              16 bytes (128 bits) - Option 2 (K1=K3)
    Block Size: 8 bytes (64 bits)
    """

    def __init__(self):
        self.des = DES()

    @property
    def block_size(self) -> int:
        return 8

    @property
    def key_size(self) -> int:
        return 24 

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        if len(data) != 8:
            raise ValueError("Data must be 8 bytes")
        
        # Determine keying option
        if len(key) == 24:
            k1 = key[:8]
            k2 = key[8:16]
            k3 = key[16:]
        elif len(key) == 16:
            k1 = key[:8]
            k2 = key[8:16]
            k3 = k1
        else:
            raise ValueError("Key must be 16 or 24 bytes")

        # EDE
        c1 = self.des.encrypt(data, k1)
        p2 = self.des.decrypt(c1, k2)
        c3 = self.des.encrypt(p2, k3)
        
        return c3

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        if len(data) != 8:
            raise ValueError("Data must be 8 bytes")

        if len(key) == 24:
            k1 = key[:8]
            k2 = key[8:16]
            k3 = key[16:]
        elif len(key) == 16:
            k1 = key[:8]
            k2 = key[8:16]
            k3 = k1
        else:
            raise ValueError("Key must be 16 or 24 bytes")

        # Reverse EDE -> DED
        p1 = self.des.decrypt(data, k3)
        c2 = self.des.encrypt(p1, k2)
        p3 = self.des.decrypt(c2, k1)
        
        return p3
