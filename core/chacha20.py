import struct
from .cipher_interface import CipherInterface

class ChaCha20(CipherInterface):
    """
    ChaCha20 Stream Cipher Implementation.
    RFC 7539 / 8439
    Key Size: 32 bytes (256 bits)
    Nonce Size: 12 bytes (96 bits)
    Counter Size: 4 bytes (32 bits)
    """

    def __init__(self):
        self._key = None
        self._nonce = None
        self._counter = 1

    @property
    def block_size(self) -> int:
        return 64  # ChaCha20 works on 64-byte blocks internally

    @property
    def key_size(self) -> int:
        return 32

    def _quarter_round(self, x, a, b, c, d):
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = x[d] ^ x[a]
        x[d] = ((x[d] << 16) | (x[d] >> 16)) & 0xFFFFFFFF
        
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = x[b] ^ x[c]
        x[b] = ((x[b] << 12) | (x[b] >> 20)) & 0xFFFFFFFF
        
        x[a] = (x[a] + x[b]) & 0xFFFFFFFF
        x[d] = x[d] ^ x[a]
        x[d] = ((x[d] << 8) | (x[d] >> 24)) & 0xFFFFFFFF
        
        x[c] = (x[c] + x[d]) & 0xFFFFFFFF
        x[b] = x[b] ^ x[c]
        x[b] = ((x[b] << 7) | (x[b] >> 25)) & 0xFFFFFFFF

    def _chacha_block(self, key, counter, nonce):
        constants = [0x61707865, 0x3320646e, 0x796b2d32, 0x6b206574]
        key_ints = struct.unpack('<8L', key)
        nonce_ints = struct.unpack('<3L', nonce)
        
        # Initial State (4x4 matrix of 32-bit words)
        # Constants | Key | Counter | Nonce
        state = list(constants + list(key_ints) + [counter] + list(nonce_ints))
        working_state = list(state)
        
        for _ in range(10): # 20 rounds (10 iterations of 2 rounds)
            # Column rounds
            self._quarter_round(working_state, 0, 4, 8, 12)
            self._quarter_round(working_state, 1, 5, 9, 13)
            self._quarter_round(working_state, 2, 6, 10, 14)
            self._quarter_round(working_state, 3, 7, 11, 15)
            # Diagonal rounds
            self._quarter_round(working_state, 0, 5, 10, 15)
            self._quarter_round(working_state, 1, 6, 11, 12)
            self._quarter_round(working_state, 2, 7, 8, 13)
            self._quarter_round(working_state, 3, 4, 9, 14)
            
        return b''.join(struct.pack('<L', (working_state[i] + state[i]) & 0xFFFFFFFF) for i in range(16))

    def encrypt(self, data: bytes, key: bytes, nonce: bytes = None) -> bytes:
        """
        Encrypts data using ChaCha20.
        Note: Stream ciphers require a Unique Nonce for security.
        For education, if nonce is None, we use a zero nonce (INSECURE).
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes")
            
        if nonce is None:
            nonce = b'\x00' * 12
        elif len(nonce) != 12:
             raise ValueError("Nonce must be 12 bytes")

        encrypted = bytearray()
        counter = 1 # Start counter at 1 usually
        
        # Process full 64-byte blocks
        for i in range(0, len(data), 64):
            keystream = self._chacha_block(key, counter, nonce)
            block = data[i:i+64]
            encrypted.extend(a ^ b for a, b in zip(block, keystream))
            counter += 1
            
        return bytes(encrypted)

    def decrypt(self, data: bytes, key: bytes, nonce: bytes = None) -> bytes:
        # Encryption and Decryption are the same in stream ciphers (XOR)
        return self.encrypt(data, key, nonce)
