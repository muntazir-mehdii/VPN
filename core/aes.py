import copy
from .cipher_interface import CipherInterface
from .aes_constants import S_BOX, INV_S_BOX, R_CON

class AES(CipherInterface):
    """
    AES-128 Implementation.
    Paper: FIPS 197
    Key Size: 16 bytes (128 bits)
    Block Size: 16 bytes (128 bits)
    Rounds: 10
    """
    
    def __init__(self):
        self._key = None
        self._round_keys = None

    @property
    def block_size(self) -> int:
        return 16

    @property
    def key_size(self) -> int:
        return 16

    def expand_key(self, key: bytes):
        """
        Key Expansion Phase.
        Generates 11 round keys for AES-128.
        """
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes for AES-128")
        
        self._key = key
        # Convert key to a list of integers
        key_symbols = [b for b in key]
        
        # The first round key is the key itself
        # Each round key is 16 bytes. Total 11 round keys (176 bytes)
        # We process column by column (word by word, 4 bytes)
        
        # 4 words per round key. Total 44 words (4 * 11)
        w = [0] * 44

        # First 4 words are the key itself
        for i in range(4):
            w[i] = (key_symbols[4*i] << 24) | (key_symbols[4*i+1] << 16) | \
                   (key_symbols[4*i+2] << 8) | (key_symbols[4*i+3])

        for i in range(4, 44):
            temp = w[i-1]
            if i % 4 == 0:
                # RotWord
                temp = ((temp << 8) & 0xFFFFFFFF) | (temp >> 24)
                # SubWord
                temp = (S_BOX[(temp >> 24) & 0xFF] << 24) | \
                       (S_BOX[(temp >> 16) & 0xFF] << 16) | \
                       (S_BOX[(temp >> 8) & 0xFF] << 8) | \
                       (S_BOX[temp & 0xFF])
                # XOR with Rcon
                rcon_val = R_CON[i // 4] << 24
                temp = temp ^ rcon_val
            
            w[i] = w[i-4] ^ temp
            
        self._round_keys = []
        for i in range(11):
            # Convert 4 words back to 16 bytes
            rk = []
            for j in range(4):
                val = w[4*i + j]
                rk.append((val >> 24) & 0xFF)
                rk.append((val >> 16) & 0xFF)
                rk.append((val >> 8) & 0xFF)
                rk.append(val & 0xFF)
            self._round_keys.append(bytes(rk))

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        if len(data) != 16:
            raise ValueError("Data must be exactly 16 bytes")
        
        self.expand_key(key)
        
        state = [list(data[i:i+4]) for i in range(0, 16, 4)]
        # Transpose to get the state matrix as described in FIPS 197 (column-major)
        # Input: [0,1,2,3, 4,5,6,7, ...] -> Rows are [0,4,8,12], [1,5,9,13]...
        # Wait, the list(data[i:i+4]) gives [[0,1,2,3], [4,5,6,7]...]
        # My implementation treats these as columns directly to simplify operations
        # State[row][col]
        # Let's map standard logic:
        # Standard: row, col. Input bytes fill column 0, then column 1...
        # Here: I will store as 4x4 list of lists.
        # s[0][0]=b0, s[1][0]=b1, s[2][0]=b2, s[3][0]=b3 ... 
        
        s = [[0]*4 for _ in range(4)]
        for r in range(4):
            for c in range(4):
                s[r][c] = data[r + 4*c]

        # AddRoundKey (Round 0)
        self._add_round_key(s, self._round_keys[0])

        # Rounds 1 to 9
        for round in range(1, 10):
            self._sub_bytes(s)
            self._shift_rows(s)
            self._mix_columns(s)
            self._add_round_key(s, self._round_keys[round])

        # Round 10
        self._sub_bytes(s)
        self._shift_rows(s)
        self._add_round_key(s, self._round_keys[10])

        # Output
        out = []
        for c in range(4):
            for r in range(4):
                out.append(s[r][c])
        return bytes(out)

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        if len(data) != 16:
            raise ValueError("Data must be exactly 16 bytes")
        
        self.expand_key(key)
        
        s = [[0]*4 for _ in range(4)]
        for r in range(4):
            for c in range(4):
                s[r][c] = data[r + 4*c]
        
        # Inverse Rounds
        # Round 10 (inverse of final round)
        self._add_round_key(s, self._round_keys[10])
        self._inv_shift_rows(s)
        self._inv_sub_bytes(s)

        # Rounds 9 to 1
        for round in range(9, 0, -1):
            self._add_round_key(s, self._round_keys[round])
            self._inv_mix_columns(s)
            self._inv_shift_rows(s)
            self._inv_sub_bytes(s)

        # Round 0
        self._add_round_key(s, self._round_keys[0])

        out = []
        for c in range(4):
            for r in range(4):
                out.append(s[r][c])
        return bytes(out)

    # --- Internals ---

    def _add_round_key(self, s, k):
        # k is linear 16 bytes. s is 4x4 [row][col]
        # k fills col 0, then col 1...
        for c in range(4):
            for r in range(4):
                s[r][c] ^= k[r + 4*c]

    def _sub_bytes(self, s):
        for r in range(4):
            for c in range(4):
                s[r][c] = S_BOX[s[r][c]]

    def _inv_sub_bytes(self, s):
        for r in range(4):
            for c in range(4):
                s[r][c] = INV_S_BOX[s[r][c]]

    def _shift_rows(self, s):
        s[1][0], s[1][1], s[1][2], s[1][3] = s[1][1], s[1][2], s[1][3], s[1][0]
        s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
        s[3][0], s[3][1], s[3][2], s[3][3] = s[3][3], s[3][0], s[3][1], s[3][2]

    def _inv_shift_rows(self, s):
        s[1][0], s[1][1], s[1][2], s[1][3] = s[1][3], s[1][0], s[1][1], s[1][2]
        s[2][0], s[2][1], s[2][2], s[2][3] = s[2][2], s[2][3], s[2][0], s[2][1]
        s[3][0], s[3][1], s[3][2], s[3][3] = s[3][1], s[3][2], s[3][3], s[3][0]

    def _mix_columns(self, s):
        for c in range(4):
            a = [s[0][c], s[1][c], s[2][c], s[3][c]]
            # Fixed MixColumns Matrix in Galois Field
            # 2 3 1 1
            # 1 2 3 1
            # 1 1 2 3
            # 3 1 1 2
            s[0][c] = self._gmul(2, a[0]) ^ self._gmul(3, a[1]) ^ a[2] ^ a[3]
            s[1][c] = a[0] ^ self._gmul(2, a[1]) ^ self._gmul(3, a[2]) ^ a[3]
            s[2][c] = a[0] ^ a[1] ^ self._gmul(2, a[2]) ^ self._gmul(3, a[3])
            s[3][c] = self._gmul(3, a[0]) ^ a[1] ^ a[2] ^ self._gmul(2, a[3])

    def _inv_mix_columns(self, s):
        for c in range(4):
            a = [s[0][c], s[1][c], s[2][c], s[3][c]]
            # Inverse MixColumns Matrix
            # 14 11 13 9
            # 9 14 11 13
            # 13 9 14 11
            # 11 13 9 14
            s[0][c] = self._gmul(14, a[0]) ^ self._gmul(11, a[1]) ^ self._gmul(13, a[2]) ^ self._gmul(9, a[3])
            s[1][c] = self._gmul(9, a[0]) ^ self._gmul(14, a[1]) ^ self._gmul(11, a[2]) ^ self._gmul(13, a[3])
            s[2][c] = self._gmul(13, a[0]) ^ self._gmul(9, a[1]) ^ self._gmul(14, a[2]) ^ self._gmul(11, a[3])
            s[3][c] = self._gmul(11, a[0]) ^ self._gmul(13, a[1]) ^ self._gmul(9, a[2]) ^ self._gmul(14, a[3])

    def _gmul(self, a, b):
        """Galois Field multiplication of a and b"""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xFF
            if hi_bit_set:
                a ^= 0x1B # Ri jndael's finite field
            b >>= 1
        return p
