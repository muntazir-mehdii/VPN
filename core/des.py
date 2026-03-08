from .cipher_interface import CipherInterface
from .des_constants import IP, FP, E, P, S_BOX, PC1, PC2, SHIFTS

class DES(CipherInterface):
    """
    DES Implementation (Educational).
    Key Size: 8 bytes (64 bits) - effective 56 bits
    Block Size: 8 bytes (64 bits)
    """

    def __init__(self):
        self._subkeys = []

    @property
    def block_size(self) -> int:
        return 8

    @property
    def key_size(self) -> int:
        return 8

    def _permute(self, block, table):
        """Permutes the block using table."""
        permuted_block = 0
        table_len = len(table)
        for i in range(table_len):
            # The table is 1-indexed. Bit length depends on input.
            # We assume 'block' is an integer of sufficient size.
            # We want to extract bit at position table[i] (from left, 1-indexed).
            # If our input 'block' is e.g. 64 bits, bit 1 is MSB.
            
            # Let's handle bit manipulation carefully.
            # We need to know the input size. For IP/FP it is 64. For PC1 64. For E 32. For P 32.
            # We will infer input size or pass it? Standard DES tables assume specific input sizes.
            pass
        return permuted_block

    # Bit manipulation Helper
    # To simplify, we'll work with strings of '0' and '1' for educational clarity in this "Educational" implementation
    # This is slower but easier to visualize/debug if needed.
    # Actually, for "Professional-grade code architecture" requested, bitwise is better.
    
    def _permute_bits(self, input_val: int, table: list, input_len: int) -> int:
        output_val = 0
        for i, pos in enumerate(table):
            # pos is 1-indexed from left.
            # input_len=64. Bit 1 is 63rd shift.
            shift = input_len - pos
            bit = (input_val >> shift) & 1
            output_val = (output_val << 1) | bit
        return output_val

    def _generate_subkeys(self, key_bytes: bytes):
        if len(key_bytes) != 8:
            raise ValueError("DES key must be 8 bytes")
        
        # Convert bytes to 64-bit int
        key_int = int.from_bytes(key_bytes, 'big')
        
        # PC1 Permutation (64 -> 56 bits)
        k56 = self._permute_bits(key_int, PC1, 64)
        
        # Split into C and D (28 bits each)
        c = (k56 >> 28) & 0xFFFFFFF
        d = k56 & 0xFFFFFFF
        
        self._subkeys = []
        for shift in SHIFTS:
            # Circular Left Shift
            c = ((c << shift) & 0xFFFFFFF) | (c >> (28 - shift))
            d = ((d << shift) & 0xFFFFFFF) | (d >> (28 - shift))
            
            # Combine
            cd = (c << 28) | d
            
            # PC2 Permutation (56 -> 48 bits)
            k48 = self._permute_bits(cd, PC2, 56)
            self._subkeys.append(k48)

    def _f_function(self, r: int, k: int) -> int:
        # Expansion (32 -> 48)
        er = self._permute_bits(r, E, 32)
        
        # XOR with subkey
        x = er ^ k
        
        # S-Box Substitution (48 -> 32)
        # x is 48 bits. split into 8 chunks of 6 bits.
        output_32 = 0
        for i in range(8):
            # Extract 6 bits. Chunk 0 is MSB.
            # (48 - 6*(i+1)) shift
            shift = 42 - 6*i
            chunk = (x >> shift) & 0x3F
            
            # Row: bits 0 and 5
            row = ((chunk >> 5) & 1) * 2 + (chunk & 1)
            # Col: bits 1,2,3,4
            col = (chunk >> 1) & 0xF
            
            val = S_BOX[i][row][col]
            output_32 = (output_32 << 4) | val
            
        # P Permutation (32 -> 32)
        return self._permute_bits(output_32, P, 32)

    def encrypt(self, data: bytes, key: bytes) -> bytes:
        if len(data) != 8:
            raise ValueError("Data must be 8 bytes")
            
        self._generate_subkeys(key)
        
        block_int = int.from_bytes(data, 'big')
        
        # Initial Permutation
        block_int = self._permute_bits(block_int, IP, 64)
        
        # Split
        l = (block_int >> 32) & 0xFFFFFFFF
        r = block_int & 0xFFFFFFFF
        
        # 16 Rounds
        for i in range(16):
            prev_l = l
            l = r
            r = prev_l ^ self._f_function(r, self._subkeys[i])
            
        # Swap after last round
        rl = (r << 32) | l
        
        # Final Permutation
        cipher_int = self._permute_bits(rl, FP, 64)
        
        return cipher_int.to_bytes(8, 'big')

    def decrypt(self, data: bytes, key: bytes) -> bytes:
        if len(data) != 8:
            raise ValueError("Data must be 8 bytes")
            
        self._generate_subkeys(key)
        
        block_int = int.from_bytes(data, 'big')
        
        # Initial Permutation
        block_int = self._permute_bits(block_int, IP, 64)
        
        # Split
        l = (block_int >> 32) & 0xFFFFFFFF
        r = block_int & 0xFFFFFFFF
        
        # 16 Rounds (Keys in reverse)
        for i in range(15, -1, -1):
            prev_l = l
            l = r
            r = prev_l ^ self._f_function(r, self._subkeys[i])
            
        # Swap
        rl = (r << 32) | l
        
        # Final Permutation
        plain_int = self._permute_bits(rl, FP, 64)
        
        return plain_int.to_bytes(8, 'big')
