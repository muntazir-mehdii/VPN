import struct

class SHA256:
    """
    SHA-256 Hashing Implementation (Educational).
    FIPS 180-4
    """
    
    def __init__(self):
        self._h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        
        self._k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

    def _rotr(self, x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def _shr(self, x, n):
        return (x >> n)

    def _sig0(self, x):
        return self._rotr(x, 7) ^ self._rotr(x, 18) ^ self._shr(x, 3)

    def _sig1(self, x):
        return self._rotr(x, 17) ^ self._rotr(x, 19) ^ self._shr(x, 10)

    def _Sig0(self, x):
        return self._rotr(x, 2) ^ self._rotr(x, 13) ^ self._rotr(x, 22)

    def _Sig1(self, x):
        return self._rotr(x, 6) ^ self._rotr(x, 11) ^ self._rotr(x, 25)

    def _ch(self, x, y, z):
        return (x & y) ^ ((~x) & z)

    def _maj(self, x, y, z):
        return (x & y) ^ (x & z) ^ (y & z)

    def update(self, data: bytes):
        # Preprocessing
        # 1. Append 1 bit (0x80)
        # 2. Append k zero bits
        # 3. Append 64-bit length (big-endian)
        
        l = len(data) * 8 # Length in bits
        chunk = data + b'\x80'
        
        while (len(chunk) * 8) % 512 != 448:
            chunk += b'\x00'
            
        chunk += struct.pack('>Q', l)
        
        # Process 512-bit chunks
        for i in range(0, len(chunk), 64):
            block = chunk[i:i+64]
            w = list(struct.unpack('>16L', block)) + [0]*48
            
            for t in range(16, 64):
                w[t] = (self._sig1(w[t-2]) + w[t-7] + self._sig0(w[t-15]) + w[t-16]) & 0xFFFFFFFF
                
            a, b, c, d, e, f, g, h = self._h
            
            for t in range(64):
                t1 = (h + self._Sig1(e) + self._ch(e, f, g) + self._k[t] + w[t]) & 0xFFFFFFFF
                t2 = (self._Sig0(a) + self._maj(a, b, c)) & 0xFFFFFFFF
                h = g
                g = f
                f = e
                e = (d + t1) & 0xFFFFFFFF
                d = c
                c = b
                b = a
                a = (t1 + t2) & 0xFFFFFFFF
                
            self._h[0] = (self._h[0] + a) & 0xFFFFFFFF
            self._h[1] = (self._h[1] + b) & 0xFFFFFFFF
            self._h[2] = (self._h[2] + c) & 0xFFFFFFFF
            self._h[3] = (self._h[3] + d) & 0xFFFFFFFF
            self._h[4] = (self._h[4] + e) & 0xFFFFFFFF
            self._h[5] = (self._h[5] + f) & 0xFFFFFFFF
            self._h[6] = (self._h[6] + g) & 0xFFFFFFFF
            self._h[7] = (self._h[7] + h) & 0xFFFFFFFF

    def digest(self) -> bytes:
        return struct.pack('>8L', *self._h)

    def hexdigest(self) -> str:
        return self.digest().hex()

def sha256_hash(data: bytes) -> str:
    h = SHA256()
    h.update(data)
    return h.hexdigest()
