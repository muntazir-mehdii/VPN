import sys
import os

# Add parent directory to path to import core
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.aes import AES

def test_aes():
    print("\n--- Testing AES-128 ---")
    key = b'\x00' * 16  # Zero key
    data = b'\x00' * 16 # Zero block
    
    print(f"Key: {key.hex()}")
    print(f"Plaintext: {data.hex()}")
    
    aes = AES()
    
    # Encrypt
    encrypted = aes.encrypt(data, key)
    print(f"Ciphertext: {encrypted.hex()}")
    
    # Decrypt
    decrypted = aes.decrypt(encrypted, key)
    print(f"Decrypted: {decrypted.hex()}")
    
    if decrypted == data:
        print("[PASS] AES Test Passed: Decrypted matches Plaintext")
    else:
        print("[FAIL] AES Test Failed: Decrypted does not match Plaintext")

    # Known Vector Test (FIPS 197 Appendix C.1)
    # Key: 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
    # Input: 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
    # Expected Output: 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
    
    k_vec = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    d_vec = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    exp_vec = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    
    print("\n--- AES Known Vector Test ---")
    vec_enc = aes.encrypt(d_vec, k_vec)
    print(f"Vector Ciphertext: {vec_enc.hex()}")
    if vec_enc == exp_vec:
        print("[PASS] AES Vector Test Passed")
    else:
        print(f"[FAIL] AES Vector Test Failed. Expected {exp_vec.hex()}")

from core.des import DES

def test_des():
    print("\n--- Testing DES ---")
    key = b'\x00' * 8
    data = b'\x00' * 8
    
    print(f"Key: {key.hex()}")
    print(f"Plaintext: {data.hex()}")
    
    des = DES()
    enc = des.encrypt(data, key)
    print(f"Ciphertext: {enc.hex()}")
    
    dec = des.decrypt(enc, key)
    print(f"Decrypted: {dec.hex()}")
    
    if dec == data:
        print("[PASS] DES Test Passed")
    else:
        print("[FAIL] DES Test Failed")

    # DES Known Vector (FIPS 46-3 / NIST SP 800-17)
    # Key: 80 00 00 00 00 00 00 00
    # Plain: 00 00 00 00 00 00 00 00
    # Cipher: 95 F8 A5 E5 DD 31 D9 00
    
    k_vec = bytes.fromhex("8000000000000000")
    d_vec = bytes.fromhex("0000000000000000")
    exp_vec = bytes.fromhex("95F8A5E5DD31D900")
    
    print("\n--- DES Known Vector Test ---")
    vec_enc = des.encrypt(d_vec, k_vec)
    print(f"Vector Ciphertext: {vec_enc.hex()}")
    if vec_enc == exp_vec:
        print("[PASS] DES Vector Test Passed")
    else:
        # Note: DES has weak keys and parity bits. Some implementations ignore LSB.
        print(f"[FAIL] DES Vector Test Failed. Expected {exp_vec.hex()}")

from core.triple_des import TripleDES
from core.hashing import sha256_hash, SHA256

def test_3des():
    print("\n--- Testing 3DES (Triple DES) ---")
    key = b'\x01' * 24 # 24 bytes key
    data = b'ABCDEFGH' # 8 bytes
    
    print(f"Key: {key.hex()}")
    print(f"Plaintext: {data.hex()}")
    
    tdes = TripleDES()
    enc = tdes.encrypt(data, key)
    print(f"Ciphertext: {enc.hex()}")
    
    dec = tdes.decrypt(enc, key)
    print(f"Decrypted: {dec.hex()}")
    
    if dec == data:
        print("[PASS] 3DES Test Passed")
    else:
        print("[FAIL] 3DES Test Failed")

def test_sha256():
    print("\n--- Testing SHA-256 ---")
    data = b"abc"
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    
    digest = sha256_hash(data)
    print(f"Input: {data}")
    print(f"Digest:   {digest}")
    print(f"Expected: {expected}")
    
    if digest == expected:
        print("[PASS] SHA-256 Test Passed")
    else:
        print("[FAIL] SHA-256 Test Failed")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "aes":
            test_aes()
        elif cmd == "des":
            test_des()
        elif cmd == "3des":
            test_3des()
        elif cmd == "sha":
            test_sha256()
        elif cmd == "all":
            test_aes()
            test_des()
            test_3des()
            test_sha256()
    else:
        test_aes()
        test_des()
        test_3des()
        test_sha256()
