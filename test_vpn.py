"""
VPN Test Suite
Run this to test TUN interface creation

IMPORTANT: Must run as Administrator!
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.wintun_wrapper import TunDevice
from core.wireguard import WireGuardProtocol
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(message)s')

def test_tun_creation():
    """Test 1: Can we create a TUN interface?"""
    print("\n" + "="*60)
    print("TEST 1: TUN Interface Creation")
    print("="*60)
    
    tun = TunDevice("VPN_Test")
    
    if tun.create():
        print("✅ SUCCESS: TUN device created!")
        print(f"   Interface name: {tun.name}")
        print("\n⚠️  Check 'ipconfig' in another terminal to see the new adapter")
        print("   It should appear as 'VPN_Test'")
        
        input("\nPress Enter to close the interface...")
        tun.close()
        print(" ✓ Interface closed")
        return True
    else:
        print("❌ FAILED: Could not create TUN device")
        print("   Make sure you're running as Administrator!")
        return False

def test_wireguard_crypto():
    """Test 2: WireGuard encryption/decryption"""
    print("\n" + "="*60)
    print("TEST 2: WireGuard Encryption")
    print("="*60)
    
    # Create two endpoints
    client = WireGuardProtocol()
    server = WireGuardProtocol()
    
    # Exchange keys
    client.set_peer_public_key(server.get_public_key())
    server.set_peer_public_key(client.get_public_key())
    
    # Test data
    plaintext = b"Hello from VPN client!"
    
    # Encrypt
    print(f"   Plaintext: {plaintext}")
    encrypted = client.encrypt_packet(plaintext)
    print(f"   Encrypted: {encrypted[:50].hex()}... ({len(encrypted)} bytes)")
    
    # Decrypt
    decrypted = server.decrypt_packet(encrypted)
    print(f"   Decrypted: {decrypted}")
    
    if decrypted == plaintext:
        print("✅ SUCCESS: Encryption/Decryption works!")
        return True
    else:
        print("❌ FAILED: Data corruption!")
        return False

def main():
    print("\n" + "="*60)
    print(" VPN COMPONENT TEST SUITE")
    print("="*60)
    print("\nThis will test:")
    print("  1. TUN/TAP interface creation (Wintun)")
    print("  2. WireGuard encryption/decryption")
    print("\n⚠️  YOU MUST RUN THIS AS ADMINISTRATOR!\n")
    
    input("Press Enter to start tests...")
    
    results = []
    
    # Test crypto first (doesn't need admin)
    results.append(("WireGuard Crypto", test_wireguard_crypto()))
    
    # Test TUN (needs admin)
    results.append(("TUN Interface", test_tun_creation()))
    
    # Summary
    print("\n" + "="*60)
    print(" TEST SUMMARY")
    print("="*60)
    for name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"  {status}  {name}")
    
    all_passed = all(r[1] for r in results)
    
    if all_passed:
        print("\n🎉 ALL TESTS PASSED!")
        print("\nYou're ready to run the full VPN!")
    else:
        print("\n⚠️  Some tests failed. Check the output above.")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
