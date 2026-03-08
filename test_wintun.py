"""
Quick WinTun Test - Run as Administrator
Tests if WinTun driver can create a TUN interface
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.wintun_wrapper import TunDevice

print("=" * 60)
print(" WinTun Driver Test")
print("=" * 60)
print()
print("Testing WinTun adapter creation...")
print("This must be run as Administrator!")
print()

tun = TunDevice("TestVPN", "TestTunnel")

if tun.create():
    print("✅ SUCCESS! TUN device created!")
    print(f"   Interface name: {tun.name}")
    print(f"   Tunnel type: {tun.tunnel_type}")
    print()
    print("Check Network Adapters (ncpa.cpl) to see the new interface!")
    print()
    input("Press Enter to close the TUN device...")
    tun.close()
    print("✓ Device closed successfully")
else:
    print("❌ FAILED to create TUN device!")
    print()
    print("Possible reasons:")
    print("  1. Not running as Administrator")
    print("  2. WinTun driver not properly installed")
    print("  3. Conflicting network adapter")
    print("  4. Windows security policy blocking driver")
    print()
    print("Try:")
    print("  - Make sure you run PowerShell as Administrator")
    print("  - Check Windows Event Viewer for driver errors")
