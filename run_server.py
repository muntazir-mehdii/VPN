"""
VPN Server Startup Script
Run this directly to start the VPN server
"""

import sys
import os
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger("ServerLauncher")

print("=" * 60)
print(" VPN SERVER - Starting...")
print("=" * 60)
print()

# Import VPN Server
try:
    from backend.vpn_server import VPNServer
    print("✓ VPN Server module loaded")
except ImportError as e:
    print(f"✗ Failed to import VPN Server: {e}")
    input("Press Enter to exit...")
    sys.exit(1)

# Create server
try:
    server = VPNServer(host='0.0.0.0', port=51820)
    print("✓ Server instance created")
except Exception as e:
    print(f"✗ Failed to create server: {e}")
    input("Press Enter to exit...")
    sys.exit(1)

# Start server
print()
print("Starting VPN Server on 0.0.0.0:51820...")
print()

if server.start():
    print("=" * 60)
    print(" ✅ VPN SERVER IS RUNNING!")
    print("=" * 60)
    print()
    print("Server Details:")
    print(f"  - Host: 0.0.0.0 (listening on all interfaces)")
    print(f"  - Port: 51820")
    print(f"  - Protocol: UDP")
    print()
    print("Waiting for client connections...")
    print("Press Ctrl+C to stop the server")
    print()
    
    # Keep running
    import time
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print()
        print("Stopping server...")
        server.stop()
        print("✓ Server stopped")
else:
    print("=" * 60)
    print(" ✗ FAILED TO START SERVER!")
    print("=" * 60)
    print()
    print("Possible reasons:")
    print("  - Port 51820 already in use")
    print("  - Not running as Administrator")
    print("  - Firewall blocking the port")
    print()
    input("Press Enter to exit...")
    sys.exit(1)
