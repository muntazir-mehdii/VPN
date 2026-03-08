"""
Direct Wintun DLL Interface
Custom wrapper for wintun.dll using ctypes
"""

import ctypes
import os
import sys
from ctypes import wintypes, POINTER, c_void_p, c_uint32, c_uint16, c_ubyte, c_bool
from typing import Optional

# Locate wintun.dll
WINTUN_DLL_PATH = os.path.join(os.path.dirname(__file__), "..", "wintun", "bin", "amd64", "wintun.dll")

if not os.path.exists(WINTUN_DLL_PATH):
    raise FileNotFoundError(f"wintun.dll not found at {WINTUN_DLL_PATH}")

# Load library with error tracking enabled
wintun = ctypes.WinDLL(WINTUN_DLL_PATH, use_last_error=True)

# Define types
WINTUN_ADAPTER_HANDLE = c_void_p
WINTUN_SESSION_HANDLE = c_void_p

# Function signatures
wintun.WintunCreateAdapter.argtypes = [
    wintypes.LPCWSTR,  # Name
    wintypes.LPCWSTR,  # TunnelType
    POINTER(ctypes.c_ubyte * 16)  # RequestedGUID
]
wintun.WintunCreateAdapter.restype = WINTUN_ADAPTER_HANDLE

wintun.WintunCloseAdapter.argtypes = [WINTUN_ADAPTER_HANDLE]
wintun.WintunCloseAdapter.restype = None

wintun.WintunStartSession.argtypes = [WINTUN_ADAPTER_HANDLE, c_uint32]
wintun.WintunStartSession.restype = WINTUN_SESSION_HANDLE

wintun.WintunEndSession.argtypes = [WINTUN_SESSION_HANDLE]
wintun.WintunEndSession.restype = None

wintun.WintunReceivePacket.argtypes = [WINTUN_SESSION_HANDLE, POINTER(c_uint32)]
wintun.WintunReceivePacket.restype = POINTER(c_ubyte)

wintun.WintunReleaseReceivePacket.argtypes = [WINTUN_SESSION_HANDLE, POINTER(c_ubyte)]
wintun.WintunReleaseReceivePacket.restype = None

wintun.WintunAllocateSendPacket.argtypes = [WINTUN_SESSION_HANDLE, c_uint32]
wintun.WintunAllocateSendPacket.restype = POINTER(c_ubyte)

wintun.WintunSendPacket.argtypes = [WINTUN_SESSION_HANDLE, POINTER(c_ubyte)]
wintun.WintunSendPacket.restype = None


class TunDevice:
    """
    TUN Virtual Network Interface using Wintun
    """
    
    def __init__(self, name: str = "wg0", tunnel_type: str = "WireGuard"):
        self.name = name
        self.tunnel_type = tunnel_type
        self.adapter_handle = None
        self.session_handle = None
        
    def create(self) -> bool:
        """Create TUN adapter"""
        try:
            # Create adapter
            self.adapter_handle = wintun.WintunCreateAdapter(
                self.name,
                self.tunnel_type,
                None  # Let Windows generate GUID
            )
            
            if not self.adapter_handle:
                # Get Windows error code
                error_code = ctypes.get_last_error()
                print(f"WintunCreateAdapter failed! Error code: {error_code}")
                print(f"Error message: {ctypes.FormatError(error_code)}")
                return False
            
            # Start session (ring buffer capacity: 0x400000 = 4MB)
            self.session_handle = wintun.WintunStartSession(self.adapter_handle, 0x400000)
            
            if not self.session_handle:
                error_code = ctypes.get_last_error()
                print(f"WintunStartSession failed! Error code: {error_code}")
                print(f"Error message: {ctypes.FormatError(error_code)}")
                self.close()
                return False
            
            return True
        except Exception as e:
            print(f"Exception in TUN device creation: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def read_packet(self, timeout_ms: int = 1000) -> Optional[bytes]:
        """
        Read a packet from the TUN device
        Returns IP packet bytes or None if timeout
        """
        if not self.session_handle:
            return None
        
        packet_size = c_uint32()
        packet_ptr = wintun.WintunReceivePacket(self.session_handle, ctypes.byref(packet_size))
        
        if not packet_ptr:
            return None
        
        # Copy data
        data = bytes(packet_ptr[:packet_size.value])
        
        # Release packet back to pool
        wintun.WintunReleaseReceivePacket(self.session_handle, packet_ptr)
        
        return data
    
    def write_packet(self, packet_data: bytes) -> bool:
        """
        Write a packet to the TUN device
        Returns True if successful
        """
        if not self.session_handle:
            return False
        
        packet_size = len(packet_data)
        packet_ptr = wintun.WintunAllocateSendPacket(self.session_handle, packet_size)
        
        if not packet_ptr:
            return False
        
        # Copy data
        ctypes.memmove(packet_ptr, packet_data, packet_size)
        
        # Send
        wintun.WintunSendPacket(self.session_handle, packet_ptr)
        
        return True
    
    def close(self):
        """Clean up resources"""
        if self.session_handle:
            wintun.WintunEndSession(self.session_handle)
            self.session_handle = None
        
        if self.adapter_handle:
            wintun.WintunCloseAdapter(self.adapter_handle)
            self.adapter_handle = None


def test_tun():
    """Test TUN device creation"""
    print("Testing Wintun TUN interface...")
    
    tun = TunDevice("TestVPN")
    
    if tun.create():
        print("✓ TUN device created successfully!")
        print(f"  Interface: {tun.name}")
        print("  Check 'ipconfig' to see the new adapter")
        
        input("Press Enter to close...")
        tun.close()
        print("✓ Device closed")
    else:
        print("✗ Failed to create TUN device")
        print("  Make sure you run this as Administrator!")


if __name__ == "__main__":
    test_tun()
