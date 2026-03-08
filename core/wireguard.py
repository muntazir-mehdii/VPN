"""
WireGuard Protocol Implementation (Simplified)
Uses existing ChaCha20 implementation

This implements a simplified WireGuard-style protocol:
- Simulated key exchange
- ChaCha20 encryption (from our existing core module)
- Session management
"""

import os
import time
import struct
import secrets
from typing import Tuple, Optional
from core.chacha20 import ChaCha20

class WireGuardProtocol:
    """
    Simplified WireGuard-style Protocol
    Uses ChaCha20 for encryption
    """
    
    # Message types
    MSG_HANDSHAKE_INIT = 1
    MSG_HANDSHAKE_RESP = 2
    MSG_DATA = 4
    
    def __init__(self):
        # Static key (32 bytes for ChaCha20)
        self.static_key = secrets.token_bytes(32)
        self.static_public = secrets.token_bytes(32)  # Simplified - in real WG this is derived
        
        # Session state
        self.peer_public_key = None
        self.session_key = None
        self.cipher = None
        self.last_handshake = 0
        self.peer_index = 0
        
    def get_public_key(self) -> bytes:
        """Get our public key"""
        return self.static_public
    
    def set_peer_public_key(self, peer_key: bytes):
        """Set peer's public key"""
        self.peer_public_key = peer_key
        
        # Derive session key (simplified - XOR of our key and peer key)
        self.session_key = bytes(a ^ b for a, b in zip(self.static_key, peer_key))
        self.cipher = ChaCha20()
    
    def create_handshake_init(self) -> bytes:
        """Create simplified handshake message"""
        sender_index = secrets.randbits(32)
        self.peer_index = sender_index
        self.last_handshake = time.time()
        
        #Simple handshake message  
        msg = bytearray()
        msg.append(self.MSG_HANDSHAKE_INIT)
        msg.extend(struct.pack('<I', sender_index))
        msg.extend(self.static_public)  # Our public key
        msg.extend(b'\x00' * 60)  # Padding
        
        return bytes(msg)
    
    def process_handshake_response(self, response: bytes) -> bool:
        """Process handshake response"""
        if len(response) < 10 or response[0] != self.MSG_HANDSHAKE_RESP:
            return False
        
        self.last_handshake = time.time()
        return True
    
    def encrypt_packet(self, plaintext: bytes) -> bytes:
        """
        Encrypt packet with ChaCha20
        """
        if not self.session_key or not self.cipher:
            raise RuntimeError("No session key - handshake required")
        
        # Encrypt with ChaCha20
        ciphertext = self.cipher.encrypt(plaintext, self.session_key)
        
        # Build message
        counter = int(time.time() * 1000) % (2**64)
        msg = bytearray()
        msg.append(self.MSG_DATA)
        msg.extend(struct.pack('<I', self.peer_index))
        msg.extend(struct.pack('<Q', counter))
        msg.extend(ciphertext)
        
        return bytes(msg)
    
    def decrypt_packet(self, packet: bytes) -> Optional[bytes]:
        """
        Decrypt packet with ChaCha20
        """
        if len(packet) < 13 or packet[0] != self.MSG_DATA:
            return None
        
        if not self.session_key or not self.cipher:
            return None
        
        # Extract ciphertext
        ciphertext = packet[13:]
        
        # Decrypt with ChaCha20
        try:
            plaintext = self.cipher.decrypt(ciphertext, self.session_key)
            return plaintext
        except Exception:
            return None
    
    def needs_rekey(self) -> bool:
        """Check if handshake refresh needed"""
        return (time.time() - self.last_handshake) > 120
