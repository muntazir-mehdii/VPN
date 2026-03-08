"""
VPN Server Component
Receives encrypted packets from clients and routes to internet via WinTun interface
"""

import socket
import threading
import logging
import subprocess
import ctypes
from typing import Dict, Tuple
from core.wireguard import WireGuardProtocol
from core.wintun_wrapper import TunDevice

logger = logging.getLogger("VPN_Server")

class VPNServer:
    """
    Production VPN Server
    - Creates TUN interface
    - Routes traffic to internet
    - Hides client IP
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 51820):
        self.host = host
        self.port = port
        self.socket = None
        self.is_running = False
        
        # TUN Interface
        self.tun = TunDevice(name="wg-server", tunnel_type="WireGuard")
        self.tun_ip = "10.0.0.1"
        self.client_ip_pool = "10.0.0."
        self.next_client_octet = 2
        
        # Mappings
        self.clients: Dict[str, WireGuardProtocol] = {}  # "ip:port" -> WGProtocol
        self.vpn_ip_map: Dict[str, str] = {}             # "10.0.0.2" -> "ip:port"
        self.client_vals: Dict[str, str] = {}            # "ip:port" -> "10.0.0.2"
        
        # Stats
        self.packets_received = 0
        self.packets_sent = 0
        
    def start(self):
        """Start VPN server and TUN interface"""
        try:
            # 1. Create TUN Device
            logger.info("Creating TUN interface 'wg-server'...")
            if not self.tun.create():
                logger.error("Failed to create TUN device - Run as Administrator!")
                return False
                
            # 2. Configure IP Access
            logger.info(f"Configuring Server IP: {self.tun_ip}...")
            # We don't set gateway for server, just the IP
            cmd = f'netsh interface ip set address name="wg-server" source=static addr={self.tun_ip} mask=255.255.255.0'
            subprocess.run(cmd, shell=True, check=True)
            
            # 3. Start UDP Socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            
            self.is_running = True
            logger.info(f"VPN Server started on {self.host}:{self.port}")
            
            # 4. Start Threads
            threading.Thread(target=self._receive_loop, daemon=True).start() # UDP -> TUN
            threading.Thread(target=self._tun_read_loop, daemon=True).start() # TUN -> UDP
            
            return True
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            self.stop()
            return False
    
    def stop(self):
        """Stop server"""
        self.is_running = False
        if self.socket:
            self.socket.close()
        if self.tun:
            self.tun.close()
        logger.info("VPN Server stopped")
    
    def _receive_loop(self):
        """Receive encrypted UDP packets from clients"""
        logger.info("Listening for UDP packets...")
        while self.is_running:
            try:
                data, addr = self.socket.recvfrom(65535)
                client_key = f"{addr[0]}:{addr[1]}"
                
                # Handle handshake or data
                msg_type = data[0] if len(data) > 0 else 0
                
                if msg_type == 1:  # Handshake init
                    logger.info(f"Handshake from {client_key}")
                    self._handle_handshake(client_key, addr, data)
                elif msg_type == 4:  # Data packet
                    self._handle_data_packet(client_key, data)
                    
                self.packets_received += 1
                
            except Exception as e:
                if self.is_running:
                    logger.error(f"UDP Receive error: {e}")
                    
    def _tun_read_loop(self):
        """Read decrypted packets from TUN and send to clients"""
        logger.info("Monitoring TUN interface...")
        while self.is_running:
            try:
                # Read packet from Windows OS
                packet = self.tun.read_packet()
                if not packet:
                    continue
                
                # Parse IPv4 Destination to find which client to send to
                # IPv4 Header: Bytes 16-19 are Destination IP
                if len(packet) >= 20: 
                    # Simple parse of 10.0.0.x
                    dest_ip_suffix = packet[19] # Last byte (e.g., 2)
                    vpn_dest = f"10.0.0.{dest_ip_suffix}"
                    
                    if vpn_dest in self.vpn_ip_map:
                        client_key = self.vpn_ip_map[vpn_dest]
                        wg = self.clients[client_key]
                        client_addr = self._parse_addr_key(client_key)
                        
                        # Encrypt and send
                        encrypted = wg.encrypt_packet(packet)
                        self.socket.sendto(encrypted, client_addr)
                        self.packets_sent += 1
                        
            except Exception as e:
                if self.is_running:
                    logger.error(f"TUN Read error: {e}")

    def _handle_handshake(self, client_key: str, addr, handshake_data):
        """Process handshake and create session"""
        # Create new session
        wg = WireGuardProtocol()
        wg.set_peer_public_key(wg.get_public_key())
        
        # Assign VPN IP (Simple allocation)
        if client_key in self.client_vals:
            client_vpn_ip = self.client_vals[client_key]
        else:
            client_vpn_ip = f"{self.client_ip_pool}{self.next_client_octet}"
            self.next_client_octet += 1
            self.client_vals[client_key] = client_vpn_ip
            self.vpn_ip_map[client_vpn_ip] = client_key
        
        # Store session
        self.clients[client_key] = wg
        
        # Send Handshake Response
        response = bytes([2]) + b'\x00' * 91 
        self.socket.sendto(response, addr)
        
        logger.info(f"Session established: {client_key} -> assigned IP {client_vpn_ip}")
    
    def _handle_data_packet(self, client_key: str, encrypted_data):
        """Decrypt data and write to TUN"""
        if client_key not in self.clients:
            logger.warning(f"Data from unknown client {client_key}")
            return
        
        wg = self.clients[client_key]
        plaintext = wg.decrypt_packet(encrypted_data)
        
        if plaintext:
            # Write to TUN (inject into OS networking)
            self.tun.write_packet(plaintext)
            
    def _parse_addr_key(self, key: str) -> Tuple[str, int]:
        parts = key.split(':')
        return (parts[0], int(parts[1]))
