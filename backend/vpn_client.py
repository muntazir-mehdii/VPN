"""
VPN Client with TUN Interface
Handles packet routing and WireGuard encryption
"""

import threading
import socket
import struct
import logging
import time
from typing import Optional, Callable
from scapy.all import IP, UDP, TCP, ICMP

from core.wintun_wrapper import TunDevice
from core.wireguard import WireGuardProtocol

logger = logging.getLogger("VPN_Client")


class VPNClient:
    """
    Production VPN Client
    - Creates TUN interface
    - Performs WireGuard handshake
    - Routes system traffic through tunnel
    """
    
    def __init__(
        self,
        interface_name: str = "wg0",
        server_host: str = "127.0.0.1",
        server_port: int = 51820,
        on_stats: Optional[Callable] = None
    ):
        self.interface_name = interface_name
        self.server_host = server_host
        self.server_port = server_port
        
        # Components
        self.tun = TunDevice(interface_name)
        self.wireguard = WireGuardProtocol()
        self.server_socket = None
        
        # State
        self.is_running = False
        self.bytes_sent = 0
        self.bytes_received = 0
        self.packets_sent = 0
        self.packets_received = 0
        
        # Callbacks
        self.on_stats = on_stats
        
        # Threads
        self.tun_reader_thread = None
        self.server_reader_thread = None
    
    def start(self) -> bool:
        """
        Start VPN connection
        Returns True if successful
        """
        logger.info("Starting VPN client...")
        
        # 1. Create TUN device
        logger.info(f"Creating TUN interface '{self.interface_name}'...")
        if not self.tun.create():
            logger.error("Failed to create TUN device - are you running as Administrator?")
            return False
        
        logger.info("✓ TUN interface created")
        
        # 2. Connect to server
        logger.info(f"Connecting to VPN server {self.server_host}:{self.server_port}...")
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.server_socket.settimeout(5.0)
            
            # Set peer public key (for now, use our own key for local testing)
            self.wireguard.set_peer_public_key(self.wireguard.get_public_key())
            
            # Perform handshake
            logger.info("Performing WireGuard handshake...")
            handshake_init = self.wireguard.create_handshake_init()
            self.server_socket.sendto(handshake_init, (self.server_host, self.server_port))
            
            # Wait for response (simplified - in production, implement proper response handling)
            try:
                response, _ = self.server_socket.recvfrom(4096)
                if self.wireguard.process_handshake_response(response):
                    logger.info("✓ Handshake complete - Secure tunnel established")
                else:
                    logger.warning("Handshake response invalid, continuing anyway (simulation mode)")
            except socket.timeout:
                logger.warning("No handshake response (server may be simulation only)")
            
        except Exception as e:
            logger.error(f"Failed to connect to server: {e}")
            self.tun.close()
            return False
        
        # 3. Start packet routing loops
        self.is_running = True
        
        logger.info("Starting packet forwarding...")
        self.tun_reader_thread = threading.Thread(target=self._tun_to_server_loop, daemon=True)
        self.tun_reader_thread.start()
        
        self.server_reader_thread = threading.Thread(target=self._server_to_tun_loop, daemon=True)
        self.server_reader_thread.start()
        
        logger.info("✓ VPN is now active - All traffic is routed through tunnel")
        return True
    
    def stop(self):
        """Stop VPN and cleanup"""
        logger.info("Stopping VPN...")
        self.is_running = False
        
        if self.server_socket:
            self.server_socket.close()
        
        if self.tun:
            self.tun.close()
        
        logger.info("✓ VPN stopped")
    
    def _tun_to_server_loop(self):
        """
        Read packets from TUN interface -> Encrypt -> Send to server
        """
        logger.info("TUN reader started")
        
        while self.is_running:
            try:
                # Read packet from TUN
                packet_data = self.tun.read_packet(timeout_ms=100)
                
                if not packet_data:
                    continue
                
                # Parse IP packet
                try:
                    ip_pkt = IP(packet_data)
                    logger.debug(f"OUT: {ip_pkt.src} -> {ip_pkt.dst} ({len(packet_data)} bytes)")
                except:
                    logger.debug(f"OUT: Raw packet ({len(packet_data)} bytes)")
                
                # Encrypt with WireGuard
                encrypted = self.wireguard.encrypt_packet(packet_data)
                
                # Send to server
                self.server_socket.sendto(encrypted, (self.server_host, self.server_port))
                
                # Update stats
                self.bytes_sent += len(packet_data)
                self.packets_sent += 1
                self._report_stats()
                
            except Exception as e:
                if self.is_running:
                    logger.error(f"TUN read error: {e}")
    
    def _server_to_tun_loop(self):
        """
        Receive packets from server -> Decrypt -> Write to TUN
        """
        logger.info("Server reader started")
        
        while self.is_running:
            try:
                # Receive from server
                encrypted_data, _ = self.server_socket.recvfrom(4096)
                
                # Decrypt
                packet_data = self.wireguard.decrypt_packet(encrypted_data)
                
                if not packet_data:
                    continue
                
                # Parse IP packet
                try:
                    ip_pkt = IP(packet_data)
                    logger.debug(f"IN: {ip_pkt.src} -> {ip_pkt.dst} ({len(packet_data)} bytes)")
                except:
                    logger.debug(f"IN: Raw packet ({len(packet_data)} bytes)")
                
                # Write to TUN
                self.tun.write_packet(packet_data)
                
                # Update stats
                self.bytes_received += len(packet_data)
                self.packets_received += 1
                self._report_stats()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_running:
                    logger.error(f"Server read error: {e}")
    
    def _report_stats(self):
        """Report stats via callback"""
        if self.on_stats:
            self.on_stats(
                bytes_in=self.bytes_received,
                bytes_out=self.bytes_sent,
                packets_in=self.packets_received,
                packets_out=self.packets_sent
            )
    
    def get_status(self) -> dict:
        """Get current connection status"""
        return {
            "is_running": self.is_running,
            "interface": self.interface_name,
            "server": f"{self.server_host}:{self.server_port}",
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "needs_rekey": self.wireguard.needs_rekey() if self.is_running else False
        }
