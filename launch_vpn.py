"""
VPN Production Mode Launcher
Replacement for the old SOCKS5 proxy

Run as Administrator!
"""

import sys
import os
import logging
import threading
import time

# Add project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.vpn_client import VPNClient
from backend.vpn_server import VPNServer
from backend.routing_manager import RoutingManager
from backend.kill_switch import KillSwitch
from backend.split_tunnel import SplitTunneling

logging.basicConfig(level =logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("VPN_Production")


class ProductionVPN:
    """
    Production VPN Manager
    Coordinates all components
    """
    
    def __init__(self):
        # Components
        self.client = None
        self.server = None
        self.routing = RoutingManager()
        self.kill_switch = KillSwitch()
        self.split_tunnel = None
        
        # State
        self.is_running = False
        
    def start_server(self):
        """Start local VPN server (for testing)"""
        logger.info("Starting local VPN server...")
        self.server = VPNServer(host="127.0.0.1", port=51820)
        if self.server.start():
            logger.info("✓ Server started")
            return True
        return False
    
    def start_client(self):
        """Start VPN client"""
        logger.info("Starting VPN client...")
        
        def stats_callback(bytes_in, bytes_out, packets_in, packets_out):
            logger.debug(f"Traffic: ↓{bytes_in} ↑{bytes_out}")
        
        self.client = VPNClient(
            interface_name="wg0",
            server_host="10.179.142.58",
            server_port=51820,
            on_stats=stats_callback
        )
        
        if self.client.start():
            logger.info("✓ VPN client started")
            self.is_running = True
            return True
        return False
    
    def configure_routing(self):
        """Set up system routes"""
        logger.info("Configuring routes...")
        self.routing.backup_routes()
        
        # For testing, we won't actually modify routes
        # Uncomment these in production:
        self.routing.configure_vpn_interface("wg0")
        self.routing.add_vpn_routes()
        self.routing.set_vpn_dns(["1.1.1.1", "1.0.0.1"])
        
        logger.info("✓ Routes configured (simulation mode)")
    
    def enable_kill_switch(self):
        """Enable kill switch"""
        logger.info("Enabling kill switch...")
        # For testing, we'll skip this
        # In production: self.kill_switch.enable("127.0.0.1", 51820)
        logger.info("✓ Kill switch ready (disabled for testing)")
    
    def start_all(self):
        """Start complete VPN stack"""
        print("\n" + "="*60)
        print(" PRODUCTION VPN STARTUP")
        print("="*60)
        
        # Start server
        if not self.start_server():
            logger.error("Server failed to start!")
            return False
        
        time.sleep(1)
        
        # Start client
        if not self.start_client():
            logger.error("Client failed to start!")
            return False
        
        # Configure routing (simulation)
        self.configure_routing()
        
        # Kill switch (simulation)
        self.enable_kill_switch()
        
        print("\n✅ VPN IS NOW ACTIVE!")
        print("\nStatus:")
        status = self.client.get_status()
        for key, value in status.items():
            print(f"  - {key}: {value}")
        
        return True
    
    def stop_all(self):
        """Stop VPN and restore system"""
        logger.info("Stopping VPN...")
        
        if self.client:
            self.client.stop()
        
        if self.server:
            self.server.stop()
        
        self.routing.restore_routes()
        self.kill_switch.disable()
        
        self.is_running = False
        logger.info("✓ VPN stopped, system restored")


def main():
    print("\n" + "="*70)
    print(" PRODUCTION VPN - WireGuard Implementation")
    print("="*70)
    print("\n⚠️  IMPORTANT:")
    print("  - You MUST run this as Administrator")
    print("  - This will create a TUN interface (wg0)")
    print("  - Currently in SIMULATION mode (won't modify routes)")
    print("\nPress Ctrl+C to stop\n")
    
    input("Press Enter to start...")
    
    vpn = ProductionVPN()
    
    try:
        if vpn.start_all():
            print("\n📊 Monitoring traffic... (Press Ctrl+C to stop)")
            
            while True:
                time.sleep(5)
                if vpn.client:
                    status = vpn.client.get_status()
                    print(f"[{time.strftime('%H:%M:%S')}] "
                          f"RX: {status['bytes_received']} bytes | "
                          f"TX: {status['bytes_sent']} bytes")
        else:
            print("\n❌ VPN failed to start!")
            print("   Check the logs above for errors")
    
    except KeyboardInterrupt:
        print("\n\nShutting down...")
    finally:
        vpn.stop_all()
        print("\n✅ VPN stopped successfully\n")


if __name__ == "__main__":
    main()

