"""
Routing Manager
Handles Windows routing table modifications for VPN
"""

import subprocess
import logging

logger = logging.getLogger("RoutingManager")


class RoutingManager:
    """
    Manages system routing tables on Windows
    WARNING: Requires Administrator privileges
    """
    
    def __init__(self):
        self.original_gateway = None
        self.original_dns = []
        self.vpn_interface_ip = "10.0.0.2"
        self.vpn_gateway = "10.0.0.1"
        self.vpn_interface_name = None
        
    def get_default_gateway(self) -> str:
        """Get current default gateway using Windows route command"""
        try:
            # Use route print to get default gateway
            result = subprocess.run(
                ['route', 'print', '0.0.0.0'],
                capture_output=True,
                text=True
            )
            
            # Parse route print output
            for line in result.stdout.split('\n'):
                # Look for 0.0.0.0 route (default gateway), skip On-link
                if '0.0.0.0' in line and 'On-link' not in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        return parts[2]  # Gateway IP
            
            return "192.168.1.1"  # Fallback
        except Exception as e:
            logger.error(f"Failed to get default gateway: {e}")
            return "192.168.1.1"
    
    def backup_routes(self):
        """Save current routing configuration"""
        logger.info("Backing up current routes...")
        self.original_gateway = self.get_default_gateway()
        logger.info(f"Original gateway: {self.original_gateway}")
    
    def configure_vpn_interface(self, interface_name: str):
        """
        Configure the TUN interface with IP address
        """
        try:
            logger.info(f"Configuring interface {interface_name}...")
            
            # Set IP address
            cmd = [
                'netsh', 'interface', 'ip', 'set', 'address',
                f'name={interface_name}',
                'static',
                self.vpn_interface_ip,
                '255.255.255.0',
                self.vpn_gateway
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.warning(f"netsh failed: {result.stderr}")
                return False
            
            logger.info(f"✓ Interface configured: {self.vpn_interface_ip}")
            self.vpn_interface_name = interface_name
            return True
            
        except Exception as e:
            logger.error(f"Failed to configure interface: {e}")
            return False
    
    def add_vpn_routes(self):
        """
        Add routes to send all traffic through VPN
        """
        try:
            logger.info("Adding VPN routes...")
            
            # Add route for 0.0.0.0/1 (first half of internet)
            subprocess.run([
                'route', 'add', '0.0.0.0', 'mask', '128.0.0.0',
                self.vpn_gateway, 'metric', '1'
            ], capture_output=True)
            
            # Add route for 128.0.0.0/1 (second half of internet)
            subprocess.run([
                'route', 'add', '128.0.0.0', 'mask', '128.0.0.0',
                self.vpn_gateway, 'metric', '1'
            ], capture_output=True)
            
            logger.info("✓ VPN routes added")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add routes: {e}")
            return False
    
    def set_vpn_dns(self, dns_servers: list = ["1.1.1.1", "1.0.0.1"]):
        """
        Set DNS servers for VPN interface
        """
        if not self.vpn_interface_name:
            return False
        
        try:
            logger.info(f"Setting DNS to {dns_servers}...")
            
            # Set primary DNS
            subprocess.run([
                'netsh', 'interface', 'ip', 'set', 'dns',
                f'name={self.vpn_interface_name}',
                'static',
                dns_servers[0]
            ], capture_output=True)
            
            # Set secondary DNS
            if len(dns_servers) > 1:
                subprocess.run([
                    'netsh', 'interface', 'ip', 'add', 'dns',
                    f'name={self.vpn_interface_name}',
                    dns_servers[1],
                    'index=2'
                ], capture_output=True)
            
            logger.info("✓ DNS configured")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set DNS: {e}")
            return False
    
    def restore_routes(self):
        """
        Restore original routing configuration
        """
        try:
            logger.info("Restoring original routes...")
            
            # Delete VPN routes
            subprocess.run(['route', 'delete', '0.0.0.0', 'mask', '128.0.0.0'], capture_output=True)
            subprocess.run(['route', 'delete', '128.0.0.0', 'mask', '128.0.0.0'], capture_output=True)
            
            logger.info("✓ Routes restored")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore routes: {e}")
            return False
