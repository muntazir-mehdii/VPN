"""
Split Tunneling
Per-domain routing bypass
"""

import subprocess
import logging
import socket

logger = logging.getLogger("SplitTunnel")


class SplitTunneling:
    """
    Split Tunneling - Route specific domains outside VPN
    """
    
    def __init__(self, original_gateway: str):
        self.original_gateway = original_gateway
        self.bypass_domains = []
        self.bypass_ips = []
    
    def add_bypass_domain(self, domain: str):
        """
        Add domain to bypass list
        Traffic to this domain will NOT go through VPN
        """
        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(domain)
            
            logger.info(f"Adding bypass route: {domain} ({ip})")
            
            # Add specific route for this IP through original gateway
            subprocess.run([
                'route', 'add', ip, 'mask', '255.255.255.255',
                self.original_gateway
            ], capture_output=True)
            
            self.bypass_domains.append(domain)
            self.bypass_ips.append(ip)
            
            logger.info(f"✓ {domain} will bypass VPN")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add bypass for {domain}: {e}")
            return False
    
    def remove_bypass_domain(self, domain: str):
        """Remove domain from bypass list"""
        try:
            if domain in self.bypass_domains:
                idx = self.bypass_domains.index(domain)
                ip = self.bypass_ips[idx]
                
                # Delete route
                subprocess.run(['route', 'delete', ip], capture_output=True)
                
                self.bypass_domains.remove(domain)
                self.bypass_ips.remove(ip)
                
                logger.info(f"✓ {domain} bypass removed")
                return True
        except Exception as e:
            logger.error(f"Failed to remove bypass: {e}")
            return False
    
    def clear_all(self):
        """Remove all bypass routes"""
        for ip in self.bypass_ips:
            subprocess.run(['route', 'delete', ip], capture_output=True)
        
        self.bypass_domains = []
        self.bypass_ips = []
        logger.info("✓ All bypass routes cleared")
    
    def get_bypass_list(self) -> list:
        """Get current bypass domains"""
        return [
            {"domain": d, "ip": i}
            for d, i in zip(self.bypass_domains, self.bypass_ips)
        ]
