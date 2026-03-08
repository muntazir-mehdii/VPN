"""
Kill Switch
Firewall-based internet kill switch for VPN
"""

import subprocess
import logging

logger = logging.getLogger("KillSwitch")


class KillSwitch:
    """
    Windows Firewall-based Kill Switch
    Blocks all non-VPN traffic when enabled
    """
    
    RULE_NAME_BLOCK_OUT = "VPN_KillSwitch_BlockOutbound"
    RULE_NAME_ALLOW_VPN = "VPN_KillSwitch_AllowVPN"
    RULE_NAME_ALLOW_LOCAL = "VPN_KillSwitch_AllowLocal"
    
    def __init__(self):
        self.is_enabled = False
        self.vpn_server_ip = None
    
    def enable(self, vpn_server_ip: str, vpn_port: int = 51820):
        """
        Enable kill switch
        Blocks all traffic except VPN connection
        """
        try:
            logger.info("Enabling Kill Switch...")
            self.vpn_server_ip = vpn_server_ip
            
            # 1. Delete existing rules if present
            self._cleanup()
            
            # 2. Create rule: ALLOW VPN server connection
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={self.RULE_NAME_ALLOW_VPN}',
                'dir=out',
                'action=allow',
                'protocol=UDP',
                f'remoteip={vpn_server_ip}',
                f'remoteport={vpn_port}'
            ], check=False, capture_output=True)
            
            # 3. Create rule: ALLOW local network
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={self.RULE_NAME_ALLOW_LOCAL}',
                'dir=out',
                'action=allow',
                'remoteip=192.168.0.0/16,10.0.0.0/8,172.16.0.0/12'
            ], check=False, capture_output=True)
            
            # 4. Create rule: BLOCK everything else
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name={self.RULE_NAME_BLOCK_OUT}',
                'dir=out',
                'action=block',
                'remoteip=0.0.0.0-255.255.255.255'
            ], check=False, capture_output=True)
            
            self.is_enabled = True
            logger.info("✓ Kill Switch ENABLED - All non-VPN traffic blocked")
            return True
            
        except Exception as e:
            logger.error(f"Failed to enable kill switch: {e}")
            return False
    
    def disable(self):
        """
        Disable kill switch
        Remove firewall rules
        """
        try:
            logger.info("Disabling Kill Switch...")
            self._cleanup()
            self.is_enabled = False
            logger.info("✓ Kill Switch disabled - Normal traffic restored")
            return True
        except Exception as e:
            logger.error(f"Failed to disable kill switch: {e}")
            return False
    
    def _cleanup(self):
        """Remove all kill switch firewall rules"""
        for rule_name in [self.RULE_NAME_BLOCK_OUT, self.RULE_NAME_ALLOW_VPN, self.RULE_NAME_ALLOW_LOCAL]:
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                f'name={rule_name}'
            ], check=False, capture_output=True)
    
    def get_status(self) -> dict:
        """Get kill switch status"""
        return {
            "enabled": self.is_enabled,
            "vpn_server": self.vpn_server_ip
        }
