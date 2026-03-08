import re
import random
import datetime

class IntrusionDetectionSystem:
    """
    Simulated Intrusion Detection System (IDS).
    Scans packets for known malicious patterns (Signatures).
    """

    SIGNATURES = {
        r"UNION SELECT": "SQL Injection Attempt",
        r"<script>": "XSS Attempt",
        r"../": "Directory Traversal",
        r"eval\(": "Remote Code Execution",
        r"DROP TABLE": "SQL Injection (Destructive)",
    }

    def __init__(self):
        self.threat_log = []
        self.blocked_count = 0

    def scan(self, data: bytes) -> dict:
        """
        Scans data for threats.
        Returns None if clean, or a Threat Event dict if malicious.
        """
        try:
            # Simple simulation: Decode to string to check PCRE patterns
            # In production deep packet inspection is more complex.
            text = data.decode('utf-8', errors='ignore')
            
            for pattern, name in self.SIGNATURES.items():
                if re.search(pattern, text, re.IGNORECASE):
                    event = {
                        "timestamp": datetime.datetime.now().isoformat(),
                        "threat": name,
                        "severity": "CRITICAL" if "SQL" in name else "HIGH",
                        "source_ip": self._random_ip(),
                        "action": "BLOCKED"
                    }
                    self.threat_log.append(event)
                    self.blocked_count += 1
                    return event
            
            # Simulate random background radiation threats (1 in 50 packets)
            if random.random() < 0.02:
                 event = {
                        "timestamp": datetime.datetime.now().isoformat(),
                        "threat": "Anomalous Traffic Pattern (Heuristic)",
                        "severity": "MEDIUM",
                        "source_ip": self._random_ip(),
                        "action": "FLAGGED"
                    }
                 self.threat_log.append(event)
                 return event

        except Exception:
            pass
        return None

    def _random_ip(self):
        return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

    def get_logs(self):
        return self.threat_log[-20:] # Return last 20
