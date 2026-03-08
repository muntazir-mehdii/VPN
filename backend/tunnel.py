import socket
import threading
import logging
import time
import secrets
from core.aes import AES
from core.des import DES
from core.triple_des import TripleDES
from core.chacha20 import ChaCha20
from core.rsa import RSA, generate_keypair
from core.signatures import DigitalSignature

from core.ids import IntrusionDetectionSystem

logger = logging.getLogger("VPN_Tunnel")

class TunnelService:
    """
    Simulated VPN Tunnel Service (Professional Edition).
    Features:
    - RSA Key Exchange Handshake
    - Digital Signatures
    - Multi-Algo Support (Block & Stream)
    - Traffic Inspection Hook
    - Intrusion Detection System (IDS)
    """
    
    def __init__(self, host="127.0.0.1", port=9000, algo="AES", on_status_change=None, on_packet=None, on_threat=None):
        self.host = host
        self.port = port
        self.is_running = False
        self.algo_name = algo
        self.cipher = None
        self.key = None
        self.thread = None
        self.sock = None
        
        # Callbacks
        self.on_status_change = on_status_change 
        self.on_packet = on_packet 
        self.on_threat = on_threat # New callback
        
        # Identity
        self.rsa = RSA()
        self.signer = DigitalSignature()
        self.server_keys = generate_keypair(bits=512)
        
        # Security
        self.ids = IntrusionDetectionSystem()

    def set_algo(self, algo: str):
        self.algo_name = algo
        logger.info(f"Tunnel Algorithm updated to {algo}")

    def _init_session_key(self):
        # Generate ephemeral session key
        if self.algo_name == "ChaCha20":
            self.key = secrets.token_bytes(32)
        elif self.algo_name == "3DES":
            self.key = secrets.token_bytes(24)
        elif self.algo_name == "DES":
            self.key = secrets.token_bytes(8)
        else: # AES
            self.key = secrets.token_bytes(16)
            
        # Init cipher engine
        if self.algo_name == "AES":
            self.cipher = AES()
        elif self.algo_name == "DES":
            self.cipher = DES()
        elif self.algo_name == "3DES":
            self.cipher = TripleDES()
        elif self.algo_name == "ChaCha20":
            self.cipher = ChaCha20()

    def start(self):
        if self.is_running:
            return
        self.is_running = True
        self.thread = threading.Thread(target=self._run_server)
        self.thread.start()
        
        # Start a Simulated Client to drive the demo
        threading.Thread(target=self._run_simulated_client, daemon=True).start()
        
        logger.info(f"Tunnel started on {self.host}:{self.port}")

    def stop(self):
        self.is_running = False
        if self.sock:
            self.sock.close()
        logger.info("Tunnel stopped")

    def _update_status(self, step, msg):
        if self.on_status_change:
            self.on_status_change(step, msg)
            
    def _run_simulated_client(self):
        """Connects to the tunnel to simulate a user"""
        time.sleep(1) # Wait for server to bind
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((self.host, self.port))
            
            # Allow handshake to complete
            time.sleep(4) 
            
            # Send traffic loop
            while self.is_running:
                msg = f"Simulated Traffic {time.time()}".encode()
                try:
                    client.sendall(msg)
                    # Receive echo
                    client.recv(1024)
                except:
                    break
                time.sleep(0.5)
            client.close()
        except Exception as e:
            logger.error(f"SimClient Error: {e}")

    def simulate_attack(self):
        """Spawns a thread to flood the server with simulated malicious packets"""
        def _attack():
            logger.warning("STARTING SIMULATED CYBER ATTACK...")
            try:
                # Create a temporary client to flood the server
                attacker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                attacker.connect((self.host, self.port))
                
                # Attack Patterns
                payloads = [
                    "UNION SELECT * FROM users",
                    "<script>alert('pwned')</script>",
                    "DROP TABLE threats",
                    "../../etc/passwd",
                    "eval(base64_decode('...'))"
                ]
                
                for _ in range(20): # Send 20 rapid-fire malicious packets
                    attack_msg = random.choice(payloads).encode()
                    attacker.sendall(attack_msg)
                    time.sleep(0.05) # Very fast
                    
                attacker.close()
                logger.warning("ATTACK SIMULATION COMPLETE")
            except Exception as e:
                logger.error(f"Attack failed: {e}")

        if self.is_running:
            threading.Thread(target=_attack).start()
            return True
        return False

    def _run_server(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        
        while self.is_running:
            try:
                self.sock.settimeout(1.0)
                client_sock, addr = self.sock.accept()
                logger.info(f"Accepted connection from {addr}")
                threading.Thread(target=self._handle_client, args=(client_sock,)).start()
            except socket.timeout:
                continue
            except Exception as e:
                # Expected when closing socket
                break

    def _perform_handshake(self, client_sock):
        """Simulates a secure RSA Handshake"""
        delay = 0.8 # Slow down for visual effect
        
        # Step 1: Client Hello
        self._update_status("HANDSHAKE_INIT", "Client Hello received. Negotiating params...")
        time.sleep(delay)
        
        # Step 2: Server Hello + Certificate (Public Key)
        self._update_status("SERVER_HELLO", f"Sending Server Certificate (RSA-512) & selecting {self.algo_name}...")
        pub_key, _ = self.server_keys
        try:
            client_sock.sendall(f"CERT:RSA512:ALGO:{self.algo_name}".encode())
        except: pass
        time.sleep(delay)
        
        # Step 3: Identity Verification (Challenge/Response)
        self._update_status("VERIFY_IDENTITY", "Verifying Client Identity (Digital Signature)...")
        challenge = secrets.token_bytes(16)
        time.sleep(delay)
        
        # Step 4: Key Exchange
        self._update_status("KEY_EXCHANGE", "Exchanging Session Keys (Encrypted with RSA)...")
        self._init_session_key()
        session_key_encrypted = self.rsa.encrypt_bytes(self.key, pub_key)
        time.sleep(delay)
        
        # Step 5: Finished
        self._update_status("HANDSHAKE_DONE", "Secure Tunnel Established. Ready for Traffic.")
        time.sleep(0.5)
        
        return True

    def _handle_client(self, client_sock):
        try:
            if not self._perform_handshake(client_sock):
                return

            self._update_status("CONNECTED", f"VPNet Secure Tunnel Active ({self.algo_name})")

            while self.is_running:
                data = client_sock.recv(1024)
                if not data:
                    break
                
                # IDS SCAN
                threat = self.ids.scan(data)
                if threat:
                    logger.warning(f"THREAT DETECTED: {threat['threat']}")
                    if self.on_threat:
                        self.on_threat(threat)
                    # Drop malicious packet
                    continue

                # Encrypt
                ciphertext = b''
                if self.algo_name == "ChaCha20":
                    ciphertext = self.cipher.encrypt(data, self.key)
                else:
                    bs = self.cipher.block_size
                    padding_len = bs - (len(data) % bs)
                    padded_data = data + bytes([padding_len] * padding_len)
                    
                    chunks = []
                    for i in range(0, len(padded_data), bs):
                        chunks.append(self.cipher.encrypt(padded_data[i:i+bs], self.key))
                    ciphertext = b''.join(chunks)

                # Packet Inspection Hook
                if self.on_packet:
                    self.on_packet("OUT", ciphertext)

                # Echo back (Simulation)
                try:
                    response = f"SECURED[{self.algo_name}]: {ciphertext.hex()[:32]}...".encode('utf-8')
                    client_sock.sendall(response)
                except:
                    break
                
        except Exception as e:
            logger.error(f"Client handling error: {e}")
        finally:
            client_sock.close()
