import socket
import threading
import select
import logging
import struct
import time

logger = logging.getLogger("VPN_Proxy")

class ProxyService:
    """
    Real SOCKS5 Proxy Server.
    RFC 1928 Implementation.
    """
    def __init__(self, host="0.0.0.0", port=1080, username=None, password=None, on_stats=None, on_packet=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.server_socket = None
        self.is_running = False
        self.threads = []
        
        # Stats
        self.bytes_in = 0
        self.bytes_out = 0
        self.active_connections = 0
        
        # Callbacks
        self.on_stats = on_stats # func(bytes_in, bytes_out, connections)
        self.on_packet = on_packet # func(direction, data)

    def start(self):
        if self.is_running:
            return
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(20)
            self.is_running = True
            
            # Start listener thread
            t = threading.Thread(target=self._accept_loop, daemon=True)
            t.start()
            self.threads.append(t)
            
            logger.info(f"SOCKS5 Proxy started on {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start proxy: {e}")
            self.is_running = False
            return False

    def stop(self):
        self.is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        self.server_socket = None
        logger.info("SOCKS5 Proxy stopped")

    def _accept_loop(self):
        while self.is_running:
            try:
                client_sock, addr = self.server_socket.accept()
                logger.info(f"New connection from {addr}")
                t = threading.Thread(target=self._handle_client, args=(client_sock,), daemon=True)
                t.start()
            except OSError:
                break # Socket closed
            except Exception as e:
                logger.error(f"Accept error: {e}")
                if not self.is_running:
                    break

    def _handle_client(self, client_sock):
        self.active_connections += 1
        self._report_stats()
        
        try:
            # 1. Negotiation
            # SOCKS5 Version (1 byte) + N methods (1 byte) + Methods (N bytes)
            header = client_sock.recv(2)
            if not header or header[0] != 5:
                return # Not SOCKS5

            nmethods = header[1]
            methods = client_sock.recv(nmethods)
            
            # Server response: Version (1 byte) + Method (1 byte)
            if self.username and self.password:
                # Require Username/Password Auth (0x02)
                client_sock.sendall(b'\x05\x02')
                
                # Auth Handshake (RFC 1929)
                # Client sends: Ver(1) | Ulen(1) | User | Plen(1) | Pass
                auth_ver = client_sock.recv(1) # Should be 1
                ulen = client_sock.recv(1)[0]
                user = client_sock.recv(ulen).decode()
                plen = client_sock.recv(1)[0]
                pwd = client_sock.recv(plen).decode()
                
                if user == self.username and pwd == self.password:
                    # Success (0x00)
                    client_sock.sendall(b'\x01\x00')
                else:
                    # Failure (0x01)
                    client_sock.sendall(b'\x01\x01')
                    logger.warning(f"Auth failed for user: {user}")
                    return
            else:
                # No Auth (0x00)
                client_sock.sendall(b'\x05\x00')
            
            # 2. Request
            # Ver (1) + Cmd (1) + Rsv (1) + Atyp (1) + [DestAddr] + DestPort (2)
            request = client_sock.recv(4)
            if not request or request[1] != 1: # Only support CONNECT (0x01)
                self._send_reply(client_sock, 7) # Command not supported
                return

            cmd = request[1]
            addr_type = request[3]
            
            dest_addr = ""
            if addr_type == 1: # IPv4
                addr_bytes = client_sock.recv(4)
                dest_addr = socket.inet_ntoa(addr_bytes)
            elif addr_type == 3: # Domain
                domain_len = client_sock.recv(1)[0]
                dest_addr = client_sock.recv(domain_len).decode()
            elif addr_type == 4: # IPv6
                # Not fully supported yet, consume bytes
                 addr_bytes = client_sock.recv(16)
                 dest_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            
            port_bytes = client_sock.recv(2)
            dest_port = struct.unpack('>H', port_bytes)[0]
            
            # 3. Connect to Destination
            try:
                remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote_sock.connect((dest_addr, dest_port))
                
                # Success Reply
                # Ver (1) + Rep (1) + Rsv (1) + Atyp (1) + BndAddr (4) + BndPort (2)
                bind_addr = remote_sock.getsockname()[0]
                bind_port = remote_sock.getsockname()[1]
                
                reply = b'\x05\x00\x00\x01' + socket.inet_aton(bind_addr) + struct.pack('>H', bind_port)
                client_sock.sendall(reply)
                
                # 4. Exchange Data
                self._exchange_loop(client_sock, remote_sock)
                
            except Exception as e:
                logger.error(f"Connect failed to {dest_addr}:{dest_port} - {e}")
                self._send_reply(client_sock, 4) # Host unreachable
                
        except Exception as e:
            logger.error(f"Client handler failed: {e}")
        finally:
            client_sock.close()
            self.active_connections -= 1
            self._report_stats()

    def _send_reply(self, sock, error_code):
        try:
            # Ver=5, Rep=Error, Rsv=0, Atyp=1 (IPv4), 0.0.0.0, Port=0
            sock.sendall(b'\x05' + bytes([error_code]) + b'\x00\x01\x00\x00\x00\x00\x00\x00')
        except:
            pass

    def _exchange_loop(self, client, remote):
        sockets = [client, remote]
        while True:
            r, _, _ = select.select(sockets, [], [], 10)
            if not r:
                continue # Timeout/Idle
            
            for s in r:
                other = remote if s is client else client
                try:
                    data = s.recv(4096 * 4)
                    if not data:
                        return # Connection closed
                    
                    # Forward
                    other.sendall(data)
                    
                    # Update Stats
                    if s is client:
                        self.bytes_out += len(data) # Upload
                        if self.on_packet: self.on_packet("OUT", data)
                    else:
                        self.bytes_in += len(data) # Download
                        if self.on_packet: self.on_packet("IN", data)
                    
                    self._report_stats()
                    
                except:
                    return

    def _report_stats(self):
        if self.on_stats:
            self.on_stats(self.bytes_in, self.bytes_out, self.active_connections)
