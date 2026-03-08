import asyncio
import logging
import threading
from fastapi import FastAPI, WebSocket, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sys
import os

# Add parent dir to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.aes import AES
from core.des import DES
from core.triple_des import TripleDES
from core.hashing import sha256_hash

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("VPN_Backend")

app = FastAPI(title="Academic VPN Backend")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from backend.proxy import ProxyService

# Global State
# Global State
class VPNState:
    is_running = False
    current_algo = "AES"
    bytes_in = 0
    bytes_out = 0
    active_connections = 0
    handshake_status = "IDLE"
    handshake_msg = "Ready to connect"
    latest_packet = ""
    threats = []
    
state = VPNState()

from backend.database import init_db, log_threat, verify_user, get_recent_threats

# Initialize DB
init_db()

def on_stats_update(bytes_in, bytes_out, connections):
    state.bytes_in = bytes_in
    state.bytes_out = bytes_out
    state.active_connections = connections
    state.handshake_status = "RUNNING" if connections > 0 else "IDLE"
    state.handshake_msg = f"{connections} active connection(s)"

# Secure Credentials
import secrets
PROXY_USER = "admin"
PROXY_PASS = secrets.token_hex(4)

# Public Tunnel
from pyngrok import ngrok
public_url = ""

def start_public_tunnel():
    global public_url
    try:
        # Open a TCP tunnel on port 1080
        # auth_token is required for TCP, assumes user has run 'ngrok config add-authtoken' or set env var
        # If not, it might fail or fallback to http (which wont work for socks).
        # We'll try/except.
        tunnel = ngrok.connect(1080, "tcp")
        public_url = tunnel.public_url
        logger.info(f"Public Tunnel Started: {public_url}")
    except Exception as e:
        logger.error(f"Ngrok Error: {e}")

def get_local_ip():
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

def on_packet(direction, data):
    # Hex dump first 16 bytes for display
    try:
        hex_str = data[:16].hex()
        state.latest_packet = f"[{direction}] {hex_str}..."
    except:
        pass

# Initialize Proxy with Auth
# Note: We bind to 0.0.0.0 to allow other devices to connect
tunnel = ProxyService(host="0.0.0.0", port=1080, 
                      username=PROXY_USER, password=PROXY_PASS,
                      on_stats=on_stats_update, on_packet=on_packet)
                      
# Start ngrok in background
threading.Thread(target=start_public_tunnel, daemon=True).start()


# Models
class ConfigRequest(BaseModel):
    algorithm: str

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/api/login")
async def login(creds: LoginRequest):
    print(f"DEBUG: Login Attempt -> User: '{creds.username}', Pass: '{creds.password}'")
    role = verify_user(creds.username, creds.password)
    if role:
        return {"status": "success", "role": role, "token": "simulated-jwt-token"}
    raise HTTPException(status_code=401, detail="Invalid credentials")

@app.get("/api/admin/threats")
async def admin_threats():
    return get_recent_threats()


@app.get("/status")
async def get_status():
    return {
        "is_running": state.is_running,
        "algorithm": state.current_algo,
        "traffic": {
            "in": state.bytes_in,
            "out": state.bytes_out
        },
        "connections": state.active_connections,
        "handshake": {
            "status": state.handshake_status,
            "message": state.handshake_msg
        },
        "threat_count": len(state.threats),
        "threat_count": len(state.threats),
        "local_ip": get_local_ip(),
        "proxy_port": 1080,
        "public_url": public_url,
        "proxy_user": PROXY_USER,
        "proxy_pass": PROXY_PASS
    }

@app.get("/threats")
async def get_threats():
    return state.threats

@app.post("/config")
async def configure_vpn(config: ConfigRequest):
    if config.algorithm not in ["AES", "DES", "3DES", "ChaCha20"]:
        raise HTTPException(status_code=400, detail="Invalid algorithm")
    
    state.current_algo = config.algorithm
    # tunnel.set_algo(config.algorithm) # Proxy doesn't switch algos on fly
    logger.info(f"Algorithm switched to {state.current_algo}")
    return {"message": f"Switched to {state.current_algo}"}

@app.post("/api/ids/simulate")
async def trigger_attack():
    # if tunnel.simulate_attack():
    #     return {"status": "attack_started", "message": "Simulated Cyber Attack Initiated"}
    # raise HTTPException(status_code=400, detail="VPN Tunnel not active")
    return {"status": "ignored", "message": "Simulation disabled in Real Proxy Mode"}

@app.post("/start")
async def start_vpn():
    state.is_running = True
    tunnel.start()
    logger.info("VPN Service Started")
    return {"status": "started"}

@app.post("/stop")
async def stop_vpn():
    state.is_running = False
    tunnel.stop()
    state.handshake_status = "IDLE"
    state.handshake_msg = "Disconnected"
    logger.info("VPN Service Stopped")
    return {"status": "stopped"}

@app.websocket("/ws/traffic")
async def websocket_traffic(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            # Simulate real-time traffic updates
            # Real-time traffic updates from ProxyService callbacks
            # if state.is_running and state.handshake_status == "CONNECTED":
            #     # Mock traffic update
            #     pass 
            latency = 0 # Calculate real latency later if possible
            
            await websocket.send_json({
                "bytes_in": state.bytes_in,
                "bytes_out": state.bytes_out,
                "is_running": state.is_running,
                "handshake_status": state.handshake_status,
                "handshake_msg": state.handshake_msg,
                "latest_packet": state.latest_packet,
                "latency": latency,
                "threats_detected": len(state.threats),
                "algorithm": state.current_algo
            })
            await asyncio.sleep(0.5) # Faster updates
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await websocket.close()

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Mount static files
app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/")
async def serve_frontend():
    return FileResponse("frontend/index.html")

if __name__ == "__main__":
    import uvicorn
    import webbrowser
    import threading
    import time
    
    def open_browser():
        time.sleep(1.5) # Give the server a moment to start
        logger.info("Opening browser to http://localhost:8000")
        webbrowser.open("http://localhost:8000")
        
    threading.Thread(target=open_browser).start()
    uvicorn.run(app, host="0.0.0.0", port=8000)
