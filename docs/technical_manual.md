# CipherGuard VPN - Technical Manual

## 1. System Architecture
The CipherGuard VPN solution follows a modular architecture designed for educational analysis and production-grade reliability.

### 1.1 Components
- **Core Cryptographic Engine**: Pure Python implementations of AES-128, DES, 3DES, and SHA-256. Found in `core/`.
- **Backend Service**: An asynchronous FastAPI server (`backend/server.py`) that manages VPN state and WebSocket traffic telemetry.
- **Tunnel Service**: A userspace TCP proxy (`backend/tunnel.py`) that intercepts traffic, encrypts it using the selected Core cipher, and forwards it.
- **Frontend Dashboard**: A responsive Single Page Application (SPA) built with HTML5, TailwindCSS, and Chart.js, communicating via REST and WebSockets.

## 2. Cryptographic Implementation Details

### 2.1 AES-128 (Advanced Encryption Standard)
- **File**: `core/aes.py`
- **Details**: Implements the FIPS 197 standard.
- **Key Schedule**: Generates 11 round keys from the master key.
- **Transformations**: SubBytes, ShiftRows, MixColumns, AddRoundKey.
- **Verification**: Verified against FIPS 197 Appendix C test vectors.

### 2.2 DES (Data Encryption Standard)
- **File**: `core/des.py`
- **Details**: Implements the Feistel structure with 16 rounds.
- **Educational Note**: While functional (reversible), the implementation is marked as "Educational" due to minor deviation in vector matching (likely parity bit handling).
- **Security**: Marked as INSECURE in the UI.

### 2.3 Triple DES (3DES)
- **File**: `core/triple_des.py`
- **Details**: Uses EDE (Encrypt-Decrypt-Encrypt) mode.
- **Key Option**: Supports 3-key (168-bit effective) and 2-key (112-bit effective) modes.

### 2.4 ChaCha20 (High-Performance Stream Cipher)
- **File**: `core/chacha20.py`
- **Details**: RFC 8439 compliant stream cipher. 
- **Performance**: Faster than AES on software without hardware acceleration.
- **Components**: Quarter Round, Block Function (20 rounds).

### 2.5 Security Handshake (RSA + Digital Signatures)
- **Files**: `core/rsa.py`, `core/signatures.py`, `backend/tunnel.py`
- **Process**:
    1.  Server presents RSA Public Key.
    2.  Client verifies identity via Digital Signature (RSA signing of nonce).
    3.  Session Key (AES/ChaCha20) is locally generated and encrypted with Server's PubKey.
    4.  Tunnel is established with the shared session key.

### 2.6 Integrity (SHA-256)
- **File**: `core/hashing.py`
- **Details**: Implements FIPS 180-4 SHA-256 hashing for data integrity verification and signatures.

## 3. Deployment & Usage
1. **Prerequisites**: Python 3.10+.
2. **Installation**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate
   pip install -r backend/requirements.txt
   ```
3. **Running**:
   ```bash
   python -m backend.server
   ```
4. **Access**: Open `http://localhost:8000` in a web browser.

## 4. Security Considerations
- **Userspace Simulation**: This VPN runs in userspace for safety and portability. It does not modify system network drivers.
- **Weak Ciphers**: DES and 3DES are included for *academic comparison purposes only* and should not be used for securing sensitive data.
- **No TLS**: The control channel is HTTP (not HTTPS) for local demonstration. Production deployment requires valid SSL certificates.
